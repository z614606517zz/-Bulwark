/*++
    FileMonitor.c
    文件防护(M3):Minifilter I/O 预操作回调。

    监控:
    - IRP_MJ_CREATE 带 FILE_DELETE_ON_CLOSE:打开即删除
    - IRP_MJ_SET_INFORMATION 的 FileDispositionInformation(标记删除)
      与 FileRenameInformation(重命名/移动)
    - IRP_MJ_WRITE:就地加密检测(采样遥测,绝不拦截)——抓"打开→从头覆写→同名保存"
      这类既不改名也不删除的加密型勒索。

    命中"受保护路径/硬拦截名单"时用 STATUS_ACCESS_DENIED 原地拒绝;未命中名单的删除/
    重命名/首块写则在"文件行为遥测"开启时 fire-and-forget 上报,供用户态勒索时序聚合。

    拦截类回调运行在 PASSIVE_LEVEL,本地查表裁决,绝不同步等待用户态。
--*/

#include "Driver.h"

// FileRenameInformationEx 的 Flags 位。旧 SDK 头未定义时兜底(WDK 10 已定义,#ifndef 仅为稳妥)。
#ifndef FILE_RENAME_REPLACE_IF_EXISTS
#define FILE_RENAME_REPLACE_IF_EXISTS 0x00000001
#endif

//
// ===== 通用受保护项匹配已移出本文件 =====
//
// BlwPrepareMatch / BlwMatchInListCtx / BlwMatchInListAnchoredCtx / BlwAddToList /
// BlwRemoveFromList / BlwLogPattern 现在都在 MatchCore.c —— 它们是纯函数(不碰 g_Blw、
// 不取锁、不依赖 IRQL),挪出去之后可以在用户态编译,由 cpp/tests/DriverMatchTest.cpp
// 做单元测试。驱动不能在开发机上加载,那是唯一能证伪这些判定的地方。
//
// 本文件保留的是【需要 g_Blw 与锁】的那一层:各名单的 Clear / Add / Is 包装函数。
//

//
// ===== 死条目准入校验:带盘符的模式一律拒收 =====
//
// 五份【文件路径】名单(ProtectedPaths / FileHardBlock / SelfGuard / FileNoLoad /
// FileExecBlock)匹配的目标恒为 FLT_FILE_NAME_NORMALIZED 规范名,形如
// \Device\HarddiskVolume3\Users\...。其中【不可能】出现 "<字母>:\" 这个三字符序列
// (数据流名可以带 ':',但流名里不允许出现 '\')。所以一条带盘符的模式:
//
//   * 永远不会命中 —— 它不是防护,是死代码;
//   * 却白占 64 槽之一,并被内核写回注册表【跨重启续留】;
//   * 槽位耗尽后 BlwAddToList 找不到空槽就静默返回 ——【此后所有新裁决都被丢弃】。
//
// 这不是假想:\Policy\FileNoLoad 现场实测有 3 条带 C:\ 前缀的条目,全是死的,各占一个槽,
// 而 reconcileKernelBlocksAfterTrust 会把注册表条目原样重推,所以它永远不会自己变好。
// 根因在用户态(blacklistExec 做了去盘符,enforceBlock 的 FileNoLoad 分支漏了),但内核
// 这一侧本来就该有一道门:能判定为「永不可能命中」的输入,不该被收进定长名单。
//
// 【CmdHardBlock 与 RegHardBlock 绝不可套用本判据】
//   * CmdHardBlock 匹配的是原始命令行,里面出现 C:\ 完全正常(`SAVE+HKLM\SAM` 这类模式
//     也可能带盘符路径);
//   * RegHardBlock 匹配的是「键路径\值名」,注册表值名允许含 ':'。
// 套上去会把真实有效的模式误拒 —— 那比多留几条死条目严重得多。
//
// 返回 TRUE 表示已拒收(调用方直接返回)。DirtyBit 用于记一笔「该名单的磁盘副本需要重写」,
// 不持久化的名单(SelfGuard)传 0。
//
static BOOLEAN
BlwRejectDeadPathPattern(
    _In_ PCSTR ListName,
    _In_opt_ PCWSTR Path,
    _In_ USHORT Length,
    _In_ LONG DirtyBit)
{
    if (!BlwPatternHasDriveLetter(Path, Length)) {
        return FALSE;
    }

    BlwLogPattern(ListName, Path, Length);
    BlwMarkDeadEntryDrop(DirtyBit);
    return TRUE;
}

//
// ===== 名单精确删除单条的公共外壳(BLW_CMD_DEL_*)=====
//
// 持锁 -> 精确删除(MatchCore.c 的 BlwRemoveFromList)-> 只在真删掉时重算在用计数。
// 计数只在变更时重算,是为了让「删不存在的条目」成为一次完全无副作用的操作 ——
// Comms.c 据返回值决定是否标脏,不该因为一次空操作触发注册表写。
//
// 三个模块(文件 / 注册表 / 命令行)共用本外壳,避免第二份「重算计数」的循环。
//
BOOLEAN
BlwRemoveFromGuardedList(
    _In_ BLW_PROTECTED_PATH* List,
    _In_ PFAST_MUTEX Lock,
    _Inout_ volatile LONG* Count,
    _In_ PCWSTR Path,
    _In_ USHORT Length)
{
    BOOLEAN removed;

    ExAcquireFastMutex(Lock);
    removed = BlwRemoveFromList(List, Path, Length);
    if (removed) {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (List[i].InUse) cnt++;
        }
        InterlockedExchange(Count, cnt);
    }
    ExReleaseFastMutex(Lock);
    return removed;
}

//
// ===== 受保护路径管理(线程安全)=====
//

void
BlwClearProtectedPaths(void)
{
    ExAcquireFastMutex(&g_Blw.PathLock);
    RtlZeroMemory(g_Blw.ProtectedPaths, sizeof(g_Blw.ProtectedPaths));
    InterlockedExchange(&g_Blw.ProtectedPathCount, 0);
    ExReleaseFastMutex(&g_Blw.PathLock);
}

void
BlwAddProtectedPath(_In_ PCWSTR Path, _In_ USHORT Length)
{
    if (BlwRejectDeadPathPattern("ProtectedPath entry REJECTED (drive-letter pattern never matches)",
                                 Path, Length, BLW_POLICY_DIRTY_PATHS)) {
        return;
    }

    ExAcquireFastMutex(&g_Blw.PathLock);
    BlwAddToList(g_Blw.ProtectedPaths, Path, Length);
    // 重新计数(简单可靠,只发生在配置下发时,频率极低)
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.ProtectedPaths[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.ProtectedPathCount, cnt);
    }
    ExReleaseFastMutex(&g_Blw.PathLock);
}

BOOLEAN
BlwDelProtectedPath(_In_ PCWSTR Path, _In_ USHORT Length)
{
    return BlwRemoveFromGuardedList(g_Blw.ProtectedPaths, &g_Blw.PathLock,
                                    &g_Blw.ProtectedPathCount, Path, Length);
}

//
// 子串匹配(大小写不敏感):目标是否包含任一受保护路径片段。
//
BOOLEAN
BlwPathIsProtected(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    ExAcquireFastMutex(&g_Blw.PathLock);
    matched = BlwMatchInListCtx(g_Blw.ProtectedPaths, g_Blw.ProtectedPathCount, Ctx, 0);
    ExReleaseFastMutex(&g_Blw.PathLock);
    return matched;
}

//
// ===== 文件「内核硬拦截」名单管理(命中即拒绝写/删/改打开)=====
//

void
BlwClearFileHardBlock(void)
{
    ExAcquireFastMutex(&g_Blw.FileHardLock);
    RtlZeroMemory(g_Blw.FileHardBlock, sizeof(g_Blw.FileHardBlock));
    InterlockedExchange(&g_Blw.FileHardCount, 0);
    ExReleaseFastMutex(&g_Blw.FileHardLock);
}

void
BlwAddFileHardBlock(_In_ PCWSTR Path, _In_ USHORT Length)
{
    if (BlwRejectDeadPathPattern("FileHardBlock entry REJECTED (drive-letter pattern never matches)",
                                 Path, Length, BLW_POLICY_DIRTY_FILEHARD)) {
        return;
    }

    ExAcquireFastMutex(&g_Blw.FileHardLock);
    BlwAddToList(g_Blw.FileHardBlock, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.FileHardBlock[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.FileHardCount, cnt);
    }
    ExReleaseFastMutex(&g_Blw.FileHardLock);
}

BOOLEAN
BlwDelFileHardBlock(_In_ PCWSTR Path, _In_ USHORT Length)
{
    return BlwRemoveFromGuardedList(g_Blw.FileHardBlock, &g_Blw.FileHardLock,
                                    &g_Blw.FileHardCount, Path, Length);
}

BOOLEAN
BlwFileIsHardBlocked(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    ExAcquireFastMutex(&g_Blw.FileHardLock);
    matched = BlwMatchInListCtx(g_Blw.FileHardBlock, g_Blw.FileHardCount, Ctx, 0);
    ExReleaseFastMutex(&g_Blw.FileHardLock);
    return matched;
}

//
// ===== 自保护足迹名单管理(owner-aware 反勒索:保护本产品完整内容)=====
//

void
BlwClearSelfGuard(void)
{
    ExAcquireFastMutex(&g_Blw.SelfGuardLock);
    RtlZeroMemory(g_Blw.SelfGuard, sizeof(g_Blw.SelfGuard));
    InterlockedExchange(&g_Blw.SelfGuardCount, 0);
    ExReleaseFastMutex(&g_Blw.SelfGuardLock);
}

void
BlwAddSelfGuard(_In_ PCWSTR Path, _In_ USHORT Length)
{
    // SelfGuard【不持久化】(见 Protocol.h 的 BLW_CMD_ADD_SELFGUARD),故 DirtyBit 传 0:
    // 拒收只需记一行日志,磁盘上没有需要自愈的副本。
    if (BlwRejectDeadPathPattern("SelfGuard entry REJECTED (drive-letter pattern never matches)",
                                 Path, Length, 0)) {
        return;
    }

    ExAcquireFastMutex(&g_Blw.SelfGuardLock);
    BlwAddToList(g_Blw.SelfGuard, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.SelfGuard[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.SelfGuardCount, cnt);
    }
    ExReleaseFastMutex(&g_Blw.SelfGuardLock);
}

BOOLEAN
BlwFileIsSelfGuarded(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    ExAcquireFastMutex(&g_Blw.SelfGuardLock);
    matched = BlwMatchInListCtx(g_Blw.SelfGuard, g_Blw.SelfGuardCount, Ctx, 0);
    ExReleaseFastMutex(&g_Blw.SelfGuardLock);
    return matched;
}

//
// ===== 系统映像护栏:「禁止执行 / 禁止加载」两份名单的准入校验 =====
//
// 真实事故:一次「确认恶意」的裁决把 actor 的映像路径钉进了 FileExecBlock,而那个 actor 是
// cmd.exe —— 真正的恶意行为是一个 .bat 借 cmd.exe 去跑危险命令。由于本驱动的名单按【去盘符、
// 大小写不敏感的子串】匹配,`\WINDOWS\SYSTEM32\CMD.EXE` 这一条的实际语义是「禁止任何 cmd.exe
// 启动」:所有 .bat/.cmd 脚本、绝大多数安装包与编译脚本全部起不来。又因为基线会被写回注册表,
// 杀服务、重装服务、重启全都救不回来 —— 只能手工改注册表。netsh.exe 也被同样钉过一次。
//
// 架构上早有定论(见 BlwCreateProcessNotifyEx 里命令行硬拦那段注释):System32 里那些【本体
// 可信、常被借用】的 LOLBin,要拦的是「那一次用法」,归 CmdHardBlock(命令行 token 合取匹配)
// 管;绝不能用 FileExecBlock 去拦「那个程序本身」。本函数把这条约定落成代码里的准入校验。
//
// 判据(精确,不过度):仅当待加入的模式串会【连带命中真实的系统二进制】时才拒绝 —— 也就是
// 该模式串是下表某条完整路径的子串。于是:
//     `\WINDOWS\SYSTEM32\CMD.EXE`、`\SYSTEM32\CMD.EXE`、`\CMD.EXE`  -> 拒绝(会挡住真 cmd)
//     `\USERS\X\APPDATA\LOCAL\TEMP\CMD.EXE`                        -> 放行(伪装成 cmd 的样本,
//                                                                     按子串匹配挡不到真 cmd)
// 即:「误封系统组件」被堵死,而「拦截改名成系统程序名的样本」这个能力一点没丢。
// 附带好处:荒谬的超短模式(如单个字符)必然是某条系统路径的子串,也会在此被拒 —— 那种模式
// 等于「禁止一切程序启动」。
//
// 另注:关键系统进程还有一道运行时防 BugCheck 0xEF 的护栏(exec-block 判定处的 !critical,
// 见 BlwIsCriticalSystemProcess)。这里是更早的一道 —— 根本不让它们进名单,连带把「进了名单
// 还要被写回注册表」的持久化污染一并挡住。
//
// 本表只用于【拒绝执行 / 拒绝加载】两份名单的准入,绝不可用于 ProtectedPaths / FileHardBlock:
// 那两份是【保护】语义(阻止别人改写 sethc.exe 之类),里面本来就该有系统路径。
//
// 表中每条必须是【大写、去盘符】的完整路径:比较时候选串会被大写化,表侧不再做归一化。
//
#define BLW_SYS_BOTH(n)  L"\\WINDOWS\\SYSTEM32\\" n, L"\\WINDOWS\\SYSWOW64\\" n

static const PCWSTR kBlwSystemImages[] = {
    // --- 脚本宿主 / 命令解释器:拦住等于禁掉一整类脚本、安装包与编译脚本 ---
    BLW_SYS_BOTH(L"CMD.EXE"),
    BLW_SYS_BOTH(L"WSCRIPT.EXE"),
    BLW_SYS_BOTH(L"CSCRIPT.EXE"),
    BLW_SYS_BOTH(L"MSHTA.EXE"),
    L"\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE",
    L"\\WINDOWS\\SYSWOW64\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE",

    // --- 其余 LOLBin:滥用归 CmdHardBlock 按「用法」拦,本体绝不禁止执行 ---
    BLW_SYS_BOTH(L"RUNDLL32.EXE"),
    BLW_SYS_BOTH(L"REGSVR32.EXE"),
    BLW_SYS_BOTH(L"NETSH.EXE"),
    BLW_SYS_BOTH(L"CERTUTIL.EXE"),
    BLW_SYS_BOTH(L"BITSADMIN.EXE"),
    BLW_SYS_BOTH(L"SCHTASKS.EXE"),
    BLW_SYS_BOTH(L"MSIEXEC.EXE"),
    BLW_SYS_BOTH(L"REG.EXE"),
    BLW_SYS_BOTH(L"SC.EXE"),
    BLW_SYS_BOTH(L"WMIC.EXE"),
    BLW_SYS_BOTH(L"VSSADMIN.EXE"),
    BLW_SYS_BOTH(L"BCDEDIT.EXE"),
    BLW_SYS_BOTH(L"WBADMIN.EXE"),
    BLW_SYS_BOTH(L"FORFILES.EXE"),

    // --- 关键系统进程:拦住 = CRITICAL_PROCESS_DIED(0xEF)/ 系统起不来 ---
    BLW_SYS_BOTH(L"SVCHOST.EXE"),
    L"\\WINDOWS\\SYSTEM32\\SMSS.EXE",
    L"\\WINDOWS\\SYSTEM32\\CSRSS.EXE",
    L"\\WINDOWS\\SYSTEM32\\WININIT.EXE",
    L"\\WINDOWS\\SYSTEM32\\WINLOGON.EXE",
    L"\\WINDOWS\\SYSTEM32\\SERVICES.EXE",
    L"\\WINDOWS\\SYSTEM32\\LSASS.EXE",
    L"\\WINDOWS\\SYSTEM32\\LSAISO.EXE",
    L"\\WINDOWS\\SYSTEM32\\FONTDRVHOST.EXE",
    L"\\WINDOWS\\SYSTEM32\\DWM.EXE",
    L"\\WINDOWS\\SYSTEM32\\CONHOST.EXE",
    L"\\WINDOWS\\SYSTEM32\\DLLHOST.EXE",
    L"\\WINDOWS\\SYSTEM32\\TASKHOSTW.EXE",
    L"\\WINDOWS\\SYSTEM32\\SPOOLSV.EXE",
    L"\\WINDOWS\\SYSTEM32\\WERFAULT.EXE",
    L"\\WINDOWS\\EXPLORER.EXE",

    // --- 核心运行库:禁止加载会让几乎所有进程都起不来 ---
    BLW_SYS_BOTH(L"NTDLL.DLL"),
    BLW_SYS_BOTH(L"KERNEL32.DLL"),
    BLW_SYS_BOTH(L"KERNELBASE.DLL"),
    BLW_SYS_BOTH(L"USER32.DLL"),
    BLW_SYS_BOTH(L"ADVAPI32.DLL"),
    BLW_SYS_BOTH(L"MSVCRT.DLL"),
    BLW_SYS_BOTH(L"UCRTBASE.DLL"),
    BLW_SYS_BOTH(L"COMBASE.DLL"),
    BLW_SYS_BOTH(L"OLE32.DLL"),
    BLW_SYS_BOTH(L"RPCRT4.DLL"),
    BLW_SYS_BOTH(L"SECHOST.DLL"),
    BLW_SYS_BOTH(L"GDI32.DLL"),
    BLW_SYS_BOTH(L"SHELL32.DLL"),
    BLW_SYS_BOTH(L"WS2_32.DLL"),
    BLW_SYS_BOTH(L"CRYPT32.DLL"),
    BLW_SYS_BOTH(L"BCRYPT.DLL"),
    BLW_SYS_BOTH(L"BCRYPTPRIMITIVES.DLL"),
};

//
// 模式串是否会连带命中某条真实的系统映像路径(判据见上)。
//
// 只在「配置下发 / 基线载入」路径上调用(PASSIVE_LEVEL,频率极低,一次几十条),因此直接朴素
// 逐条滑窗扫描,不引入任何预处理或额外分配;不要求 Pattern 以 NUL 结尾。
//
static BOOLEAN
BlwPatternHitsSystemImage(_In_opt_ PCWSTR Pattern, _In_ USHORT Chars)
{
    ULONG i;

    if (Pattern == NULL || Chars == 0) {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(kBlwSystemImages); i++) {
        PCWSTR sys = kBlwSystemImages[i];
        USHORT sysChars = 0;
        USHORT s;

        while (sys[sysChars] != L'\0') {
            sysChars++;
        }
        if (Chars > sysChars) {
            continue;   // 模式比系统路径长,不可能是它的子串
        }

        for (s = 0; (USHORT)(s + Chars) <= sysChars; s++) {
            USHORT k;
            for (k = 0; k < Chars; k++) {
                // 表侧已是大写,候选逐字符大写化 -> 等价于大小写不敏感比较。
                if (sys[s + k] != BlwUpcaseChar(Pattern[k])) {
                    break;
                }
            }
            if (k == Chars) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

//
// ===== 「禁止加载」模块名单管理(命中且执行/映射意图打开即拒绝)=====
//

void
BlwClearFileNoLoad(void)
{
    ExAcquireFastMutex(&g_Blw.FileNoLoadLock);
    RtlZeroMemory(g_Blw.FileNoLoad, sizeof(g_Blw.FileNoLoad));
    InterlockedExchange(&g_Blw.FileNoLoadCount, 0);
    ExReleaseFastMutex(&g_Blw.FileNoLoadLock);
}

void
BlwAddFileNoLoad(_In_ PCWSTR Path, _In_ USHORT Length)
{
    // 准入校验 1:带盘符的模式永远匹配不上规范名 —— 现场那 3 条死条目就在这份名单里。
    if (BlwRejectDeadPathPattern("NoLoad entry REJECTED (drive-letter pattern never matches)",
                                 Path, Length, BLW_POLICY_DIRTY_NOLOAD)) {
        return;
    }
    // 准入校验 2:禁止加载核心运行库(ntdll/kernel32/...)等于让系统上几乎所有进程都起不来。
    if (BlwPatternHitsSystemImage(Path, Length)) {
        BlwLogPattern("NoLoad entry REJECTED (would block a system image)", Path, Length);
        BlwMarkDeadEntryDrop(BLW_POLICY_DIRTY_NOLOAD);
        return;
    }

    ExAcquireFastMutex(&g_Blw.FileNoLoadLock);
    BlwAddToList(g_Blw.FileNoLoad, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.FileNoLoad[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.FileNoLoadCount, cnt);
    }
    ExReleaseFastMutex(&g_Blw.FileNoLoadLock);
}

//
// 【为什么这两份名单用锚定匹配,而受保护/硬拦名单仍用子串匹配】
//
// FileNoLoad 与 FileExecBlock 是【拒绝】语义,误判的代价是「某个模块加载不了 / 某个程序
// 永远起不来」,而且名单跨重启续留 —— 所以判据必须比「保护」类名单收得更紧。子串匹配会
// 连带命中一批并非被判定为恶意的对象:名单里有 `\USERS\U\TEMP\A.EXE` 时,它同时挡住
//     ...\Temp\a.exe.bak        (备份文件)
//     ...\Temp\a.exe\sub\x.dll  (恰好叫 a.exe 的目录下的任何模块)
// 锚定判据要求「从目录边界起、到串尾(或数据流分隔符 ':')止」,把这类误伤去掉,同时
// 保住两种真实用法:用户态下发的「去盘符完整路径」,以及 set-baseline-policy.ps1 文档里
// 的文件名片段写法(-FileExecBlock '\evil.exe')。完整判据与取舍见 MatchCore.c 的
// BLW_MATCH_MODE 注释;各形态的断言在 cpp/tests/DriverMatchTest.c 第 [7] 组。
//
// ProtectedPaths / FileHardBlock / SelfGuard / 注册表两份名单【保持子串语义】:它们是
// 保护语义,里面本来就有 "\START MENU\PROGRAMS\STARTUP\" 这类出现在路径中段的目录片段。
//
BOOLEAN
BlwDelFileNoLoad(_In_ PCWSTR Path, _In_ USHORT Length)
{
    return BlwRemoveFromGuardedList(g_Blw.FileNoLoad, &g_Blw.FileNoLoadLock,
                                    &g_Blw.FileNoLoadCount, Path, Length);
}

BOOLEAN
BlwFileIsNoLoad(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    ExAcquireFastMutex(&g_Blw.FileNoLoadLock);
    matched = BlwMatchInListAnchoredCtx(g_Blw.FileNoLoad, g_Blw.FileNoLoadCount, Ctx);
    ExReleaseFastMutex(&g_Blw.FileNoLoadLock);
    return matched;
}

//
// ===== 「禁止执行」名单管理(进程创建命中即内核本地拒绝创建)=====
//
// 与 FileNoLoad 结构/接口完全一致,仅用途不同:此名单在进程创建回调里对新进程
// 映像路径做子串匹配,命中即把 CreationStatus 置为拒绝,使恶意样本无法启动。
//

void
BlwClearFileExecBlock(void)
{
    ExAcquireFastMutex(&g_Blw.FileExecBlockLock);
    RtlZeroMemory(g_Blw.FileExecBlock, sizeof(g_Blw.FileExecBlock));
    InterlockedExchange(&g_Blw.FileExecBlockCount, 0);
    ExReleaseFastMutex(&g_Blw.FileExecBlockLock);
}

void
BlwAddFileExecBlock(_In_ PCWSTR Path, _In_ USHORT Length)
{
    // 准入校验 1:带盘符的模式永远匹配不上规范名,只会白占槽并跨重启续留。
    if (BlwRejectDeadPathPattern("ExecBlock entry REJECTED (drive-letter pattern never matches)",
                                 Path, Length, BLW_POLICY_DIRTY_EXECBLOCK)) {
        return;
    }
    // 准入校验 2:绝不收录会连带挡住系统组件的模式(cmd.exe / netsh.exe 那次事故就是这么来的)。
    // LOLBin 的滥用请走 CmdHardBlock —— 那才是按「用法」拦、而不是按「程序」拦的地方。
    if (BlwPatternHitsSystemImage(Path, Length)) {
        BlwLogPattern("ExecBlock entry REJECTED (would block a system image)", Path, Length);
        BlwMarkDeadEntryDrop(BLW_POLICY_DIRTY_EXECBLOCK);
        return;
    }

    ExAcquireFastMutex(&g_Blw.FileExecBlockLock);
    BlwAddToList(g_Blw.FileExecBlock, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.FileExecBlock[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.FileExecBlockCount, cnt);
    }
    ExReleaseFastMutex(&g_Blw.FileExecBlockLock);
}

BOOLEAN
BlwDelFileExecBlock(_In_ PCWSTR Path, _In_ USHORT Length)
{
    return BlwRemoveFromGuardedList(g_Blw.FileExecBlock, &g_Blw.FileExecBlockLock,
                                    &g_Blw.FileExecBlockCount, Path, Length);
}

// 锚定匹配,理由同 BlwFileIsNoLoad 上方那段说明。
BOOLEAN
BlwFileIsExecBlocked(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    ExAcquireFastMutex(&g_Blw.FileExecBlockLock);
    matched = BlwMatchInListAnchoredCtx(g_Blw.FileExecBlock, g_Blw.FileExecBlockCount, Ctx);
    ExReleaseFastMutex(&g_Blw.FileExecBlockLock);
    return matched;
}

//
// 构造文件事件并【仅异步上报】(不等待裁决)。拦截与否完全由内核本地
// 配置(受保护路径表)决定 —— 调用方在确认命中受保护路径后才调用本函数,
// 这里只负责把"已被内核拦截"的事实异步告知用户态供记录/告警。
// 绝不发同步 IPC,绝不阻塞 I/O 线程。
//
static void
BlwReportFileBlock(_In_ ULONG eventType, _In_ PCUNICODE_STRING fileName)
{
    if (!g_Blw.Active) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    BlwReportEvent(eventType, HandleToULong(PsGetCurrentProcessId()), 0,
                   fileName, NULL, 0, 0);
}

//
// 构造「文件行为遥测」事件并 fire-and-forget 上报(不阻断 I/O)。
// 与 BlwReportFileBlock 的区别:这是【未命中任何名单】的正常文件操作,内核不拦截,
// 仅把"某进程对某文件做了重命名/删除标记"这一事实异步告知用户态,供勒索时序聚合。
// 仅在 FileTelemetryEnabled 开启时上报;PASSIVE_LEVEL;绝不发同步 IPC。
//
static void
BlwReportFileTelemetry(_In_ ULONG eventType, _In_ PCUNICODE_STRING fileName)
{
    if (!g_Blw.Active) {
        return;
    }
    if (g_Blw.FileTelemetryEnabled == 0) {
        return;  // 遥测未开启
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    // Type 恒为 BlwEventFileModify;ParentPid 复用为原始操作类型(删除标记 / 重命名),供用户态区分。
    // 入队即返回,队列满则丢弃(遥测可丢)。
    BlwReportEvent(BlwEventFileModify, HandleToULong(PsGetCurrentProcessId()), eventType,
                   fileName, NULL, 0, 0);
}

//
// ===== I/O 预操作回调 =====
//

//
// ===== 释放物可见面:落地区新建可执行 / 脚本文件 =====
//
// 【补的是什么缺口】BlwPreCreate 原先只上报 delete-on-close,「新建了一个文件」这件事在驱动
// 模式下完全不可见。于是 dropper 的典型动作 —— 往 %TEMP% / AppData 写一个 payload.exe ——
// 用户态在驱动模式下看不到,释放物污点、「写出即执行」关联、落盘即扫都因此没有触发点。
// (无驱动的 ETW 模式反而有:EtwProcessEventSource 订阅了 kFileCreateNew。驱动模式不该更瞎。)
//
// 【为什么要两层门槛】对「所有新建文件」上报会直接压垮上报通道(系统每秒新建大量临时文件)。
// 所以必须同时满足:
//   1) 位于【落地区】—— 用卷相对锚定前缀判定,绝不用子串包含(C:\Users\u\ProgramData\ 这种
//      用户自建目录会骗过子串判定,见 BlwVolumeRelativeOffset 上方那段事故说明);
//   2) 扩展名是【可执行 / 脚本 / 安装包】之一。
// 两层叠起来,事件量与 ETW 那条(isDroppedExecutable)同量级,已在真机跑过量级的那一条。
//
// 【已知代价】pre-create 不知道创建最终是否成功,会有少量「其实没创建成」的上报。要消掉它
// 得新注册一个 post-create 回调,那是更高的风险(回调出错即蓝屏,而本机不能加载测试),
// 收益只是去掉少量噪声 —— 刻意不做。用户态拿到路径后本来就要核实文件是否存在。
//
// 落地区【刻意不含 \Program Files\ 等标准安装目录】:那里普通用户写不进去,新建可执行文件
// 基本都是正常安装/更新行为,上报只会是噪声。
//
static BOOLEAN
BlwIsDroppedPayload(_In_opt_ PCWSTR Path, _In_ USHORT Chars)
{
    // 落地区(卷相对锚定前缀)。\Users\ 已覆盖 AppData / Temp / Downloads / Desktop / Public。
    static const BLW_NAME_ENTRY kDropZones[] = {
        BLW_NAME(L"\\Users\\"),
        BLW_NAME(L"\\ProgramData\\"),
        BLW_NAME(L"\\Windows\\Temp\\"),
        BLW_NAME(L"\\PerfLogs\\"),
        BLW_NAME(L"\\$Recycle.Bin\\"),
    };

    // 可执行 / 脚本 / 安装包扩展名。与用户态 isDroppedExecutable 的口径对齐。
    static const BLW_NAME_ENTRY kPayloadExt[] = {
        BLW_NAME(L".exe"),  BLW_NAME(L".dll"),  BLW_NAME(L".sys"),  BLW_NAME(L".scr"),
        BLW_NAME(L".com"),  BLW_NAME(L".pif"),  BLW_NAME(L".cpl"),  BLW_NAME(L".ocx"),
        BLW_NAME(L".drv"),  BLW_NAME(L".bat"),  BLW_NAME(L".cmd"),  BLW_NAME(L".ps1"),
        BLW_NAME(L".psm1"), BLW_NAME(L".vbs"),  BLW_NAME(L".vbe"),  BLW_NAME(L".js"),
        BLW_NAME(L".jse"),  BLW_NAME(L".wsf"),  BLW_NAME(L".wsh"),  BLW_NAME(L".hta"),
        BLW_NAME(L".jar"),  BLW_NAME(L".msi"),  BLW_NAME(L".msp"),  BLW_NAME(L".lnk"),
    };

    USHORT off;
    ULONG  i;
    BOOLEAN inZone = FALSE;

    if (Path == NULL || Chars == 0) {
        return FALSE;
    }

    off = BlwVolumeRelativeOffset(Path, Chars);
    if (off == 0) {
        return FALSE;   // 认不出卷前缀(网络路径等)-> 不上报,与其它锚定判定同一 fail-safe 方向
    }

    for (i = 0; i < RTL_NUMBER_OF(kDropZones); i++) {
        if (BlwStartsWithCI(Path + off, (USHORT)(Chars - off),
                            kDropZones[i].Name, kDropZones[i].Chars)) {
            inZone = TRUE;
            break;
        }
    }
    if (!inZone) {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(kPayloadExt); i++) {
        const USHORT extChars = kPayloadExt[i].Chars;

        if (Chars < extChars) {
            continue;
        }
        if (BlwStartsWithCI(Path + (Chars - extChars), extChars,
                            kPayloadExt[i].Name, extChars)) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 本次 CREATE 的 Disposition 是否会【新建或覆盖】文件内容(而不是单纯打开已有文件)。
// Disposition 在 Create.Options 的最高字节里。
//
static BOOLEAN
BlwCreateDispositionWrites(_In_ ULONG CreateOptions)
{
    const ULONG disposition = (CreateOptions >> 24) & 0xFF;

    return (disposition == FILE_SUPERSEDE ||
            disposition == FILE_CREATE ||
            disposition == FILE_OPEN_IF ||
            disposition == FILE_OVERWRITE ||
            disposition == FILE_OVERWRITE_IF);
}

//
// IRP_MJ_CREATE:仅关注"打开即删除"(FILE_DELETE_ON_CLOSE)。
//
FLT_PREOP_CALLBACK_STATUS
BlwPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    ULONG createOptions;
    ACCESS_MASK desiredAccess;
    BOOLEAN deleteOnClose;
    BOOLEAN writeOrDeleteIntent;
    BOOLEAN executeIntent;
    BOOLEAN needHardCheck;
    BOOLEAN needProtCheck;
    BOOLEAN needNoLoadCheck;
    BOOLEAN needSelfGuardCheck;
    BOOLEAN needTelemetry;
    BOOLEAN needDropWatch;
    ULONG   actorPid = 0;   // 惰性取值:只有确实要判定主体身份时才取,不给最快路径添开销
    BLW_MATCH_CTX ctx;   // 预归一化的文件名(仅在确实需要查名单时才填充,见下方快速放行)

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    // 【自足基线】不再因用户态未连接而整体放行:本地硬拦截 / 禁止加载 / 受保护路径名单
    // 在无客户端时依旧生效。空配置由下方「各名单计数全为 0 且遥测关」的快速路径放行(零解析开销);
    // 遥测上报函数(BlwReportFileTelemetry/BlwReportFileBlock)内部自带 Active 判空。

    // 内核态发起的 I/O 不拦截,避免影响系统
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // 页面文件的打开【绝不】干预:内存管理器打开 / 扩展页面文件时若被过滤器拒绝或拖慢,
    // 后果是死锁或 BugCheck。这类打开本来就是内核态发起(已被上面拦掉),这里再显式挡一道,
    // 免得将来有人放宽上面那条 RequestorMode 判断时把这个前提一起弄丢。
    //
    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // 卷本身的打开(裸设备句柄:既无文件名、也无相对打开的父对象)直接放行。
    // FltGetFileNameInformation 对这种打开必然失败,原来会白跑一次昂贵调用再由失败分支放行;
    // 这里用两次字段判断把它提前挡掉。也不影响防护:通过裸卷句柄改的是扇区,
    // 本来就不经过文件级过滤,不是本回调能覆盖的面。
    //
    if (Data->Iopb->TargetFileObject != NULL &&
        Data->Iopb->TargetFileObject->FileName.Length == 0 &&
        Data->Iopb->TargetFileObject->RelatedFileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    createOptions = Data->Iopb->Parameters.Create.Options;
    deleteOnClose = (createOptions & FILE_DELETE_ON_CLOSE) ? TRUE : FALSE;

    // 取本次打开请求的期望访问权限(写/删/追加/改属性即视为「篡改意图」)。
    desiredAccess = 0;
    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }
    writeOrDeleteIntent = (deleteOnClose ||
        (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES |
                          FILE_WRITE_EA | DELETE | WRITE_DAC | WRITE_OWNER))) ? TRUE : FALSE;

    // 执行/映射意图:DLL/EXE 加载会以 FILE_EXECUTE 打开镜像。据此识别「加载」类打开,
    // 用于「禁止加载」名单的精准拦截(只拦执行映射,不影响把该文件当普通数据读)。
    executeIntent = (desiredAccess & FILE_EXECUTE) ? TRUE : FALSE;

    // 已封禁主体(情报确认恶意):拒绝其带【写/删/执行意图】的文件打开 —— 挡住投放/加密/删除/加载。
    // 只读打开放行(减少其退出前的病态情况,进程随后会被结束)。封禁集非空时才查(空则零开销),
    // 且无需解析文件名,开销极低。
    if ((writeOrDeleteIntent || executeIntent) && g_Blw.BannedPidCount > 0) {
        actorPid = HandleToULong(PsGetCurrentProcessId());
        if (BlwPidIsBanned(actorPid)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    // 需要做硬拦截检查:有硬拦截名单 且 本次是写/删意图打开(只读打开一律放行)。
    needHardCheck = (g_Blw.FileHardCount > 0 && writeOrDeleteIntent);
    // 需要做受保护路径检查(原逻辑):有受保护路径 且 本次是 delete-on-close。
    needProtCheck = (g_Blw.ProtectedPathCount > 0 && deleteOnClose);
    // 需要做「禁止加载」检查:有禁止加载名单 且 本次是执行/映射意图打开。
    needNoLoadCheck = (g_Blw.FileNoLoadCount > 0 && executeIntent);
    // 需要做「自保护足迹」检查:有自保名单 且 本次是写/删/改名意图打开(只读放行,不影响本产品被加载执行)。
    needSelfGuardCheck = (g_Blw.SelfGuardCount > 0 && writeOrDeleteIntent);

    // 需要做「文件行为遥测」:遥测开启 且 本次是 delete-on-close(打开即删除)。
    // 仅针对 delete-on-close 这一稀有且高价值的删除信号,不对普通写打开做任何处理,
    // 因此不引入每次 CREATE 的额外开销。
    // FileTelemetryEnabled 是 volatile LONG,直接读即为原子读;原来用 InterlockedCompareExchange
    // 只为「原子读」,却在每次 CREATE / SET_INFO / WRITE 上付出一次带锁的 cmpxchg,纯属浪费。
    needTelemetry = (g_Blw.FileTelemetryEnabled != 0) && deleteOnClose;

    //
    // 需要做「释放物可见面」上报:遥测开启 且 本次打开会新建/覆盖文件内容 且 带写意图。
    // 排除 delete-on-close(那是删除信号,由 needTelemetry 负责,两者互斥)。
    // 这里只是【廉价的前置筛选】——真正的两层门槛(落地区 + 可执行扩展名)在下面拿到
    // 规范名之后才判,见 BlwIsDroppedPayload。
    //
    needDropWatch = (g_Blw.FileTelemetryEnabled != 0) && writeOrDeleteIntent && !deleteOnClose &&
                    BlwCreateDispositionWrites(createOptions);

    // 六类都不需要 -> 直接放行,绝不解析文件名(性能关键)。
    // FltGetFileNameInformation 是昂贵调用,系统每秒数千次 CREATE 全做会显著拖慢 I/O。
    if (!needHardCheck && !needProtCheck && !needNoLoadCheck && !needSelfGuardCheck &&
        !needTelemetry && !needDropWatch) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // 【别把 NORMALIZED 改成 OPENED】
    //
    // 这一句是本回调剩下最贵的开销:自保名单启用后,系统里每一个「带写意图的打开」都要走它。
    // 因此它看起来像个显而易见的优化点 —— FLT_FILE_NAME_OPENED 便宜得多,微软也确实推荐在
    // pre-create 阶段用 OPENED 而非 NORMALIZED。但对本产品【不能换】:
    //
    //   * OPENED 返回的是「调用方当初怎么写就怎么给」的名字,可能是 8.3 短名
    //     (C:\PROGRA~1\...)、也可能是挂载点 / 符号链接形式的路径;
    //   * 本驱动的所有名单都是【长名子串】匹配。攻击者只要用短名或换一条挂载路径打开同一个
    //     文件,OPENED 给出的名字就匹配不上,自保 / 硬拦截 / 禁止加载全部被绕过。
    //   * NORMALIZED 会把短名、挂载点、符号链接统一解析成规范长名,是这里唯一不可绕过的形式。
    //
    // 也就是说这里是「拿性能换不可绕过」,是有意的取舍,不是漏改。真要降这块成本,正确方向是
    // 继续收窄「什么情况才需要取名字」(上面那批 needXxx 判断和快速放行),而不是换名字格式。
    //
    // 已知代价:挂了网络卷(映射盘)时,对该卷的规范化查询会走网络,明显更慢。目前接受 ——
    // 勒索加密网络共享同样要被拦,不能为省这点开销把网络卷排除在防护之外。
    //
    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    //
    // 把文件名【一次性】大写化,下面最多四个名单的匹配全部复用这份归一化结果。
    // 原实现每个名单都要把整条路径重新归一化一遍(最坏四遍),而路径动辄上百字符。
    //
    BlwPrepareMatch(&ctx, &nameInfo->Name);

    //
    // 1) 文件硬拦截:命中名单且为写/删意图打开 -> 内核本地直接拒绝(只读打开已被
    //    needHardCheck 排除,因此读取这些文件不受影响)。比受保护路径更强:不仅防
    //    删除/重命名,还防内容篡改(任何带写权限的打开都被拒)。零 IPC、零等待。
    //
    if (needHardCheck && BlwFileIsHardBlocked(&ctx)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        BlwReportFileBlock(BlwEventFileDelete, &nameInfo->Name);  // 异步记录,不阻塞
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;
    }

    //
    // 1a) 自保护足迹(owner-aware 反勒索):命中本产品完整内容路径 且 为写/删/改名意图打开 且
    //     发起者不是本产品自身受保护进程 -> 内核本地拒绝。勒索病毒 / 任何外部进程都无法加密 /
    //     篡改 / 删除本产品的任何文件;本产品自身进程(BlwPidIsProtected)豁免,可正常读写自己
    //     的数据(信誉缓存 / 规则 / 日志 / 隔离区等)。只读打开不受影响(writeOrDeleteIntent
    //     已排除),故本产品二进制仍可被系统正常加载执行。先判属主(便宜的 PID 查表)再匹配路径。
    //
    if (needSelfGuardCheck) {
        if (actorPid == 0) {
            actorPid = HandleToULong(PsGetCurrentProcessId());   // 上面封禁判定没取过才取
        }
        if (!BlwPidIsProtected(actorPid) && BlwFileIsSelfGuarded(&ctx)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            BlwReportFileBlock(BlwEventFileDelete, &nameInfo->Name);  // 异步记录,不阻塞
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_COMPLETE;
        }
    }

    //
    // 1b) 禁止加载名单:命中且本次为执行/映射意图打开 -> 内核本地直接拒绝。
    //     使已确认恶意的侧载 DLL/EXE 无法被任何进程加载(即便宿主是合法签名进程)。
    //     只读数据访问不受影响(executeIntent 已排除)。专治白加黑。
    //
    if (needNoLoadCheck && BlwFileIsNoLoad(&ctx)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        BlwReportFileBlock(BlwEventImageBlocked, &nameInfo->Name);  // 异步记录,不阻塞
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;
    }

    //
    // 2) 受保护路径(原逻辑):仅针对 delete-on-close 的删除意图。命中即拒绝。
    //    受保护路径是用户态显式下发的高价值反篡改目标(SAM/hosts/sethc/启动项/任务计划等)。
    //
    //    对本产品自身受保护进程豁免 —— 与自保足迹、以及 BlwPreSetInformation 里的同名判定
    //    保持同一口径。ProtectedPaths 含 "\START MENU\PROGRAMS\STARTUP\" 这类宽目录,不豁免
    //    就等于连产品自己的足迹清理都删不掉启动目录里的恶意持久化项(详见 BlwPreSetInformation
    //    处那段说明)。外部进程照旧一律拒绝。
    //
    if (needProtCheck) {
        if (actorPid == 0) {
            actorPid = HandleToULong(PsGetCurrentProcessId());   // 前面几处判定都没取过才取
        }
        if (!BlwPidIsProtected(actorPid) && BlwPathIsProtected(&ctx)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            BlwReportFileBlock(BlwEventFileDelete, &nameInfo->Name);  // 异步记录,不阻塞
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_COMPLETE;   // 拒绝该操作
        }
    }

    //
    // 3) 行为遥测:未命中任何名单的 delete-on-close(打开即删除)。不拦截,
    //    仅 fire-and-forget 上报供用户态勒索时序聚合(批量删除原文件是加密型勒索的常见步骤)。
    //
    if (needTelemetry) {
        BlwReportFileTelemetry(BlwEventFileDelete, &nameInfo->Name);
    }

    //
    // 4) 释放物可见面:落地区新建/覆盖出一个可执行或脚本文件 -> fire-and-forget 上报。
    //    不拦截。这是驱动模式下「dropper 刚把 payload 写出来」的唯一触发点,详见
    //    BlwIsDroppedPayload 上方的说明。
    //
    //    本产品自身进程豁免:更新、隔离区落盘、规则/缓存写入都会在 %ProgramData% 下新建文件,
    //    上报自己等于给用户态制造纯噪声(与 SelfGuard 的属主判定同一口径)。
    //
    //    子类型复用 BlwEventFileRename:用户态按 ParentPid 还原时,非「删除标记」一律映射为
    //    FileWrite(DriverEventSource.cpp 的 BlwEventFileModify 分支),正是这里要的语义
    //    「这个文件被写出来了」。IRP_MJ_WRITE 那条采样上报用的也是同一个子类型,口径一致。
    //    (代价:UI 详情文案会显示成「重命名/移动」。要精确区分得新增子类型 + 改用户态映射,
    //     那是用户态那条线的工作,不在本次驱动改动范围内。)
    //
    if (needDropWatch) {
        if (actorPid == 0) {
            actorPid = HandleToULong(PsGetCurrentProcessId());
        }
        if (!BlwPidIsProtected(actorPid) &&
            BlwIsDroppedPayload(nameInfo->Name.Buffer,
                                (USHORT)(nameInfo->Name.Length / sizeof(WCHAR)))) {
            BlwReportFileTelemetry(BlwEventFileRename, &nameInfo->Name);
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//
// IRP_MJ_SET_INFORMATION:关注删除标记与重命名。
//
FLT_PREOP_CALLBACK_STATUS
BlwPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    FILE_INFORMATION_CLASS infoClass;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    ULONG eventType;
    BOOLEAN interesting = FALSE;
    ULONG   actorPid = 0;   // 惰性取值(同 BlwPreCreate)
    BLW_MATCH_CTX ctx;   // 预归一化的文件名(仅在确实需要查名单时才填充;源名判完后复用于目标名)

    *CompletionContext = NULL;

    // 【自足基线】本地硬拦截 / 受保护路径名单在无客户端时依旧生效;空配置时下方按计数
    // (ProtectedPathCount==0 && FileHardCount==0 && !telemetryOn)快速放行,零解析开销。
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    switch (infoClass) {
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        eventType = BlwEventFileDelete;
        interesting = TRUE;
        break;
    case FileRenameInformation:
    case FileRenameInformationEx:
        eventType = BlwEventFileRename;
        interesting = TRUE;
        break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!interesting) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 已封禁主体(情报确认恶意):拒绝其删除标记 / 重命名。封禁集非空时才查(空则零开销),无需解析文件名。
    if (g_Blw.BannedPidCount > 0) {
        actorPid = HandleToULong(PsGetCurrentProcessId());
        if (BlwPidIsBanned(actorPid)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    // 既无受保护路径、又无文件硬拦截名单、又未开启文件行为遥测 -> 直接放行,
    // 跳过昂贵的文件名解析(每秒大量 SetInfo 全做会拖慢系统)。
    if (g_Blw.ProtectedPathCount == 0 && g_Blw.FileHardCount == 0 &&
        g_Blw.SelfGuardCount == 0 && g_Blw.FileTelemetryEnabled == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    // 文件名一次性大写化,下面三个名单的匹配复用同一份归一化结果。
    BlwPrepareMatch(&ctx, &nameInfo->Name);

    // 自保护足迹(owner-aware 反勒索):非本产品受保护进程对本产品文件的删除标记 / 重命名 ->
    // 内核本地拒绝(挡住勒索对本产品文件的改名 / 删除)。本产品自身进程豁免。
    if (g_Blw.SelfGuardCount > 0) {
        if (actorPid == 0) {
            actorPid = HandleToULong(PsGetCurrentProcessId());   // 上面封禁判定没取过才取
        }
        if (!BlwPidIsProtected(actorPid) && BlwFileIsSelfGuarded(&ctx)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            BlwReportFileBlock(eventType, &nameInfo->Name);  // 异步记录,不阻塞
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_COMPLETE;
        }
    }

    //
    // 本地裁决:命中文件硬拦截名单 或 受保护路径,即直接拦截删除标记/重命名,不发同步 IPC。
    //
    // 【受保护路径对本产品自身进程豁免】—— 与上面自保足迹那条同一口径(owner-aware)。
    //
    // 为什么必须豁免:ProtectedPaths 是【宽目录子串】,里面有 "\START MENU\PROGRAMS\STARTUP\"
    // 这类目录。原实现在这里不看发起方,于是「删除启动目录里的任何文件」对【所有人】都被拒绝,
    // 包括本产品自己的足迹清理(ThreatRemediator)。后果是:恶意软件往启动目录投个持久化项,
    // 产品能检测、能告警、却永远清不掉它 —— 防篡改把自己的处置能力一起锁死了。
    //
    // 实测(本轮现场):一套「白加黑」侧载(签名壳 DigitalUnit.exe + 被篡改的 QtCore4.dll)
    // 经 BITS 每 19 分钟往启动目录投一个快捷方式,累计 14 个;连 BITS 自己的临时文件清理都被
    // 这条拦住,所以它们只堆积、不消失。人工清理也不行,只能先把驱动停掉 —— 这与产品原则
    // 「始终保留正常的、用户可驱动的处置路径」直接冲突。
    //
    // 豁免只给 BlwPidIsProtected(本产品服务 / UI,由用户态在连接时下发 PID),范围与自保足迹
    // 完全一致。外部进程(含勒索)对受保护路径的删除/改名照旧一律拒绝,防篡改强度不变。
    //
    // 文件硬拦截名单(FileHardBlock)【不】给豁免:它的语义是「这个文件绝不允许被改一次」
    //(hosts / sethc.exe / SAM …),是精确条目而非宽目录,产品自身也没有改它们的正当理由。
    //
    if (g_Blw.FileHardCount > 0 && BlwFileIsHardBlocked(&ctx)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        BlwReportFileBlock(eventType, &nameInfo->Name);  // 异步记录,不阻塞
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;
    }
    if (g_Blw.ProtectedPathCount > 0) {
        if (actorPid == 0) {
            actorPid = HandleToULong(PsGetCurrentProcessId());   // 前面两处判定都没取过才取
        }
        if (!BlwPidIsProtected(actorPid) && BlwPathIsProtected(&ctx)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            BlwReportFileBlock(eventType, &nameInfo->Name);  // 异步记录,不阻塞
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_COMPLETE;
        }
    }

    //
    // ===== 重命名的【目标】名字也要查名单 =====
    //
    // 补上一个真实缺口:上面只匹配了【源】名字,于是「把任意文件改名覆盖到受保护路径上」
    // 这条完全不被拦 —— 攻击者根本不需要写那个受保护文件,只要把自己的文件改名盖上去就行,
    // 源名字不在名单里,一路放行。这等于绕过受保护路径 / 硬拦截 / 自保足迹三道防护。
    //
    // 三个名单的处置强度按各自语义定,避免无谓误报:
    //   * 自保足迹  : 一律拒绝(非本产品进程往本产品目录里改名放东西,本来就该拦;
    //                 owner-aware,本产品自身进程豁免)。与「自保对写意图打开一律拒绝」一致。
    //   * 文件硬拦  : 一律拒绝(语义就是「这个文件绝不允许被改一次」)。与「硬拦对写意图打开
    //                 一律拒绝」一致,不会比现状多拦任何东西。
    //   * 受保护路径: 【仅当 ReplaceIfExists 置位时】拒绝。这类名单是宽目录子串(启动项、任务
    //                 计划目录…),而它现有语义只防「删除 / 改名走原文件」。不带 replace 的改名
    //                 遇到已存在的目标本来就会失败,毁不掉任何受保护文件;真正的破坏是「覆盖」。
    //                 只拦覆盖,既补住了缺口,又不会把「往受保护目录里放一个新文件」这种
    //                 安装器常见行为一并拦掉(那种行为现状也不拦,保持一致)。
    //
    // 取目标名字用 FltGetDestinationFileNameInformation:它会替我们处理「相对某目录句柄改名」
    // (RootDirectory != NULL)与「全限定路径改名」两种形式,并给出规范化名。失败时不拦
    //(fail-open):源名判定已经跑过了,而为了一个取不到名字的边缘情形去拒绝正常改名,
    // 违背「绝不因防御自身把系统弄坏」的底线。
    //
    if (eventType == BlwEventFileRename &&
        (g_Blw.SelfGuardCount > 0 || g_Blw.FileHardCount > 0 || g_Blw.ProtectedPathCount > 0) &&
        KeGetCurrentIrql() == PASSIVE_LEVEL) {

        PFILE_RENAME_INFORMATION ren =
            (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

        if (ren != NULL && ren->FileNameLength > 0) {
            PFLT_FILE_NAME_INFORMATION destInfo = NULL;

            status = FltGetDestinationFileNameInformation(
                FltObjects->Instance,
                FltObjects->FileObject,
                ren->RootDirectory,
                ren->FileName,
                ren->FileNameLength,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                &destInfo);

            if (NT_SUCCESS(status) && destInfo != NULL) {
                BOOLEAN deny = FALSE;
                BOOLEAN replaceIfExists;

                FltParseFileNameInformation(destInfo);

                // 源名判定已结束,ctx 可以复用给目标名 —— 省掉再来一份 1KB 的栈上归一化缓冲。
                BlwPrepareMatch(&ctx, &destInfo->Name);

                // FileRenameInformation 的首字段是 BOOLEAN ReplaceIfExists;
                // FileRenameInformationEx 的首字段是 ULONG Flags,bit0 即 FILE_RENAME_REPLACE_IF_EXISTS。
                // 两者的 RootDirectory / FileNameLength / FileName 布局相同,故上面共用一个结构体读取,
                // 只有首字段需要分开取。
                if (infoClass == FileRenameInformationEx) {
                    ULONG flags = 0;
                    RtlCopyMemory(&flags, ren, sizeof(flags));
                    replaceIfExists = (flags & FILE_RENAME_REPLACE_IF_EXISTS) != 0;
                } else {
                    replaceIfExists = (ren->ReplaceIfExists != FALSE);
                }

                if (g_Blw.SelfGuardCount > 0) {
                    if (actorPid == 0) {
                        actorPid = HandleToULong(PsGetCurrentProcessId());
                    }
                    if (!BlwPidIsProtected(actorPid) && BlwFileIsSelfGuarded(&ctx)) {
                        deny = TRUE;
                    }
                }
                if (!deny && g_Blw.FileHardCount > 0 && BlwFileIsHardBlocked(&ctx)) {
                    deny = TRUE;
                }
                // 受保护路径同样对本产品自身进程豁免(与源名判定处、以及 BlwPreCreate
                // 保持同一口径):否则产品的足迹清理连「把恶意启动项改名搬走」都做不到。
                if (!deny && replaceIfExists && g_Blw.ProtectedPathCount > 0) {
                    if (actorPid == 0) {
                        actorPid = HandleToULong(PsGetCurrentProcessId());
                    }
                    if (!BlwPidIsProtected(actorPid) && BlwPathIsProtected(&ctx)) {
                        deny = TRUE;
                    }
                }

                if (deny) {
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    // 上报目标名:用户态看到的才是「谁想覆盖哪个受保护文件」。
                    BlwReportFileBlock(BlwEventFileRename, &destInfo->Name);
                    FltReleaseFileNameInformation(destInfo);
                    FltReleaseFileNameInformation(nameInfo);
                    return FLT_PREOP_COMPLETE;
                }

                FltReleaseFileNameInformation(destInfo);
            }
        }
    }

    // 未命中任何名单的正常删除/重命名:不拦截,但若遥测开启则 fire-and-forget 上报,
    // 供用户态做勒索行为时序聚合(批量改写 / 扩展名同化 / 蜜罐触碰)。
    BlwReportFileTelemetry(eventType, &nameInfo->Name);

    //
    // 重命名额外上报【目标名】。「先写 x.tmp 再改名成 x.exe」是投递载荷的常见手法:只报源名,
    // 用户态记下的是一个已经不存在的 x.tmp,真正落地的 x.exe 从未出现 —— 释放物污点与
    // 「写出即执行」关联都因此漏掉它。复用 BlwReportFileTelemetry(同为 FileModify + 原始
    // 操作类型 = 重命名),协议不变,也不进用户态的裁决追踪。
    //
    // 门槛与 BlwReportFileTelemetry 内部相同,这里提前判一次只是为了在遥测关闭时
    // 省掉 FltGetDestinationFileNameInformation 的开销。取不到目标名就算了(fail-open)。
    //
    if (eventType == BlwEventFileRename && g_Blw.Active && g_Blw.FileTelemetryEnabled != 0 &&
        KeGetCurrentIrql() == PASSIVE_LEVEL) {

        PFILE_RENAME_INFORMATION ren =
            (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

        if (ren != NULL && ren->FileNameLength > 0) {
            PFLT_FILE_NAME_INFORMATION destInfo = NULL;

            status = FltGetDestinationFileNameInformation(
                FltObjects->Instance,
                FltObjects->FileObject,
                ren->RootDirectory,
                ren->FileName,
                ren->FileNameLength,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                &destInfo);

            if (NT_SUCCESS(status) && destInfo != NULL) {
                BlwReportFileTelemetry(BlwEventFileRename, &destInfo->Name);
                FltReleaseFileNameInformation(destInfo);
            }
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//
// IRP_MJ_WRITE:就地加密检测(采样遥测,绝不拦截)。
//
// 勒索软件除了"改名/删除原文件",更常见的是【打开文件 -> 从头覆写密文 -> 同名保存】,
// 这类就地加密既不改名也不删除,前面的 SET_INFORMATION 钩子抓不到。本钩子用极低成本的
// 采样把"用户态进程从文件头(偏移 0)发起写入"这一事实异步上报,喂给用户态勒索时序聚合
// (批量改写速率)。设计铁律:
//   * 仅遥测开启时才工作;关闭时第一行就返回,零开销。
//   * 只对【偏移 0 起写】采样 —— 加密通常重写整个文件,首块必从 0 写起;
//     普通追加写(日志/数据库)偏移非 0,直接放行,避免海量正常写入触发上报。
//   * 【按 PID 散列】的分槽采样:同一进程每 N 次符合条件的写才解析一次文件名并上报,
//     绝不每次写都解析文件名(FltGetFileNameInformation 昂贵)。分槽而不是共用一个全局
//     计数器,是因为用户态勒索聚合按【发起进程】算改写速率 —— 全局预算会被任何一个写得
//     很密的正常进程吃掉,噪声越大越拦不住勒索。完整说明见 BLW_GLOBALS::WriteSampleSlots。
//   * 同一文件被反复从头覆写不重复计入(WriteSeenFile 备忘),预算只花在「不同的文件」上。
//   * 绝不拦截、绝不发同步 IPC:只 fire-and-forget 入队,队列满即丢。
//

//
// 本次「偏移 0 起写」是否该上报。无锁,可在任意 IRQL 调用。
//
// FileObject 只作【不透明身份标签】使用 ——【绝不解引用】。它可能早已被释放;我们唯一用到它的
// 地方是与「上一次在同一槽里计入过的那个值」做一次相等比较,比错了的后果仅仅是多上报或少上报
// 一条遥测,既不会访问无效内存,也不影响任何拦截判定。
//
static BOOLEAN
BlwWriteSampleShouldReport(_In_ ULONG Pid, _In_opt_ PVOID FileObjectKey)
{
    const ULONG slot = (Pid >> 2) & BLW_WRITE_SLOT_MASK;
    const LONG64 key = (LONG64)(ULONG_PTR)FileObjectKey;
    LONG n;

    //
    // 同一个文件被反复从偏移 0 覆写(日志轮转 / 数据库回写 / 进度文件)不重复计入 ——
    // 采样预算应当只花在「不同的文件」上,那才是勒索批量加密的特征。
    // key==0(拿不到 FileObject)时跳过这一步,直接按计数采样,不因此漏掉信号。
    //
    if (key != 0) {
        if (InterlockedExchange64(&g_Blw.WriteSeenFile[slot], key) == key) {
            return FALSE;
        }
    }

    //
    // 计数从 1 开始 -> 取模为 1 时命中,故【每个槽的第一次首块写必定上报】:
    // 只改几个文件的样本也能被看见,不会整批落在采样间隙里。
    //
    // 取模刻意走【无符号 + 位与】:计数器是 LONG,长时间运行后会溢出成负数,而负数的 % 结果
    // 落在 {-31..0},再也不会等于 1 —— 那个槽会从此永久停止上报(静默的能力退化)。
    // 采样率是 2 的幂(下面 C_ASSERT 保证),故位与在无符号回绕下节奏依然精确。
    //
    n = InterlockedIncrement(&g_Blw.WriteSampleSlots[slot]);
    return ((((ULONG)n) & (BLW_WRITE_SAMPLE_RATE - 1)) == 1);
}
C_ASSERT((BLW_WRITE_SAMPLE_RATE & (BLW_WRITE_SAMPLE_RATE - 1)) == 0);

FLT_PREOP_CALLBACK_STATUS
BlwPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    LARGE_INTEGER byteOffset;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    // 已封禁主体(情报确认恶意):拒绝其任何写入 —— 挡住就地加密 / 覆写。必须在遥测开关之前判断
    // (遥测关闭时也要拦)。封禁集非空 + 用户态发起时才查(空/内核写则零开销)。
    if (g_Blw.BannedPidCount > 0 && Data->RequestorMode != KernelMode &&
        BlwPidIsBanned(HandleToULong(PsGetCurrentProcessId()))) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    // 1) 遥测未开启 -> 立即放行(零开销,这是热路径的第一道闸)。
    //    volatile LONG 直接读即原子读;原来用 InterlockedCompareExchange 做「原子读」,
    //    等于在【每一次写 IRP】上都执行一条带锁的 cmpxchg —— 这是最热的路径上最不该付的开销。
    if (g_Blw.FileTelemetryEnabled == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (!g_Blw.Active) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    // 2) 内核态发起的写不关注(分页写/系统缓存回写等),避免噪声与重入。
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    // 2a) 分页 I/O 一律不看:它是内存管理器回写映射页/缓存页产生的,不是应用发起的
    //     「打开 -> 从头覆写」行为,既不该计入勒索速率,也白白消耗后面的偏移判断与采样。
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    // 3) 只看"从文件头(偏移 0)起写"——加密重写整文件的首块特征。
    //    普通追加/随机写偏移非 0,直接放行(占绝大多数写,零解析开销)。
    byteOffset = Data->Iopb->Parameters.Write.ByteOffset;
    if (byteOffset.QuadPart != 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // 4) 采样节流(按 PID 分槽 + 同文件去重)。完整理由见 BLW_GLOBALS::WriteSampleSlots:
    //    原实现用【一个】全局计数器,全系统共享 1/32 预算,任何写得密的正常进程都会把它吃掉,
    //    而用户态勒索聚合是按发起进程算速率的 —— 那是真实的检出损失。
    //
    //    全程无锁:一次 InterlockedExchange64(同文件去重)+ 一次 InterlockedIncrement(计数)。
    //
    if (!BlwWriteSampleShouldReport(HandleToULong(PsGetCurrentProcessId()),
                                    Data->Iopb->TargetFileObject)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 5) 文件名解析只能在 PASSIVE_LEVEL 安全进行;否则跳过本次采样(下次再说)。
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    // fire-and-forget 上报为"重命名/改写"类遥测(用户态映射为 FileWrite 喂勒索聚合)。
    BlwReportFileTelemetry(BlwEventFileRename, &nameInfo->Name);

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
