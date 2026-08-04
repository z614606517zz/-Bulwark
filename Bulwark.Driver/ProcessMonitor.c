/*++
    ProcessMonitor.c
    进程创建拦截:PsSetCreateProcessNotifyRoutineEx。

    回调在创建者线程上下文、PASSIVE_LEVEL 被调用,允许我们同步地把事件
    发给用户态并等待裁决。若裁决为 Block,设置 CreateInfo->CreationStatus
    为 STATUS_ACCESS_DENIED,内核将拒绝该进程启动。

    性能:在内核侧对"操作系统自带目录"的映像直接放行,不走 IPC,
    避免每次开个 cmd.exe / svchost.exe 都要等用户态裁决。这些路径
    普通用户态写不了,落地恶意样本进不来,在内核侧白名单是安全的。
--*/

#include "Driver.h"

//
// 大小写不敏感:判断 Str 是否包含子串 Sub(均为以 NUL 结尾的宽字符)。
// 用于按"路径子串"匹配系统目录,覆盖 \??\C:\... 与 \Device\HarddiskVolumeN\...
// 等各种前缀形式,避免严格前缀漏判导致关键系统进程意外走 IPC 裁决。
//
//
// 大小写不敏感子串匹配(Sub 为 NUL 结尾的短常量)。
//
// 原实现对每个滑动窗口偏移都调一次 RtlCompareUnicodeString(...TRUE) —— 该调用内部会对两侧
// 逐字符做 Unicode 大写化,成本是 O(子串长度)。「可信系统目录」白名单有 11 条,一次进程创建
// 就是 11 × 路径长度 次这样的调用。
//
// 现在用「首字符 + 末字符」双锚点先筛:两端都对上才比中间,且全部用内联的 BlwUpcaseChar
// (ASCII 快路,无函数调用)。判定结果与原来完全一致 —— 同一套 Unicode 大写表。
//
BOOLEAN
BlwWideContainsCI(_In_ PCWSTR Str, _In_ USHORT StrChars, _In_ PCWSTR Sub)
{
    USHORT subChars = 0;
    USHORT limit;
    USHORT s;
    WCHAR  first;
    WCHAR  last;

    if (Str == NULL || Sub == NULL || StrChars == 0) {
        return FALSE;
    }

    while (subChars < BLW_MAX_PATH && Sub[subChars] != L'\0') {
        subChars++;
    }
    if (subChars == 0 || subChars > StrChars) {
        return FALSE;
    }

    first = BlwUpcaseChar(Sub[0]);
    last = BlwUpcaseChar(Sub[subChars - 1]);
    limit = (USHORT)(StrChars - subChars);

    for (s = 0; s <= limit; s++) {
        USHORT k;

        if (BlwUpcaseChar(Str[s]) != first) {
            continue;
        }
        if (BlwUpcaseChar(Str[s + subChars - 1]) != last) {
            continue;
        }
        for (k = 1; (USHORT)(k + 1) < subChars; k++) {
            if (BlwUpcaseChar(Str[s + k]) != BlwUpcaseChar(Sub[k])) {
                break;
            }
        }
        if ((USHORT)(k + 1) >= subChars) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 「路径以 \<文件名> 结尾」类常量名单的公共判定(见 Driver.h 的 BLW_NAME_ENTRY 说明)。
//
BOOLEAN
BlwImageNameIn(
    _In_reads_(TableCount) const BLW_NAME_ENTRY* Table,
    _In_ ULONG TableCount,
    _In_opt_ PCWSTR Path,
    _In_ USHORT Chars)
{
    USHORT nameStart;
    USHORT nameChars;
    ULONG  i;
    WCHAR  firstUp;

    if (Path == NULL || Chars == 0) {
        return FALSE;
    }

    // 反向定位最后一个 '\',其后即文件名。整条路径里没有 '\' 时不匹配 ——
    // 与原来「尾部匹配 \<名字>」的语义一致(那种写法也要求路径里出现 '\')。
    nameStart = Chars;
    while (nameStart > 0 && Path[nameStart - 1] != L'\\') {
        nameStart--;
    }
    if (nameStart == 0) {
        return FALSE;
    }

    nameChars = (USHORT)(Chars - nameStart);
    if (nameChars == 0) {
        return FALSE;
    }

    firstUp = BlwUpcaseChar(Path[nameStart]);

    for (i = 0; i < TableCount; i++) {
        USHORT k;

        if (Table[i].Chars != nameChars) {
            continue;   // 长度不同,不可能相等
        }
        if (BlwUpcaseChar(Table[i].Name[0]) != firstUp) {
            continue;   // 首字符不同,不可能相等
        }
        for (k = 1; k < nameChars; k++) {
            if (BlwUpcaseChar(Path[nameStart + k]) != BlwUpcaseChar(Table[i].Name[k])) {
                break;
            }
        }
        if (k == nameChars) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// ================== 命令行硬拦(执行前拦截·按用法而非按身份)==================
//
// 见 Driver.h 里 CmdHardBlock 的说明:LOLBin 的威胁全在「用法」,而内核回调里
// PS_CREATE_NOTIFY_INFO.CommandLine 直接可读,故这条判定完全可以、也必须在内核本地完成。
//

void
BlwClearCmdHardBlock(void)
{
    ExAcquireFastMutex(&g_Blw.CmdHardLock);
    RtlZeroMemory(g_Blw.CmdHardBlock, sizeof(g_Blw.CmdHardBlock));
    InterlockedExchange(&g_Blw.CmdHardCount, 0);
    ExReleaseFastMutex(&g_Blw.CmdHardLock);
}

void
BlwAddCmdHardBlock(_In_ PCWSTR Pattern, _In_ USHORT Length)
{
    ExAcquireFastMutex(&g_Blw.CmdHardLock);
    // 复用通用名单追加:内部会把模式串【大写化一次】后存入,故下面的 token 比较只需
    // 对命令行侧做即时大写化(模式侧已归一),与其它名单的存储约定完全一致。
    BlwAddToList(g_Blw.CmdHardBlock, Pattern, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.CmdHardBlock[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.CmdHardCount, cnt);
    }
    ExReleaseFastMutex(&g_Blw.CmdHardLock);
}

//
// 单个 token 是否作为大小写不敏感子串出现在命令行中。
//
// Tok 已在加入名单时大写化;Target 是【原始命令行】,逐字符即时大写化后比较 —— 不预归一化
// 是刻意的:命令行可长达 32767 字符,预归一化就要么开大缓冲、要么截断,而截断会直接造成
// 「填充垫料把危险 token 推出截断范围」的绕过。逐字符比较的代价只在进程创建这条低频路径上。
//
// 窗口过滤沿用项目里其它匹配器的「首字符 + 末字符」双锚点:两端都对上才比中间段,
// 把绝大多数必然失败的比较剪掉。判定结果与逐窗口整串比较完全一致(同一套 Unicode 大写表)。
//
static BOOLEAN
BlwTokenInCmdLine(
    _In_reads_(TargetChars) PCWSTR Target,
    _In_ ULONG TargetChars,
    _In_reads_(TokChars) PCWSTR Tok,
    _In_ USHORT TokChars)
{
    ULONG limit;
    ULONG s;
    WCHAR first;
    WCHAR last;

    if (TokChars == 0 || (ULONG)TokChars > TargetChars) {
        return FALSE;
    }

    first = Tok[0];
    last = Tok[TokChars - 1];
    limit = TargetChars - TokChars;

    for (s = 0; s <= limit; s++) {
        USHORT k;

        if (BlwUpcaseChar(Target[s]) != first) {
            continue;
        }
        if (BlwUpcaseChar(Target[s + TokChars - 1]) != last) {
            continue;
        }
        for (k = 1; (USHORT)(k + 1) < TokChars; k++) {
            if (BlwUpcaseChar(Target[s + k]) != Tok[k]) {
                break;
            }
        }
        if ((USHORT)(k + 1) >= TokChars) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 一条模式是否命中命令行:模式按 BLW_CMD_TOKEN_SEP('+')切分为多个 token,
// 【全部 token 都出现】才算命中(合取 / AND 语义)。
//
// 为什么是合取而不是整串子串:整串子串对参数顺序和空格数量敏感,
// `vssadmin delete shadows /all` 与 `vssadmin /for=c: delete shadows` 只有前者能被
// 一条固定子串覆盖,攻击者调个顺序就绕过了。合取则与顺序、空格、大小写、是否带全路径无关。
//
// 空模式(全是分隔符、没有任何有效 token)返回 FALSE —— 绝不让一条配置错误的空模式
// 变成「匹配一切命令行」从而拦死整个系统。
//
static BOOLEAN
BlwCmdPatternMatches(
    _In_ const BLW_PROTECTED_PATH* Entry,
    _In_reads_(TargetChars) PCWSTR Target,
    _In_ ULONG TargetChars)
{
    USHORT start = 0;
    USHORT i;
    BOOLEAN haveToken = FALSE;

    // i == Length 时收尾处理最后一段,故循环到 <= Length。
    for (i = 0; i <= Entry->Length; i++) {
        if (i == Entry->Length || Entry->Path[i] == BLW_CMD_TOKEN_SEP) {
            USHORT tokChars = (USHORT)(i - start);

            if (tokChars > 0) {
                haveToken = TRUE;
                if (!BlwTokenInCmdLine(Target, TargetChars, &Entry->Path[start], tokChars)) {
                    return FALSE;   // 有一个 token 不在命令行里 -> 整条模式不命中
                }
            }
            start = (USHORT)(i + 1);
        }
    }

    return haveToken;
}

BOOLEAN
BlwCmdLineIsBlocked(_In_opt_ PCUNICODE_STRING CommandLine)
{
    ULONG   chars;
    LONG    count;
    LONG    seen = 0;
    ULONG   i;
    BOOLEAN matched = FALSE;

    if (CommandLine == NULL || CommandLine->Buffer == NULL || CommandLine->Length == 0) {
        return FALSE;   // 无命令行(CommandLine 为可选字段)-> 无从判定,放行
    }

    chars = CommandLine->Length / sizeof(WCHAR);
    if (chars == 0) {
        return FALSE;
    }

    ExAcquireFastMutex(&g_Blw.CmdHardLock);
    count = g_Blw.CmdHardCount;
    // seen < count:扫到最后一个在用项就收尾,不遍历剩余空槽(名单通常十余条)。
    for (i = 0; i < BLW_MAX_PROTECTED && seen < count; i++) {
        if (!g_Blw.CmdHardBlock[i].InUse) {
            continue;
        }
        seen++;
        if (BlwCmdPatternMatches(&g_Blw.CmdHardBlock[i], CommandLine->Buffer, chars)) {
            matched = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_Blw.CmdHardLock);

    return matched;
}

//
// LOLBin(Living-off-the-Land)名单:这些程序虽在 System32(受 ACL 保护、本体可信),
// 但常被攻击者用「恶意命令行参数」滥用(无文件攻击 / 下载执行 / 凭据转储 / 删卷影 等)。
// 路径白名单对它们必须「开口子」—— 即便在系统目录也要上报用户态,让命令行检测有机会运行。
// 否则 rundll32/powershell/certutil 等被滥用时,会在内核层就被路径白名单静默放过。
//
static BOOLEAN
BlwImageIsLolBin(_In_ PCWSTR Path, _In_ USHORT Chars)
{
    static const BLW_NAME_ENTRY kLolBins[] = {
        BLW_NAME(L"powershell.exe"), BLW_NAME(L"pwsh.exe"),     BLW_NAME(L"cmd.exe"),
        BLW_NAME(L"wscript.exe"),    BLW_NAME(L"cscript.exe"),  BLW_NAME(L"mshta.exe"),
        BLW_NAME(L"rundll32.exe"),   BLW_NAME(L"regsvr32.exe"), BLW_NAME(L"certutil.exe"),
        BLW_NAME(L"bitsadmin.exe"),  BLW_NAME(L"wmic.exe"),     BLW_NAME(L"vssadmin.exe"),
        BLW_NAME(L"bcdedit.exe"),    BLW_NAME(L"wbadmin.exe"),  BLW_NAME(L"schtasks.exe"),
        BLW_NAME(L"at.exe"),         BLW_NAME(L"msbuild.exe"),  BLW_NAME(L"installutil.exe"),
        BLW_NAME(L"regsvcs.exe"),    BLW_NAME(L"regasm.exe"),   BLW_NAME(L"mavinject.exe"),
        BLW_NAME(L"cmstp.exe"),      BLW_NAME(L"msdt.exe"),     BLW_NAME(L"hh.exe"),
        BLW_NAME(L"forfiles.exe"),   BLW_NAME(L"pcalua.exe"),   BLW_NAME(L"scriptrunner.exe"),
        BLW_NAME(L"netsh.exe"),
    };

    return BlwImageNameIn(kLolBins, RTL_NUMBER_OF(kLolBins), Path, Chars);
}

//
// 内核侧快速白名单:位于 OS 自带 / 标准安装目录下的映像。
// 这些目录受 Windows 文件 ACL 与 WRP 保护,普通账户无写权限,
// 风险极低,直接放行避免对每个 svchost/explorer/cmd/Office/浏览器都做 IPC。
// 体感等价:命中此白名单的程序"启动零延迟"——这是参考 Sysmon/Defender 等
// 商业驱动的做法。这些目录里若真出现恶意,前置防御(签名/规则/MOTW)早已介入。
//
// 用"子串包含"而非"严格前缀":CreateInfo->ImageFileName 可能是
// \??\C:\Windows\System32\... 也可能是 \Device\HarddiskVolumeN\Windows\System32\...
// 等形式,严格前缀会漏判,导致 svchost 等关键进程意外走 IPC,
// 一旦用户态裁决错误/超时即可能拒绝创建关键进程而蓝屏(0xEF)。
//
static BOOLEAN
BlwImageIsTrustedSystemPath(_In_ PCWSTR Path, _In_ USHORT Chars)
{
    static const PCWSTR kNeedles[] = {
        // 系统目录(WRP / 高 ACL)
        L"\\Windows\\System32\\",
        L"\\Windows\\SysWOW64\\",
        L"\\Windows\\WinSxS\\",
        L"\\Windows\\servicing\\",
        L"\\Windows\\SystemApps\\",
        L"\\Windows\\ImmersiveControlPanel\\",
        L"\\Windows Defender\\",
        L"\\Windows Defender Advanced Threat Protection\\",
        L"\\Microsoft.NET\\",

        // 标准安装目录(普通用户无写权限,正常软件 99% 装在这里)
        L"\\Program Files\\",
        L"\\Program Files (x86)\\",
    };

    ULONG i;
    for (i = 0; i < RTL_NUMBER_OF(kNeedles); i++) {
        if (BlwWideContainsCI(Path, Chars, kNeedles[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 「真正的系统映像目录」判定 —— 只有这几处,普通用户写不进去(WRP + 高 ACL)。
//
// 【刻意不复用 BlwImageIsTrustedSystemPath】:那份名单里含 \Program Files\ 等常规安装目录,
// 用它来给「关键系统进程」放行,等于把 C:\Program Files\Foo\csrss.exe 也认成关键进程。
// 关键进程护栏的语义是「这个文件就是 Windows 自己的那一份」,判据必须收得比可信目录更紧。
//
static BOOLEAN
BlwPathIsSystemImageDir(_In_opt_ PCWSTR Path, _In_ USHORT Chars)
{
    if (Path == NULL || Chars == 0) {
        return FALSE;
    }
    return BlwWideContainsCI(Path, Chars, L"\\Windows\\System32\\")
        || BlwWideContainsCI(Path, Chars, L"\\Windows\\SysWOW64\\")
        || BlwWideContainsCI(Path, Chars, L"\\Windows\\WinSxS\\");
}

//
// 关键系统进程名单:这些进程一旦被拒绝创建/被误杀,系统会立刻 BugCheck
// (CRITICAL_PROCESS_DIED 0xEF)。无论用户态裁决如何,内核侧绝不阻止它们。
// 这是防蓝屏的最后一道硬底线 —— 即便协议错位/服务误判/超时,也不能拖垮系统。
//
// 判据 = 【文件名命中名单】且【映像位于真正的系统目录】,两个条件必须同时成立。
//
// 为什么必须加上路径条件:原实现只按"映像文件名以 \名字 结尾"匹配,于是任何目录下改名叫
// csrss.exe 的样本都自动获得了这道护栏的豁免 —— 既拦不住它启动(exec-block 处的 !critical),
// 也杀不掉它(BlwKillProcessById 的护栏 3)。这不是理论风险:实测机器上
// C:\Users\<u>\AppData\Local\DBG\csrss.exe(SalatStealer,已被情报确认恶意)就是靠这个
// 免疫了内核级结束,用户态每 60 秒重试一次、连续几十小时都杀不掉它。
// 「改名成系统进程」是最基础的伪装手法,护栏不该按它自己声称的名字给它发豁免。
//
// 收紧之后真实系统进程仍有双重保障:一是它们本就住在 System32(路径条件成立),
// 二是结束路径上另有内核权威的 PsIsProcessCritical 判定(见 BlwKillProcessById 护栏 3)。
//
static BOOLEAN
BlwIsCriticalSystemProcess(_In_opt_ PCWSTR Path, _In_ USHORT Chars)
{
    static const BLW_NAME_ENTRY kCritical[] = {
        BLW_NAME(L"smss.exe"),
        BLW_NAME(L"csrss.exe"),
        BLW_NAME(L"wininit.exe"),
        BLW_NAME(L"winlogon.exe"),
        BLW_NAME(L"services.exe"),
        BLW_NAME(L"lsass.exe"),
        BLW_NAME(L"svchost.exe"),
        BLW_NAME(L"lsaiso.exe"),
        BLW_NAME(L"fontdrvhost.exe"),
        BLW_NAME(L"dwm.exe"),
        BLW_NAME(L"spoolsv.exe"),
        BLW_NAME(L"WerFault.exe"),
        BLW_NAME(L"WerFaultSecure.exe"),
        BLW_NAME(L"wermgr.exe"),
    };

    if (!BlwImageNameIn(kCritical, RTL_NUMBER_OF(kCritical), Path, Chars)) {
        return FALSE;
    }
    return BlwPathIsSystemImageDir(Path, Chars);
}

//
// 进程创建/退出通知回调。
//
// 架构说明(参考 Sysmon / Defender ATP 的 EDR 模型):
//   原实现采用「同步等待用户态裁决」模型 —— 内核挂起进程创建,等用户态做规则
//   匹配/签名校验/哈希计算/IPC 往返再回写裁决。这种模型在事件密集时(登录、
//   开多个程序、GC、签名验证慢)会让用户态成为热路径瓶颈,把所有进程创建串行
//   化,体感就是"启动卡顿"乃至"卡死后必须重启"。
//
//   现改为「Fire-and-Forget 遥测 + 启动后补偿处置」模型:
//     1) 内核只做关键路径的同步白名单(系统目录 / Program Files / 关键系统进程),
//        命中即直接放行,完全不发 IPC,启动零延迟;
//     2) 不在白名单的进程,内核以「仅记录」方式上报用户态(BlwReportEvent,
//        不等待回复),立刻放行进程启动 —— 永远不挂起进程创建;
//     3) 用户态规则引擎事后裁决,若为 Block 则用户态以 OpenProcess+
//        TerminateProcess 结束这个刚启动的进程(对应 Worker.Enforce 中的
//        UserModeObserved/IsReportOnly 补偿处置分支)。
//
// 收益:
//   - 用户态再慢/再卡也绝不影响进程创建,系统永远不会因防御软件卡死;
//   - Filter Manager IPC 发送队列拥塞时,我们丢弃记录而非阻塞内核回调,
//     杜绝"用户态背压压垮系统"。
//
//   与 Sysmon/EDR 一样,「post-launch kill」会让恶意进程短暂运行约几十毫秒,
//   绝大多数攻击样本仍在初始化阶段被结束,效果与同步阻断接近,但代价是
//   稳定性提升一个数量级。
//
static void
BlwCreateProcessNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    PCUNICODE_STRING image;
    PCWSTR  imgBuf = NULL;
    USHORT  imgChars = 0;
    ULONG   newPid;
    ULONG   parentPid;
    BOOLEAN critical;

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL) {
        // 进程退出:从封禁集摘除该 PID,防止 PID 复用时误伤新进程。
        BlwRemoveBannedPid(HandleToULong(ProcessId));
        return;
    }

    // 已封禁主体(情报确认恶意)创建子进程 -> 一律拒绝(封禁集非空时才查,空则零开销)。
    // 放在空载快速路径之前:即便无客户端,封禁主体的拦截也必须生效。创建者上下文即当前进程。
    if (g_Blw.BannedPidCount > 0 &&
        BlwPidIsBanned(HandleToULong(PsGetCurrentProcessId()))) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        KdPrint(("[Bulwark] Banned actor pid %u denied spawning a child.\n",
            HandleToULong(PsGetCurrentProcessId())));
        return;
    }

    // 【自足基线】即便用户态服务未连接,内核仍用本地 exec-block / 命令行硬拦名单做执行前拦截 ——
    // 服务被杀 / 未启动 / 未安装时防护都不掉线。仅当「无客户端可上报」且「无执行前拦截
    // 名单可用」且「无命令行硬拦名单」且「无已知恶意集」时,才保留原来的空载快速放行
    //(既无处上报、也无可拦截,零开销)。
    // 遥测上报(BlwReportEvent)内部自带 Active 判空,无客户端时自动跳过发送。
    if (!g_Blw.Active && g_Blw.FileExecBlockCount == 0 && g_Blw.KnownBadCount == 0 &&
        g_Blw.CmdHardCount == 0) {
        return;
    }

    newPid = HandleToULong(ProcessId);
    parentPid = HandleToULong(CreateInfo->ParentProcessId);

    //
    // 直接在 CreateInfo->ImageFileName(\??\C:\...)上做所有判定,不再先铺开事件结构。
    //
    // 原实现一进来就 RtlZeroMemory 整个 2.1KB 的 BLW_EVENT_MESSAGE 并把映像路径拷进去,
    // 然后才做白名单判定 —— 于是【每一个】svchost / explorer / RuntimeBroker 的启动都要
    // 白付一次 2.1KB 清零 + 一次路径拷贝,而它们几乎全部会被白名单直接放行。现在只有真的
    // 要上报时才碰事件结构(在 BlwReportEvent 内部就地填环形槽)。
    //
    // 顺带修掉一处精度问题:原来判定用的是被截断到 519 字符的副本,超长路径会让
    // 「关键系统进程」「可信系统目录」这类尾部/子串判定看错内容;现在一律用完整路径判定。
    //
    image = CreateInfo->ImageFileName;
    if (image != NULL && image->Buffer != NULL && image->Length > 0) {
        imgBuf = image->Buffer;
        imgChars = (USHORT)(image->Length / sizeof(WCHAR));
    }

    // 关键系统进程判定在下面被用到两次(执行前拦截的护栏 + 上报前的兜底),只算一次。
    critical = BlwIsCriticalSystemProcess(imgBuf, imgChars);

    //
    // ===== 执行前拦截(exec-block)=====
    // 新进程映像路径命中「已确认恶意」名单 -> 内核本地直接拒绝创建
    // (CreateInfo->CreationStatus = STATUS_ACCESS_DENIED),样本根本无法启动。
    // 零用户态往返、无竞态,补上「事后 kill 让样本先跑几十毫秒」的短板;重启后仍拦(名单重推)。
    //
    // 必须放在下面「可信系统路径快速放行」之前 —— 恶意样本可能被装进 Program Files 等常规目录,
    // 若先被路径白名单放行就漏拦了。唯一的硬护栏是「关键系统进程绝不拦」(防 CRITICAL_PROCESS_DIED
    // 0xEF):即便名单被误配为含关键进程也绝不拦死系统。先查计数(热路径零锁快速判空),
    // 有名单才做子串匹配。命中即上报一条 BlwEventImageBlocked(信息型「已阻断」,不会触发用户态对
    // 该 PID 的扫描/结束 —— kill 只由 BlwEventProcessCreate 的裁决驱动)。
    //
    if (imgChars > 0 && g_Blw.FileExecBlockCount > 0 && !critical) {
        BLW_MATCH_CTX ctx;

        BlwPrepareMatch(&ctx, image);
        if (BlwFileIsExecBlocked(&ctx)) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            // 供用户态展示「已阻止恶意程序启动」:两个路径字段都填,兼容用户态取任一字段。
            BlwReportEvent(BlwEventImageBlocked, newPid, parentPid, image, image, 0, 0);
            KdPrint(("[Bulwark] Exec blocked (pre-create denied): %wZ\n", image));
            return;
        }
    }

    //
    // ===== 命令行硬拦(执行前拦截·按用法)=====
    // 新进程的【完整命令行】命中命令行硬拦名单 -> 内核本地直接拒绝创建,危险命令根本不会执行。
    //
    // 位置至关重要:必须放在下面「可信系统路径快速放行」【之前】。命令行硬拦的全部意义就在于
    // 拦住 System32 里那些本体可信的 LOLBin(vssadmin / wmic / bcdedit / wevtutil ...)被恶意
    // 使用 —— 它们无一例外都住在可信路径里,一旦先被路径白名单放行,这条防护就等于不存在。
    //
    // 唯一的硬护栏仍是「关键系统进程绝不拦」(防 CRITICAL_PROCESS_DIED 0xEF):即便名单被误配成
    // 能命中 svchost/lsass 的模式,也绝不拦死系统。先查计数(热路径零锁快速判空),有名单才读命令行。
    //
    // 与事后 kill 的本质差别:`vssadmin delete shadows /all /quiet` 这类命令在毫秒级内就完成
    // 不可逆破坏,「启动后补偿结束进程」根本来不及 —— 卷影已经没了。这里是真正的行为前阻断。
    //
    if (g_Blw.CmdHardCount > 0 && !critical &&
        BlwCmdLineIsBlocked(CreateInfo->CommandLine)) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        // ImagePath=映像路径(供 UI 显示是谁),TargetPath=被拦下的完整命令行(供 UI 显示拦了什么)。
        BlwReportEvent(BlwEventCommandBlocked, newPid, parentPid,
                       CreateInfo->CommandLine, image, 0, 0);
        KdPrint(("[Bulwark] Command blocked (pre-create denied): %wZ\n",
            CreateInfo->CommandLine));
        return;
    }

    //
    // 内核侧快速白名单:OS 自带 / 标准安装目录的进程直接放行,不发 IPC。
    // 大幅降低进程创建延迟(尤其登录/启动期间的 svchost / explorer /
    // RuntimeBroker 等大批进程)。这些路径受 ACL 保护,普通账户写不进。
    //
    // 例外:LOLBin(rundll32/powershell/certutil 等)即便在系统目录也【不】走快速放行 ——
    // 它们的威胁来自「命令行参数被滥用」,必须上报用户态做命令行检测,否则无文件攻击/
    // 凭据转储/下载执行等会在内核层被静默放过(本体可信 ≠ 用法可信)。
    //
    if (imgChars > 0 &&
        BlwImageIsTrustedSystemPath(imgBuf, imgChars) &&
        !BlwImageIsLolBin(imgBuf, imgChars)) {
        return;
    }

    //
    // 防蓝屏硬底线:无论命中哪条规则,关键系统进程绝不上报(也就不可能被
    // 用户态补偿结束)。这是稳定性兜底。
    //
    if (critical) {
        return;
    }

    //
    // 仅遥测上报,不等待裁决,立即返回。用户态规则引擎事后裁决;
    // 若为 Block,用户态自行以 TerminateProcess 结束这个 PID。
    // BlwReportEvent 内部已自带 rundown 保护,且对 IPC 失败容错,绝不挂起调用方。
    //
    // 内核本地事后研判:有已知恶意集时,把这个非白名单新进程交给哈希 worker 异步扫描
    //(worker 读文件 + SHA-256,命中已知恶意即结束它)。默认惰性:无已知恶意集则跳过,零开销。
    // 仅入队 PID(自旋锁下写环),微秒级返回,绝不在此读文件/算哈希。
    if (g_Blw.KnownBadCount > 0) {
        BlwEnqueueHashScan(newPid);
    }

    //
    // TargetPath 带上【完整命令行】(此前这里传 NULL,命令行被直接丢掉)。
    //
    // 为什么必须在这里给:CreateInfo->CommandLine 是内核在进程创建回调里【本来就拿得到】的,
    // 上面的命令行硬拦已经在用它。而用户态原先只能在收到事件后按 PID 去读目标进程的 PEB
    // (Worker::enrich -> ProcessInspector::tryGetCommandLine)—— 那是一场必输的竞速:
    // reg.exe / schtasks.exe / cmstp.exe 这类 LOLBin 常在毫秒级内退出,PEB 读不到,
    // 于是所有依赖命令行的判定(攻击链的 Set-ExecutionPolicy / Add-MpPreference /
    // -encodedcommand / \Temp\ 等标记,以及大量 LOLBin 规则)在真机上时灵时不灵。
    // 实测(--attackchain-check 的可达性诊断):18 条组合里有 6 条因此只能算「稀疏」。
    //
    // 【刻意复用 TargetPath 而不新增字段】:BLW_EVENT_MESSAGE 的布局一个字节都不能变 ——
    // 握手校验按结构体大小逐一比对,改了布局就得升协议版本,已部署的驱动/服务会因版本
    // 不符而整体降级为不拦截。而 ProcessCreate 的 TargetPath 此前恒为空,是白放着的容量;
    // BlwEventCommandBlocked 早就是这么用它的(TargetPath=被拦下的命令行),故语义一致。
    // 用户态侧把它读进 e.commandLine(而不是 e.target),因此既有按 target 写的规则语义不变。
    //
    BlwReportEvent(BlwEventProcessCreate, newPid, parentPid,
                   CreateInfo->CommandLine, image, 0, 0);
}

NTSTATUS
BlwRegisterProcessCallback(void)
{
    NTSTATUS status;

    if (g_Blw.ProcessCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetCreateProcessNotifyRoutineEx(BlwCreateProcessNotifyEx, FALSE);
    if (NT_SUCCESS(status)) {
        g_Blw.ProcessCallbackRegistered = TRUE;
        KdPrint(("[Bulwark] Process callback registered.\n"));
    }
    return status;
}

void
BlwUnregisterProcessCallback(void)
{
    if (g_Blw.ProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(BlwCreateProcessNotifyEx, TRUE); // Remove
        g_Blw.ProcessCallbackRegistered = FALSE;
        KdPrint(("[Bulwark] Process callback unregistered.\n"));
    }
}

// ZwTerminateProcess 已由 ntddk.h 声明,直接使用。PROCESS_TERMINATE 访问权(0x0001)在内核头中
// 未定义,显式补上(ObOpenObjectByPointer 请求该权限,KernelMode 访问模式下绕过 ACL 检查)。
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

//
// PsIsProcessCritical(EPROCESS.BreakOnTermination 的公开读取接口,Win8.1+ 由 ntoskrnl 导出)。
//
// 用【运行时解析】而不是直接调用,两个实测理由:
//   1) 当前 WDK(SDK 10.0.26100)的 ntddk.h 并没有声明它 —— 直接调用报 C4013,而本工程
//      warning-as-error,编译直接失败;
//   2) 在本文件里手写原型 + 静态链接,等于把「这套 ntoskrnl.lib 里有没有这个导出」变成
//      链接期赌注,赌输了是链接错误,赌赢了也仍然要求目标机内核有该导出才能加载驱动。
// MmGetSystemRoutineAddress 没有这两个问题:解析不到就退回「名单 + 系统目录」判定,
// 也就是本次修改之前的行为,不会有任何退化。仅在 PASSIVE_LEVEL 调用(该 API 的要求),
// BlwKillProcessById 本身就跑在 PASSIVE_LEVEL(FltSendMessage 处理路径)。
//
// 用 union 转换函数指针而不是直接强转:MSVC 对「数据指针强转函数指针」会报 C4055,
// 本工程把警告当错误,那条会直接让编译失败。
//
typedef BOOLEAN (*BLW_PS_IS_PROCESS_CRITICAL)(_In_ PEPROCESS Process);

static BOOLEAN
BlwProcessIsKernelCritical(_In_ PEPROCESS Process)
{
    static BLW_PS_IS_PROCESS_CRITICAL s_fn = NULL;
    static BOOLEAN s_resolved = FALSE;

    if (!s_resolved) {
        union { PVOID p; BLW_PS_IS_PROCESS_CRITICAL fn; } cast;
        UNICODE_STRING name;

        RtlInitUnicodeString(&name, L"PsIsProcessCritical");
        cast.p = MmGetSystemRoutineAddress(&name);
        s_fn = cast.fn;
        s_resolved = TRUE;   // 解析失败也不重试:结果不会变
        if (s_fn == NULL) {
            KdPrint(("[Bulwark] PsIsProcessCritical unavailable; name+path guard only.\n"));
        }
    }

    // 解析不到时返回 FALSE = 「这一条判据不表态」,交给下面的名单 + 系统目录判定兜住。
    return (s_fn != NULL) ? s_fn(Process) : FALSE;
}

//
// 驱动级结束进程(BLW_CMD_KILL_PID 的内核实现)。用户态 VT 确认某新进程恶意后下发本命令 ——
// 内核直接 ZwTerminateProcess,比用户态 OpenProcess+TerminateProcess 更强(不受目标用户态反杀/
// 权限对抗影响)。
//
// 硬护栏(任一命中即拒绝,绝不结束 —— 防蓝屏/防自杀):
//   1) PID <= 4:Idle/System,碰即崩。
//   2) 本软件受保护进程(服务/UI 自身)。
//   3) 关键系统进程,两道独立判据,任一成立即拒绝:
//      3a) PsIsProcessCritical —— 内核【权威】标记(EPROCESS.BreakOnTermination)。这就是
//          CRITICAL_PROCESS_DIED(0xEF)的触发条件本身,比任何名单都准:真 csrss / smss /
//          wininit / winlogon / services / lsass 全都带这个标记,而伪装成同名的样本没有。
//      3b) 映像名命中关键进程名单【且】位于真正的系统目录(见 BlwIsCriticalSystemProcess)。
//          覆盖 svchost / dwm / spoolsv 这类"杀了不蓝屏但会搞坏桌面/服务"的进程。
//      这两条一起,把「真系统进程绝不误杀」和「改名伪装的样本必须能杀」同时满足 ——
//      原实现只有按名字的 3b,于是 AppData 里叫 csrss.exe 的样本反而杀不掉(实测)。
// 目标已退出/打不开则安全返回,绝不蓝屏。本函数在 PASSIVE_LEVEL 调用(FltSendMessage 处理路径)。
//
NTSTATUS
BlwKillProcessById(_In_ ULONG Pid)
{
    PEPROCESS proc = NULL;
    HANDLE hProc = NULL;
    PUNICODE_STRING imageName = NULL;
    NTSTATUS status;

    // 护栏 1:PID 合法性。
    if (Pid <= 4) {
        return STATUS_INVALID_PARAMETER;
    }
    // 护栏 2:绝不结束本软件受保护进程(自我保护,防自杀)。
    if (BlwPidIsProtected(Pid)) {
        KdPrint(("[Bulwark] KILL refused: PID %u is self-protected.\n", Pid));
        return STATUS_ACCESS_DENIED;
    }

    // 取 EPROCESS(加引用)。进程已退出则直接返回(不算失败)。
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        return status;
    }

    // 护栏 3a:内核权威的关键进程标记。带此标记的进程一被结束就是 CRITICAL_PROCESS_DIED,
    // 所以这一条就是防蓝屏的真正底线 —— 它不看名字、不看路径,伪装骗不过它。
    if (BlwProcessIsKernelCritical(proc)) {
        KdPrint(("[Bulwark] KILL refused: PID %u is kernel-critical (BreakOnTermination).\n", Pid));
        ObDereferenceObject(proc);
        return STATUS_ACCESS_DENIED;
    }

    // 护栏 3b:映像名命中关键进程名单【且】位于真正的系统目录。覆盖 svchost / dwm / spoolsv
    // 这类没有 BreakOnTermination、但结束后会搞坏桌面或成片服务的进程。
    // 注意判定里含路径条件:AppData 里改名成 csrss.exe 的样本【不】受这条豁免(那正是要杀的)。
    status = SeLocateProcessImageName(proc, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL && imageName->Buffer != NULL && imageName->Length > 0) {
        USHORT chars = (USHORT)(imageName->Length / sizeof(WCHAR));
        BOOLEAN critical = BlwIsCriticalSystemProcess(imageName->Buffer, chars);
        ExFreePool(imageName);
        if (critical) {
            KdPrint(("[Bulwark] KILL refused: PID %u is a system process in System32.\n", Pid));
            ObDereferenceObject(proc);
            return STATUS_ACCESS_DENIED;
        }
    }
    // SeLocateProcessImageName 失败时保守继续(已过 PID/受保护/内核权威三道护栏)。

    // 打开并结束。KernelMode 访问模式绕过 ACL,可结束任意非关键进程。
    status = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, NULL,
                                   PROCESS_TERMINATE, *PsProcessType, KernelMode, &hProc);
    if (NT_SUCCESS(status) && hProc != NULL) {
        status = ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
        ZwClose(hProc);
        KdPrint(("[Bulwark] Kernel-terminated PID %u (status 0x%x).\n", Pid, status));
    }

    ObDereferenceObject(proc);
    return status;
}
