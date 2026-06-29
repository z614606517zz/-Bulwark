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
BOOLEAN
BlwWideContainsCI(_In_ PCWSTR Str, _In_ USHORT StrChars, _In_ PCWSTR Sub)
{
    UNICODE_STRING usStr, usSub;

    if (Str == NULL || Sub == NULL || StrChars == 0) {
        return FALSE;
    }

    usStr.Buffer = (PWSTR)Str;
    usStr.Length = StrChars * sizeof(WCHAR);
    usStr.MaximumLength = usStr.Length;

    RtlInitUnicodeString(&usSub, Sub);
    if (usSub.Length == 0 || usSub.Length > usStr.Length) {
        return FALSE;
    }

    {
        USHORT strChars = (USHORT)(usStr.Length / sizeof(WCHAR));
        USHORT subChars = (USHORT)(usSub.Length / sizeof(WCHAR));
        USHORT limit = (USHORT)(strChars - subChars);
        USHORT s;

        for (s = 0; s <= limit; s++) {
            UNICODE_STRING window;
            window.Buffer = &usStr.Buffer[s];
            window.Length = usSub.Length;
            window.MaximumLength = usSub.Length;
            if (RtlCompareUnicodeString(&window, &usSub, TRUE) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
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
    static const PCWSTR kLolBins[] = {
        L"\\powershell.exe", L"\\pwsh.exe", L"\\cmd.exe",
        L"\\wscript.exe", L"\\cscript.exe", L"\\mshta.exe",
        L"\\rundll32.exe", L"\\regsvr32.exe", L"\\certutil.exe",
        L"\\bitsadmin.exe", L"\\wmic.exe", L"\\vssadmin.exe",
        L"\\bcdedit.exe", L"\\wbadmin.exe", L"\\schtasks.exe",
        L"\\at.exe", L"\\msbuild.exe", L"\\installutil.exe",
        L"\\regsvcs.exe", L"\\regasm.exe", L"\\mavinject.exe",
        L"\\cmstp.exe", L"\\msdt.exe", L"\\hh.exe",
        L"\\forfiles.exe", L"\\pcalua.exe", L"\\scriptrunner.exe",
        L"\\netsh.exe",
    };

    UNICODE_STRING usPath;
    ULONG i;

    if (Path == NULL || Chars == 0) return FALSE;

    usPath.Buffer = (PWSTR)Path;
    usPath.Length = Chars * sizeof(WCHAR);
    usPath.MaximumLength = usPath.Length;

    for (i = 0; i < RTL_NUMBER_OF(kLolBins); i++) {
        UNICODE_STRING usName;
        RtlInitUnicodeString(&usName, kLolBins[i]);
        if (usName.Length <= usPath.Length) {
            UNICODE_STRING tail;
            tail.Buffer = (PWSTR)((PUCHAR)usPath.Buffer + usPath.Length - usName.Length);
            tail.Length = usName.Length;
            tail.MaximumLength = usName.Length;
            if (RtlCompareUnicodeString(&tail, &usName, TRUE) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
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
// 关键系统进程名单:这些进程一旦被拒绝创建/被误杀,系统会立刻 BugCheck
// (CRITICAL_PROCESS_DIED 0xEF)。无论用户态裁决如何,内核侧绝不阻止它们。
// 这是防蓝屏的最后一道硬底线 —— 即便协议错位/服务误判/超时,也不能拖垮系统。
//
// 按"映像文件名以 \名字 结尾"匹配(大小写不敏感),避免被路径前缀差异绕过。
//
static BOOLEAN
BlwIsCriticalSystemProcess(_In_ PCWSTR Path, _In_ USHORT Chars)
{
    static const PCWSTR kCritical[] = {
        L"\\smss.exe",
        L"\\csrss.exe",
        L"\\wininit.exe",
        L"\\winlogon.exe",
        L"\\services.exe",
        L"\\lsass.exe",
        L"\\svchost.exe",
        L"\\lsaiso.exe",
        L"\\fontdrvhost.exe",
        L"\\dwm.exe",
        L"\\spoolsv.exe",
        L"\\WerFault.exe",
        L"\\WerFaultSecure.exe",
        L"\\wermgr.exe",
    };

    UNICODE_STRING usPath;
    ULONG i;

    if (Path == NULL || Chars == 0) {
        return FALSE;
    }

    usPath.Buffer = (PWSTR)Path;
    usPath.Length = Chars * sizeof(WCHAR);
    usPath.MaximumLength = usPath.Length;

    for (i = 0; i < RTL_NUMBER_OF(kCritical); i++) {
        UNICODE_STRING usName;
        RtlInitUnicodeString(&usName, kCritical[i]);
        if (usName.Length <= usPath.Length) {
            UNICODE_STRING tail;
            tail.Buffer = (PWSTR)((PUCHAR)usPath.Buffer + usPath.Length - usName.Length);
            tail.Length = usName.Length;
            tail.MaximumLength = usName.Length;
            if (RtlCompareUnicodeString(&tail, &usName, TRUE) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

//
// 从 CreateInfo 拷贝映像路径到事件结构(带长度上限保护)。
//
static void
BlwCopyImagePath(_Inout_ PBLW_EVENT_MESSAGE msg, _In_opt_ PCUNICODE_STRING src)
{
    USHORT chars = 0;

    msg->ImagePath[0] = L'\0';
    msg->ImagePathLength = 0;

    if (src == NULL || src->Buffer == NULL || src->Length == 0) {
        return;
    }

    chars = (USHORT)(src->Length / sizeof(WCHAR));
    if (chars > (BLW_MAX_PATH - 1)) {
        chars = BLW_MAX_PATH - 1;
    }

    RtlCopyMemory(msg->ImagePath, src->Buffer, chars * sizeof(WCHAR));
    msg->ImagePath[chars] = L'\0';
    msg->ImagePathLength = chars;
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
    BLW_EVENT_MESSAGE msg;

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL) {
        // 进程退出,本里程碑不处理
        return;
    }

    // 仅在已连接用户态时上报;否则直接放行,降低对系统的影响。
    if (!g_Blw.Active) {
        return;
    }

    RtlZeroMemory(&msg, sizeof(msg));
    msg.EventId = (ULONG64)InterlockedIncrement64(&g_Blw.NextEventId);
    msg.Type = BlwEventProcessCreate;
    msg.ActorPid = HandleToULong(ProcessId);
    msg.ParentPid = HandleToULong(CreateInfo->ParentProcessId);

    // 优先用 ImageFileName(\??\C:\...)
    if (CreateInfo->ImageFileName != NULL) {
        BlwCopyImagePath(&msg, CreateInfo->ImageFileName);
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
    if (msg.ImagePathLength > 0 &&
        BlwImageIsTrustedSystemPath(msg.ImagePath, msg.ImagePathLength) &&
        !BlwImageIsLolBin(msg.ImagePath, msg.ImagePathLength)) {
        return;
    }

    //
    // 防蓝屏硬底线:无论命中哪条规则,关键系统进程绝不上报(也就不可能被
    // 用户态补偿结束)。这是稳定性兜底。
    //
    if (BlwIsCriticalSystemProcess(msg.ImagePath, msg.ImagePathLength)) {
        return;
    }

    //
    // 仅遥测上报,不等待裁决,立即返回。用户态规则引擎事后裁决;
    // 若为 Block,用户态自行以 TerminateProcess 结束这个 PID。
    // BlwReportEvent 内部已自带 rundown 保护,且对 IPC 失败容错,绝不挂起调用方。
    //
    BlwReportEvent(&msg);

    //
    // 影子模式(沙盒):父进程为影子 -> 子进程自动继承影子身份。
    // 这样由影子进程派生的整棵进程树都在沙盒内,副作用全部被吞掉。
    //
    if (BlwPidIsShadow(HandleToULong(CreateInfo->ParentProcessId))) {
        BlwAddShadowPid(HandleToULong(ProcessId));
    }
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
