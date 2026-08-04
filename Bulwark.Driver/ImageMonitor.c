/*++
    ImageMonitor.c
    模块/驱动加载监控:PsSetLoadImageNotifyRoutine。

    用途:为规则引擎提供 ImageLoad 事件,覆盖:
      - BYOVD:从用户可写目录加载内核驱动(.sys)
      - DLL 侧载:合法进程从 AppData/Temp 等可写目录加载 DLL

    重要限制:
      1) 该回调是「通知型」,无法阻止加载(不像进程创建可置 STATUS_ACCESS_DENIED)。
         因此只「仅记录上报」(BlwReportEvent),由用户态规则引擎决定后续处置
         (如结束加载进程 / 告警)。
      2) 系统内每个 EXE/DLL 加载都会触发本回调,量极大。必须在内核侧先做强过滤,
         只上报「可疑路径」的加载,否则会淹没用户态并拖慢系统。

    回调在加载进程的上下文、PASSIVE_LEVEL 被调用,可安全调用 BlwReportEvent。
--*/

#include "Driver.h"

static BOOLEAN g_ImageCallbackRegistered = FALSE;

//
// 大小写不敏感:判断 Str 是否包含子串 Sub。Str/Sub 均为以 NUL 结尾的宽字符。
//
static BOOLEAN
BlwWideContains(_In_ PCWSTR Str, _In_ USHORT StrChars, _In_ PCWSTR Sub)
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
        USHORT strChars = usStr.Length / sizeof(WCHAR);
        USHORT subChars = usSub.Length / sizeof(WCHAR);
        USHORT limit = strChars - subChars;
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
// 判断映像是否以 ".sys" 结尾(内核驱动模块)。
//
static BOOLEAN
BlwEndsWithSys(_In_ PCWSTR Str, _In_ USHORT StrChars)
{
    if (Str == NULL || StrChars < 4) {
        return FALSE;
    }
    return (Str[StrChars - 4] == L'.' &&
            (Str[StrChars - 3] == L's' || Str[StrChars - 3] == L'S') &&
            (Str[StrChars - 2] == L'y' || Str[StrChars - 2] == L'Y') &&
            (Str[StrChars - 1] == L's' || Str[StrChars - 1] == L'S'));
}

//
// 可疑落地目录(仅保留正常软件几乎不出现的高风险位置)。
//
// 重要:许多正常软件(Electron 应用如 Slack/Discord/Teams、Steam 游戏、
// 部分浏览器扩展)会从 AppData/ProgramData 加载大量 DLL。如果对这些目录
// 全量上报,事件量会瞬间爆炸,把系统拖垮。这里只保留:
//   - \Temp\:正常程序极少把 DLL 长期放在 Temp 加载
//   - \Users\Public\:正常软件不在这里部署(明显恶意特征)
// AppData / ProgramData / Downloads 等改由「用户态规则 + 启动后处置」
// 处理,内核侧不再做这种宽口径上报。
//
// 【这份名单只用于用户态 DLL】。刻意不加 AppData / ProgramData —— 那正是上面说的事件风暴
// 来源。侧载 DLL 的检测改由用户态承担:主体进程创建事件本来就会上报(ProgramData / AppData
// 都不在内核的可信路径白名单里),服务在富化该事件时会顺带校验同目录模块是否「签名后被篡改」
// (见 Worker::detectSideloadedTamperedModule)。那条路径能拿到验签能力、有缓存、且只在
// 进程创建这条低频路径上跑一次,比在每个 DLL 加载上做宽口径上报正确得多。
//
static BOOLEAN
BlwPathIsSuspicious(_In_ PCWSTR Path, _In_ USHORT Chars)
{
    return BlwWideContains(Path, Chars, L"\\Temp\\")
        || BlwWideContains(Path, Chars, L"\\Users\\Public\\");
}

//
// 「用户可写目录」判定 —— 只用于【内核模块(.sys)】加载,即 BYOVD。
//
// 与上面那份名单分开的理由:事件风暴的来源是用户态 DLL(一个 Electron 应用启动就加载上百个),
// 而内核驱动加载是极低频事件(整机每天个位数),对它用宽口径判定没有任何量级风险。
//
// 原实现两者共用那份窄名单,于是「从 ProgramData / AppData 加载未签名驱动」这条 BYOVD 路径
// 完全不上报 —— 而攻击者把易受攻击的签名驱动丢在 ProgramData 下再加载,是这类攻击最常见的落法
//(丢在 \Temp\ 反而不典型,因为驱动要长期驻留)。这是一处纯粹的覆盖缺口,补上不付任何代价。
//
static BOOLEAN
BlwPathIsUserWritable(_In_ PCWSTR Path, _In_ USHORT Chars)
{
    return BlwWideContains(Path, Chars, L"\\Temp\\")
        || BlwWideContains(Path, Chars, L"\\Users\\Public\\")
        || BlwWideContains(Path, Chars, L"\\ProgramData\\")
        || BlwWideContains(Path, Chars, L"\\AppData\\")
        || BlwWideContains(Path, Chars, L"\\Downloads\\")
        || BlwWideContains(Path, Chars, L"\\Desktop\\");
}

//
// 映像加载通知回调。
//
static VOID
BlwLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    USHORT chars;
    BOOLEAN isKernelModule;
    BOOLEAN report = FALSE;

    if (!g_Blw.Active) {
        return;
    }
    if (FullImageName == NULL || FullImageName->Buffer == NULL || FullImageName->Length == 0) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;  // 无法安全发送
    }

    // 用完整长度做下面的过滤判定(上报时的长度截断由 BlwReportEvent 内部负责)。
    // 原实现先把 chars 截到 BLW_MAX_PATH-1 再判定,会让超长路径的 ".sys" 后缀判定看错位置。
    chars = (USHORT)(FullImageName->Length / sizeof(WCHAR));

    // ProcessId == 0 表示内核驱动加载(SystemModeImage 亦标识系统模块)。
    isKernelModule = (ProcessId == NULL) || (ImageInfo != NULL && ImageInfo->SystemModeImage);

    //
    // 强过滤:仅上报可疑加载,避免事件风暴。
    //   1) 内核驱动(.sys)从用户可写目录加载 -> 疑似 BYOVD
    //   2) 用户态 DLL 从可疑目录加载 -> 疑似 DLL 侧载
    // 系统目录(System32/WinSxS/Program Files)下的正常加载一律忽略。
    //
    if (isKernelModule) {
        // 驱动加载(BYOVD):只关心从【用户可写目录】加载的 .sys。这里用宽口径判定 ——
        // 驱动加载是极低频事件,不存在事件风暴风险,而 ProgramData / AppData 恰恰是这类
        // 攻击最常见的落点(见 BlwPathIsUserWritable 的说明)。
        if (BlwEndsWithSys(FullImageName->Buffer, chars) &&
            BlwPathIsUserWritable(FullImageName->Buffer, chars)) {
            report = TRUE;
        }
    } else {
        // 用户态模块:从可疑目录加载即上报(用户态再按签名/规则细化)。
        if (BlwPathIsSuspicious(FullImageName->Buffer, chars)) {
            report = TRUE;
        }
    }

    if (!report) {
        return;
    }

    // 被加载的模块路径放入 TargetPath(供规则 TargetPattern 匹配,如 *.sys / *\AppData\*.dll)。
    // 仅记录上报(无法阻止加载);用户态据此处置。
    BlwReportEvent(BlwEventImageLoad,
                   isKernelModule ? 0 : HandleToULong(ProcessId), 0,
                   FullImageName, NULL, 0, 0);
}

NTSTATUS
BlwRegisterImageCallback(void)
{
    NTSTATUS status;

    if (g_ImageCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetLoadImageNotifyRoutine(BlwLoadImageNotify);
    if (NT_SUCCESS(status)) {
        g_ImageCallbackRegistered = TRUE;
        KdPrint(("[Bulwark] Image-load callback registered.\n"));
    } else {
        KdPrint(("[Bulwark] PsSetLoadImageNotifyRoutine failed 0x%x\n", status));
    }
    return status;
}

void
BlwUnregisterImageCallback(void)
{
    if (g_ImageCallbackRegistered) {
        PsRemoveLoadImageNotifyRoutine(BlwLoadImageNotify);
        g_ImageCallbackRegistered = FALSE;
        KdPrint(("[Bulwark] Image-load callback unregistered.\n"));
    }
}
