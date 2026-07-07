/*++
    ThreadMonitor.c
    远程线程注入监控:PsSetCreateThreadNotifyRoutine。

    用途:为规则引擎提供 RemoteThread 事件,覆盖经典的 CreateRemoteThread /
    NtCreateThreadEx 跨进程注入(向 explorer/svchost/winlogon 等注入)。

    原理:线程创建通知在「创建者」进程上下文触发,并带「目标」进程 PID。
    当创建者 != 目标(且创建者非 System / 非受保护进程)时,即为跨进程线程
    创建——这正是远程线程注入的特征。

    限制(与映像加载相同):
      - 该回调为「通知型」,无法阻止线程创建,只能仅记录上报(BlwReportEvent),
        由用户态规则引擎据此处置。
      - 仅上报「跨进程」创建,进程内自建线程(绝大多数)直接忽略,避免事件风暴。

    Target 留给用户态解析:内核侧只填目标 PID(复用 ParentPid 字段),
    用户态用 PID 解析目标进程完整路径再交规则的 TargetPattern 匹配
    (如 *\explorer.exe / *\lsass.exe)。

    回调在 PASSIVE_LEVEL 被调用,可安全调用 BlwReportEvent。
--*/

#include "Driver.h"

static BOOLEAN g_ThreadCallbackRegistered = FALSE;

//
// 高价值受害进程白名单:只有这些进程被注入时才上报。
// 大量正常软件(浏览器多进程、调试器、UWP runtime broker 等)
// 也会跨进程创建线程,如果对所有跨进程注入都上报,事件量会爆炸。
// 这里只关注被恶意软件高频针对的目标。
//
static BOOLEAN
BlwIsHighValueInjectionTarget(_In_ PCWSTR Path, _In_ USHORT Chars)
{
    static const PCWSTR kTargets[] = {
        L"\\lsass.exe",
        L"\\winlogon.exe",
        L"\\csrss.exe",
        L"\\services.exe",
        L"\\smss.exe",
        L"\\WeChat.exe",
        L"\\Weixin.exe",
        L"\\WXWork.exe",
        L"\\QQ.exe",
        L"\\TIM.exe",
    };

    UNICODE_STRING usPath, usName;
    ULONG i;

    if (Path == NULL || Chars == 0) return FALSE;

    usPath.Buffer = (PWSTR)Path;
    usPath.Length = Chars * sizeof(WCHAR);
    usPath.MaximumLength = usPath.Length;

    for (i = 0; i < RTL_NUMBER_OF(kTargets); i++) {
        RtlInitUnicodeString(&usName, kTargets[i]);
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
// 解析进程映像路径(通过 PsLookupProcessByProcessId + 取 SectionObject 名)。
// 内核侧近似匹配名字,不必拿到完整 Win32 路径。
//
static BOOLEAN
BlwGetProcessImageName(_In_ HANDLE Pid, _Out_writes_(BLW_MAX_PATH) PWCHAR Out, _Out_ PUSHORT Chars)
{
    PEPROCESS proc = NULL;
    NTSTATUS status;
    PUNICODE_STRING name = NULL;
    BOOLEAN ok = FALSE;

    *Chars = 0;
    Out[0] = L'\0';

    status = PsLookupProcessByProcessId(Pid, &proc);
    if (!NT_SUCCESS(status) || proc == NULL) return FALSE;

    if (NT_SUCCESS(SeLocateProcessImageName(proc, &name)) && name != NULL) {
        USHORT chars = name->Length / sizeof(WCHAR);
        if (chars > (BLW_MAX_PATH - 1)) chars = BLW_MAX_PATH - 1;
        RtlCopyMemory(Out, name->Buffer, chars * sizeof(WCHAR));
        Out[chars] = L'\0';
        *Chars = chars;
        ExFreePool(name);
        ok = TRUE;
    }
    ObDereferenceObject(proc);
    return ok;
}

//
// 线程创建/退出通知回调。
//
static VOID
BlwCreateThreadNotify(
    _In_ HANDLE ProcessId,   // 线程所属(目标)进程
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create)
{
    BLW_EVENT_MESSAGE msg;
    ULONG actorPid;
    ULONG targetPid;
    WCHAR targetImage[BLW_MAX_PATH];
    USHORT targetChars = 0;

    UNREFERENCED_PARAMETER(ThreadId);

    if (!g_Blw.Active || !Create) {
        return;  // 仅关心线程创建
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    actorPid = HandleToULong(PsGetCurrentProcessId());
    targetPid = HandleToULong(ProcessId);

    // 进程内自建线程(创建者==目标)-> 忽略(绝大多数,正常)。
    if (actorPid == targetPid) {
        return;
    }

    // System(PID 4)发起 -> 忽略(系统线程管理)。
    if (actorPid == 4 || actorPid == 0) {
        return;
    }

    // 受保护进程(本软件服务/UI)发起 -> 忽略。
    if (BlwPidIsProtected(actorPid)) {
        return;
    }

    //
    // 关键过滤:只对「高价值受害进程」上报。
    // 浏览器(多进程)、UWP RuntimeBroker、调试器等都会跨进程创建线程,
    // 如果全量上报会形成事件风暴。这里只关注 lsass/winlogon/IM 等
    // 恶意软件高频针对的目标。
    //
    if (!BlwGetProcessImageName(ProcessId, targetImage, &targetChars)) {
        return;  // 解析不到目标进程名,直接跳过(避免误报)
    }
    if (!BlwIsHighValueInjectionTarget(targetImage, targetChars)) {
        return;
    }

    RtlZeroMemory(&msg, sizeof(msg));
    msg.EventId = (ULONG64)InterlockedIncrement64(&g_Blw.NextEventId);
    msg.Type = BlwEventRemoteThread;
    msg.ActorPid = actorPid;
    msg.ParentPid = targetPid;   // 复用字段:被注入的目标进程 PID

    // 仅记录上报(无法阻止);用户态据规则处置。
    BlwReportEvent(&msg);
}

NTSTATUS
BlwRegisterThreadCallback(void)
{
    NTSTATUS status;

    if (g_ThreadCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetCreateThreadNotifyRoutine(BlwCreateThreadNotify);
    if (NT_SUCCESS(status)) {
        g_ThreadCallbackRegistered = TRUE;
        KdPrint(("[Bulwark] Thread-create callback registered.\n"));
    } else {
        KdPrint(("[Bulwark] PsSetCreateThreadNotifyRoutine failed 0x%x\n", status));
    }
    return status;
}

void
BlwUnregisterThreadCallback(void)
{
    if (g_ThreadCallbackRegistered) {
        PsRemoveCreateThreadNotifyRoutine(BlwCreateThreadNotify);
        g_ThreadCallbackRegistered = FALSE;
        KdPrint(("[Bulwark] Thread-create callback unregistered.\n"));
    }
}
