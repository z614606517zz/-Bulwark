/*++
    SelfProtect.c
    自我保护(M5):ObRegisterCallbacks。

    注册进程/线程句柄操作的 Pre 回调。当其他进程试图以危险权限打开
    "受保护进程"(本安全软件的服务/UI)时,剥离这些危险权限,使得
    结束进程、写内存、创建远程线程等攻击无法得手。

    回调可能在任意进程上下文、APC_LEVEL 被调用,因此不做同步裁决,
    采取"直接剥离权限 + 异步记录"策略(业界 HIPS/EDR 通用做法)。

    放行规则:
    - 受保护进程操作自己 / 操作其他受保护进程 -> 放行
    - System(PID 4)发起的操作 -> 放行(避免影响系统)
    - 其他进程打开受保护进程 -> 剥离危险权限
--*/

#include "Driver.h"

// 进程/线程访问权限常量(内核头未必导出用户态名称,这里按官方定义补齐)
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#endif

#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE                   (0x0001)
#define THREAD_SUSPEND_RESUME              (0x0002)
#define THREAD_GET_CONTEXT                 (0x0008)
#define THREAD_SET_CONTEXT                 (0x0010)
#define THREAD_SET_INFORMATION             (0x0020)
#define THREAD_QUERY_INFORMATION           (0x0040)
#endif

// 需要剥离的进程访问权限(攻击常用)
#define BLW_PROC_DENY (PROCESS_TERMINATE | PROCESS_VM_WRITE | \
                       PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | \
                       PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION)

// 需要剥离的线程访问权限
#define BLW_THREAD_DENY (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | \
                         THREAD_SET_CONTEXT | THREAD_SET_INFORMATION)

// 内存防护(反注入/反进程镂空)剥离的进程权限:只剥「写内存 / 远程线程 / 内存操作 / 挂起」这类
// 注入和进程镂空必需的权限,保留读/查询/结束 —— 既挡住注入和镂空,又把对正常工具
// (任务管理器、调试器只读、监控软件)的误伤降到最低。
// 进程镂空(Process Hollowing)需要: PROCESS_SUSPEND_RESUME(挂起) + 
// PROCESS_VM_OPERATION(用于 NtUnmapViewOfSection) + PROCESS_VM_WRITE(写入新代码)
#define BLW_MEMPROT_PROC_DENY (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | \
                               PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME)

// 内存防护剥离的线程权限:挡住线程劫持(SetContext)与远程 APC 注入前置。
#define BLW_MEMPROT_THREAD_DENY (THREAD_SET_CONTEXT | THREAD_SET_INFORMATION)

//
// ===== 受保护 PID 管理(无锁,使用 Interlocked)=====
//

void
BlwClearProtectedPids(void)
{
    ULONG i;
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        InterlockedExchange(&g_Blw.ProtectedPids[i], 0);
    }
}

void
BlwAddProtectedPid(_In_ ULONG Pid)
{
    ULONG i;
    if (Pid == 0) {
        return;
    }
    // 去重
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if ((ULONG)g_Blw.ProtectedPids[i] == Pid) {
            return;
        }
    }
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (InterlockedCompareExchange(&g_Blw.ProtectedPids[i], (LONG)Pid, 0) == 0) {
            break;
        }
    }
}

BOOLEAN
BlwPidIsProtected(_In_ ULONG Pid)
{
    ULONG i;
    if (Pid == 0) {
        return FALSE;
    }
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if ((ULONG)g_Blw.ProtectedPids[i] == Pid) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// ===== 内存防护(反注入)目标 PID 管理(无锁,使用 Interlocked)=====
//

void
BlwClearMemProtPids(void)
{
    ULONG i;
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        InterlockedExchange(&g_Blw.MemProtPids[i], 0);
    }
}

void
BlwAddMemProtPid(_In_ ULONG Pid)
{
    ULONG i;
    if (Pid == 0) {
        return;
    }
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if ((ULONG)g_Blw.MemProtPids[i] == Pid) {
            return;  // 去重
        }
    }
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (InterlockedCompareExchange(&g_Blw.MemProtPids[i], (LONG)Pid, 0) == 0) {
            break;
        }
    }
}

BOOLEAN
BlwPidIsMemProtected(_In_ ULONG Pid)
{
    ULONG i;
    if (Pid == 0) {
        return FALSE;
    }
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if ((ULONG)g_Blw.MemProtPids[i] == Pid) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 异步上报一条自保事件(仅记录)。
//
static void
BlwReportSelfProtect(_In_ ULONG actorPid, _In_ ULONG targetPid)
{
    BLW_EVENT_MESSAGE msg;

    if (!g_Blw.Active || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    RtlZeroMemory(&msg, sizeof(msg));
    msg.EventId = (ULONG64)InterlockedIncrement64(&g_Blw.NextEventId);
    msg.Type = BlwEventSelfProtect;
    msg.ActorPid = actorPid;
    msg.ParentPid = targetPid;   // 复用字段:被保护的目标 PID

    BlwReportEvent(&msg);
}

//
// 异步上报一条内存防护(反注入)事件(仅记录)。
//
static void
BlwReportMemProtect(_In_ ULONG actorPid, _In_ ULONG targetPid)
{
    BLW_EVENT_MESSAGE msg;

    if (!g_Blw.Active || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    RtlZeroMemory(&msg, sizeof(msg));
    msg.EventId = (ULONG64)InterlockedIncrement64(&g_Blw.NextEventId);
    msg.Type = BlwEventMemoryProtect;
    msg.ActorPid = actorPid;
    msg.ParentPid = targetPid;   // 复用字段:被保护(被注入)的目标 PID

    BlwReportEvent(&msg);
}

//
// 进程/线程句柄 Pre 回调:剥离对受保护进程的危险权限。
//
static OB_PREOP_CALLBACK_STATUS
BlwPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    ULONG targetPid = 0;
    ULONG actorPid;
    ACCESS_MASK denyMask;
    PACCESS_MASK pDesired;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!g_Blw.ObCallbackRegistered) {
        return OB_PREOP_SUCCESS;
    }

    // 内核句柄不限制
    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    actorPid = HandleToULong(PsGetCurrentProcessId());

    // 取目标 PID 与「自保剥离掩码」
    if (OperationInformation->ObjectType == *PsProcessType) {
        PEPROCESS targetProc = (PEPROCESS)OperationInformation->Object;
        targetPid = HandleToULong(PsGetProcessId(targetProc));
        denyMask = BLW_PROC_DENY;
    } else if (OperationInformation->ObjectType == *PsThreadType) {
        PETHREAD targetThread = (PETHREAD)OperationInformation->Object;
        targetPid = HandleToULong(PsGetThreadProcessId(targetThread));
        denyMask = BLW_THREAD_DENY;
    } else {
        return OB_PREOP_SUCCESS;
    }

    {
        BOOLEAN targetIsSelf = BlwPidIsProtected(targetPid);
        BOOLEAN targetIsMemProt = (!targetIsSelf) && BlwPidIsMemProtected(targetPid);

        // 目标既非受保护进程、也非内存防护目标 -> 放行(绝大多数情况,零开销)。
        if (!targetIsSelf && !targetIsMemProt) {
            return OB_PREOP_SUCCESS;
        }

        // 通用豁免:操作自身、System(PID 4)、本软件受保护进程发起 -> 放行。
        if (actorPid == targetPid || actorPid == 4 || BlwPidIsProtected(actorPid)) {
            return OB_PREOP_SUCCESS;
        }

        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            pDesired = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        } else {
            pDesired = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        }

        if (targetIsSelf) {
            // 自我保护:剥离对本软件进程的全部危险权限(结束/写内存/远程线程/挂起…)。
            if ((*pDesired & denyMask) != 0) {
                *pDesired &= ~denyMask;
                BlwReportSelfProtect(actorPid, targetPid);
                KdPrint(("[Bulwark] SelfProtect: stripped 0x%x from pid %u -> pid %u\n",
                    denyMask, actorPid, targetPid));
            }
        } else {
            // 内存防护(反注入):只剥「写内存 / 远程线程」类权限,保留读/查询/结束,
            // 让跨进程注入写不进高价值进程,同时尽量不误伤正常工具。
            ACCESS_MASK memMask = (OperationInformation->ObjectType == *PsThreadType)
                ? BLW_MEMPROT_THREAD_DENY : BLW_MEMPROT_PROC_DENY;
            if ((*pDesired & memMask) != 0) {
                *pDesired &= ~memMask;
                BlwReportMemProtect(actorPid, targetPid);
                KdPrint(("[Bulwark] MemProtect: stripped 0x%x from pid %u -> pid %u (anti-inject)\n",
                    memMask, actorPid, targetPid));
            }
        }
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS
BlwRegisterObCallbacks(void)
{
    NTSTATUS status;
    OB_OPERATION_REGISTRATION ops[2];
    OB_CALLBACK_REGISTRATION reg;
    UNICODE_STRING altitude;

    if (g_Blw.ObCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(ops, sizeof(ops));

    ops[0].ObjectType = PsProcessType;
    ops[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[0].PreOperation = BlwPreOperationCallback;
    ops[0].PostOperation = NULL;

    ops[1].ObjectType = PsThreadType;
    ops[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[1].PreOperation = BlwPreOperationCallback;
    ops[1].PostOperation = NULL;

    RtlInitUnicodeString(&altitude, L"385199");

    RtlZeroMemory(&reg, sizeof(reg));
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 2;
    reg.Altitude = altitude;
    reg.RegistrationContext = NULL;
    reg.OperationRegistration = ops;

    status = ObRegisterCallbacks(&reg, &g_Blw.ObRegHandle);
    if (NT_SUCCESS(status)) {
        g_Blw.ObCallbackRegistered = TRUE;
        KdPrint(("[Bulwark] Ob callbacks registered.\n"));
    } else {
        KdPrint(("[Bulwark] ObRegisterCallbacks failed 0x%x\n", status));
    }
    return status;
}

void
BlwUnregisterObCallbacks(void)
{
    if (g_Blw.ObCallbackRegistered) {
        // 先标记停用,避免回调与卸载竞争
        g_Blw.ObCallbackRegistered = FALSE;
        if (g_Blw.ObRegHandle != NULL) {
            ObUnRegisterCallbacks(g_Blw.ObRegHandle);
            g_Blw.ObRegHandle = NULL;
        }
        KdPrint(("[Bulwark] Ob callbacks unregistered.\n"));
    }
}
