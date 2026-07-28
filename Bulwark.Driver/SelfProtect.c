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

// 凭据保护(反转储·LSASS)剥离的进程权限:在反注入基础上【额外剥离 PROCESS_VM_READ】——
// 读 lsass 进程内存正是 mimikatz / procdump / comsvcs MiniDump 等凭据转储的核心手段。
// 连同写内存 / 内存操作 / 远程线程 / 挂起一并剥离,凭据既读不出、也注入不进。刻意【保留】
// PROCESS_QUERY_INFORMATION / PROCESS_TERMINATE / SYNCHRONIZE,不影响任务管理器枚举与进程管理。
#define BLW_CRED_PROC_DENY (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | \
                            PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME)

//
// ===== PID 集合通用原语(读侧完全无锁)=====
//
// 三个「只在配置下发时变更」的集合(受保护 / 反注入 / 凭据保护)共用这组原语。
// 读侧先做一次 64 位掩码位测试即可否决绝大多数查询(见 Driver.h 的 BLW_PID_BIT 说明),
// 只有位命中时才退回原来的 64 槽线性扫描给出最终判定 —— 判定结果与原实现逐位一致。
//

static BOOLEAN
BlwPidSetContains(_In_ volatile LONG* Set, _In_ volatile LONG64* Mask, _In_ ULONG Pid)
{
    ULONG i;

    if (Pid == 0) {
        return FALSE;
    }

    // 【热路径主分支】一次原子读 + 位测试。位为 0 => 该 PID 绝不在集合中,立即返回。
    // 把原来「每次查询 64 次内存访问」降为「1 次」。集合为空时掩码恒为 0,开销更是趋零。
    if (((ULONG64)*Mask & BLW_PID_BIT(Pid)) == 0) {
        return FALSE;
    }

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if ((ULONG)Set[i] == Pid) {
            return TRUE;
        }
    }
    return FALSE;
}

static void
BlwPidSetAdd(_Inout_ volatile LONG* Set, _Inout_ volatile LONG64* Mask, _In_ ULONG Pid)
{
    ULONG i;

    if (Pid == 0) {
        return;
    }
    // 去重
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if ((ULONG)Set[i] == Pid) {
            return;
        }
    }

    // 定序铁律:【先置掩码位,再写槽位】。中间态只会是「掩码有、集合无」,读者线性扫描
    // 返回 FALSE,等价于「尚未加入」—— 绝不会出现「集合有、掩码无」的假否决。
    InterlockedOr64(Mask, (LONG64)BLW_PID_BIT(Pid));

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (InterlockedCompareExchange(&Set[i], (LONG)Pid, 0) == 0) {
            break;
        }
    }
}

static void
BlwPidSetClear(_Inout_ volatile LONG* Set, _Inout_ volatile LONG64* Mask)
{
    ULONG i;

    // 定序铁律:【先清槽位,再清掩码】。中间态同样只会是「掩码有、集合无」(安全)。
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        InterlockedExchange(&Set[i], 0);
    }
    InterlockedExchange64(Mask, 0);
}

//
// ===== 受保护 PID 管理 =====
//

void
BlwClearProtectedPids(void)
{
    BlwPidSetClear(g_Blw.ProtectedPids, &g_Blw.ProtectedPidMask);
}

void
BlwAddProtectedPid(_In_ ULONG Pid)
{
    BlwPidSetAdd(g_Blw.ProtectedPids, &g_Blw.ProtectedPidMask, Pid);
}

BOOLEAN
BlwPidIsProtected(_In_ ULONG Pid)
{
    return BlwPidSetContains(g_Blw.ProtectedPids, &g_Blw.ProtectedPidMask, Pid);
}

//
// ===== 内存防护(反注入)目标 PID 管理 =====
//

void
BlwClearMemProtPids(void)
{
    BlwPidSetClear(g_Blw.MemProtPids, &g_Blw.MemProtPidMask);
}

void
BlwAddMemProtPid(_In_ ULONG Pid)
{
    BlwPidSetAdd(g_Blw.MemProtPids, &g_Blw.MemProtPidMask, Pid);
}

BOOLEAN
BlwPidIsMemProtected(_In_ ULONG Pid)
{
    return BlwPidSetContains(g_Blw.MemProtPids, &g_Blw.MemProtPidMask, Pid);
}

//
// ===== 凭据保护(反转储)目标 PID 管理 =====
//

void
BlwClearCredProtPids(void)
{
    BlwPidSetClear(g_Blw.CredProtPids, &g_Blw.CredProtPidMask);
}

void
BlwAddCredProtPid(_In_ ULONG Pid)
{
    BlwPidSetAdd(g_Blw.CredProtPids, &g_Blw.CredProtPidMask, Pid);
}

BOOLEAN
BlwPidIsCredProtected(_In_ ULONG Pid)
{
    return BlwPidSetContains(g_Blw.CredProtPids, &g_Blw.CredProtPidMask, Pid);
}

//
// ===== 已封禁主体(情报确认恶意)PID 管理 =====
//
// 命中即各拦截回调对该 PID 的文件写/删/改、注册表写、网络外联、创建子进程一律拒绝。
// 「情报一确认即全维封杀」,不依赖结束进程的时机;结束进程被反抗/滞后时它也做不成任何事。
//
// 与其余三个集合的唯一区别:本集合【存在并发写】—— 进程退出时摘除(BlwRemoveBannedPid,
// 系统里每个进程退出都会调到)vs 情报确认时加入(命令下发 / HashScan worker)。摘除必须
// 重算掩码,而重算若与并发加入交错,可能把刚加入 PID 的位擦掉,造成真正的假否决。
// 因此【写侧】用 BannedLock 互斥;【读侧】(BlwPidIsBanned,出现在所有拦截热路径上)
// 依旧全程无锁。
//

// 按当前槽位内容重算封禁集掩码。调用方必须持有 BannedLock。
static void
BlwRebuildBannedMask(void)
{
    ULONG64 mask = 0;
    ULONG i;

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        ULONG p = (ULONG)g_Blw.BannedPids[i];
        if (p != 0) {
            mask |= BLW_PID_BIT(p);
        }
    }
    InterlockedExchange64(&g_Blw.BannedPidMask, (LONG64)mask);
}

void
BlwClearBannedPids(void)
{
    KIRQL oldIrql;
    ULONG i;

    KeAcquireSpinLock(&g_Blw.BannedLock, &oldIrql);
    // 定序铁律:先清槽位,再清掩码。
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        InterlockedExchange(&g_Blw.BannedPids[i], 0);
    }
    InterlockedExchange(&g_Blw.BannedPidCount, 0);
    InterlockedExchange64(&g_Blw.BannedPidMask, 0);
    KeReleaseSpinLock(&g_Blw.BannedLock, oldIrql);
}

void
BlwAddBannedPid(_In_ ULONG Pid)
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN added = FALSE;

    // 硬护栏:绝不封禁 Idle/System(<=4)、本软件受保护进程(防自封)、凭据保护进程(如 lsass)。
    // 已知恶意集与用户态信誉/规则只会针对用户态恶意样本,系统关键进程不会进封禁集。
    // 两个查表本身无锁,放在取锁之前判定。
    if (Pid <= 4) {
        return;
    }
    if (BlwPidIsProtected(Pid) || BlwPidIsCredProtected(Pid)) {
        return;
    }

    KeAcquireSpinLock(&g_Blw.BannedLock, &oldIrql);
    // 去重
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if ((ULONG)g_Blw.BannedPids[i] == Pid) {
            KeReleaseSpinLock(&g_Blw.BannedLock, oldIrql);
            return;
        }
    }
    // 定序铁律:先置掩码位,再写槽位。
    InterlockedOr64(&g_Blw.BannedPidMask, (LONG64)BLW_PID_BIT(Pid));
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (InterlockedCompareExchange(&g_Blw.BannedPids[i], (LONG)Pid, 0) == 0) {
            InterlockedIncrement(&g_Blw.BannedPidCount);
            added = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_Blw.BannedLock, oldIrql);

    if (added) {
        KdPrint(("[Bulwark] Banned actor PID %u (deny ALL its behaviors).\n", Pid));
    }
}

void
BlwRemoveBannedPid(_In_ ULONG Pid)
{
    KIRQL oldIrql;
    ULONG i;

    if (Pid == 0) {
        return;
    }

    // 【进程退出热路径】无锁双重快速否决:封禁集为空、或布隆位未置 => 与本 PID 无关,
    // 立刻返回,既不取锁也不扫表。系统里几乎所有进程退出都走这条路径(原实现无论如何
    // 都要扫满 64 槽)。
    if (g_Blw.BannedPidCount <= 0 ||
        ((ULONG64)g_Blw.BannedPidMask & BLW_PID_BIT(Pid)) == 0) {
        return;
    }

    KeAcquireSpinLock(&g_Blw.BannedLock, &oldIrql);
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if ((ULONG)g_Blw.BannedPids[i] == Pid) {
            // 定序铁律:先清槽位,再重算掩码 —— 中间态只会「掩码有、集合无」(安全)。
            InterlockedExchange(&g_Blw.BannedPids[i], 0);
            InterlockedDecrement(&g_Blw.BannedPidCount);
            BlwRebuildBannedMask();
            break;
        }
    }
    KeReleaseSpinLock(&g_Blw.BannedLock, oldIrql);
}

BOOLEAN
BlwPidIsBanned(_In_ ULONG Pid)
{
    return BlwPidSetContains(g_Blw.BannedPids, &g_Blw.BannedPidMask, Pid);
}

//
// 异步上报一条自保事件(仅记录)。
//
static void
BlwReportSelfProtect(_In_ ULONG actorPid, _In_ ULONG targetPid)
{
    if (!g_Blw.Active || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    // ParentPid 复用字段:被保护的目标 PID。
    BlwReportEvent(BlwEventSelfProtect, actorPid, targetPid, NULL, NULL, 0, 0);
}

//
// 异步上报一条内存防护(反注入)事件(仅记录)。
//
static void
BlwReportMemProtect(_In_ ULONG actorPid, _In_ ULONG targetPid)
{
    if (!g_Blw.Active || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    // ParentPid 复用字段:被保护(被注入)的目标 PID。
    BlwReportEvent(BlwEventMemoryProtect, actorPid, targetPid, NULL, NULL, 0, 0);
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
    ULONG64 anyTargetMask;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!g_Blw.ObCallbackRegistered) {
        return OB_PREOP_SUCCESS;
    }

    // 内核句柄不限制
    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    //
    // 【热路径第一道闸】本回调运行在全系统每一次进程/线程句柄的创建与复制上,是内核里
    // 最高频的回调之一。三个「被保护目标」集合的布隆掩码一次并起来:全为 0 说明没有任何
    // 需要保护的目标(服务未启动 / 未下发时的常态),立刻放行 —— 连目标 PID 都不必取。
    //
    anyTargetMask = (ULONG64)g_Blw.ProtectedPidMask |
                    (ULONG64)g_Blw.CredProtPidMask |
                    (ULONG64)g_Blw.MemProtPidMask;
    if (anyTargetMask == 0) {
        return OB_PREOP_SUCCESS;
    }

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

    //
    // 【热路径第二道闸】单次位测试即可否决绝大多数句柄操作:目标 PID 的位在三个集合的
    // 并集掩码里都没置 => 它绝不属于任何被保护集合,放行。原实现在此要做三次 64 槽线性
    // 扫描(最多 192 次内存访问),现在是 1 次位测试。位命中时才走下面的精确判定,
    // 因此【最终判定与剥权行为与原实现完全一致】。
    //
    if ((anyTargetMask & BLW_PID_BIT(targetPid)) == 0) {
        return OB_PREOP_SUCCESS;
    }

    actorPid = HandleToULong(PsGetCurrentProcessId());

    {
        BOOLEAN targetIsSelf = BlwPidIsProtected(targetPid);
        // 凭据保护优先级高于反注入(其掩码是反注入的超集,额外含 VM_READ)。
        BOOLEAN targetIsCred = (!targetIsSelf) && BlwPidIsCredProtected(targetPid);
        BOOLEAN targetIsMemProt = (!targetIsSelf && !targetIsCred) && BlwPidIsMemProtected(targetPid);

        // 目标既非受保护进程、也非凭据保护、也非内存防护目标 -> 放行(绝大多数情况,零开销)。
        if (!targetIsSelf && !targetIsCred && !targetIsMemProt) {
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
        } else if (targetIsCred) {
            // 凭据保护(反转储·LSASS):在反注入基础上【额外剥 PROCESS_VM_READ】,挡住
            // mimikatz / procdump 等读 lsass 内存偷凭据;线程句柄沿用反注入线程掩码防线程劫持。
            //
            // 【关键:静默剥权,绝不上报事件】。读 lsass 的合法程序极多(杀软/EDR/备份/监控,如
            // 卡巴斯基 avp.exe),若像反注入那样上报 BlwReportMemProtect,会被用户态「内存注入 VT
            // 验证」当成注入源去查信誉 → 误判恶意 → 结束进程 + 加入禁止执行名单(曾误杀共存杀软)。
            // 凭据保护的正确语义是「拦住转储读取本身」,而【不追杀读取方】—— 故这里只剥权、不产生
            // 任何事件,杜绝误杀合法 lsass 读取方的连锁反应。攻击者的转储照样因缺 VM_READ 而失败。
            ACCESS_MASK credMask = (OperationInformation->ObjectType == *PsThreadType)
                ? BLW_MEMPROT_THREAD_DENY : BLW_CRED_PROC_DENY;
            if ((*pDesired & credMask) != 0) {
                *pDesired &= ~credMask;
                KdPrint(("[Bulwark] CredProtect(LSASS): stripped 0x%x from pid %u -> pid %u (anti-dump, silent)\n",
                    credMask, actorPid, targetPid));
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
