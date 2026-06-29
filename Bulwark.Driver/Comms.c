/*++
    Comms.c
    内核 <-> 用户态服务 通信(基于 Filter Manager 通信端口)。

    - BlwInitCommunication: 创建命名通信端口,等待用户态连接。
    - 连接/断开回调维护单个客户端端口。
    - BlwReportEvent: 通过 FltSendMessage(0 超时,fire-and-forget)把事件异步发给
      用户态,绝不等待回复 —— 内核永不阻塞在用户态裁决上(这是消除卡死的核心)。
--*/

#include "Driver.h"

//
// 用户态调用 FilterConnectCommunicationPort 时触发。
// 记录客户端端口,标记激活。
//
static NTSTATUS
BlwConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    g_Blw.ClientPort = ClientPort;
    // 重新初始化端口 rundown(允许此后发送方获取保护)
    ExReInitializeRundownProtection(&g_Blw.ClientPortRundown);
    g_Blw.Active = TRUE;
    *ConnectionPortCookie = NULL;

    KdPrint(("[Bulwark] User-mode service connected.\n"));
    return STATUS_SUCCESS;
}

//
// 用户态断开 / 进程退出时触发。
//
static VOID
BlwDisconnectNotify(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    KdPrint(("[Bulwark] User-mode service disconnecting...\n"));

    // 先停用,阻止新的发送方进入
    g_Blw.Active = FALSE;

    // 等待所有正在进行的发送(已 acquire rundown 的调用)完成,
    // 之后再关闭端口,杜绝对已释放端口的 use-after-free。
    ExWaitForRundownProtectionRelease(&g_Blw.ClientPortRundown);

    if (g_Blw.ClientPort != NULL) {
        FltCloseClientPort(g_Blw.Filter, &g_Blw.ClientPort);
        g_Blw.ClientPort = NULL;
    }

    KdPrint(("[Bulwark] User-mode service disconnected.\n"));
}

//
// 用户态主动发消息给内核时触发:用于下发受保护路径配置。
//
static NTSTATUS
BlwMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);

    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(BLW_CONFIG_MESSAGE)) {
        return STATUS_INVALID_PARAMETER;
    }

    // 复制到本地,避免直接访问用户态缓冲(可能在另一进程地址空间)
    BLW_CONFIG_MESSAGE cfg;
    __try {
        RtlCopyMemory(&cfg, InputBuffer, sizeof(cfg));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    // 协议握手:把内核结构体布局回给用户态校验。必须在其它命令之前处理,
    // 因为它需要写 OutputBuffer。用户态据此确认双方 Protocol.h 完全一致,
    // 布局不一致时一律降级、绝不拦截,从根上杜绝结构体错位导致的误判蓝屏。
    if (cfg.Command == BLW_CMD_HANDSHAKE) {
        if (OutputBuffer == NULL || OutputBufferLength < sizeof(BLW_HANDSHAKE_REPLY)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        __try {
            PBLW_HANDSHAKE_REPLY reply = (PBLW_HANDSHAKE_REPLY)OutputBuffer;
            reply->ProtocolVersion = BLW_PROTOCOL_VERSION;
            reply->EventMessageSize = (ULONG)sizeof(BLW_EVENT_MESSAGE);
            reply->ConfigMessageSize = (ULONG)sizeof(BLW_CONFIG_MESSAGE);
            reply->VerdictReplySize = (ULONG)sizeof(BLW_VERDICT_REPLY);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_INVALID_USER_BUFFER;
        }
        *ReturnOutputBufferLength = sizeof(BLW_HANDSHAKE_REPLY);
        return STATUS_SUCCESS;
    }

    switch (cfg.Command) {
    case BLW_CMD_CLEAR_PATHS:
        BlwClearProtectedPaths();
        KdPrint(("[Bulwark] Protected paths cleared.\n"));
        break;
    case BLW_CMD_ADD_PATH:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddProtectedPath(cfg.Path, cfg.PathLength);
            KdPrint(("[Bulwark] Protected path added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_REGKEYS:
        BlwClearProtectedRegKeys();
        KdPrint(("[Bulwark] Protected reg keys cleared.\n"));
        break;
    case BLW_CMD_ADD_REGKEY:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddProtectedRegKey(cfg.Path, cfg.PathLength);
            KdPrint(("[Bulwark] Protected reg key added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_PIDS:
        BlwClearProtectedPids();
        KdPrint(("[Bulwark] Protected pids cleared.\n"));
        break;
    case BLW_CMD_ADD_PID:
        BlwAddProtectedPid(cfg.Pid);
        KdPrint(("[Bulwark] Protected pid added: %u\n", cfg.Pid));
        break;
    case BLW_CMD_CLEAR_BLOCKIP:
        BlwClearBlockList();
        KdPrint(("[Bulwark] Net block list cleared.\n"));
        break;
    case BLW_CMD_ADD_BLOCKIP:
        BlwAddBlockIp(cfg.BlockIpV4, cfg.BlockPort);
        KdPrint(("[Bulwark] Net block added: 0x%08x:%u\n", cfg.BlockIpV4, cfg.BlockPort));
        break;
    case BLW_CMD_CLEAR_REGHARD:
        BlwClearRegHardBlock();
        KdPrint(("[Bulwark] Reg hard-block list cleared.\n"));
        break;
    case BLW_CMD_ADD_REGHARD:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddRegHardBlock(cfg.Path, cfg.PathLength);
            KdPrint(("[Bulwark] Reg hard-block added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_FILEHARD:
        BlwClearFileHardBlock();
        KdPrint(("[Bulwark] File hard-block list cleared.\n"));
        break;
    case BLW_CMD_ADD_FILEHARD:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddFileHardBlock(cfg.Path, cfg.PathLength);
            KdPrint(("[Bulwark] File hard-block added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_MEMPROT:
        BlwClearMemProtPids();
        KdPrint(("[Bulwark] MemProtect target list cleared.\n"));
        break;
    case BLW_CMD_ADD_MEMPROT:
        BlwAddMemProtPid(cfg.Pid);
        KdPrint(("[Bulwark] MemProtect target pid added: %u\n", cfg.Pid));
        break;
    case BLW_CMD_CLEAR_NOLOAD:
        BlwClearFileNoLoad();
        KdPrint(("[Bulwark] No-load module list cleared.\n"));
        break;
    case BLW_CMD_ADD_NOLOAD:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddFileNoLoad(cfg.Path, cfg.PathLength);
            KdPrint(("[Bulwark] No-load module added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_SET_FILETELEMETRY:
        // Pid 字段复用为开关:0=关,非0=开。
        InterlockedExchange(&g_Blw.FileTelemetryEnabled, cfg.Pid != 0 ? 1 : 0);
        KdPrint(("[Bulwark] File behavior telemetry %ws.\n",
            cfg.Pid != 0 ? L"enabled" : L"disabled"));
        break;
    case BLW_CMD_CLEAR_SHADOW_PIDS:
        BlwClearShadowPids();
        KdPrint(("[Bulwark] Shadow mode PIDs cleared.\n"));
        break;
    case BLW_CMD_ADD_SHADOW_PID:
        BlwAddShadowPid(cfg.Pid);
        KdPrint(("[Bulwark] Shadow mode PID added: %u\n", cfg.Pid));
        break;
    case BLW_CMD_SET_SHADOW_OBSERVE:
        InterlockedExchange(&g_Blw.ShadowObserveMode, cfg.Pid != 0 ? 1 : 0);
        KdPrint(("[Bulwark] Shadow observe mode %ws.\n",
            cfg.Pid != 0 ? L"enabled (allow all, rollback later)" : L"disabled (block destructive)"));
        break;
    case BLW_CMD_SET_SHADOW_FSREDIRECT:
        InterlockedExchange(&g_Blw.ShadowFsRedirect, cfg.Pid != 0 ? 1 : 0);
        KdPrint(("[Bulwark] Shadow filesystem redirect %ws.\n",
            cfg.Pid != 0 ? L"enabled (sandbox isolation)" : L"disabled"));
        break;
    case BLW_CMD_SET_SHADOW_SANDBOX:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwSetSandboxPath(cfg.Path, cfg.PathLength);
        }
        break;
    case BLW_CMD_SET_SHADOW_ISOLATION:
        InterlockedExchange(&g_Blw.ShadowIsolationMode, cfg.Pid != 0 ? 1 : 0);
        KdPrint(("[Bulwark] Shadow isolation mode %ws.\n",
            cfg.Pid != 0 ? L"enabled (transparent redirect to sandbox)" : L"disabled"));
        break;
    case BLW_CMD_SET_SANDBOX_EXEMPT:
        InterlockedExchange(&g_Blw.SandboxExemptMode, cfg.Pid != 0 ? 1 : 0);
        KdPrint(("[Bulwark] Sandbox exempt mode %ws.\n",
            cfg.Pid != 0 ? L"enabled (bypass all protection)" : L"disabled"));
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
BlwInitCommunication(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(DriverObject);

    // 仅允许管理员/系统连接该端口
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&portName, BLW_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    status = FltCreateCommunicationPort(
        g_Blw.Filter,
        &g_Blw.ServerPort,
        &oa,
        NULL,                 // ServerPortCookie
        BlwConnectNotify,
        BlwDisconnectNotify,
        BlwMessageNotify,
        1);                   // MaxConnections = 1 (只有服务连接)

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FltCreateCommunicationPort failed 0x%x\n", status));
        g_Blw.ServerPort = NULL;
    }
    return status;
}

void
BlwTearDownCommunication(void)
{
    // 停用并等待在途发送结束,再关闭端口(与断开回调一致的安全顺序)
    g_Blw.Active = FALSE;
    if (g_Blw.ClientPort != NULL) {
        ExWaitForRundownProtectionRelease(&g_Blw.ClientPortRundown);
        FltCloseClientPort(g_Blw.Filter, &g_Blw.ClientPort);
        g_Blw.ClientPort = NULL;
    }
    if (g_Blw.ServerPort != NULL) {
        FltCloseCommunicationPort(g_Blw.ServerPort);
        g_Blw.ServerPort = NULL;
    }
    g_Blw.Active = FALSE;
}

//
// ============ 异步事件队列实现(彻底消除卡顿)============
//
// 设计:回调 -> BlwReportEvent(自旋锁下 memcpy 入环形缓冲 + set event)-> 立即返回。
//       后台 BlwSenderThread 在 PASSIVE_LEVEL 循环:等事件 -> 出队 -> FltSendMessage
//       (0 超时,fire-and-forget)。所有 IPC 成本都在这个独立线程上,
//       完全不影响任何内核回调的执行时间。
//

//
// 后台发送线程:把环形缓冲里的事件逐条以 0 超时发给用户态。
//
static VOID
BlwSenderThread(_In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    for (;;) {
        // 等待"有事件"或"停止"信号
        KeWaitForSingleObject(&g_Blw.RingEvent, Executive, KernelMode, FALSE, NULL);

        for (;;) {
            BLW_EVENT_MESSAGE local;
            KIRQL oldIrql;
            BOOLEAN haveItem = FALSE;

            // 出队一条(自旋锁仅保护下标与拷贝,极短)
            KeAcquireSpinLock(&g_Blw.RingLock, &oldIrql);
            if (g_Blw.RingTail != g_Blw.RingHead) {
                local = g_Blw.EventRing[g_Blw.RingTail];
                g_Blw.RingTail = (g_Blw.RingTail + 1) % BLW_EVENT_QUEUE_CAP;
                haveItem = TRUE;
            }
            KeReleaseSpinLock(&g_Blw.RingLock, oldIrql);

            if (!haveItem) {
                break;  // 队列空,回到外层等待
            }

            // 发送(0 超时,不等待回复,不阻塞)。失败直接丢弃这条遥测。
            if (g_Blw.Active && g_Blw.ClientPort != NULL &&
                ExAcquireRundownProtection(&g_Blw.ClientPortRundown)) {
                if (g_Blw.Active && g_Blw.ClientPort != NULL) {
                    LARGE_INTEGER zero;
                    zero.QuadPart = 0;
                    FltSendMessage(g_Blw.Filter, &g_Blw.ClientPort,
                        &local, sizeof(local), NULL, NULL, &zero);
                }
                ExReleaseRundownProtection(&g_Blw.ClientPortRundown);
            }
        }

        if (InterlockedCompareExchange(&g_Blw.SenderStop, 0, 0) != 0) {
            break;  // 收到停止信号且已排空,退出
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
BlwStartEventQueue(void)
{
    HANDLE threadHandle = NULL;
    NTSTATUS status;

    // 预分配环形缓冲(非分页内存,供 DISPATCH_LEVEL 入队访问)
    g_Blw.EventRing = (PBLW_EVENT_MESSAGE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        (SIZE_T)BLW_EVENT_QUEUE_CAP * sizeof(BLW_EVENT_MESSAGE),
        BLW_TAG);
    if (g_Blw.EventRing == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_Blw.RingHead = 0;
    g_Blw.RingTail = 0;
    g_Blw.SenderStop = 0;
    KeInitializeSpinLock(&g_Blw.RingLock);
    // 同步事件(自动重置):入队后 set,发送线程消费后回到等待。
    KeInitializeEvent(&g_Blw.RingEvent, SynchronizationEvent, FALSE);

    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS,
        NULL, NULL, NULL, BlwSenderThread, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_Blw.EventRing, BLW_TAG);
        g_Blw.EventRing = NULL;
        return status;
    }

    // 取线程对象供卸载时等待退出,然后关句柄
    ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, *PsThreadType,
        KernelMode, (PVOID*)&g_Blw.SenderThread, NULL);
    ZwClose(threadHandle);

    KdPrint(("[Bulwark] Event queue started.\n"));
    return STATUS_SUCCESS;
}

void
BlwStopEventQueue(void)
{
    // 通知线程停止并唤醒它排空后退出
    InterlockedExchange(&g_Blw.SenderStop, 1);
    KeSetEvent(&g_Blw.RingEvent, IO_NO_INCREMENT, FALSE);

    if (g_Blw.SenderThread != NULL) {
        KeWaitForSingleObject(g_Blw.SenderThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_Blw.SenderThread);
        g_Blw.SenderThread = NULL;
    }

    if (g_Blw.EventRing != NULL) {
        ExFreePoolWithTag(g_Blw.EventRing, BLW_TAG);
        g_Blw.EventRing = NULL;
    }
    KdPrint(("[Bulwark] Event queue stopped. dropped=%lld\n",
        InterlockedCompareExchange64(&g_Blw.DroppedEvents, 0, 0)));
}

//
// 入队一条事件。所有内核回调唯一的对外路径。
// 仅自旋锁下 memcpy + 唤醒发送线程,微秒级返回;可在 <= DISPATCH_LEVEL 调用。
// 队列满则丢弃并计数,绝不阻塞调用方。
//
void
BlwReportEvent(_In_ PBLW_EVENT_MESSAGE Event)
{
    KIRQL oldIrql;
    LONG nextHead;
    BOOLEAN queued = FALSE;

    if (!g_Blw.Active || g_Blw.EventRing == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_Blw.RingLock, &oldIrql);
    nextHead = (g_Blw.RingHead + 1) % BLW_EVENT_QUEUE_CAP;
    if (nextHead != g_Blw.RingTail) {   // 未满
        g_Blw.EventRing[g_Blw.RingHead] = *Event;   // 结构体值拷贝(memcpy)
        g_Blw.RingHead = nextHead;
        queued = TRUE;
    }
    KeReleaseSpinLock(&g_Blw.RingLock, oldIrql);

    if (queued) {
        KeSetEvent(&g_Blw.RingEvent, IO_NO_INCREMENT, FALSE);
    } else {
        InterlockedIncrement64(&g_Blw.DroppedEvents);   // 队列满,丢弃(遥测可丢)
    }
}
