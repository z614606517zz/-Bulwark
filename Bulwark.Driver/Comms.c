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

    // 自保护足迹随断连清除:自保是「owner-aware(仅放行本产品进程)」,而属主判定依赖运行中的
    // 受保护 PID —— 服务停了就不该再拦。清除后,更新/卸载本产品(复制新文件、删除安装目录)无需
    // 先卸载驱动即可进行(停服务即解除自保)。重新连接时由服务在 pushInitialConfig 里重新登记。
    BlwClearSelfGuard();

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

    //
    // 内核级足迹清理·读:以「忽略共享访问检查」读取被占用文件的一段到 OutputBuffer,
    // 供用户态做可逆金库副本。复用字段:Path=源文件;Pid=偏移低 32 位;BlockIpV4=偏移高 32 位。
    //
    // 必须先读进内核缓冲再拷到 OutputBuffer:OutputBuffer 是【调用方进程里的用户态地址】,
    // FltMgr 不会替我们探测或锁定它,直接把它交给 ZwReadFile 当输出缓冲既不安全也可能失败。
    // 因此走「内核缓冲 -> __try 拷贝」两步。
    //
    if (cfg.Command == BLW_CMD_QUARANTINE_READ) {
        ULONG64 offset;
        PVOID kbuf;
        ULONG want;
        ULONG got = 0;
        NTSTATUS st;

        if (OutputBuffer == NULL || OutputBufferLength == 0) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        cfg.Path[BLW_MAX_PATH - 1] = L'\0';
        if (cfg.PathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        // 夹断单次读取量,不让用户态决定内核分页池的分配尺寸(见 BLW_CLEANUP_READ_MAX)。
        want = OutputBufferLength;
        if (want > BLW_CLEANUP_READ_MAX) {
            want = BLW_CLEANUP_READ_MAX;
        }

        kbuf = ExAllocatePool2(POOL_FLAG_PAGED, want, BLW_TAG);
        if (kbuf == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        offset = ((ULONG64)cfg.BlockIpV4 << 32) | (ULONG64)cfg.Pid;
        st = BlwCleanupReadFile(cfg.Path, offset, kbuf, want, &got);
        if (NT_SUCCESS(st) && got > 0) {
            __try {
                RtlCopyMemory(OutputBuffer, kbuf, got);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                ExFreePoolWithTag(kbuf, BLW_TAG);
                return STATUS_INVALID_USER_BUFFER;
            }
        }
        ExFreePoolWithTag(kbuf, BLW_TAG);

        if (!NT_SUCCESS(st)) {
            return st;   // 打开 / 读取失败:用户态据此回退到用户态清理
        }
        *ReturnOutputBufferLength = got;   // 0 = 到达文件尾 / 空文件
        return STATUS_SUCCESS;
    }

    //
    // 内核级足迹清理·删:POSIX 强制删除被占用 / 已映射(运行中 exe、已加载 dll)的文件。
    //
    // 语义:命令本身只要参数合法就算「已受理」(返回 STATUS_SUCCESS),真正的删除结果放在
    // reply.Status(0 = 删成功;否则为 NTSTATUS)。这样用户态能区分「旧驱动不认这条命令」
    // (FilterSendMessage 失败)和「认了但没删掉」(reply.Status != 0),后者才回退用户态处置。
    //
    // 内核侧硬护栏在 BlwCleanupForceDelete 内:绝不删本产品自身内容 / 硬拦名单里的关键文件。
    //
    if (cfg.Command == BLW_CMD_FORCE_DELETE) {
        NTSTATUS st;

        if (OutputBuffer == NULL || OutputBufferLength < sizeof(BLW_FILEOP_REPLY)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        cfg.Path[BLW_MAX_PATH - 1] = L'\0';
        if (cfg.PathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        st = BlwCleanupForceDelete(cfg.Path);
        __try {
            ((PBLW_FILEOP_REPLY)OutputBuffer)->Status = (LONG)st;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_INVALID_USER_BUFFER;
        }
        *ReturnOutputBufferLength = sizeof(BLW_FILEOP_REPLY);
        KdPrint(("[Bulwark] Kernel force-delete %ws -> 0x%x\n", cfg.Path, st));
        return STATUS_SUCCESS;
    }

    switch (cfg.Command) {
    case BLW_CMD_CLEAR_PATHS:
        BlwClearProtectedPaths();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_PATHS);
        KdPrint(("[Bulwark] Protected paths cleared.\n"));
        break;
    case BLW_CMD_ADD_PATH:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddProtectedPath(cfg.Path, cfg.PathLength);
            // 裁决持久化:受保护路径写回,使服务下发的配置基线跨重启、在服务启动前即生效。
            // 这里只标脏,真正的写回由后台线程去抖合并(见 Policy.c)。
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_PATHS);
            KdPrint(("[Bulwark] Protected path added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_REGKEYS:
        BlwClearProtectedRegKeys();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_REGKEYS);
        KdPrint(("[Bulwark] Protected reg keys cleared.\n"));
        break;
    case BLW_CMD_ADD_REGKEY:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddProtectedRegKey(cfg.Path, cfg.PathLength);
            // 裁决持久化:受保护注册表键写回,基线跨重启在服务启动前即生效。
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_REGKEYS);
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
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_REGHARD);
        KdPrint(("[Bulwark] Reg hard-block list cleared.\n"));
        break;
    case BLW_CMD_ADD_REGHARD:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddRegHardBlock(cfg.Path, cfg.PathLength);
            // 裁决持久化:反重建的注册表硬拦项写回,跨重启继续挡住恶意持久化重建。
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_REGHARD);
            KdPrint(("[Bulwark] Reg hard-block added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_FILEHARD:
        BlwClearFileHardBlock();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_FILEHARD);
        KdPrint(("[Bulwark] File hard-block list cleared.\n"));
        break;
    case BLW_CMD_ADD_FILEHARD:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddFileHardBlock(cfg.Path, cfg.PathLength);
            // 裁决持久化:文件硬拦(含本产品自保二进制)写回,基线跨重启在服务启动前即自保。
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_FILEHARD);
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
    case BLW_CMD_CLEAR_CREDPROT:
        BlwClearCredProtPids();
        KdPrint(("[Bulwark] CredProtect target list cleared.\n"));
        break;
    case BLW_CMD_ADD_CREDPROT:
        BlwAddCredProtPid(cfg.Pid);
        KdPrint(("[Bulwark] CredProtect(LSASS) target pid added: %u\n", cfg.Pid));
        break;
    case BLW_CMD_CLEAR_BANNED:
        BlwClearBannedPids();
        KdPrint(("[Bulwark] Banned actor list cleared.\n"));
        break;
    case BLW_CMD_ADD_BANNED:
        // 情报确认恶意:封禁该 PID —— 其任何文件/注册表/网络/子进程行为此后一律被内核拒绝。
        BlwAddBannedPid(cfg.Pid);
        KdPrint(("[Bulwark] Banned actor pid added: %u (deny ALL its behaviors).\n", cfg.Pid));
        break;
    case BLW_CMD_CLEAR_SELFGUARD:
        // 自保护足迹清单清空(不持久化:仅服务连接期间有效)。
        BlwClearSelfGuard();
        KdPrint(("[Bulwark] SelfGuard footprint cleared.\n"));
        break;
    case BLW_CMD_ADD_SELFGUARD:
        // 追加一条本产品「完整内容」路径子串:此后非本产品受保护进程对该路径的写/删/改名一律被拒
        //(反勒索加密本产品自身)。【故意不持久化】—— 断连(停服务)即清除,使更新/卸载本产品无需
        // 先卸载驱动(停服务解除自保 -> 复制新文件 -> 再启动)。
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddSelfGuard(cfg.Path, cfg.PathLength);
            KdPrint(("[Bulwark] SelfGuard footprint added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_NOLOAD:
        BlwClearFileNoLoad();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_NOLOAD);
        KdPrint(("[Bulwark] No-load module list cleared.\n"));
        break;
    case BLW_CMD_ADD_NOLOAD:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddFileNoLoad(cfg.Path, cfg.PathLength);
            // 裁决持久化:确认恶意的侧载模块写回注册表,跨重启继续钉死「白加黑」。
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_NOLOAD);
            KdPrint(("[Bulwark] No-load module added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_CMDBLOCK:
        BlwClearCmdHardBlock();
        // 裁决持久化:把(已清空的)命令行硬拦名单写回注册表,使清空跨重启生效。
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_CMDHARD);
        KdPrint(("[Bulwark] Command hard-block list cleared.\n"));
        break;
    case BLW_CMD_ADD_CMDBLOCK:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddCmdHardBlock(cfg.Path, cfg.PathLength);
            // 裁决持久化:命令行硬拦模式写回注册表,使「删卷影 / 清日志 / 转储凭据」这类
            // 一瞬间就完成不可逆破坏的命令,在【服务未启动或被杀】时也照样被内核独立拦下。
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_CMDHARD);
            KdPrint(("[Bulwark] Command hard-block pattern added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_SET_FILETELEMETRY:
        // Pid 字段复用为开关:0=关,非0=开。
        InterlockedExchange(&g_Blw.FileTelemetryEnabled, cfg.Pid != 0 ? 1 : 0);
        KdPrint(("[Bulwark] File behavior telemetry %ws.\n",
            cfg.Pid != 0 ? L"enabled" : L"disabled"));
        break;
    case BLW_CMD_KILL_PID:
        // 驱动级结束进程:用户态 VT 确认恶意后下发。BlwKillProcessById 内带硬护栏
        //(PID>4、非受保护、非关键系统进程),失败/被拒不算通信错误 —— 一律回 STATUS_SUCCESS
        // 表示"命令已处理";真正是否结束由用户态观察 + 用户态兜底结束保证。
        (void)BlwKillProcessById(cfg.Pid);
        KdPrint(("[Bulwark] KILL_PID command for PID %u handled.\n", cfg.Pid));
        break;
    case BLW_CMD_CLEAR_EXECBLOCK:
        BlwClearFileExecBlock();
        // 裁决持久化:把(已清空的)执行前拦截名单写回注册表,使清空跨重启生效。
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_EXECBLOCK);
        KdPrint(("[Bulwark] Exec-block list cleared.\n"));
        break;
    case BLW_CMD_ADD_EXECBLOCK:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddFileExecBlock(cfg.Path, cfg.PathLength);
            // 裁决持久化:确认恶意后下发的执行前拦截项写回注册表,跨杀服务/重启由内核独立续拦。
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_EXECBLOCK);
            KdPrint(("[Bulwark] Exec-block image added: %ws\n", cfg.Path));
        }
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
        KIRQL emptyIrql;
        BOOLEAN empty;

        //
        // 先宣告「即将空闲」,再【重新判一次队列是否为空】才睡。
        // 这个顺序是生产者侧「仅在 idle 时才 KeSetEvent」优化不会丢唤醒的关键:
        // 若某个生产者在我们置 idle 之前入队并因看到 idle=0 而没有唤醒我们,
        // 那么它的入队一定发生在下面这次判空之前,我们会看到队列非空从而不睡。
        //
        InterlockedExchange(&g_Blw.SenderIdle, 1);

        KeAcquireSpinLock(&g_Blw.RingLock, &emptyIrql);
        empty = (g_Blw.RingHead == g_Blw.RingTail);
        KeReleaseSpinLock(&g_Blw.RingLock, emptyIrql);

        if (empty && InterlockedCompareExchange(&g_Blw.SenderStop, 0, 0) == 0) {
            // 等待"有事件"或"停止"信号
            KeWaitForSingleObject(&g_Blw.RingEvent, Executive, KernelMode, FALSE, NULL);
        }

        InterlockedExchange(&g_Blw.SenderIdle, 0);

        for (;;) {
            BLW_EVENT_MESSAGE local;
            KIRQL oldIrql;
            BOOLEAN haveItem = FALSE;

            // 出队一条(自旋锁仅保护下标与拷贝,极短)
            KeAcquireSpinLock(&g_Blw.RingLock, &oldIrql);
            if (g_Blw.RingTail != g_Blw.RingHead) {
                local = g_Blw.EventRing[g_Blw.RingTail];
                g_Blw.RingTail = (g_Blw.RingTail + 1) & BLW_EVENT_QUEUE_MASK;
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
    g_Blw.SenderIdle = 0;
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
// 往事件结构的某个路径字段里填一条 UNICODE_STRING(带长度上限与结尾 NUL)。
// 尾部剩余空间一并清零:环形槽是复用的,不清零会把上一条事件的路径残留一起发给用户态。
// 清零总量与原来「在栈上 RtlZeroMemory 整个结构」相同,只是不再多一次 2KB 的整体拷贝。
//
static void
BlwFillPathField(
    _Out_writes_(BLW_MAX_PATH) PWCHAR Dest,
    _Out_ PUSHORT DestChars,
    _In_opt_ PCUNICODE_STRING Src)
{
    USHORT chars = 0;

    if (Src != NULL && Src->Buffer != NULL && Src->Length > 0) {
        chars = (USHORT)(Src->Length / sizeof(WCHAR));
        if (chars > (BLW_MAX_PATH - 1)) {
            chars = BLW_MAX_PATH - 1;
        }
        RtlCopyMemory(Dest, Src->Buffer, (SIZE_T)chars * sizeof(WCHAR));
    }
    RtlZeroMemory(&Dest[chars], (SIZE_T)(BLW_MAX_PATH - chars) * sizeof(WCHAR));
    *DestChars = chars;
}

//
// 入队一条事件。所有内核回调唯一的对外路径。
// 仅自旋锁下就地填槽 + 必要时唤醒发送线程,微秒级返回;可在 <= DISPATCH_LEVEL 调用。
// 队列满则丢弃并计数,绝不阻塞调用方。
//
void
BlwReportEvent(
    _In_ ULONG Type,
    _In_ ULONG ActorPid,
    _In_ ULONG ParentPid,
    _In_opt_ PCUNICODE_STRING TargetPath,
    _In_opt_ PCUNICODE_STRING ImagePath,
    _In_ ULONG RemoteIpV4,
    _In_ USHORT RemotePort)
{
    KIRQL oldIrql;
    LONG nextHead;
    BOOLEAN queued = FALSE;

    if (!g_Blw.Active || g_Blw.EventRing == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_Blw.RingLock, &oldIrql);
    nextHead = (g_Blw.RingHead + 1) & BLW_EVENT_QUEUE_MASK;
    if (nextHead != g_Blw.RingTail) {   // 未满
        PBLW_EVENT_MESSAGE slot = &g_Blw.EventRing[g_Blw.RingHead];

        // 就地构造(不经栈上中转)。
        slot->EventId = (ULONG64)InterlockedIncrement64(&g_Blw.NextEventId);
        slot->Type = Type;
        slot->ActorPid = ActorPid;
        slot->ParentPid = ParentPid;
        slot->RemoteIpV4 = RemoteIpV4;
        slot->RemotePort = RemotePort;
        BlwFillPathField(slot->ImagePath, &slot->ImagePathLength, ImagePath);
        BlwFillPathField(slot->TargetPath, &slot->TargetPathLength, TargetPath);

        g_Blw.RingHead = nextHead;
        queued = TRUE;
    }
    KeReleaseSpinLock(&g_Blw.RingLock, oldIrql);

    if (!queued) {
        InterlockedIncrement64(&g_Blw.DroppedEvents);   // 队列满,丢弃(遥测可丢)
        return;
    }

    //
    // 只在发送线程确实处于(或即将进入)等待时才付出 KeSetEvent 的代价 —— 它要获取调度器锁,
    // 在开机 / 登录这类事件突发里对每条事件都做一次是纯浪费(发送线程本来就在排空循环里)。
    // CAS 成功(1 -> 0)说明我们把它从「空闲」状态领走了,必须负责唤醒它。
    // 不会丢唤醒:发送线程在置 idle=1 之后【必定再判一次队列是否为空】,若非空就不睡而直接排空,
    // 因此「生产者看到 idle=0 而不唤醒」的情形下,发送线程一定还会再看一遍队列。
    //
    if (InterlockedCompareExchange(&g_Blw.SenderIdle, 0, 1) == 1) {
        KeSetEvent(&g_Blw.RingEvent, IO_NO_INCREMENT, FALSE);
    }
}
