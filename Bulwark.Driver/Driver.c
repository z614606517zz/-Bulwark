/*++
    Driver.c
    磐垒主动防御内核驱动入口。

    设计:
    - 注册一个"无操作回调"的 Minifilter,目的只是借用 Filter Manager 提供的
      通信端口机制(FltCreateCommunicationPort / FltSendMessage)与用户态服务通信。
    - 通过 PsSetCreateProcessNotifyRoutineEx 拦截进程创建。
    - 进程创建时,把事件发给用户态等待裁决;若裁决为 Block,设置
      CreateInfo->CreationStatus = STATUS_ACCESS_DENIED 阻止进程启动。

    全部使用微软文档化 API,PatchGuard 友好。
--*/

#include "Driver.h"

BLW_GLOBALS g_Blw = { 0 };

DRIVER_INITIALIZE DriverEntry;

//
// Minifilter 卸载回调:Filter Manager 请求卸载时调用。
//
static NTSTATUS
BlwFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    NTSTATUS wfpStatus;

    PAGED_CODE();

    //
    // 卸载顺序至关重要,否则会触发 BugCheck 0xCE
    // (DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS):
    //
    // 0) 先拆 WFP,并且【拆不掉就整体放弃卸载】(详见下方)。
    // 1) 再注销其余不属于 Minifilter 的独立回调(进程/注册表/对象),
    //    这些回调的函数指针都指向本驱动镜像,卸载前必须全部摘除。
    // 2) 关闭通信端口,停止与用户态的收发。
    // 3) 最后调用 FltUnregisterFilter —— 这是关键的一步:
    //    它会 detach 所有卷实例,并【排空所有在途的 IRP_MJ_CREATE /
    //    IRP_MJ_SET_INFORMATION 预操作回调】,确保 Filter Manager 不再
    //    持有指向本驱动 BlwPreCreate/BlwPreSetInformation 的指针,
    //    之后镜像被卸载才安全。原实现遗漏了这一步,导致镜像卸载后
    //    Filter Manager 仍调用已释放内存中的 BlwPreCreate → 蓝屏。
    //

    //
    // 【WFP 必须第一个拆,而且是唯一可以否决整次卸载的一步】
    //
    // 其余回调的注销都是"一定成功"的(Ps*/Cm*/Ob* 的 Remove 系列没有失败语义),
    // 只有 WFP callout 的注销会因为过滤引擎仍持有引用而返回 STATUS_DEVICE_BUSY。
    // 一旦出现这种情况,WFP 里还留着指向本镜像 BlwClassifyFn 的指针,镜像卸载后
    // 下一条外发连接就会跳进已释放内存 —— 蓝屏。
    //
    // 所以把它提到【所有拆卸动作之前】:失败时什么都还没动,直接返回
    // STATUS_FLT_DO_NOT_DETACH 让 Filter Manager 保持本驱动加载(fltmc unload 会
    // 报"设备正忙",用户稍后重试即可,BlwUnregisterWfp 内部状态支持续拆)。
    // 若换成原来那样"先拆一堆再拆 WFP",发现拆不掉时已经无法回头了。
    //
    // 例外:强制卸载(FLTFL_FILTER_UNLOAD_MANDATORY,如系统关机路径)【不允许】否决,
    // 此时只能记录并继续 —— 但那条路径上系统即将停止调度,风险窗口趋近于零。
    //
    wfpStatus = BlwUnregisterWfp();
    if (!NT_SUCCESS(wfpStatus)) {
        if (!FlagOn(Flags, FLTFL_FILTER_UNLOAD_MANDATORY)) {
            KdPrint(("[Bulwark] Unload REFUSED: WFP callout still busy (0x%x). "
                     "Nothing torn down; retry later.\n", wfpStatus));
            return STATUS_FLT_DO_NOT_DETACH;
        }
        KdPrint(("[Bulwark] Mandatory unload: proceeding despite WFP 0x%x.\n", wfpStatus));
    }

    BlwUnregisterProcessCallback();
    BlwUnregisterImageCallback();
    BlwUnregisterThreadCallback();
    BlwUnregisterRegistryCallback();
    BlwUnregisterObCallbacks();

    //
    // 设备对象只有在 callout 确实注销掉之后才能删 —— callout 是依附在它上面注册的。
    // WfpCalloutId != 0 表示注销没成功(只可能出现在上面的强制卸载分支),此时宁可
    // 泄漏一个设备对象,也绝不删掉 WFP 还在引用的对象。
    //
    if (g_Blw.WfpDeviceObject != NULL && g_Blw.WfpCalloutId == 0) {
        IoDeleteDevice(g_Blw.WfpDeviceObject);
        g_Blw.WfpDeviceObject = NULL;
    }
    // 停止哈希扫描 worker:进程回调已摘除(不再有新 PID 入队),且必须在 BlwStopEventQueue 之前
    // (worker 命中时会经 BlwReportEvent 用事件环)。等其退出后再拆事件队列,杜绝对已释放环的访问。
    BlwStopHashWorker();

    // 停止策略写回线程:会把仍未落地的脏名单全部刷进注册表后再退出,
    // 保证「已学习裁决」(执行前拦截 / 禁止加载 / 注册表硬拦)不因去抖延迟而丢失。
    // 必须在此(仍可安全调用 Zw* 的 PASSIVE_LEVEL 阶段)完成。
    BlwStopPolicyPersist();

    // 所有回调已摘除,不会再有新事件入队;停止并排空后台发送线程,
    // 必须在关闭通信端口之前(发送线程仍可能在用 ClientPort)。
    BlwStopEventQueue();
    BlwTearDownCommunication();

    // 排空并注销 Minifilter(摘除 I/O 预操作回调)。必须在返回前完成。
    if (g_Blw.Filter != NULL) {
        FltUnregisterFilter(g_Blw.Filter);
        g_Blw.Filter = NULL;
    }

    return STATUS_SUCCESS;
}

//
// 本驱动挂接 IRP_MJ_CREATE 与 IRP_MJ_SET_INFORMATION 的预操作回调用于文件防护,
// 并借用 Minifilter 的通信端口与用户态交互。
//
CONST FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE,          0, BlwPreCreate,         NULL },
    { IRP_MJ_SET_INFORMATION, 0, BlwPreSetInformation, NULL },
    { IRP_MJ_WRITE,           0, BlwPreWrite,          NULL },
    { IRP_MJ_OPERATION_END }
};

//
// 实例设置回调:对每个卷决定是否附加。这里附加到所有支持的卷。
//
static NTSTATUS
BlwInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    PAGED_CODE();
    return STATUS_SUCCESS;   // 附加到该卷
}

//
// 实例卸载查询:允许手动卸载(detach)。
//
static NTSTATUS
BlwInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    return STATUS_SUCCESS;
}

CONST FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),       // Size
    FLT_REGISTRATION_VERSION,       // Version
    0,                              // Flags
    NULL,                           // Context registration
    g_Callbacks,                    // Operation callbacks
    BlwFilterUnload,                // FilterUnload
    BlwInstanceSetup,               // InstanceSetup
    BlwInstanceQueryTeardown,       // InstanceQueryTeardown
    NULL,                           // InstanceTeardownStart
    NULL,                           // InstanceTeardownComplete
    NULL, NULL, NULL, NULL
};

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    // 让本驱动的非分页分配默认走 NX 内存池(安全实践)
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    KdPrint(("[Bulwark] DriverEntry\n"));

    // 初始化受保护路径锁
    ExInitializeFastMutex(&g_Blw.PathLock);
    ExInitializeFastMutex(&g_Blw.FileHardLock);
    ExInitializeFastMutex(&g_Blw.SelfGuardLock);  // 自保护足迹锁(owner-aware 反勒索)
    ExInitializeFastMutex(&g_Blw.FileNoLoadLock);
    ExInitializeFastMutex(&g_Blw.FileExecBlockLock);
    ExInitializeFastMutex(&g_Blw.CmdHardLock);    // 命令行硬拦名单锁(执行前拦截危险命令用法)
    ExInitializeFastMutex(&g_Blw.RegLock);
    ExInitializeFastMutex(&g_Blw.RegHardLock);
    ExInitializeFastMutex(&g_Blw.KnownBadLock);   // 已知恶意 SHA-256 集合锁(事后哈希研判)
    // WFP 状态锁:串行化「拉起 / 拆除 / BFE 状态变更回调」。必须在注册 BFE 订阅之前初始化,
    // 因为订阅一建立回调就可能立刻触发并取这把锁。
    ExInitializeFastMutex(&g_Blw.WfpLock);
    // NetLock 用自旋锁:WFP classifyFn 可能在 DISPATCH_LEVEL 运行,
    // FAST_MUTEX 在 > APC_LEVEL 获取会蓝屏。
    KeInitializeSpinLock(&g_Blw.NetLock);
    // BannedLock 只保护「已封禁 PID 集」的写侧(加入 / 摘除 / 清空)。读侧(出现在所有
    // 拦截热路径上)全程无锁,故这把锁几乎不会被争用。用自旋锁而非 FAST_MUTEX,以便
    // 将来在任意 IRQL 下也能安全变更该集合。
    KeInitializeSpinLock(&g_Blw.BannedLock);
    // 客户端端口 rundown 保护:初始化后立即置为"已 run down",
    // 这样未连接时发送方 ExAcquireRundownProtection 会失败并安全放行;
    // 连接时 BlwConnectNotify 通过 ExReInitializeRundownProtection 重新激活。
    ExInitializeRundownProtection(&g_Blw.ClientPortRundown);
    ExWaitForRundownProtectionRelease(&g_Blw.ClientPortRundown);

    // 1) 注册 Minifilter(I/O 回调 + 通信端口)
    status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_Blw.Filter);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FltRegisterFilter failed 0x%x\n", status));
        return status;
    }

    // 2) 建立与用户态服务的通信端口
    status = BlwInitCommunication(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwInitCommunication failed 0x%x\n", status));
        FltUnregisterFilter(g_Blw.Filter);
        g_Blw.Filter = NULL;
        return status;
    }

    // 2.5) 启动异步事件队列 + 后台发送线程。必须在任何回调注册之前就绪,
    //      因为所有回调都通过 BlwReportEvent 入队。失败则回滚。
    status = BlwStartEventQueue();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwStartEventQueue failed 0x%x\n", status));
        BlwTearDownCommunication();
        FltUnregisterFilter(g_Blw.Filter);
        g_Blw.Filter = NULL;
        return status;
    }

    // 3) 开始过滤(激活 Minifilter)
    status = FltStartFiltering(g_Blw.Filter);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FltStartFiltering failed 0x%x\n", status));
        BlwStopEventQueue();
        BlwTearDownCommunication();
        FltUnregisterFilter(g_Blw.Filter);
        g_Blw.Filter = NULL;
        return status;
    }

    // 4) 注册进程创建回调
    status = BlwRegisterProcessCallback();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwRegisterProcessCallback failed 0x%x\n", status));
        BlwStopEventQueue();
        BlwTearDownCommunication();
        FltUnregisterFilter(g_Blw.Filter);
        g_Blw.Filter = NULL;
        return status;
    }

    // 5) 注册注册表回调
    status = BlwRegisterRegistryCallback(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwRegisterRegistryCallback failed 0x%x\n", status));
        BlwUnregisterProcessCallback();
        BlwStopEventQueue();
        BlwTearDownCommunication();
        FltUnregisterFilter(g_Blw.Filter);
        g_Blw.Filter = NULL;
        return status;
    }

    // 5.5) 注册映像加载回调(ImageLoad:BYOVD / DLL 侧载)。失败不致命:
    //      仅记录型增强,其余防护仍可用。
    status = BlwRegisterImageCallback();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwRegisterImageCallback failed 0x%x (映像监控不可用,其余防护继续)\n", status));
        // 不回滚
    }

    // 5.6) 注册线程创建回调(RemoteThread:跨进程注入)。失败不致命:
    //      仅记录型增强,其余防护仍可用。
    status = BlwRegisterThreadCallback();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwRegisterThreadCallback failed 0x%x (线程监控不可用,其余防护继续)\n", status));
        // 不回滚
    }

    // 6) 注册对象回调(自我保护)。失败不致命:记录并继续,其他防护仍可用。
    status = BlwRegisterObCallbacks();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwRegisterObCallbacks failed 0x%x (自保不可用,其余防护继续)\n", status));
        // 不回滚,自保为可选增强
    }

    //
    // 7) 创建设备对象并【武装】WFP(网络防护)。失败不致命。
    //
    // 注意这里是"武装"而不是"注册成功":本驱动可能被注册成 boot-start
    //(bulwark.ps1 -BootStart / INF 的 StartType=1),那时 DriverEntry 跑在系统启动极早期,
    // BFE(基础筛选引擎)服务还没起来,FwpmEngineOpen 必然失败。BlwWfpStart 会为此订阅
    // BFE 状态变更,等 BFE 就绪后自动把 WFP 补上 —— 所以【绝不能】把"此刻还没注册上"
    // 当成失败去删设备对象:那样订阅回调将来就没有设备对象可用来注册 callout,
    // 网络防护会永久缺失(这正是原实现每次开机都拦不住外联的原因)。
    //
    {
        UNICODE_STRING devName;
        PDEVICE_OBJECT devObj = NULL;
        NTSTATUS netStatus;

        RtlInitUnicodeString(&devName, L"\\Device\\BulwarkNet");
        netStatus = IoCreateDevice(DriverObject, 0, &devName,
            FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
        if (NT_SUCCESS(netStatus)) {
            g_Blw.WfpDeviceObject = devObj;
            netStatus = BlwWfpStart(devObj);
            if (!NT_SUCCESS(netStatus)) {
                //
                // 走到这里意味着【连 BFE 订阅都没建立起来,且当场也拉不起来】——
                // 确实再没有任何补救路径,可以放弃网络防护了。
                //
                // 但设备对象只有在 callout 确实没有残留注册时才能删 —— callout 依附于它。
                // BlwWfpStart 的回滚分支在"注销不掉 callout"的极端情况下会保留
                // WfpCalloutId != 0,此时保留设备对象(泄漏一个对象)远好于删掉
                // WFP 仍在引用的对象;卸载路径也会因此拒绝卸载,不会留下悬空指针。
                //
                KdPrint(("[Bulwark] BlwWfpStart failed 0x%x (网络防护不可用)\n", netStatus));
                if (g_Blw.WfpCalloutId == 0 && g_Blw.WfpBfeSubscription == NULL) {
                    IoDeleteDevice(devObj);
                    g_Blw.WfpDeviceObject = NULL;
                }
            }
        } else {
            KdPrint(("[Bulwark] IoCreateDevice failed 0x%x (网络防护不可用)\n", netStatus));
        }
    }

    // 7.5) 启动异步哈希扫描 worker(内核本地事后研判)。失败非致命:仅哈希研判不可用,
    //      其余防护继续。默认惰性 —— 无已知恶意集时 worker 只是空等,零开销。
    status = BlwStartHashWorker();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwStartHashWorker failed 0x%x (哈希研判不可用,其余防护继续)\n", status));
        // 不回滚
    }

    // 8) 内核自足基线:从注册表加载防护策略,填充各本地名单。所有名单锁与回调此时均已就绪,
    //    因此即便加载期间有回调触发,也只会看到「部分填充」的名单(每次 Add 在各自锁下原子完成),
    //    安全。加载失败非致命(基线为空 = 等待用户态服务连接后下发)。这一步让驱动在【服务未启动 /
    //    被杀 / 未安装】时也具备完整的本地行为前拦截基线 —— 防护不再依赖可被杀掉的用户态进程。
    //    先保存服务键(供加载与后续「裁决写回」复用),再载入基线。
    BlwSaveRegistryPath(RegistryPath);
    BlwLoadPolicyFromRegistry();

    // 8.5) 启动策略写回线程(去抖合并注册表写回)。必须在开始接收配置命令后不久即就绪;
    //      启动失败非致命 —— BlwMarkPolicyDirty 会退化为原来的同步写回。
    status = BlwStartPolicyPersist();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwStartPolicyPersist failed 0x%x (改为同步写回,功能不受影响)\n", status));
        // 不回滚
    }

    KdPrint(("[Bulwark] Loaded successfully\n"));
    return STATUS_SUCCESS;
}
