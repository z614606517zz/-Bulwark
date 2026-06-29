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
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    //
    // 卸载顺序至关重要,否则会触发 BugCheck 0xCE
    // (DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS):
    //
    // 1) 先注销不属于 Minifilter 的独立回调(进程/注册表/对象/WFP),
    //    这些回调的函数指针都指向本驱动镜像,卸载前必须全部摘除。
    // 2) 关闭通信端口,停止与用户态的收发。
    // 3) 最后调用 FltUnregisterFilter —— 这是关键的一步:
    //    它会 detach 所有卷实例,并【排空所有在途的 IRP_MJ_CREATE /
    //    IRP_MJ_SET_INFORMATION 预操作回调】,确保 Filter Manager 不再
    //    持有指向本驱动 BlwPreCreate/BlwPreSetInformation 的指针,
    //    之后镜像被卸载才安全。原实现遗漏了这一步,导致镜像卸载后
    //    Filter Manager 仍调用已释放内存中的 BlwPreCreate → 蓝屏。
    //

    BlwUnregisterProcessCallback();
    BlwUnregisterImageCallback();
    BlwUnregisterThreadCallback();
    BlwUnregisterRegistryCallback();
    BlwUnregisterObCallbacks();
    BlwUnregisterWfp();
    if (g_Blw.WfpDeviceObject != NULL) {
        IoDeleteDevice(g_Blw.WfpDeviceObject);
        g_Blw.WfpDeviceObject = NULL;
    }
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
    UNREFERENCED_PARAMETER(RegistryPath);

    // 让本驱动的非分页分配默认走 NX 内存池(安全实践)
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    KdPrint(("[Bulwark] DriverEntry\n"));

    // 初始化受保护路径锁
    ExInitializeFastMutex(&g_Blw.PathLock);
    ExInitializeFastMutex(&g_Blw.FileHardLock);
    ExInitializeFastMutex(&g_Blw.FileNoLoadLock);
    ExInitializeFastMutex(&g_Blw.RegLock);
    ExInitializeFastMutex(&g_Blw.RegHardLock);
    // NetLock 用自旋锁:WFP classifyFn 可能在 DISPATCH_LEVEL 运行,
    // FAST_MUTEX 在 > APC_LEVEL 获取会蓝屏。
    KeInitializeSpinLock(&g_Blw.NetLock);
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

    // 7) 创建设备对象并注册 WFP(网络防护)。失败不致命。
    {
        UNICODE_STRING devName;
        PDEVICE_OBJECT devObj = NULL;
        NTSTATUS netStatus;

        RtlInitUnicodeString(&devName, L"\\Device\\BulwarkNet");
        netStatus = IoCreateDevice(DriverObject, 0, &devName,
            FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
        if (NT_SUCCESS(netStatus)) {
            g_Blw.WfpDeviceObject = devObj;
            netStatus = BlwRegisterWfp(devObj);
            if (!NT_SUCCESS(netStatus)) {
                KdPrint(("[Bulwark] BlwRegisterWfp failed 0x%x (网络防护不可用)\n", netStatus));
                IoDeleteDevice(devObj);
                g_Blw.WfpDeviceObject = NULL;
            }
        } else {
            KdPrint(("[Bulwark] IoCreateDevice failed 0x%x (网络防护不可用)\n", netStatus));
        }
    }

    KdPrint(("[Bulwark] Loaded successfully\n"));
    return STATUS_SUCCESS;
}
