/*++
    NetMonitor.c
    网络防护(M6):Windows Filtering Platform(WFP)。

    在 ALE 连接授权层(FWPM_LAYER_ALE_AUTH_CONNECT_V4)注册一个 callout +
    filter。每个外发连接建立前,classifyFn 被调用,我们检查远端 IP/端口
    是否命中黑名单:命中则 BLOCK,否则 PERMIT(交还其他过滤器)。

    classifyFn 可能在 DISPATCH_LEVEL 运行,因此不做同步裁决(不发消息等待),
    仅做黑名单判断并异步上报命中事件供 UI 记录。

    黑名单由用户态通过 FilterSendMessage 下发。
--*/

#include "Driver.h"

// WFP 内核头依赖 NDIS6 类型(NET_BUFFER_LIST / NDIS_HANDLE 等),
// 必须在包含 fwpsk.h 之前声明 NDIS6 支持,否则相关声明缺失导致编译失败。
#ifndef NDIS_SUPPORT_NDIS6
#define NDIS_SUPPORT_NDIS6 1
#endif
#include <fwpsk.h>
#include <fwpmk.h>
#include <initguid.h>

// 本驱动 WFP 标识 GUID
// {C9A1F7D2-3B6E-4A21-9F8C-1E2D3C4B5A60}
DEFINE_GUID(BLW_CALLOUT_GUID,
    0xc9a1f7d2, 0x3b6e, 0x4a21, 0x9f, 0x8c, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x60);
// {C9A1F7D2-3B6E-4A21-9F8C-1E2D3C4B5A61}
DEFINE_GUID(BLW_SUBLAYER_GUID,
    0xc9a1f7d2, 0x3b6e, 0x4a21, 0x9f, 0x8c, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x61);

//
// ===== 黑名单管理(线程安全)=====
//

void
BlwClearBlockList(void)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Blw.NetLock, &oldIrql);
    RtlZeroMemory(g_Blw.BlockList, sizeof(g_Blw.BlockList));
    KeReleaseSpinLock(&g_Blw.NetLock, oldIrql);
}

void
BlwAddBlockIp(_In_ ULONG IpV4, _In_ USHORT Port)
{
    ULONG i;
    KIRQL oldIrql;
    if (IpV4 == 0) {
        return;
    }
    KeAcquireSpinLock(&g_Blw.NetLock, &oldIrql);
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (!g_Blw.BlockList[i].InUse) {
            g_Blw.BlockList[i].IpV4 = IpV4;
            g_Blw.BlockList[i].Port = Port;
            g_Blw.BlockList[i].InUse = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_Blw.NetLock, oldIrql);
}

static BOOLEAN
BlwIpIsBlocked(_In_ ULONG IpV4, _In_ USHORT Port)
{
    ULONG i;
    BOOLEAN blocked = FALSE;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_Blw.NetLock, &oldIrql);
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (!g_Blw.BlockList[i].InUse) {
            continue;
        }
        if (g_Blw.BlockList[i].IpV4 == IpV4 &&
            (g_Blw.BlockList[i].Port == 0 || g_Blw.BlockList[i].Port == Port)) {
            blocked = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_Blw.NetLock, oldIrql);
    return blocked;
}

//
// 异步上报一条网络拦截事件(仅记录)。
//
static void
BlwReportNetBlock(_In_ ULONG actorPid, _In_ ULONG remoteIp, _In_ USHORT remotePort)
{
    BLW_EVENT_MESSAGE msg;

    if (!g_Blw.Active || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;  // 高 IRQL 不上报
    }

    RtlZeroMemory(&msg, sizeof(msg));
    msg.EventId = (ULONG64)InterlockedIncrement64(&g_Blw.NextEventId);
    msg.Type = BlwEventNetworkConnect;
    msg.ActorPid = actorPid;
    msg.RemoteIpV4 = remoteIp;
    msg.RemotePort = remotePort;

    BlwReportEvent(&msg);
}

//
// WFP classify 回调:决定放行/阻断外发连接。
//
static void NTAPI
BlwClassifyFn(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
    ULONG remoteIp;
    USHORT remotePort;
    ULONG actorPid = 0;

    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // 默认放行
    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (!g_Blw.Active) {
        return;
    }

    // 若上层已硬性允许或不可改写,直接返回
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }

    // 取远端 IP(V4,主机字节序)与端口
    remoteIp = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    remotePort = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;

    if (BlwIpIsBlocked(remoteIp, remotePort)) {
        if (inMetaValues != NULL &&
            FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
            actorPid = (ULONG)inMetaValues->processId;
        }

        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;  // 阻止后续过滤器改写

        BlwReportNetBlock(actorPid, remoteIp, remotePort);
        KdPrint(("[Bulwark] Net BLOCK pid=%u ip=0x%08x port=%u\n",
            actorPid, remoteIp, remotePort));
    }

    //
    // 影子模式(沙盒):影子进程的所有外发连接一律 BLOCK,防止真实外联。
    // 同时上报行为事件供用户态分析(目标地址/端口)。
    //
    if (actorPid == 0 && inMetaValues != NULL &&
        FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        actorPid = (ULONG)inMetaValues->processId;
    }
    if (actorPid != 0 && BlwPidIsShadow(actorPid)) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        BlwReportNetBlock(actorPid, remoteIp, remotePort);
        KdPrint(("[Bulwark] Shadow Net BLOCK pid=%u ip=0x%08x port=%u\n",
            actorPid, remoteIp, remotePort));
    }
}

//
// callout 通知回调(添加/删除 filter 时被调用)。
//
static NTSTATUS NTAPI
BlwNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

//
// 注册 WFP:打开引擎 -> 注册 callout -> 添加 sublayer -> 添加 filter。
//
NTSTATUS
BlwRegisterWfp(_In_ PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS status;
    FWPS_CALLOUT sCallout = { 0 };
    FWPM_CALLOUT mCallout = { 0 };
    FWPM_SUBLAYER subLayer = { 0 };
    FWPM_FILTER mFilter = { 0 };
    FWPM_DISPLAY_DATA disp = { 0 };
    BOOLEAN inTxn = FALSE;
    FWPM_SESSION session = { 0 };

    if (g_Blw.WfpRegistered) {
        return STATUS_SUCCESS;
    }

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;  // 引擎句柄关闭时自动清理对象

    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_Blw.WfpEngine);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FwpmEngineOpen failed 0x%x\n", status));
        return status;
    }

    // 1) 注册 callout 到过滤引擎(内核)
    sCallout.calloutKey = BLW_CALLOUT_GUID;
    sCallout.classifyFn = BlwClassifyFn;
    sCallout.notifyFn = BlwNotifyFn;
    sCallout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister(DeviceObject, &sCallout, &g_Blw.WfpCalloutId);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FwpsCalloutRegister failed 0x%x\n", status));
        goto cleanup;
    }

    status = FwpmTransactionBegin(g_Blw.WfpEngine, 0);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }
    inTxn = TRUE;

    // 2) 注册 callout 到管理引擎
    disp.name = L"Bulwark Connect Callout";
    mCallout.calloutKey = BLW_CALLOUT_GUID;
    mCallout.displayData = disp;
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    status = FwpmCalloutAdd(g_Blw.WfpEngine, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FwpmCalloutAdd failed 0x%x\n", status));
        goto cleanup;
    }

    // 3) 添加 sublayer
    subLayer.subLayerKey = BLW_SUBLAYER_GUID;
    subLayer.displayData.name = L"Bulwark SubLayer";
    subLayer.flags = 0;
    subLayer.weight = 0x8000;
    status = FwpmSubLayerAdd(g_Blw.WfpEngine, &subLayer, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FwpmSubLayerAdd failed 0x%x\n", status));
        goto cleanup;
    }

    // 4) 添加 filter:在 ALE_AUTH_CONNECT_V4 层调用我们的 callout
    mFilter.displayData.name = L"Bulwark Connect Filter";
    mFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    mFilter.subLayerKey = BLW_SUBLAYER_GUID;
    mFilter.weight.type = FWP_EMPTY;   // 自动分配权重
    mFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    mFilter.action.calloutKey = BLW_CALLOUT_GUID;
    mFilter.numFilterConditions = 0;   // 无条件:所有外发连接都过我们回调

    status = FwpmFilterAdd(g_Blw.WfpEngine, &mFilter, NULL, &g_Blw.WfpFilterId);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FwpmFilterAdd failed 0x%x\n", status));
        goto cleanup;
    }

    status = FwpmTransactionCommit(g_Blw.WfpEngine);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }
    inTxn = FALSE;

    g_Blw.WfpRegistered = TRUE;
    g_Blw.WfpDeviceObject = DeviceObject;
    KdPrint(("[Bulwark] WFP registered.\n"));
    return STATUS_SUCCESS;

cleanup:
    if (inTxn) {
        FwpmTransactionAbort(g_Blw.WfpEngine);
    }
    if (g_Blw.WfpCalloutId != 0) {
        FwpsCalloutUnregisterById(g_Blw.WfpCalloutId);
        g_Blw.WfpCalloutId = 0;
    }
    if (g_Blw.WfpEngine != NULL) {
        FwpmEngineClose(g_Blw.WfpEngine);
        g_Blw.WfpEngine = NULL;
    }
    return status;
}

void
BlwUnregisterWfp(void)
{
    if (!g_Blw.WfpRegistered) {
        return;
    }
    g_Blw.WfpRegistered = FALSE;

    // 引擎为动态会话,关闭时自动移除 filter/callout/sublayer 对象
    if (g_Blw.WfpEngine != NULL) {
        FwpmEngineClose(g_Blw.WfpEngine);
        g_Blw.WfpEngine = NULL;
    }
    // 注销内核 callout
    if (g_Blw.WfpCalloutId != 0) {
        FwpsCalloutUnregisterById(g_Blw.WfpCalloutId);
        g_Blw.WfpCalloutId = 0;
    }
    KdPrint(("[Bulwark] WFP unregistered.\n"));
}
