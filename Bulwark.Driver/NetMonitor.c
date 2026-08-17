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
    // 定序:先清条目,再清布隆位与计数 —— 中间态只会「位还在、条目没了」(读者多取一次锁
    // 后扫不到,判定正确),绝不会出现「条目还在、位已清」的假否决。
    RtlZeroMemory(g_Blw.BlockList, sizeof(g_Blw.BlockList));
    InterlockedExchange(&g_Blw.BlockIpCount, 0);
    InterlockedExchange64(&g_Blw.BlockIpMask, 0);
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
    // 定序:先置布隆位,再写条目(读者的位测试在锁外进行,故位必须先可见)。
    InterlockedOr64(&g_Blw.BlockIpMask, (LONG64)BLW_IP_BIT(IpV4));
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (!g_Blw.BlockList[i].InUse) {
            g_Blw.BlockList[i].IpV4 = IpV4;
            g_Blw.BlockList[i].Port = Port;
            g_Blw.BlockList[i].InUse = TRUE;
            InterlockedIncrement(&g_Blw.BlockIpCount);
            break;
        }
    }
    KeReleaseSpinLock(&g_Blw.NetLock, oldIrql);
}

//
// 查黑名单。运行在【每一条外发连接】的 WFP classify 上(可能是 DISPATCH_LEVEL)。
//
// 先做一次无锁布隆位测试:位未置说明没有任何条目用这个 IP,直接放行 —— 名单为空
// (绝大多数部署的常态)时掩码恒为 0,连自旋锁都不会取。只有位命中(真命中或极少数
// 哈希碰撞)才取锁做精确判定,因此最终判定与原实现完全一致。
//
static BOOLEAN
BlwIpIsBlocked(_In_ ULONG IpV4, _In_ USHORT Port)
{
    ULONG i;
    LONG  count;
    LONG  seen = 0;
    BOOLEAN blocked = FALSE;
    KIRQL oldIrql;

    if (((ULONG64)g_Blw.BlockIpMask & BLW_IP_BIT(IpV4)) == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_Blw.NetLock, &oldIrql);
    count = g_Blw.BlockIpCount;
    for (i = 0; i < BLW_MAX_PROTECTED && seen < count; i++) {
        if (!g_Blw.BlockList[i].InUse) {
            continue;
        }
        seen++;
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
    if (!g_Blw.Active || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;  // 高 IRQL 不上报
    }

    BlwReportEvent(BlwEventNetworkConnect, actorPid, 0, NULL, NULL, remoteIp, remotePort);
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

    // 【自足基线】网络黑名单在无客户端时依旧生效(BlwReportNetBlock 内部自带 Active 判空)。
    // 黑名单为空时下方查表自然不命中,开销可忽略。

    // 若上层已硬性允许或不可改写,直接返回
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }

    // 已封禁主体(情报确认恶意):拒绝其任何外联(不看目标 IP)—— 断其 C2 / 回传 / 下载。
    // 封禁集非空时才查(空则零开销)。BlwPidIsBanned 为无锁查表,DISPATCH_LEVEL 安全。
    if (g_Blw.BannedPidCount > 0 && inMetaValues != NULL &&
        FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        ULONG connPid = (ULONG)inMetaValues->processId;
        if (connPid != 0 && BlwPidIsBanned(connPid)) {
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            return;
        }
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
// 真正把 WFP 拉起来:注册内核 callout -> 打开引擎 -> 添加管理层 callout / sublayer / filter。
//
// 【调用约定】必须在持有 g_Blw.WfpLock 时调用,且要求 BFE(基础筛选引擎)已在运行 ——
// 判断与调度由 BlwWfpStart / BlwBfeStateChangeFn 负责,本函数只管做事。
//
// 【逐件幂等】两个部件各自看自己的状态位:
//   * WfpCalloutId == 0 才注册内核 callout(它在 netio 里,BFE 重启不一定带走它);
//   * WfpEngine  == NULL 才开引擎、加管理层对象(这些一定随 BFE 一起消失)。
// 这样 BFE 重启后再次进来,只会补回真正缺的那一半,不会重复注册。
//
static NTSTATUS
BlwWfpBringUpLocked(void)
{
    NTSTATUS status;
    FWPS_CALLOUT sCallout = { 0 };
    FWPM_CALLOUT mCallout = { 0 };
    FWPM_SUBLAYER subLayer = { 0 };
    FWPM_FILTER mFilter = { 0 };
    FWPM_DISPLAY_DATA disp = { 0 };
    BOOLEAN inTxn = FALSE;
    BOOLEAN calloutAddedHere = FALSE;
    FWPM_SESSION session = { 0 };

    if (g_Blw.WfpRegistered) {
        return STATUS_SUCCESS;
    }
    if (g_Blw.WfpDeviceObject == NULL) {
        return STATUS_DEVICE_NOT_READY;   // 没有设备对象就注册不了 callout
    }

    // 1) 注册 callout 到内核过滤引擎(netio)。
    if (g_Blw.WfpCalloutId == 0) {
        sCallout.calloutKey = BLW_CALLOUT_GUID;
        sCallout.classifyFn = BlwClassifyFn;
        sCallout.notifyFn = BlwNotifyFn;
        sCallout.flowDeleteFn = NULL;

        status = FwpsCalloutRegister(g_Blw.WfpDeviceObject, &sCallout, &g_Blw.WfpCalloutId);

        //
        // STATUS_FWP_ALREADY_EXISTS:这个 GUID 的 callout 还注册着,但我们手里没有它的 id
        //(典型来路:上一轮 BFE 重启 / 半拆状态)。没有 id 就既不能用它、也不能注销它,
        // 只能按 key 摘掉再重新注册一次,把 id 拿回来。只重试一次,失败就放弃网络防护。
        //
        if (status == STATUS_FWP_ALREADY_EXISTS) {
            KdPrint(("[Bulwark] Callout GUID already registered; re-registering to recover its id.\n"));
            (void)FwpsCalloutUnregisterByKey(&BLW_CALLOUT_GUID);
            g_Blw.WfpCalloutId = 0;
            status = FwpsCalloutRegister(g_Blw.WfpDeviceObject, &sCallout, &g_Blw.WfpCalloutId);
        }

        if (!NT_SUCCESS(status)) {
            KdPrint(("[Bulwark] FwpsCalloutRegister failed 0x%x\n", status));
            g_Blw.WfpCalloutId = 0;
            return status;
        }
        calloutAddedHere = TRUE;
    }

    // 2) 打开引擎(动态会话:句柄关闭时自动清理本会话加的对象)。
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_Blw.WfpEngine);
    if (!NT_SUCCESS(status)) {
        // 【最常见的一条】BFE 还没起来时这里会失败(boot-start 驱动尤其如此)。
        // 调用方会保留 BFE 订阅,等 FWPM_SERVICE_RUNNING 再回来补上。
        KdPrint(("[Bulwark] FwpmEngineOpen failed 0x%x (BFE not ready?)\n", status));
        g_Blw.WfpEngine = NULL;
        goto cleanup;
    }

    status = FwpmTransactionBegin(g_Blw.WfpEngine, 0);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }
    inTxn = TRUE;

    // 3) 注册 callout 到管理引擎
    disp.name = L"Bulwark Connect Callout";
    mCallout.calloutKey = BLW_CALLOUT_GUID;
    mCallout.displayData = disp;
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    status = FwpmCalloutAdd(g_Blw.WfpEngine, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FwpmCalloutAdd failed 0x%x\n", status));
        goto cleanup;
    }

    // 4) 添加 sublayer
    subLayer.subLayerKey = BLW_SUBLAYER_GUID;
    subLayer.displayData.name = L"Bulwark SubLayer";
    subLayer.flags = 0;
    subLayer.weight = 0x8000;
    status = FwpmSubLayerAdd(g_Blw.WfpEngine, &subLayer, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FwpmSubLayerAdd failed 0x%x\n", status));
        goto cleanup;
    }

    // 5) 添加 filter:在 ALE_AUTH_CONNECT_V4 层调用我们的 callout
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
    KdPrint(("[Bulwark] WFP registered (callout id %u).\n", g_Blw.WfpCalloutId));
    return STATUS_SUCCESS;

cleanup:
    // 与 BlwUnregisterWfp 同一套定序:先回滚 / 关引擎,再注销内核 callout。
    // 走到这里事务从未提交过,没有 filter 引用 callout,故注销必然成功;
    // 但顺序保持一致,免得将来有人在这条路径上加了"提交后才失败"的分支而踩到
    // STATUS_DEVICE_BUSY —— 那会留下一个已注册的 callout 指向即将卸载的镜像。
    if (inTxn) {
        FwpmTransactionAbort(g_Blw.WfpEngine);
    }
    if (g_Blw.WfpEngine != NULL) {
        FwpmEngineClose(g_Blw.WfpEngine);
        g_Blw.WfpEngine = NULL;
    }

    //
    // 【只回滚本次新注册的 callout】。若 callout 是上一轮留下来的(calloutAddedHere == FALSE),
    // 就原样留着 —— 它此刻没有任何 filter 引用,不会被调用,而下一次 BFE 就绪时
    // BlwWfpBringUpLocked 能直接复用它。反过来若在这里把别人留下的 callout 摘掉,
    // 只会白白多一次注册/注销往返。
    //
    if (calloutAddedHere && g_Blw.WfpCalloutId != 0) {
        if (NT_SUCCESS(FwpsCalloutUnregisterById(g_Blw.WfpCalloutId))) {
            g_Blw.WfpCalloutId = 0;
        } else {
            // 极端情况:callout 注销不掉。保留非 0 的 id —— BlwFilterUnload 里的
            // "WfpCalloutId == 0" 判断会据此不去删设备对象,后续卸载也会被否决,
            // 不会让 WFP 指向已释放镜像。
            KdPrint(("[Bulwark] WFP rollback: callout still registered, keeping it pinned.\n"));
        }
    }
    return status;
}

//
// ===== BFE(基础筛选引擎)状态订阅 =====
//
// 【为什么必须有这一层】
//   FwpmEngineOpen 依赖 BFE 服务。而本驱动被注册成 boot-start 时(bulwark.ps1 -BootStart,
//   或 INF 里的 StartType=1),DriverEntry 跑在系统启动的极早期 —— BFE 根本还没起来,
//   FwpmEngineOpen 必然失败。原实现只在 DriverEntry 里试一次、失败就记一行日志放弃,
//   于是【每次开机网络防护都静默缺失】:C2 外联 / 数据回传 / 载荷下载全部不拦,而日志里
//   只有一行看起来无关紧要的 "网络防护不可用",UI 上什么都看不出来。
//   demand-start(服务主动加载)时 BFE 早就在跑,所以这个缺口只在开机自启配置下出现 ——
//   恰恰是为了"消除重启后的防护空窗"才引入的配置,结果自己带来一个新的空窗。
//
// 【顺带修掉 BFE 运行期重启】
//   BFE 服务被重启(手工、或被攻击者停掉再起来)时,本驱动加的 filter / sublayer / 管理层
//   callout 会随会话一起消失,而原实现没有任何重建路径 —— 网络防护此后永久失效直到重装驱动。
//   订阅同一个回调把这条也一并覆盖了。
//
static void CALLBACK
BlwBfeStateChangeFn(_Inout_ void* context, _In_ FWPM_SERVICE_STATE newState)
{
    UNREFERENCED_PARAMETER(context);

    // 回调在 PASSIVE_LEVEL 触发,可以安全取 FAST_MUTEX、调 Fwpm*。
    ExAcquireFastMutex(&g_Blw.WfpLock);

    if (newState == FWPM_SERVICE_RUNNING) {
        if (!g_Blw.WfpRegistered) {
            NTSTATUS status = BlwWfpBringUpLocked();
            KdPrint(("[Bulwark] BFE running -> WFP bring-up 0x%x\n", status));
            // Release 构建里 KdPrint 是空宏,status 会变成"已赋值未使用"(C4189)。
            // 与 BlwLogPattern 里同一处理:显式声明用过它。
            UNREFERENCED_PARAMETER(status);
        }
    } else if (newState == FWPM_SERVICE_STOPPED) {
        //
        // BFE 已经停了:本会话的引擎句柄此刻已失效,【绝不能】再对它调用任何 Fwpm*
        //(包括 FwpmEngineClose)—— 那些对象随 BFE 一起没了,没有东西需要关。
        // 这里只清掉我们自己的记账,让后续的 RUNNING 通知能干净地重建。
        //
        // 内核 callout(WfpCalloutId)【刻意保留】:它注册在 netio 而不是 BFE 里,
        // 不随 BFE 消失;留着它,BFE 回来时只需补开引擎、重加 filter。
        //
        g_Blw.WfpEngine = NULL;
        g_Blw.WfpFilterId = 0;
        g_Blw.WfpRegistered = FALSE;
        KdPrint(("[Bulwark] BFE stopped -> WFP objects gone; will rebuild when it returns.\n"));
    }
    // START_PENDING / STOP_PENDING:过渡态,不动作,等终态通知。

    ExReleaseFastMutex(&g_Blw.WfpLock);
}

//
// 启动网络防护。语义是【武装】而不是"立即注册成功":
//   * BFE 已在运行  -> 当场把 WFP 拉起来;
//   * BFE 还没起来  -> 保持订阅,等它 RUNNING 时由 BlwBfeStateChangeFn 自动补上。
// 两种情况都返回 STATUS_SUCCESS —— 对调用方来说"已武装"就是成功,这样 boot-start
// 场景不会再被当成失败而放弃网络防护。
//
// 只有【连订阅都建立不起来、且当场也拉不起来】才返回失败(此时确实没有任何补救路径)。
//
NTSTATUS
BlwWfpStart(_In_ PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS subStatus;
    NTSTATUS upStatus;

    // 必须先落地设备对象:订阅一旦建立,回调可能立刻触发并需要用它注册 callout。
    g_Blw.WfpDeviceObject = DeviceObject;

    //
    // 【先订阅,再查当前状态】—— 顺序不能反。
    // 反过来的话,"查到 STOPPED" 与 "建立订阅" 之间若 BFE 恰好起来了,那次跃迁的通知
    // 谁都收不到,驱动会一直等一个永不再来的事件。先订阅则最坏只是多收一次 RUNNING,
    // 而 BlwWfpBringUpLocked 是幂等的,多收无害。
    //
    // 不持锁调用:FwpmBfeStateSubscribeChanges 可能在返回前就同步回调一次,
    // 而回调自己要取 WfpLock —— FAST_MUTEX 不可重入,持锁进去就是死锁。
    //
    subStatus = FwpmBfeStateSubscribeChanges(DeviceObject, BlwBfeStateChangeFn,
                                            NULL, &g_Blw.WfpBfeSubscription);
    if (!NT_SUCCESS(subStatus)) {
        KdPrint(("[Bulwark] FwpmBfeStateSubscribeChanges failed 0x%x "
                 "(no deferred bring-up; one-shot attempt only)\n", subStatus));
        g_Blw.WfpBfeSubscription = NULL;
    }

    ExAcquireFastMutex(&g_Blw.WfpLock);
    if (FwpmBfeStateGet() == FWPM_SERVICE_RUNNING) {
        upStatus = BlwWfpBringUpLocked();
    } else {
        upStatus = STATUS_DEVICE_NOT_READY;
        KdPrint(("[Bulwark] BFE not running yet; WFP bring-up deferred to state-change callback.\n"));
    }
    ExReleaseFastMutex(&g_Blw.WfpLock);

    // 有订阅 = 已武装,即便此刻还没拉起来也算成功。
    if (NT_SUCCESS(subStatus) || NT_SUCCESS(upStatus)) {
        return STATUS_SUCCESS;
    }
    return upStatus;
}

//
// 注销 WFP。成功返回 STATUS_SUCCESS;失败(典型 STATUS_DEVICE_BUSY)表示过滤引擎仍持有
// 本驱动的 callout 引用 —— 调用方必须据此【拒绝卸载驱动】。
//
// 【为什么必须检查返回值】(原实现忽略它,是一条真实的蓝屏路径):
//   FwpsCalloutUnregisterById 在「引擎里还有 filter 引用这个 callout」时返回
//   STATUS_DEVICE_BUSY,callout 保持注册状态 —— 也就是 WFP 里仍存着指向本镜像
//   BlwClassifyFn 的函数指针。原实现无论成败都把 WfpCalloutId 清零、上层紧接着
//   IoDeleteDevice 删掉 callout 依附的设备对象,然后镜像被卸载。之后系统里
//   【下一条外发连接】就会让 WFP 调用一个已经不存在的函数 -> 蓝屏。
//   触发时机不是罕见边缘:停服务、更新驱动、卸载产品,每次都会走这条卸载路径。
//
// 定序也是必需的:先关引擎(动态会话,关闭即移除本驱动加的 filter/sublayer/管理层 callout),
// 才可能让内核 callout 的引用计数归零;反过来做必然 STATUS_DEVICE_BUSY。
//
// 引擎已关但 callout 注销失败时,本函数【保持 WfpCalloutId != 0 且 WfpEngine = NULL】,
// 于是下一次卸载尝试会跳过关引擎、直接重试注销 callout —— 状态是可恢复的,不会卡死在半拆状态。
//
NTSTATUS
BlwUnregisterWfp(void)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG    attempt;

    //
    // 0) 【第一件事:退订 BFE 状态通知】。不退订就拆,会和 BlwBfeStateChangeFn 打架 ——
    //    我们正在拆,一条 FWPM_SERVICE_RUNNING 通知就能把 callout 和 filter 重新装回去,
    //    然后镜像卸载,WFP 里留着指向已释放代码的指针。
    //
    //    必须【不持 WfpLock】调用:FwpmBfeStateUnsubscribeChanges 会等在途回调跑完,
    //    而在途回调正等着 WfpLock —— 持锁去退订就是经典的相互等待死锁。
    //    退订返回后,保证不会再有新的回调进来。
    //
    if (g_Blw.WfpBfeSubscription != NULL) {
        FwpmBfeStateUnsubscribeChanges(g_Blw.WfpBfeSubscription);
        g_Blw.WfpBfeSubscription = NULL;
        KdPrint(("[Bulwark] BFE state subscription removed.\n"));
    }

    ExAcquireFastMutex(&g_Blw.WfpLock);

    // 没有引擎也没有 callout = 本来就没起来过,直接算成功。
    // 【不能只看 WfpRegistered】:BFE 未就绪时它一直是 FALSE,但内核 callout 可能已经
    // 注册好了(BlwWfpBringUpLocked 的第 1 步成功、第 2 步失败),漏拆就是悬空指针。
    if (g_Blw.WfpEngine == NULL && g_Blw.WfpCalloutId == 0) {
        g_Blw.WfpRegistered = FALSE;
        ExReleaseFastMutex(&g_Blw.WfpLock);
        return STATUS_SUCCESS;
    }

    // 1) 关引擎(动态会话):移除本驱动添加的 filter / sublayer / 管理层 callout。
    //    这一步让内核 callout 不再被任何 filter 引用,下面的注销才可能成功。
    if (g_Blw.WfpEngine != NULL) {
        FwpmEngineClose(g_Blw.WfpEngine);
        g_Blw.WfpEngine = NULL;
    }

    // 2) 注销内核 callout。引擎关闭后引用不一定立刻归零(在途 classify 需要排空),
    //    故对 STATUS_DEVICE_BUSY 做有限次退让重试;仍不成功就把失败如实报给调用方。
    if (g_Blw.WfpCalloutId != 0) {
        for (attempt = 0; ; attempt++) {
            status = FwpsCalloutUnregisterById(g_Blw.WfpCalloutId);
            if (status != STATUS_DEVICE_BUSY || attempt >= BLW_WFP_UNREG_RETRIES) {
                break;
            }
            {
                // 相对延时,单位 100ns,负值 = 相对当前时间。
                LARGE_INTEGER delay;
                delay.QuadPart = -(LONGLONG)BLW_WFP_UNREG_DELAY_MS * 10 * 1000;
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
            }
        }

        if (!NT_SUCCESS(status)) {
            // callout 仍在注册状态:上层【必须】拒绝卸载。
            // WfpCalloutId 保持非 0(上层据此判断"设备对象还不能删")。
            KdPrint(("[Bulwark] FwpsCalloutUnregisterById failed 0x%x after %u retries; "
                     "unload must be refused.\n", status, attempt));
            ExReleaseFastMutex(&g_Blw.WfpLock);
            return status;
        }
        g_Blw.WfpCalloutId = 0;
    }

    g_Blw.WfpRegistered = FALSE;
    ExReleaseFastMutex(&g_Blw.WfpLock);
    KdPrint(("[Bulwark] WFP unregistered.\n"));
    return STATUS_SUCCESS;
}
