#pragma once
#include <QObject>
#include <QHash>
#include <QByteArray>
#include <QUuid>
#include <QList>
#include <functional>
#include <utility>

#include "bulwark/ipc/IpcMessage.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/models/VtScanRecord.h"

class QLocalServer;
class QLocalSocket;

namespace bulwark::service {

// 服务端命名管道服务器(监听 "Bulwark.Control")。接受多个 UI 客户端,收发按行分隔的
// 紧凑 JSON 帧(IpcMessage)。事件驱动(QLocalServer/QLocalSocket),无后台线程。
// 对应 .NET Ipc/IpcServer.cs:除推送(弹窗/拦截/日志/事件)外,处理 UI 的规则/设置/信任/
// 隔离/持久化/VT/情报等请求 —— 通过下面的 std::function 回调委托给 Worker/宿主。
class IpcServer : public QObject {
    Q_OBJECT
public:
    explicit IpcServer(QObject* parent = nullptr);
    bool start();   // 监听控制管道;成功返回 true
    void stop();
    int clientCount() const { return buffers_.size(); }
    // 被拒的未授权连接累计数(诊断用)。持续增长意味着有进程在反复尝试连管道 ——
    // 那本身就是一条值得看的安全信号,不该只散落在日志行里。
    quint64 rejectedConnectionCount() const { return rejectedConnections_; }

    // ---- 请求处理回调(由 Worker/main 绑定;对应 .NET 的 Func/Action)----
    // 未绑定的回调按「服务未启用该功能」优雅降级,绝不崩溃或断开连接。
    std::function<QList<bulwark::DefenseRule>()>              rulesRequested;
    std::function<void(const QUuid&)>                        ruleDeleteRequested;
    std::function<void(const bulwark::ipc::AddRulePayload&)>  ruleAddRequested;
    std::function<bulwark::RuntimeSettings()>                 settingsRequested;
    std::function<void(const bulwark::RuntimeSettings&)>      settingsUpdated;
    std::function<QList<bulwark::DefenseRule>()>              trustListRequested;
    std::function<void(const bulwark::ipc::AddTrustPayload&)> trustAddRequested;
    std::function<void(const QUuid&)>                        trustRemoveRequested;
    std::function<bulwark::ipc::VtResponsePayload(const bulwark::ipc::VtRequestPayload&)> vtRequested;
    // 云信誉详情按需拉取(异步):宿主后台拉取 VT 完整报告 + 行为,完成后经 sendVtDetail 回推。
    std::function<void(const QUuid& requestId, const QString& sha256)> vtDetailRequested;
    std::function<bulwark::ipc::QuarantineListResponsePayload()>              quarantineListRequested;
    std::function<bulwark::ipc::QuarantineActionResultPayload(const QUuid&)>  quarantineRestoreRequested;
    std::function<bulwark::ipc::QuarantineActionResultPayload(const QUuid&)>  quarantineDeleteRequested;
    std::function<std::pair<bool, QString>(const QString&)>   manualQuarantineRequested;
    std::function<bulwark::ipc::VtHistoryResponsePayload()>   vtHistoryRequested;
    std::function<bulwark::ipc::PersistenceListResponsePayload()> persistenceListRequested;
    // 自启动项清理(高危,用户在自启动项页显式点击)。同步返回:清理动作是本机注册表/文件操作,
    // 毫秒级完成,不需要像取证查询那样异步。未绑定时优雅降级为「服务未启用该功能」。
    std::function<bulwark::ipc::PersistenceCleanupResultPayload(
        const bulwark::ipc::PersistenceCleanupRequestPayload&)> persistenceCleanupRequested;
    std::function<bulwark::ipc::EventHistoryResponsePayload()>     eventHistoryRequested;
    std::function<void()>                                         eventHistoryClearRequested;
    // ---- 取证查询(耗时:要解析数万条历史 JSON)。约定为【异步】:宿主在后台线程算完后
    //      经 sendTimeline / sendAttackGraph 回推,绝不在 IPC 线程上同步等待。----
    std::function<void(const bulwark::ipc::TimelineRequestPayload&)>    timelineRequested;
    std::function<void(const bulwark::ipc::AttackGraphRequestPayload&)> attackGraphRequested;
    // ---- 进程管理。列表同样是异步(首次快照要对几百个映像验签);处置动作很快,同步返回。----
    std::function<void(const bulwark::ipc::ProcessListRequestPayload&)> processListRequested;
    std::function<bulwark::ipc::ProcessActionResultPayload(
        const bulwark::ipc::ProcessActionRequestPayload&)>              processActionRequested;
    std::function<bulwark::ipc::IntelRefreshResultPayload(const bulwark::ipc::IntelRefreshRequestPayload&)> intelRefreshRequested;
    std::function<bulwark::ipc::IntelRefreshResultPayload(const bulwark::ipc::IntelApplyRequestPayload&)>   intelApplyRequested;
    // ---- 攻击链组合引擎。读的是内存里的表状态与有上限的命中记录,微秒级,故同步返回。----
    std::function<bulwark::ipc::AttackChainResponsePayload()> attackChainRequested;
    std::function<void()>                                    attackChainClearRequested;
    // ---- 在线更新。两者都是【异步】的:检查要一次网络往返(可达 15s),下载是几 MB。
    //      宿主在后台线程做完后经 sendUpdateCheck / sendUpdateProgress /
    //      sendUpdateDownloadResult 回推,绝不在 IPC 线程上等网络 —— 那会把弹窗和
    //      拦截通知一起堵住。----
    std::function<void()>                                    updateCheckRequested;
    std::function<void()>                                    updateDownloadRequested;
    // 就地应用已下载的更新。同样是异步的:要重新校验三个 PE 的签名并做文件替换。
    std::function<void()>                                    updateApplyRequested;
    // ---- 磁盘垃圾清理。两者都是【异步】的:要遍历 %TEMP% / 浏览器缓存这类动辄数万文件的
    //      目录,秒级到十几秒。宿主在后台线程做完后经 sendJunkScan / sendJunkClean 回推,
    //      中途用 sendJunkProgress 报进度 —— 与取证查询、进程列表、在线更新同一约定。----
    std::function<void(const bulwark::ipc::JunkScanRequestPayload&)>  junkScanRequested;
    std::function<void(const bulwark::ipc::JunkCleanRequestPayload&)> junkCleanRequested;
    // 大文件查找。同样异步(要遍历整块磁盘)。注意【没有对应的删除回调】—— 本功能纯只读,
    // 界面只提供「打开所在位置」,详见 JunkCleaner.h 里 LargeFileScanner 的说明。
    std::function<void(const bulwark::ipc::LargeFileScanRequestPayload&)> largeFileScanRequested;
    std::function<void(int)>                                 uiProcessConnected;

    // ---- 服务 -> UI 广播 ----
    void sendPrompt(const bulwark::SecurityEvent& e);   // PromptRequest(payload=事件 JSON)
    void sendBlock(const bulwark::SecurityEvent& e);    // BlockNotification
    // 攻击链命中即时通知。无论最终处置是 Block / Ask / Allow 都发 —— 见 IpcMessageType 处说明。
    void sendAttackChainHit(const bulwark::ipc::AttackChainHitPayload& hit);
    void sendLog(const QString& line);                  // LogEntry(纯字符串)
    void sendEventLog(const bulwark::SecurityEvent& e,
                      bulwark::VerdictAction action, bulwark::VerdictSource source,
                      bulwark::EnforcementOutcome enforcement =
                          bulwark::EnforcementOutcome::NotApplicable); // EventLogEntry
    void sendRemediationReport(const bulwark::ipc::RemediationReportPayload& report); // RemediationReport
    void sendVtScanUpdate(const bulwark::VtScanRecord& record);                       // VtScanUpdate
    void sendVtDetail(const bulwark::ipc::VtDetailResponsePayload& detail);           // VtDetailResponse(异步)
    void requestAiScan(const bulwark::SecurityEvent& e);                              // AiScanRequest
    // 取证查询 / 进程管理的异步回推(须在主线程调用;后台线程用 QMetaObject::invokeMethod 编组)。
    void sendTimeline(const bulwark::ipc::TimelineResponsePayload& payload);          // EventTimelineResponse
    void sendAttackGraph(const bulwark::ipc::AttackGraphResponsePayload& payload);    // AttackGraphResponse
    void sendProcessList(const bulwark::ipc::ProcessListResponsePayload& payload);    // ProcessListResponse
    // 在线更新的异步回推(须在主线程调用;后台线程用 QMetaObject::invokeMethod 编组)。
    void sendUpdateCheck(const bulwark::ipc::UpdateCheckResponsePayload& payload);          // UpdateCheckResponse
    void sendUpdateProgress(const bulwark::ipc::UpdateProgressPayload& payload);            // UpdateProgressNotification
    void sendUpdateDownloadResult(const bulwark::ipc::UpdateDownloadResponsePayload& p);    // UpdateDownloadResponse
    void sendUpdateApplyResult(const bulwark::ipc::UpdateApplyResponsePayload& p);          // UpdateApplyResponse
    // 磁盘垃圾清理的异步回推(同上,须在主线程调用)。
    void sendJunkScan(const bulwark::ipc::JunkScanResponsePayload& payload);                // JunkScanResponse
    void sendJunkClean(const bulwark::ipc::JunkCleanResponsePayload& payload);              // JunkCleanResponse
    void sendJunkProgress(const bulwark::ipc::JunkProgressPayload& payload);                // JunkProgressNotification
    void sendLargeFileScan(const bulwark::ipc::LargeFileScanResponsePayload& payload);      // LargeFileScanResponse

    // 主动推送最新快照(改动后回推,UI 无需再请求)。
    void sendRules();
    void sendSettings();
    void sendTrustList();
    void sendQuarantineList();
    void sendAttackChain();

signals:
    void helloReceived(int processId, const QString& role);
    void promptResponse(const QUuid& eventId, bulwark::VerdictAction action,
                        bool remember, bulwark::RememberScope scope);
    void aiScanResponse(const bulwark::ipc::AiScanResponsePayload& resp);
    void clientCountChanged(int count);

private slots:
    void onNewConnection();
    void onReadyRead();
    void onDisconnected();

private:
    void broadcast(const bulwark::ipc::IpcMessage& msg);
    void handleLine(QLocalSocket* sock, const QString& line);

    QLocalServer* server_ = nullptr;
    QHash<QLocalSocket*, QByteArray> buffers_; // 每连接的行缓冲(仅【已通过认证】的连接入表)
    quint64 rejectedConnections_ = 0;          // 被拒的未授权连接累计数
};

} // namespace bulwark::service
