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
    std::function<bulwark::ipc::EventHistoryResponsePayload()>     eventHistoryRequested;
    std::function<void()>                                         eventHistoryClearRequested;
    std::function<bulwark::ipc::IntelRefreshResultPayload(const bulwark::ipc::IntelRefreshRequestPayload&)> intelRefreshRequested;
    std::function<bulwark::ipc::IntelRefreshResultPayload(const bulwark::ipc::IntelApplyRequestPayload&)>   intelApplyRequested;
    std::function<void(int)>                                 uiProcessConnected;

    // ---- 服务 -> UI 广播 ----
    void sendPrompt(const bulwark::SecurityEvent& e);   // PromptRequest(payload=事件 JSON)
    void sendBlock(const bulwark::SecurityEvent& e);    // BlockNotification
    void sendLog(const QString& line);                  // LogEntry(纯字符串)
    void sendEventLog(const bulwark::SecurityEvent& e,
                      bulwark::VerdictAction action, bulwark::VerdictSource source); // EventLogEntry
    void sendRemediationReport(const bulwark::ipc::RemediationReportPayload& report); // RemediationReport
    void sendVtScanUpdate(const bulwark::VtScanRecord& record);                       // VtScanUpdate
    void sendVtDetail(const bulwark::ipc::VtDetailResponsePayload& detail);           // VtDetailResponse(异步)
    void requestAiScan(const bulwark::SecurityEvent& e);                              // AiScanRequest

    // 主动推送最新快照(改动后回推,UI 无需再请求)。
    void sendRules();
    void sendSettings();
    void sendTrustList();
    void sendQuarantineList();

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
    QHash<QLocalSocket*, QByteArray> buffers_; // 每连接的行缓冲
};

} // namespace bulwark::service
