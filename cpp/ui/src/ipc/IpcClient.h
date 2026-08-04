#pragma once
#include <QByteArray>
#include <QList>
#include <QObject>
#include <QString>
#include <QUuid>

#include "ai/AiScanner.h"
#include "bulwark/ipc/IpcMessage.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/VtScanRecord.h"

class QLocalSocket;
class QTimer;
class AiScanner;
class AiScanHistoryStore;

// UI-side named-pipe client. Connects to the service's control pipe
// ("Bulwark.Control"), performs the Hello handshake, reads newline-delimited
// JSON frames and re-emits them as Qt signals. Auto-reconnects. Event-driven
// (QLocalSocket) — no background thread, unlike the .NET blocking loop.
//
// Beyond the push channel (prompt / block / ai-scan / log), this now speaks the
// full request/response protocol so the management pages bind to live service
// data: rules, trust, settings, quarantine, persistence audit, VT history and
// ThreatFox intel. Each request has a matching *Received signal.
class IpcClient : public QObject
{
    Q_OBJECT
public:
    explicit IpcClient(QObject* parent = nullptr);
    ~IpcClient() override;

    void start();               // begin connecting + auto-reconnect
    bool isConnected() const;

    // UI -> service: the user's verdict for a prompted event.
    void sendVerdict(const QUuid& eventId, bulwark::VerdictAction action, bool remember,
                     bulwark::RememberScope scope);

    // ---- UI -> service requests (no-op when disconnected) ----
    void requestRules();
    void addRule(const bulwark::ipc::AddRulePayload& p);
    void deleteRule(const QUuid& ruleId);
    void requestSettings();
    void updateSettings(const bulwark::RuntimeSettings& s);
    void requestTrust();
    void addTrust(const QString& actorPath, const QString& note, bool isDirectory = false);
    void removeTrust(const QUuid& ruleId);
    void requestQuarantine();
    void quarantineRestore(const QUuid& id);
    void quarantineDelete(const QUuid& id);
    void requestPersistence();
    // 清理一条自启动持久化项(高危,由用户在自启动项页显式点击触发)。
    // 结果经 persistenceCleanupDone 回来;服务端带「已加白 / 本产品自身」两道护栏。
    void requestPersistenceCleanup(const bulwark::PersistenceEntry& entry);
    void requestEventHistory();
    void clearEventHistory();          // 清空服务端事件历史(活动日志/拦截记录共享)
    // ---- 取证回溯:事件时间线 / 攻击图。服务端异步作答(要扫历史文件),响应经对应信号到达。----
    void requestTimeline(const bulwark::ipc::TimelineRequestPayload& p);
    // 返回本次请求的 id:攻击图窗口据此只认自己的那份响应(多个窗口同时开着也不会串)。
    QUuid requestAttackGraph(const QUuid& seedEventId, int rootPid = 0, int windowSeconds = 3600);
    // ---- 进程管理:快照 + 处置(结束 / 挂起 / 隔离 / 信任 / 算哈希)----
    void requestProcesses(bool includeCommandLine = true, bool resolveOrigin = true);
    void processAction(const bulwark::ipc::ProcessActionRequestPayload& p);
    // ---- 攻击链:组合表状态 + 命中记录 ----
    void requestAttackChain();
    void clearAttackChainHits();       // 清空服务端命中记录(清后服务端会主动回推空列表)
    void requestVtHistory();
    void manualQuarantine(const QString& path); // 清理报告「重试隔离」
    void vtQuery(const bulwark::ipc::VtRequestPayload& p);
    void vtDetail(const QString& sha256); // 按需拉取某哈希的 VT 完整报告(云信誉详情弹窗)
    void intelRefresh(bool previewOnly);
    void intelApply(const QList<bulwark::DefenseRule>& rules);
    void aiScanFile(const QString& path);          // manual AI research of a chosen file
    void aiGenerateRules(const QString& request);  // natural-language -> suggested rules (UI-side)

    // Persisted AI research history (newest first). AI scans run UI-side, so this
    // is where the "AI 研判" page backfills its records across restarts.
    AiScanner* aiScanner() const { return m_ai; }
    QList<AiScanResult> aiScanHistory() const;
    void clearAiScanHistory();         // 清空 UI 侧 AI 研判历史(落盘同步清空)

signals:
    void connectionChanged(bool connected);
    // Push channel.
    void promptReceived(const bulwark::SecurityEvent& event);
    void blockNotification(const bulwark::SecurityEvent& event);
    void aiScanStarted(const bulwark::SecurityEvent& event);
    void logReceived(const QString& line);
    void eventLogReceived(const bulwark::ipc::EventLogPayload& entry);
    void eventHistoryReceived(const QList<bulwark::ipc::EventLogPayload>& events);
    void vtScanUpdate(const bulwark::VtScanRecord& record);
    void remediationReport(const bulwark::ipc::RemediationReportPayload& report);
    void manualQuarantineResult(const bulwark::ipc::ManualQuarantineResultPayload& result);
    // Request/response channel.
    void rulesReceived(const QList<bulwark::DefenseRule>& rules);
    void trustReceived(const QList<bulwark::DefenseRule>& entries);
    void settingsReceived(const bulwark::RuntimeSettings& settings);
    void quarantineReceived(const QList<bulwark::ipc::QuarantineItemPayload>& items);
    void quarantineActionResult(const bulwark::ipc::QuarantineActionResultPayload& r);
    void persistenceReceived(const bulwark::ipc::PersistenceListResponsePayload& payload);
    void persistenceCleanupDone(const bulwark::ipc::PersistenceCleanupResultPayload& payload);
    void timelineReceived(const bulwark::ipc::TimelineResponsePayload& payload);
    void attackGraphReceived(const bulwark::ipc::AttackGraphResponsePayload& payload);
    void attackChainReceived(const bulwark::ipc::AttackChainResponsePayload& payload);
    // 攻击链刚命中一次(实时推送,用于右下角 toast);不受静默模式影响。
    void attackChainHit(const bulwark::ipc::AttackChainHitPayload& hit);
    void processListReceived(const bulwark::ipc::ProcessListResponsePayload& payload);
    void processActionResult(const bulwark::ipc::ProcessActionResultPayload& result);
    void vtResponse(const bulwark::ipc::VtResponsePayload& resp);
    void vtDetailReceived(const bulwark::ipc::VtDetailResponsePayload& detail); // VT 完整报告
    void vtHistoryReceived(const QList<bulwark::VtScanRecord>& records);
    void intelResult(const bulwark::ipc::IntelRefreshResultPayload& result);
    void aiScanRecord(const AiScanResult& result); // a completed AI research (auto or manual)
    void aiRulesSuggested(const QList<AiSuggestedRule>& rules); // NL -> suggested rules for review

private slots:
    void tryConnect();
    void onConnected();
    void onDisconnected();
    void onReadyRead();

private:
    void send(const bulwark::ipc::IpcMessage& msg);
    void dispatch(const QString& line);

    QLocalSocket* m_sock = nullptr;
    QTimer* m_reconnect = nullptr;
    QByteArray m_buf;
    bool m_connected = false;
    AiScanner* m_ai = nullptr; // UI-side AI research client (config from live settings)
    AiScanHistoryStore* m_aiHistory = nullptr; // persisted AI research records (UI-side)
};
