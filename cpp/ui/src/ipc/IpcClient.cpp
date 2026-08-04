#include "ipc/IpcClient.h"

#include "ai/AiScanHistoryStore.h"
#include "bulwark/ipc/IpcMessageType.h"
#include "bulwark/ipc/PipeNames.h"

#include <QCoreApplication>
#include <QLocalSocket>
#include <QTimer>

using namespace bulwark;
using namespace bulwark::ipc;

IpcClient::IpcClient(QObject* parent)
    : QObject(parent), m_ai(new AiScanner(this)), m_aiHistory(new AiScanHistoryStore())
{
    // When the UI-side AI research finishes, surface it to the AI page and — for
    // service-requested scans (non-null event id) — echo the verdict back so the
    // service can fold it (AiDecisionPolicy) / compensate on malicious.
    connect(m_ai, &AiScanner::finished, this, [this](const AiScanResult& r) {
        emit aiScanRecord(r);
        if (m_aiHistory)
            m_aiHistory->append(r); // persist every result (auto + manual) so the AI page survives restarts
        if (r.eventId.isNull())
            return; // manual scan — display only, nothing to report to the service
        bulwark::ipc::AiScanResponsePayload p;
        p.eventId = r.eventId;
        p.available = r.available;
        p.recommendation = r.recommendation;
        p.summary = r.summary;
        p.confidence = r.confidence;
        send(IpcMessage::from(IpcMessageType::AiScanResponse, p));
    });
    // AI-suggested rules (natural language -> rules) are surfaced for user review.
    connect(m_ai, &AiScanner::rulesSuggested, this,
            [this](const QList<AiSuggestedRule>& rules) { emit aiRulesSuggested(rules); });
}

IpcClient::~IpcClient() { delete m_aiHistory; }

QList<AiScanResult> IpcClient::aiScanHistory() const
{
    return m_aiHistory ? m_aiHistory->getAll() : QList<AiScanResult>();
}

void IpcClient::clearAiScanHistory()
{
    if (m_aiHistory)
        m_aiHistory->clear();
}

void IpcClient::start()
{
    if (m_sock)
        return;

    m_sock = new QLocalSocket(this);
    connect(m_sock, &QLocalSocket::connected, this, &IpcClient::onConnected);
    connect(m_sock, &QLocalSocket::disconnected, this, &IpcClient::onDisconnected);
    connect(m_sock, &QLocalSocket::errorOccurred, this,
            [this](QLocalSocket::LocalSocketError) { onDisconnected(); });
    connect(m_sock, &QLocalSocket::readyRead, this, &IpcClient::onReadyRead);

    m_reconnect = new QTimer(this);
    m_reconnect->setInterval(1000);
    m_reconnect->setSingleShot(true);
    connect(m_reconnect, &QTimer::timeout, this, &IpcClient::tryConnect);

    tryConnect();
}

bool IpcClient::isConnected() const
{
    return m_sock && m_sock->state() == QLocalSocket::ConnectedState;
}

void IpcClient::tryConnect()
{
    if (m_sock && m_sock->state() == QLocalSocket::UnconnectedState)
        m_sock->connectToServer(controlPipe());
}

void IpcClient::onConnected()
{
    if (!m_connected) {
        m_connected = true;
        emit connectionChanged(true);
    }
    HelloPayload hello;
    hello.processId = static_cast<int>(QCoreApplication::applicationPid());
    hello.role = QStringLiteral("ui");
    send(IpcMessage::from(IpcMessageType::Hello, hello));
}

void IpcClient::onDisconnected()
{
    const bool was = m_connected;
    m_connected = false;
    m_buf.clear();
    if (was)
        emit connectionChanged(false);
    if (m_reconnect && !m_reconnect->isActive())
        m_reconnect->start();
}

void IpcClient::onReadyRead()
{
    m_buf += m_sock->readAll();
    int nl;
    while ((nl = m_buf.indexOf('\n')) >= 0) {
        const QByteArray lineBytes = m_buf.left(nl);
        m_buf.remove(0, nl + 1);
        const QString line = QString::fromUtf8(lineBytes).trimmed();
        if (!line.isEmpty())
            dispatch(line);
    }
}

void IpcClient::dispatch(const QString& line)
{
    const auto msg = IpcMessage::deserialize(line);
    if (!msg)
        return;

    switch (msg->type) {
    // ---- push channel ----
    case IpcMessageType::PromptRequest:
        emit promptReceived(msg->payloadAs<SecurityEvent>());
        break;
    case IpcMessageType::BlockNotification:
        emit blockNotification(msg->payloadAs<SecurityEvent>());
        break;
    case IpcMessageType::AiScanRequest: {
        // Raise a lightweight "AI 研判中" toast, then run the UI-side model. The
        // AiScanner echoes an AiScanResponse back to the service when it finishes
        // (fail-open: if unconfigured / erroring it replies available=false, so the
        // service's fail-open timeout path is preserved).
        const auto ev = msg->payloadAs<SecurityEvent>();
        emit aiScanStarted(ev);
        m_ai->scan(ev, QString::fromUtf8("双击"));
        break;
    }
    case IpcMessageType::LogEntry:
        emit logReceived(msg->payload);
        break;
    case IpcMessageType::EventLogEntry:
        emit eventLogReceived(msg->payloadAs<EventLogPayload>());
        break;
    case IpcMessageType::EventHistoryResponse:
        emit eventHistoryReceived(msg->payloadAs<EventHistoryResponsePayload>().events);
        break;
    case IpcMessageType::AttackChainHitNotification:
        // 攻击链命中即时通知。与 AttackChainResponse 分开:后者是「点开攻击链页面时的全量快照」,
        // 这条是「刚刚命中了一次」的实时推送,用来弹右下角 toast。
        emit attackChainHit(msg->payloadAs<AttackChainHitPayload>());
        break;
    case IpcMessageType::AttackChainResponse:
        emit attackChainReceived(msg->payloadAs<AttackChainResponsePayload>());
        break;
    case IpcMessageType::VtScanUpdate:
        emit vtScanUpdate(msg->payloadAs<bulwark::VtScanRecord>());
        break;
    case IpcMessageType::RemediationReport:
        emit remediationReport(msg->payloadAs<RemediationReportPayload>());
        break;
    case IpcMessageType::ManualQuarantineResponse:
        emit manualQuarantineResult(msg->payloadAs<ManualQuarantineResultPayload>());
        break;

    // ---- request/response channel ----
    case IpcMessageType::RulesResponse:
        emit rulesReceived(msg->payloadAs<RulesResponsePayload>().rules);
        break;
    case IpcMessageType::TrustListResponse:
        emit trustReceived(msg->payloadAs<TrustListResponsePayload>().entries);
        break;
    case IpcMessageType::SettingsResponse: {
        const auto s = msg->payloadAs<bulwark::RuntimeSettings>();
        m_ai->setConfig(s.aiBaseUrl, s.aiApiKey, s.aiModel); // keep the AI client in sync with settings
        // 这三项与下面两项此前只在 RuntimeSettings 里被序列化、无人消费(静态特征提取用硬编码常量,
        // 「额度守卫」功能根本不存在)。在这里一并同步,它们才真正生效。
        StaticFeatureLimits lim;
        lim.maxReadBytes   = static_cast<qint64>(s.aiScanBinarySampleLimitMb) * 1024 * 1024;
        lim.scriptCapBytes = s.aiScanScriptTextLimitKb * 1024;
        lim.maxStrings     = s.aiScanMaxStrings;
        m_ai->setStaticLimits(lim);
        m_ai->setCreditGuard(s.aiCreditGuardEnabled, s.aiMonthlyCreditBudget);
        emit settingsReceived(s);
        break;
    }
    case IpcMessageType::QuarantineListResponse:
        emit quarantineReceived(msg->payloadAs<QuarantineListResponsePayload>().items);
        break;
    case IpcMessageType::QuarantineActionResult:
        emit quarantineActionResult(msg->payloadAs<QuarantineActionResultPayload>());
        break;
    case IpcMessageType::PersistenceListResponse:
        emit persistenceReceived(msg->payloadAs<PersistenceListResponsePayload>());
        break;
    case IpcMessageType::PersistenceCleanupResponse:
        emit persistenceCleanupDone(msg->payloadAs<PersistenceCleanupResultPayload>());
        break;
    case IpcMessageType::EventTimelineResponse:
        emit timelineReceived(msg->payloadAs<TimelineResponsePayload>());
        break;
    case IpcMessageType::AttackGraphResponse:
        emit attackGraphReceived(msg->payloadAs<AttackGraphResponsePayload>());
        break;
    case IpcMessageType::ProcessListResponse:
        emit processListReceived(msg->payloadAs<ProcessListResponsePayload>());
        break;
    case IpcMessageType::ProcessActionResponse:
        emit processActionResult(msg->payloadAs<ProcessActionResultPayload>());
        break;
    case IpcMessageType::VtQueryResponse:
        emit vtResponse(msg->payloadAs<VtResponsePayload>());
        break;
    case IpcMessageType::VtDetailResponse:
        emit vtDetailReceived(msg->payloadAs<VtDetailResponsePayload>());
        break;
    case IpcMessageType::VtHistoryResponse:
        emit vtHistoryReceived(msg->payloadAs<VtHistoryResponsePayload>().records);
        break;
    case IpcMessageType::IntelRefreshResponse:
    case IpcMessageType::IntelApplyResponse:
        emit intelResult(msg->payloadAs<IntelRefreshResultPayload>());
        break;
    default:
        break;
    }
}

void IpcClient::sendVerdict(const QUuid& eventId, VerdictAction action, bool remember,
                            RememberScope scope)
{
    PromptResponsePayload p;
    p.eventId = eventId;
    p.action = action;
    p.remember = remember;
    p.scope = scope;
    send(IpcMessage::from(IpcMessageType::PromptResponse, p));
}

// ---- UI -> service requests ------------------------------------------------

void IpcClient::requestRules()
{
    send(IpcMessage::create(IpcMessageType::RulesRequest, {}));
}

void IpcClient::addRule(const AddRulePayload& p)
{
    send(IpcMessage::from(IpcMessageType::AddRule, p));
}

void IpcClient::deleteRule(const QUuid& ruleId)
{
    DeleteRulePayload p;
    p.ruleId = ruleId;
    send(IpcMessage::from(IpcMessageType::DeleteRule, p));
}

void IpcClient::requestSettings()
{
    send(IpcMessage::create(IpcMessageType::SettingsRequest, {}));
}

void IpcClient::updateSettings(const bulwark::RuntimeSettings& s)
{
    send(IpcMessage::create(IpcMessageType::SettingsUpdate, s.toJson()));
}

void IpcClient::requestTrust()
{
    send(IpcMessage::create(IpcMessageType::TrustListRequest, {}));
}

void IpcClient::addTrust(const QString& actorPath, const QString& note, bool isDirectory)
{
    AddTrustPayload p;
    p.actorPath = actorPath;
    p.note = note;
    p.isDirectory = isDirectory;
    send(IpcMessage::from(IpcMessageType::AddTrust, p));
}

void IpcClient::removeTrust(const QUuid& ruleId)
{
    RemoveTrustPayload p;
    p.ruleId = ruleId;
    send(IpcMessage::from(IpcMessageType::RemoveTrust, p));
}

void IpcClient::requestQuarantine()
{
    send(IpcMessage::create(IpcMessageType::QuarantineListRequest, {}));
}

void IpcClient::quarantineRestore(const QUuid& id)
{
    QuarantineActionPayload p;
    p.id = id;
    send(IpcMessage::from(IpcMessageType::QuarantineRestore, p));
}

void IpcClient::quarantineDelete(const QUuid& id)
{
    QuarantineActionPayload p;
    p.id = id;
    send(IpcMessage::from(IpcMessageType::QuarantineDelete, p));
}

void IpcClient::requestPersistenceCleanup(const bulwark::PersistenceEntry& entry)
{
    PersistenceCleanupRequestPayload p;
    p.entry = entry;
    send(IpcMessage::from(IpcMessageType::PersistenceCleanupRequest, p));
}

void IpcClient::requestPersistence()
{
    send(IpcMessage::create(IpcMessageType::PersistenceListRequest, {}));
}

void IpcClient::requestEventHistory()
{
    send(IpcMessage::create(IpcMessageType::EventHistoryRequest, {}));
}

void IpcClient::clearEventHistory()
{
    send(IpcMessage::create(IpcMessageType::EventHistoryClearRequest, {}));
}

void IpcClient::requestAttackChain()
{
    send(IpcMessage::create(IpcMessageType::AttackChainRequest, {}));
}

void IpcClient::clearAttackChainHits()
{
    send(IpcMessage::create(IpcMessageType::AttackChainClearRequest, {}));
}

void IpcClient::manualQuarantine(const QString& path)
{
    ManualQuarantinePayload p;
    p.path = path;
    send(IpcMessage::from(IpcMessageType::ManualQuarantineRequest, p));
}

void IpcClient::requestTimeline(const TimelineRequestPayload& p)
{
    send(IpcMessage::from(IpcMessageType::EventTimelineRequest, p));
}

QUuid IpcClient::requestAttackGraph(const QUuid& seedEventId, int rootPid, int windowSeconds)
{
    AttackGraphRequestPayload p;
    p.seedEventId = seedEventId;
    p.rootPid = rootPid;
    p.windowSeconds = windowSeconds;
    send(IpcMessage::from(IpcMessageType::AttackGraphRequest, p));
    return p.requestId;
}

void IpcClient::requestProcesses(bool includeCommandLine, bool resolveOrigin)
{
    ProcessListRequestPayload p;
    p.includeCommandLine = includeCommandLine;
    p.resolveOrigin = resolveOrigin;
    send(IpcMessage::from(IpcMessageType::ProcessListRequest, p));
}

void IpcClient::processAction(const ProcessActionRequestPayload& p)
{
    send(IpcMessage::from(IpcMessageType::ProcessActionRequest, p));
}

void IpcClient::requestVtHistory()
{
    send(IpcMessage::create(IpcMessageType::VtHistoryRequest, {}));
}

void IpcClient::vtQuery(const VtRequestPayload& p)
{
    send(IpcMessage::from(IpcMessageType::VtQueryRequest, p));
}

void IpcClient::vtDetail(const QString& sha256)
{
    bulwark::ipc::VtRequestPayload p;      // 复用请求体:filePath 携带 sha256
    p.requestId = QUuid::createUuid();
    p.filePath = sha256;
    send(IpcMessage::from(IpcMessageType::VtDetailRequest, p));
}

void IpcClient::intelRefresh(bool previewOnly)
{
    IntelRefreshRequestPayload p;
    p.previewOnly = previewOnly;
    send(IpcMessage::from(IpcMessageType::IntelRefreshRequest, p));
}

void IpcClient::intelApply(const QList<bulwark::DefenseRule>& rules)
{
    IntelApplyRequestPayload p;
    p.rules = rules;
    send(IpcMessage::from(IpcMessageType::IntelApplyRequest, p));
}

void IpcClient::aiScanFile(const QString& path)
{
    // Manual, user-initiated research (runs entirely in the UI; not reported to
    // the service). Config was synced from the last SettingsResponse.
    m_ai->scanFile(path, QString::fromUtf8("手动"));
}

void IpcClient::aiGenerateRules(const QString& request)
{
    // UI-side: ask the model to turn a natural-language intent into rules; the
    // result arrives via aiRulesSuggested for user review before adoption.
    m_ai->generateRules(request);
}

void IpcClient::send(const IpcMessage& msg)
{
    if (!m_sock || m_sock->state() != QLocalSocket::ConnectedState)
        return;
    const QByteArray bytes = (msg.serialize() + QLatin1Char('\n')).toUtf8();
    m_sock->write(bytes);
    m_sock->flush();
}
