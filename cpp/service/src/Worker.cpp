#include "bulwark/service/Worker.h"
#include "bulwark/service/IpcServer.h"
#include "bulwark/service/EventSource.h"
#include "bulwark/service/RuleStore.h"
#include "bulwark/service/AuditLog.h"
#include "bulwark/service/FirstSeenStore.h"
#include "bulwark/service/QuarantineManager.h"
#include "bulwark/service/ThreatRemediator.h"
#include "bulwark/service/EventHistoryStore.h"
#include "bulwark/service/reputation/ReputationManager.h"
#include "bulwark/service/reputation/ThreatBookClient.h"
#include "bulwark/service/reputation/VirusTotalClient.h"
#include "bulwark/service/VtScanHistoryStore.h"
#include "bulwark/service/monitoring/ProcessInspector.h"
#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/engine/AiDecisionPolicy.h"

#include "bulwark/json/JsonSupport.h"

#include <QDateTime>
#include <QFileInfo>
#include <QJsonObject>
#include <QMutexLocker>

#include <optional>

namespace bulwark::service {
using bulwark::VerdictAction;
using bulwark::VerdictSource;
using bulwark::SecurityEvent;
using bulwark::service::monitoring::ProcessInspector;
using bulwark::engine::TrustPolicy;

namespace {
// 网络 IP 情报互证参数(与 .NET Worker 常量一致)。
constexpr int    kNetworkIntelMinScore = 40;                     // 低于此分且无硬指标的外联不查
constexpr qint64 kIpIntelCacheTtlMs    = 7LL * 24 * 3600 * 1000; // IP 情报 7 天强缓存(护极低月配额)
constexpr int    kIpQueueMax           = 64;                     // 后台 IP 查询队列上限
constexpr int    kVtQueueMax           = 64;                     // 后台 VT 扫描队列上限
constexpr int    kRecentDropWindowSecs = 5 * 60;                 // "写出即执行"关联时间窗
constexpr qint64 kVtUnknownDedupTtlSec = 24LL * 3600;            // 未收录/无结论去重窗(24h)

// 把内部清理报告转成发往 UI 的「足迹清理报告」负载(如实列出已清理项与未能清理项)。
bulwark::ipc::RemediationReportPayload makeRemediationPayload(
    const bulwark::SecurityEvent& e, const QString& reason, const RemediationReport& r) {
    bulwark::ipc::RemediationReportPayload p;
    p.timestampUtc = QDateTime::currentDateTimeUtc();
    p.actorPath = e.actorPath;
    p.actorPid = e.actorPid;
    p.reason = reason;
    p.actorQuarantined = r.quarantinedFiles.contains(e.actorPath, Qt::CaseInsensitive);
    p.quarantinedFiles = r.quarantinedFiles;
    p.removedRegistryValues = r.removedRegistryValues;
    p.skipped = r.skipped;
    return p;
}

// 据行为画像 IOC 生成一批拦截规则(主动防护):释放文件哈希 -> 禁跑(精确硬拦);C2 外联 IP ->
// 禁外联;释放文件名 -> 落地即询问(非阻断,避免误报)。note 以 tag 开头,便于识别与去重。
QVector<bulwark::DefenseRule> buildRulesFromProfile(const bulwark::ThreatBehaviorProfile& p,
                                                    const QString& tag) {
    QVector<bulwark::DefenseRule> rules;
    // 1) 释放文件哈希 -> 禁止运行(精确、最稳,同族样本复用即被拦)。
    for (const QString& h : p.droppedFileHashes) {
        const QString hl = h.trimmed().toLower();
        if (hl.size() != 64) continue;
        bulwark::DefenseRule r;
        r.type = bulwark::EventType::ProcessCreate;
        r.actorHashes.insert(hl);
        r.action = VerdictAction::Block;
        r.hardOverride = true;
        r.note = tag + QStringLiteral(" 已知恶意释放物,禁止运行(sha256 ") + hl.left(12) + QStringLiteral("…)");
        rules.append(r);
    }
    // 2) C2 外联 IP -> 禁止外联(整 IP、任意端口)。
    for (const QString& ioc : p.contactedIps) {
        QString ipOnly = ioc.trimmed();
        const int c = ipOnly.lastIndexOf(QLatin1Char(':'));
        if (c > 0) {
            bool ok = false;
            ipOnly.mid(c + 1).toInt(&ok);
            if (ok) ipOnly = ipOnly.left(c); // 去掉端口,按整 IP 拦
        }
        if (ipOnly.isEmpty()) continue;
        bulwark::DefenseRule r;
        r.type = bulwark::EventType::NetworkConnect;
        r.targetPattern = ipOnly + QStringLiteral(":*");
        r.action = VerdictAction::Block;
        r.note = tag + QStringLiteral(" 已知 C2 外联地址,禁止外联:") + ipOnly;
        rules.append(r);
    }
    // 3) 释放文件名 -> 落地即询问(仅收有区分度的名字,最多 20 条,避免噪声与误报)。
    int nameRules = 0;
    for (const QString& name : p.droppedFileNames) {
        if (nameRules >= 20) break;
        if (name.size() < 6 || !name.contains(QLatin1Char('.'))) continue;
        bulwark::DefenseRule r;
        r.type = bulwark::EventType::FileWrite;
        r.targetPattern = QStringLiteral("*\\") + name;
        r.action = VerdictAction::Ask;
        r.note = tag + QStringLiteral(" 已知恶意释放文件名:") + name;
        rules.append(r);
        ++nameRules;
    }
    return rules;
}

// 从命令行提取以 .msi/.msp 结尾的实参(支持带引号的路径)。用于双击 MSI 时定位安装包本身。
QString firstInstallerArg(const QString& cmdLine) {
    QStringList tokens;
    QString cur;
    bool inQuote = false;
    for (const QChar ch : cmdLine) {
        if (ch == QLatin1Char('"')) { inQuote = !inQuote; continue; }
        if (ch.isSpace() && !inQuote) { if (!cur.isEmpty()) { tokens << cur; cur.clear(); } continue; }
        cur += ch;
    }
    if (!cur.isEmpty()) tokens << cur;
    for (const QString& t : tokens) {
        const QString low = t.toLower();
        if (low.endsWith(QLatin1String(".msi")) || low.endsWith(QLatin1String(".msp")))
            return t;
    }
    return QString();
}
} // namespace

Worker::Worker(bulwark::engine::RuleEngine* engine, IpcServer* ipc, EventSource* source,
               RuleStore* ruleStore, AuditLog* audit, FirstSeenStore* firstSeen,
               QuarantineManager* quarantine, reputation::ReputationManager* reputation,
               const bulwark::RuntimeSettings* settings, QObject* parent)
    : QObject(parent), engine_(engine), ipc_(ipc), ruleStore_(ruleStore), audit_(audit),
      firstSeen_(firstSeen), quarantine_(quarantine), reputation_(reputation), settings_(settings) {
    if (quarantine)
        remediator_ = std::make_unique<ThreatRemediator>(*quarantine, Logger(QStringLiteral("Remediator")));
    if (reputation_) {
        // 后台线程的「确认恶意」回调 -> 编组回主线程再处置(碰 IPC/Qt 对象必须在主线程)。
        reputation_->setMaliciousConfirmed(
            [this](const bulwark::SecurityEvent& ev, const bulwark::FileReputation& rep) {
                confirmReputationMaliciousAsync(ev, rep); // 后台拉行为画像后再编组回主线程处置
            });
    }
    source_ = source;
    connect(source, &EventSource::eventProduced, this, &Worker::onEvent);
    connect(ipc_, &IpcServer::promptResponse, this, &Worker::onPromptResponse);
    connect(ipc_, &IpcServer::aiScanResponse, this, &Worker::onAiScanResponse);
}

// unique_ptr<ThreatRemediator> 的析构需在此(完整类型可见处)生成。
Worker::~Worker() {
    // 先停后台 worker 并 join,再让成员析构 —— 保证不会在对象析构后回调 this。
    ipRunning_.store(false);
    vtRunning_.store(false);
    {
        QMutexLocker lk(&ipMx_);
        ipCv_.wakeAll();
    }
    {
        QMutexLocker lk(&vtMx_);
        vtCv_.wakeAll();
    }
    if (ipWorker_.joinable())
        ipWorker_.join();
    if (vtWorker_.joinable())
        vtWorker_.join();
}

void Worker::setIpIntel(reputation::ThreatBookClient* tb) {
    ipIntel_ = tb;
    if (ipIntel_ && !ipRunning_.exchange(true))
        ipWorker_ = std::thread([this] { ipConsumeLoop(); });
}

void Worker::setVtScan(reputation::VirusTotalClient* vt, VtScanHistoryStore* history) {
    vt_ = vt;
    vtHistory_ = history;
    if (vt_ && !vtRunning_.exchange(true))
        vtWorker_ = std::thread([this] { vtScanLoop(); });
}

QString Worker::describe(const SecurityEvent& e, VerdictAction action) const {
    const QString act = action == VerdictAction::Block ? QString::fromUtf8("\xe6\x8b\xa6\xe6\x88\xaa")
                      : action == VerdictAction::Ask   ? QString::fromUtf8("\xe8\xaf\xa2\xe9\x97\xae")
                                                       : QString::fromUtf8("\xe6\x94\xbe\xe8\xa1\x8c");
    QString line = QStringLiteral("[%1] %2 %3 %4 -> %5 (%6 %7)")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")),
             act, bulwark::eventTypeToString(e.type), e.actorPath, e.target,
             QString::fromUtf8("\xe9\xa3\x8e\xe9\x99\xa9"), QString::number(e.riskScore));
    // 拦截 / 询问时附上命中的规则说明,让「是哪条规则起的作用」在日志里直接可见(放行不附,避免刷屏)。
    if (action != VerdictAction::Allow && !e.matchedRuleNote.isEmpty())
        line += QStringLiteral(" [\xe8\xa7\x84\xe5\x88\x99: %1]").arg(e.matchedRuleNote);
    return line;
}

void Worker::onEvent(const SecurityEvent& incoming) {
    SecurityEvent e = incoming; // evaluate 需要可变引用(写回证据/分数)

    // 总开关关闭 / 该维度未启用 -> 直接放行(不富化、不评估、不处置),仅记日志/审计。
    // 对应 .NET Worker.HandleEventAsync 开头的短路;让 UI 的总开关与分项开关真正生效。
    if (settings_ && (!settings_->protectionEnabled || !isDimensionEnabled(e.type))) {
        ipc_->sendLog(describe(e, VerdictAction::Allow));
        ipc_->sendEventLog(e, VerdictAction::Allow, VerdictSource::DefaultPolicy);
        writeAudit(e, VerdictAction::Allow, VerdictSource::DefaultPolicy);
        return;
    }

    enrich(e);                  // 先富化(签名/哈希/命令行/首见/祖先链),规则引擎才有据可判
    chain_.record(e);                        // 记入进程链(供后续事件关联与足迹清理)
    e.chainContext = chain_.buildContext(e); // 合并历史 + 祖先链上下文,喂给杀伤链阶段分析
    const bulwark::Verdict v = engine_->evaluate(e);
    // 用户明确信任(文件/文件夹)命中:信任即「完全不检测」——放行并跳过全部后台扫描
    //(外部信誉 / 微步 IP 情报 / VirusTotal / AI 研判),仅保留记录与放行。
    const bool skipDetection = e.userTrusted;
    // 已被本地裁决为拦截(含「记住的恶意哈希」硬拦规则)-> 不必再查云端:对已知恶意不重复调用。
    if (!skipDetection && reputation_ && v.action != VerdictAction::Block)
        reputation_->maybeEnqueue(e); // 值得则后台限流查外部信誉(填缓存,下次命中即用)

    // 网络外联 IP 情报互证:对「未被判 Block 的可疑外联」后台查微步 IP 信誉,确认恶意再补偿拦截。
    // 用户态观测源无法在连接前阻断,故这里不改当前裁决,由后台确认恶意后结束外联进程树。
    if (!skipDetection && e.type == bulwark::EventType::NetworkConnect && v.action != VerdictAction::Block)
        maybeQueryEgressIp(e);

    // 双击 / 释放载荷病毒扫描:对未被判 Block 的进程创建,后台 VT 扫描(哈希查 + 未收录则上传),
    // 确认恶意再补偿结束进程树(用户态观测源无法在进程创建前阻断)。
    if (!skipDetection && e.type == bulwark::EventType::ProcessCreate && v.action != VerdictAction::Block) {
        maybeScanDoubleClick(e);
        maybeScanInstallerPackage(e); // 双击 MSI/MSP:扫描安装包本身(msiexec 只是宿主进程)
    }

    // 安装包 / 可执行体「落盘即扫」:银狐等常以 .msi 投递,双击跑的是签名 msiexec —— 常规双击查杀
    // 看不到安装包本身,且 Driver 源不带命令行导致抠不出包路径。故在文件写入阶段就对写入用户可写
    // 目录的安装包/可执行体直接送 VT 扫描(不依赖执行、不抢命令行),命中恶意即隔离文件(不杀写入方)。
    if (!skipDetection && e.type == bulwark::EventType::FileWrite && v.action != VerdictAction::Block)
        maybeScanDroppedInstaller(e);

    // AI 大模型研判(可选补充,默认关):双击查杀的主路径是 VirusTotal(上面的 maybeScanDoubleClick)。
    // 只有当用户显式开启「灰区 AI 会诊」(aiGrayZoneConsultEnabled)时,才对未拦截的双击/释放载荷
    // 额外请求 UI 侧大模型研判 —— 避免双击普通程序也自动调用大模型。UI 回 AiScanResponse,恶意则由
    // onAiScanResponse 折叠 + 补偿处置。
    if (!skipDetection && e.type == bulwark::EventType::ProcessCreate && v.action != VerdictAction::Block
        && settings_ && settings_->aiGrayZoneConsultEnabled && settings_->aiConfigured()
        && shouldAiScan(e)) {
        if (aiPending_.size() > 256)
            aiPending_.clear(); // 有界:UI 未回执也不无限增长
        aiPending_.insert(e.id, e);
        ipc_->requestAiScan(e);
    }

    // 静默模式:把「询问」降级为放行,但确定性高危不降级——反而升级为拦截 + 隔离。
    // 「确定性高危」= 存在硬恶意指标(hasThreatIndicator)且风险 >= 可疑阈值:静默只压低置信打扰,
    // 绝不放过银狐等投递链里的高危行为(注入 / 持久化 / 关杀软 / 侧载等)。无硬指标的软信号仍照常放行。
    VerdictAction action = v.action;
    VerdictSource source = v.source;
    if (action == VerdictAction::Ask && settings_ && settings_->silentMode) {
        if (e.hasThreatIndicator && e.riskScore >= bulwark::engine::ThreatDetector::Suspicious) {
            action = VerdictAction::Block;
            source = VerdictSource::Heuristic;
            log_.warning(QStringLiteral("静默模式:确定性高危升级为拦截(硬指标 + 风险 %1):%2")
                             .arg(e.riskScore).arg(e.actorPath));
        } else {
            action = VerdictAction::Allow;
            source = VerdictSource::DefaultPolicy;
        }
    }

    // 已签名主体默认放行(不弹提醒):开启「信任已签名主体」且主体持有有效数字签名
    //(未签名失配 / 未吊销 / 未过期后签名)时,把「询问」降级为放行——不再为签名程序弹窗打扰。
    // 注意:引擎判定的 Block(高危硬指标、吊销/过期后签名等确定性恶意)不受影响,仍然拦截;
    // 签名失配 / 无签名的主体也不在此列,照常询问。此策略由 trustSignedActors 开关控制,可关闭。
    if (action == VerdictAction::Ask && settings_ && settings_->trustSignedActors
        && e.actorSigned && !e.signatureMismatch && !e.certRevoked && !e.signedAfterCertExpiry) {
        action = VerdictAction::Allow;
        source = VerdictSource::TrustedSigner;
        log_.info(QStringLiteral("已签名主体默认放行(信任签名,不弹询问):%1").arg(e.actorPath));
    }

    switch (action) {
        case VerdictAction::Ask:
            pending_.insert(e.id, e);
            ipc_->sendPrompt(e);
            break;
        case VerdictAction::Block:
            ipc_->sendBlock(e);
            enforceBlock(e);            // 用户态观测源:事后补偿性结束进程树
            // 确定性恶意:隔离载荷 + 清除持久化。用最终裁决(可能被静默模式升级为 Block)驱动,
            // 而非原始 v —— 否则静默升级的高危不会触发隔离(v.action 仍是 Ask)。
            remediateIfMalicious(e, action == v.action ? v
                                                       : bulwark::Verdict::forEvent(e, action, source));
            break;
        default:
            break;
    }
    // 阻塞式源(内核驱动)需把最终裁决回写内核(放行/拦截)。仅内核实际等待裁决的事件
    // (文件/注册表/结束进程)会真正回复;进程创建等 fire-and-forget 事件在源侧为 no-op。
    // 询问(Ask)延后到用户回复时(onPromptResponse)再回写。观测源 wantsVerdict()==false。
    if (source_ && source_->wantsVerdict() && action != VerdictAction::Ask)
        source_->submitVerdict(e, action);

    ipc_->sendLog(describe(e, action));
    ipc_->sendEventLog(e, action, source);
    if (eventHistory_) { // 落结构化事件历史,供 UI 打开活动日志/拦截记录时回填
        bulwark::ipc::EventLogPayload p;
        p.event = e;
        p.action = action;
        p.source = source;
        eventHistory_->add(p);
    }
    writeAudit(e, action, source);
    log_.info(describe(e, action));
}

bool Worker::isDimensionEnabled(bulwark::EventType type) const {
    if (!settings_)
        return true;
    switch (type) {
        case bulwark::EventType::ProcessCreate:
        case bulwark::EventType::ProcessTerminate:
        case bulwark::EventType::RemoteThread:
        case bulwark::EventType::ImageLoad:
            return settings_->processProtection;
        case bulwark::EventType::FileWrite:
        case bulwark::EventType::FileDelete:
            return settings_->fileProtection;
        case bulwark::EventType::RegistryWrite:
            return settings_->registryProtection;
        case bulwark::EventType::SelfProtect:
            return settings_->selfProtection;
        case bulwark::EventType::NetworkConnect:
        case bulwark::EventType::DnsQuery:
            return settings_->networkProtection;
        default:
            return true;
    }
}

void Worker::onPromptResponse(const QUuid& eventId, VerdictAction action,
                              bool remember, bulwark::RememberScope scope) {
    auto it = pending_.find(eventId);
    if (it == pending_.end()) return;
    SecurityEvent e = it.value();
    pending_.erase(it);

    log_.info(QStringLiteral("用户裁决: %1 -> %2%3")
                  .arg(e.actorPath, bulwark::verdictActionToString(action),
                       remember ? QStringLiteral(" (记住)") : QString()));

    if (remember && action != VerdictAction::Ask) {
        std::optional<QDateTime> expires;
        bool sessionOnly = false;
        const QDateTime now = QDateTime::currentDateTimeUtc();
        switch (scope) {
            case bulwark::RememberScope::Session:   sessionOnly = true; break;
            case bulwark::RememberScope::OneHour:   expires = now.addSecs(3600); break;
            case bulwark::RememberScope::OneDay:    expires = now.addSecs(86400); break;
            case bulwark::RememberScope::Permanent:
            default: break;
        }
        engine_->createRuleFrom(e, action, expires, sessionOnly);
        ruleStore_->save(engine_->getRules());
    }

    // 用户裁决为拦截:对用户态观测源(含内核驱动进程创建等 fire-and-forget 事件)补偿性
    // 结束进程树(enforceBlock 内部仅对 userModeObserved 生效,并含关键进程防护)。
    if (action == VerdictAction::Block)
        enforceBlock(e);
    // 阻塞式源(内核驱动):把用户裁决回写内核。仅文件/注册表/结束进程等内核等待类事件真正回复。
    if (source_ && source_->wantsVerdict())
        source_->submitVerdict(e, action);

    ipc_->sendLog(describe(e, action));
    recordEvent(e, action, VerdictSource::UserPrompt); // 用户裁决登记到活动 / 拦截记录
    writeAudit(e, action, VerdictSource::UserPrompt);
}

void Worker::enrich(SecurityEvent& e) {
    // 1) 补全映像路径:内核/ETW 事件偶尔只带 PID 占位,按 PID 反查完整路径更可靠。
    if ((e.actorPath.isEmpty() || e.actorPath.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        && e.actorPid > 0) {
        QString resolved = ProcessInspector::tryGetProcessImagePath(e.actorPid);
        // 短命进程(reg.exe / sc.exe 等)做完注册表/文件写入即退出,按 PID 实时反查失败;
        // 回退到进程链历史里该 PID 早先 ProcessCreate 记下的映像路径,签名判定才不会因此落空。
        if (resolved.isEmpty())
            resolved = chain_.lastKnownPath(e.actorPid);
        if (!resolved.isEmpty()) {
            e.actorPath = resolved;
            if (e.target.isEmpty() || e.target.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
                e.target = resolved;
        }
    }

    // 2) 命令行:内核/ETW 进程事件不带命令行,大量规则(LOLBin / vssadmin / certutil /
    //    bcdedit / WMI 持久化 等)依赖命令行特征——按 PID 读 PEB 回填。
    if (e.commandLine.isEmpty() && e.actorPid > 0)
        e.commandLine = ProcessInspector::tryGetCommandLine(e.actorPid);

    // 3) 父进程路径(可疑父子链判定,如 Office -> powershell)。
    if (e.parentPath.isEmpty() && e.parentPid > 0)
        e.parentPath = ProcessInspector::tryGetProcessImagePath(e.parentPid);

    // 3.5) 用 OS API 回溯完整父进程祖先链种入 chainContext(即便进程链跟踪器无历史,
    //      刚开机/首个事件时溯源链也完整;buildContext 随后会与历史合并)。
    seedAncestryChain(e);

    // 4) 主体取证:映像路径指向真实文件时才做签名/哈希,避免对占位符做无谓 I/O。
    const QString path = e.actorPath;
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive)) {
        e.actorSigned = false;
        return;
    }

    e.actorSigned    = ProcessInspector::isSigned(path);
    e.actorPublisher = ProcessInspector::tryGetPublisher(path);
    e.actorHash      = ProcessInspector::tryComputeSha256(path);

    // 签名失配:内嵌了签名但信任校验不过(篡改 / 盗用证书的典型特征)。已知未受信时,
    // 只需检测是否内嵌签名即可,避免在进程创建同步裁决路径上重复一次验签。
    if (!e.actorSigned)
        e.signatureMismatch = ProcessInspector::hasEmbeddedSignature(path);

    // 证书画像:指纹 / 有效期 / 吊销 / 过期后签名(证书被吊销即便验签不过仍是硬指标)。
    const ProcessInspector::CertInfo ci = ProcessInspector::getCertInfo(path);
    if (!ci.thumbprint.isEmpty())    e.actorCertThumbprint = ci.thumbprint;
    if (ci.notAfterUtc.isValid())    e.certNotAfterUtc     = ci.notAfterUtc;
    if (ci.signingTimeUtc.isValid()) e.signingTimeUtc      = ci.signingTimeUtc;
    e.certRevoked           = ci.revoked;
    e.signedAfterCertExpiry = ci.signedAfterCertExpiry;

    // 文件体积:银狐 / 游蛇 惯用「文件膨胀」把样本撑到数十 MB 以规避扫描。
    const QFileInfo fi(path);
    if (fi.exists() && fi.isFile())
        e.actorFileSize = fi.size();

    // 本机首见(低流行度信号):按 SHA-256 判定并落盘;单独不触发拦截,仅参与提分。
    if (firstSeen_ && !e.actorHash.isEmpty())
        e.isFirstSeen = firstSeen_->markAndCheckFirstSeen(e.actorHash);

    // 外部信誉(同步只读缓存,绝不联网):命中已知结论则挂到事件参与本地评分。
    // 网络查询由 onEvent 后的 maybeEnqueue 在后台线程完成并回填缓存,下次即命中。
    if (reputation_ && !e.actorHash.isEmpty()) {
        const std::optional<bulwark::FileReputation> rep = reputation_->tryGetCached(e.actorHash);
        if (rep.has_value())
            e.reputation = rep;
    }
}

void Worker::seedAncestryChain(SecurityEvent& e) {
    // 逐级回溯父进程,把每一级(含主体自身)作为一条 ChainEventInfo 追加到 e.chainContext。
    // 防环:限制深度并记录已访问 PID;同 PID 不重复添加。对应 .NET DriverEventSource.SeedAncestryChain。
    QSet<int> existingPids;
    for (const bulwark::ChainEventInfo& c : e.chainContext)
        if (c.actorPid > 0)
            existingPids.insert(c.actorPid);

    QSet<int> visited;
    int cur = e.actorPid;
    int depth = 0;
    QVector<bulwark::ChainEventInfo> seeded;
    while (cur > 0 && depth < 16 && !visited.contains(cur)) {
        visited.insert(cur);
        const int parent = (cur == e.actorPid && e.parentPid > 0)
                               ? e.parentPid
                               : ProcessInspector::tryGetParentPid(cur);
        if (!existingPids.contains(cur)) {
            const QString curPath = (cur == e.actorPid)
                                        ? e.actorPath
                                        : ProcessInspector::tryGetProcessImagePath(cur);
            // 跳过无法解析路径的中间节点(仅 PID 意义不大),但主体始终保留。
            if (cur == e.actorPid || !curPath.isEmpty()) {
                bulwark::ChainEventInfo node;
                node.timestampUtc = e.timestampUtc.isValid() ? e.timestampUtc
                                                             : QDateTime::currentDateTimeUtc();
                node.type = e.type;
                node.actorPid = cur;
                node.parentPid = parent;
                node.actorPath = curPath;
                node.target = (cur == e.actorPid) ? e.target : QString();
                node.riskScore = (cur == e.actorPid) ? e.riskScore : 0;
                seeded.append(node);
            }
        }
        if (parent <= 0)
            break;
        cur = parent;
        ++depth;
    }
    if (!seeded.isEmpty())
        e.chainContext += seeded;
}

void Worker::enforceBlock(const SecurityEvent& e) {
    // 内核源(驱动)是真正的 pre-action 拦截,动作发生前即被阻断,无需在此重复结束。
    // 用户态观测源(ETW / WMI)只能观测,故对其拦截执行补偿性处置——结束作恶进程树。
    if (!e.userModeObserved)
        return;

    // 优先结束 RPC 真凶(如经 svchost 代发的请求),否则结束事件主体本身。
    const int pid = e.originatorPid > 0 ? e.originatorPid : e.actorPid;
    if (pid <= 4)
        return; // 系统/Idle 等绝不触碰

    const int killed = ProcessInspector::terminateProcessTree(pid);
    if (killed > 0)
        log_.info(QStringLiteral("拦截处置:已结束进程树 PID=%1(共 %2 个进程)。")
                      .arg(pid).arg(killed));
    else
        log_.warning(QStringLiteral("拦截处置:PID=%1 未结束任何进程(已退出,或为受保护/关键进程)。")
                         .arg(pid));
}

void Worker::remediateIfMalicious(const SecurityEvent& e, const bulwark::Verdict& v) {
    if (!remediator_)
        return;
    // 仅对「确定性恶意」的进程主体执行隔离 + 足迹清理:命中规则 / 启发式判定。
    // 默认策略 / 超时兜底 / 用户裁决的 Block 不触发,避免误清理良性程序。
    if (v.action != VerdictAction::Block)
        return;
    if (v.source != VerdictSource::Rule && v.source != VerdictSource::Heuristic)
        return;
    if (e.type != bulwark::EventType::ProcessCreate && e.type != bulwark::EventType::RemoteThread)
        return;
    if (e.actorPath.trimmed().isEmpty())
        return;

    // 足迹:进程链跟踪器收集该恶意进程树(含后代)记录过的全部事件——remediate 据此隔离
    // 其释放/关联的文件,并移除指向这些文件的注册表自启动 / IFEO / 服务持久化。
    const RemediationReport report = remediator_->remediate(e, chain_.collectTreeEvents(e.actorPid));

    if (report.totalActions() == 0 && report.skipped.isEmpty())
        return; // 无任何动作,不打扰

    const QString summary =
        QStringLiteral("恶意足迹清理:隔离文件 %1 个,移除持久化 %2 项,未清理 %3 项 [%4]")
            .arg(report.quarantinedFiles.size())
            .arg(report.removedRegistryValues.size())
            .arg(report.skipped.size())
            .arg(e.actorPath);
    ipc_->sendLog(summary);
    log_.warning(summary);

    // 「足迹清理报告」推 UI(透明列出已清理 / 未清理项,支持「重试隔离」)。
    ipc_->sendRemediationReport(makeRemediationPayload(
        e,
        v.source == VerdictSource::Rule
            ? (e.matchedRuleNote.isEmpty() ? QString::fromUtf8("命中防护规则") : e.matchedRuleNote)
            : QString::fromUtf8("启发式判定恶意"),
        report));

    // 审计留痕(action=Remediate),明细含成功清理项与未清理项及原因。
    using namespace bulwark::json;
    QJsonObject o;
    o["timestampUtc"] = dateTimeToIso(QDateTime::currentDateTimeUtc());
    o["type"] = bulwark::eventTypeToString(e.type);
    o["actorPath"] = e.actorPath;
    o["actorPid"] = e.actorPid;
    o["target"] = QStringLiteral("足迹清理 · 成功 %1 · 未清理 %2")
                      .arg(report.totalActions()).arg(report.skipped.size());
    o["action"] = QStringLiteral("Remediate");
    o["source"] = bulwark::verdictSourceToString(v.source);
    o["riskScore"] = e.riskScore;
    QStringList details;
    for (const QString& f : report.quarantinedFiles)
        details << (QStringLiteral("隔离文件:") + f);
    for (const QString& r : report.removedRegistryValues)
        details << (QStringLiteral("移除持久化:") + r);
    for (const bulwark::ipc::RemediationSkippedItem& s : report.skipped)
        details << (QStringLiteral("未清理:") + s.target + QStringLiteral("(") + s.reason + QStringLiteral(")"));
    o["reasons"] = strListToJson(details);
    audit_->writeRecord(o);
}

void Worker::confirmReputationMaliciousAsync(const SecurityEvent& e, const bulwark::FileReputation& rep) {
    // 后台线程:确认恶意后顺带拉取样本行为画像(VT 沙箱报告)——释放文件/注册表/外联 IP 等。
    // 无 VT 句柄 / 无哈希则画像为空,处置自动降级为原有「隔离主体 + 清持久化」,不受影响。
    bulwark::ThreatBehaviorProfile profile;
    const QString sha = !rep.sha256.isEmpty() ? rep.sha256 : e.actorHash;
    if (reputation_ && !sha.isEmpty())
        profile = reputation_->fetchBehaviorProfile(sha); // 聚合 VT + HA 等各源的行为画像
    QMetaObject::invokeMethod(
        this, [this, e, rep, profile] { onReputationMalicious(e, rep, profile); },
        Qt::QueuedConnection);
}

void Worker::onReputationMalicious(const SecurityEvent& e, const bulwark::FileReputation& rep,
                                   const bulwark::ThreatBehaviorProfile& profile) {
    // 后台信誉查询确认恶意(已编组回主线程):告警 + 结束仍在运行的进程树 + 隔离载荷/清除持久化;
    // 若带行为画像,则额外清理已知释放物、并据 IOC 生成主动拦截规则。
    SecurityEvent ev = e;
    ev.reputation = rep;
    ev.hasThreatIndicator = true;

    const QString label = rep.threatLabel.trimmed().isEmpty() ? QString::fromUtf8("恶意") : rep.threatLabel;
    const QString srcName = rep.source.trimmed().isEmpty() ? QString::fromUtf8("外部信誉") : rep.source;
    // 命中型源(如 MalwareBazaar)无引擎计数,改用威胁名表述,避免出现「0/0」。
    const QString detail = rep.totalEngines > 0
                               ? QStringLiteral("%1/%2").arg(rep.malicious).arg(rep.totalEngines)
                               : label;
    const QString msg = QStringLiteral("%1 确认恶意:%2(%3)").arg(srcName, ev.actorPath, detail);
    log_.warning(msg);
    ipc_->sendLog(msg);
    // 确认恶意:抬高风险分并补一条原因,拦截记录/活动日志的风险等级与 toast「来源」才如实。
    if (ev.riskScore < 90) ev.riskScore = 90;
    ev.riskReasons.append(QStringLiteral("%1 判定恶意:%2").arg(srcName, detail));
    ipc_->sendBlock(ev);
    recordEvent(ev, VerdictAction::Block, VerdictSource::Heuristic);

    // 结束进程树(样本可能仍在运行);关键系统进程由 ProcessInspector 内部安全门槛保护。
    if (ev.actorPid > 4)
        ProcessInspector::terminateProcessTree(ev.actorPid);

    // 主动防护 + 记忆:据行为画像 IOC 生成拦截规则,并【记住该恶意样本本身的哈希】——注入本地
    // 硬拦规则(落盘)后,下次同一文件再运行会被本地引擎直接拦截,不再重复调用 VT / 云端。
    int injectedRules = 0;
    if (injectIntelRules_) {
        QVector<bulwark::DefenseRule> intelRules;
        const QString selfSha = !rep.sha256.isEmpty() ? rep.sha256 : e.actorHash;
        if (selfSha.size() == 64) {
            bulwark::DefenseRule r;
            r.type = bulwark::EventType::ProcessCreate;
            r.actorHashes.insert(selfSha.toLower());
            r.action = VerdictAction::Block;
            r.hardOverride = true;
            r.note = QString::fromUtf8("[情报-恶意] 云端确认恶意,已记住哈希(禁止运行,不再重复云查)");
            intelRules.append(r);
        }
        if (profile.fetched)
            intelRules += buildRulesFromProfile(profile, QString::fromUtf8("[情报-行为]"));
        if (!intelRules.isEmpty())
            injectedRules = injectIntelRules_(intelRules);
    }
    if (profile.fetched && !profile.isEmpty()) {
        const QString pmsg =
            QStringLiteral("情报行为画像[%1]:释放文件 %2、注册表 %3、外联IP %4、域名 %5;已注入主动拦截规则 %6 条。")
                .arg(profile.source.isEmpty() ? QStringLiteral("VirusTotal") : profile.source)
                .arg(profile.droppedFileNames.size()).arg(profile.registryKeysSet.size())
                .arg(profile.contactedIps.size()).arg(profile.contactedDomains.size()).arg(injectedRules);
        log_.warning(pmsg);
        ipc_->sendLog(pmsg);
    }

    // 隔离载荷 + 清除持久化(remediate 已并入画像「已知释放文件」翻译到本机后的路径)。
    int quarantined = 0, removed = 0, skipped = 0;
    if (remediator_) {
        const RemediationReport report =
            remediator_->remediate(ev, chain_.collectTreeEvents(ev.actorPid), profile);
        quarantined = static_cast<int>(report.quarantinedFiles.size());
        removed = static_cast<int>(report.removedRegistryValues.size());
        skipped = static_cast<int>(report.skipped.size());
        bulwark::ipc::RemediationReportPayload payload = makeRemediationPayload(
            ev, QStringLiteral("外部信誉判定恶意:%1(%2/%3)").arg(label).arg(rep.malicious).arg(rep.totalEngines),
            report);
        // 情报补充摘要(供 UI「清理报告」展示:该样本已知会做什么 + 已生成多少主动拦截规则)。
        payload.intelSource = profile.source;
        payload.intelDroppedFiles = profile.droppedFileNames;
        payload.intelRegistryKeys = profile.registryKeysSet;
        payload.intelContactedIps = profile.contactedIps;
        payload.intelContactedDomains = profile.contactedDomains;
        payload.intelRulesInjected = injectedRules;
        ipc_->sendRemediationReport(payload);
    }

    using namespace bulwark::json;
    QJsonObject o;
    o["timestampUtc"] = dateTimeToIso(QDateTime::currentDateTimeUtc());
    o["type"] = bulwark::eventTypeToString(ev.type);
    o["actorPath"] = ev.actorPath;
    o["actorPid"] = ev.actorPid;
    o["target"] = QStringLiteral("信誉确认恶意 · 隔离 %1 · 移除 %2 · 未清理 %3")
                      .arg(quarantined).arg(removed).arg(skipped);
    o["action"] = QStringLiteral("Block");
    o["source"] = QString::fromUtf8("威胁情报");
    o["riskScore"] = ev.riskScore;
    o["reasons"] = strListToJson(QStringList{
        QStringLiteral("外部信誉命中:%1/%2(%3)").arg(rep.malicious).arg(rep.totalEngines).arg(label) });
    audit_->writeRecord(o);
}

void Worker::onAiScanResponse(const bulwark::ipc::AiScanResponsePayload& resp) {
    auto it = aiPending_.find(resp.eventId);
    if (it == aiPending_.end())
        return; // 未知/手动扫描回执:服务未追踪,忽略
    const SecurityEvent e = it.value();
    aiPending_.erase(it);

    // 把 AI 研判视为对该观测事件的灰区会诊,按 AiDecisionPolicy 折叠:恶意 -> 补偿处置。
    const bulwark::engine::AiDecisionPolicy::Outcome outcome =
        bulwark::engine::AiDecisionPolicy::apply(e, VerdictAction::Ask, resp.available,
                                                 resp.recommendation, resp.summary);
    const QString verdictText = !resp.available
        ? QStringLiteral("不可用")
        : (resp.recommendation == VerdictAction::Block ? QString::fromUtf8("恶意")
                                                       : QString::fromUtf8("未见异常"));
    log_.info(QStringLiteral("AI 研判回执:%1 -> %2%3")
                  .arg(e.actorPath, verdictText,
                       resp.summary.trimmed().isEmpty() ? QString()
                                                        : (QStringLiteral(" · ") + resp.summary)));
    if (outcome.action == VerdictAction::Block)
        onAiMalicious(e, resp.summary);
}

void Worker::onAiMalicious(const SecurityEvent& e, const QString& summary) {
    SecurityEvent ev = e;
    ev.hasThreatIndicator = true;
    const QString reason = summary.trimmed().isEmpty()
        ? QString::fromUtf8("AI 研判判定恶意")
        : (QString::fromUtf8("AI 研判判定恶意:") + summary);
    log_.warning(reason + QStringLiteral(" [") + ev.actorPath + QStringLiteral("]"));
    ipc_->sendLog(reason);
    if (ev.riskScore < 90) ev.riskScore = 90;
    ev.riskReasons.append(QString::fromUtf8("AI 研判判定恶意"));
    ipc_->sendBlock(ev);
    recordEvent(ev, VerdictAction::Block, VerdictSource::Heuristic);

    // 补偿处置:结束进程树(关键系统进程由 ProcessInspector 内部安全门槛保护)。
    if (ev.actorPid > 4)
        ProcessInspector::terminateProcessTree(ev.actorPid);

    // 隔离载荷 + 清除持久化。
    int quarantined = 0, removed = 0, skipped = 0;
    if (remediator_) {
        const RemediationReport report = remediator_->remediate(ev, chain_.collectTreeEvents(ev.actorPid));
        quarantined = static_cast<int>(report.quarantinedFiles.size());
        removed = static_cast<int>(report.removedRegistryValues.size());
        skipped = static_cast<int>(report.skipped.size());
        ipc_->sendRemediationReport(makeRemediationPayload(ev, reason, report));
    }

    using namespace bulwark::json;
    QJsonObject o;
    o["timestampUtc"] = dateTimeToIso(QDateTime::currentDateTimeUtc());
    o["type"] = bulwark::eventTypeToString(ev.type);
    o["actorPath"] = ev.actorPath;
    o["actorPid"] = ev.actorPid;
    o["target"] = QStringLiteral("AI 研判恶意 · 隔离 %1 · 移除 %2 · 未清理 %3")
                      .arg(quarantined).arg(removed).arg(skipped);
    o["action"] = QStringLiteral("Block");
    o["source"] = QString::fromUtf8("AI 研判");
    o["riskScore"] = ev.riskScore;
    o["reasons"] = strListToJson(QStringList{ reason });
    audit_->writeRecord(o);
}

void Worker::maybeQueryEgressIp(const bulwark::SecurityEvent& e) {
    if (!ipIntel_ || !ipRunning_.load())
        return;
    // 微步 IP 情报随「微步在线 ThreatBook」总开关启用(UI 该开关即描述为「文件 + IP 情报」)。
    // 独立的 threatBookNetworkIntelEnabled 作为可选额外开关,二者任一开启即生效——否则该开关
    // 无 UI 入口、永远为 false,会让整条 IP 情报链路(queryIp / onEgressMalicious)成为死代码。
    // 极低的月配额由客户端自身的 scene 月度配额兜底,无需再用开关抑制。
    if (!settings_ || !(settings_->threatBookEnabled || settings_->threatBookNetworkIntelEnabled))
        return;
    const QString ip = extractRemoteIpv4(e.target);
    if (ip.isEmpty() || isPrivateOrReserved(ip))
        return;
    // 强可信 / 健康签名主体的外联不查(正常业务外联,省配额、符合低误报)。
    if (TrustPolicy::isStronglyTrusted(e).ok || TrustPolicy::isHealthySigned(e).ok)
        return;
    // 仅对「已有可疑信号」的外联做情报互证:硬指标 / 风险分达阈值 / 主体未签名。
    const bool suspicious = e.hasThreatIndicator || e.riskScore >= kNetworkIntelMinScore || !e.actorSigned;
    if (!suspicious)
        return;

    bool cachedMalicious = false;
    bool enqueued = false;
    {
        QMutexLocker lk(&ipMx_);
        const auto it = ipCache_.constFind(ip);
        if (it != ipCache_.constEnd()
            && it.value().second.msecsTo(QDateTime::currentDateTimeUtc()) < kIpIntelCacheTtlMs) {
            cachedMalicious = (it.value().first == bulwark::ReputationVerdict::Malicious);
        } else if (!ipInflight_.contains(ip) && ipQueue_.size() < kIpQueueMax) {
            ipInflight_.insert(ip);
            ipQueue_.enqueue(IpJob{ ip, e });
            enqueued = true;
        }
    }
    // 锁外处置:缓存命中恶意即在主线程直接补偿;否则唤醒后台 worker 去查。
    if (cachedMalicious)
        onEgressMalicious(e, ip, QString());
    else if (enqueued)
        ipCv_.wakeOne();
}

void Worker::ipConsumeLoop() {
    while (ipRunning_.load()) {
        IpJob job;
        {
            QMutexLocker lk(&ipMx_);
            while (ipRunning_.load() && ipQueue_.isEmpty())
                ipCv_.wait(&ipMx_);
            if (!ipRunning_.load())
                return;
            job = ipQueue_.dequeue();
        }

        const bulwark::IpReputation rep = ipIntel_->queryIp(job.ip); // 阻塞:限流 + 一次 curl
        {
            QMutexLocker lk(&ipMx_);
            ipInflight_.remove(job.ip);
            if (rep.querySucceeded) // 失败不缓存(下次可重试),与 .NET fail-open 一致
                ipCache_.insert(job.ip, { rep.verdict, QDateTime::currentDateTimeUtc() });
        }

        if (rep.querySucceeded && rep.verdict == bulwark::ReputationVerdict::Malicious) {
            const bulwark::SecurityEvent ev = job.e;
            const QString ip = job.ip;
            const QString label = rep.threatLabel;
            // 编组回主线程处置(碰 IPC/进程操作须在主线程,与其它引擎变更串行)。
            QMetaObject::invokeMethod(
                this, [this, ev, ip, label] { onEgressMalicious(ev, ip, label); },
                Qt::QueuedConnection);
        }
    }
}

void Worker::onEgressMalicious(const bulwark::SecurityEvent& e, const QString& ip, const QString& label) {
    bulwark::SecurityEvent ev = e;
    ev.hasThreatIndicator = true;
    const QString suffix = label.trimmed().isEmpty() ? QString() : (QStringLiteral(" · ") + label);
    const QString msg = QStringLiteral("微步 IP 信誉判定恶意,拦截外联并结束进程:%1 -> %2%3")
                            .arg(ev.actorPath, ip, suffix);
    log_.warning(msg);
    ipc_->sendLog(msg);
    if (ev.riskScore < 85) ev.riskScore = 85;
    ev.riskReasons.append(QStringLiteral("微步 IP 信誉:远端 %1 判定为恶意").arg(ip));
    ipc_->sendBlock(ev);

    // 补偿处置:结束外联进程树(用户态观测源无法在连接前阻断)。关键系统进程由内部安全门槛保护。
    const int pid = ev.originatorPid > 0 ? ev.originatorPid : ev.actorPid;
    if (pid > 4)
        ProcessInspector::terminateProcessTree(pid);

    using namespace bulwark::json;
    QJsonObject o;
    o["timestampUtc"] = dateTimeToIso(QDateTime::currentDateTimeUtc());
    o["type"] = bulwark::eventTypeToString(ev.type);
    o["actorPath"] = ev.actorPath;
    o["actorPid"] = ev.actorPid;
    o["target"] = ev.target;
    o["action"] = QStringLiteral("Block");
    o["source"] = QString::fromUtf8("\xe5\xa8\x81\xe8\x83\x81\xe6\x83\x85\xe6\x8a\xa5"); // 威胁情报
    o["riskScore"] = ev.riskScore;
    o["reasons"] = strListToJson(QStringList{
        QStringLiteral("微步 IP 信誉:远端 %1 判定为恶意%2").arg(ip, suffix) });
    audit_->writeRecord(o);
    recordEvent(ev, VerdictAction::Block, VerdictSource::Heuristic);
}

// 登记到结构化事件历史 + 实时 EventLogEntry(见 Worker.h 说明)。异步补偿处置与用户
// 裁决都经此,拦截记录 / 活动日志才看得到它们。
void Worker::recordEvent(const SecurityEvent& e, VerdictAction action, VerdictSource source) {
    ipc_->sendEventLog(e, action, source);
    if (eventHistory_) {
        bulwark::ipc::EventLogPayload p;
        p.event = e;
        p.action = action;
        p.source = source;
        eventHistory_->add(p);
    }
}

QString Worker::extractRemoteIpv4(const QString& target) {
    const QString t = target.trimmed();
    if (t.isEmpty())
        return QString();
    QString host = t;
    const int colon = host.lastIndexOf(QLatin1Char(':'));
    if (colon > 0 && host.indexOf(QLatin1Char(':')) == colon) // 单个冒号 -> ip:port
        host = host.left(colon);
    // 校验 IPv4 点分(4 段、每段 0-255)。非 IPv4(含 IPv6/域名)返回空。
    const QStringList parts = host.split(QLatin1Char('.'));
    if (parts.size() != 4)
        return QString();
    for (const QString& p : parts) {
        bool ok = false;
        const int n = p.toInt(&ok);
        if (!ok || p.isEmpty() || n < 0 || n > 255)
            return QString();
    }
    return host;
}

bool Worker::isPrivateOrReserved(const QString& ipv4) {
    const QStringList parts = ipv4.split(QLatin1Char('.'));
    if (parts.size() != 4)
        return true;
    int b[4] = { 0, 0, 0, 0 };
    for (int i = 0; i < 4; ++i) {
        bool ok = false;
        b[i] = parts[i].toInt(&ok);
        if (!ok)
            return true;
    }
    // 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 0/8, 100.64/10(CGNAT), 224+(组播/保留)
    if (b[0] == 10) return true;
    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
    if (b[0] == 192 && b[1] == 168) return true;
    if (b[0] == 127) return true;
    if (b[0] == 169 && b[1] == 254) return true;
    if (b[0] == 0) return true;
    if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
    if (b[0] >= 224) return true;
    return false;
}

bool Worker::isDoubleClickLaunch(const bulwark::SecurityEvent& e) const {
    // 用户经资源管理器/桌面双击启动:进程创建 + 父进程为 explorer.exe。
    if (e.type != bulwark::EventType::ProcessCreate)
        return false;
    if (e.parentPath.isEmpty())
        return false;
    return QFileInfo(e.parentPath).fileName().compare(QLatin1String("explorer.exe"), Qt::CaseInsensitive) == 0;
}

bool Worker::isDropperSpawnedPayload(const bulwark::SecurityEvent& e) const {
    // 释放器派生载荷:进程创建 + 未签名 + 本机首见 + 从可疑落地目录运行。
    if (e.type != bulwark::EventType::ProcessCreate)
        return false;
    if (e.actorSigned)
        return false; // 带可信签名的不在此列(降误报)
    if (!e.isFirstSeen)
        return false; // 本机已见过的常规程序不重复打扰
    return bulwark::engine::ThreatDetector::isSuspiciousDropDir(e.actorPath);
}

bool Worker::isRecentlyDroppedExecutable(const bulwark::SecurityEvent& e) {
    // "写出即执行":进程创建 + 未签名 + 该映像最近被(其他进程)写入过。
    if (e.type != bulwark::EventType::ProcessCreate)
        return false;
    if (e.actorSigned)
        return false; // 带签名的更新器/安装器写出并自启属正常
    return chain_.wasRecentlyWritten(e.actorPath, kRecentDropWindowSecs);
}

bool Worker::shouldAiScan(const bulwark::SecurityEvent& e) {
    // 排除自启子进程(进程名=父进程名):explorer 拉起子窗口、浏览器多进程等,非「双击新程序」。
    if (e.type == bulwark::EventType::ProcessCreate && !e.actorPath.isEmpty() && !e.parentPath.isEmpty()) {
        const QString actorName = QFileInfo(e.actorPath).fileName();
        const QString parentName = QFileInfo(e.parentPath).fileName();
        if (!actorName.isEmpty() && actorName.compare(parentName, Qt::CaseInsensitive) == 0)
            return false;
    }
    // 排除 Windows 系统目录里的进程:系统组件本身不送扫,避免签名偶发读失败被误判为可疑。
    if (!e.actorPath.isEmpty()) {
        QString lower = e.actorPath.toLower();
        lower.replace(QLatin1Char('/'), QLatin1Char('\\'));
        if (lower.contains(QLatin1String("\\windows\\system32\\"))
            || lower.contains(QLatin1String("\\windows\\syswow64\\"))
            || lower.contains(QLatin1String("\\windows\\winsxs\\")))
            return false;
        const int slash = lower.lastIndexOf(QLatin1Char('\\'));
        if (slash > 0 && lower.left(slash).endsWith(QLatin1String("\\windows")))
            return false;
    }
    // 已知安全软件 / 强可信 / 健康签名 / 明确安全:直接放行,不重复送扫(降误报、省配额)。
    if (TrustPolicy::isTrustedSecurityProduct(e).ok)
        return false;
    if (TrustPolicy::isStronglyTrusted(e).ok || TrustPolicy::isHealthySigned(e).ok)
        return false;
    if (TrustPolicy::isCleanSigned(e).ok)
        return false;

    return isDoubleClickLaunch(e) || isDropperSpawnedPayload(e) || isRecentlyDroppedExecutable(e);
}

void Worker::maybeScanDoubleClick(const bulwark::SecurityEvent& e) {
    if (!vt_ || !vtRunning_.load())
        return;
    if (!settings_ || !settings_->aiScanDoubleClickEnabled)
        return;
    if (!shouldAiScan(e))
        return;
    const QString key = e.actorHash.isEmpty() ? e.actorPath : e.actorHash;
    if (key.isEmpty())
        return;
    {
        QMutexLocker lk(&vtMx_);
        if (vtInflight_.contains(key))
            return;
        if (vtQueue_.size() >= kVtQueueMax)
            return;
        vtInflight_.insert(key);
        vtQueue_.enqueue(e);
    }
    vtCv_.wakeOne();
}

void Worker::maybeScanInstallerPackage(const bulwark::SecurityEvent& e) {
    // MSI/MSP 双击安装:Windows 实际运行的是签名的 msiexec.exe,安装包(.msi)本身从不作为进程
    // 出现,故普通双击查杀看不到它。这里在用户双击 msiexec 安装时,从命令行取出安装包路径,
    // 直接把「安装包本身」送 VirusTotal 扫描(命中恶意再结束 msiexec 停止安装)。
    if (!vt_ || !vtRunning_.load())
        return;
    if (!settings_ || !settings_->aiScanDoubleClickEnabled)
        return;
    if (e.type != bulwark::EventType::ProcessCreate || e.actorPath.isEmpty())
        return;
    if (QFileInfo(e.actorPath).fileName().compare(QLatin1String("msiexec.exe"), Qt::CaseInsensitive) != 0)
        return;
    if (!isDoubleClickLaunch(e)) // 仅用户双击/命令行触发(父=explorer),排除系统静默安装/更新/卸载
        return;
    const QString pkg = firstInstallerArg(e.commandLine);
    if (pkg.isEmpty() || !QFileInfo::exists(pkg))
        return;

    // 合成事件:主体=安装包(而非 msiexec),PID 沿用 msiexec(命中恶意可结束安装),哈希留空
    // 交由 runVtScan 后台补算。以包路径作在途去重键。
    bulwark::SecurityEvent pkgEvent = e;
    pkgEvent.actorPath = pkg;
    pkgEvent.actorHash.clear();
    pkgEvent.commandLine.clear();
    const QString key = pkg;
    {
        QMutexLocker lk(&vtMx_);
        if (vtInflight_.contains(key))
            return;
        if (vtQueue_.size() >= kVtQueueMax)
            return;
        vtInflight_.insert(key);
        vtQueue_.enqueue(pkgEvent);
    }
    vtCv_.wakeOne();
    log_.info(QStringLiteral("双击安装包送 VirusTotal 扫描:%1").arg(pkg));
}

void Worker::maybeScanDroppedInstaller(const bulwark::SecurityEvent& e) {
    // 落盘即扫:写入「用户可写投放点」的安装包(.msi/.msp)与可执行体(.exe/.scr)一旦出现,
    // 立即送 VT/聚合信誉查(不依赖是否被执行、也不抢 msiexec 命令行)。银狐等以 .msi 投递、双击
    // 跑的是签名 msiexec,常规双击查杀看不到安装包本身 —— 此路在投递落地阶段就兜住。
    if (!vt_ || !vtRunning_.load())
        return;
    if (!settings_ || !settings_->aiScanDoubleClickEnabled)
        return;
    if (e.type != bulwark::EventType::FileWrite || e.target.trimmed().isEmpty())
        return;

    const QString path = e.target;
    QString low = path;
    low.replace(QLatin1Char('/'), QLatin1Char('\\'));
    low = low.toLower();

    const bool isInstaller = low.endsWith(QLatin1String(".msi")) || low.endsWith(QLatin1String(".msp"));
    const bool isExecutable = low.endsWith(QLatin1String(".exe")) || low.endsWith(QLatin1String(".scr"));
    if (!isInstaller && !isExecutable)
        return;

    auto has = [&low](const char* seg) { return low.contains(QLatin1String(seg)); };
    // 安装包在任意用户落地点都扫(高信号、低频)。
    const bool installerZone =
        has("\\downloads\\") || has("\\desktop\\") || has("\\users\\public\\") ||
        has("\\programdata\\") || has("\\appdata\\local\\temp\\") ||
        has("\\appdata\\roaming\\") || has("\\windows\\temp\\");
    // 裸可执行体只在高危投放点扫,避免 AppData 里正常应用频繁写 exe 烧掉 VT 配额。
    const bool exeZone =
        has("\\downloads\\") || has("\\desktop\\") || has("\\users\\public\\") ||
        has("\\appdata\\local\\temp\\") || has("\\windows\\temp\\");
    if (isInstaller ? !installerZone : !exeZone)
        return;

    // 跳过本软件自身目录与隔离区,避免自扫/回环。
    if (has("\\bulwark\\") || has("\\quarantine\\"))
        return;
    if (!QFileInfo::exists(path))
        return;

    // 合成扫描事件:主体 = 被写入的文件本身;PID 清零 —— 落盘文件尚未运行,命中恶意只隔离文件,
    // 绝不结束写入方进程(explorer / 浏览器 / 更新器)。哈希留空,由 runVtScan 后台补算。
    bulwark::SecurityEvent scanEvent;
    scanEvent.type = bulwark::EventType::ProcessCreate; // 复用双击/载荷扫描与恶意处置路径
    scanEvent.actorPath = path;
    scanEvent.actorPid = 0;
    scanEvent.originatorPid = 0;
    scanEvent.timestampUtc = QDateTime::currentDateTimeUtc();

    // 在途去重键须与 runVtScan 内部一致(哈希为空时取 actorPath),否则扫描结束移除不掉、后续无法再扫。
    const QString key = scanEvent.actorPath;
    {
        QMutexLocker lk(&vtMx_);
        if (vtInflight_.contains(key))
            return;
        if (vtQueue_.size() >= kVtQueueMax)
            return;
        vtInflight_.insert(key);
        vtQueue_.enqueue(scanEvent);
    }
    vtCv_.wakeOne();
    log_.info(QStringLiteral("安装包/可执行体落盘送 VirusTotal 扫描:%1").arg(path));
}

void Worker::vtScanLoop() {
    while (vtRunning_.load()) {
        bulwark::SecurityEvent job;
        {
            QMutexLocker lk(&vtMx_);
            while (vtRunning_.load() && vtQueue_.isEmpty())
                vtCv_.wait(&vtMx_);
            if (!vtRunning_.load())
                return;
            job = vtQueue_.dequeue();
        }
        runVtScan(job);
    }
}

void Worker::runVtScan(bulwark::SecurityEvent e) {
    // 入队去重键(在算哈希之前定,与 maybeScan* 入队键一致,才能正确移除在途标记)。
    const QString key = e.actorHash.isEmpty() ? e.actorPath : e.actorHash;
    // 合成的安装包扫描等场景哈希为空:后台补算 SHA-256,以便先走「按哈希查」的省流路径。
    if (e.actorHash.isEmpty() && !e.actorPath.isEmpty() && QFileInfo::exists(e.actorPath))
        e.actorHash = QuarantineManager::tryComputeSha256(e.actorPath);
    const QString hash = e.actorHash;

    // 去重:近期已扫过的哈希复用结论(确定性结论永久去重;未收录 24h 内去重,不重复上传)。
    if (vtHistory_ && !hash.isEmpty()) {
        const std::optional<bulwark::VtScanRecord> prior =
            vtHistory_->tryGetFinishedByHash(hash, kVtUnknownDedupTtlSec);
        if (prior.has_value()) {
            if (prior->outcome == bulwark::VtScanOutcome::Malicious) {
                bulwark::FileReputation rep;
                rep.sha256 = hash;
                rep.verdict = bulwark::ReputationVerdict::Malicious;
                rep.malicious = prior->malicious;
                rep.totalEngines = prior->totalEngines;
                rep.threatLabel = prior->threatLabel;
                rep.querySucceeded = true;
                confirmReputationMaliciousAsync(e, rep); // 后台拉画像后编组回主线程处置
            }
            QMutexLocker lk(&vtMx_);
            vtInflight_.remove(key);
            return; // 命中历史结论 -> 不重复扫
        }
    }

    // 研判期间冻结目标进程(可选;上传+轮询最长数分钟,冻结防其间造成破坏)。
    const bool suspend = settings_ && settings_->aiScanSuspendDuringScan && e.actorPid > 0;
    if (suspend)
        ProcessInspector::trySuspend(e.actorPid);

    bulwark::VtScanRecord record;
    record.id = e.id;
    record.sha256 = hash;
    record.filePath = e.actorPath;
    record.fileName = QFileInfo(e.actorPath).fileName();
    record.source = QStringLiteral("\xe5\x8f\x8c\xe5\x87\xbb"); // 双击
    record.stage = bulwark::VtScanStage::Querying;
    record.message = QStringLiteral("正在查询 VirusTotal 是否已收录…");
    publishVtRecord(record);

    // 1) 先按哈希查(秒级,省去对已收录文件的重复上传)。
    bulwark::FileReputation rep;
    rep.sha256 = hash;
    rep.verdict = bulwark::ReputationVerdict::Unknown;
    if (!hash.isEmpty()) {
        rep = vt_->query(hash, false);
        if (rep.source.isEmpty()) rep.source = QStringLiteral("VirusTotal");
    }
    bool foundByHash = rep.querySucceeded && rep.verdict != bulwark::ReputationVerdict::Unknown;

    // 1b) VirusTotal 未收录 / 查询失败(配额·网络)时,按哈希回退到其他已启用情报源
    //     (MalwareBazaar / OTX / 微步 / MetaDefender / HybridAnalysis),由聚合器合并取最强
    //     结论。这些源只能按哈希查(无法扫描未知文件),故放在昂贵的 VT 上传【之前】:一旦
    //     命中就无需上传;即便 VT 挂了也仍能拿到结论。
    if (!foundByHash && reputation_ && !hash.isEmpty()) {
        record.message = QStringLiteral("VirusTotal 未收录,正在查询其他情报源…");
        publishVtRecord(record);
        const bulwark::FileReputation alt = reputation_->queryNow(hash);
        if (alt.querySucceeded && alt.verdict != bulwark::ReputationVerdict::Unknown) {
            rep = alt;            // 采用回退结论(alt.source 已标注命中源)
            foundByHash = true;
        }
    }

    // 2) 未收录 -> 上传整文件云端多引擎扫描,进度经回调推 UI。
    if (!foundByHash && !e.actorPath.isEmpty() && QFileInfo::exists(e.actorPath)) {
        const auto progress = [this, &record](bulwark::VtScanStage stage, int pct) {
            record.stage = stage;
            record.percent = pct;
            record.uploaded = true;
            if (stage == bulwark::VtScanStage::Uploading)
                record.message = QStringLiteral("正在上传文件… %1%").arg(pct);
            else if (stage == bulwark::VtScanStage::Analyzing)
                record.message = QStringLiteral("已上传,VirusTotal 云端多引擎分析中…");
            else if (stage == bulwark::VtScanStage::Completed)
                record.message = QStringLiteral("分析完成,正在汇总结论…");
            publishVtRecord(record);
        };
        rep = vt_->uploadAndScan(e.actorPath, hash, progress);
        if (rep.source.isEmpty()) rep.source = QStringLiteral("VirusTotal");
        record.uploaded = true;
    }

    finalizeVtRecord(record, rep); // 落终态 + 推 UI + 落历史(去重)

    if (rep.querySucceeded && rep.verdict == bulwark::ReputationVerdict::Malicious) {
        // 恶意 -> 后台拉行为画像后编组回主线程补偿处置(结束进程树 + 隔离载荷 + 清持久化 +
        // 据画像清释放物/注规则);保持冻结不恢复。
        confirmReputationMaliciousAsync(e, rep);
    } else if (suspend) {
        ProcessInspector::tryResume(e.actorPid); // 非恶意 -> 恢复运行
    }

    QMutexLocker lk(&vtMx_);
    vtInflight_.remove(key);
}

void Worker::finalizeVtRecord(bulwark::VtScanRecord& record, const bulwark::FileReputation& rep) {
    record.malicious = rep.malicious;
    record.totalEngines = rep.totalEngines;
    record.threatLabel = rep.threatLabel;
    if (!rep.sha256.isEmpty())
        record.sha256 = rep.sha256;

    if (!rep.querySucceeded) {
        record.stage = bulwark::VtScanStage::Error;
        record.outcome = bulwark::VtScanOutcome::Error;
        record.message = QStringLiteral("VT 查询失败 / 超时(已按放行处理)");
    } else {
        record.stage = bulwark::VtScanStage::Completed;
        record.outcome = rep.verdict == bulwark::ReputationVerdict::Malicious  ? bulwark::VtScanOutcome::Malicious
                       : rep.verdict == bulwark::ReputationVerdict::Suspicious ? bulwark::VtScanOutcome::Suspicious
                       : rep.verdict == bulwark::ReputationVerdict::Clean      ? bulwark::VtScanOutcome::Clean
                                                                               : bulwark::VtScanOutcome::Unknown;
        // 命中来源标注:非 VirusTotal 的回退源附「· 来源 X」;命中型源(无引擎计数)省略 N/M。
        const bool fromVt = rep.source.isEmpty() || rep.source == QStringLiteral("VirusTotal");
        const QString srcSuffix = fromVt ? QString()
                                         : QStringLiteral(" · 来源 ") + rep.source;
        const QString engines = rep.totalEngines > 0
                                    ? QStringLiteral(" · %1/%2").arg(rep.malicious).arg(rep.totalEngines)
                                    : QString();
        if (record.outcome == bulwark::VtScanOutcome::Malicious)
            record.message = QStringLiteral("恶意") + engines
                           + (rep.threatLabel.isEmpty() ? QString() : QStringLiteral(" · ") + rep.threatLabel)
                           + srcSuffix;
        else if (record.outcome == bulwark::VtScanOutcome::Suspicious)
            record.message = QStringLiteral("可疑") + engines + srcSuffix;
        else if (record.outcome == bulwark::VtScanOutcome::Clean)
            record.message = QStringLiteral("干净")
                           + (rep.totalEngines > 0 ? QStringLiteral(" · 0/%1").arg(rep.totalEngines) : QString())
                           + srcSuffix;
        else
            record.message = QStringLiteral("未收录 / 无明确结论");
    }
    publishVtRecord(record);
}

void Worker::publishVtRecord(const bulwark::VtScanRecord& record) {
    bulwark::VtScanRecord r = record;
    r.timestampUtc = QDateTime::currentDateTimeUtc();
    // 仅「终态」记录(Completed/Error)进持久历史:中间进度(Querying/Uploading/Analyzing)
    // 只用于 UI 实时卡片,不落盘——否则服务中途重启/扫描异常会在历史里留下永久「进行中」
    // 幽灵(空文件/空哈希的非终态记录)。历史只保存有结论的那一条。
    if (vtHistory_ && r.isTerminal())
        vtHistory_->upsert(r); // 线程安全(自带锁)
    // 推 UI 必须在主线程(碰 IPC/QLocalSocket)。编组回主线程发送。
    QMetaObject::invokeMethod(
        this, [this, r] { ipc_->sendVtScanUpdate(r); }, Qt::QueuedConnection);
}

void Worker::writeAudit(const SecurityEvent& e, VerdictAction action, VerdictSource source) {
    using namespace bulwark::json;
    QJsonObject o;
    o["timestampUtc"] = dateTimeToIso(QDateTime::currentDateTimeUtc());
    o["type"] = bulwark::eventTypeToString(e.type);
    o["actorPath"] = e.actorPath;
    o["actorPid"] = e.actorPid;
    o["target"] = e.target;
    o["riskScore"] = e.riskScore;
    o["action"] = bulwark::verdictActionToString(action);
    o["source"] = bulwark::verdictSourceToString(source);
    // 命中的规则说明(可空):此前审计只记 source=Rule 却不记「是哪条规则」,导致规则命中不可追溯、
    // 让人误以为规则没生效。落盘规则名后,事后可直接查「被 [情报-行为]xxx / 未签名可疑目录 等拦/放」。
    if (!e.matchedRuleNote.isEmpty())
        o["matchedRule"] = e.matchedRuleNote;
    o["reasons"] = strListToJson(e.riskReasons);
    audit_->writeRecord(o);
}

} // namespace bulwark::service
