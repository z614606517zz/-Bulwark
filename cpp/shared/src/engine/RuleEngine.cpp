#include "bulwark/engine/RuleEngine.h"
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/engine/DgaDomainAnalyzer.h"
#include "bulwark/engine/AttackAnnotator.h"
#include "bulwark/engine/DefaultRules.h"
#include <QStringList>
#include <algorithm>

namespace bulwark::engine {

using detail::u;
using detail::fileNameLower;

namespace {
// 本软件自身组件进程映像名(小写)。须与 CMake 构建产物名(下划线)一致——早期沿用
// .NET 程序集名(点号 bulwark.service.exe)导致永不匹配真实的 bulwark_service.exe,自身
// 组件放行形同虚设。按名匹配可被同名程序冒用,故仅作快速通道,真正的稳妥判定靠安装目录
// 前缀(addSelfDirectory,由服务在启动时登记 applicationDirPath)。
const QSet<QString>& selfImageNames() {
    static const QSet<QString> s = {
        "bulwark_service.exe", "bulwark_ui.exe",
    };
    return s;
}
} // namespace

void RuleEngine::addSelfDirectory(const QString& dir) {
    if (dir.trimmed().isEmpty()) return;
    QString norm = dir.trimmed().toLower();
    norm.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!norm.endsWith(QLatin1Char('\\'))) norm += QLatin1Char('\\');
    QMutexLocker locker(&selfDirLock_);
    selfDirectories_.insert(norm);
}

bool RuleEngine::matchesSelf(const QString& path) const {
    if (path.isEmpty()) return false;
    const QString name = fileNameLower(path);
    if (!name.isEmpty() && selfImageNames().contains(name)) return true;

    QMutexLocker locker(&selfDirLock_);
    if (!selfDirectories_.isEmpty()) {
        QString pathLower = path.toLower();
        pathLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
        for (const QString& d : selfDirectories_)
            if (pathLower.startsWith(d)) return true;
    }
    return false;
}

bool RuleEngine::isSelfComponent(const SecurityEvent& e) const {
    return matchesSelf(e.actorPath) || matchesSelf(e.parentPath);
}

std::optional<QString> RuleEngine::matchedUserTrust(const SecurityEvent& e) const {
    QReadLocker locker(&rulesLock_);
    for (auto it = rules_.constBegin(); it != rules_.constEnd(); ++it) {
        const DefenseRule& r = it.value();
        // 仅「文件信任中心」生成的 Allow 信任项(文件精确 actorPath 或目录通配 actorPattern)。
        if (r.action == VerdictAction::Allow && r.isTrustEntry() && r.matches(e))
            return r.note.isEmpty() ? QStringLiteral("用户信任") : r.note;
    }
    return std::nullopt;
}

int RuleEngine::ruleTier(const DefenseRule& r) {
    const bool exactActor = !r.actorPath.isEmpty() || !r.actorHashes.isEmpty();
    if (exactActor) return 2;
    if (r.hardOverride) return 1;
    return 0;
}

int RuleEngine::rulePriority(VerdictAction a) {
    switch (a) {
        case VerdictAction::Block: return 2;
        case VerdictAction::Ask:   return 1;
        default:                   return 0;
    }
}

void RuleEngine::loadRules(const QVector<DefenseRule>& rules) {
    QHash<QUuid, DefenseRule> fresh;
    for (const DefenseRule& r : rules) fresh.insert(r.id, r);
    QWriteLocker locker(&rulesLock_);
    rules_ = std::move(fresh);
}

QVector<DefenseRule> RuleEngine::getRules() const {
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QReadLocker locker(&rulesLock_);
    QVector<DefenseRule> out;
    out.reserve(rules_.size());
    for (auto it = rules_.constBegin(); it != rules_.constEnd(); ++it)
        if (!it.value().isExpired(now)) out.append(it.value());
    return out;
}

int RuleEngine::pruneExpired() {
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QWriteLocker locker(&rulesLock_);
    int removed = 0;
    for (auto it = rules_.begin(); it != rules_.end(); ) {
        if (it.value().isExpired(now)) { it = rules_.erase(it); ++removed; }
        else ++it;
    }
    return removed;
}

void RuleEngine::addRule(const DefenseRule& rule) {
    QWriteLocker locker(&rulesLock_);
    rules_.insert(rule.id, rule);
}

bool RuleEngine::removeRule(const QUuid& id) {
    QWriteLocker locker(&rulesLock_);
    return static_cast<bool>(rules_.remove(id));
}

void RuleEngine::appendDecisionEvidence(SecurityEvent& e, const Verdict& v) {
    QString action;
    switch (v.action) {
        case VerdictAction::Block: action = u("阻止"); break;
        case VerdictAction::Ask:   action = u("询问用户"); break;
        default:                   action = u("放行"); break;
    }
    QString source;
    switch (v.source) {
        case VerdictSource::Rule:          source = u("命中规则"); break;
        case VerdictSource::Heuristic:     source = u("行为研判"); break;
        case VerdictSource::TrustedSigner: source = u("可信放行"); break;
        case VerdictSource::UserPrompt:    source = u("用户裁决"); break;
        case VerdictSource::Timeout:       source = u("超时按默认策略"); break;
        default:                           source = u("默认策略"); break;
    }
    e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Decision,
        u("最终裁决:") + action + u("(依据:") + source + u(";风险分 ") +
        QString::number(e.riskScore) + u(")"), 0, false);
}

Verdict RuleEngine::evaluate(SecurityEvent& e) {
    const Verdict verdict = evaluateInternal(e);
    appendDecisionEvidence(e, verdict);
    AttackAnnotator::annotate(e);
    return verdict;
}

DefenseRule RuleEngine::createRuleFrom(SecurityEvent& e, VerdictAction action,
                                       std::optional<QDateTime> expiresUtc, bool sessionOnly) {
    DefenseRule rule;
    rule.actorPath = e.actorPath;
    rule.type = e.type;
    rule.targetPattern = e.target.isEmpty() ? QString() : e.target;
    rule.action = action;
    rule.expiresUtc = expiresUtc;
    rule.sessionOnly = sessionOnly;
    addRule(rule);
    return rule;
}

Verdict RuleEngine::evaluateInternal(SecurityEvent& e) {
    // 1) 无条件放行通道(放在最前,早于威胁检测与勒索/信标等时序早退):
    //    a. 本软件自身组件;b. 用户明确信任的文件/文件夹。用户信任即「完全跳过一切检测」——
    //    即便命中勒索蜜罐/硬指标也不处置,因为这是用户明确的白名单选择。
    if (isSelfComponent(e)) {
        e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Trust, u("本软件自身组件,无条件放行"), 0, false);
        return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
    }
    if (const std::optional<QString> trustNote = matchedUserTrust(e)) {
        e.userTrusted = true; // 通知 Worker 跳过全部后台扫描(VT/IP/AI)
        e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Trust,
                      u("用户信任放行,已跳过全部检测:") + *trustNote, 0, false);
        return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::Rule);
    }

    // 2) 已安装的知名安全软件:共存放行
    {
        const TrustDecision sec = TrustPolicy::isTrustedSecurityProduct(e);
        if (sec.ok) {
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, sec.reason, 0, false);
            return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
        }
    }

    // 3) 威胁检测,填充 RiskScore / 硬指标
    ThreatDetector::analyze(e);

    // 4) 有状态时序检测:勒索批量改写 / C2 信标 / 外联速率
    if (e.type == EventType::FileWrite || e.type == EventType::FileDelete) {
        const RansomwareBehaviorMonitor::Result rm = ransomware_.observe(e);
        if (rm.score > 0) {
            e.riskScore = qMin(100, e.riskScore + rm.score);
            bool first = true;
            for (const QString& r : rm.reasons) {
                e.addEvidence(QStringLiteral("RansomwareBehaviorMonitor"),
                    (rm.canaryHit || rm.hardSignal) ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                    r, first ? rm.score : 0);
                first = false;
            }
            if (rm.canaryHit) {
                e.hasThreatIndicator = true;
                return Verdict::forEvent(e, VerdictAction::Block, VerdictSource::Heuristic);
            }
            const bool trustedActor =
                TrustPolicy::isStronglyTrusted(e).ok ||
                TrustPolicy::isHealthySigned(e).ok ||
                (e.actorSigned && TrustPolicy::isBenignSigner(e).ok);
            if (rm.hardSignal) {
                if (trustedActor) {
                    e.addEvidence(QStringLiteral("RansomwareBehaviorMonitor"), EvidenceKind::Trust,
                        u("主体签名健康,勒索行为特征按误报抑制(未触蜜罐诱饵)"), 0, false);
                } else {
                    e.hasThreatIndicator = true;
                    if (rm.score >= ThreatDetector::Suspicious)
                        return Verdict::forEvent(e, VerdictAction::Block, VerdictSource::Heuristic);
                }
            } else {
                if (!trustedActor) {
                    e.hasThreatIndicator = true;
                    if (rm.score >= ThreatDetector::Suspicious)
                        return Verdict::forEvent(e, VerdictAction::Ask, VerdictSource::Heuristic);
                }
            }
        }
    }
    else if (e.type == EventType::NetworkConnect) {
        const ScoreResult b = beacon_.observe(e);
        const bool beaconHit = b.score > 0;
        if (beaconHit) {
            e.riskScore = qMin(100, e.riskScore + b.score);
            bool first = true;
            for (const QString& r : b.reasons) {
                e.addEvidence(QStringLiteral("BeaconDetector"), EvidenceKind::HardIndicator, r, first ? b.score : 0);
                first = false;
            }
            e.hasThreatIndicator = true;
        }
        const ScoreResult d = DgaDomainAnalyzer::analyze(e.target);
        const bool dgaSuspicious = d.score >= 40;
        if (d.score > 0) {
            e.riskScore = qMin(100, e.riskScore + d.score);
            const bool corroborated = beaconHit || (!e.actorSigned && dgaSuspicious);
            bool first = true;
            for (const QString& r : d.reasons) {
                e.addEvidence(QStringLiteral("DgaDomainAnalyzer"),
                    corroborated ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal, r, first ? d.score : 0);
                first = false;
            }
            if (corroborated) {
                e.hasThreatIndicator = true;
                e.addEvidence(QStringLiteral("DgaDomainAnalyzer"), EvidenceKind::Corroboration,
                    u("DGA 随机域名与其它恶意指标互证(升格为硬指标)"), 0, false);
            }
        }
        const ScoreResult eg = egress_.observe(e);
        if (eg.score > 0) {
            e.riskScore = qMin(100, e.riskScore + eg.score);
            const bool corroborated = beaconHit || dgaSuspicious || !e.actorSigned;
            const bool escalated = corroborated && eg.score >= 50;
            bool first = true;
            for (const QString& r : eg.reasons) {
                e.addEvidence(QStringLiteral("EgressRateMonitor"),
                    escalated ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal, r, first ? eg.score : 0);
                first = false;
            }
            if (escalated) {
                e.hasThreatIndicator = true;
                e.addEvidence(QStringLiteral("EgressRateMonitor"), EvidenceKind::Corroboration,
                    u("异常外联速率/扇出与其它恶意指标互证(升格为硬指标)"), 0, false);
            }
        }
    }
    else if (e.type == EventType::DnsQuery) {
        const ScoreResult d = DgaDomainAnalyzer::analyze(e.target);
        if (d.score > 0) {
            e.riskScore = qMin(100, e.riskScore + d.score);
            bool first = true;
            for (const QString& r : d.reasons) {
                e.addEvidence(QStringLiteral("DgaDomainAnalyzer"), EvidenceKind::SoftSignal, r, first ? d.score : 0);
                first = false;
            }
        }
    }

    // 5) 行为基线偏离(软信号,仅互证升格)
    if (enableBaseline) {
        const BaselineAnalyzer::Result bl = baseline_.observe(e);
        if (bl.score > 0 && bl.deviation) {
            e.riskScore = qMin(100, e.riskScore + bl.score);
            const bool corroborated = e.hasThreatIndicator;
            bool first = true;
            for (const QString& r : bl.reasons) {
                e.addEvidence(QStringLiteral("BaselineAnalyzer"),
                    corroborated ? EvidenceKind::Corroboration : EvidenceKind::SoftSignal, r, first ? bl.score : 0);
                first = false;
            }
            if (corroborated)
                e.addEvidence(QStringLiteral("BaselineAnalyzer"), EvidenceKind::Corroboration,
                    u("行为偏离自身历史基线,与其它恶意指标互证"), 0, false);
        }
    }

    // 6) 显式规则优先(层级 > 具体度 > 动作强度 > 最近创建)
    {
        QVector<DefenseRule> matches;
        {
            QReadLocker locker(&rulesLock_);
            for (auto it = rules_.constBegin(); it != rules_.constEnd(); ++it)
                if (it.value().matches(e)) matches.append(it.value());
        }
        if (!matches.isEmpty()) {
            std::sort(matches.begin(), matches.end(), [](const DefenseRule& a, const DefenseRule& b) {
                const int ta = ruleTier(a), tb = ruleTier(b);
                if (ta != tb) return ta > tb;
                const int sa = specificity(a), sb = specificity(b);
                if (sa != sb) return sa > sb;
                const int pa = rulePriority(a.action), pb = rulePriority(b.action);
                if (pa != pb) return pa > pb;
                return a.createdUtc > b.createdUtc;
            });
            const DefenseRule hit = matches.first();

            if (hit.exemptTrustedOsComponent && hit.action != VerdictAction::Block) {
                const TrustDecision os = TrustPolicy::isTrustedOsComponent(e);
                if (os.ok) {
                    e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, os.reason);
                    return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
                }
            }
            if (hit.action == VerdictAction::Ask && DefaultRules::isDevTool(e.actorPath)) {
                e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Trust, u("开发工具自动放行(白名单)"));
                return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
            }
            e.matchedRuleNote = hit.note;
            const QString actionName = hit.action == VerdictAction::Block ? QStringLiteral("Block")
                                     : hit.action == VerdictAction::Ask ? QStringLiteral("Ask")
                                     : QStringLiteral("Allow");
            e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Rule,
                u("命中规则:") + (hit.note.isEmpty() ? actionName : hit.note), 0, false);
            return Verdict::forEvent(e, hit.action, VerdictSource::Rule);
        }
    }

    // 7) 强可信主体直接放行(唯一跳过行为检测的通道)
    if (trustSignedActors) {
        const TrustDecision t = TrustPolicy::isStronglyTrusted(e);
        if (t.ok) {
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, t.reason);
            return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
        }
    }

    // 8) 签名异常(吊销 / 过期后签名)-> Block
    if (e.certRevoked || e.signedAfterCertExpiry)
        return Verdict::forEvent(e, VerdictAction::Block, VerdictSource::Heuristic);

    // 9) 健康签名直接放行
    if (trustSignedActors) {
        const TrustDecision h = TrustPolicy::isHealthySigned(e);
        if (h.ok) {
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, h.reason);
            return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
        }
    }

    // 10) 仅当存在硬恶意指标才处置:高危拦截,其余询问
    if (e.hasThreatIndicator) {
        return e.riskScore >= ThreatDetector::HighRisk
            ? Verdict::forEvent(e, VerdictAction::Block, VerdictSource::Heuristic)
            : Verdict::forEvent(e, VerdictAction::Ask, VerdictSource::Heuristic);
    }

    // 11) 无硬指标:一律放行(仅记录)
    if (e.actorSigned) {
        const TrustDecision bn = TrustPolicy::isBenignSigner(e);
        if (bn.ok)
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, bn.reason);
        else if (e.riskScore > 0)
            e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Info, u("无恶意行为特征(默认放行)"));
    } else if (e.riskScore > 0) {
        e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Info, u("无恶意行为特征(默认放行)"));
    }

    return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::DefaultPolicy);
}

} // namespace bulwark::engine
