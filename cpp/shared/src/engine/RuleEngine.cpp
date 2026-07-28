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

std::optional<QString> RuleEngine::trustNoteForPath(const QString& path) const {
    QString p = path.trimmed();
    if (p.isEmpty()) return std::nullopt;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));

    // 占位符路径:内核源在解析不出映像时会填 "PID 1234"(见 Worker::blacklistExec 的同名护栏)。
    // 这种事件无法判定主体身份 —— 宁可不豁免,绝不能因为一个占位符把真实的恶意处置放过去。
    if (p.startsWith(QLatin1String("PID "), Qt::CaseInsensitive)) return std::nullopt;

    // 本软件自身组件:任何情况下都不该被自己的内核名单钉死(否则一次误判即自锁,且跨重启)。
    if (matchesSelf(p)) return QStringLiteral("本软件自身组件");

    const QDateTime now = QDateTime::currentDateTimeUtc();
    QReadLocker locker(&rulesLock_);
    for (auto it = rules_.constBegin(); it != rules_.constEnd(); ++it) {
        const DefenseRule& r = it.value();
        if (r.action != VerdictAction::Allow || !r.enabled || r.isExpired(now) || !r.isTrustEntry())
            continue;
        // 文件信任 = actorPath 精确(大小写不敏感);目录信任 = actorPattern 通配("<目录>\*")。
        const bool hitFile = !r.actorPath.isEmpty() && r.actorPath.compare(p, Qt::CaseInsensitive) == 0;
        const bool hitDir  = !r.actorPattern.isEmpty() && DefenseRule::wildcardMatch(r.actorPattern, p);
        if (hitFile || hitDir)
            return r.note.isEmpty() ? QStringLiteral("用户信任") : r.note;
    }
    return std::nullopt;
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

    // 2b) 已知良性厂商应用(QQ/微信/企业微信/TIM 等即时通讯):正常存在大量周期性心跳保活外联,
    //     极易被信标检测 / 微步 IP 情报 / ThreatFox IP 规则误判为 C2 回连而被结束进程。要求持有
    //     健康的厂商签名(防同名冒充)后,对【外联与 DNS 事件】在时序检测与规则匹配之前放行,并置
    //     userTrusted 让 Worker 跳过该事件的后台情报查询,避免正常保活被情报链路误伤。
    //
    //     【作用域必须锁死在网络维度】此前这里对【全部事件类型】早返回 Allow,后果是这五个映像名
    //     一旦签名健康,它们作为主体的任何行为都不再经过 ThreatDetector、也不再匹配规则 —— 于是
    //     专门为「银狐」IM 群控加的那批规则(wxhook / WeChatSDK / vchat 等具名 hook 模块【被加载】、
    //     向 IM 安装目录植入接口 DLL)全部失效,DLL 侧载检测(可写目录加载未签名模块)同样失效:
    //     攻击者只要把合法签名的 WeChat.exe 连同恶意 DLL 一起投递,主体就是「签名健康的微信」。
    //     误报本来只出在「周期性外联被判 C2」这一处,不该用全维度豁免去换。
    //
    //     残留风险(已知、有意保留):这类主体的外联本身仍被放行,故被侧载的 IM 宿主可以维持 C2
    //     通道。要收掉这一条需要模块级(而非进程级)的外联归因,不在本次改动范围内;但投递阶段的
    //     落地、加载、注入、持久化现在都会被正常检测到。
    if (e.type == EventType::NetworkConnect || e.type == EventType::DnsQuery) {
        const TrustDecision app = TrustPolicy::isTrustedVendorApp(e);
        if (app.ok) {
            e.userTrusted = true; // 仅跳过本条外联/DNS 事件的后台情报查询(微步 IP / 哈希信誉)
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust,
                          app.reason + u("(仅外联/DNS 维度)"), 0, false);
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
        // 信标检测分两档(见 BeaconDetector):CV ≤ kCvRegular 记 55 分(抖动极低,几乎只有程序化
        // 回连才有这种规律),CV ≤ kCvSemiRegular 记 35 分(「近周期性」)。原先两档都无条件置硬指标,
        // 但「近周期性」这一档对正常软件的定时轮询几乎必然误报 —— 代理客户端拉订阅、更新器查版本、
        // 云盘同步全是几分钟一次的准周期外联(实测 clash-win64 每 ≈160s 拉一次订阅即被判 C2 回连)。
        // 故只把低抖动高置信档当硬指标,近周期档降为软信号交互证升格。
        const bool beaconHard = b.score >= 55;
        if (beaconHit) {
            e.riskScore = qMin(100, e.riskScore + b.score);
            bool first = true;
            for (const QString& r : b.reasons) {
                e.addEvidence(QStringLiteral("BeaconDetector"),
                              beaconHard ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                              r, first ? b.score : 0);
                first = false;
            }
            if (beaconHard) e.hasThreatIndicator = true;
        }
        const ScoreResult d = DgaDomainAnalyzer::analyze(e.target);
        const bool dgaSuspicious = d.score >= 40;
        if (d.score > 0) {
            e.riskScore = qMin(100, e.riskScore + d.score);
            // 互证条件里原先含 `!e.actorSigned` —— 用「未签名」这个【软信号】去升格另一个软信号,
            // 与本项目「软信号只加分、需与硬指标互证」的原则相冲突,实际效果是「任何未签名程序连
            // 一个随机域名就定罪」。改为只认高置信信标档。
            const bool corroborated = beaconHard;
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
            // 同上:原先 `|| !e.actorSigned` 让「未签名」单独就能把外联速率/扇出升格成硬指标。
            // 代理 / VPN / P2P / BT 客户端天然向大量节点扇出(实测 UniClashCore「10 秒内连向 38 个
            // 不同目标」被判横移扫描,14 次误报),而它们恰恰常常没有签名 —— 这条互证等于没有互证。
            const bool corroborated = beaconHard || dgaSuspicious;
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

            // 强可信 OS 组件豁免。原先这里排除了 Block 规则(`hit.action != Block`),导致三条
            // 显式标了 exemptTrustedOsComponent 的规则里有两条(WDAC 的 SiPolicy.p7b /
            // CiPolicies\Active\*)的豁免意图从未生效 —— Windows 自己部署 WDAC 策略照样被拦。
            // 现在对 Block 规则同样尊重该标记,但**只**认 isTrustedOsComponent,它本身已经很严:
            //   · e.hasThreatIndicator 为真 -> 不豁免(硬指标永远压过豁免);
            //   · 主体是 LOLBin / 脚本宿主(powershell/rundll32/mshta…)-> 不豁免;
            //   · 还必须通过 isStronglyTrusted(微软签名 + 系统目录 + 无危险命令行 + 无异常父子链)。
            // 因此只有「签名健康的系统自身组件在做它本职的敏感操作」才会被放行;未签名注入方、
            // 落在 Temp 的同名程序、带危险命令行的主体一律照旧拦截。该标记仅由内置规则显式设置,
            // 用户规则默认为 false,不受影响。
            if (hit.exemptTrustedOsComponent) {
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
