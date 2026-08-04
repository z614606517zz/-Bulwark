#include "bulwark/service/Worker.h"
#include "bulwark/service/IpcServer.h"
#include "bulwark/service/EventSource.h"
#include "bulwark/service/RuleStore.h"
#include "bulwark/service/AuditLog.h"
#include "bulwark/service/FirstSeenStore.h"
#include "bulwark/service/QuarantineManager.h"
#include "bulwark/service/ThreatRemediator.h"
#include "bulwark/service/EventHistoryStore.h"
#include "bulwark/service/AlertExporter.h"
#include "bulwark/service/AttackChainEngine.h"
#include "bulwark/service/reputation/ReputationManager.h"
#include "bulwark/service/reputation/ThreatBookClient.h"
#include "bulwark/service/reputation/VirusTotalClient.h"
#include "bulwark/service/reputation/ProxyReputationService.h"
#include "bulwark/service/reputation/AggregateReputationService.h"
#include "bulwark/service/VtScanHistoryStore.h"
#include "bulwark/service/ThreatIntelContribStore.h"
#include "bulwark/service/monitoring/ProcessInspector.h"
#include "bulwark/service/monitoring/ProcessOriginResolver.h"
#include "bulwark/service/ServiceControlTracer.h"
// 「这个 IP 能不能整段封禁」的统一判定,与 ThreatFoxFeed 共用同一份名单。
#include "bulwark/service/IpBlockPolicy.h"
#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/engine/AiDecisionPolicy.h"

#include "bulwark/json/JsonSupport.h"

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QJsonObject>
#include <QMutexLocker>

#include <optional>
#include <thread>
#include <chrono>
namespace bulwark::service {
using bulwark::VerdictAction;
using bulwark::VerdictSource;
using bulwark::SecurityEvent;
using bulwark::service::monitoring::ProcessInspector;
using bulwark::service::monitoring::ProcessOrigin;
using bulwark::service::monitoring::ProcessOriginResolver;
using bulwark::engine::TrustPolicy;

namespace {
// 网络 IP 情报互证参数(与 .NET Worker 常量一致)。
constexpr int    kNetworkIntelMinScore = 40;                     // 低于此分且无硬指标的外联不查
constexpr qint64 kIpIntelCacheTtlMs    = 7LL * 24 * 3600 * 1000; // IP 情报 7 天强缓存(护极低月配额)
constexpr int    kIpQueueMax           = 64;                     // 后台 IP 查询队列上限
constexpr int    kVtQueueMax           = 64;                     // 后台 VT 扫描队列上限
constexpr int    kVtWorkerThreads      = 4;                      // 后台 VT 扫描线程池大小(并行处理,避免长耗时上传阻塞其它文件的查询状态推送)
constexpr int    kRecentDropWindowSecs = 5 * 60;                 // "写出即执行"关联时间窗
constexpr qint64 kVtUnknownDedupTtlSec = 24LL * 3600;            // 未收录/无结论去重窗(24h)
// 待用户裁决事件的上限。超出时按默认策略收尾最旧的一条(而不是静默丢弃)——
// 丢弃会让内核阻塞类事件永远收不到回写,也会让该事件既不出现在拦截记录也不出现在活动日志里。
constexpr int    kMaxPendingPrompts    = 512;

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
    //
    // 两道闸,与下面域名分支的口径一致(域名分支一直有,IP 分支原先两道都缺 —— 见
    // isUnsafeToBlanketBlockIp 的说明,那是「装了防护后一堆软件打不开/登不上」的主因):
    //   · 共享基础设施 / 非公网 / 畸形地址一律不收;
    //   · 条数设上限,单个样本连了几百个地址时不至于把规则库灌满(规则库是定长预算,
    //     被垃圾条目占满会挤掉真正有价值的规则)。
    constexpr int kMaxIpRules = 50;
    int ipRules = 0;
    for (const QString& ioc : p.contactedIps) {
        if (ipRules >= kMaxIpRules) break;
        QString ipOnly = ioc.trimmed();
        const int c = ipOnly.lastIndexOf(QLatin1Char(':'));
        if (c > 0) {
            bool ok = false;
            ipOnly.mid(c + 1).toInt(&ok);
            if (ok) ipOnly = ipOnly.left(c); // 去掉端口,按整 IP 拦
        }
        if (ipOnly.isEmpty()) continue;
        if (isUnsafeToBlanketBlockIp(ipOnly)) continue;
        bulwark::DefenseRule r;
        r.type = bulwark::EventType::NetworkConnect;
        r.targetPattern = ipOnly + QStringLiteral(":*");
        r.action = VerdictAction::Block;
        r.note = tag + QStringLiteral(" 已知 C2 外联地址,禁止外联:") + ipOnly;
        rules.append(r);
        ++ipRules;
    }
    // 2b) C2 外联域名 -> 禁止 DNS 解析/连接(优先级高,拦截在 DNS 阶段,IP 未解析就阻断)。
    // 限制数量避免误报,只收录有明确恶意指向的域名(最多 50 条)。
    int domainRules = 0;
    for (const QString& domain : p.contactedDomains) {
        if (domainRules >= 50) break;
        const QString d = domain.trimmed().toLower();
        if (d.isEmpty() || d.size() < 4) continue; // 过滤过短/空域名
        // 排除常见合法域名(避免误拦 CDN/云服务),只拦明确恶意的域名
        if (d.contains(QLatin1String("microsoft")) || d.contains(QLatin1String("windows"))
            || d.contains(QLatin1String("google")) || d.contains(QLatin1String("amazon"))
            || d.contains(QLatin1String("cloudflare")) || d.contains(QLatin1String("akamai")))
            continue;
        bulwark::DefenseRule r;
        r.type = bulwark::EventType::DnsQuery; // 拦截 DNS 查询
        r.targetPattern = d;
        r.action = VerdictAction::Block;
        r.note = tag + QStringLiteral(" 已知 C2 域名,禁止解析:") + d;
        rules.append(r);
        ++domainRules;
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
    // 4) 注册表持久化键 -> 禁止写入(阻止恶意软件重建自启动/劫持项)。
    // 限制 30 条,过滤过短键名(避免误拦正常软件),优先拦截高危持久化点。
    int regRules = 0;
    for (const QString& regKey : p.registryKeysSet) {
        if (regRules >= 30) break;
        const QString key = regKey.trimmed();
        if (key.size() < 15) continue; // 过滤过短键名
        // 排除系统关键路径（避免误拦）
        if (key.contains(QLatin1String("\\Windows\\"), Qt::CaseInsensitive) ||
            key.contains(QLatin1String("\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), Qt::CaseInsensitive))
            continue;
        bulwark::DefenseRule r;
        r.type = bulwark::EventType::RegistryWrite;
        r.targetPattern = key;
        r.action = VerdictAction::Block;
        r.note = tag + QStringLiteral(" 已知恶意注册表持久化,禁止写入:") + key;
        rules.append(r);
        ++regRules;
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
      firstSeen_(firstSeen), quarantine_(quarantine), reputation_(reputation), settings_(settings),
      memVtBucket_(4, 3600000) { // 内存防护 VT 验证限流桶:默认 4/小时(由 BulwarkOptions.MemoryProtectionVtVerifyPerHour 配置)
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

    // 弹窗超时巡检:1s 粒度足够(超时本身是秒级配置),且空 pending_ 时开销可忽略。
    // 用定时器而不是给每条事件各起一个 QTimer —— 后者在事件突发时会造成大量定时器对象。
    promptTimer_ = new QTimer(this);
    promptTimer_->setInterval(1000);
    connect(promptTimer_, &QTimer::timeout, this, &Worker::onPromptTimeoutTick);
    promptTimer_->start();
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
    for (std::thread& t : vtWorkers_)
        if (t.joinable())
            t.join();
    // 兜底扫描线程:置停后 join(循环以 1s 步进检查 sweepRunning_,最多等 ~1s)。
    sweepRunning_.store(false);
    if (sweepWorker_.joinable())
        sweepWorker_.join();
}

void Worker::setIpIntel(reputation::ThreatBookClient* tb) {
    ipIntel_ = tb;
    if (ipIntel_ && !ipRunning_.exchange(true))
        ipWorker_ = std::thread([this] { ipConsumeLoop(); });
}

void Worker::setVtScan(reputation::VirusTotalClient* vt, VtScanHistoryStore* history) {
    vt_ = vt;
    vtHistory_ = history;
    // 起一个小线程池并行跑扫描:一个未收录文件的「上传 + 轮询」最长约 4 分钟,单线程时会把
    // 后续双击文件全堵在队列里,导致「VT 查询中」状态数分钟后才出现。多线程后长上传不再独占
    // worker,新双击文件能被空闲线程立刻取走并立即推送「查询中」状态(共享限流/配额/历史/IPC
    // 均已各自加锁或编组回主线程,可安全并发)。
    if (vt_ && !vtRunning_.exchange(true)) {
        vtWorkers_.reserve(kVtWorkerThreads);
        for (int i = 0; i < kVtWorkerThreads; ++i)
            vtWorkers_.emplace_back([this] { vtScanLoop(); });
        log_.info(QStringLiteral("双击/释放载荷病毒扫描 worker 已启动(%1 个后台线程)。").arg(kVtWorkerThreads));
    } else if (!vt_) {
        log_.warning(QStringLiteral("双击/释放载荷病毒扫描未启动:VT 客户端为空。"));
    }
}

void Worker::setCloudScanChain(reputation::ProxyReputationService* proxy,
                               reputation::AggregateReputationService* aggregate) {
    repProxy_ = proxy;
    repAggregate_ = aggregate;
    log_.info(QStringLiteral("云扫描分级链路:本地缓存 -> %1 -> VirusTotal -> %2 -> 上传扫描%3。")
                  .arg(proxy ? QStringLiteral("中央服务器") : QStringLiteral("(无中央服务器)"),
                       aggregate ? QStringLiteral("其他情报源") : QStringLiteral("(无其他源)"),
                       proxy ? QStringLiteral(";新结论回传服务器") : QString()));
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

// 零风险放行的文本日志折叠。设计与「为什么必须折叠」见 Worker.h 的 allowBursts_ 段说明。
bool Worker::shouldLogAllow(const SecurityEvent& e, VerdictAction action, QString* summaryOut) {
    // 任意一项带调查信号即照常整条记录 —— 折叠的前提是「这条事件完全无话可说」。
    if (action != VerdictAction::Allow) return true;
    if (e.riskScore != 0) return true;
    if (e.hasThreatIndicator) return true;
    if (!e.matchedRuleNote.isEmpty()) return true;

    // 键 = 主体 + 事件类型。刻意【不含 target】:刷屏的正是同一主体对成千上万个不同临时
    // 文件做同一件事(swapfs-10031/10032/...),把 target 计入键等于永远都是「首见」,折叠失效。
    const QString key = e.actorPath.toLower() + QStringLiteral("|")
                      + QString::number(static_cast<int>(e.type));
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();

    // 有界:主体种类爆炸时整表清空,不做 LRU。清空的唯一后果是下一条重新算「首见」而多打
    // 一行日志 —— 偏向「多记」而不是「漏记」。
    if (allowBursts_.size() > kAllowFoldMaxKeys && !allowBursts_.contains(key))
        allowBursts_.clear();

    auto it = allowBursts_.find(key);
    if (it == allowBursts_.end()) {
        AllowBurst b;
        b.firstMs = nowMs;
        allowBursts_.insert(key, b);
        return true;                    // 首见:整条记录
    }

    AllowBurst& b = it.value();
    if (nowMs - b.firstMs >= kAllowFoldWindowMs) {
        // 窗口到期:先把这一窗折叠掉的条数汇总,再以本条作为新窗口的首条整条记录。
        if (b.folded > 0 && summaryOut) {
            // 中文一律走 UTF-8 转义 + fromUtf8,与 describe() 同口径:不依赖源文件编码,
            // 也不依赖 MSVC 对 u"" 拼接窄字面量的实现定义转码行为。
            *summaryOut = QString::fromUtf8("[%1] \xe5\xb7\xb2\xe6\x8a\x98\xe5\x8f\xa0 %2 "
                                            "\xe6\x9d\xa1\xe5\x90\x8c\xe7\xb1\xbb\xe9\x9b\xb6"
                                            "\xe9\xa3\x8e\xe9\x99\xa9\xe6\x94\xbe\xe8\xa1\x8c"
                                            "(%3 %4)\xef\xbc\x8c\xe7\xaa\x97\xe5\x8f\xa3 %5 "
                                            "\xe7\xa7\x92")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
                .arg(QString::number(b.folded))
                .arg(bulwark::eventTypeToString(e.type))
                .arg(e.actorPath)
                .arg(QString::number((nowMs - b.firstMs) / 1000));
        }
        b.firstMs = nowMs;
        b.folded  = 0;
        return true;
    }

    ++b.folded;
    return false;                       // 窗口内重复:折叠
}

void Worker::onEvent(const SecurityEvent& incoming) {
    SecurityEvent e = incoming; // evaluate 需要可变引用(写回证据/分数)

    // 总开关关闭 / 该维度未启用 -> 直接放行(不富化、不评估、不处置),仅记日志/审计。
    // 对应 .NET Worker.HandleEventAsync 开头的短路;让 UI 的总开关与分项开关真正生效。
    if (settings_ && (!settings_->protectionEnabled || !isDimensionEnabled(e.type))) {
        // 这条路径在总开关/分项开关关闭时对【每一条】事件都成立,是比共存放行更猛的刷屏源
        // (没有任何过滤),所以同样走折叠。事件未富化,风险恒 0、无硬指标,判定天然命中。
        // 只发 UI 实时日志、不写 service.log —— 与本路径原有行为保持一致(原本就没有 log_.info)。
        QString offSummary;
        const bool emitOff = shouldLogAllow(e, VerdictAction::Allow, &offSummary);
        if (!offSummary.isEmpty())
            ipc_->sendLog(offSummary);
        if (emitOff)
            ipc_->sendLog(describe(e, VerdictAction::Allow));
        ipc_->sendEventLog(e, VerdictAction::Allow, VerdictSource::DefaultPolicy);
        writeAudit(e, VerdictAction::Allow, VerdictSource::DefaultPolicy);
        return;
    }

    enrich(e);                  // 先富化(签名/哈希/命令行/首见/祖先链),规则引擎才有据可判
    chain_.record(e);                        // 记入进程链(供后续事件关联与足迹清理)
    e.chainContext = chain_.buildContext(e); // 合并历史 + 祖先链上下文,喂给杀伤链阶段分析

    // 攻击链组合:给该进程记下本次触发的动作标记,若因此凑齐了某个「服务器从真实样本里数出来的
    // 组合」,就把它作为证据喂进事件。必须在 evaluate 之前 —— 这样结论由既有裁决流水线产出,
    // 用户信任 / 自身组件 / 已装杀软那几道放行通道仍在它之前生效,组合命中越不过它们。
    // 富化之后才调:匹配要用到签名状态与命令行,富化前这些字段还是空的。
    // 命中留到裁决之后再记录(要记下最终处置是放行/拦截/询问),故先接在局部变量里。
    //
    // 自身组件直接跳过记账:它们在裁决流水线【第一步】就被无条件放行,攻击链对它们下的任何结论
    // 都到不了处置环节 —— 记下来只会把命中表(上限 500 条)灌满自噪声,把真实命中挤出去。
    // 实测确有此事:本产品的 UI 自己就会命中「系统进程名出现在非常规位置」那条组合。
    // 这里零检测损失 —— 唯一被排除的是「永远不会被拦」的那一类主体。
    std::optional<ChainHit> chainHit;
    if (attackChain_ && !engine_->isSelfComponent(e)) {
        if (const auto hit = attackChain_->observe(e)) {
            attackChain_->applyHitToEvent(e, *hit);
            chainHit = hit;
            log_.warning(QStringLiteral("攻击链组合命中%1:%2 → %3(%4 个样本作证)")
                             .arg(attackChain_->isDryRun() ? QStringLiteral("(dry-run 仅记录)")
                                                           : QString())
                             .arg(e.actorPath)
                             .arg(hit->titles.join(QStringLiteral(" + ")))
                             .arg(hit->pattern.support));
        }
    }

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

    // 内存防护 VT 验证:内核驱动已阻止跨进程注入(ObRegisterCallbacks 剥权),但注入源是恶意
    // 程序还是正常软件的误触仍需确认。限流(默认 4/小时)查 VT,命中恶意则补偿处置。
    if (!skipDetection && e.memoryInjection && settings_ && settings_->memoryProtectionVtVerifyEnabled)
        maybeVerifyMemoryInjection(e);

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

    bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;
    switch (action) {
        case VerdictAction::Ask: {
            // 超量保护:先按默认策略收尾最旧的一条,再放新的进来。绝不静默丢弃 ——
            // 内核阻塞类事件靠这条回写才能放行/拦截,悄悄扔掉会让它永远等不到裁决。
            if (pending_.size() >= kMaxPendingPrompts) {
                QUuid oldestId;
                QDateTime oldest;
                for (auto it = pending_.constBegin(); it != pending_.constEnd(); ++it) {
                    const QDateTime ts = it.value().event.timestampUtc;
                    if (!oldest.isValid() || ts < oldest) { oldest = ts; oldestId = it.key(); }
                }
                const auto victim = pending_.find(oldestId);
                if (victim != pending_.end()) {
                    const SecurityEvent old = victim.value().event;
                    pending_.erase(victim);
                    resolvePromptByDefault(
                        old, QStringLiteral("待裁决队列已满(%1 条)").arg(kMaxPendingPrompts));
                }
            }
            const int timeoutSecs = settings_ ? settings_->promptTimeoutSeconds : 0;
            PendingPrompt p;
            p.event = e;
            // <= 0 表示不超时(等用户点到底);> 0 才记截止时间。
            if (timeoutSecs > 0)
                p.deadlineUtc = QDateTime::currentDateTimeUtc().addSecs(timeoutSecs);
            pending_.insert(e.id, p);
            ipc_->sendPrompt(e);
            break;
        }
        case VerdictAction::Block:
            ipc_->sendBlock(e);
            //
            // persistentBlacklist 只在【引擎自己就判了 Block】时为真。
            //
            // 静默模式把 Ask 升级来的 Block 属于「被抑制的询问」,不是「已确认恶意」:引擎的原始
            // 结论是「拿不准,该问用户」(RuleEngine 第 10 步在 riskScore < HighRisk 时给 Ask)。
            // 这种不确定的结论绝不能钉进内核 FileExecBlock / FileNoLoad —— 那两份名单由驱动写回
            // 注册表、跨杀服务与重启由内核独立续拦,协议上又没有「删除单条」,一次误判就是
            // 「该程序永久起不来,且用户在 UI 怎么加白都没用」(事件在进程创建回调就被
            // STATUS_ACCESS_DENIED,根本到不了规则引擎)。
            //
            // 实测事故:Kiro(Amazon 有效签名的 Electron IDE)因两个纯统计信号凑到硬指标、
            // riskScore 恰好 50 命中 Suspicious 等号,被静默模式升级为 Block 并永久钉入内核禁运,
            // 重装服务、重启都救不回来 —— 只能手工改注册表。
            //
            // 与上面 660 行的超时兜底同一口径(那里已经这么做了):不确定的处置只结束当前进程,
            // 不留跨重启的持久拦截。真正确定的恶意仍照旧钉死 —— 引擎直接判 Block(高危硬指标 /
            // 命中 Block 规则 / 吊销签名)、外部信誉确认恶意(onReputationMalicious 单独调
            // blacklistExec)这些路径都不受本改动影响。
            //
            enforcement = enforceBlock(e, /*persistentBlacklist=*/v.action == VerdictAction::Block);
            maybeQuarantineOnBlock(e);     // 设置「拦截时一并隔离载荷」开启时才动作(带三道护栏)
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

    // 文本日志(service.log + UI 实时日志)对「零调查价值的放行」折叠,否则共存安全软件的临时
    // 文件 churn 会在几秒内滚完 5MB 上限,把启动过程与真实告警全部挤出日志。判定见 shouldLogAllow。
    QString foldSummary;
    const bool emitLine = shouldLogAllow(e, action, &foldSummary);
    if (!foldSummary.isEmpty()) {          // 上一窗口的汇总先落,保持时间顺序
        ipc_->sendLog(foldSummary);
        log_.info(foldSummary);
    }
    if (emitLine) {
        const QString line = describe(e, action);
        ipc_->sendLog(line);
        log_.info(line);
    }
    // 走同一个 recordEvent 漏斗(它与这里原本内联的两步完全等价),这样「结构化历史 + 实时推送 +
    // ECS 告警导出」只有一处实现,不会再出现某条新增路径漏掉其中一项的情况。
    // 注意:结构化历史与审计【不参与上面的折叠】,仍逐条完整落盘 —— 折叠只压文本滚动面,
    // 不动统计口径,也不动取证轨迹。
    recordEvent(e, action, source, enforcement);
    writeAudit(e, action, source);

    // 攻击链命中记录:放在最后,这样能记下【最终】处置(可能被静默模式升级、或被签名信任降级)。
    // 独立于事件历史保存 —— 一条攻击链跨多个事件,挂在任一条事件上都看不到全貌。
    if (attackChain_ && chainHit.has_value()) {
        const QString actionName = action == VerdictAction::Block ? QStringLiteral("Block")
                                 : action == VerdictAction::Ask   ? QStringLiteral("Ask")
                                                                  : QStringLiteral("Allow");
        const service::ChainHitRecord rec = attackChain_->recordHit(*chainHit, e, actionName);

        // 即时通知(右下角自动消失的 toast)。
        //
        // 【刻意不看 silentMode】。静默模式的语义是「不要为决策打扰我」—— 它把询问降级成放行。
        // 但那恰恰造出一个盲区:攻击链凑齐了 N 个动作、有真实样本作证,却被静默放行,而用户
        // 完全不知道发生过。这是通知而非提问:不带处置按钮、自动消失、不抢焦点,不构成打扰,
        // 所以不该被静默模式吞掉。要彻底关掉它有独立开关 attackChainToast。
        //
        // 也【刻意不复用 BlockNotification】:那条只在真拦下时发,而这里三种处置都要发。
        if (ipc_ && (!settings_ || settings_->attackChainToast)) {
            bulwark::ipc::AttackChainHitPayload p;
            p.whenUtc   = rec.whenUtc;
            p.actorPath = rec.actorPath;
            p.actorPid  = rec.actorPid;
            p.titles    = rec.titles;
            p.grade     = rec.grade;
            p.maxLevel  = rec.maxLevel;
            p.support   = rec.support;
            p.families  = rec.families;
            p.dryRun    = rec.dryRun;
            p.action    = rec.action;
            p.eventType = rec.eventType;
            ipc_->sendAttackChainHit(p);
        }
    }
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
    SecurityEvent e = it.value().event;
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

    // 用户裁决为拦截:执行真实处置并拿到真实结果(内核前拦 / 已结束进程 / 加黑名单 / 仅告警)。
    bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;
    if (action == VerdictAction::Block) {
        enforcement = enforceBlock(e);
        maybeQuarantineOnBlock(e); // 用户显式裁决拦截时同样尊重「拦截时一并隔离载荷」设置
    }
    // 阻塞式源(内核驱动):把用户裁决回写内核。仅文件/注册表/结束进程等内核等待类事件真正回复。
    if (source_ && source_->wantsVerdict())
        source_->submitVerdict(e, action);

    ipc_->sendLog(describe(e, action));
    recordEvent(e, action, VerdictSource::UserPrompt, enforcement); // 用户裁决登记到活动 / 拦截记录
    writeAudit(e, action, VerdictSource::UserPrompt);
}

void Worker::onPromptTimeoutTick() {
    if (pending_.isEmpty())
        return;
    const QDateTime now = QDateTime::currentDateTimeUtc();

    // 先收集再处置:resolvePromptByDefault 会走 enforceBlock / IPC / 审计,期间不应在
    // 遍历中改动 pending_。
    QVector<SecurityEvent> expired;
    for (auto it = pending_.begin(); it != pending_.end(); ) {
        const QDateTime& deadline = it.value().deadlineUtc;
        if (deadline.isValid() && deadline <= now) {
            expired.append(it.value().event);
            it = pending_.erase(it);
        } else {
            ++it;
        }
    }
    for (const SecurityEvent& e : expired)
        resolvePromptByDefault(e, QStringLiteral("用户未在 %1 秒内裁决")
                                      .arg(settings_ ? settings_->promptTimeoutSeconds : 0));
}

void Worker::resolvePromptByDefault(const SecurityEvent& e, const QString& why) {
    // 默认策略来自 RuntimeSettings::defaultBlock(UI 的「默认拦截未知行为」开关)。
    // 在此之前该开关在服务端只被打印进一行日志,不参与任何裁决 —— 现在它真正决定超时兜底方向。
    const bool block = settings_ && settings_->defaultBlock;
    const VerdictAction action = block ? VerdictAction::Block : VerdictAction::Allow;

    const QString msg = QStringLiteral("弹窗超时按默认策略处置(%1):%2 -> %3")
                            .arg(why, e.actorPath,
                                 block ? QStringLiteral("拦截") : QStringLiteral("放行"));
    log_.warning(msg);
    ipc_->sendLog(msg);

    bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;
    if (block) {
        ipc_->sendBlock(e);
        // persistentBlacklist=false:超时兜底并非「已确认恶意」,不把映像/模块钉进内核持久名单。
        enforcement = enforceBlock(e, /*persistentBlacklist=*/false);
    }
    // 阻塞式源(内核驱动)必须收到回写,否则该操作在内核侧一直悬着。
    if (source_ && source_->wantsVerdict())
        source_->submitVerdict(e, action);

    // 这是 VerdictSource::Timeout 唯一的产生点 —— 此前该枚举值从未被产生过。
    recordEvent(e, action, VerdictSource::Timeout, enforcement);
    writeAudit(e, action, VerdictSource::Timeout);
}

void Worker::enrich(SecurityEvent& e) {
    // 0) 服务创建「真凶」溯源。创建服务走 RPC 交由 services.exe(SCM)代写注册表,内核回调
    //    归因永远是 SCM 而非真实发起者;此处把它还原成真正调用方。
    //
    //    这段原先在 DriverEventSource::buildAndQueue 里(驱动读线程)。搬到这里有两个理由:
    //    一是 trace() 要做 1MB 全系统进程+线程快照 + 逐候选 OpenProcess,属于该函数注释明令
    //    「交主线程」的昂贵富化,放在读线程会堵住整个内核事件投递;二是它在读线程的栈帧里会
    //    写坏待入队事件的 chainContext(详见 buildAndQueue 里的说明),是服务反复崩溃的触发点。
    //
    //    必须放在第 1 步【之前】:溯源会改写 actorPid,下面按 PID 反查路径才查的是真凶。
    if (e.type == bulwark::EventType::RegistryWrite && e.actorPid > 0
        && ServiceControlTracer::isServiceDatabaseKey(e.target)) {
        const ServiceOriginator orig = ServiceControlTracer::trace(e.actorPid);
        // 仅高置信唯一候选才改写主体,否则保守留 SCM —— 绝不据此去结束 services.exe。
        if (orig.highConfidence()) {
            e.actorPid = orig.originatorPid;
            e.actorPath = orig.originatorPath;
            e.detail += QStringLiteral(" · 真凶溯源:%1(PID %2)")
                            .arg(QFileInfo(orig.originatorPath).fileName())
                            .arg(orig.originatorPid);
        }
    }

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

    //
    // 3.1) 本软件自身组件:跳过所有【昂贵且对结论毫无影响】的取证。
    //
    // 裁决流水线的第 1 步就是 `isSelfComponent -> 无条件放行`,早于威胁检测、时序检测与规则
    // 匹配,没有任何例外分支。也就是说下面这些取证结果对自身组件的裁决【一个字节都用不上】:
    //   · 启动来源溯源(3.2):服务枚举 + 计划任务查表;
    //   · 祖先链回溯(3.5):最多 16 级,每级 OpenProcess + NtQueryInformationProcess +
    //     QueryFullProcessImageName,且【不带缓存】—— 这是本函数里唯一逐条事件都要付的
    //     系统调用大头;
    //   · 证书画像 / 侧载模块扫描 / 首见落盘 / 云信誉查询。
    //
    // 而自身组件恰恰是最高频的事件来源:服务自己在持续写 %ProgramData%\Bulwark\ 下的日志、
    // 规则、信誉缓存、事件历史,这些写入全都经内核文件遥测回到本函数。给「一定会被无条件
    // 放行」的自己做全套取证,是纯粹自噪声。
    //
    // 仍然保留的:映像路径 / 命令行 / 父路径(上面已做,均为单次调用),以及下面第 4 步里
    // 按文件身份缓存的签名 / 发布者 / 哈希 —— 它们要出现在 UI 的活动日志里,且命中缓存后
    // 成本可忽略。这里刻意只砍「每条事件都重新付、且结论用不上」的那部分。
    //
    const bool selfComponent = engine_ && engine_->isSelfComponent(e);

    // 3.2) 启动来源溯源:把「父进程是 svchost.exe / services.exe / 任务宿主」这种到此为止的
    //      溯源链继续往下钉到【具体是哪个服务、哪个计划任务】。这是持久化落地执行这条链上最
    //      关键的一环 —— 没有它,「攻击者装了个服务/计划任务来拉起载荷」在日志上和普通系统
    //      行为长得一模一样。
    //
    //      纯溯源:结论只写入事件的 origin* 字段并记一条 Info 证据(0 分),【不参与风险评分】。
    //      「由计划任务启动」本身完全合法,不该因此提分;它的价值在于分析时能一眼看到因果。
    if (e.actorPid > 0 && !selfComponent) {
        const ProcessOrigin origin =
            ProcessOriginResolver::resolve(e.actorPid, e.actorPath, e.parentPid, e.commandLine);
        if (origin.resolved()) {
            e.originKind = origin.kind;
            e.originService = origin.serviceName;
            e.originServiceDisplay = origin.serviceDisplayName;
            e.originTask = origin.taskPath;
            e.originDetail = origin.detail;
            // 只有「服务 / 计划任务」这两类才值得单独记一条证据 —— 它们补上的是真正的盲区;
            // 「由 explorer.exe 启动」这种没有信息量,写进去只会稀释证据链。
            if (origin.kind == bulwark::ProcessOriginKind::Service
                || origin.kind == bulwark::ProcessOriginKind::ScheduledTask) {
                e.addEvidence(QStringLiteral("启动来源"), bulwark::EvidenceKind::Info,
                              QStringLiteral("%1%2")
                                  .arg(e.originLabel(),
                                       origin.detail.isEmpty()
                                           ? QString()
                                           : QStringLiteral("(%1)").arg(origin.detail)),
                              0, /*alsoReason=*/false);
            }
        }
    }

    // 3.5) 用 OS API 回溯完整父进程祖先链种入 chainContext(即便进程链跟踪器无历史,
    //      刚开机/首个事件时溯源链也完整;buildContext 随后会与历史合并)。
    if (!selfComponent)
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

    // 自身组件到此为止(理由见第 3.1 步):签名 / 发布者 / 哈希已经拿到,足够 UI 如实展示,
    // 而下面的证书链构建、侧载扫描、首见落盘、云查询对「无条件放行」的结论没有任何影响。
    if (selfComponent)
        return;

    // 证书画像:指纹 / 有效期 / 吊销 / 过期后签名(证书被吊销即便验签不过仍是硬指标)。
    const ProcessInspector::CertInfo ci = ProcessInspector::getCertInfo(path);
    if (!ci.thumbprint.isEmpty())    e.actorCertThumbprint = ci.thumbprint;
    if (ci.notAfterUtc.isValid())    e.certNotAfterUtc     = ci.notAfterUtc;
    if (ci.signingTimeUtc.isValid()) e.signingTimeUtc      = ci.signingTimeUtc;
    e.certRevoked           = ci.revoked;
    e.signedAfterCertExpiry = ci.signedAfterCertExpiry;

    // 侧载模块篡改(「白加黑」):主体签名健康时,顺带看一眼同目录有没有「签名后被改过」的模块。
    // 放在签名/证书判定【之后】—— 它要先知道主体自己是不是签名健康的壳。按目录缓存,低频。
    detectSideloadedTamperedModule(e);

    // 文件体积:银狐 / 游蛇 惯用「文件膨胀」把样本撑到数十 MB 以规避扫描。
    const QFileInfo fi(path);
    if (fi.exists() && fi.isFile())
        e.actorFileSize = fi.size();

    // 本机首见(低流行度信号):按 SHA-256 判定并落盘;单独不触发拦截,仅参与提分。
    if (firstSeen_ && !e.actorHash.isEmpty())
        e.isFirstSeen = firstSeen_->markAndCheckFirstSeen(e.actorHash);

    // 外部信誉:
    // 1. 优先读本地缓存(无网络开销);
    // 2. 若缓存未命中且主体为【未签名 + 高危场景】,发起【有界等待】的云查询,防止已知恶意样本
    //    首次执行漏网。「高危场景」= 首见 || 可疑目录 || 体积异常 —— 这些软信号单独不触发云查询
    //    (避免所有首见都联网),但组合出现时足以触发;已签名样本不在此列,由后台异步链路处理。
    // 3. 其余场景由 onEvent 后的 maybeEnqueue 在后台异步查询并回填缓存,下次即命中。
    //
    // 【这里曾是「防护延迟过高」的主因】原实现调的是 reputation_->queryNow —— 那个接口的声明
    // 上就写着「绝不用于事件热路径」。它在本线程上一路阻塞:中央代理超时(默认 8s)+ 回退本地
    // 直连聚合(各源并行,收敛到最慢单源,默认 10~15s),最坏二十多秒。而出队 / 富化 / 裁决 /
    // IPC / 弹窗超时巡检全都在这同一个线程上串行,于是一条事件就能让【全部后续事件】停摆同样
    // 长的时间:内核事件在 4096 深的队列里堆到丢弃(直接等于漏检)、拦截与询问迟迟不到 UI、
    // 连每秒一次的弹窗超时巡检都不再跳。触发条件毫不苛刻 —— 代理端口不可达时,每一次缓存未命中
    // 都要先等满超时才回退。
    //
    // 改为 queryNowBounded 后语义只差一点:预算内答复照旧参与本条裁决(服务器正常时 200~800ms,
    // 常态命中);超预算则放手让流水线继续,查询仍在后台跑完并回填缓存,迟到的恶意结论转由既有
    // 补偿处置链路(结束进程树 + 隔离 + 内核禁运)兜住。检测能力不减,延迟上限从「秒到数十秒」
    // 变成一个明确的可配置常数。
    if (reputation_ && !e.actorHash.isEmpty()) {
        const std::optional<bulwark::FileReputation> cached = reputation_->tryGetCached(e.actorHash);
        if (cached.has_value()) {
            e.reputation = cached;
        } else if (!e.actorSigned) {
            // 快速判定是否属于高危未签名场景(避免对所有未签名文件都同步查询):
            // 1) 首见;2) 可疑目录;3) 体积异常(>60MB)。
            const QString pathLower = e.actorPath.toLower();
            const bool inSuspiciousDir = pathLower.contains(QLatin1String("\\temp\\")) ||
                                         pathLower.contains(QLatin1String("\\public\\")) ||
                                         pathLower.contains(QLatin1String("\\programdata\\")) ||
                                         pathLower.contains(QLatin1String("\\desktop\\")) ||
                                         pathLower.contains(QLatin1String("\\downloads\\"));
            const bool oversized = e.actorFileSize >= 60LL * 1024 * 1024;
            const bool suspicious = e.isFirstSeen || inSuspiciousDir || oversized;
            if (suspicious) {
                // 有界等待的云查询(限流仍在客户端内部控制)。超预算即返回 Unknown 放行本条,
                // 查询本身继续在后台跑完;详见上方说明与 queryNowBounded。
                const bulwark::FileReputation rep =
                    reputation_->queryNowBounded(e, inlineRepBudgetMs_);
                if (rep.querySucceeded && rep.verdict != bulwark::ReputationVerdict::Unknown) {
                    e.reputation = rep;
                    log_.info(QStringLiteral("高危未签名场景同步云查命中:%1(%2/%3 · %4)")
                                  .arg(e.actorPath)
                                  .arg(rep.malicious).arg(rep.totalEngines)
                                  .arg(rep.verdict == bulwark::ReputationVerdict::Malicious ? QStringLiteral("恶意")
                                     : rep.verdict == bulwark::ReputationVerdict::Suspicious ? QStringLiteral("可疑")
                                     : QStringLiteral("干净")));
                }
            }
        }
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
                // 溯源链上每一级都标出它自己的启动来源。这样一条链读下来是
                // 「计划任务 \Foo -> powershell.exe -> dropper.exe」而不是
                // 「svchost.exe -> powershell.exe -> dropper.exe」—— 后者根本看不出因果。
                // 结论带 60s 备忘缓存,所以逐级解析并不昂贵;仍限制在前 6 级以内封顶开销。
                if (cur == e.actorPid) {
                    node.originKind = e.originKind;
                    node.originLabel = e.originLabel();
                } else if (depth <= 6) {
                    const ProcessOrigin anc =
                        ProcessOriginResolver::resolve(cur, curPath, parent, QString());
                    if (anc.resolved()) {
                        node.originKind = anc.kind;
                        bulwark::SecurityEvent tmp; // 复用同一套措辞,避免两处各写一份
                        tmp.originKind = anc.kind;
                        tmp.originService = anc.serviceName;
                        tmp.originServiceDisplay = anc.serviceDisplayName;
                        tmp.originTask = anc.taskPath;
                        node.originLabel = tmp.originLabel();
                    }
                }
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

// 恶意进程终结:先用户态结束整棵进程树(快照内枚举子孙一并结束),再对根 PID 追加【驱动级】
// 内核结束(BLW_CMD_KILL_PID -> ZwTerminateProcess)作兜底 —— 应对能反抗用户态 TerminateProcess
// 的高级样本(内核结束不受目标用户态对抗影响)。内核未连接/旧驱动/被内核护栏拒绝时返回 false,
// 不影响用户态结果。关键系统进程由内核+用户态双重护栏保护,绝不误杀。返回是否已结束。
bool Worker::killMalicious(int pid) {
    if (pid <= 4)
        return false;
    // 情报/规则确认恶意:先【封禁该主体】—— 其任何文件写/删/改、注册表写、网络外联、创建子进程
    // 此后被内核各回调一律拒绝。不依赖下面「结束进程」的时机:即便被反杀 / 滞后,封禁期间它也
    // 一个动作都做不成(「情报一确认即全维封杀」)。旧驱动/未连接时 no-op,不影响后续结束进程。
    if (source_)
        source_->banProcess(pid);
    const int killed = ProcessInspector::terminateProcessTree(pid);   // 用户态结束整树(枚举子孙)
    const bool kkill = source_ && source_->killProcess(pid);           // 驱动级兜底(内核 ZwTerminateProcess)

    // 以【目标是否真的退出了】为准来判定成败,而不是以「命令是否被受理」为准。
    //
    // 为什么必须实测:驱动对 BLW_CMD_KILL_PID 是 fire-and-forget,Comms.c 对该命令
    // 【一律回 STATUS_SUCCESS】(被内核护栏拒绝也算成功,见其注释),所以 killProcess()
    // 的 true 只说明"内核收下了这条命令",完全不代表进程死了。原实现据此就打出
    // 「+ 驱动级内核结束」并返回成功 —— 实测出现过连续几十小时每 60 秒打一次这条日志、
    // 而目标进程一直活着的情况(兜底扫描每分钟重来一遍,却没人报告失败)。
    // 安全产品不能把"命令已发出"说成"威胁已清除"。
    //
    // 判定用 waitForExit 而不是「PID 还在不在进程快照里」:结束是异步的(线程要收尾),
    // 且被别人持有句柄的僵尸进程会一直留在快照里。用快照判会把刚刚杀成功的目标误报成
    // 「未能终结」—— 那是把一个假消息换成另一个假消息。300ms 上限只花在处置路径上
    // (仅对已确认恶意的主体走一次),不碰任何热路径。
    const bool gone = ProcessInspector::waitForExit(pid, 300);
    if (gone) {
        log_.info(QStringLiteral("恶意进程终结:PID=%1(用户态结束 %2 个%3)。")
                      .arg(pid).arg(killed)
                      .arg(kkill ? QStringLiteral(" + 驱动级内核结束") : QString()));
        return true;
    }

    // 没死。如实报出来,并带上排障需要的两条信息:是否被"关键进程"护栏挡住、映像路径。
    // (封禁主体已在上面下发,所以即便杀不掉,它的文件/注册表/网络/子进程也已被内核全维拒绝。)
    log_.warning(QStringLiteral("恶意进程未能终结:PID=%1 仍在运行(用户态结束 %2 个,内核结束命令%3)。"
                                "关键进程护栏=%4,映像=%5。已封禁主体,其行为仍被内核全维拒绝。")
                     .arg(pid).arg(killed)
                     .arg(kkill ? QStringLiteral("已受理") : QStringLiteral("未受理"))
                     .arg(ProcessInspector::isCriticalProcess(pid) ? QStringLiteral("命中(按此判定不予结束)")
                                                                   : QStringLiteral("未命中"))
                     .arg(ProcessInspector::tryGetProcessImagePath(pid)));
    return false;
}

void Worker::blacklistExec(const QString& imagePath) {
    if (!source_)
        return;
    QString p = imagePath.trimmed();
    if (p.isEmpty())
        return;
    // 只处理形似真实文件路径的映像(带盘符或以反斜杠开头);占位符如 "PID 1234" 直接跳过。
    const bool looksPath =
        (p.size() >= 2 && p[1] == QLatin1Char(':')) || p.startsWith(QLatin1Char('\\'));
    if (!looksPath)
        return;
    // 加白豁免:被用户明确信任(或本软件自身)的映像绝不下发内核「禁止执行」名单。
    // 这份名单由内核写回注册表持久化、跨杀服务与重启由内核独立续拦,且协议上没有「删除单条」——
    // 一旦对已加白的程序钉进去,用户在 UI 再怎么加白都不生效:内核在进程创建回调就地
    // STATUS_ACCESS_DENIED,事件根本到不了规则引擎。故这里是必须守住的最后一道闸。
    if (const std::optional<QString> note = engine_->trustNoteForPath(p)) {
        log_.info(QStringLiteral("执行前拦截已跳过(该主体已加白:%1):%2").arg(*note, p));
        return;
    }
    // 去掉盘符(如 "C:"),下发【盘符无关】的路径子串:内核在进程创建回调里拿到的映像路径可能是
    // \??\C:\... 也可能是 \Device\HarddiskVolumeN\...,二者都包含去盘符后的 "\Users\...\x.exe" 子串,
    // 从而稳定命中(与内核系统目录白名单用盘符无关子串同理)。UNC "\\host\..." 本就盘符无关,保持不变。
    QString needle = p;
    if (needle.size() >= 2 && needle[1] == QLatin1Char(':'))
        needle = needle.mid(2);
    // 过短的子串风险大(可能误拦无关进程),放弃 —— 确认恶意的样本映像总是较长的完整路径。
    if (needle.size() < 6)
        return;
    if (source_->blockExecPath(needle))
        log_.info(QStringLiteral("执行前拦截:已把恶意映像加入内核禁止执行名单(下次启动将被内核前拦):%1").arg(p));
}

bool Worker::abortIfTrustedNow(const SecurityEvent& e, const QString& stage) {
    const std::optional<QString> note = engine_->trustNoteForPath(e.actorPath);
    if (!note)
        return false;
    // 后台链路回执可能比事件晚几十秒到几分钟,期间用户完全可能刚把该程序加白。此时按加白语义
    //(「信任即完全不检测、不处置」)放弃处置 —— 否则加白前排队的扫描回来照样结束进程,还会把
    // 路径钉进内核禁运名单,变成用户怎么加白都解不开的死结。
    const QString msg = QStringLiteral("%1 已确认恶意,但该主体此刻已被加白(%2)—— 按信任语义放弃处置:%3")
                            .arg(stage, *note, e.actorPath);
    log_.info(msg);
    ipc_->sendLog(msg);
    return true;
}

std::pair<bool, QString> Worker::forceQuarantine(const QString& path) {
    if (!remediator_)
        return { false, QStringLiteral("清理器不可用(隔离区未就绪)") };
    const std::pair<bool, QString> r = remediator_->forceQuarantine(path);
    if (r.first)
        ipc_->sendQuarantineList();   // 成功即回推,隔离区页面无需再请求
    return r;
}

bulwark::ipc::PersistenceCleanupResultPayload Worker::cleanupPersistence(
    const bulwark::ipc::PersistenceCleanupRequestPayload& req) {
    bulwark::ipc::PersistenceCleanupResultPayload res;
    res.requestId = req.requestId;
    res.entryId = req.entry.id;

    if (!remediator_) {
        res.message = QStringLiteral("清理器不可用(隔离区未就绪)");
        return res;
    }
    const bulwark::PersistenceEntry& entry = req.entry;
    if (entry.id.trimmed().isEmpty() || entry.location.trimmed().isEmpty()) {
        res.message = QStringLiteral("条目信息不完整,已放弃清理(未做任何处置)");
        return res;
    }

    // 护栏:已加白的目标不清理。自启动项页把「已加白」也列出来供审计,但清理必须尊重信任语义 ——
    // 否则用户刚加白的开机自启程序会被这里清掉,与加白的承诺直接冲突。
    if (!entry.imagePath.trimmed().isEmpty()) {
        if (const std::optional<QString> note = engine_->trustNoteForPath(entry.imagePath)) {
            res.message = QStringLiteral("该项目标已加白(%1),按信任语义放弃清理").arg(*note);
            log_.info(res.message + QStringLiteral(":") + entry.imagePath);
            return res;
        }
        // 护栏:本产品自身的自启动项绝不清理(否则用户一键把自己的防护开机自启删了)。
        if (isSweepExemptPath(entry.imagePath)) {
            res.message = QStringLiteral("系统组件 / 本产品自身的自启动项不允许从此处清理");
            log_.warning(res.message + QStringLiteral(":") + entry.imagePath);
            return res;
        }
    }

    const RemediationReport report = remediator_->cleanupPersistenceEntry(entry);
    // 持久化反重建:刚清掉的项立刻加入内核注册表硬拦,挡住守护进程秒级重写(与自动清理同一处置)。
    applyRegHardening(report);

    res.quarantinedFiles = report.quarantinedFiles;
    res.removedRegistryValues = report.removedRegistryValues;
    res.skipped = report.skipped;
    res.success = report.totalActions() > 0;
    res.message = res.success
        ? QStringLiteral("已清理:隔离文件 %1 个,移除持久化 %2 项%3")
              .arg(report.quarantinedFiles.size())
              .arg(report.removedRegistryValues.size())
              .arg(report.skipped.isEmpty()
                       ? QString()
                       : QStringLiteral(",另有 %1 项未能处理").arg(report.skipped.size()))
        : (report.skipped.isEmpty()
               ? QStringLiteral("未产生任何动作(该项可能已被移除)")
               : QStringLiteral("清理失败:%1").arg(report.skipped.first().reason));

    const QString msg = QStringLiteral("自启动项清理[%1] %2 -> %3")
                            .arg(entry.name, entry.location, res.message);
    log_.warning(msg);
    ipc_->sendLog(msg);
    if (!report.quarantinedFiles.isEmpty())
        ipc_->sendQuarantineList();   // 有文件进隔离区,主动回推让隔离区页面即时可见

    // 审计留痕(与自动足迹清理同一 action=Remediate 口径,便于事后统一检索)。
    using namespace bulwark::json;
    QJsonObject o;
    o["timestampUtc"] = dateTimeToIso(QDateTime::currentDateTimeUtc());
    o["type"] = QStringLiteral("Persistence");
    o["actorPath"] = entry.imagePath;
    o["actorPid"] = 0;
    o["target"] = entry.location + QStringLiteral(" \\ ") + entry.name;
    o["action"] = QStringLiteral("Remediate");
    o["source"] = QStringLiteral("UserPrompt");
    o["riskScore"] = entry.riskScore;
    QStringList details;
    for (const QString& f : report.quarantinedFiles) details << (QStringLiteral("隔离文件:") + f);
    for (const QString& r : report.removedRegistryValues) details << (QStringLiteral("移除持久化:") + r);
    for (const bulwark::ipc::RemediationSkippedItem& s : report.skipped)
        details << (QStringLiteral("未清理:") + s.target + QStringLiteral("(") + s.reason + QStringLiteral(")"));
    o["reasons"] = strListToJson(details);
    audit_->writeRecord(o);

    return res;
}

void Worker::reconcileKernelBlocksAfterTrust() {
    if (!source_)
        return;

    // ① 解除内核「已封禁主体」:killMalicious 每次都先 banProcess(pid),内核此后拒绝该 PID 的一切
    //    文件/注册表/网络/子进程行为。加白撤不掉它 —— 用户看到的是「程序还在跑但什么都干不了」。
    //    PID 是短命标识(进程退出即无意义),整表清空代价极低:真正恶意的主体在下一个动作就会被
    //    兜底扫描 / 情报链路重新封禁。这是让加白【立刻】对已在运行的进程生效的唯一办法。
    source_->clearBannedProcesses();

    // 权威基线取自内核写回的注册表(含【上次运行】钉进去的条目 —— 那些才是用户最可能撞上的);
    // 本进程的 execBlockPushed_ 只用来把「去盘符子串」还原成完整路径以便查加白。
    const QStringList kernelExec = source_->persistedExecBlockList();
    const QStringList kernelNoLoad = source_->persistedModuleNoLoadList();

    // 判断一条内核条目会不会命中某个已加白目标。内核条目是【去盘符的路径子串】,内核按子串匹配,
    // 故只要「某个加白路径(去盘符后)包含该子串」,这条就会把已加白的程序挡住 —— 必须剔除。
    const QVector<bulwark::DefenseRule> rules = engine_->getRules();
    QStringList trustedNeedles; // 已加白目标的去盘符形式(文件精确路径 / 目录前缀)
    for (const bulwark::DefenseRule& r : rules) {
        if (!r.isTrustEntry() || r.action != VerdictAction::Allow || !r.enabled)
            continue;
        QString t = !r.actorPath.isEmpty() ? r.actorPath : r.actorPattern;
        if (t.isEmpty())
            continue;
        if (t.endsWith(QStringLiteral("\\*")))   // 目录信任 "<dir>\*" -> 取目录前缀
            t.chop(2);
        if (t.size() >= 2 && t[1] == QLatin1Char(':'))
            t = t.mid(2);                        // 去盘符,与内核条目同形
        if (!t.isEmpty())
            trustedNeedles << t;
    }
    auto wouldBlockTrusted = [&trustedNeedles](const QString& entry) {
        for (const QString& t : trustedNeedles)
            if (t.contains(entry, Qt::CaseInsensitive) || entry.contains(t, Qt::CaseInsensitive))
                return true;
        return false;
    };

    // ---- 禁止执行名单 ----
    QStringList keepExec, dropExec;
    for (const QString& entry : kernelExec)
        (wouldBlockTrusted(entry) ? dropExec : keepExec) << entry;
    if (!dropExec.isEmpty()) {
        if (source_->clearExecBlock()) {
            for (const QString& entry : keepExec)
                source_->blockExecPath(entry);
            const QString msg =
                QStringLiteral("加白对账:已解除内核「禁止执行」名单中 %1 条会挡住已加白程序的条目"
                               "(保留 %2 条)。这些程序此后可正常启动。")
                    .arg(dropExec.size()).arg(keepExec.size());
            log_.warning(msg);
            ipc_->sendLog(msg);
            for (const QString& entry : dropExec)
                log_.info(QStringLiteral("  已解除执行前拦截:%1").arg(entry));
        } else {
            log_.warning(QStringLiteral("加白对账:内核未连接或不受理清空命令,「禁止执行」名单中 %1 条"
                                        "针对已加白程序的条目仍在生效(重启服务并连上驱动后会自动重试)。")
                             .arg(dropExec.size()));
        }
    }

    // ---- 禁止加载模块名单(白加黑防护的侧载 DLL)----
    QStringList keepLoad, dropLoad;
    for (const QString& entry : kernelNoLoad)
        (wouldBlockTrusted(entry) ? dropLoad : keepLoad) << entry;
    if (!dropLoad.isEmpty()) {
        if (source_->clearModuleNoLoad()) {
            for (const QString& entry : keepLoad)
                source_->blockModuleLoad(entry);
            const QString msg =
                QStringLiteral("加白对账:已解除内核「禁止加载」名单中 %1 条会挡住已加白模块的条目(保留 %2 条)。")
                    .arg(dropLoad.size()).arg(keepLoad.size());
            log_.warning(msg);
            ipc_->sendLog(msg);
        } else {
            log_.warning(QStringLiteral("加白对账:内核未连接,「禁止加载」名单中 %1 条针对已加白模块的条目仍在生效。")
                             .arg(dropLoad.size()));
        }
    }
}

void Worker::applyRegHardening(const RemediationReport& report) {
    if (!source_ || report.hardenedRegTargets.isEmpty())
        return;
    QSet<QString> seen;
    int n = 0;
    for (const QString& t : report.hardenedRegTargets) {
        const QString k = t.trimmed();
        if (k.size() < 8)                    // 过短子串风险大(可能误拦无关键),跳过
            continue;
        const QString low = k.toLower();
        if (seen.contains(low))              // 本批去重
            continue;
        seen.insert(low);
        if (source_->hardenRegistryKey(k))
            ++n;
    }
    if (n > 0)
        log_.warning(
            QStringLiteral("持久化反重建:已把 %1 条已清理的自启动项加入内核注册表硬拦(阻止恶意软件立刻重建)。").arg(n));
}

bulwark::EnforcementOutcome Worker::enforceBlock(const SecurityEvent& e, bool persistentBlacklist) {
    using bulwark::EnforcementOutcome;

    // (a) 内核已在【动作发生前】真正阻断(文件/注册表硬拦名单、受保护路径删除/改名、禁止加载、
    //     自我保护剥权、反注入剥权、黑名单 IP 的 WFP 阻断)。拦截真实且完整;发起方可能只是误触
    //     受保护目标的正常程序,故不再补杀(遵循「最小化误伤」)。如实返回「已拦截」。
    if (e.kernelBlocked)
        return EnforcementOutcome::KernelBlocked;

    // (b) 观测型事件——动作已经发生(ETW/WMI 观测,或内核 fire-and-forget 的进程创建/镜像加载/
    //     软注册表/远程线程/网络观测):内核无法在发生前阻断,唯一真实的处置是【立即结束作恶
    //     进程】。对侧载模块额外加入内核禁止加载名单,使【下次】加载被内核前拦(白加黑防护)。
    bool blacklisted = false;
    if (persistentBlacklist && e.type == bulwark::EventType::ImageLoad
        && source_ && !e.target.trimmed().isEmpty()) {
        // 与 blacklistExec 同理:「禁止加载」名单也由内核写回注册表持久化、只加不减,故已加白的
        // 模块(或落在已加白目录下的模块)绝不下发,否则用户加白后该 DLL 仍会被内核拒绝映射。
        const QString mod = e.target.trimmed();
        if (const std::optional<QString> note = engine_->trustNoteForPath(mod)) {
            log_.info(QStringLiteral("禁止加载已跳过(该模块已加白:%1):%2").arg(*note, mod));
        } else {
            blacklisted = source_->blockModuleLoad(mod);
        }
    }

    // 进程创建类的确认恶意主体:加入内核「禁止执行」名单,使其【被守护进程/持久化/重启后规则命中
    // 拉起时】的再次启动被内核前拦(与下面结束进程配对——kill 收拾正在跑的,exec-block 挡再次启动)。
    // persistentBlacklist=false 的路径(超时兜底 / AI 不可用)跳过 —— 见声明处的说明。
    if (persistentBlacklist && e.type == bulwark::EventType::ProcessCreate)
        blacklistExec(e.actorPath);

    // 优先结束 RPC 真凶(如经 svchost 代发的请求),否则结束事件主体本身。
    const int pid = e.originatorPid > 0 ? e.originatorPid : e.actorPid;
    // 用户态结束整树 + 驱动级(内核 ZwTerminateProcess)兜底补刀(难被反杀);详见 killMalicious。
    if (killMalicious(pid))
        return EnforcementOutcome::Terminated;

    // 未能结束任何进程。若已把侧载模块加入禁止加载名单,本次虽未拦下,下次加载会被内核前拦。
    if (blacklisted) {
        log_.info(QStringLiteral("拦截处置:侧载模块已加入内核禁止加载名单(下次加载将被前拦):%1")
                      .arg(e.target));
        return EnforcementOutcome::ModuleBlacklisted;
    }

    // 既非内核前拦、又无可结束的进程、又非可加黑的模块:如实标记「仅告警,未实际拦截」。
    log_.warning(QStringLiteral("拦截处置:PID=%1 未能结束任何进程(已退出/受保护/关键进程),"
                                "该事件仅告警、未实际拦截。").arg(pid));
    return EnforcementOutcome::AlertedOnly;
}

void Worker::maybeQuarantineOnBlock(const SecurityEvent& e) {
    //
    // RuntimeSettings::quarantineOnBlock(「拦截时一并隔离主体载荷」)。此前该字段只有 JSON
    // 读写两行,服务端与 UI 都没有任何消费点 —— 是个纯挂着的死字段。这里是它唯一的生效点。
    //
    // 与 remediateIfMalicious 的分工:那个只对「确定性恶意」(命中规则 / 启发式)的进程主体做
    // 完整足迹清理(隔离释放物 + 清持久化 + 反重建硬拦);这个是用户显式打开的更激进策略 ——
    // 【任何】成功拦截都把主体可执行体移进隔离区。故必须自带护栏,否则一次误判就搬走系统文件。
    //
    if (!settings_ || !settings_->quarantineOnBlock || !quarantine_)
        return;

    const QString path = e.actorPath.trimmed();
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return;   // 占位符路径(内核源解析不出映像时会填 "PID 1234"),无从隔离

    // 护栏 1:已加白的主体绝不隔离(与所有后台处置路径同一口径)。
    if (const std::optional<QString> note = engine_->trustNoteForPath(path)) {
        log_.info(QStringLiteral("拦截时隔离已跳过(该主体已加白:%1):%2").arg(*note, path));
        return;
    }
    // 护栏 2:系统目录 / 本产品自身绝不隔离。isSweepExemptPath 覆盖 System32 / SysWOW64 /
    // WinSxS 与含 "bulwark" 的路径 —— 把系统组件或自己搬进隔离区等于自毁。
    if (isSweepExemptPath(path)) {
        log_.info(QStringLiteral("拦截时隔离已跳过(系统目录 / 本产品自身):%1").arg(path));
        return;
    }
    // 护栏 3:带健康签名的主体不隔离。走到 Block 的签名主体多半是 LOLBin 用法问题
    // (powershell 跑了危险命令行),隔离 powershell.exe 本体是灾难性的误伤。
    if (bulwark::engine::TrustPolicy::isHealthySigned(e).ok) {
        log_.info(QStringLiteral("拦截时隔离已跳过(主体持健康签名,拦的是用法而非文件):%1").arg(path));
        return;
    }
    if (!QFileInfo::exists(path))
        return;

    const QString hash = QuarantineManager::tryComputeSha256(path);
    const auto entry = quarantine_->quarantine(
        path, QStringLiteral("拦截时自动隔离(设置:拦截时一并隔离载荷)"), e.actorPid, hash);
    if (entry.has_value()) {
        const QString msg = QStringLiteral("拦截时隔离:已把主体载荷移入隔离区(可还原):%1").arg(path);
        log_.warning(msg);
        ipc_->sendLog(msg);
        ipc_->sendQuarantineList();   // 主动回推,UI 隔离区页面无需再请求
    } else {
        log_.warning(QStringLiteral("拦截时隔离失败(文件被占用或权限不足):%1").arg(path));
    }
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
    applyRegHardening(report); // 持久化反重建:清掉的自启动项即刻加入内核注册表硬拦,挡住守护进程秒级重写

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
    // 据「已知恶意哈希」(样本自身 + VT 释放物哈希)在本机落地区按哈希精确定位实际落地的文件,
    // 交由 remediate 隔离(即使带合法数字签名也照隔离,如 BYOVD 驱动)。只读、有界扫描,在此
    // 后台线程执行——绝不阻塞主线程。无哈希则为空,处置照旧降级为「隔离主体 + 清持久化」。
    {
        QStringList hashTargets = profile.droppedFileHashes;
        if (sha.size() == 64) hashTargets << sha.toLower();
        if (!hashTargets.isEmpty())
            profile.locatedLocalPaths = ThreatRemediator::locateDroppedFilesByHash(hashTargets);
    }
    // 威胁情报共享(默认关):行为画像此刻已在手上,顺路留一份脱敏副本等夜间上传 ——
    // 不额外发一次 behaviour_summary 请求,不多花 VT 配额。注意必须在 locatedLocalPaths
    // 填好【之后】也无妨:ContribStore 刻意不取该字段(本机路径),脱敏在它内部执行。
    retainThreatIntel(rep, profile);
    QMetaObject::invokeMethod(
        this, [this, e, rep, profile] { onReputationMalicious(e, rep, profile); },
        Qt::QueuedConnection);
}

void Worker::retainThreatIntel(const bulwark::FileReputation& rep,
                               const bulwark::ThreatBehaviorProfile& profile) {
    if (!intelContrib_)
        return;
    if (!settings_ || !settings_->cloudBehaviorUploadEnabled)
        return; // 用户未开启共享 -> 一个字节都不收集
    ThreatIntelContribStore::Record rec;
    if (!ThreatIntelContribStore::fromScan(rep, profile, &rec))
        return; // 非恶意/可疑,或无有效哈希 -> 不收集
    intelContrib_->append(rec);
}

void Worker::onReputationMalicious(const SecurityEvent& e, const bulwark::FileReputation& rep,
                                   const bulwark::ThreatBehaviorProfile& profile) {
    // 后台信誉查询确认恶意(已编组回主线程):告警 + 结束仍在运行的进程树 + 隔离载荷/清除持久化;
    // 若带行为画像,则额外清理已知释放物、并据 IOC 生成主动拦截规则。
    if (abortIfTrustedNow(e, QStringLiteral("外部信誉")))
        return;
    SecurityEvent ev = e;
    ev.reputation = rep;
    ev.hasThreatIndicator = true;
    // 记住该已确认恶意哈希 —— 兜底扫描据此复查在跑进程,实时链路漏网的也能被逮住。
    rememberMaliciousHash(!rep.sha256.isEmpty() ? rep.sha256 : e.actorHash);

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
    // 先结束进程树(样本可能仍在运行)并据真实结果如实记录处置;关键系统进程由内部安全门槛保护。
    // 未能结束(进程已退出)时标 AlertedOnly——载荷仍会在下方 remediate 阶段被隔离失活。
    bulwark::EnforcementOutcome outcome = bulwark::EnforcementOutcome::AlertedOnly;
    if (killMalicious(ev.actorPid))
        outcome = bulwark::EnforcementOutcome::Terminated;
    // 执行前拦截:把该恶意映像加入内核禁止执行名单,挡住其被守护进程/持久化拉起时的再次启动。
    blacklistExec(ev.actorPath);
    recordEvent(ev, VerdictAction::Block, VerdictSource::Heuristic, outcome);

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
        applyRegHardening(report); // 持久化反重建:清掉的自启动项即刻加入内核注册表硬拦
        quarantined = static_cast<int>(report.quarantinedFiles.size());
        removed = static_cast<int>(report.removedRegistryValues.size());
        skipped = static_cast<int>(report.skipped.size());
        bulwark::ipc::RemediationReportPayload payload = makeRemediationPayload(
            ev, QStringLiteral("外部信誉判定恶意:%1(%2/%3)").arg(label).arg(rep.malicious).arg(rep.totalEngines),
            report);
        // 情报补充摘要(供 UI「清理报告」展示:该样本已知会做什么 + 已生成多少主动拦截规则)。
        payload.intelSource = profile.source;
        payload.intelDroppedFiles = profile.droppedFileNames;
        payload.intelDroppedFilePaths = profile.droppedFilePaths;
        payload.intelDroppedFileHashes = profile.droppedFileHashes;
        payload.intelRegistryKeys = profile.registryKeysSet;
        payload.intelContactedIps = profile.contactedIps;
        payload.intelContactedDomains = profile.contactedDomains;
        payload.intelServices = profile.serviceNames;
        payload.intelProcessNames = profile.processNames;
        payload.intelMutexes = profile.mutexes;
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
                                                 resp.recommendation, resp.summary,
                                                 settings_ && settings_->aiScanBlockOnFailure);
    const QString verdictText = !resp.available
        ? QStringLiteral("不可用")
        : (resp.recommendation == VerdictAction::Block ? QString::fromUtf8("恶意")
                                                       : QString::fromUtf8("未见异常"));
    log_.info(QStringLiteral("AI 研判回执:%1 -> %2%3")
                  .arg(e.actorPath, verdictText,
                       resp.summary.trimmed().isEmpty() ? QString()
                                                        : (QStringLiteral(" · ") + resp.summary)));
    if (outcome.action != VerdictAction::Block)
        return;

    // 分流:必须区分「AI 确实判定恶意」与「因为问不到 AI 而按设置 fail-closed 拦截」。
    // outcome.rememberMalicious 只在前者为真(见 AiDecisionPolicy)。
    if (outcome.rememberMalicious) {
        onAiMalicious(e, resp.summary);
        return;
    }

    // fail-closed 路径(aiScanBlockOnFailure):按拦截处置,但【绝不】做那些以「已确认恶意」
    // 为前提的动作 —— 不记住哈希、不隔离载荷、不清持久化、更不把映像钉进内核禁止执行名单。
    // 后者会被内核写回注册表持久化、跨重启续拦,只因一次网络抖动就把用户的正常程序永久钉死,
    // 是完全不可接受的。这里只做可逆的当次处置。
    if (abortIfTrustedNow(e, QStringLiteral("AI 不可用(按设置拦截)")))
        return;
    SecurityEvent ev = e;
    const QString reason =
        QStringLiteral("AI 研判不可用,按设置(AI 不可用时按拦截处理)拦截本次灰区行为");
    log_.warning(reason + QStringLiteral(" [") + ev.actorPath + QStringLiteral("]"));
    ipc_->sendLog(reason);
    ev.riskReasons.append(reason);
    ipc_->sendBlock(ev);
    const bulwark::EnforcementOutcome enf = enforceBlock(ev, /*persistentBlacklist=*/false);
    recordEvent(ev, VerdictAction::Block, VerdictSource::Timeout, enf);
    writeAudit(ev, VerdictAction::Block, VerdictSource::Timeout);
}

void Worker::onAiMalicious(const SecurityEvent& e, const QString& summary) {
    if (abortIfTrustedNow(e, QStringLiteral("AI 研判")))
        return;
    SecurityEvent ev = e;
    ev.hasThreatIndicator = true;
    // 记住该已确认恶意哈希 —— 供兜底扫描复查在跑进程,漏网的也能被逮住。
    rememberMaliciousHash(e.actorHash);
    const QString reason = summary.trimmed().isEmpty()
        ? QString::fromUtf8("AI 研判判定恶意")
        : (QString::fromUtf8("AI 研判判定恶意:") + summary);
    log_.warning(reason + QStringLiteral(" [") + ev.actorPath + QStringLiteral("]"));
    ipc_->sendLog(reason);
    if (ev.riskScore < 90) ev.riskScore = 90;
    ev.riskReasons.append(QString::fromUtf8("AI 研判判定恶意"));
    ipc_->sendBlock(ev);
    // 先补偿处置(结束进程树)并据真实结果如实记录;关键系统进程由内部安全门槛保护。
    // 未能结束(进程已退出)时标 AlertedOnly——载荷仍会在下方 remediate 阶段被隔离失活。
    bulwark::EnforcementOutcome outcome = bulwark::EnforcementOutcome::AlertedOnly;
    if (killMalicious(ev.actorPid))
        outcome = bulwark::EnforcementOutcome::Terminated;
    // 执行前拦截:把该恶意映像加入内核禁止执行名单,挡住其被守护进程/持久化拉起时的再次启动。
    blacklistExec(ev.actorPath);
    recordEvent(ev, VerdictAction::Block, VerdictSource::Heuristic, outcome);

    // 隔离载荷 + 清除持久化。
    int quarantined = 0, removed = 0, skipped = 0;
    if (remediator_) {
        const RemediationReport report = remediator_->remediate(ev, chain_.collectTreeEvents(ev.actorPid));
        applyRegHardening(report); // 持久化反重建:清掉的自启动项即刻加入内核注册表硬拦
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
    // 本月配额已用尽就地返回。查下去只会拿到 querySucceeded=false 的 Unknown,而那个结果
    // 按「失败可重试」语义不进 ipCache_,于是同一个 IP 会被整月反复入队 —— 后台线程被无谓唤醒、
    // 诊断日志被刷爆。配额是个确定状态,提前问一次即可全部省掉(跨月自动恢复)。
    if (ipIntel_->ipIntelBudgetSpent())
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
    if (abortIfTrustedNow(e, QStringLiteral("微步 IP 情报")))
        return;
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
    // 据真实结果如实记录;未能结束(进程已退出)时标 AlertedOnly。
    const int pid = ev.originatorPid > 0 ? ev.originatorPid : ev.actorPid;
    bulwark::EnforcementOutcome outcome = bulwark::EnforcementOutcome::AlertedOnly;
    if (killMalicious(pid))
        outcome = bulwark::EnforcementOutcome::Terminated;

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
    recordEvent(ev, VerdictAction::Block, VerdictSource::Heuristic, outcome);
}

// 登记到结构化事件历史 + 实时 EventLogEntry(见 Worker.h 说明)。异步补偿处置与用户
// 裁决都经此,拦截记录 / 活动日志才看得到它们。
void Worker::recordEvent(const SecurityEvent& e, VerdictAction action, VerdictSource source,
                         bulwark::EnforcementOutcome enforcement) {
    ipc_->sendEventLog(e, action, source, enforcement);
    if (eventHistory_) {
        bulwark::ipc::EventLogPayload p;
        p.event = e;
        p.action = action;
        p.source = source;
        p.enforcement = enforcement;
        eventHistory_->add(p);
    }
    // ECS/SIEM 告警导出(appsettings 的 ExportEcsAlerts,默认关)。
    //
    // 这是 AlertExporter 唯一的调用点。在此之前整条链是孤岛:AlertExporter 从未被构造、
    // ExportEcsAlerts 只被 bindBool 解析一次就没人读、而 EcsAlertFormatter(11 KB 的完整 ECS
    // 字段映射)唯一的调用方就是 AlertExporter —— 三者互相引用,却没有任何外部入口。
    //
    // 放在 recordEvent 而不是 onEvent:所有终态路径(同步派发、用户裁决、超时兜底、信誉/AI/
    // IP 情报确认恶意、兜底扫描)都经过这里,导出才不会只覆盖一部分事件。
    if (alertExporter_)
        alertExporter_->exportAlert(e, bulwark::Verdict::forEvent(e, action, source));
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

//
// 侧载模块篡改检测(「白加黑」):主体目录里有没有「内嵌厂商签名但校验不过」的模块。
//
// 这条判据补的是一处实测漏检 —— 详见 SecurityEvent::tamperedModulePath 的说明:
// AOMEI 正规签名的 DigitalUnit.exe 当白壳,同目录被篡改的 QtCore4.dll 是黑件,靠计划任务
// 每 19 分钟拉起,而每次的裁决都是「签名健康 -> 放行,风险 5」。内核的 ImageLoad 上报只覆盖
// \Temp\ 与 \Users\Public\(为防事件风暴刻意收窄),所以那个 DLL 的加载根本没产生过事件。
// 与其去放宽内核侧的宽口径上报(会重新引入事件风暴),不如在这条【低频】路径上主动看一眼。
//
// 成本控制,四道:
//   1) 只在主体【签名且签名健康】时才扫 —— 这正是「白加黑」的前提。未签名主体本来就会被
//      无签名 / 可疑目录 / 首见等一堆信号顶起来,不需要额外 I/O;
//   2) 跳过标准安装目录(Program Files / Windows)—— 那里写入需要管理员,不是投递落点;
//   3) 单目录最多验 kMaxVerify 个模块,避免撞上带几百个 DLL 的大应用时线性铺开;
//   4) 结果【按目录缓存】—— 那个样本每 19 分钟起一次,不缓存就等于每 19 分钟重扫一遍。
//
void Worker::detectSideloadedTamperedModule(bulwark::SecurityEvent& e) {
    constexpr int kMaxVerify = 40;       // 单目录最多验签这么多个模块
    constexpr int kMaxCache  = 512;      // 缓存目录数上限(超了整体清空,避免无界增长)

    // 「白加黑」的前提:壳是签名健康的。主体自己就失配 / 无签名的,交给既有判据。
    if (!e.actorSigned || e.signatureMismatch)
        return;
    const QString path = e.actorPath;
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return;

    const QString dir = QFileInfo(path).absolutePath();
    if (dir.isEmpty())
        return;

    // 标准安装目录跳过:普通用户写不进去,不是投递落点(与 ThreatDetector 文件膨胀那条
    // 「位于安装目录的大文件是安装器放的」同一判断)。
    QString dirLower = dir.toLower();
    dirLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (dirLower.contains(QLatin1String("\\program files\\")) ||
        dirLower.contains(QLatin1String("\\program files (x86)\\")) ||
        dirLower.startsWith(QLatin1String("c:\\windows\\")))
        return;

    const QString key = dirLower;
    const auto cached = tamperScanCache_.constFind(key);
    if (cached != tamperScanCache_.constEnd()) {
        if (!cached.value().isEmpty())
            e.tamperedModulePath = cached.value();
        return;
    }

    QString found;
    QDir d(dir);
    const QStringList filters{ QStringLiteral("*.dll"), QStringLiteral("*.exe"),
                               QStringLiteral("*.ocx"), QStringLiteral("*.cpl") };
    const QFileInfoList entries = d.entryInfoList(filters, QDir::Files | QDir::NoSymLinks, QDir::Name);
    int verified = 0;
    for (const QFileInfo& fi : entries) {
        if (verified >= kMaxVerify)
            break;
        // 主体自己已经单独验过了(上面的 actorSigned / signatureMismatch)。
        if (fi.absoluteFilePath().compare(path, Qt::CaseInsensitive) == 0)
            continue;
        ++verified;
        if (ProcessInspector::isSignatureMismatch(fi.absoluteFilePath())) {
            found = fi.absoluteFilePath();
            break;
        }
    }

    if (tamperScanCache_.size() >= kMaxCache)
        tamperScanCache_.clear();
    tamperScanCache_.insert(key, found);   // 空串 = 扫过且干净,下次直接跳过

    if (!found.isEmpty()) {
        e.tamperedModulePath = found;
        log_.warning(QStringLiteral("侧载模块篡改:主体 %1 签名健康,但同目录 %2 内嵌签名校验不通过"
                                    "(签名壳 + 被篡改模块 = 白加黑)。")
                         .arg(path, found));
    }
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
        vtQueuedIds_.insert(e.id);
        // 持锁内先推「排队中」:保证 UI 收到的第一条是本次扫描的排队态,而非某条空闲 worker 抢先
        // 取走任务后推来的「查询中」(否则会出现查询中→排队中的回跳)。推送仅编组到主线程,不阻塞。
        publishVtQueued(e);
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
        vtQueuedIds_.insert(pkgEvent.id);
        publishVtQueued(pkgEvent); // 双击 MSI:入队即推「排队中」即时反馈(持锁内,先于 worker 取到任务)
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

void Worker::maybeVerifyMemoryInjection(const bulwark::SecurityEvent& e) {
    // 内存防护 VT 验证:内核 ObRegisterCallbacks 已在打开句柄时剥离写内存/远程线程/
    // 挂起/结束权限,注入已被阻止。这里只做追溯验证——确认注入源是否恶意,以便补偿处置。
    const QString hash = e.actorHash;
    if (hash.size() != 64) {
        // 哈希为空时跳过(注入事件可能来自短命进程,未完成签名/哈希富化)。
        if (!e.actorPath.isEmpty() && e.actorPid > 4)
            log_.debug(QStringLiteral("内存防护 VT 验跳过(无哈希):%1 PID %2")
                           .arg(e.actorPath).arg(e.actorPid));
        return;
    }
    {   QMutexLocker lk(&memVtMx_);
        if (memVtCachedMalicious_.contains(hash))
            return; // 已确认过恶意,不必重复查
    }
    if (!memVtBucket_.tryConsume(false)) {
        log_.debug(QStringLiteral("内存防护 VT 验证跳过(超限流,默认 4/小时):%1").arg(hash.left(12)));
        return;
    }
    // 同步查 VT(限流 4/小时,1 次 HTTP 往返对主线程影响可忽略);priority=true 占用 VT 预留的
    // 优先级配额,内存防护/反注入验证尽量不被双击查杀等普通查询挤占。
    const bulwark::FileReputation rep = reputation_->queryNow(hash, /*priority=*/true);
    if (!rep.querySucceeded) {
        log_.debug(QStringLiteral("内存防护 VT 验证查询失败:%1").arg(hash.left(12)));
        return;
    }
    if (rep.verdict != bulwark::ReputationVerdict::Malicious) {
        log_.debug(QStringLiteral("内存防护 VT 验证:非恶意(%1/%2):%3")
                       .arg(rep.malicious).arg(rep.totalEngines).arg(hash.left(12)));
        return;
    }
    // VT 确认恶意:记缓存 + 补偿处置(注入已阻止,但仍需结束作恶进程树 + 隔离载荷)。
    {
        QMutexLocker lk(&memVtMx_);
        memVtCachedMalicious_.insert(hash);
        if (memVtCachedMalicious_.size() > 1024) {
            // 有界缓存:移除最旧的 128 条。
            auto it = memVtCachedMalicious_.begin();
            for (int i = 0; i < 128 && it != memVtCachedMalicious_.end(); ++i)
                it = memVtCachedMalicious_.erase(it);
        }
    }
    log_.warning(QStringLiteral("内存防护 VT 验证:注入源确认恶意(%1/%2),Hash=%3,路径=%4")
                     .arg(rep.malicious).arg(rep.totalEngines).arg(hash.left(16)).arg(e.actorPath));
    // 编组回主线程补偿处置(与 onReputationMalicious 共享路径)。
    QMetaObject::invokeMethod(this, [this, e, rep] {
        onReputationMalicious(e, rep);
    }, Qt::QueuedConnection);
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
    // 入队时是否已推过「排队中」卡片(仅双击路径会推)。取出该标记:命中去重短路时需用缓存结论
    // 收尾这张卡片,否则「排队中」会一直悬着(直到 UI 兜底超时才关);正常流程则由后续各阶段推送收尾。
    bool queuedCardShown;
    {
        QMutexLocker lk(&vtMx_);
        queuedCardShown = vtQueuedIds_.remove(e.id);
    }
    // 合成的安装包扫描等场景哈希为空:后台补算 SHA-256,以便先走「按哈希查」的省流路径。
    if (e.actorHash.isEmpty() && !e.actorPath.isEmpty() && QFileInfo::exists(e.actorPath))
        e.actorHash = QuarantineManager::tryComputeSha256(e.actorPath);
    const QString hash = e.actorHash;

    // 去重:近期已扫过的哈希复用结论(确定性结论永久去重;未收录 24h 内去重,不重复上传)。
    if (vtHistory_ && !hash.isEmpty()) {
        const std::optional<bulwark::VtScanRecord> prior =
            vtHistory_->tryGetFinishedByHash(hash, kVtUnknownDedupTtlSec);
        if (prior.has_value()) {
            // 若入队时已弹「排队中」卡片,用缓存结论收尾它(以本次 id/路径关联),避免卡片悬空;
            // 结论已在历史里,故 persistTerminal=false 不以新 id 重复落盘。未推过卡片的后台路径
            //(落盘即扫)保持静默,不打扰。
            if (queuedCardShown) {
                bulwark::VtScanRecord done = *prior;
                done.id = e.id;
                done.filePath = e.actorPath;
                done.fileName = QFileInfo(e.actorPath).fileName();
                if (done.source.isEmpty())
                    done.source = QStringLiteral("\xe5\x8f\x8c\xe5\x87\xbb"); // 双击
                done.stage = bulwark::VtScanStage::Completed;
                publishVtRecord(done, /*persistTerminal=*/false);
            }
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
    record.message = QStringLiteral("正在查询中央服务器是否已收录…");
    publishVtRecord(record);

    // 云扫描分级链路(顺序刻意如此,先便宜/覆盖广的,再贵的):
    //   0) 本地分级缓存  —— 零往返、零配额
    //   1) 中央服务器    —— 机队共享缓存 + 服务端持有的 Key,不消耗本机任何源配额
    //   2) VirusTotal    —— 70+ 引擎,单源覆盖最广
    //   3) 其他情报源    —— 仅在 VT 未收录/失败时才查(已排除 VT,不重复扣它的额度)
    //   4) 上传整文件    —— 只有以上全都答不出、且文件在手时才做(最贵,分钟级)
    //   5) 回传服务器    —— 把本地新查到的结论同步回去,让整个机队共享
    bulwark::FileReputation rep;
    rep.sha256 = hash;
    rep.verdict = bulwark::ReputationVerdict::Unknown;
    // 「已有结论」判据:权威成功且不是 Unknown。Unknown 一律继续往下走(直到上传)。
    bool foundByHash = false;
    // 结论是否已在服务器那边(服务器直接给的,或本地缓存里那条此前就来自/已同步给服务器):
    // 决定收尾时要不要回传。刻意不为「缓存命中」再发一次回传 —— 否则每次双击同一个程序都要
    // 白发一遍。代价是:若当初回传恰好失败(服务器离线),这条结论要等缓存过期后才有机会重传。
    bool alreadyShared = false;

    // 0) 本地分级 TTL 缓存(含此前经服务器/VT/其他源得到并缓存的结论)。命中即刻出结论,
    //    连一次网络往返都不用。注意只在「确有结论」时短路:缓存里的 Unknown 负缓存不作数,
    //    否则未收录文件会永远走不到上传那一步(上传的去重另由 vtHistory 那层负责)。
    if (!hash.isEmpty() && reputation_) {
        const auto cached = reputation_->tryGetFresh(hash);
        if (cached.has_value() && cached->querySucceeded
            && cached->verdict != bulwark::ReputationVerdict::Unknown) {
            rep = *cached;
            foundByHash = true;
            alreadyShared = true;
        }
    }

    // 1) 先问中央服务器有没有收录(只问服务器,不触发它的本地回退 —— 本地各级由下面自己按
    //    顺序编排)。服务器命中的好处:整个机队共享一份情报,且完全不消耗本机 VT/其他源配额。
    //
    //    这一步有三种结局,必须分开记,不能都讲成「服务器没有」:
    //      · 已收录     -> 直接采用,后面每一级都跳过,一个本地密钥都不动;
    //      · 权威未收录 -> 服务器确实答了、确实没有这条哈希 -> 这才轮到本地密钥;
    //      · 没问到     -> 未启用 / 熔断冷却中 / 本机请求预算用尽 / HTTP·JSON 失败
    //                     (判据见 queryServerOnly 的 answered 出参)。照样回退本地密钥
    //                     (保护不能退化),但【绝不能对外讲成「服务器未收录」】—— 两件事
    //                     混成一句之后,「这次到底有没有走服务器」在日志和卡片上就再也查不清了,
    //                     而「云扫描是否真的服务器优先」恰恰只能从这里看出来。
    bool serverAnswered = false; // 服务器给出了可采信的权威回复(未必有实据)
    if (!foundByHash && !hash.isEmpty() && repProxy_) {
        bool hasRecord = false;
        const bulwark::FileReputation srv =
            repProxy_->queryServerOnly(hash, /*priority=*/false, &hasRecord, &serverAnswered);
        if (hasRecord) {
            rep = srv;
            if (rep.source.isEmpty()) rep.source = QStringLiteral("Proxy");
            foundByHash = true;
            alreadyShared = true;
        }
        log_.info(QStringLiteral("云扫描 %1:中央服务器%2")
                      .arg(hash.left(12),
                           hasRecord
                               ? QStringLiteral("已收录(%1/%2 源=%3),本地密钥一个都不动")
                                     .arg(srv.malicious).arg(srv.totalEngines)
                                     .arg(srv.source.isEmpty() ? QStringLiteral("-") : srv.source)
                               : serverAnswered
                                     ? QStringLiteral("未收录,转本地密钥查询")
                                     : QStringLiteral("未应答(未启用/熔断/请求预算用尽/查询失败),转本地密钥查询")));
    }

    // 2) 服务器没有收录(或这次没问到)-> 用本机密钥查 VirusTotal(按哈希,秒级;省去对已收录
    //    文件的重复上传)。卡片文案按上一步的真实结局区分,别把「没问到」写成「未收录」。
    bool vtAnswered = false; // VT 权威作答(区别于配额/网络/鉴权失败),供下一级文案用
    if (!foundByHash && !hash.isEmpty()) {
        record.message = serverAnswered
            ? QStringLiteral("服务器未收录,正在查询 VirusTotal…")
            : QStringLiteral("服务器暂未应答,正在查询 VirusTotal…");
        publishVtRecord(record);
        const bulwark::FileReputation vtRep = vt_->query(hash, false);
        vtAnswered = vtRep.querySucceeded;
        if (vtRep.querySucceeded && vtRep.verdict != bulwark::ReputationVerdict::Unknown) {
            rep = vtRep;
            if (rep.source.isEmpty()) rep.source = QStringLiteral("VirusTotal");
            foundByHash = true;
        }
    }

    // 3) VirusTotal 未收录 / 查询失败(配额·网络)时,按哈希回退到其他已启用情报源
    //    (MalwareBazaar / OTX / 微步 / MetaDefender / HybridAnalysis),由聚合器并行查询并
    //    合并取最强结论。刻意【排除 VirusTotal】:聚合器里的 VT 与上一级用的是同一个客户端
    //    实例,再查一遍会真的扣两次额度、还多等一次往返。这些源只能按哈希查(无法扫描未知
    //    文件),故放在昂贵的 VT 上传【之前】:一旦命中就无需上传;即便 VT 挂了也仍有结论。
    if (!foundByHash && !hash.isEmpty() && repAggregate_) {
        record.message = vtAnswered
            ? QStringLiteral("VirusTotal 未收录,正在查询其他情报源…")
            : QStringLiteral("VirusTotal 查询未成功,正在查询其他情报源…");
        publishVtRecord(record);
        const bulwark::FileReputation alt =
            repAggregate_->queryExcluding(hash, false, QStringLiteral("VirusTotal"));
        if (alt.querySucceeded && alt.verdict != bulwark::ReputationVerdict::Unknown) {
            rep = alt;            // 采用回退结论(alt.source 已标注命中源)
            foundByHash = true;
        }
    }

    // 4) 全都未收录 -> 上传整文件云端多引擎扫描,进度经回调推 UI。
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

    // 5) 回填 + 回传。
    //    · 本地分级缓存:本链路自行编排了各级查询(没走 queryNow),故须显式回填,否则同一
    //      哈希的后续事件与后台信誉队列会把整条链路重跑一遍。
    //    · 中央服务器:把「服务器当时没有、本地查到/上传扫出来」的结论同步回去,让整个机队
    //      共享。上传扫描得到的结论尤其值钱 —— 服务器凭哈希查不到,只有拿到文件的端点才能
    //      产出。alreadyShared 为真时不回传(那本来就是服务器给的)。回传是 fire-and-forget,
    //      内部派线程发送,不拖慢这次扫描的收尾;只回传确有实据的结论(0 引擎的 clean 与
    //      Unknown 会被 maybeSyncToServer 挡掉)。
    if (!rep.sha256.isEmpty() && rep.querySucceeded) {
        if (reputation_)
            reputation_->storeResult(rep);
        if (!alreadyShared && repProxy_)
            repProxy_->maybeSyncToServer(rep);
    }

    // 6) 威胁情报共享(默认关):这里只处理【可疑】样本 —— 恶意样本走
    //    confirmReputationMaliciousAsync(见下方),那条路上行为画像本来就要拉,
    //    在那里顺路留一份即可,不必在这里重复请求一次 behaviour_summary 白花 VT 配额。
    if (settings_ && settings_->cloudBehaviorUploadEnabled && intelContrib_ && reputation_
        && rep.querySucceeded && rep.verdict == bulwark::ReputationVerdict::Suspicious
        && !hash.isEmpty()) {
        retainThreatIntel(rep, reputation_->fetchBehaviorProfile(hash));
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
        // 经中央服务器命中时 rep.source 形如 "Proxy:VirusTotal" —— 「Proxy:」只是取数管路的细节,
        // 对用户没有意义。展示前剥掉:服务器转来的 VT 结论就和本地直连 VT 一样不带来源后缀,
        // 其他源只显示源名本身。不剥的话这条消息会长出一行,把居中查毒卡片的结论挤到卡片外面。
        QString srcName = rep.source.trimmed();
        if (srcName.startsWith(QLatin1String("Proxy:"), Qt::CaseInsensitive))
            srcName = srcName.mid(6).trimmed();
        else if (srcName.compare(QLatin1String("Proxy"), Qt::CaseInsensitive) == 0)
            srcName.clear(); // 服务器未标注底层源:说不清是谁给的结论,那就不标
        const bool fromVt = srcName.isEmpty() || srcName == QStringLiteral("VirusTotal");
        const QString srcSuffix = fromVt ? QString()
                                         : QStringLiteral(" · 来源 ") + srcName;
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

void Worker::publishVtQueued(const bulwark::SecurityEvent& e) {
    // 入队即推一条「排队中」记录:双击后立刻在 UI(居中查毒卡片 + 云信誉查询历史行)出现,不必等
    // 后台 worker 取到任务、算完哈希、走到「查询中」才显示 —— 在有长耗时上传占用线程时那可能要等
    // 数分钟。与后续各阶段记录同 id、同路径,UI 据此更新同一张卡片/同一行。非终态,不落历史。
    bulwark::VtScanRecord record;
    record.id = e.id;
    record.sha256 = e.actorHash;
    record.filePath = e.actorPath;
    record.fileName = QFileInfo(e.actorPath).fileName();
    record.source = QStringLiteral("\xe5\x8f\x8c\xe5\x87\xbb"); // 双击
    record.stage = bulwark::VtScanStage::Queued;
    record.message = QStringLiteral("已加入云查杀队列,排队中…");
    publishVtRecord(record);
}

void Worker::publishVtRecord(const bulwark::VtScanRecord& record, bool persistTerminal) {
    bulwark::VtScanRecord r = record;
    r.timestampUtc = QDateTime::currentDateTimeUtc();
    // 仅「终态」记录(Completed/Error)进持久历史:中间进度(Queued/Querying/Uploading/Analyzing)
    // 只用于 UI 实时卡片,不落盘——否则服务中途重启/扫描异常会在历史里留下永久「进行中」
    // 幽灵(空文件/空哈希的非终态记录)。历史只保存有结论的那一条。persistTerminal=false 时
    // 即使终态也不落盘(命中去重收尾卡片:结论已在历史里,避免以新 id 重复落一条)。
    if (persistTerminal && vtHistory_ && r.isTerminal())
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

// ============================ 兜底扫描(catch-all sweep)============================
// 目的:实时链路可能漏检【已确认恶意】的进程 —— 遥测丢包、云端确认迟到、或进程在防护启动前
// 就已在跑。这里用一条后台线程周期性枚举在跑进程,按【已确认恶意情报】(引擎记住的恶意哈希
// + 信誉缓存判恶意)比对,命中即编组回主线程补处置(封禁 PID + 结束进程树 + 隔离载荷)。
// 纯用户态,复用既有 killMalicious(内含 banProcess)/ blacklistExec / remediate,不改驱动。
// 只匹配【已确认恶意】(非启发式),误报趋近于零。

void Worker::startMaliciousSweep() {
    if (sweepRunning_.load())
        return;
    seedMaliciousHashesFromRules(); // 先把持久化的记忆恶意哈希灌进快照(重启后仍能兜底)
    sweepRunning_.store(true);
    sweepWorker_ = std::thread([this] {
        try {
            sweepLoop();
        } catch (...) {
            // 后台兜底线程绝不因异常带崩服务。
        }
    });
    log_.info(QString::fromUtf8("兜底扫描已启动:定期复查在跑进程,逮住漏网的已确认恶意。"));
}

void Worker::rememberMaliciousHash(const QString& sha256) {
    if (sha256.size() != 64)
        return;
    QMutexLocker lk(&maliciousHashMx_);
    confirmedMaliciousHashes_.insert(sha256.toLower());
}

void Worker::seedMaliciousHashesFromRules() {
    if (!engine_)
        return;
    const QVector<bulwark::DefenseRule> rules = engine_->getRules();
    QMutexLocker lk(&maliciousHashMx_);
    for (const bulwark::DefenseRule& r : rules) {
        // 只吸纳「拦截型」规则里的哈希(记忆恶意 / 情报黑名单);放行/信任规则不纳入。
        if (r.action != VerdictAction::Block)
            continue;
        for (const QString& h : r.actorHashes)
            if (h.size() == 64)
                confirmedMaliciousHashes_.insert(h.toLower());
    }
}

bool Worker::isSweepExemptPath(const QString& path) {
    if (path.isEmpty())
        return true;
    const QString p = path.toLower();
    // 系统目录(WRP/高 ACL、微软签名,不会命中恶意情报且数量大)+ 本产品自身 -> 免扫,省开销防误伤。
    if (p.contains(QStringLiteral("\\windows\\system32\\")) ||
        p.contains(QStringLiteral("\\windows\\syswow64\\")) ||
        p.contains(QStringLiteral("\\windows\\winsxs\\")) ||
        p.contains(QStringLiteral("bulwark")))
        return true;
    return false;
}

void Worker::sweepLoop() {
    // 后台线程:严禁直接碰主线程 Qt 对象(engine_/ipc_ 等)。只用线程安全的哈希快照
    //(maliciousHashMx_ 保护)+ 信誉只读缓存;命中后 QueuedConnection 编组回主线程处置。
    QHash<QString, QString> pathHashCache; // path -> 大写 SHA-256(本线程私有,避免重复哈希)

    // 首轮延迟:等握手/规则加载/信誉预热稳定后再扫,减少启动期抖动。
    for (int i = 0; i < 15 && sweepRunning_.load(); ++i)
        std::this_thread::sleep_for(std::chrono::seconds(1));

    while (sweepRunning_.load()) {
        const bool enabled = !settings_ || settings_->protectionEnabled; // 总开关关闭时不扫
        if (enabled) {
            const QList<int> pids = ProcessInspector::enumeratePids();
            for (int pid : pids) {
                if (!sweepRunning_.load())
                    break;
                const QString path = ProcessInspector::tryGetProcessImagePath(pid);
                if (path.isEmpty() || isSweepExemptPath(path))
                    continue;

                QString hashU = pathHashCache.value(path);
                if (hashU.isEmpty()) {
                    hashU = ProcessInspector::tryComputeSha256(path); // 大写十六进制
                    if (!hashU.isEmpty())
                        pathHashCache.insert(path, hashU);
                }
                if (hashU.size() != 64)
                    continue;

                // —— 按【已确认恶意情报】比对:引擎记住的恶意哈希(小写)+ 信誉缓存判恶意 ——
                QString label;
                bool malicious = false;
                {
                    QMutexLocker lk(&maliciousHashMx_);
                    if (confirmedMaliciousHashes_.contains(hashU.toLower())) {
                        malicious = true;
                        label = QString::fromUtf8("已记忆恶意哈希");
                    }
                }
                if (!malicious && reputation_) {
                    const std::optional<bulwark::FileReputation> rep = reputation_->tryGetCached(hashU);
                    if (rep && rep->isMalicious()) {
                        malicious = true;
                        label = rep->threatLabel.trimmed().isEmpty()
                                    ? QString::fromUtf8("信誉判定恶意")
                                    : rep->threatLabel;
                    }
                }
                if (!malicious)
                    continue;

                // 命中:构造观测型 ProcessCreate 事件,编组回主线程做真正处置。
                SecurityEvent e;
                e.type = bulwark::EventType::ProcessCreate;
                e.actorPid = pid;
                e.actorPath = path;
                e.target = path;
                e.actorHash = hashU;
                e.userModeObserved = true;
                e.hasThreatIndicator = true;
                e.riskScore = 95;
                e.detail = label;
                QMetaObject::invokeMethod(
                    this, [this, e] { handleSweptMalicious(e, VerdictSource::Heuristic); },
                    Qt::QueuedConnection);
            }
        }
        // 每轮间隔 ~60s,1s 步进以便及时响应停止。
        for (int i = 0; i < 60 && sweepRunning_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void Worker::handleSweptMalicious(const SecurityEvent& e, VerdictSource source) {
    // 主线程:与信誉/AI 确认恶意共用同一处置路径 —— 封禁 PID(killMalicious 内已 banProcess)
    // + 结束进程树 + 执行前拦截入内核禁运名单 + 隔离载荷/清除持久化。
    if (abortIfTrustedNow(e, QStringLiteral("兜底扫描")))
        return;
    SecurityEvent ev = e;
    ev.hasThreatIndicator = true;
    const QString msg = QString::fromUtf8("兜底扫描:发现漏网的已确认恶意进程 PID=%1 %2(%3)—— 补封禁+结束+隔离。")
                            .arg(QString::number(ev.actorPid), ev.actorPath, ev.detail);
    log_.warning(msg);
    ipc_->sendLog(msg);
    if (ev.riskScore < 95)
        ev.riskScore = 95;
    ev.riskReasons.append(QString::fromUtf8("兜底扫描复查:已确认恶意"));
    ipc_->sendBlock(ev);

    // 结束仍在运行的进程树(killMalicious 内已先 banProcess 封禁 PID);未能结束(已退出)标 AlertedOnly。
    bulwark::EnforcementOutcome outcome = bulwark::EnforcementOutcome::AlertedOnly;
    if (killMalicious(ev.actorPid))
        outcome = bulwark::EnforcementOutcome::Terminated;
    // 执行前拦截:恶意映像加入内核禁止执行名单,挡住其被守护进程/持久化再次拉起。
    blacklistExec(ev.actorPath);
    recordEvent(ev, VerdictAction::Block, source, outcome);

    // 隔离载荷 + 清除持久化(remediateIfMalicious 内对 source==Heuristic 会执行补救)。
    remediateIfMalicious(ev, bulwark::Verdict::forEvent(ev, VerdictAction::Block, source));
}

} // namespace bulwark::service
