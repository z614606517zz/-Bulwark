#include "bulwark/service/Worker.h"
#include "bulwark/service/IpcServer.h"
#include "bulwark/service/EventSource.h"
#include "bulwark/service/RuleStore.h"
#include "bulwark/service/AuditLog.h"
#include "bulwark/service/FirstSeenStore.h"
#include "bulwark/service/QuarantineManager.h"
#include "bulwark/service/UserModeProcessContainment.h"
#include "bulwark/service/SystemHardening.h"
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
#include "bulwark/engine/ScriptAnalyzer.h"

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

// 情报来源的展示名:把 FileReputation::source 里的取数管路细节翻成用户看得懂的一句。
//
// 为什么必须翻:云查毒刻意「先问中央服务器有没有收录,没收录才动本机 VT 密钥」,于是
//「这条结论是服务器给的还是本机直连查的」是用户唯一能验证该策略生效的地方。而线上取值形如
// "Proxy:VirusTotal"(服务器转来的 VT 结论)/ "Proxy"(服务器未标注底层源)/ "VirusTotal" /
// "MalwareBazaar" …… 其中 "Proxy:" 这个前缀对用户毫无意义,却正好盖住了那个区分。
// 早先的做法是把前缀整段剥掉,结果服务器命中与本机直连 VT 命中在界面上一模一样。
QString intelSourceDisplayName(const QString& raw) {
    const QString s = raw.trimmed();
    if (s.startsWith(QLatin1String("Proxy:"), Qt::CaseInsensitive)) {
        const QString under = s.mid(6).trimmed();
        return under.isEmpty() ? QStringLiteral("中央服务器")
                               : QStringLiteral("中央服务器·") + under;
    }
    if (s.compare(QLatin1String("Proxy"), Qt::CaseInsensitive) == 0)
        return QStringLiteral("中央服务器"); // 服务器没说底层是谁给的,那就只讲到服务器这一层
    return s;
}

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

//
// 证据链里【硬恶意指标】的条数(按来源去重)。
//
// 用途只有一处:判断「静默模式要不要把询问升级成拦截」。那里原先的条件是
// `hasThreatIndicator && riskScore >= Suspicious(50)`,而 hasThreatIndicator 是一个布尔的
// 或运算 —— 任何一处判据置了它就为真,凑不凑得出互证完全看不出来。于是「一个判据 + 一堆
// 软信号凑到 50 分」与「三个独立维度都指向恶意」在那条闸上无法区分,前者被当后者处置
//(结束进程树 + 隔离 + 足迹清理),而前者恰恰是误报的典型形状。
//
// 按 source 去重的理由:同一个分析器会为一次判定写多行理由(LolbinAnalyzer / ScriptAnalyzer
// 常常一次写三四条),不去重的话一个维度就能自己凑出「2 条硬证据」,等于没有收紧。
//
int hardEvidenceSourceCount(const bulwark::SecurityEvent& e) {
    QSet<QString> sources;
    for (const bulwark::Evidence& ev : e.evidenceChain)
        if (ev.kind == bulwark::EvidenceKind::HardIndicator)
            sources.insert(ev.source);
    return sources.size();
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

    // 弹窗超时巡检:1s 粒度足够(超时本身是秒级配置),且空 pending_ 时开销可忽略。
    // 用定时器而不是给每条事件各起一个 QTimer —— 后者在事件突发时会造成大量定时器对象。
    promptTimer_ = new QTimer(this);
    promptTimer_->setInterval(1000);
    connect(promptTimer_, &QTimer::timeout, this, &Worker::onPromptTimeoutTick);
    promptTimer_->start();

    // 污点候选的验签 + 哈希:单线程足够(每次拦截最多 kTaintMaxPerBlock 个文件),
    // 且串行执行让「同一批候选」的注入顺序与拦截顺序一致。
    taintPool_.setMaxThreadCount(1);
}

// unique_ptr<ThreatRemediator> 的析构需在此(完整类型可见处)生成。
Worker::~Worker() {
    // 污点后台任务:丢掉排队的、等在跑的收尾。任务只经 QueuedConnection 回调 this,
    // 本对象析构时 Qt 会连同投递给它的未处理事件一起清掉,不会悬空回调。
    taintPool_.clear();
    taintPool_.waitForDone();
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
    // ServerOnly 下别再把「-> VirusTotal -> 其他情报源 -> 上传扫描」写进日志:那三级压根不走。
    // 启动日志是排查「这台机器到底会不会外发」的第一现场,写错等于把排查引到反方向。
    if (proxy && proxy->isServerOnly()) {
        log_.info(QStringLiteral("云扫描链路(本机不动用第三方情报源):本地缓存 -> 中央服务器是否已收录;"
                                 "不用本机密钥查各情报源、不上传文件,未收录即无云端结论。"));
        return;
    }
    log_.info(QStringLiteral("云扫描分级链路:本地缓存 -> %1 -> VirusTotal -> %2 -> 上传扫描%3。")
                  .arg(proxy ? QStringLiteral("中央服务器") : QStringLiteral("(无中央服务器)"),
                       aggregate ? QStringLiteral("其他情报源") : QStringLiteral("(无其他源)"),
                       proxy ? QStringLiteral(";新结论回传服务器") : QString()));
}

QString Worker::describe(const SecurityEvent& e, VerdictAction action) const {
    QString act = action == VerdictAction::Block ? QString::fromUtf8("\xe6\x8b\xa6\xe6\x88\xaa")
                : action == VerdictAction::Ask   ? QString::fromUtf8("\xe8\xaf\xa2\xe9\x97\xae")
                                                 : QString::fromUtf8("\xe6\x94\xbe\xe8\xa1\x8c");
    // 内核已在发生前阻断的操作,绝不能按用户态结论写成「放行」。
    //
    // 内核基线(自我保护 / 命令行硬拦 / 本地已知恶意集)与用户态 RuleEngine 是两条【独立】
    // 的决策路径:内核同步决定并当场执行,用户态只是事后收到通知、再各自算一遍。两边结论
    // 不一致是正常的,而生效的永远是内核那条。
    //
    // 不区分的后果是日志会骗人 —— 实测:安装更新时备份被内核自我保护拒绝(Copy-Item 报
    // 「访问被拒绝」),而同一时刻审计日志里十几条都写着「放行 FileDelete ...」。排查时
    // 照着日志走会得出「没被拦」的错误结论,实际白跑一轮。
    if (e.kernelBlocked && action != VerdictAction::Block)
        act = QString::fromUtf8("\xe5\x86\x85\xe6\xa0\xb8\xe5\xb7\xb2\xe6\x8b\xa6")   // 内核已拦
            + QString::fromUtf8("\x28") + act + QString::fromUtf8("\x29");            // (用户态结论)
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

    // 待机中(「退出界面即停止防护」且界面不在跑)-> 什么都不做,连日志与审计都不记。
    //
    // 走到这里的只可能是「事件源停干净之前已经入队」的残余:待机会把 ETW 会话与内核源都停掉。
    // 刻意不像下面总开关那条路径那样逐条记成「放行」—— 待机期间本产品没有在观测,把这些残余
    // 记进事件历史等于伪造一段「我看着呢」的记录,那比没有记录更坏。
    if (protectionSuspended_.load())
        return;

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
    //(外部信誉 / 微步 IP 情报 / VirusTotal),仅保留记录与放行。
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

    // 静默模式:把「询问」降级为放行,但确定性高危不降级——反而升级为拦截 + 隔离。
    // 「确定性高危」= 风险 >= 高危线,或 >= 2 个不同来源的硬恶意指标(互证)。静默只压低置信
    // 打扰,绝不放过银狐等投递链里的高危行为(注入 / 持久化 / 关杀软 / 侧载等);但也不比引擎
    // 自己的拦截线更激进 —— 取舍与实测误伤见下面那段。无硬指标的软信号仍照常放行。
    VerdictAction action = v.action;
    VerdictSource source = v.source;
    if (action == VerdictAction::Ask && settings_ && settings_->silentMode) {
        //
        // 【升级为拦截必须有互证,不能只有「一个硬指标 + 50 分」】
        //
        // 原条件是 `hasThreatIndicator && riskScore >= Suspicious(50)`。两个问题:
        //   ① hasThreatIndicator 只是个布尔或运算 —— 一个判据置了它就为真,所以
        //      「一处判据 + 一堆软信号凑够 50 分」和「三个独立维度都指向恶意」在这条闸上
        //      完全等价,而前者正是误报的典型形状;
        //   ② 这条闸比引擎自己的拦截线【更松】:RuleEngine 第 10 步要 riskScore >= 80 才判
        //      Block,50~79 这一档它明确给的是 Ask(「拿不准,该问用户」)。静默模式的语义是
        //      「不要为决策打扰我」,它不该顺便把引擎拿不准的那一档改成结束进程树 —— 后面紧跟
        //      的是隔离载荷、足迹清理、连带处置发起方,一次误判的代价远不止少弹一个窗。
        //
        // 实测这条闸吃掉的东西:winget 装的官方 Inno Setup(`innosetup-6.7.3.tmp`,70 分 +
        // 一个来自「批量改写」的硬指标)被结束进程树;powershell 跑构建脚本同样命中。
        //
        // 现在两条路任一成立才升级:
        //   · 风险 >= HighRisk(80) —— 与引擎自己的拦截线对齐,不再比它更激进;
        //   · 或者有 >= 2 个【不同来源】的硬指标 —— 那就是互证成立,即便分数没到 80
        //     也足以在无人值守时自行处置(银狐投递链的典型形态:侧载 + 注入 + 持久化)。
        // 其余情况按静默模式本来的语义放行并留痕,用户随时能在日志/历史里看到它。
        //
        const int hardSources = hardEvidenceSourceCount(e);
        const bool corroborated =
            e.riskScore >= bulwark::engine::ThreatDetector::HighRisk || hardSources >= 2;
        if (e.hasThreatIndicator && e.riskScore >= bulwark::engine::ThreatDetector::Suspicious
            && corroborated) {
            action = VerdictAction::Block;
            source = VerdictSource::Heuristic;
            log_.warning(QStringLiteral("静默模式:确定性高危升级为拦截(硬指标 %1 个来源 + 风险 %2):%3")
                             .arg(hardSources).arg(e.riskScore).arg(e.actorPath));
        } else if (e.hasThreatIndicator
                   && e.riskScore >= bulwark::engine::ThreatDetector::Suspicious) {
            // 够 50 分、有硬指标,但没凑到互证。这一条【必须留日志】:它是本次改动放过的那一档,
            // 静默模式又不会弹窗,不说出来就等于无声地改变了处置强度而没人知道。
            action = VerdictAction::Allow;
            source = VerdictSource::DefaultPolicy;
            log_.warning(QStringLiteral("静默模式:硬指标只有 %1 个来源、风险 %2 未到高危线(%3),"
                                        "按静默放行并留痕(不升级为拦截 —— 引擎对这一档的原始结论"
                                        "是「该问用户」,静默模式不该比它更激进):%4")
                             .arg(hardSources).arg(e.riskScore)
                             .arg(bulwark::engine::ThreatDetector::HighRisk)
                             .arg(e.actorPath));
        } else {
            action = VerdictAction::Allow;
            source = VerdictSource::DefaultPolicy;
        }
    }

    // 已签名主体默认放行(不弹提醒):开启「信任已签名主体」且主体持有有效数字签名
    //(未签名失配 / 未吊销 / 未过期后签名)时,把「询问」降级为放行——不再为签名程序弹窗打扰。
    // 注意:引擎判定的 Block(高危硬指标、吊销/过期后签名等确定性恶意)不受影响,仍然拦截;
    // 签名失配 / 无签名的主体也不在此列,照常询问。此策略由 trustSignedActors 开关控制,可关闭。
    //
    // 【白加黑必须排除在这条降级之外】签名壳侧载的整个要害就是「壳的签名是真的、健康的」——
    // 它百分之百满足上面那四个条件。于是不排除的话:ThreatDetector 给的 45 分硬指标让流水线
    // 第 9 步不放行、第 10 步给出「询问」,紧接着就被这里降级成放行,检测等于白做。
    // 这两个字段都只在【互证成立】时才非空(系统同名模块 / 最近才落地,见 detectSideloadedTamperedModule),
    // 所以排除范围很窄,不会把普通签名程序重新拖回弹窗。
    //
    // 【硬指标也必须排除在这条降级之外】上面只排掉了白加黑,漏掉的是更常见、覆盖面更大的
    // 一整档:RuleEngine 第 10 步对「有硬恶意指标但 riskScore < HighRisk(80)」给的是【询问】
    //(>= 80 才直接 Block,阈值见 ThreatDetector::HighRisk / Suspicious)。而硬指标最集中的
    // 那批主体 —— powershell / rundll32 / mshta / certutil / vssadmin 这些 LOLBin —— 全是
    // 微软的健康签名,上面那四个条件一个不少地满足。于是「硬指标 + 中等风险」这一档在引擎
    // 明确表示「该问用户」之后,被这里无声改回放行:检测、打分、证据链全部白做,而且日志里
    // 只留下一行「已签名主体默认放行」,排查时完全看不出曾经有过硬指标。
    //
    // 签名回答的是「这个文件是谁发布的」,硬指标回答的是「这一次的用法是不是恶意的」——
    // 后者不该被前者盖掉。白加黑那条排除项讲的是同一个道理,只是它当时只修了自己那一种形态。
    //
    // 【取舍:弹窗会变多】凡是签名主体凑到一个硬指标又没到 80 分,现在都会弹一次询问。这是
    // 有意接受的代价,相对的一侧是「投递链里最典型的那一段被静默放行」。嫌打扰有两条既有
    // 出路,且都比「默认吞掉硬指标」更可控:静默模式(上面那段,对【无】硬指标的询问降级为
    // 放行)、以及把具体程序加白(管线第 1 步,信任即完全不检测)。
    //
    // 注意本条与上面 silentMode 那段方向【相反】,且那是刻意的:静默模式对「硬指标 + 风险
    // >= Suspicious」是【升级为拦截】。两处共用同一条分界线 —— 硬指标既不许被静默吞掉,
    // 也不许被签名吞掉;区别只在一边往上抬、一边只是不往下放。
    const bool sideloadSuspect =
        !e.tamperedModulePath.isEmpty() || !e.sideloadedUnsignedModulePath.isEmpty();
    //
    // 【用户态 ImageLoad:签名宿主不替它加载的模块背书(6b)】
    // 上面 sideloadSuspect 只挡住了【互证成立】的那一小撮(系统同名模块 / 刚落地),条件很窄。
    // 更普遍的形态是:宿主签名真实健康(它就是个正经程序),从 Temp 加载一个未签名 DLL。
    // 这种事件里 actorSigned 恒为真,四个健康位一个不缺,于是规则刚给出的「询问」会在这里
    // 被无声降级为放行 —— 段 7.3 那三条 Temp-DLL 规则(经 6b 修好判据后才真正活过来)将
    // 全部被吃掉,和修好前的漏检没有区别。
    //
    // 所以对用户态 ImageLoad 追加一项:模块自身也得有健康签名,签名宿主的信任才顺延过去。
    // 「我信任这个签名程序」从来不等于「我信任它从 Temp 拉进来的任何一个未签名 DLL」。
    //
    // 内核驱动加载(actorPid <= 0)不在此列:那条路上 actorSigned 恒假,这条降级本来就
    // 永远不触发,具名 BYOVD 名单的 Ask 档正依赖这一点。此处刻意不去「顺手也改成判模块」,
    // 否则签名的 .sys 会新得到一条静默放行路径。
    const bool imageLoadUnsignedModule =
        (e.type == bulwark::EventType::ImageLoad && e.actorPid > 0 &&
         !(e.targetSigned && !e.targetSignatureMismatch));
    if (action == VerdictAction::Ask && settings_ && settings_->trustSignedActors
        && e.actorSigned && !e.signatureMismatch && !e.certRevoked && !e.signedAfterCertExpiry
        && !sideloadSuspect && !e.hasThreatIndicator && !imageLoadUnsignedModule) {
        action = VerdictAction::Allow;
        source = VerdictSource::TrustedSigner;
        log_.info(QStringLiteral("已签名主体默认放行(信任签名,不弹询问):%1").arg(e.actorPath));
    } else if (action == VerdictAction::Ask && sideloadSuspect && settings_
               && settings_->trustSignedActors && e.actorSigned) {
        log_.warning(QStringLiteral("白加黑侧载嫌疑:主体签名健康,但不适用「已签名默认放行」,"
                                    "保留询问:%1").arg(e.actorPath));
    } else if (action == VerdictAction::Ask && e.hasThreatIndicator && settings_
               && settings_->trustSignedActors && e.actorSigned) {
        // 侧载那条放在前面:它是硬指标的一个【具体】形态(tampered/unsigned 模块由
        // ThreatDetector 记为硬指标),所以两条都会成立时应当报出更具体的那句。
        log_.warning(QStringLiteral("主体签名健康但带硬恶意指标(风险 %1),不适用「已签名默认放行」,"
                                    "保留询问:%2").arg(e.riskScore).arg(e.actorPath));
    } else if (action == VerdictAction::Ask && imageLoadUnsignedModule && settings_
               && settings_->trustSignedActors && e.actorSigned) {
        // 放在最后:上面两条都比它具体。这一条是兜底的那一大档 —— 签名宿主 + 未签名模块,
        // 既没凑到互证(sideloadSuspect),也没凑到硬指标,但规则已经明确要求询问。
        // 必须留一行日志:这条降级此前是静默的,排查时看不出曾经有过判定。
        log_.warning(QStringLiteral("主体签名健康但加载的模块无健康签名,不适用「已签名默认放行」,"
                                    "保留询问:%1 -> %2").arg(e.actorPath, e.target));
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
            //
            // 【2.3 检出即挂起 —— 命令行硬拦的用户态补偿】
            //
            // 问题:弹窗期间那个进程照常在跑。有内核驱动时不要紧 —— 进程创建/命令行是在内核
            // 回调里【阻塞等裁决】的,它压根还没开始执行。无驱动时完全相反:事件是 ETW 事后
            // 观测,我们弹窗的同时样本正在全速工作,用户思考的那几秒就是它的可用时间。
            // 这是「无驱动缺什么」里最不容易被看见的一条:能力表上写着「有检测」,实际检测
            // 到了也拦不住这一次。
            //
            // 冻结是这里唯一可用的手段,因为它【可撤销】:用户点放行就 thaw,进程继续跑、
            // 不丢状态。断子绝不能用在这条路径上(不可撤销,见 UserModeProcessContainment)。
            //
            // 三道收窄,避免把弹窗变成「凡是问一句就先把程序冻住」:
            //   ① 仅在内核【不】等裁决时做 —— 有驱动时进程本来就还没跑,冻它没有意义;
            //   ② 要求本次已凑到硬恶意指标 —— 软信号不单独定罪,更不该据此冻结;
            //   ③ autoThaw=true —— 没人来裁决时到期自己放手(这类对象尚未确认恶意)。
            // 另有部署开关可整项关掉,关掉后行为与改动前逐字一致。
            if (containment_ && freezeOnDetect_ && e.hasThreatIndicator && e.actorPid > 4
                && !(source_ && source_->wantsVerdict())) {
                containment_->freeze(e.actorPid, e.actorPath,
                                     QStringLiteral("检出待裁决,弹窗期间冻结(风险 %1)")
                                         .arg(e.riskScore),
                                     true);
            }
            ipc_->sendPrompt(e);
            break;
        }
        case VerdictAction::Block:
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
            // 命中【释放物污点】规则的拦截同样不进内核持久名单:污点是「和某次拦截有关联」推出来的,
            // 不是对这个文件本身的确认;它走用户态规则就是为了加白能撤销、到期会失效。若这里照常
            // blacklistExec / blockModuleLoad,等于绕一圈又把它钉进了只加不减的内核名单。
            enforcement = enforceBlock(e, /*persistentBlacklist=*/v.action == VerdictAction::Block
                                              && !isTaintRuleNote(e.matchedRuleNote));
            // 通知【在处置之后】发,带上真实结果。
            //
            // 原来这一行在 enforceBlock 之前,于是右下角通知只能一律写「已拦截」—— 而
            // enforceBlock 可能返回 AlertedOnly(内核无法前拦、又没有可结束的进程,什么都没做)
            // 或 Failed(尝试结束但进程仍在跑)。那两种情况下「已拦截」是彻头彻尾的谎报,
            // 而它们恰恰是用户最需要自己动手的两种。enforceBlock 是同步的,这点延迟换的是不说假话。
            ipc_->sendBlock(e, enforcement);
            maybeQuarantineOnBlock(e);     // 设置「拦截时一并隔离载荷」开启时才动作(带三道护栏)
            {
                // 确定性恶意:隔离载荷 + 清除持久化。用最终裁决(可能被静默模式升级为 Block)驱动,
                // 而非原始 v —— 否则静默升级的高危不会触发隔离(v.action 仍是 Ask)。
                const bulwark::Verdict finalV =
                    action == v.action ? v : bulwark::Verdict::forEvent(e, action, source);
                remediateIfMalicious(e, finalV);
                // 释放物污点:引擎原始结论就是 Block 且属确定性恶意 -> 硬拦;静默模式升级来的
                // Block(原始结论是「拿不准」)只标「落地即询问」—— 不确定的处置不产出硬拦。
                // 内核前拦且无硬指标的(多半是正常程序误触受保护目标)不标。
                // 引擎判 Block 但不属确定性恶意的(例如保护型规则拦了一次写入)不标:那拦的是动作。
                if (!e.kernelBlocked || e.hasThreatIndicator) {
                    if (v.action == VerdictAction::Block) {
                        if (isDeterministicMaliciousBlock(e, finalV)) {
                            taintDroppedFiles(e, VerdictAction::Block,
                                              e.matchedRuleNote.isEmpty() ? QStringLiteral("引擎判定恶意")
                                                                          : e.matchedRuleNote);
                            // 被拦的是【派生出来的】子进程时,上面 enforceBlock 结束的可能只是一个
                            // 系统程序(vssadmin / comsvcs 之类),样本本体还在跑 —— 连带处置那个
                            // 发起方。刻意挂在这道闸上:与污点同一个「引擎确认恶意」前提,
                            // 用户裁决 / 超时兜底那两条路径都不该走进来(见该函数声明处)。
                            maybeHandleLaunchingParent(e);
                        }
                    } else {
                        taintDroppedFiles(e, VerdictAction::Ask, QStringLiteral("静默模式升级拦截"));
                    }
                }
            }
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
        // 也【刻意不复用 BlockNotification】:那条的主体是「某个动作被拦了 / 没拦成」,
        // 只在裁决为 Block 时发;而攻击链三种处置(Block / Ask / Allow)都要发,
        // 且它要展示的是凑齐的动作链与作证样本数,那条通知的字段结构装不下。
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

    // 【2.3 的撤销边:裁决一到就解冻】
    // 弹窗期间可能已经把主体冻住了(见 onEvent 的 Ask 分支)。裁决为放行时必须【立刻】解冻,
    // 而且要在下面那些处置之前做 —— 用户点的是「放行」,再多停一毫秒都是在违背这个决定。
    // 裁决为拦截时刻意不在这里解冻:enforceBlock -> killMalicious 会把它改成「已确认恶意」
    // 的冻结(autoThaw=false);那条路上先解冻再重冻会白送一个空窗。
    if (containment_ && action != VerdictAction::Block && e.actorPid > 4)
        containment_->thaw(e.actorPid, QStringLiteral("用户裁决为放行"));

    // 用户裁决为拦截:执行真实处置并拿到真实结果(内核前拦 / 已结束进程 / 加黑名单 / 仅告警)。
    bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;
    if (action == VerdictAction::Block) {
        // 询问本身来自一条污点规则时,同 onEvent:不把它钉进内核持久名单(污点必须可被加白撤销)。
        enforcement = enforceBlock(e, /*persistentBlacklist=*/!isTaintRuleNote(e.matchedRuleNote));
        // 把结果回给用户。
        //
        // 此前这条路【完全没有任何反馈】:用户在询问弹窗上按了「拦截」,弹窗一关就没下文 ——
        // 而 enforceBlock 完全可能返回 AlertedOnly(什么都没拦下)或 Failed(没杀成)。
        // 用户主动做了一次安全决定,却无从知道它到底生效没有,只能默认「我点了就拦住了」。
        // 这正是最该说实话的地方:现在按真实结果回一条通知(已拦截 / 已结束进程 /
        // 仅告警·未拦截 / 拦截失败),未拦下的那两种 UI 会给出手动处理入口。
        ipc_->sendBlock(e, enforcement);
        maybeQuarantineOnBlock(e); // 用户显式裁决拦截时同样尊重「拦截时一并隔离载荷」设置
        remediateOnUserBlock(e);   // 用户显式选择阻止:清它此前的释放物 / 持久化(可还原)
        // 用户的「阻止」不是引擎的确认 -> 释放物只标「落地即询问」,不产出硬拦。
        taintDroppedFiles(e, VerdictAction::Ask, QStringLiteral("用户选择阻止"));
    } else if (action == VerdictAction::Allow && isTaintRuleNote(e.matchedRuleNote)) {
        dropTaintRulesMatching(e); // 用户亲自放行了一个被污点询问的文件 -> 撤销该污点
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

    // 2.3 的另一条撤销边:超时按默认放行时也要立刻解冻。
    // (冻结自身有 TTL 兜底,但那是给「连这条兜底都没跑到」准备的最后一道网;正常路径必须
    //  在此处显式放手 —— 靠超时去解一个已经做完决定的冻结,会白挂一到两分钟。)
    if (containment_ && !block && e.actorPid > 4)
        containment_->thaw(e.actorPid, QStringLiteral("弹窗超时按默认策略放行"));

    bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;
    if (block) {
        // persistentBlacklist=false:超时兜底并非「已确认恶意」,不把映像/模块钉进内核持久名单。
        enforcement = enforceBlock(e, /*persistentBlacklist=*/false);
        ipc_->sendBlock(e, enforcement);   // 先处置、再通知,通知里写的才是真事(见 onEvent 处说明)
        // 同理,释放物只标「落地即询问」。不做足迹清理:没有人确认过它恶意。
        taintDroppedFiles(e, VerdictAction::Ask, QStringLiteral("弹窗超时按默认策略拦截"));
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

    //
    // 3.9) 映像加载:求【被加载模块自身】的签名。
    //
    // 必须单独求,不能复用下面第 4 步的主体取证:ImageLoad 的 actorPath 是【宿主进程】
    //(用户态 DLL)或伪串「内核(驱动加载)」(内核模块),actorSigned 说的是它们,不是那个模块。
    // 而侧载 / BYOVD 的判据要看的恰恰是模块自己 —— 段 7 的规则注释长期把 actorSigned 当成
    // 模块签名在用,那是误解。
    //
    // 放在第 4 步【之前】,因为内核模块加载的 actorPath 根本不是真实文件,主体取证那一段对它
    // 没有任何有效结论;放后面还会被将来可能加的提前 return 吃掉。
    //
    // 成本:ImageLoad 的上报口径本来就很窄(用户态只报 \Temp\ 与 \Users\Public\,驱动只报用户
    // 可写目录),且 collectForensics 按「小写路径|大小|修改时刻」缓存,重复加载同一模块命中缓存。
    // includeCert=false:目标只需要「有没有可信签名 / 有签名但校验不过」两件事,不建证书画像。
    if (e.type == bulwark::EventType::ImageLoad) {
        const QString mod = e.target.trimmed();
        if (!mod.isEmpty() && !mod.startsWith(QLatin1String("PID "), Qt::CaseInsensitive)) {
            const ProcessInspector::ForensicFacts mf =
                ProcessInspector::collectForensics(mod, /*includeCert=*/false);
            e.targetSigned = mf.trustedSignature;
            if (!e.targetSigned)
                e.targetSignatureMismatch = mf.embeddedSignature;
            // 记一条 0 分的 Info 证据:这批事件多半会走到询问弹窗,而「这个驱动/模块是谁签的」
            // 正是用户判断时唯一有用的信息。刻意不进 riskReasons(那是计分理由,这条不计分)。
            e.addEvidence(QStringLiteral("模块签名"), bulwark::EvidenceKind::Info,
                          e.targetSigned
                              ? (mf.publisher.isEmpty()
                                     ? QStringLiteral("被加载模块持有可信签名")
                                     : QStringLiteral("被加载模块持有可信签名:%1").arg(mf.publisher))
                              : (e.targetSignatureMismatch
                                     ? QStringLiteral("被加载模块内嵌签名但校验不过(篡改 / 盗用证书)")
                                     : QStringLiteral("被加载模块没有可信签名")),
                          0, /*alsoReason=*/false);
        }
    }

    // 4) 主体取证:映像路径指向真实文件时才做签名/哈希,避免对占位符做无谓 I/O。
    const QString path = e.actorPath;
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive)) {
        e.actorSigned = false;
        return;
    }

    //
    // 一次取齐:签名 / 发布者 / SHA-256 /(无可信签名时的)内嵌签名 / 证书画像 / 文件体积。
    //
    // 原先是逐项调 isSigned、tryGetPublisher、tryComputeSha256、hasEmbeddedSignature、
    // getCertInfo,再单独构造一个 QFileInfo 取体积 —— 而每个逐项接口内部都要先算一次「文件
    // 身份」(小写路径|大小|修改时刻)作为缓存键,算身份就是一次 stat。结果是【一条事件对同
    // 一个文件 stat 五六遍】,即便这些事实全部命中缓存、验签与哈希一次都没真跑。事件风暴下
    // 这笔开销按事件数线性放大,而且全压在主线程上。
    //
    // collectForensics 把 stat 收敛成一次,求值范围与原来的调用序列一一对应:
    //   · 证书画像仅在【非自身组件】时求(includeCert),与原先「自身组件在此提前 return」等价;
    //   · 内嵌签名仅在没有可信签名时求,与原先那个 if 等价 —— 已知未受信时只需知道有没有内嵌
    //     签名,不必在进程创建的同步裁决路径上再验一次签。
    // 故结论逐字段不变,省掉的纯粹是重复的 stat。
    //
    const ProcessInspector::ForensicFacts facts =
        ProcessInspector::collectForensics(path, /*includeCert=*/!selfComponent);

    e.actorSigned    = facts.trustedSignature;
    e.actorPublisher = facts.publisher;
    e.actorHash      = facts.sha256;
    // 签名失配:内嵌了签名但信任校验不过。保留原来的条件写法,使「有可信签名时不触碰该字段」
    // 这一点逐字节不变(facts.embeddedSignature 此时也恒为 false)。
    //
    // signatureTampered 是从里面分出来的那一小撮【真篡改】(WinVerifyTrust 明确回
    // TRUST_E_BAD_DIGEST)。两个字段的分工见 SecurityEvent 里的说明:信任判定两个都不给信任,
    // 但打分只允许 signatureTampered 单独定罪 —— 「根证书没导入」「文件读不出来」不是恶意证据。
    if (!e.actorSigned) {
        e.signatureMismatch = facts.embeddedSignature;
        e.signatureTampered = facts.signatureDigestMismatch;
    }

    // 自身组件到此为止(理由见第 3.1 步):签名 / 发布者 / 哈希已经拿到,足够 UI 如实展示,
    // 而下面的证书链构建、侧载扫描、首见落盘、云查询对「无条件放行」的结论没有任何影响。
    if (selfComponent)
        return;

    // 证书画像:指纹 / 有效期 / 吊销 / 过期后签名(证书被吊销即便验签不过仍是硬指标)。
    const ProcessInspector::CertInfo& ci = facts.cert;
    if (!ci.thumbprint.isEmpty())    e.actorCertThumbprint = ci.thumbprint;
    if (ci.notAfterUtc.isValid())    e.certNotAfterUtc     = ci.notAfterUtc;
    if (ci.signingTimeUtc.isValid()) e.signingTimeUtc      = ci.signingTimeUtc;
    e.certRevoked           = ci.revoked;
    e.signedAfterCertExpiry = ci.signedAfterCertExpiry;

    // 侧载模块篡改(「白加黑」):主体签名健康时,顺带看一眼同目录有没有「签名后被改过」的模块。
    // 放在签名/证书判定【之后】—— 它要先知道主体自己是不是签名健康的壳。按目录缓存,低频。
    detectSideloadedTamperedModule(e);

    // 脚本宿主要执行的脚本文件:读正文跑判据。
    // 放在这里的理由与上面一致 —— 需要命令行(第 2 步已回填)且只对非自身组件做。
    scanScriptFileBody(e);

    // 文件体积:银狐 / 游蛇 惯用「文件膨胀」把样本撑到数十 MB 以规避扫描。
    // 复用上面那一次 stat 的结果(原先在这里又构造了一个 QFileInfo)。
    if (facts.isRealFile)
        e.actorFileSize = facts.fileSize;

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
    //
    // 【PID 必须对应一个真实存在的进程(2.4 实测发现)】
    //
    // UserModeBehaviorSource 在无法归因时会填一个【合成 PID】(kSyntheticActorPid,
    // 0x0B00000 = 11534336),只为让勒索监视器的 ActorPid>0 前置条件成立。它那里的注释写着
    // 「这些事件不结束进程,不存在误杀风险」—— 那个前提早就不成立了:诱饵命中是无条件 Block,
    // 流水线照常走到这里。实测日志(verify2.log):
    //     恶意进程终结:PID=11534336(用户态结束 0 个 + 驱动级内核结束)
    // 三件事同时发生,每一件都不该发生:
    //   ① banProcess(11534336) 把一个【不存在的 PID】写进内核封禁集。11534336 是 4 的倍数,
    //      完全可能是将来某个真实进程的 PID —— 那个无辜进程会被内核全维拒绝,且没人查得出原因;
    //   ② terminateProcessTree 对着空气跑一遍;
    //   ③ waitForExit 对不存在的 PID 按「已退出」处理(那是它刻意的、且正确的语义),于是整条
    //      路径以一行「恶意进程终结」收尾 —— 一次彻头彻尾的谎报,而且恰好出现在最需要说实话的
    //      地方:诱饵命中了,但我们根本不知道是谁干的。
    //
    // 正确的说法是「检测到了,但没有可处置的主体」。归因存在时(0.5 的
    // KernelFileWriteAttribution 打开后)走的是真实 PID,这条判据不会拦住它。
    if (!ProcessInspector::enumeratePids().contains(pid)) {
        log_.warning(QStringLiteral("处置中止:PID=%1 在当前进程快照里不存在 —— 该事件很可能没有"
                                    "归因到真实发起进程(用户态行为源在无法归因时会填合成 PID)。"
                                    "【没有可结束的进程】,本次不下发内核封禁、不做任何处置,"
                                    "也不报告「已终结」。")
                         .arg(pid));
        return false;
    }
    // 情报/规则确认恶意:先【封禁该主体】—— 其任何文件写/删/改、注册表写、网络外联、创建子进程
    // 此后被内核各回调一律拒绝。不依赖下面「结束进程」的时机:即便被反杀 / 滞后,封禁期间它也
    // 一个动作都做不成(「情报一确认即全维封杀」)。旧驱动/未连接时 no-op,不影响后续结束进程。
    // banProcess 的返回值【必须接住】:它是内核封禁到底有没有发生的唯一凭据。
    // 原实现丢弃了它,然后在下面失败分支里无条件宣称「已封禁主体,内核全维拒绝」——
    // 无驱动时那是一句凭空的安慰(EventSource 默认实现直接 return false)。
    const bool banned = source_ && source_->banProcess(pid);
    // 映像路径必须在【结束之前】取 —— 杀完就取不到了。两处要用:下面的收容记录,
    // 以及成功后的 rememberTerminated(它靠这个路径防 PID 复用误认,见 killedByUs_ 声明处)。
    const QString img = ProcessInspector::tryGetProcessImagePath(pid);
    //
    // 【杀之前先收容(2.1/2.2/2.3)】这两级放在 terminateProcessTree 之前是有原因的:
    // 结束一棵进程树不是原子的 —— 要枚举快照、逐个 OpenProcess、逐个 TerminateProcess,
    // 每一步都给了样本时间。这段窗口里它能起一个子进程把自己重新拉起来,或者改名换路径再跑。
    //   · 冻结:一次调用停住它全部线程,窗口里不会再有新动作;
    //   · 断子:即使被恢复也起不了子进程(实测 ERROR_NOT_ENOUGH_QUOTA 1816)。
    // 顺序是先冻结再断子:冻结更快且覆盖面更大,先把它按住再慢慢上锁。
    //
    // 无 containment_ 时这两级整段跳过,killMalicious 的行为与注入前逐字一致。
    if (containment_) {
        // autoThaw=false:这是已确认恶意的路径。若下面杀成功,收容记录会被一并清掉;
        // 杀不掉才留着 —— 那正是我们要它停在那里的情形(解除路径是用户加白 -> reconcile)。
        containment_->freeze(pid, img, QStringLiteral("已确认恶意,处置前冻结"), false);
        containment_->cutOffChildren(pid, true, QStringLiteral("已确认恶意,处置前断子"));
    }
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
        // 记住是我们杀的:它退出前排队的事件随后还会走完流水线,那些事件的处置结论
        // 该是「主体已被结束」而不是「未做任何实际阻断,需要人工关注」(见 killedByUs_ 声明处)。
        rememberTerminated(pid, img);
        return true;
    }

    // 没死。如实报出来,并带上排障需要的两条信息:是否被"关键进程"护栏挡住、映像路径。
    //
    // 【原来这句话在无驱动时是假的】原文结尾写死了「已封禁主体,其行为仍被内核全维拒绝」。
    // banProcess 是内核能力:EventSource 的默认实现直接返回 false,EventSource=Wmi 或驱动
    // 掉线时它是彻底的 no-op。于是这条日志在最需要说实话的地方(杀不掉)给出了一个完全
    // 不存在的安慰 —— 读日志的人以为威胁已被全维封住,实际什么都没发生。
    // 现在按实际拿到的手段分别陈述:内核封禁只在驱动在线时才提;用户态收容只在真的成立时才提。
    QStringList held;
    if (banned)
        held << QStringLiteral("已封禁主体(内核对其文件/注册表/网络/子进程一律拒绝)");
    if (containment_) {
        if (containment_->isFrozen(pid))
            held << QStringLiteral("已冻结(全部线程挂起,不再有新动作;在界面加白即可解除)");
        if (containment_->isChildrenCutOff(pid))
            held << QStringLiteral("已断子(无法再创建子进程)");
    }
    log_.warning(QStringLiteral("恶意进程未能终结:PID=%1 仍在运行(用户态结束 %2 个,内核结束命令%3)。"
                                "关键进程护栏=%4,映像=%5。已施加的收容:%6")
                     .arg(pid).arg(killed)
                     .arg(kkill ? QStringLiteral("已受理") : QStringLiteral("未受理"))
                     .arg(ProcessInspector::isCriticalProcess(pid) ? QStringLiteral("命中(按此判定不予结束)")
                                                                   : QStringLiteral("未命中"))
                     .arg(ProcessInspector::tryGetProcessImagePath(pid))
                     .arg(held.isEmpty()
                              ? QStringLiteral("【无】—— 本次处置实际没有对该进程起到任何作用,"
                                               "需要人工处理")
                              : held.join(QStringLiteral(";"))));
    return false;
}

bool Worker::blacklistExec(const QString& imagePath) {
    if (!source_)
        return false;
    QString p = imagePath.trimmed();
    if (p.isEmpty())
        return false;
    // 只处理形似真实文件路径的映像(带盘符或以反斜杠开头);占位符如 "PID 1234" 直接跳过。
    const bool looksPath =
        (p.size() >= 2 && p[1] == QLatin1Char(':')) || p.startsWith(QLatin1Char('\\'));
    if (!looksPath)
        return false;
    // 加白豁免:被用户明确信任(或本软件自身)的映像绝不下发内核「禁止执行」名单。
    // 这份名单由内核写回注册表持久化、跨杀服务与重启由内核独立续拦,且协议上没有「删除单条」——
    // 一旦对已加白的程序钉进去,用户在 UI 再怎么加白都不生效:内核在进程创建回调就地
    // STATUS_ACCESS_DENIED,事件根本到不了规则引擎。故这里是必须守住的最后一道闸。
    if (const std::optional<QString> note = engine_->trustNoteForPath(p)) {
        log_.info(QStringLiteral("执行前拦截已跳过(该主体已加白:%1):%2").arg(*note, p));
        return false;
    }
    //
    // 系统目录 / 本产品自身的映像【绝不】下发,哪怕本次确实判了 Block。
    //
    // 【为什么必须有这道闸】大量 Block 规则是按【命令行】判的(关防火墙、改 Defender 策略、
    // sc create binPath=… 指向可写目录),而那类事件的主体恰恰是 cmd.exe / powershell.exe /
    // netsh.exe / sc.exe 这些系统自带程序 —— 拦的是「用法」,不是这个文件。原实现只有上面
    // 那道加白闸,于是这类规则一命中就会把 \Windows\System32\cmd.exe 之类钉进内核禁运名单:
    // 那份名单由内核写回注册表、跨重启续拦、协议上没有「删除单条」,后果是整台机器再也起不了
    // cmd —— MSBuild、各种安装脚本、乃至本产品自己的构建全部报 MSB6003 / 0x80004005。
    // 这不是假想:内核基线曾把 CMD.EXE 钉进这份名单,rebuild_full.ps1 头部至今记着那次事故。
    //
    // 而且对系统程序做「执行前拦截」本身就没有意义:不可能永久禁止 cmd.exe 启动。真正的处置是
    // 上面 killMalicious 结束这次的进程树,以及按规则拦掉那个具体动作 —— 这两项都不受影响。
    // isSweepExemptPath 覆盖 System32 / SysWOW64 / WinSxS 与本产品目录(按真实路径前缀,
    // 不是名字子串),与兜底扫描、拦截时隔离用的是同一份判定。
    //
    if (isSweepExemptPath(p)) {
        log_.info(QStringLiteral("执行前拦截已跳过(系统目录 / 本产品自身,拦的是用法而非文件):%1").arg(p));
        return false;
    }
    // 去掉盘符(如 "C:"),下发【盘符无关】的路径子串:内核在进程创建回调里拿到的映像路径可能是
    // \??\C:\... 也可能是 \Device\HarddiskVolumeN\...,二者都包含去盘符后的 "\Users\...\x.exe" 子串,
    // 从而稳定命中(与内核系统目录白名单用盘符无关子串同理)。UNC "\\host\..." 本就盘符无关,保持不变。
    QString needle = p;
    if (needle.size() >= 2 && needle[1] == QLatin1Char(':'))
        needle = needle.mid(2);
    // 过短的子串风险大(可能误拦无关进程),放弃 —— 确认恶意的样本映像总是较长的完整路径。
    if (needle.size() < 6)
        return false;
    // 返回值要如实反映「这个映像现在是不是真的起不来了」,所以两条路各自记账:
    // 内核名单可能因未连驱动 / 槽位耗尽而没受理,此时只剩下面的 ACE(它自己也可能被开关关掉)。
    bool denied = false;
    if (source_->blockExecPath(needle)) {
        log_.info(QStringLiteral("执行前拦截:已把恶意映像加入内核禁止执行名单(下次启动将被内核前拦):%1").arg(p));
        denied = true;
    }

    //
    // 【3.5 跨重启的那一半】上面那份名单在有驱动时由内核写注册表续拦;无驱动时落到
    // UserModeExecBlock 的独占句柄,而句柄【不跨重启】—— 开机到本服务启动之间那段空窗里,
    // 这个映像是可以执行的(UserModeExecBlock::replay 的日志就是在说这件事)。
    // 「拒绝执行」ACE 补的正是那一段:它是文件系统上的持久元数据,开机即生效。
    //
    // 三点刻意为之:
    //   · 受 denyExecuteEnabled_ 约束,默认关 —— 这是跨重启、且卸载本产品也不会消失的改动;
    //   · 放在两道闸【之后】,所以加白与系统目录豁免自动适用,不需要再抄一遍;
    //   · 与独占句柄叠加而不是替代:句柄挡「现在」并且连改名删除一起挡,ACE 挡「重启之后」。
    //     实测两者互不干扰(ACE 只拒执行,不拒读,所以我们自己的隔离照常)。
    if (hardening_ && denyExecuteEnabled_) {
        if (hardening_->denyExecute(p) || hardening_->hasDenyExecute(p))
            denied = true;
    }
    return denied;
}

// 可撤销的执行前拦截(只加「拒绝执行」ACE,绝不碰内核名单)。设计理由见 Worker.h 的声明处。
bool Worker::denyExecuteRevocable(const QString& imagePath, const QString& why) {
    QString p = imagePath.trimmed();
    if (p.isEmpty())
        return false;
    // 占位符路径("PID 1234")与非路径形态直接跳过 —— 与 blacklistExec 同一门槛。
    const bool looksPath =
        (p.size() >= 2 && p[1] == QLatin1Char(':')) || p.startsWith(QLatin1Char('\\'));
    if (!looksPath)
        return false;
    // 三道闸的顺序与 blacklistExec 逐条对齐,但每一条在这里的理由都要单独站得住:
    //   ① 已加白 —— 加白的语义是「完全不检测、不处置」,给它加 ACE 等于用户加白了却还起不来;
    //   ② 系统目录 / 本产品自身 —— 污点候选理论上不该落在这里(taintDroppedFiles 有落地区
    //      护栏),但污点规则是【按路径】匹配的,一条规则命中时的 actorPath 完全可能是
    //      cmd.exe(实测:runner.bat / file.bat 的污点规则命中的就是 cmd.exe 的 ProcessCreate)。
    //      给 System32 里的程序加跨重启拒绝执行 ACE 是整个项目里后果最重的一种误伤 ——
    //      那是文件系统上的持久元数据,卸载本产品也不消失。这道闸是本函数存在的前提;
    //   ③ 文件不在盘上就没有可加 ACE 的对象(样本常被自己的隔离先搬走)。
    if (const std::optional<QString> note = engine_->trustNoteForPath(p)) {
        log_.info(QStringLiteral("可撤销执行前拦截已跳过(该主体已加白:%1):%2").arg(*note, p));
        return false;
    }
    if (isSweepExemptPath(p)) {
        log_.info(QStringLiteral("可撤销执行前拦截已跳过(系统目录 / 本产品自身,拦的是用法而非文件):%1")
                      .arg(p));
        return false;
    }
    if (!QFileInfo::exists(p))
        return false;
    if (!hardening_) {
        log_.warning(QStringLiteral("【未做到执行前拦截】加固器不可用,%1 只做了事后结束进程 —— "
                                    "该映像再次被双击时仍会先运行起来:%2").arg(why, p));
        return false;
    }
    //
    // 开关关着时【必须把「没做到」说出来】,不能静默返回。
    //
    // 沉默才是这类路径真正的问题:本项目已经在 applyRegHardening 与 BlockedRemoteEndpoints
    // 上各栽过一次 —— 能力只在某个条件下成立,而不成立时日志里一个字都没有,于是读日志的人
    // 以为「拦截了」,实际只是事后 kill。这里的现象恰好是用户看到的那一个:样本先跑再被杀。
    if (!denyExecuteEnabled_) {
        log_.warning(QStringLiteral("【未做到执行前拦截】%1,但 FileDenyExecuteEnabled=false,"
                                    "本次只做了事后结束进程 —— 该映像再次被双击时仍会先运行起来"
                                    "(约 1-3 秒)再被拦:%2。要真正做到「起不来」,把该开关置为 true"
                                    "(代价:在文件上留一条跨重启的拒绝执行 ACE,撤销入口是在界面加白)。")
                         .arg(why, p));
        return false;
    }
    // 已经有了:不重复记日志(同一样本会被多次双击),但【要返回 true】——
    // 调用方问的是「这个映像现在起不来了吗」,而不是「这一次有没有新加 ACE」。
    if (hardening_->hasDenyExecute(p))
        return true;
    if (hardening_->denyExecute(p)) {
        const QString msg =
            QStringLiteral("执行前拦截(可撤销):已对 %1 加「拒绝执行」ACE —— 下次双击直接失败"
                           "(错误 5),不再先运行起来。原因:%2。撤销:在界面加白该程序即自动移除;"
                           "注意 ACE 不随污点规则到期而消失,且复制一份副本可绕过。")
                .arg(p, why);
        log_.warning(msg);
        ipc_->sendLog(msg);
        return true;
    }
    // 加 ACE 失败(文件被独占 / 改 DACL 被拒)。SystemHardening 自己会记原因,这里只如实回话:
    // 没做到,调用方不能对用户声称「下次启动会被拦」。
    return false;
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

    const QString p = path.trimmed();
    if (p.isEmpty())
        return { false, QStringLiteral("未提供文件路径") };

    // 这条路径是【用户从 UI 点「重试隔离」】进来的,原先一道护栏都没有:IPC 侧只检查了
    // 路径非空,这里直接转发给清理器。而隔离失败会回退到 MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)
    // ——以 SYSTEM 身份的"重启后删除任意文件"。也就是说一条任意路径就能让下次开机时删掉
    // 系统文件,把机器搞成起不来。自动处置路径(maybeQuarantineOnBlock)本来就有三道护栏,
    // 唯独这条用户触发的没有。
    //
    // 这里补上其中【与"别把系统搞坏"直接相关】的部分,刻意不加"已加白就拒绝"那道:
    // 用户明确点了重试隔离,那是他自己的意图,不该被自己先前的加白挡住。
    //
    // 注意不能拿 TrustPolicy::isHealthySigned 来当这里的签名护栏:那个判据读的是
    // SecurityEvent 上【富化之后】的签名字段(它的注释也写明"需在 ThreatDetector::analyze
    // 之后调用")。本函数只有一个路径,临时造一个空事件传进去会恒定返回"未签名",
    // 那就是一道看着像护栏、实际永不生效的死代码。要按路径判就得用按路径验签的接口。
    if (isSweepExemptPath(p))
        return { false, QStringLiteral("拒绝隔离:该路径属于系统目录或本产品自身,隔离它会破坏系统或防护自身") };
    // 按路径验签(嵌入式 + catalog)。带可信签名的文件本体几乎不会是载荷 —— 拦下来的通常是
    // LOLBin 的【用法】,把 powershell.exe 本体搬进隔离区是灾难性误伤。
    if (ProcessInspector::isSigned(p))
        return { false, QStringLiteral("拒绝隔离:该文件持有可信数字签名,隔离文件本体属于误伤(拦截的是行为,不是文件)") };

    const std::pair<bool, QString> r = remediator_->forceQuarantine(p);
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
    // 只保留【与内核匹配语义一致】的那一个方向。
    //
    // 内核按「加白路径(去盘符)包含该条目子串」来挡人,所以判据就是 t.contains(entry)。
    // 原实现还额外或上了反向的 entry.contains(t) —— 那个方向不对应任何内核行为,只会误伤:
    // 目录信任被 chop("\*") 后留下的是很短的针(例如 "\users\bob\"),几乎任何一条位于该
    // 目录下的内核「禁止执行」条目都会被它反向包含,于是【已确认恶意】的映像被当成
    // 「会挡住加白程序」而从名单里删掉 —— 加白一个目录等于给该目录下所有已封禁恶意体解禁。
    auto wouldBlockTrusted = [&trustedNeedles](const QString& entry) {
        if (entry.isEmpty())
            return false;
        for (const QString& t : trustedNeedles)
            if (t.contains(entry, Qt::CaseInsensitive))
                return true;
        return false;
    };

    // ①c 移除被加白程序上的「拒绝执行」ACE(3.5,约束 3)。
    //
    // 这一条【不看 denyExecuteEnabled_】,是刻意的:那个开关管的是「还要不要继续加」,
    // 而这里管的是「此前加过的怎么解」。两者混在一起会造出本项目最糟的一种状态 ——
    // 部署方先开着跑了一段时间、加了若干条跨重启 ACE,然后把开关关掉,于是那些 ACE
    // 再也没有任何代码路径会去碰它们:它们跨重启、卸载本产品也不消失,用户只能自己
    // 去文件属性里翻安全页。
    //
    // 它只按【已加白的路径】去尝试移除,而不是遍历磁盘找 ACE:我们不维护清单(见
    // SystemHardening 头文件的说明,清单与真实状态分歧过一次就够了),所以撤销的入口
    // 只能是「用户指名了哪个程序」。
    if (hardening_) {
        int removed = 0;
        for (const bulwark::DefenseRule& r : rules) {
            if (!r.isTrustEntry() || r.action != VerdictAction::Allow || !r.enabled)
                continue;
            const QString p = !r.actorPath.isEmpty() ? r.actorPath : r.actorPattern;
            // 只处理具体文件:目录信任("<dir>\*")没有确定的文件可解,遍历目录去找 ACE
            // 属于另一件事,不在加白这一下里顺手做。
            if (p.isEmpty() || p.endsWith(QStringLiteral("\\*")))
                continue;
            if (hardening_->hasDenyExecute(p) && hardening_->undenyExecute(p))
                ++removed;
        }
        if (removed > 0) {
            log_.warning(QStringLiteral("加白对账:已移除 %1 个已加白程序上的跨重启「拒绝执行」ACE。")
                             .arg(removed));
        }
    }

    // ①b 解冻被加白程序的进程(约束 3:加白必须能撤销一切)。
    //
    // 冻结是新加的处置手段,而且是【无驱动时唯一还成立的那一个】:杀不掉的已确认恶意进程会被
    // autoThaw=false 地挂在那里,刻意不设期限。既然如此,它就必须有解除口 —— 否则用户在界面
    // 加白之后看到的仍是一个永远卡死的程序,并且【不会再有任何东西来救它】(冻结不落盘,
    // 没有 replay 会重来一遍,这一点反而让问题更隐蔽:重启才能恢复)。
    // 方向与上面 wouldBlockTrusted 相反是对的:那个问「这条封禁会不会挡住已加白的程序」
    // (针是封禁条目),这里问「这个被冻结进程的映像是不是已加白的那个」(针是加白路径)。
    if (containment_) {
        int thawed = 0;
        for (const QString& t : trustedNeedles)
            thawed += containment_->thawByPathNeedle(t, QStringLiteral("用户已加白该程序"));
        if (thawed > 0) {
            log_.warning(QStringLiteral("加白对账:已解冻 %1 个被冻结的进程(其映像已在信任名单内)。")
                             .arg(thawed));
        }
    }

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
    QStringList fellBack;   // 内核没受理的,交给用户态补位(见函数末尾)
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
        else
            fellBack << k;
    }
    if (n > 0)
        log_.warning(
            QStringLiteral("持久化反重建:已把 %1 条已清理的自启动项加入内核注册表硬拦(阻止恶意软件立刻重建)。").arg(n));

    //
    // 【无驱动时这整段原本是彻底的 no-op,而且一个字都不说】
    //
    // hardenRegistryKey 是内核能力(EventSource 默认实现直接 return false)。上面那句日志又
    // 只在 n>0 时打,所以 EventSource=Wmi 或驱动掉线时的真实情况是:清理完持久化 -> 反重建
    // 一条都没下发 -> 日志里连一行「没做到」都没有。守护进程秒级重写那个竞态完全敞开,
    // 而排查的人看不出任何异常。这与 1.2 里 BlockedRemoteEndpoints 只在驱动连上时才下发
    // 是同一类缺口,也是同一个教训:一个只在有驱动时才成立的能力,必须在没驱动时【喊出来】。
    //
    // 用户态补位要分清工具,不能一律套同一个:
    //   · 共享键(Run / RunOnce / Services 根 …)下的【某个值】—— 注册表安全描述符在键上
    //     不在值上,所以 DENY ACE 做不到「只保护这一个值」。对 Run 加 DENY 会打断每个安装
    //     程序。这类只能靠 3.1 的即时监视 + 回滚:值被重写就立刻还原。
    //   · 恶意【独占】键(它自建的服务键 / 自建子键)—— 这种可以直接上 DENY ACE,
    //     比回滚更彻底(写都写不进去,而不是写进去再被还原)。
    if (!fellBack.isEmpty() && hardening_ && regHardenEnabled_) {
        int watched = 0, denied = 0;
        QStringList unusable;
        for (const QString& t : fellBack) {
            // 目标形如 "HKLM\SOFTWARE\...\Run\ValueName"(上报路径就是这么拼的)。
            // 取到最后一个反斜杠之前,得到那个【键】;取不到就说明形态不可用,如实记下。
            const int cut = t.lastIndexOf(QLatin1Char('\\'));
            if (cut <= 0) {
                unusable << t;
                continue;
            }
            const QString key = t.left(cut);
            if (!key.startsWith(QLatin1String("HK"), Qt::CaseInsensitive)) {
                unusable << t;
                continue;
            }
            if (SystemHardening::isExclusiveRegistryKey(key)) {
                if (hardening_->denyRegistryWrite(key, /*exclusiveKeyOnly=*/true))
                    ++denied;
            } else {
                hardening_->watchKeyLive(key);
                ++watched;
            }
        }
        log_.warning(QStringLiteral("持久化反重建(用户态补位,内核未受理 %1 条):"
                                    "已对 %2 个共享键启用即时监视+回滚、对 %3 个恶意独占键加"
                                    "「拒绝写值」ACE%4。"
                                    "注意:回滚是【事后还原】,不是阻止写入 —— 恶意软件仍能写进去,"
                                    "只是会被立刻还原;真正的写入前阻断只有内核硬拦做得到。")
                         .arg(fellBack.size())
                         .arg(watched)
                         .arg(denied)
                         .arg(unusable.isEmpty()
                                  ? QString()
                                  : QStringLiteral(";另有 %1 条目标形态无法解析成注册表键,"
                                                   "用户态无从处理:%2")
                                        .arg(unusable.size())
                                        .arg(unusable.join(QStringLiteral(" | ")))));
    } else if (!fellBack.isEmpty()) {
        // 用户态补位不可用时同样要说话 —— 沉默是这段代码原本最大的问题,而不是能力缺失本身。
        log_.warning(QStringLiteral("持久化反重建:%1 条已清理的自启动项【未能下发任何反重建】——"
                                    "内核未受理(无驱动时 hardenRegistryKey 是空操作),"
                                    "用户态补位%2。恶意软件可以立刻把这些持久化项写回来,"
                                    "本服务既不会阻止也不会还原。要补上这一段,"
                                    "把 RegistryInstantRollbackEnabled 置为 true。")
                         .arg(fellBack.size())
                         .arg(hardening_ ? QStringLiteral("已按配置关闭"
                                                          "(RegistryInstantRollbackEnabled=false)")
                                         : QStringLiteral("未注入")));
    }
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
        } else if (e.actorPid <= 0) {
            //
            // 内核驱动加载(DriverEventSource 对 ActorPid==0 才置那个伪 actorPath):**下发是无效的**,
            // 所以干脆不下发。
            //
            // FileNoLoad 的唯一执行点是 minifilter 的 BlwPreCreate,而那个回调一开头就有
            // `if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;`。
            // 驱动映像是内核自己(MmLoadSystemImage)打开的,RequestorMode 就是 KernelMode ——
            // 判定压根不会执行。于是这条下发唯一的效果是:白占 64 槽里的一个槽位、被内核写回
            // 注册表跨重启续留,而且协议上没有「删除单条」。槽位耗尽后【此后所有新的恶意裁决
            // 都被静默丢弃】(FileMonitor.c:200-212),这是无声的能力退化。
            //
            // 真实现场:卡巴斯基的 klids.sys 被「可写目录加载内核驱动」那条规则拦下,往
            // \Services\Bulwark\Policy\FileNoLoad 钉了一条永久条目,而驱动照常加载成功。
            //
            // (静态阅读 FileMonitor.c / ImageMonitor.c 得到的结论,未在真实内核里实测。)
            // 要真正做到「拦住驱动加载」得另起一条路(注册前拦服务创建 / 驱动签名准入),
            // 不是这份名单能做的事。
            //
            log_.info(QStringLiteral("禁止加载未下发(内核驱动加载走内核态打开,minifilter 无法拦截,"
                                     "下发只会白占 64 槽之一并跨重启续留):%1").arg(mod));
        } else {
            //
            // 【去盘符】内核名单按「去盘符、大小写不敏感的子串」匹配(FileMonitor.c:385),而它
            // 比对的是 FLT_FILE_NAME_NORMALIZED 规范名,形如 \Device\HarddiskVolume3\...。
            // 带盘符的条目("C:\...")永远不是那个串的子串,于是**一条都不会生效** ——
            // blacklistExec 早就做了这一步,这里漏了,所以「禁止加载」名单长期是个空壳。
            // 过短子串风险大(可能误拦无关模块),与 blacklistExec 同一门槛:< 6 字符放弃。
            //
            QString needle = mod;
            needle.replace(QLatin1Char('/'), QLatin1Char('\\'));
            if (needle.size() >= 2 && needle[1] == QLatin1Char(':'))
                needle = needle.mid(2);
            if (needle.size() < 6) {
                log_.info(QStringLiteral("禁止加载未下发(去盘符后子串过短,风险大于收益):%1").arg(mod));
            } else {
                blacklisted = source_->blockModuleLoad(needle);
            }
        }
    }

    // 进程创建类的确认恶意主体:加入内核「禁止执行」名单,使其【被守护进程/持久化/重启后规则命中
    // 拉起时】的再次启动被内核前拦(与下面结束进程配对——kill 收拾正在跑的,exec-block 挡再次启动)。
    // persistentBlacklist=false 的路径(超时兜底)跳过 —— 见声明处的说明。
    bool execDenied = false;
    if (e.type == bulwark::EventType::ProcessCreate) {
        if (persistentBlacklist) {
            execDenied = blacklistExec(e.actorPath);
        } else if (isTaintRuleNote(e.matchedRuleNote)) {
            //
            // 【污点命中:不进内核名单,但也不能什么前拦都没有】
            //
            // persistentBlacklist=false 有两个来源,必须分开对待:
            //   · 弹窗超时兜底 / 静默模式升级 —— 引擎的原始结论是「拿不准」,这种不确定的处置
            //     连跨重启的 ACE 都不该留,所以这里【不】接它(条件只认污点规则);
            //   · 命中「[污点-释放物]」规则 —— 那是「某个兄弟文件已被云端哈希确认恶意,这一批
            //     是同一次投递落下来的」,确定性足够支撑一个【可撤销】的执行前拦截。
            //
            // 实测缺口(2026-09-30):lclcache.exe 被中央服务器确认恶意(21/75)后登记了 19 个
            // 释放物 + 31 条污点规则,内核 FileExecBlock 里却始终只有 lclcache.exe 一条。于是
            // 双击其余 14 个样本时,每一个都先跑起来释放 DLL / 写 Run 项 / 外联,1-3 秒后才被
            // kill;wps.exe 更是在 21:12、21:14、21:20、21:21 被成功运行了 4 次。
            execDenied = denyExecuteRevocable(
                e.actorPath, QStringLiteral("命中污点规则(同批投递的确认恶意释放物)"));
        }
    }

    // 优先结束 RPC 真凶(如经 svchost 代发的请求),否则结束事件主体本身。
    const int pid = e.originatorPid > 0 ? e.originatorPid : e.actorPid;
    // 用户态结束整树 + 驱动级(内核 ZwTerminateProcess)兜底补刀(难被反杀);详见 killMalicious。
    if (killMalicious(pid))
        return EnforcementOutcome::Terminated;

    //
    // 没能结束任何进程。下面三种情形【都不是】「什么都没做」,所以必须排在 AlertedOnly 之前:
    // 原先它们全落进 AlertedOnly,而那条文案是「未做任何实际阻断,需要人工关注」——
    // 于是右下角弹「检测到危险行为,未能拦截」、语音念「请手动处理」,而我们其实已经处置到位。
    // 两处实测分别记在 Worker.h 里 killedByUs_ 与 denyExecuteRevocable 的声明处。
    //

    // (1) 主体已被【我们自己】此前的处置结束 —— 本条是它退出前排队的动作。
    //     用 e.actorPath 比对:此刻那个进程已经没了,查不到实时路径。originatorPid 生效时
    //     (经 svchost 代发)actorPath 不是它的映像,于是匹配不上 —— 宁可退回 AlertedOnly,
    //     也绝不凭 PID 单独认定(PID 会复用)。
    if (wasTerminatedByUs(pid, e.actorPath)) {
        log_.info(QStringLiteral("拦截处置:PID=%1 已在本次之前被本产品结束(本条是它退出前排队的"
                                 "动作),无需再处置:%2").arg(pid).arg(e.actorPath));
        return EnforcementOutcome::ActorAlreadyGone;
    }

    // (2) 该映像已被禁止再次启动(内核禁止执行名单 / 文件「拒绝执行」ACE)。
    if (execDenied) {
        log_.info(QStringLiteral("拦截处置:本次没有可结束的进程,但该映像已被禁止再次启动"
                                 "(下次启动将直接失败):%1").arg(e.actorPath));
        return EnforcementOutcome::ExecDenied;
    }

    // (3) 侧载模块已加入禁止加载名单:本次虽未拦下,下次加载会被内核前拦。
    if (blacklisted) {
        log_.info(QStringLiteral("拦截处置:侧载模块已加入内核禁止加载名单(下次加载将被前拦):%1")
                      .arg(e.target));
        return EnforcementOutcome::ModuleBlacklisted;
    }

    // 既非内核前拦、又无可结束的进程、又没留下任何形式的前拦:如实标记「仅告警,未实际拦截」。
    log_.warning(QStringLiteral("拦截处置:PID=%1 未能结束任何进程(已退出/受保护/关键进程),"
                                "该事件仅告警、未实际拦截。").arg(pid));
    return EnforcementOutcome::AlertedOnly;
}

// 登记「这个进程是我们结束的」。只在 killMalicious 确认目标真的退出之后调用。
void Worker::rememberTerminated(int pid, const QString& imagePath) {
    if (pid <= 4)
        return;
    const QDateTime now = QDateTime::currentDateTimeUtc();
    // 顺带清理:过期条目 + 超量丢最旧。刻意不引入定时器 —— 这份记录只用于消化同一波排队事件。
    for (auto it = killedByUs_.begin(); it != killedByUs_.end();) {
        if (it.value().second.secsTo(now) > kKilledMemoryTtlSecs)
            it = killedByUs_.erase(it);
        else
            ++it;
    }
    while (killedByUs_.size() >= kKilledMemoryMax) {
        auto oldest = killedByUs_.begin();
        for (auto it = killedByUs_.begin(); it != killedByUs_.end(); ++it)
            if (it.value().second < oldest.value().second)
                oldest = it;
        killedByUs_.erase(oldest);
    }
    // 路径可能解析不出来(进程已退出)。仍然登记:wasTerminatedByUs 对空路径一律不认,
    // 所以空条目不会造成误认,只是这一条起不到作用 —— 那是正确的保守方向。
    killedByUs_.insert(pid, qMakePair(imagePath.trimmed(), now));
}

bool Worker::wasTerminatedByUs(int pid, const QString& imagePath) const {
    const auto it = killedByUs_.constFind(pid);
    if (it == killedByUs_.constEnd())
        return false;
    const QString remembered = it.value().first;
    const QString asked = imagePath.trimmed();
    // 两头任一为空都不认:PID 单独作证不够(PID 会复用),宁可退回「仅告警」这个保守结论。
    if (remembered.isEmpty() || asked.isEmpty())
        return false;
    if (remembered.compare(asked, Qt::CaseInsensitive) != 0)
        return false;
    return it.value().second.secsTo(QDateTime::currentDateTimeUtc()) <= kKilledMemoryTtlSecs;
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

    //
    // 【ImageLoad 整类跳过(6b)】本函数隔离的是 e.actorPath,也就是「主体载荷」。对其他事件
    // 类型这个等式成立;ImageLoad 上不成立 —— 被拦的东西是 e.target(那个模块),actorPath
    // 是【宿主进程】。照常走下去就是:拦了一个坏 DLL,却把加载它的宿主 exe 搬进隔离区。
    //
    // 下面护栏 3(健康签名主体不隔离)能挡住宿主是签名程序的那一半,但挡不住「未签名宿主
    // 加载未签名模块」;而且就算挡住了,靠护栏兜住一个类型上就不该走到这儿的路径也不对。
    //
    // 刻意【不】改成「隔离 e.target」:那要处理正被映射进进程的模块(移文件会失败或让宿主
    // 崩),属独立改动。ImageLoad 的实际处置本来就走 enforceBlock 的「禁止加载」名单
    //(内核 FileNoLoad / 用户态 UserModeExecBlock),不依赖隔离区。
    if (e.type == bulwark::EventType::ImageLoad) {
        log_.info(QStringLiteral("拦截时隔离已跳过(模块加载事件:宿主不是载荷,处置走「禁止加载」名单):"
                                 "%1 -> %2").arg(e.actorPath, e.target));
        return;
    }

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
    // 默认策略 / 超时兜底 / 用户裁决的 Block 不触发,避免误清理良性程序(用户裁决另走
    // remediateOnUserBlock)。
    if (!isDeterministicMaliciousBlock(e, v))
        return;
    // 事件类型含 RegistryWrite / FileWrite:dropper 最常见的是在「写持久化 / 落载荷」这一步被拦,
    // 那时载荷已经落好、它的 FileWrite 足迹都在链里 —— 只认 ProcessCreate / RemoteThread 会让
    // 这一大类拦截一个释放物都不清。主体本身的安全性由 isSafeToRemove(系统目录 / 系统工具 /
    // 签名护栏)兜底;写注册表的主体已由 enrich 第 0 步把 SCM 还原成真凶。写类事件是否算
    // 「确定性恶意」见 isDeterministicMaliciousBlock(要求硬指标或情报/污点规则)。
    if (e.type != bulwark::EventType::ProcessCreate && e.type != bulwark::EventType::RemoteThread
        && e.type != bulwark::EventType::RegistryWrite && e.type != bulwark::EventType::FileWrite)
        return;
    if (e.actorPath.trimmed().isEmpty())
        return;

    // 足迹:进程链跟踪器收集该恶意进程树(含后代)记录过的全部事件——remediate 据此隔离
    // 其释放/关联的文件,并移除指向这些文件的注册表自启动 / IFEO / 服务持久化。
    const RemediationReport report = remediator_->remediate(e, chain_.collectTreeEvents(e.actorPid));
    applyRegHardening(report); // 持久化反重建:清掉的自启动项即刻加入内核注册表硬拦,挡住守护进程秒级重写

    publishRemediation(
        e, report,
        v.source == VerdictSource::Rule
            ? (e.matchedRuleNote.isEmpty() ? QString::fromUtf8("命中防护规则") : e.matchedRuleNote)
            : QString::fromUtf8("启发式判定恶意"),
        v.source);
}

void Worker::publishRemediation(const SecurityEvent& e, const RemediationReport& report,
                                const QString& reason, VerdictSource source) {
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
    ipc_->sendRemediationReport(makeRemediationPayload(e, reason, report));
    if (!report.quarantinedFiles.isEmpty())
        ipc_->sendQuarantineList(); // 主动回推,UI 隔离区页面无需再请求

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
    o["source"] = bulwark::verdictSourceToString(source);
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

bool Worker::isDeterministicMaliciousBlock(const SecurityEvent& e, const bulwark::Verdict& v) {
    if (v.action != VerdictAction::Block)
        return false;
    if (v.source != VerdictSource::Rule && v.source != VerdictSource::Heuristic)
        return false;
    if (e.type == bulwark::EventType::FileWrite || e.type == bulwark::EventType::RegistryWrite) {
        if (e.hasThreatIndicator)
            return true;
        // 情报规则([情报-*])与污点规则本身就是「对恶意样本的确认」推出来的。
        return e.matchedRuleNote.startsWith(QStringLiteral("[情报")) || isTaintRuleNote(e.matchedRuleNote);
    }
    return true;
}

// ============================================================================
// 连带处置「派生出恶意子进程的那个发起方」(为什么需要它、挂在哪道闸上见 Worker.h)
// ============================================================================
namespace {
// 宿主 / 外壳进程名:命中一律只记日志,绝不结束、绝不禁运、绝不隔离。
//
// 【为什么必须另加这一份,isSweepExemptPath 不够】那个函数只覆盖
// \windows\system32\ | \windows\syswow64\ | \windows\winsxs\ 与本产品的安装 / 数据目录,
// 而桌面外壳在 C:\Windows\explorer.exe —— 一条都不命中。结束 explorer 的进程树会把整个
// 用户会话(资源管理器 + 它派生出来的一切程序)一起带走,而 explorer 恰恰是用户双击任何
// 东西时的父进程,也就是这条连带处置最容易撞上的那一个。
//
// ProcessInspector::isCriticalProcess 也挡不住它:那个判据认的是内核 IsProcessCritical
// 标记与「结束即 bugcheck」的关键进程名单,explorer 结束不蓝屏,所以不在其中 ——
//「不蓝屏」和「可以杀」是两件不同的事。
//
// 【按名字匹配、不锚定路径,是刻意的】代价是:一个把自己改名成 explorer.exe 丢进 %TEMP%
// 的样本会从【这条连带处置】里逃掉。这个取舍是有意接受的 —— 它并没有逃掉检测,当它自己
// 作为主体触发事件时照样被正常处置;而反过来,一旦护栏漏掉真正的 explorer,后果是用户
// 整个桌面被杀,且不可逆。本方法是「由子进程的结论【推导】出来的」二阶处置,推导路径上
// 应当取保守的那一侧。
bool isHostOrShellProcessName(const QString& path) {
    static const QSet<QString> kNames = {
        QStringLiteral("explorer.exe"),        // 桌面外壳:结束它 = 杀掉整个用户会话
        QStringLiteral("services.exe"),   QStringLiteral("svchost.exe"),
        QStringLiteral("wininit.exe"),    QStringLiteral("winlogon.exe"),
        QStringLiteral("userinit.exe"),   QStringLiteral("lsass.exe"),
        QStringLiteral("lsaiso.exe"),     QStringLiteral("csrss.exe"),
        QStringLiteral("smss.exe"),       QStringLiteral("taskhostw.exe"),
        QStringLiteral("taskhost.exe"),   QStringLiteral("sihost.exe"),
        QStringLiteral("runtimebroker.exe"), QStringLiteral("dllhost.exe"),
        QStringLiteral("rundll32.exe"),   QStringLiteral("wmiprvse.exe"),
        QStringLiteral("searchindexer.exe"), QStringLiteral("fontdrvhost.exe"),
        QStringLiteral("dwm.exe"),        QStringLiteral("conhost.exe"),
        QStringLiteral("ctfmon.exe"),
    };
    return kNames.contains(QFileInfo(path).fileName().toLower());
}

// 空串 / 内核源在解析不出映像时填的 "PID 1234" 占位 —— 两者都不能拿来做路径判定:
// 占位串会让下面每一道路径护栏都判空,等于全部失效(同一道护栏在 trustNoteForPath /
// blacklistExec / maybeQuarantineOnBlock 里都有)。
bool unusableImagePath(const QString& p) {
    return p.isEmpty() || p.startsWith(QLatin1String("PID "), Qt::CaseInsensitive);
}

// 路径归一(仅用于两个来源的同一性比较):分隔符统一,比较时再忽略大小写。
QString normalizedForCompare(const QString& p) {
    QString s = p.trimmed();
    s.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return s;
}
} // namespace

void Worker::maybeHandleLaunchingParent(const SecurityEvent& e) {
    // 触发条件 1:只对【进程创建】且【带硬恶意指标】的确认恶意拦截生效。
    // 不带硬指标的 Block 大多是「保护型规则拦了一个动作」(写类事件的额外要求见
    // isDeterministicMaliciousBlock),那种结论里没有任何一句在说「派生它的那个进程恶意」。
    if (e.type != bulwark::EventType::ProcessCreate || !e.hasThreatIndicator)
        return;

    const int ppid = e.parentPid;
    // <= 4 是 Idle / System。等于 actorPid 或 originatorPid 时 enforceBlock 已经结束过它了,
    // 再走一遍只会在日志里造出「同一个东西被处置了两次」的假象。
    if (ppid <= 4 || ppid == e.actorPid || ppid == e.originatorPid)
        return;

    // 父路径。enrich 第 3 步【只在 e.parentPath 为空时】按 PID 实时反查,而短命父进程那一刻
    // 往往已经退出、反查不到,字段就一直是空的 —— 故这里补一次进程链历史回退(它记的是该
    // PID 早先 ProcessCreate 时的映像路径)。
    QString parentPath = e.parentPath.trimmed();
    if (unusableImagePath(parentPath))
        parentPath = chain_.lastKnownPath(ppid).trimmed();
    if (unusableImagePath(parentPath))
        return;

    // 护栏 1:本产品自身 / 用户已加白 —— 与所有处置路径同一口径。
    // trustNoteForPath 命中 matchesSelf 时会返回「本软件自身组件」,所以它同时是自身组件护栏;
    // isSelfComponent(e) 再查一遍原事件(它看 actorPath 与 parentPath),覆盖「父路径是从链
    // 历史回退来的、与事件字段不一致」的情形。少了任一边都会留下一个自处置的口子。
    if (engine_->isSelfComponent(e))
        return;
    if (const std::optional<QString> note = engine_->trustNoteForPath(parentPath)) {
        log_.info(QStringLiteral("连带处置发起方已跳过(该发起方已加白:%1):%2").arg(*note, parentPath));
        return;
    }

    // 护栏 2:系统目录 / 本产品目录。与兜底扫描、拦截时隔离、blacklistExec 共用同一份判定,
    // 不另抄一份(按真实路径前缀,不是名字子串 —— 见 isSweepExemptPath 上方那两处子串信任的记录)。
    if (isSweepExemptPath(parentPath)) {
        log_.info(QStringLiteral("连带处置发起方已跳过(系统目录 / 本产品自身):%1").arg(parentPath));
        return;
    }

    // 护栏 3:宿主 / 外壳进程。isSweepExemptPath 覆盖不到 C:\Windows\explorer.exe,
    // 详见 isHostOrShellProcessName —— 那是这条路径上最危险、也最容易撞上的一次误伤。
    if (isHostOrShellProcessName(parentPath)) {
        log_.warning(QStringLiteral("连带处置发起方已跳过(宿主 / 外壳进程,只记录不动手):%1(PID %2)"
                                    " —— 其派生的 %3 已被单独处置。")
                         .arg(parentPath).arg(ppid).arg(e.actorPath));
        return;
    }

    // 护栏 4:确认「这个 PID 此刻仍然是那个父进程」。
    //
    // ProcessChainTracker::forget() 在本项目里【没有任何调用点】,而且不是遗漏 —— 项目根本
    // 没有「进程已退出」遥测(见该方法上方的长注释:驱动的退出分支直接 return,ETW 只订阅
    // 创建)。于是链记录只按时间窗淘汰,Windows 复用 PID 时新进程会在窗口内继承旧进程的记录,
    // 也就是说上面回退来的 parentPath 完全可能属于【同一 PID 上的前一个进程】。
    //
    // 本方法的三个动作(结束进程树 / 内核禁运 / 隔离载荷)的正当性全都建立在「那个样本本体
    // 还在跑」之上;这一点确认不了,推导链就断了,而这三个动作任一个的误伤代价都远高于
    //「少处置一次」。故:实时反查 ppid 的映像路径,必须解析得到【且与 parentPath 相同】才动手。
    // 两个值都写进日志,这样偶发的不一致是可诊断的,而不是静默失效。
    const QString livePath = ProcessInspector::tryGetProcessImagePath(ppid);
    if (livePath.isEmpty()
        || normalizedForCompare(livePath).compare(normalizedForCompare(parentPath),
                                                  Qt::CaseInsensitive) != 0) {
        log_.info(QStringLiteral("连带处置发起方已放弃(无法确认 PID %1 仍是该父进程:实时映像=%2,"
                                 "事件/链记录=%3)—— 已退出或 PID 被复用,不据陈旧归因动手。")
                      .arg(ppid)
                      .arg(livePath.isEmpty() ? QStringLiteral("(解析不到)") : livePath)
                      .arg(parentPath));
        return;
    }

    // 护栏 5:发起方带可信签名 -> 放弃。
    //
    // 按【路径】验签,刻意【不用】TrustPolicy::isHealthySigned:那个判据读的是富化之后的
    // SecurityEvent 签名字段(它的注释也写明须在 ThreatDetector::analyze 之后调用)。这里手上
    // 只有一个路径,临时造一个空事件传进去会恒定返回「未签名」—— 那是一道看着像护栏、实际
    // 永不生效的死护栏。Worker::forceQuarantine 的注释里已经踩过并记下了这个坑。
    // collectForensics 一次取齐「可信签名 + SHA-256 + 是否真实文件 + 体积」,与逐项接口共用
    // 同一批缓存,比连着调三四个接口少好几遍 stat。
    const ProcessInspector::ForensicFacts facts =
        ProcessInspector::collectForensics(parentPath, /*includeCert=*/false);
    if (facts.trustedSignature) {
        log_.info(QStringLiteral("连带处置发起方已跳过(发起方持可信签名,不据子进程的结论反推它恶意):%1")
                      .arg(parentPath));
        return;
    }
    if (!facts.isRealFile) {
        // 路径指不到真实文件:上一步的「未签名」成了空话(不存在的文件一律验不出签名),
        // 隔离与内核禁运也无从谈起。唯一还剩的动作是结束进程,但那条的前提已经由护栏 4
        // 覆盖过 —— 走到这里说明归因本身可疑,保守放弃。
        log_.info(QStringLiteral("连带处置发起方已放弃(发起方路径指向的文件不存在,无法验签 / 隔离):%1")
                      .arg(parentPath));
        return;
    }

    // 触发条件 2:只对【可疑】的发起方动手 —— 未签名(上面已确认)且满足下面两条之一。
    //
    // 为什么必须有这道互证:「未签名」在绿色软件遍地的机器上区分度太低(解压即用的工具天然
    // 大批未签名),单凭它做连带处置会把一堆便携工具当成投递器。两条判据:
    //   · isSuspiciousDropDir:落在投递目录(Temp / Downloads / AppData 一族),与规则和打分
    //     共用同一份名单;
    //   · wasRecentlyWritten:这个文件本身就是 kRecentDropWindowSecs 内刚被别人写出来的。
    //
    // 刻意【不用】FirstSeenStore 做判据:它的接口是 markAndCheck —— 带落盘副作用的「查一次
    // 就算见过」。在护栏里调它等于把「首见」这件事消耗掉,污染后续真正需要它的判定。
    const bool inDropDir = bulwark::engine::ThreatDetector::isSuspiciousDropDir(parentPath);
    const bool justDropped = chain_.wasRecentlyWritten(parentPath, kRecentDropWindowSecs);
    if (!inDropDir && !justDropped) {
        log_.info(QStringLiteral("连带处置发起方已跳过(发起方未签名,但既不在投递目录、也不是最近才"
                                 "落地 —— 互证不成立,只记录):%1(PID %2)").arg(parentPath).arg(ppid));
        return;
    }

    // ---- 走到这里:构造一条描述【发起方】的事件,照 handleSweptMalicious 的模板处置 ----
    const QString childName = QFileInfo(e.actorPath).fileName();
    const QString suspicionWhy = inDropDir ? QStringLiteral("位于投递目录")
                                           : QStringLiteral("是最近才落地的文件");

    SecurityEvent ev;
    ev.type = bulwark::EventType::ProcessCreate;
    ev.actorPid = ppid;
    ev.actorPath = parentPath;
    ev.target = parentPath;
    ev.actorHash = facts.sha256;
    ev.actorFileSize = facts.fileSize;
    ev.actorPublisher = facts.publisher;      // 未签名 -> 通常为空,如实留空
    ev.commandLine = ProcessInspector::tryGetCommandLine(ppid);
    ev.userModeObserved = true;               // 事后补偿处置,不是内核前拦 —— 别把它显示成真前拦
    ev.hasThreatIndicator = true;
    ev.riskScore = 90;                        // >= HighRisk:引擎已对其派生进程给出确定性恶意结论
    ev.detail = QStringLiteral("因其派生进程被确认恶意而连带处置:%1(PID %2)%3")
                    .arg(childName)
                    .arg(e.actorPid)
                    .arg(e.matchedRuleNote.isEmpty() ? QString()
                                                     : QStringLiteral(" · 规则:") + e.matchedRuleNote);
    // 按证据登记(addEvidence 同时进 riskReasons,与原来两行 append 等价)。这条事件是现场构造的、
    // 没经过引擎,不登记的话证据链为空,拦截通知与拦截记录都说不出它为什么被处置、是什么。
    ev.addEvidence(QStringLiteral("LaunchingParent"), bulwark::EvidenceKind::HardIndicator, ev.detail);
    ev.addEvidence(QStringLiteral("LaunchingParent"), bulwark::EvidenceKind::Corroboration,
                   QStringLiteral("发起方未签名且%1").arg(suspicionWhy));

    // 日志刻意写成【一次】处置。killMalicious 走的是 terminateProcessTree,结束父进程树时会
    // 连带结束它的后代 —— 包括刚被 enforceBlock 结束的那个子进程。写成「两次独立处置」会让
    // 读日志的人以为样本又派生了一轮,那是凭空多出来的一条攻击链。
    const QString head =
        QStringLiteral("连带处置发起方:子进程 %1 已被确认恶意,其发起方 %2(PID %3)未签名且%4 ——"
                       "结束其进程树(含刚被拦下的该子进程)并清理足迹。")
            .arg(childName, parentPath)
            .arg(ppid)
            .arg(suspicionWhy);
    log_.warning(head);
    ipc_->sendLog(head);

    bulwark::EnforcementOutcome outcome = bulwark::EnforcementOutcome::AlertedOnly;
    if (killMalicious(ppid))
        outcome = bulwark::EnforcementOutcome::Terminated;

    //
    // blacklistExec:【下发】。这份名单(内核 FileExecBlock)只加不减、由内核写回注册表跨重启
    // 续拦、协议上没有「删除单条」—— 代价极不对称,所以必须逐条说清为什么这里敢下发:
    //
    //   · 判据强度够:引擎对其派生进程给出的是「确定性恶意 + 硬指标」,而这个发起方本身
    //     【未签名】且【位于投递目录或刚刚落地】。这正是 blacklistExec 存在的理由 —— 被持久化
    //     / 守护进程重新拉起的样本本体;只结束进程的话它下次开机照样回来,而本改动的出发点
    //     恰恰就是「样本本体没被处置」。
    //   · blacklistExec 自带的两道闸正好挡住了历史上出事的那一类:已加白的映像跳过、系统目录
    //     与本产品目录跳过。CMD.EXE 被钉进名单那次事故(记录在 blacklistExec 里)的根因是
    //     【系统程序】被下发,而系统程序在这里连护栏 2 / 3 都过不去。
    //   · 有恢复路径,不是「只能手改注册表」:用户在 UI 加白后 reconcileKernelBlocksAfterTrust
    //     会从注册表读回内核的权威名单、剔掉命中已加白目标的条目,再整表重下发。
    //
    // 这套理由依赖「未签名」与「投递目录 / 刚落地」这两个条件同时在场。将来若放宽其中任一条,
    // 必须连这段一起重新评估 —— 别让判据悄悄变松而结论(可以永久禁运)留在原地。
    //
    blacklistExec(parentPath);

    ipc_->sendBlock(ev, outcome);   // 处置之后再通知,通知里写的才是真事(见 onEvent 处的说明)
    recordEvent(ev, VerdictAction::Block, VerdictSource::Heuristic, outcome);
    // 隔离载荷 + 清除持久化。这里终于是对【样本本体】做清理:原实现把系统程序当主体,
    // 于是 isSafeToRemove 的系统目录护栏会把整批候选跳过,一个释放物都清不掉。
    remediateIfMalicious(ev, bulwark::Verdict::forEvent(ev, VerdictAction::Block,
                                                        VerdictSource::Heuristic));
    // 发起方是确定性恶意 -> 其释放物按硬拦标污点(与 taintDroppedFiles 的 Block 档一致)。
    taintDroppedFiles(ev, VerdictAction::Block, QStringLiteral("发起方因派生恶意进程被连带确认"));
}

void Worker::remediateOnUserBlock(const SecurityEvent& e) {
    if (!remediator_)
        return;
    if (e.type != bulwark::EventType::ProcessCreate && e.type != bulwark::EventType::RemoteThread
        && e.type != bulwark::EventType::RegistryWrite && e.type != bulwark::EventType::FileWrite)
        return;
    const QString actor = e.actorPath.trimmed();
    if (actor.isEmpty() || actor.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return;
    // 与所有处置路径同一口径:已加白 / 本产品自身不动。
    if (const std::optional<QString> note = engine_->trustNoteForPath(actor)) {
        log_.info(QStringLiteral("用户阻止后的足迹清理已跳过(该主体已加白:%1):%2").arg(*note, actor));
        return;
    }
    if (engine_->isSelfComponent(e))
        return;

    // 优先清 RPC 真凶(与 enforceBlock 结束的是同一棵树)。
    const int pid = e.originatorPid > 0 ? e.originatorPid : e.actorPid;
    const RemediationReport report = remediator_->remediate(e, chain_.collectTreeEvents(pid));
    applyRegHardening(report);
    publishRemediation(e, report, QString::fromUtf8("用户选择阻止"), VerdictSource::UserPrompt);
}

// ============================================================================
// 释放物污点(设计与护栏见 Worker.h taintDroppedFiles 的说明)
// ============================================================================
namespace {
constexpr int kTaintMaxPerBlock   = 20;   // 单次拦截最多标这么多个文件
constexpr int kTaintMaxTotal      = 200;  // 规则库里污点规则总量上限(规则库是定长预算)
constexpr int kTaintConfirmedDays = 30;   // 确定性恶意 -> 硬拦有效期
constexpr int kTaintUserDays      = 7;    // 用户阻止 / 超时兜底 -> 询问有效期

// 污点规则 note 里固定带「 · 路径=<完整路径>」尾段:哈希规则没有路径字段,撤销(加白 / 用户放行)
// 时靠它把同一文件的路径规则与哈希规则一起找出来。
const QString& taintPathMarker() {
    static const QString m = QStringLiteral(" · 路径=");
    return m;
}

QString taintNotePath(const QString& note) {
    const int i = note.lastIndexOf(taintPathMarker());
    return i < 0 ? QString() : note.mid(i + taintPathMarker().size()).trimmed();
}

enum class TaintKind { None, Exec, Script, Module };

// 按扩展名决定污点规则形态:
//   Exec   -> ProcessCreate,按主体路径 + 哈希匹配(被改名 / 搬走也能命中);
//   Script -> ProcessCreate,按命令行匹配(主体是 powershell / wscript / msiexec 这类宿主);
//   Module -> ImageLoad,按目标模块路径匹配(白加黑侧载的正面覆盖)。
TaintKind taintKindOf(const QString& path) {
    static const QSet<QString> kExec   = { QStringLiteral("exe"), QStringLiteral("scr"), QStringLiteral("com") };
    static const QSet<QString> kScript = {
        QStringLiteral("bat"), QStringLiteral("cmd"), QStringLiteral("ps1"), QStringLiteral("vbs"),
        QStringLiteral("vbe"), QStringLiteral("js"),  QStringLiteral("jse"), QStringLiteral("wsf"),
        QStringLiteral("hta"), QStringLiteral("jar"), QStringLiteral("msi"), QStringLiteral("msp") };
    static const QSet<QString> kModule = {
        QStringLiteral("dll"), QStringLiteral("ocx"), QStringLiteral("cpl"), QStringLiteral("drv"),
        QStringLiteral("sys") };
    const QString ext = QFileInfo(path).suffix().toLower();
    if (kExec.contains(ext))   return TaintKind::Exec;
    if (kScript.contains(ext)) return TaintKind::Script;
    if (kModule.contains(ext)) return TaintKind::Module;
    return TaintKind::None;
}

// 去盘符的路径尾段(与 blacklistExec 同理):ImageLoad 目标 / 命令行里既可能是 C:\... 也可能是
// \Device\HarddiskVolumeN\...,二者都包含去盘符后的 "\Users\...\x.dll"。
QString driveAgnostic(const QString& path) {
    QString p = path.trimmed();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (p.size() >= 2 && p[1] == QLatin1Char(':'))
        p = p.mid(2);
    return p;
}

// 「公共落地根目录」:Temp / Downloads / Desktop / AppData 根 / ProgramData 根 / 用户目录根 / 盘符根。
// 签名写入方(浏览器、msiexec、解压工具)会往这些目录写一大堆互不相干的文件,
// 不能按「同一写入方 + 同一目录」把它们打成一批。
bool isSharedDropRoot(const QString& dir) {
    QString d = dir.toLower();
    d.replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (d.endsWith(QLatin1Char('\\')))
        d.chop(1);
    if (d.size() <= 3)
        return true;
    static const char* const kRoots[] = {
        "\\appdata\\local\\temp", "\\windows\\temp", "\\downloads", "\\desktop", "\\documents",
        "\\users\\public", "\\appdata\\roaming", "\\appdata\\local", "\\programdata", "\\temp", "\\tmp",
    };
    for (const char* r : kRoots)
        if (d.endsWith(QLatin1String(r)))
            return true;
    const int u = d.indexOf(QLatin1String("\\users\\"));
    if (u >= 0 && d.indexOf(QLatin1Char('\\'), u + 7) < 0)
        return true; // X:\Users\<name>
    return false;
}

struct TaintCandidate {
    QString path;
    TaintKind kind = TaintKind::None;
};

// 「写出被拦主体的那个 dropper」同批写出的文件。签名 / 系统写入方(restricted)只收与主体
// 同一私有目录下的,见 isSharedDropRoot。
struct TaintDropperBatch {
    QString dropperPath;
    bool dropperIsSystem = false;     // 系统目录 / 路径未知 -> 直接按 restricted 处理
    QString subjectDir;
    QVector<TaintCandidate> files;
    TaintCandidate dropperSelf;       // dropper 自身(未签名时才标)
};

struct TaintResult {
    QString path;
    TaintKind kind = TaintKind::None;
    QString sha256;   // 小写;算不出为空
    //
    // 这个候选是【被拦主体自己写出来的】(false),还是【只是和它同一批被第三方写出来的】(true)。
    //
    // 两者的证据强度差一个量级,必须分开定级:
    //   · false:被确认恶意的那个进程亲手释放的文件 —— 它就是载荷本身,硬拦成立;
    //   · true :某个第三方 dropper(压缩软件 / 浏览器 / 安装器)在同一个目录里写出的兄弟文件。
    //           「和恶意文件同一次解包」是一条关联,不是对这个文件的任何判定。
    // 实测代价:360zip.exe 把一个压缩包解到 Desktop\新建文件夹 (5)\,其中一个文件被中央服务器
    // 确认恶意(21/75),于是同目录另外 18 个全部拿到 Block + hardOverride 的污点规则。
    // 四方接码客户端.exe 就是这么被结束进程 + 隔离 + 加上跨重启拒绝执行 ACE 的 —— 它自己的
    // 证据链只有「无可信数字签名 / 未签名程序从可疑目录运行 / 命令行熵 4.7」,hasThreatIndicator
    // 为 false,风险 56,云端对它的哈希【未收录】。也就是说:没有任何一条证据说它是恶意的。
    bool byAssociation = false;
};
} // namespace

QString Worker::taintRuleTag() {
    return QStringLiteral("[污点-释放物]");
}

bool Worker::isTaintRuleNote(const QString& note) {
    return note.startsWith(taintRuleTag());
}

void Worker::taintDroppedFiles(const SecurityEvent& e, VerdictAction grade, const QString& why) {
    if (!injectIntelRules_)
        return;
    if (grade != VerdictAction::Block && grade != VerdictAction::Ask)
        return;
    const QString actor = e.actorPath.trimmed();
    if (actor.isEmpty() || actor.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return;
    if (engine_->isSelfComponent(e))
        return;
    if (engine_->trustNoteForPath(actor))
        return; // 主体已加白:没有「被拦」可传

    QSet<QString> seen;
    // 主线程上只做纯字符串 / 规则集判定;存在性、验签、哈希全交后台。
    auto eligible = [&](const QString& raw, TaintCandidate* out) -> bool {
        const QString p = raw.trimmed();
        if (p.isEmpty())
            return false;
        const QString key = p.toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
        if (seen.contains(key))
            return false;
        const TaintKind kind = taintKindOf(p);
        if (kind == TaintKind::None)
            return false;
        if (isSweepExemptPath(p))                       // System32 / SysWOW64 / WinSxS / 本产品
            return false;
        if (!ThreatRemediator::isInUserDropZone(p))     // 与足迹清理同一份落地区 / 保护区名单
            return false;
        if (engine_->trustNoteForPath(p))               // 已加白
            return false;
        seen.insert(key);
        out->path = p;
        out->kind = kind;
        return true;
    };

    QVector<TaintCandidate> direct;
    auto addDirect = [&](const QString& p) {
        TaintCandidate c;
        if (direct.size() < kTaintMaxPerBlock && eligible(p, &c))
            direct.append(c);
    };

    // 0) 侧载被拦时,被加载的那个模块本身就是载荷。
    if (e.type == bulwark::EventType::ImageLoad)
        addDirect(e.target);

    // 1) 被拦主体(及后代)写过的文件。健康签名主体(LOLBin 被拦的是用法)只收它自己写的,
    //    不下探后代 —— 否则 explorer / 签名宿主的「后代」可能是半个桌面会话。
    const bool actorHealthySigned = TrustPolicy::isHealthySigned(e).ok;
    for (const QString& p : chain_.filesWrittenBy(e.actorPid, actor, !actorHealthySigned))
        addDirect(p);
    if (e.originatorPid > 0 && e.originatorPid != e.actorPid)
        for (const QString& p : chain_.filesWrittenBy(e.originatorPid, QString(), false))
            addDirect(p);

    // 2) 被拦的东西本身是刚被释放出来的 -> 回溯写出它的 dropper,把同批的其他载荷一起标。
    //    这是污点最大的实际收益:银狐类投递链一次落一整套(白 exe + 黑 dll + 载荷)。
    QVector<TaintDropperBatch> batches;
    QStringList subjects{ actor };
    if (e.type == bulwark::EventType::ImageLoad && !e.target.trimmed().isEmpty())
        subjects << e.target.trimmed();
    for (const QString& subject : subjects) {
        const bulwark::engine::ProcessChainTracker::Writer w =
            chain_.lastWriterOf(subject, kRecentDropWindowSecs);
        if (!w.isValid() || w.pid == e.actorPid)
            continue;
        if (!w.path.isEmpty() && engine_->trustNoteForPath(w.path))
            continue; // 写入方已加白(用户信任的安装器):不把它整批标掉
        TaintDropperBatch b;
        b.dropperPath = w.path;
        b.dropperIsSystem = w.path.isEmpty() || isSweepExemptPath(w.path);
        b.subjectDir = QFileInfo(subject).absolutePath().replace(QLatin1Char('/'), QLatin1Char('\\'));
        for (const QString& p : chain_.filesWrittenBy(w.pid, w.path, true)) {
            TaintCandidate c;
            if (b.files.size() < kTaintMaxPerBlock && eligible(p, &c))
                b.files.append(c);
        }
        if (!b.dropperIsSystem)
            eligible(w.path, &b.dropperSelf);
        if (!b.files.isEmpty() || !b.dropperSelf.path.isEmpty())
            batches.append(b);
    }

    if (direct.isEmpty() && batches.isEmpty())
        return;

    QString reason = why.trimmed();
    if (isTaintRuleNote(reason))
        reason = QStringLiteral("关联释放物再次被拦");
    if (reason.size() > 60)
        reason = reason.left(60) + QStringLiteral("…");
    const QString subjectActor = actor;

    // 后台:存在性 + 验签 + SHA-256。签名文件跳过,除非其哈希已被确认恶意(BYOVD / 被盗证书)。
    taintPool_.start([this, direct, batches, grade, reason, subjectActor]() {
        auto knownBad = [this](const QString& sha) {
            if (sha.isEmpty())
                return false;
            QMutexLocker lk(&maliciousHashMx_);
            return confirmedMaliciousHashes_.contains(sha);
        };
        QVector<TaintResult> results;
        int skippedSigned = 0;
        auto consider = [&](const TaintCandidate& c, bool byAssociation) {
            if (results.size() >= kTaintMaxPerBlock || c.path.isEmpty())
                return;
            if (!QFileInfo(c.path).isFile())
                return;
            const QString sha = QuarantineManager::tryComputeSha256(c.path).toLower();
            if (ProcessInspector::isSigned(c.path) && !knownBad(sha)) {
                ++skippedSigned;
                return;
            }
            results.append(TaintResult{ c.path, c.kind, sha, byAssociation });
        };
        // 被拦主体(及其后代)亲手写出来的:它们就是载荷,按传入的档位处置。
        for (const TaintCandidate& c : direct)
            consider(c, /*byAssociation=*/false);
        for (const TaintDropperBatch& b : batches) {
            const bool restricted = b.dropperIsSystem || ProcessInspector::isSigned(b.dropperPath);
            if (restricted && isSharedDropRoot(b.subjectDir))
                continue; // 签名写入方 + 公共目录:同批关系不成立
            const QString dirPrefix = b.subjectDir.toLower() + QLatin1Char('\\');
            for (const TaintCandidate& c : b.files) {
                if (restricted && !c.path.toLower().replace(QLatin1Char('/'), QLatin1Char('\\'))
                                       .startsWith(dirPrefix))
                    continue;
                // 同批兄弟:只是关联,不是对这个文件的判定 -> 一律降为「运行前询问」。
                consider(c, /*byAssociation=*/true);
            }
            if (!restricted) {
                // 未签名 dropper 自身(被植入的安装包 / 下载器)。它【不是】旁观的兄弟文件:
                // 恶意载荷是从它肚子里出来的,这一点由它自己的行为作证,所以不算关联档。
                consider(b.dropperSelf, /*byAssociation=*/false);
            }
        }
        if (results.isEmpty())
            return;
        QMetaObject::invokeMethod(
            this,
            [this, results, grade, reason, subjectActor, skippedSigned]() {
                // 编组回主线程后再查一次加白:后台期间用户完全可能刚加白了其中某个文件。
                const QDateTime now = QDateTime::currentDateTimeUtc();
                QVector<bulwark::DefenseRule> rules;
                QStringList tainted;
                QStringList askedOnly;
                for (const TaintResult& r : results) {
                    if (engine_->trustNoteForPath(r.path))
                        continue;
                    //
                    // 档位【逐条】决定,不再整批共用传入的 grade。
                    //
                    // 硬拦只给「被拦主体亲手释放的载荷」;只是同一次解包出来的兄弟文件一律降为
                    // 询问(理由见 TaintResult::byAssociation)。这条区分是本轮加的 —— 原来两者
                    // 共用 grade,于是一个压缩包里混着一份恶意样本,就会让同目录其它文件全部拿到
                    // Block + hardOverride,并经 enforceBlock 走到结束进程树、隔离、跨重启拒绝
                    // 执行 ACE。那是在没有任何一条针对该文件的证据的情况下做出的处置。
                    //
                    // 关联档仍然有用:它把判断权交回用户(运行前询问),而不是默默放过;到期也
                    // 更短(kTaintUserDays)。静默模式下它会按静默语义放行并留痕 —— 用户既然选了
                    // 「不要问我」,对一条「拿不准」的关联就不该替他做销毁性处置。
                    const bool hard = grade == VerdictAction::Block && !r.byAssociation;
                    const QDateTime expires = now.addDays(hard ? kTaintConfirmedDays : kTaintUserDays);
                    const QString verb = hard ? QStringLiteral("禁止运行/加载")
                                              : QStringLiteral("运行/加载前询问");
                    const QString why = r.byAssociation ? (reason + QStringLiteral("(同批解包的关联文件)"))
                                                        : reason;
                    const QString base = taintRuleTag() + QStringLiteral(" ") + why
                                       + QStringLiteral(" · ") + verb;
                    const QString tail = taintPathMarker() + r.path;
                    auto make = [&]() {
                        bulwark::DefenseRule d;
                        d.action = hard ? VerdictAction::Block : VerdictAction::Ask;
                        d.hardOverride = hard;
                        d.expiresUtc = expires;
                        return d;
                    };
                    const QString needle = driveAgnostic(r.path);
                    switch (r.kind) {
                        case TaintKind::Exec: {
                            bulwark::DefenseRule d = make();
                            d.type = bulwark::EventType::ProcessCreate;
                            d.actorPath = r.path;
                            d.note = base + tail;
                            rules.append(d);
                            if (r.sha256.size() == 64) {
                                bulwark::DefenseRule h = make();
                                h.type = bulwark::EventType::ProcessCreate;
                                h.actorHashes.insert(r.sha256);
                                h.note = base + QStringLiteral("(sha256 ") + r.sha256.left(12)
                                       + QStringLiteral("…)") + tail;
                                rules.append(h);
                            }
                            break;
                        }
                        case TaintKind::Script: {
                            if (needle.size() < 6)
                                continue;
                            bulwark::DefenseRule d = make();
                            d.type = bulwark::EventType::ProcessCreate;
                            d.commandLinePattern = QStringLiteral("*") + needle + QStringLiteral("*");
                            d.note = base + tail;
                            rules.append(d);
                            break;
                        }
                        case TaintKind::Module: {
                            if (needle.size() < 6)
                                continue;
                            bulwark::DefenseRule d = make();
                            d.type = bulwark::EventType::ImageLoad;
                            d.targetPattern = QStringLiteral("*") + needle;
                            d.note = base + tail;
                            rules.append(d);
                            break;
                        }
                        default:
                            continue;
                    }
                    if (hard)
                        tainted << r.path;
                    else
                        askedOnly << r.path;
                }
                if (rules.isEmpty())
                    return;
                evictOldTaintRules(static_cast<int>(rules.size()));
                const int added = injectIntelRules_ ? injectIntelRules_(rules) : 0;
                //
                // 如实区分「布防成功」与「一条都没生效」。
                //
                // injectIntelRules_ 返回的是【真正入库的条数】:去重命中(同一释放物已被标过)
                // 或规则库定长预算被占满时它会返回 0 —— 那意味着这些释放物下次运行时【不会】
                // 被拦。原来的文案不看这个返回值,一律写「标记其释放物 N 个」,于是 0 条生效
                // 时日志读起来和成功布防一模一样。这条链路本来就是为「拦了主体、但它释放的
                // 东西还在盘上」兜底的,布防没成还报成功等于把缺口盖住。
                //
                //
                // 两个档位要分开报,不能合成一个数字。
                //
                // 「硬拦 N 个」和「询问 M 个」对用户的意义完全不同:前者意味着那些文件再也起
                // 不来,后者意味着下次运行会问他一句(静默模式下则是放行并留痕)。原文案只有
                // 一个总数 + 一个按整批 grade 算出来的 scope,在逐条定级之后那句话就不成立了。
                //
                QStringList parts;
                if (!tainted.isEmpty())
                    parts << QStringLiteral("硬拦 %1 个(再次运行/加载即拦截,%2 天内有效):%3")
                                 .arg(tainted.size())
                                 .arg(kTaintConfirmedDays)
                                 .arg(tainted.join(QStringLiteral("; ")));
                if (!askedOnly.isEmpty())
                    parts << QStringLiteral("询问 %1 个(同批解包的关联文件,证据只到「关联」,"
                                            "故运行/加载前询问而不直接拦,%2 天内有效):%3")
                                 .arg(askedOnly.size())
                                 .arg(kTaintUserDays)
                                 .arg(askedOnly.join(QStringLiteral("; ")));
                const int total = tainted.size() + askedOnly.size();
                QString msg;
                if (added > 0) {
                    msg = QStringLiteral("释放物已布防:%1 被拦(%2),共登记 %3 个"
                                         "(新增规则 %4 条,跳过带可信签名 %5 个)。%6")
                              .arg(subjectActor, reason)
                              .arg(total)
                              .arg(added)
                              .arg(skippedSigned)
                              .arg(parts.join(QStringLiteral(" | ")));
                    log_.warning(msg);
                } else {
                    msg = QStringLiteral("释放物【未能布防】:%1 被拦(%2),找到释放物 %3 个,"
                                         "但一条规则都没能生效(已被标记过,或规则库预算已满)"
                                         "—— 这些文件再次运行时不会被本条策略管住。%4")
                              .arg(subjectActor, reason)
                              .arg(total)
                              .arg(parts.join(QStringLiteral(" | ")));
                    log_.warning(msg);
                }
                ipc_->sendLog(msg);
            },
            Qt::QueuedConnection);
    });
}

int Worker::evictOldTaintRules(int incoming) {
    QVector<QPair<QDateTime, QUuid>> taint;
    for (const bulwark::DefenseRule& r : engine_->getRules())
        if (isTaintRuleNote(r.note))
            taint.append(qMakePair(r.createdUtc, r.id));
    const int over = static_cast<int>(taint.size()) + incoming - kTaintMaxTotal;
    if (over <= 0)
        return 0;
    std::stable_sort(taint.begin(), taint.end(),
                     [](const QPair<QDateTime, QUuid>& a, const QPair<QDateTime, QUuid>& b) {
                         return a.first < b.first;
                     });
    int removed = 0;
    for (int i = 0; i < over && i < taint.size(); ++i)
        if (engine_->removeRule(taint[i].second))
            ++removed;
    if (removed > 0) {
        ruleStore_->save(engine_->getRules());
        log_.info(QStringLiteral("释放物污点:规则总量达上限 %1,已淘汰最旧的 %2 条。")
                      .arg(kTaintMaxTotal).arg(removed));
    }
    return removed;
}

void Worker::dropTaintRulesMatching(const SecurityEvent& e) {
    const QVector<bulwark::DefenseRule> all = engine_->getRules();
    // 先找命中本事件的污点规则,取出它们登记的文件路径;再把同一文件的所有污点规则
    // (路径规则 + 哈希规则)一并删除。
    QSet<QString> paths;
    for (const bulwark::DefenseRule& r : all)
        if (isTaintRuleNote(r.note) && r.matches(e)) {
            const QString p = taintNotePath(r.note);
            if (!p.isEmpty())
                paths.insert(p.toLower());
        }
    if (paths.isEmpty())
        return;
    int removed = 0;
    for (const bulwark::DefenseRule& r : all)
        if (isTaintRuleNote(r.note) && paths.contains(taintNotePath(r.note).toLower())
            && engine_->removeRule(r.id))
            ++removed;
    if (removed > 0) {
        ruleStore_->save(engine_->getRules());
        const QString msg = QStringLiteral("释放物污点:用户已放行,撤销该文件的污点规则 %1 条:%2")
                                .arg(removed).arg(QStringList(paths.values()).join(QStringLiteral("; ")));
        log_.info(msg);
        ipc_->sendLog(msg);
    }
}

void Worker::purgeTaintRulesAfterTrust() {
    int removed = 0;
    for (const bulwark::DefenseRule& r : engine_->getRules()) {
        if (!isTaintRuleNote(r.note))
            continue;
        const QString p = taintNotePath(r.note);
        if (!p.isEmpty() && engine_->trustNoteForPath(p) && engine_->removeRule(r.id))
            ++removed;
    }
    if (removed > 0) {
        ruleStore_->save(engine_->getRules());
        log_.info(QStringLiteral("加白后撤销释放物污点规则 %1 条。").arg(removed));
    }
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
    // 原因按【硬指标证据】登记(addEvidence 默认同时追加进 riskReasons,与原来那行 append 等价)。
    // 只进 riskReasons 时证据链里没有它:拦截记录的「判定依据」只列证据链,于是看不到「是云端
    // 判的恶意」。有引擎计数时也把威胁名写上 —— 原来有计数就不写名字,而名字才说明拦下的是什么。
    const QString threatName = rep.threatLabel.trimmed();
    ev.addEvidence(QStringLiteral("Reputation"), bulwark::EvidenceKind::HardIndicator,
                   QStringLiteral("%1 判定恶意:%2").arg(
                       intelSourceDisplayName(srcName),
                       rep.totalEngines > 0 && !threatName.isEmpty()
                           ? QStringLiteral("%1(%2)").arg(detail, threatName)
                           : detail));
    // 先结束进程树(样本可能仍在运行)并据真实结果如实记录处置;关键系统进程由内部安全门槛保护。
    // 未能结束(进程已退出)时标 AlertedOnly——载荷仍会在下方 remediate 阶段被隔离失活。
    bulwark::EnforcementOutcome outcome = bulwark::EnforcementOutcome::AlertedOnly;
    if (killMalicious(ev.actorPid))
        outcome = bulwark::EnforcementOutcome::Terminated;
    // 执行前拦截:把该恶意映像加入内核禁止执行名单,挡住其被守护进程/持久化拉起时的再次启动。
    blacklistExec(ev.actorPath);
    // 通知在处置之后发,如实带上「进程树到底结束了没有」(见 onEvent 处说明)。
    ipc_->sendBlock(ev, outcome);
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
    // 释放物污点:云端画像只覆盖「沙箱里见过的」释放物;本机实际观测到的同批落地物在这里补上。
    taintDroppedFiles(ev, VerdictAction::Block, QStringLiteral("%1 确认恶意").arg(srcName));

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

        // 同 vtScanLoop:异常逸出线程函数 = std::terminate = 防护服务整体死亡。
        // queryIp 内部有限流等待与一次 curl 调用,不是不会抛的代码。
        try {
            const bulwark::IpReputation rep = ipIntel_->queryIp(job.ip); // 阻塞:限流 + 一次 curl
            {
                QMutexLocker lk(&ipMx_);
                ipInflight_.remove(job.ip);
                if (rep.querySucceeded) // 失败不缓存(下次可重试),与 .NET fail-open 一致
                    ipCache_.insert(job.ip, { rep.verdict, QDateTime::currentDateTimeUtc() });
                pruneIpCacheLocked();
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
        } catch (const std::exception& ex) {
            QMutexLocker lk(&ipMx_);
            ipInflight_.remove(job.ip);   // 否则该 IP 永久卡在「在途」,再也不查
            log_.error(QStringLiteral("IP 情报线程异常(已忽略本次任务 %1):%2")
                           .arg(job.ip, QString::fromUtf8(ex.what())));
        } catch (...) {
            QMutexLocker lk(&ipMx_);
            ipInflight_.remove(job.ip);
            log_.error(QStringLiteral("IP 情报线程未知异常(已忽略本次任务 %1)").arg(job.ip));
        }
    }
}

// 先按 TTL 清掉真正过期的条目;若仍超上限,再按时间戳丢最旧的一批。
// 只在插入后调用,复杂度与表大小同阶但触发很稀疏(每次外联查询一次 TTL 扫描)。
void Worker::pruneIpCacheLocked() {
    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (auto it = ipCache_.begin(); it != ipCache_.end();) {
        if (it.value().second.msecsTo(now) >= kIpIntelCacheTtlMs)
            it = ipCache_.erase(it);
        else
            ++it;
    }
    if (ipCache_.size() <= kIpCacheMax)
        return;
    // 仍超限(TTL 内的活跃条目就很多):按时间戳升序丢掉最旧的,保留最近的 kIpCacheMax 条。
    QList<QPair<QDateTime, QString>> byAge;
    byAge.reserve(ipCache_.size());
    for (auto it = ipCache_.constBegin(); it != ipCache_.constEnd(); ++it)
        byAge.append({ it.value().second, it.key() });
    std::sort(byAge.begin(), byAge.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    const int drop = ipCache_.size() - kIpCacheMax;
    for (int i = 0; i < drop; ++i)
        ipCache_.remove(byAge.at(i).second);
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
    // 按硬指标证据登记(同 onReputationMalicious;addEvidence 同时进 riskReasons),并带上微步给的
    // 威胁标签(C2 / Botnet …)—— 原来只进 riskReasons 且不带标签,通知与拦截记录都说不出拦的是什么。
    ev.addEvidence(QStringLiteral("IpReputation"), bulwark::EvidenceKind::HardIndicator,
                   QStringLiteral("微步 IP 信誉:远端 %1 判定为恶意%2").arg(ip, suffix));

    // 补偿处置:结束外联进程树(用户态观测源无法在连接前阻断)。关键系统进程由内部安全门槛保护。
    // 据真实结果如实记录;未能结束(进程已退出)时标 AlertedOnly。
    const int pid = ev.originatorPid > 0 ? ev.originatorPid : ev.actorPid;
    bulwark::EnforcementOutcome outcome = bulwark::EnforcementOutcome::AlertedOnly;
    if (killMalicious(pid))
        outcome = bulwark::EnforcementOutcome::Terminated;
    ipc_->sendBlock(ev, outcome);   // 处置之后再通知(见 onEvent 处说明)

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
    // 放在 recordEvent 而不是 onEvent:所有终态路径(同步派发、用户裁决、超时兜底、信誉 /
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
// 侧载检测(「白加黑」):主体目录里有没有可疑模块。两种形态,一次扫描同时判:
//
//   形态 1 · 模块【内嵌厂商签名但校验不过】(被改过的正规模块)-> e.tamperedModulePath。
//     补的是一处实测漏检 —— 详见 SecurityEvent::tamperedModulePath 的说明:AOMEI 正规签名的
//     DigitalUnit.exe 当白壳,同目录被篡改的 QtCore4.dll 是黑件,靠计划任务每 19 分钟拉起,
//     而每次的裁决都是「签名健康 -> 放行,风险 5」。内核的 ImageLoad 上报只覆盖 \Temp\ 与
//     \Users\Public\(为防事件风暴刻意收窄),所以那个 DLL 的加载根本没产生过事件。
//
//   形态 2 · 模块【完全没有签名】,且叠加互证 -> e.sideloadedUnsignedModulePath。
//     这是银狐 2026 年的主流落法(签名壳 + 新写的 powrprof.dll / wsc.dll 一类系统同名 DLL),
//     形态 1 对它一条都不命中:没有内嵌签名,isSignatureMismatch 恒为假。
//     互证二者取一:系统同名(ThreatDetector::isSideloadProneModuleName)或【最近才落地】。
//     没有互证绝不报 —— 绿色软件天然带一堆自研未签名 DLL,裸判会误伤一片。
//
// 与其去放宽内核侧的宽口径上报(会重新引入事件风暴),不如在这条【低频】路径上主动看一眼。
//
// 成本控制,五道:
//   1) 只在主体【签名且签名健康】时才扫 —— 这正是「白加黑」的前提。未签名主体本来就会被
//      无签名 / 可疑目录 / 首见等一堆信号顶起来,不需要额外 I/O;
//   2) 跳过标准安装目录(Program Files / Windows)—— 那里写入需要管理员,不是投递落点;
//   3) 单目录最多验 kMaxVerify 个模块,避免撞上带几百个 DLL 的大应用时线性铺开;
//   4) 形态 2 的验签【只对已经通过廉价互证的候选做】(先比名字 / 查最近写入表,再验签)——
//      否则每个模块都要多一次 WinVerifyTrust,正常大应用目录直接翻倍;
//   5) 结果【按目录 + 目录修改时间缓存】—— 那个样本每 19 分钟起一次,不缓存就等于每 19 分钟
//      重扫一遍。
//
//      【为什么键里必须带目录 mtime】原实现只按目录名缓存,且只在缓存满 512 条时整体清空。
//      于是「先扫过一次干净、之后才把恶意 DLL 放进来」的目录会被永久判为干净 —— 而这正是
//      白加黑的标准时序(先装正规软件或先落白壳,再投黑件)。NTFS 在目录里增删文件会更新目录
//      的 mtime,所以把它并进键里,投递动作一定会让缓存失效重扫。
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

    // 键 = 目录 + 目录修改时间(见上面第 5 条:只按目录名缓存会把「后放进来的黑件」永久漏掉)。
    const QDateTime dirMtime = QFileInfo(dir).lastModified();
    const QString key = dirLower + QLatin1Char('|')
                      + QString::number(dirMtime.toMSecsSinceEpoch());
    const auto cached = tamperScanCache_.constFind(key);
    if (cached != tamperScanCache_.constEnd()) {
        const SideloadScan& hit = cached.value();
        if (!hit.tamperedPath.isEmpty())
            e.tamperedModulePath = hit.tamperedPath;
        if (!hit.unsignedPath.isEmpty()) {
            e.sideloadedUnsignedModulePath = hit.unsignedPath;
            e.sideloadedUnsignedModuleWhy  = hit.unsignedWhy;
        }
        return;
    }

    SideloadScan scan;
    QDir d(dir);
    // 形态 2 只看【模块】,不看 .exe:未签名的辅助 exe 挨着签名主程序是很常见的正常形态
    //(更新器、崩溃上报器、解压出来的工具集),而「被 exe 加载」这件事只对模块成立。
    // 形态 1 仍然把 .exe 一起验(被篡改的正规 exe 同样是强信号)。
    const QStringList filters{ QStringLiteral("*.dll"), QStringLiteral("*.exe"),
                               QStringLiteral("*.ocx"), QStringLiteral("*.cpl"),
                               QStringLiteral("*.drv") };
    const QFileInfoList entries = d.entryInfoList(filters, QDir::Files | QDir::NoSymLinks, QDir::Name);
    int verified = 0;
    for (const QFileInfo& fi : entries) {
        if (verified >= kMaxVerify)
            break;
        // 主体自己已经单独验过了(上面的 actorSigned / signatureMismatch)。
        const QString modPath = fi.absoluteFilePath();
        if (modPath.compare(path, Qt::CaseInsensitive) == 0)
            continue;
        ++verified;

        // 形态 1:内嵌签名校验不过。命中即收工 —— 它比形态 2 更确定(分值也更高)。
        if (ProcessInspector::isSignatureMismatch(modPath)) {
            scan.tamperedPath = modPath;
            break;
        }

        // 形态 2:先过廉价互证,再验签(见上面第 4 条的成本说明)。
        if (!scan.unsignedPath.isEmpty())
            continue;   // 已经找到一个,不必再验后面的
        const QString suffix = fi.suffix().toLower();
        if (suffix == QLatin1String("exe"))
            continue;
        QString why;
        if (bulwark::engine::ThreatDetector::isSideloadProneModuleName(modPath))
            why = QStringLiteral("系统同名模块");
        else if (chain_.wasRecentlyWritten(modPath, kRecentDropWindowSecs))
            why = QStringLiteral("最近落地");
        if (why.isEmpty())
            continue;
        if (ProcessInspector::isSigned(modPath))
            continue;   // 有可信签名 -> 正常模块
        scan.unsignedPath = modPath;
        scan.unsignedWhy  = why;
    }

    if (tamperScanCache_.size() >= kMaxCache)
        tamperScanCache_.clear();
    tamperScanCache_.insert(key, scan);   // 两个字段都空 = 扫过且干净,下次直接跳过

    if (!scan.tamperedPath.isEmpty()) {
        e.tamperedModulePath = scan.tamperedPath;
        log_.warning(QStringLiteral("侧载模块篡改:主体 %1 签名健康,但同目录 %2 内嵌签名校验不通过"
                                    "(签名壳 + 被篡改模块 = 白加黑)。")
                         .arg(path, scan.tamperedPath));
    }
    if (!scan.unsignedPath.isEmpty()) {
        e.sideloadedUnsignedModulePath = scan.unsignedPath;
        e.sideloadedUnsignedModuleWhy  = scan.unsignedWhy;
        log_.warning(QStringLiteral("白加黑侧载:主体 %1 签名健康,但同目录 %2 未签名且%3"
                                    "(签名壳 + 未签名模块 = 银狐主流落法)。")
                         .arg(path, scan.unsignedPath, scan.unsignedWhy));
    }
}

//
// 脚本宿主要执行的脚本文件:读正文、跑判据、把结论写进事件。
//
// 【补的是什么盲区】脚本宿主的命令行里只有一个路径,正文一个字节都不在里面 —— 于是
// `cmd.exe /c "...\x.bat"` 这条事件在检测侧看不出 x.bat 是 `echo hello` 还是一个
// 1.9MB 的混淆加载器。判据本身在 ScriptAnalyzer::analyzeScriptFile(纯函数,取舍依据
// 与实测语料见那里的注释),这里只负责【有界地】把正文喂给它。
//
// 成本控制(这是同步裁决路径,不能拖):
//   · 只对进程创建事件、且主体是已知脚本宿主时才做;
//   · 正文只读前 256KB;
//   · 只有「超大 WSH 脚本」这条罕见路径才为结构统计再完整流式读一遍(O(1) 内存);
//   · 按「路径|大小|mtime」缓存结论 —— 同一脚本被计划任务反复拉起是常态。
//
void Worker::scanScriptFileBody(bulwark::SecurityEvent& e) {
    using bulwark::engine::ScriptAnalyzer;
    using bulwark::engine::ScriptType;

    constexpr int kMaxCache = 512;   // 与 tamperScanCache_ 同策略:超上限整体清空

    if (e.type != bulwark::EventType::ProcessCreate)
        return;
    if (e.commandLine.isEmpty())
        return;

    // 主体必须是脚本宿主。不是宿主就没有「它要跑哪个脚本」这件事 ——
    // 一个普通程序的命令行里带个 .bat 路径通常只是参数(编辑器打开它、压缩工具打包它)。
    const QString hostName = bulwark::engine::detail::fileNameLower(e.actorPath);
    const bool isCmd   = hostName == QLatin1String("cmd.exe");
    const bool isPwsh  = hostName == QLatin1String("powershell.exe")
                      || hostName == QLatin1String("pwsh.exe");
    const bool isWsh   = hostName == QLatin1String("wscript.exe")
                      || hostName == QLatin1String("cscript.exe");
    const bool isMshta = hostName == QLatin1String("mshta.exe");
    if (!isCmd && !isPwsh && !isWsh && !isMshta)
        return;

    const QString scriptPath = ScriptAnalyzer::extractScriptFilePath(e.commandLine);
    if (scriptPath.isEmpty())
        return;
    const ScriptType type = ScriptAnalyzer::scriptTypeFromPath(scriptPath);
    if (type == ScriptType::Unknown)
        return;

    QFileInfo fi(scriptPath);
    if (!fi.isFile())
        return;   // 相对路径 / 已删除 / 拿不到:不猜,直接放过

    // 用户已明确信任的文件/文件夹:裁决第 1 步就无条件放行了,扫了也用不上。
    if (e.userTrusted)
        return;

    const QString key = scriptPath.toLower() + QLatin1Char('|')
                      + QString::number(fi.size()) + QLatin1Char('|')
                      + QString::number(fi.lastModified().toMSecsSinceEpoch());
    const auto cached = scriptBodyCache_.constFind(key);
    if (cached != scriptBodyCache_.constEnd()) {
        const ScriptBodyScan& hit = cached.value();
        if (hit.score > 0 || hit.hard) {
            e.scriptFilePath          = scriptPath;
            e.scriptFileScore         = hit.score;
            e.scriptFileHardIndicator = hit.hard;
            e.scriptFileHits          = hit.hits;
            e.scriptFileReasons       = hit.reasons;
        }
        return;
    }

    QFile f(scriptPath);
    if (!f.open(QIODevice::ReadOnly))
        return;   // 被占用 / 无权限:放过。这里【不】走内核强读,不值得为一次评分付那个代价
    const QByteArray raw = f.read(ScriptAnalyzer::kScanPrefixBytes);

    // 超大 WSH 脚本:再顺序读完剩下的部分,只为算整文件的长行 / Base64 段长度。
    // 不缓冲文件内容,只累加两个整数。
    ScriptAnalyzer::StreamStats stats;
    const bool wantStats = isWsh && ScriptAnalyzer::isWshScriptType(type)
                        && fi.size() >= ScriptAnalyzer::kOversizedWshBytes;
    if (wantStats) {
        stats.feed(raw.constData(), raw.size());
        QByteArray chunk;
        while (!(chunk = f.read(1 << 20)).isEmpty())
            stats.feed(chunk.constData(), chunk.size());
        stats.finish();
    }
    f.close();

    // UTF-16LE BOM:WSH 脚本很常见(记事本另存即是)。其余按 UTF-8 解,坏字节走替换字符。
    QString body;
    if (raw.size() >= 2 && static_cast<uchar>(raw[0]) == 0xFF
                        && static_cast<uchar>(raw[1]) == 0xFE) {
        body = QString::fromUtf16(reinterpret_cast<const char16_t*>(raw.constData() + 2),
                                  (raw.size() - 2) / 2);
    } else {
        body = QString::fromUtf8(raw);
    }

    const ScriptAnalyzer::FileScan fs = ScriptAnalyzer::analyzeScriptFile(
        body, type, fi.size(), isWsh, wantStats ? &stats : nullptr);

    ScriptBodyScan scan;
    scan.score   = fs.score;
    scan.hard    = fs.hardSignal;
    scan.hits    = fs.hits;
    scan.reasons = fs.reasons;
    if (scriptBodyCache_.size() >= kMaxCache)
        scriptBodyCache_.clear();
    scriptBodyCache_.insert(key, scan);   // 全空 = 扫过且干净,下次直接跳过

    if (fs.empty())
        return;

    e.scriptFilePath          = scriptPath;
    e.scriptFileScore         = fs.score;
    e.scriptFileHardIndicator = fs.hardSignal;
    e.scriptFileHits          = fs.hits;
    e.scriptFileReasons       = fs.reasons;

    if (fs.hardSignal) {
        log_.warning(QStringLiteral("脚本正文判据命中:%1 执行 %2 —— %3(%4 分)")
                         .arg(hostName, scriptPath,
                              fs.hits.join(QLatin1String(", ")),
                              QString::number(fs.score)));
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

bool Worker::shouldCloudScan(const bulwark::SecurityEvent& e) {
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
    if (!shouldCloudScan(e))
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
    // MSI/MSP 安装:Windows 实际运行的是签名的 msiexec.exe,安装包(.msi)本身从不作为进程
    // 出现,故普通双击查杀看不到它。这里在 msiexec 起来时从命令行取出安装包路径,直接把
    // 「安装包本身」送 VirusTotal 扫描(命中恶意再结束 msiexec 停止安装)。
    if (!vt_ || !vtRunning_.load())
        return;
    if (!settings_ || !settings_->aiScanDoubleClickEnabled)
        return;
    if (e.type != bulwark::EventType::ProcessCreate || e.actorPath.isEmpty())
        return;
    if (QFileInfo(e.actorPath).fileName().compare(QLatin1String("msiexec.exe"), Qt::CaseInsensitive) != 0)
        return;
    //
    // 【不再要求父进程是 explorer.exe】原先只认「资源管理器里双击」,于是这些同样是用户主动
    // 安装的路径全看不到:浏览器下载栏直接「打开」(父 = chrome/msedge)、从 cmd / PowerShell
    // 里跑 msiexec /i、从压缩包窗口直接运行、以及钓鱼邮件附件用默认程序打开。银狐正是以
    // 「下载即打开」为主的投递方式,卡在父进程判定上等于把主路径挡在检测之外。
    //
    // 放开之后要防的是「系统静默安装 / 更新 / 卸载」把配额刷掉,故改为按命令行判定:
    //   · 必须能从命令行里取出一个真实存在的 .msi/.msp(卸载走的是 /x {ProductCode},取不出
    //     包路径,天然被排除);
    //   · 排除 msiexec 自己的子实例(父也是 msiexec:/V 服务端与 EXE 型自定义动作都是这样起的),
    //     那是同一次安装的内部展开,包本身已在父实例那里扫过一次;
    //   · 下面的 vtInflight_ / VT 历史按哈希去重仍然生效,同一个包不会被重复上传。
    //
    if (!e.parentPath.isEmpty()
        && QFileInfo(e.parentPath).fileName().compare(QLatin1String("msiexec.exe"),
                                                      Qt::CaseInsensitive) == 0)
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
    // 落盘即扫:写入「用户可写投放点」的安装包(.msi/.msp)、可执行体(.exe/.scr)与模块
    //(.dll/.ocx/.cpl/.drv)一旦出现,立即送 VT/聚合信誉查(不依赖是否被执行、也不抢 msiexec
    // 命令行)。银狐等以 .msi 投递、双击跑的是签名 msiexec,常规双击查杀看不到安装包本身 ——
    // 此路在投递落地阶段就兜住;模块那一路兜的是白加黑里的「黑」(载荷本体是 DLL,不会作为
    // 进程出现,双击查杀永远看不到它)。各类型的落地区与签名门槛不同,详见下面每处说明。
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
    // 模块(.dll 及同类可加载体):银狐的载荷本体就是 DLL(白加黑的「黑」),只扫 exe 会正好
    // 漏掉它。但 DLL 落地远比 exe 频繁(Inno / NSIS 装个软件就往 %TEMP% 解出几十个),所以
    // 下面 moduleZone 用的是【明显更窄】的判据,不能与 exe 同口径。
    const bool isModule = low.endsWith(QLatin1String(".dll")) || low.endsWith(QLatin1String(".ocx"))
                          || low.endsWith(QLatin1String(".cpl")) || low.endsWith(QLatin1String(".drv"));
    if (!isInstaller && !isExecutable && !isModule)
        return;

    auto has = [&low](const char* seg) { return low.contains(QLatin1String(seg)); };
    // 安装包在任意用户落地点都扫(高信号、低频)。
    const bool installerZone =
        has("\\downloads\\") || has("\\desktop\\") || has("\\users\\public\\") ||
        has("\\programdata\\") || has("\\appdata\\local\\temp\\") ||
        has("\\appdata\\roaming\\") || has("\\windows\\temp\\");
    // 裸可执行体的高危投放点(原口径,保持不变:这几处扫不看签名)。
    const bool exeZone =
        has("\\downloads\\") || has("\\desktop\\") || has("\\users\\public\\") ||
        has("\\appdata\\local\\temp\\") || has("\\windows\\temp\\");
    // 【新增】ProgramData 与 AppData\Roaming:银狐的主力暂存点(伪装安装包那条链就落在
    // ProgramData\<随机>\)。原先把这两处从 exe 扫描里排除是为了省 VT 配额 —— 正规更新器
    // 确实会往这里写 exe。故不是直接放开,而是【只扫未签名的】:签名的更新产物照旧不花配额,
    // 银狐那种未签名载荷会被扫到。签名核验是纯本机调用(WTD_REVOKE_NONE +
    // WTD_CACHE_ONLY_URL_RETRIEVAL,不联网)且带缓存,与 detectSideloadedTamperedModule
    // 在富化路径上的用法同一量级,不会把事件线程拖住。
    const bool exeZoneUnsignedOnly = has("\\programdata\\") || has("\\appdata\\roaming\\");
    // 模块只在两种情形下扫,且都要求未签名:
    //   1) 用的是系统 DLL 的名字(搜索顺序劫持的标准做法,正常应用不会自带同名私有模块);
    //   2) 落在 ProgramData / Users\Public —— 这两处不是安装器解包的常规中间目录,
    //      正常软件很少往这里丢模块,而银狐恰好在这里暂存。
    // 【刻意不含 %TEMP% 的普通模块】那正是 Inno / NSIS 解包的落点,放开会在一次正常安装里
    // 烧掉几十枚 VT 配额,而且全是误报。
    const bool moduleZone =
        bulwark::engine::ThreatDetector::isSideloadProneModuleName(path)
        || has("\\programdata\\") || has("\\users\\public\\");

    bool requireUnsigned = false;
    if (isInstaller) {
        if (!installerZone)
            return;
    } else if (isExecutable) {
        if (exeZone) {
            requireUnsigned = false;
        } else if (exeZoneUnsignedOnly) {
            requireUnsigned = true;
        } else {
            return;
        }
    } else { // isModule
        if (!moduleZone)
            return;
        requireUnsigned = true;
    }

    // 跳过本软件自身(安装目录 + %ProgramData%\Bulwark\,隔离区金库就在其下)与系统目录,
    // 避免自扫 / 回环。
    //
    // 【原先是 low.contains("\\bulwark\\") || low.contains("\\quarantine\\")】那是按【名字子串】
    // 豁免:随便建一个叫 bulwark 或 quarantine 的目录,往里投的载荷就永远不会被落盘即扫看到。
    // 与 Worker::setSelfExemptDirs 注释里记的同一类错误(那处已改成按真实路径前缀判定),
    // 这里改为复用同一个判定,不再留名字后门。
    if (isSweepExemptPath(path))
        return;
    if (!QFileInfo::exists(path))
        return;
    if (requireUnsigned && ProcessInspector::isSigned(path))
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
    // 【曾是事件线程上的一处无界停摆】原实现调 reputation_->queryNow(hash, priority=true),
    // 注释写的是「1 次 HTTP 往返对主线程影响可忽略」——但那个接口在本线程上一路阻塞:
    // ReputationCurl 起 curl.exe 并 waitForStarted(5s) + waitForFinished((timeout+10)s),
    // 期间不跑事件循环。而本函数是从 onEvent 同步调进来的,出队 / 富化 / 裁决 / IPC /
    // 弹窗超时巡检全在这同一个线程上串行,于是一次注入验证就能让内核事件在 4096 深的
    // 队列里堆到丢弃 —— 与 enrich 第 6 步当年那个 bug 是同一个,只是这条路径没跟着改。
    //
    // 换成同一个有界车道:预算内答复照旧参与本次补偿处置;超预算则放手,查询仍在车道
    // 线程上跑完并回填缓存,若结论恶意由车道线程走 onMalicious_(与后台队列确认恶意同
    // 一条补偿处置链路)。限流令牌不浪费,检测能力不减。
    if (!reputation_)
        return;
    const bulwark::FileReputation rep = reputation_->queryNowBounded(e, inlineRepBudgetMs_);
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
        if (!memVtCachedMalicious_.contains(hash)) {
            memVtCachedMalicious_.insert(hash);
            memVtCacheOrder_.enqueue(hash);
        }
        if (memVtCachedMalicious_.size() > kMemVtCacheMax) {
            // 有界缓存。注意【不能】按 QSet 的迭代顺序删:Qt6 的 QHash/QSet 每进程随机化
            // 桶序,"begin() 起的 N 条" 既不是最旧的、也不是稳定的一批,原实现那句
            // 「移除最旧的 128 条」是做不到的 —— 结果可能把刚确认恶意的哈希立刻删掉,
            // 下一次注入又要再花一枚 4/小时的令牌去查同一个样本。
            // 改成按插入顺序记账的 FIFO,删的就是真正最早进来的那批。
            const int drop = memVtCachedMalicious_.size() - kMemVtCacheMax + kMemVtCacheEvict;
            for (int i = 0; i < drop && !memVtCacheOrder_.isEmpty(); ++i)
                memVtCachedMalicious_.remove(memVtCacheOrder_.dequeue());
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
        // 后台兜底线程绝不因异常带崩服务(与 startMaliciousSweep 同口径)。
        // runVtScan 里有 JSON 解析、文件读写、哈希与四次网络往返;异常一旦逸出线程函数,
        // 标准要求调用 std::terminate —— 整个防护服务直接死掉,而不只是这一次扫描失败。
        try {
            runVtScan(job);
        } catch (const std::exception& ex) {
            log_.error(QStringLiteral("双击/释放载荷病毒扫描线程异常(已忽略本次任务):%1")
                           .arg(QString::fromUtf8(ex.what())));
        } catch (...) {
            log_.error(QStringLiteral("双击/释放载荷病毒扫描线程未知异常(已忽略本次任务)"));
        }
    }
}

void Worker::runVtScan(bulwark::SecurityEvent e) {
    // 入队去重键(在算哈希之前定,与 maybeScan* 入队键一致,才能正确移除在途标记)。
    const QString key = e.actorHash.isEmpty() ? e.actorPath : e.actorHash;

    // 在途标记用 RAII 摘除,而不是在每条返回路径上手写一遍。
    //
    // 原实现只在两处显式 remove(命中历史的早退 + 函数末尾)。本函数中间要做 JSON 解析、
    // 文件读写、哈希计算和四次网络往返,任何一处抛异常都会跳过那两句 —— 这个 key 就永久
    // 留在 vtInflight_ 里,该文件此后【再也不会被扫描】(maybeScan* 每次都判为「在途」直接
    // 返回)。这是静默的检测能力丢失,不会有任何日志。
    struct InflightGuard {
        Worker* self;
        const QString& key;
        ~InflightGuard() {
            QMutexLocker lk(&self->vtMx_);
            self->vtInflight_.remove(key);
        }
    } inflightGuard{this, key};
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
            return; // 命中历史结论 -> 不重复扫(在途标记由 inflightGuard 摘除)
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
    // 中央服务器这一跳到底存在吗(已启用 + 有端点 + 有哈希可查)。进度文案必须据此写:
    // 代理没开却写「正在查询中央服务器…」,就是在卡片上骗人 —— 而「云查是否真的服务器优先」
    // 恰恰只能从这几句文案上看出来,一旦写错,现场排查就再也分不清走的是服务器还是本机密钥。
    const bool serverHop = repProxy_ && repProxy_->isServerEnabled() && !hash.isEmpty();
    // 【本机不动用任何第三方情报源】(ReputationProxy.ServerOnly):第 2/3/4 级(本机密钥查 VT、
    // 其他情报源、上传整文件)全部跳过,云端只保留「问服务器收录了吗」这一跳。判据从代理那里读,
    // 不在 Worker 里再存一份开关 —— 两处各写一份必然跑偏。
    const bool localSources = !(repProxy_ && repProxy_->isServerOnly());
    record.message = QStringLiteral("正在查询本机信誉缓存…");
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
            // 标注「这次一次网络都没走」。不覆盖底层出处:缓存只是副本,结论仍是当初那个源
            // 给的,故写成「本机缓存·中央服务器·VirusTotal」这样的两段式(见 finalizeVtRecord)。
            record.intelSource = QStringLiteral("本机缓存");
            const QString producer = intelSourceDisplayName(rep.source);
            if (!producer.isEmpty())
                record.intelSource += QStringLiteral("·") + producer;
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
    if (!foundByHash && serverHop) {
        record.message = QStringLiteral("正在查询中央服务器是否已收录…");
        publishVtRecord(record);
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
                                     ? (localSources ? QStringLiteral("未收录,转本地密钥查询")
                                                     : QStringLiteral("未收录;本机不动用第三方情报源,无云端结论"))
                                     : (localSources
                                            ? QStringLiteral("未应答(未启用/熔断/请求预算用尽/查询失败),转本地密钥查询")
                                            : QStringLiteral("未应答(未启用/熔断/查询失败);本机不动用第三方情报源,无云端结论"))));
    }

    // 1.5) ServerOnly:链路到这里就结束了(第 2/3/4 级都不走)。服务器【权威地答过「没有收录」】
    //      时,那是一个有效结论(未收录),不是查询失败 —— 必须如实记成 querySucceeded 的
    //      Unknown:否则卡片会写成「查询失败」(把服务器答过这件事说没了),而且这条结论进不了
    //      本地负缓存,同一个哈希每次双击都要再问服务器一遍。
    //      刻意【不原样采用】服务器那条回复:老服务端会把「谁都没数据」讲成 verdict=clean/0 引擎,
    //      照抄就会被本地缓存按 CleanCacheTtlDays(7 天)当成「此文件干净」—— 那正是
    //      serverHasRecord / downgradeToUnknown 一直在堵的漏,这里不能再开一次。
    if (!foundByHash && !localSources && serverAnswered) {
        rep.verdict = bulwark::ReputationVerdict::Unknown;
        rep.malicious = 0;
        rep.totalEngines = 0;
        rep.threatLabel.clear();
        rep.source.clear(); // 「没有收录」不是谁给的结论,不标来源
        rep.querySucceeded = true;
        rep.fetchedUtc = QDateTime::currentDateTimeUtc();
    }

    // 2) 服务器没有收录(或这次没问到)-> 用本机密钥查 VirusTotal(按哈希,秒级;省去对已收录
    //    文件的重复上传)。卡片文案按上一步的真实结局区分,别把「没问到」写成「未收录」。
    bool vtAnswered = false; // VT 权威作答(区别于配额/网络/鉴权失败),供下一级文案用
    if (!foundByHash && !hash.isEmpty() && localSources) {
        record.message = !serverHop
            ? QStringLiteral("中央服务器未启用,正在查询 VirusTotal…")
            : serverAnswered
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
    if (!foundByHash && !hash.isEmpty() && repAggregate_ && localSources) {
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
    //    ServerOnly 下【绝不走这一步】:上传整文件是本机对第三方发出的最重的一次外发,
    //    也是最大的隐私暴露面,正是那个模式首先要禁掉的事。
    if (!foundByHash && localSources && !e.actorPath.isEmpty() && QFileInfo::exists(e.actorPath)) {
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
    // 在途标记由 inflightGuard 在作用域结束时摘除(含异常路径)。
}

void Worker::finalizeVtRecord(bulwark::VtScanRecord& record, const bulwark::FileReputation& rep) {
    record.malicious = rep.malicious;
    record.totalEngines = rep.totalEngines;
    record.threatLabel = rep.threatLabel;
    if (!rep.sha256.isEmpty())
        record.sha256 = rep.sha256;

    // 【本机不动用任何第三方情报源】模式:文案必须跟着变,否则会把「本机按策略压根没查」写成
    // 「各情报源都失败了」—— 那是两件完全不同的事,一个是配置,一个是故障。
    const bool serverOnly = repProxy_ && repProxy_->isServerOnly();

    if (!rep.querySucceeded) {
        record.stage = bulwark::VtScanStage::Error;
        record.outcome = bulwark::VtScanOutcome::Error;
        // 不写成「VT 查询失败」:走到这里意味着中央服务器、VirusTotal、其余情报源【全都】没能
        // 权威作答(链路见 runVtScan),单独点名 VT 会让人以为换个源就好了,而实际上是整条云查
        // 都没结论。谁也没答上来时不标来源。
        record.message = serverOnly
            ? QStringLiteral("云查毒未得出结论(中央服务器未应答;本机不动用第三方情报源,已按放行处理)")
            : QStringLiteral("云查毒未得出结论(服务器与各情报源均未成功,已按放行处理)");
        record.intelSource.clear();
    } else {
        record.stage = bulwark::VtScanStage::Completed;
        record.outcome = rep.verdict == bulwark::ReputationVerdict::Malicious  ? bulwark::VtScanOutcome::Malicious
                       : rep.verdict == bulwark::ReputationVerdict::Suspicious ? bulwark::VtScanOutcome::Suspicious
                       : rep.verdict == bulwark::ReputationVerdict::Clean      ? bulwark::VtScanOutcome::Clean
                                                                               : bulwark::VtScanOutcome::Unknown;
        // 命中来源标注:一律附「· 来源 X」;命中型源(无引擎计数)省略 N/M。
        //
        // 「一律」是刻意的。这条链路的核心策略是「先问中央服务器有没有收录,没收录才动本机
        // VT 密钥」,而用户能验证它的唯一位置就是这句结论。早先只给非 VT 的回退源标来源,并把
        // "Proxy:" 前缀整段剥掉,于是「服务器命中」与「本机直连 VT 命中」在界面上完全一样 ——
        // 策略到底有没有生效,从界面上根本看不出来。intelSource 若已由上游标注(命中本机缓存)
        // 则沿用那个更精确的说法,否则据 rep.source 翻译。
        if (record.intelSource.isEmpty())
            record.intelSource = intelSourceDisplayName(rep.source);
        const QString srcSuffix = record.intelSource.isEmpty()
                                      ? QString()
                                      : QStringLiteral(" · 来源 ") + record.intelSource;
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
            record.message = serverOnly
                ? QStringLiteral("中央服务器未收录(本机不动用第三方情报源,已按放行处理)")
                : QStringLiteral("未收录 / 无明确结论");
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

//
// 兜底扫描的免扫判定。
//
// 【原实现的两处子串信任都必须收掉】
//   1) p.contains("bulwark") —— 任何路径里出现这个子串就免扫。于是
//      C:\Users\<u>\Downloads\bulwark_setup.exe、或者干脆建一个名叫 bulwark 的目录,
//      就跳过了「防漏检的最后一道网」,顺带也跳过了 maybeQuarantineOnBlock 的隔离
//      (那里同样调本函数)。
//   2) p.contains("\\windows\\system32\\") 等 —— C:\temp\Windows\System32\evil.exe 免扫。
//
// 现在:系统目录按【盘符锚定前缀】判定;本产品自身按【安装目录 / 数据目录前缀】判定,
// 由 main 在启动时经 setSelfExemptDirs 登记真实路径,不再靠名字猜。
//
QStringList Worker::s_sweepExemptDirs;
QMutex Worker::s_sweepExemptMx;

void Worker::setSelfExemptDirs(const QStringList& dirs) {
    QMutexLocker lk(&s_sweepExemptMx);
    s_sweepExemptDirs.clear();
    for (const QString& d : dirs) {
        QString n = d.trimmed().toLower();
        if (n.isEmpty()) continue;
        n.replace(QLatin1Char('/'), QLatin1Char('\\'));
        if (!n.endsWith(QLatin1Char('\\'))) n += QLatin1Char('\\');
        s_sweepExemptDirs << n;
    }
}

bool Worker::isSweepExemptPath(const QString& path) {
    if (path.isEmpty())
        return true;
    QString p = path.toLower();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));

    // 盘符锚定的系统目录(WRP/高 ACL、微软签名,不会命中恶意情报且数量大)-> 免扫。
    if (p.size() >= 2 && p.at(1) == QLatin1Char(':')) {
        const QStringView rel = QStringView(p).mid(2);
        if (rel.startsWith(QStringLiteral("\\windows\\system32\\")) ||
            rel.startsWith(QStringLiteral("\\windows\\syswow64\\")) ||
            rel.startsWith(QStringLiteral("\\windows\\winsxs\\")))
            return true;
    }

    // 本产品自身(安装目录 + %ProgramData%\Bulwark\),按真实路径前缀而不是名字子串。
    {
        QMutexLocker lk(&s_sweepExemptMx);
        for (const QString& d : s_sweepExemptDirs)
            if (p.startsWith(d)) return true;
    }
    return false;
}

void Worker::sweepLoop() {
    // 后台线程:严禁直接碰主线程 Qt 对象(engine_/ipc_ 等)。只用线程安全的哈希快照
    //(maliciousHashMx_ 保护)+ 信誉只读缓存;命中后 QueuedConnection 编组回主线程处置。
    //
    // 哈希缓存的键是【路径 + 大小 + 修改时间】,不是光路径。
    //
    // 原实现只用路径做键,有两个后果,第二个是检测漏洞:
    //   1) 这张表只增不减,进程路径多的机器上长期驻留;
    //   2) 文件被【原地替换】后(恶意软件自更新、被投毒的升级包写回同一路径),缓存里
    //      仍是旧哈希,于是兜底扫描永远拿旧哈希去比对情报,新的恶意体一次都不会被逮到。
    //      而"兜底扫描"的全部意义就是逮住漏网的那一个。
    struct HashEntry {
        QString hashUpper;
        qint64 size = 0;
        qint64 mtimeMs = 0;
    };
    QHash<QString, HashEntry> pathHashCache;
    constexpr int kSweepHashCacheMax = 2048;

    // 首轮延迟:等握手/规则加载/信誉预热稳定后再扫,减少启动期抖动。
    for (int i = 0; i < 15 && sweepRunning_.load(); ++i)
        std::this_thread::sleep_for(std::chrono::seconds(1));

    while (sweepRunning_.load()) {
        // 读无锁镜像,不碰 settings_(那个结构体会被主线程整体赋值,见 sweepProtectionEnabled_)。
        // 待机(「退出界面即停止防护」)同样要停:兜底扫描是【主动】去枚举进程、算哈希、
        // 比对情报并结束+隔离的,待机时它是唯一还会自己动手处置的东西 —— 漏掉它,
        // 用户看到的就是「界面都退出了还在隔离文件」,也就是这次要修的那个现象本身。
        const bool enabled = sweepProtectionEnabled_.load() && !protectionSuspended_.load();
        if (enabled) {
            const QList<int> pids = ProcessInspector::enumeratePids();
            for (int pid : pids) {
                if (!sweepRunning_.load())
                    break;
                const QString path = ProcessInspector::tryGetProcessImagePath(pid);
                if (path.isEmpty() || isSweepExemptPath(path))
                    continue;

                // 先 stat 一次,拿到判断缓存是否仍然有效所需的身份信息。
                const QFileInfo fi(path);
                const qint64 size = fi.size();
                const qint64 mtimeMs = fi.lastModified().toMSecsSinceEpoch();

                QString hashU;
                const auto it = pathHashCache.constFind(path);
                if (it != pathHashCache.constEnd()
                    && it.value().size == size && it.value().mtimeMs == mtimeMs) {
                    hashU = it.value().hashUpper;    // 同一个文件,复用哈希
                }
                if (hashU.isEmpty()) {
                    hashU = ProcessInspector::tryComputeSha256(path); // 大写十六进制
                    if (!hashU.isEmpty()) {
                        if (pathHashCache.size() >= kSweepHashCacheMax)
                            pathHashCache.clear();   // 有界:整体丢弃,下轮重算(纯性能缓存)
                        pathHashCache.insert(path, HashEntry{ hashU, size, mtimeMs });
                    }
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
                // 信誉缓存既是第二条判据,也是拦截通知上「威胁类型 / 威胁名」的来源:命中记忆的哈希
                // 多半也在缓存里(onReputationMalicious 确认时两边都记),所以照样取一次、挂到事件上。
                // tryGetCached 是纯内存查询(const),原来对绝大多数进程本来就会调用。
                std::optional<bulwark::FileReputation> cachedRep;
                if (reputation_) {
                    cachedRep = reputation_->tryGetCached(hashU);
                    if (cachedRep && !cachedRep->isMalicious())
                        cachedRep.reset();
                }
                if (!malicious && cachedRep) {
                    malicious = true;
                    label = cachedRep->threatLabel.trimmed().isEmpty()
                                ? QString::fromUtf8("信誉判定恶意")
                                : cachedRep->threatLabel;
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
                // 只用于如实展示(这条路径不再过引擎,ThreatDetector 不会读到它)。
                e.reputation = cachedRep;
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
    // 主线程:与信誉确认恶意共用同一处置路径 —— 封禁 PID(killMalicious 内已 banProcess)
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
    // 按硬指标证据登记(addEvidence 同时进 riskReasons),并写明凭什么确认的(已记忆的恶意哈希 /
    // 信誉缓存里的威胁名)。事件是兜底扫描现场构造的,不登记的话证据链为空,通知与拦截记录都
    // 说不出拦下的是什么。
    ev.addEvidence(QStringLiteral("Reputation"), bulwark::EvidenceKind::HardIndicator,
                   ev.detail.trimmed().isEmpty()
                       ? QString::fromUtf8("兜底扫描复查:已确认恶意")
                       : QString::fromUtf8("兜底扫描复查:已确认恶意(%1)").arg(ev.detail.trimmed()));

    // 结束仍在运行的进程树(killMalicious 内已先 banProcess 封禁 PID);未能结束(已退出)标 AlertedOnly。
    bulwark::EnforcementOutcome outcome = bulwark::EnforcementOutcome::AlertedOnly;
    if (killMalicious(ev.actorPid))
        outcome = bulwark::EnforcementOutcome::Terminated;
    // 执行前拦截:恶意映像加入内核禁止执行名单,挡住其被守护进程/持久化再次拉起。
    blacklistExec(ev.actorPath);
    ipc_->sendBlock(ev, outcome);   // 处置之后再通知(见 onEvent 处说明)
    recordEvent(ev, VerdictAction::Block, source, outcome);

    // 隔离载荷 + 清除持久化(remediateIfMalicious 内对 source==Heuristic 会执行补救)。
    remediateIfMalicious(ev, bulwark::Verdict::forEvent(ev, VerdictAction::Block, source));
    // 兜底扫描逮到的是已确认恶意哈希 -> 释放物硬拦。
    taintDroppedFiles(ev, VerdictAction::Block, QStringLiteral("兜底扫描确认恶意"));
}

} // namespace bulwark::service
