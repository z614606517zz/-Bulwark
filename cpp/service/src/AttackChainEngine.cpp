#include "bulwark/service/AttackChainEngine.h"
#include "bulwark/service/reputation/ReputationCurl.h"
#include "bulwark/engine/ThreatDetector.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QMetaObject>
#include <QMutexLocker>
#include <QRandomGenerator>
#include <QTime>
#include <QTimeZone>

#include <algorithm>
#include <chrono>

namespace bulwark::service {
namespace {

// 服务器下发的 event 字段是 bulwark::EventType 的成员名。按名字还原成枚举 ——
// 绝不按序号传:枚举序号是「线上有效」的(与 .NET 侧对齐),但名字更抗改动,
// 且服务器侧本来就是按名字生成的(见 engine_build.py 的 MARKER_RULES)。
std::optional<bulwark::EventType> eventTypeFromName(const QString& name) {
    static const QHash<QString, bulwark::EventType> kMap = {
        { QStringLiteral("ProcessCreate"),    bulwark::EventType::ProcessCreate },
        { QStringLiteral("ProcessTerminate"), bulwark::EventType::ProcessTerminate },
        { QStringLiteral("RemoteThread"),     bulwark::EventType::RemoteThread },
        { QStringLiteral("ImageLoad"),        bulwark::EventType::ImageLoad },
        { QStringLiteral("FileWrite"),        bulwark::EventType::FileWrite },
        { QStringLiteral("FileDelete"),       bulwark::EventType::FileDelete },
        { QStringLiteral("RegistryWrite"),    bulwark::EventType::RegistryWrite },
        { QStringLiteral("NetworkConnect"),   bulwark::EventType::NetworkConnect },
        { QStringLiteral("SelfProtect"),      bulwark::EventType::SelfProtect },
        { QStringLiteral("DnsQuery"),         bulwark::EventType::DnsQuery },
    };
    const auto it = kMap.constFind(name.trimmed());
    return it == kMap.constEnd() ? std::nullopt : std::optional<bulwark::EventType>(it.value());
}

int gradeRank(const QString& g) {
    if (g == QLatin1String("hard")) return 3;
    if (g == QLatin1String("strong")) return 2;
    if (g == QLatin1String("ask")) return 1;
    return 0;
}

// 档位内按支持度加分的两个常数。
//
// 服务器的分档门槛是 10 / 8 / 5 个样本(SUPPORT_FOR_HARD / STRONG / ASK),实测下发的
// 支持度大多落在 5~40 之间,故步长取 3 才有区分度(取 8 的话典型值只能加 0~1 分,等于没做)。
constexpr int kSupportPerPoint = 3;    // 超出本档门槛每 3 个样本 +1 分
constexpr int kMaxSupportBonus = 20;   // 加分上限

// 组合命中该加多少分。依据 ThreatDetector 的既有阈值(HighRisk=80 / Suspicious=50),
// 让「服务器给出的强度」直接落到「既有流水线的处置档位」上,不另立一套判定标准:
//   hard   -> 80: 独立即可触达高危 -> 流水线判 Block(服务器口径:>=3 动作 + 含高危 + >=10 样本作证)
//   strong -> 55 起: 落在可疑档     -> 判 Ask
//   ask    -> 50 起: 恰好可疑档      -> 判 Ask
//
// ---- 为什么要把 support 算进来 ----
// support(多少真实样本为这条组合作证)一路从服务器带到客户端、写进证据文案,却对分数
// 【毫无影响】—— 一条 200 个样本作证的组合与一条勉强够 5 个的完全同分。而这两者的可信度
// 显然不同,「有多少真实样本作证」本来就是本引擎唯一的置信来源。
//
// ---- 为什么必须硬钳位 ----
// 非 hard 档一律钳在 HighRisk - 1(79)。79 跨到 80 就是「询问」变「拦截」,那是实质的处置
// 变更,不是打分微调。支持度多寡绝不该让一条 ask/strong 组合【单凭自己】越过闸门 ——
// 它仍然只能靠与其它独立指标互证(analyze 里 score += chainScore 之后还会叠加各自的信号)
// 才可能到 80,而那正是本产品的互证模型要的效果。
// hard 档保持恒定 80:它本就直接 Block,再加分不改变任何行为。
int gradeScore(const QString& g, int support) {
    using bulwark::engine::ThreatDetector;
    if (g == QLatin1String("hard"))
        return ThreatDetector::HighRisk;

    int base, floorSupport;
    if (g == QLatin1String("strong")) {
        base = ThreatDetector::Suspicious + 5;   // 55
        floorSupport = 8;                        // 服务器 SUPPORT_FOR_STRONG
    } else {
        base = ThreatDetector::Suspicious;       // 50
        floorSupport = 5;                        // 服务器 SUPPORT_FOR_ASK
    }
    const int bonus =
        std::clamp((support - floorSupport) / kSupportPerPoint, 0, kMaxSupportBonus);
    // 钳位:非 hard 档永远到不了 HighRisk。
    return std::min(base + bonus, ThreatDetector::HighRisk - 1);
}

QString gradeLabel(const QString& g) {
    if (g == QLatin1String("hard")) return QStringLiteral("可直接阻断");
    if (g == QLatin1String("strong")) return QStringLiteral("阻断或强提示");
    return QStringLiteral("弹窗询问");
}

// 降一档,以 ask 为地板。
//
// 刻意【不】降到「丢弃」:降档的依据(正常软件里见过 / 靠稀疏事件点亮)说明的是
// 「不该凭它直接拦」,不是「这条组合没用」。降到 ask 仍然会弹窗问用户,检出不丢;
// 直接丢掉才是真的损失检出,而那属于服务器侧 _cap_by_benign 的职责(它有完整语料可依)。
QString downgradeGrade(const QString& g) {
    if (g == QLatin1String("hard")) return QStringLiteral("strong");
    if (g == QLatin1String("strong")) return QStringLiteral("ask");
    return QStringLiteral("ask");
}

// ---- 可达性诊断用的小工具 ---------------------------------------------------- #

// 把通配式切成「字面片段」:去掉 * 与 ? 之后剩下的那些连续常量串。
// 例:"*\\CurrentVersion\\Run*" -> ["\\CurrentVersion\\Run"]。
// 用途:判断这个 target 有没有机会与内核的监视集(纯子串匹配)产生交集。
QStringList literalRuns(const QString& pattern) {
    QStringList out;
    QString cur;
    for (const QChar c : pattern) {
        if (c == QLatin1Char('*') || c == QLatin1Char('?')) {
            if (cur.size() >= 3)
                out << cur;
            cur.clear();
        } else {
            cur.append(c);
        }
    }
    if (cur.size() >= 3)
        out << cur;
    return out;
}

// 该 target 通配式有没有机会被「子串监视集」放进来。
//
// 内核与 ETW 两侧都是【纯子串命中才上报】,所以判据是:存在某个监视项 W 与该 target 的
// 某个字面片段 L 有包含关系(任一方向)。两个方向都要看:
//   * L 含 W:监视项更宽(watch="\Windows Defender",标记要 "*\Windows Defender\Exclusions*")
//     -> 上报的键可能落在标记的范围内,可达。
//   * W 含 L:监视项更窄(watch="\SystemCertificates\ROOT",标记要 "*\SystemCertificates\*")
//     -> 被上报的那部分键仍满足标记,可达。
// 片段长度门槛 3 是为了不让 "\\" 之类的碎片把一切都判成可达。
bool watchSetCovers(const QString& targetPattern, const QStringList& watch) {
    const QStringList runs = literalRuns(targetPattern);
    if (runs.isEmpty())
        return true;   // 没有字面片段(纯通配)-> 任何被上报的目标都可能匹配
    for (const QString& rawRun : runs) {
        const QString L = rawRun.toLower();
        for (const QString& rawW : watch) {
            const QString W = rawW.trimmed().toLower();
            if (W.size() < 3)
                continue;
            if (L.contains(W) || W.contains(L))
                return true;
        }
    }
    return false;
}

} // namespace

// ============================== ChainMarker ==================================

bool ChainMarker::matchesEvent(const bulwark::SecurityEvent& e) const {
    if (!matcher.matches(e))
        return false;
    // 「不含」条件:命中即判否。用同一个 wildcardMatch,不引入第二套通配语义。
    if (!cmdlineAbsent.isEmpty()
        && bulwark::DefenseRule::wildcardMatch(cmdlineAbsent, e.commandLine))
        return false;
    if (!targetAbsent.isEmpty()
        && bulwark::DefenseRule::wildcardMatch(targetAbsent, e.target))
        return false;
    if (!parentAbsent.isEmpty()
        && bulwark::DefenseRule::wildcardMatch(parentAbsent, e.parentPath))
        return false;
    return true;
}

// ============================ ChainHitRecord =================================

QJsonObject ChainHitRecord::toJson() const {
    QJsonObject o;
    o[QStringLiteral("whenUtc")] = whenUtc.toUTC().toString(Qt::ISODate);
    o[QStringLiteral("actorPath")] = actorPath;
    o[QStringLiteral("actorPid")] = actorPid;
    // 组合的稳定标识。排查「哪条组合在刷误报」只能靠它 —— titles 里的标题来自 Sigma
    // 规则名,服务器改名后整段历史就与新表对不上号(见 ChainHitRecord::patternKey)。
    o[QStringLiteral("patternKey")] = patternKey;
    o[QStringLiteral("titles")] = QJsonArray::fromStringList(titles);
    o[QStringLiteral("grade")] = grade;
    o[QStringLiteral("serverGrade")] = serverGrade;
    o[QStringLiteral("capReason")] = capReason;
    o[QStringLiteral("maxLevel")] = maxLevel;
    o[QStringLiteral("support")] = support;
    o[QStringLiteral("benignSupport")] = benignSupport;
    o[QStringLiteral("families")] = families;
    o[QStringLiteral("dryRun")] = dryRun;
    o[QStringLiteral("action")] = action;
    o[QStringLiteral("eventType")] = eventType;
    return o;
}

ChainHitRecord ChainHitRecord::fromJson(const QJsonObject& o) {
    ChainHitRecord r;
    // 落盘时按 ISO + UTC 写出;回读时显式指定 UTC 时区(Qt6 的 setTimeSpec 已弃用)。
    r.whenUtc = QDateTime::fromString(o.value(QLatin1String("whenUtc")).toString(), Qt::ISODate);
    if (r.whenUtc.isValid())
        r.whenUtc.setTimeZone(QTimeZone::UTC);
    r.actorPath = o.value(QLatin1String("actorPath")).toString();
    r.actorPid = o.value(QLatin1String("actorPid")).toInt();
    r.patternKey = o.value(QLatin1String("patternKey")).toString();
    for (const QJsonValue& v : o.value(QLatin1String("titles")).toArray())
        r.titles << v.toString();
    r.grade = o.value(QLatin1String("grade")).toString();
    // 老记录没有这两个字段(本版之前落的盘):serverGrade 缺失时退回 grade,
    // 使「grade != serverGrade 即说明本机压过档」这个判据对老记录不会给出假阳。
    r.serverGrade = o.value(QLatin1String("serverGrade")).toString();
    if (r.serverGrade.isEmpty())
        r.serverGrade = r.grade;
    r.capReason = o.value(QLatin1String("capReason")).toString();
    r.maxLevel = o.value(QLatin1String("maxLevel")).toString();
    r.support = o.value(QLatin1String("support")).toInt();
    r.benignSupport = o.value(QLatin1String("benignSupport")).toInt();
    r.families = o.value(QLatin1String("families")).toString();
    r.dryRun = o.value(QLatin1String("dryRun")).toBool(true);
    r.action = o.value(QLatin1String("action")).toString();
    r.eventType = o.value(QLatin1String("eventType")).toString();
    return r;
}

// ============================ AttackChainEngine ==============================

AttackChainEngine::AttackChainEngine(const AttackChainOptions& opt,
                                     const QString& dataDirOverride) : opt_(opt) {
    // 留空 -> %ProgramData%\Bulwark(生产路径)。非空仅用于回归测试的状态隔离,
    // 见头文件里 dataDirOverride 的说明。
    const QString dir = dataDirOverride.trimmed().isEmpty() ? programDataDir()
                                                            : dataDirOverride.trimmed();
    cachePath_ = QDir(dir).filePath(QStringLiteral("attackchain.json"));
    hitsPath_ = QDir(dir).filePath(QStringLiteral("attackchain_hits.jsonl"));
    loadHits();
}

// 启动时把最近的命中记录读回内存,使 UI 重启后仍能看到历史。
// 只保留文件尾部的 kMaxRecords 条(整文件读进来即可 —— 有轮转,体积有界)。
void AttackChainEngine::loadHits() {
    QFile f(hitsPath_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly | QIODevice::Text))
        return;
    QVector<ChainHitRecord> all;
    while (!f.atEnd()) {
        const QByteArray line = f.readLine().trimmed();
        if (line.isEmpty())
            continue;
        QJsonParseError err{};
        const QJsonDocument doc = QJsonDocument::fromJson(line, &err);
        if (err.error != QJsonParseError::NoError || !doc.isObject())
            continue;
        all.append(ChainHitRecord::fromJson(doc.object()));
    }
    f.close();
    if (all.size() > kMaxRecords)
        all = all.mid(all.size() - kMaxRecords);
    QMutexLocker lk(&hitsLock_);
    hits_ = std::move(all);
}

ChainHitRecord AttackChainEngine::recordHit(const ChainHit& hit, const bulwark::SecurityEvent& e,
                                            const QString& action) {
    ChainHitRecord r;
    r.whenUtc = QDateTime::currentDateTimeUtc();
    r.actorPath = e.actorPath;
    r.actorPid = e.actorPid;
    r.patternKey = hit.pattern.key;
    r.titles = hit.titles;
    r.grade = hit.pattern.grade;
    r.serverGrade = hit.pattern.serverGrade;
    r.capReason = hit.pattern.capReason;
    r.maxLevel = hit.pattern.maxLevel;
    r.support = hit.pattern.support;
    r.benignSupport = hit.pattern.benignSupport;
    r.families = hit.pattern.families;
    r.dryRun = opt_.DryRun;
    r.action = action;
    r.eventType = bulwark::eventTypeToString(e.type);

    {
        QMutexLocker lk(&hitsLock_);
        hits_.append(r);
        if (hits_.size() > kMaxRecords)
            hits_.remove(0, hits_.size() - kMaxRecords);
    }

    // 落盘(单代轮转,沿用 rep_diag.log 的约定):命中是低频事件,追加开销可忽略。
    constexpr qint64 kMaxBytes = 2 * 1024 * 1024;
    if (QFileInfo(hitsPath_).size() >= kMaxBytes) {
        const QString prev = hitsPath_ + QStringLiteral(".1");
        QFile::remove(prev);
        QFile::rename(hitsPath_, prev);
    }
    QFile f(hitsPath_);
    if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
        f.write(QJsonDocument(r.toJson()).toJson(QJsonDocument::Compact));
        f.write("\r\n");
        f.close();
    }
    // 把记录还给调用方 —— Worker 要用同一份内容发即时通知。返回而不是让 Worker 自己再拼一遍:
    // 两处各拼一次早晚会跑偏(改了这里忘了那里),而通知与记录本就该说同一件事。
    return r;
}

QVector<ChainHitRecord> AttackChainEngine::recentHits(int limit) const {
    QMutexLocker lk(&hitsLock_);
    QVector<ChainHitRecord> out;
    const int n = std::min(limit > 0 ? limit : hits_.size(), hits_.size());
    out.reserve(n);
    for (int i = hits_.size() - 1; i >= hits_.size() - n; --i)   // 最新在前
        out.append(hits_[i]);
    return out;
}

void AttackChainEngine::clearHits() {
    {
        QMutexLocker lk(&hitsLock_);
        hits_.clear();
    }
    QFile::remove(hitsPath_);
    QFile::remove(hitsPath_ + QStringLiteral(".1"));
}

QString AttackChainEngine::versionLabel() const {
    QMutexLocker lk(&tableLock_);
    if (!label_.isEmpty())
        return label_;
    // 老服务器不下发 label -> 回退成 "v<整数>",而不是留空。版本号在界面上不该是空白。
    return version_ > 0 ? (QLatin1Char('v') + QString::number(version_)) : QStringLiteral("—");
}

int AttackChainEngine::version() const {
    QMutexLocker lk(&tableLock_);
    return version_;
}

int AttackChainEngine::patternCount() const {
    QMutexLocker lk(&tableLock_);
    return patterns_.size();
}

int AttackChainEngine::trackedProcessCount() const {
    QMutexLocker lk(&tableLock_);
    return ledger_.size();
}

int AttackChainEngine::markerCount() const {
    QMutexLocker lk(&tableLock_);
    return markers_.size();
}

bool AttackChainEngine::applyTable(const QJsonObject& payload) {
    const int ver = payload.value(QLatin1String("version")).toInt();
    // label 是【给人看的】版本号(服务器侧 0.1 起、每次内容变化 +0.1)。
    // version 仍是整数,并且仍是「要不要重新下载」的唯一判据 —— 两者刻意分开:
    // 小数不适合做单调递增的下载判据(比较有精度坑),整数不适合给人念。
    // 老服务器不带 label 时留空,展示处回退成 "v<整数>"。
    const QString lab = payload.value(QLatin1String("label")).toString().trimmed();
    // 服务器说没变化 -> 保持现有表(这是 ?since= 的省流量路径,不是错误)。
    // 但 label 要收下:客户端装上本版后若一直没有新内容,否则界面会长期回退显示整数版本号。
    if (payload.value(QLatin1String("unchanged")).toBool()) {
        if (!lab.isEmpty()) {
            QMutexLocker lk(&tableLock_);
            label_ = lab;
        }
        return false;
    }

    // ---- 解析标记 ----
    QHash<QString, ChainMarker> marks;
    const QJsonObject mobj = payload.value(QLatin1String("markers")).toObject();
    for (auto it = mobj.constBegin(); it != mobj.constEnd(); ++it) {
        const QJsonObject m = it.value().toObject();
        // 不可观测的标记直接丢:客户端没有条件可判,留着只会让组合永远凑不齐。
        if (!m.value(QLatin1String("observable")).toBool())
            continue;
        const std::optional<bulwark::EventType> et =
            eventTypeFromName(m.value(QLatin1String("event")).toString());
        if (!et.has_value())
            continue;

        ChainMarker cm;
        cm.id = it.key();
        cm.title = m.value(QLatin1String("title")).toString();
        cm.level = m.value(QLatin1String("level")).toString();

        // 关键:直接构造一条「只含条件」的 DefenseRule 当匹配器,复用 matches()/wildcardMatch。
        // 服务器的字段名与 DefenseRule 同名同义,故这里是纯搬运,不做语义转换。
        const QJsonObject cond = m.value(QLatin1String("match")).toObject();
        cm.matcher.type = *et;
        // actor 走 actorPattern 而非 actorPath:服务器给的是通配式("*\\svchost.exe"),
        // 而 actorPath 是精确比较,填错就永远匹配不上。
        cm.matcher.actorPattern     = cond.value(QLatin1String("actor")).toString();
        cm.matcher.targetPattern    = cond.value(QLatin1String("target")).toString();
        cm.matcher.commandLinePattern = cond.value(QLatin1String("cmdline")).toString();
        cm.matcher.parentPattern    = cond.value(QLatin1String("parent")).toString();
        cm.matcher.requireUnsigned  = cond.value(QLatin1String("unsigned")).toBool();
        // 「不含」条件(见 ChainMarker 的说明)。老服务器不下发这几个键时为空 -> 不限,
        // 行为与本字段加入之前逐字节相同。
        cm.cmdlineAbsent = cond.value(QLatin1String("cmdline_absent")).toString();
        cm.targetAbsent  = cond.value(QLatin1String("target_absent")).toString();
        cm.parentAbsent  = cond.value(QLatin1String("parent_absent")).toString();
        // expiresUtc 保持未设置:一旦有值,matches() 会在到期后静默恒假,标记再也不会置位。
        cm.matcher.action = bulwark::VerdictAction::Ask; // 占位,本引擎不用它的 action
        cm.matcher.note = QStringLiteral("[攻击链标记] ") + cm.title;
        marks.insert(cm.id, cm);
    }

    // ---- 解析组合 ----
    const int minRank = gradeRank(opt_.MinGrade.trimmed().toLower());
    int unreachable = 0;   // 主体冲突 -> 本客户端不可能命中的组合数
    int redundant   = 0;   // 证据重复(多个标记条件相同) -> 不构成互证的组合数
    QVector<ChainPattern> pats;
    const QJsonArray parr = payload.value(QLatin1String("patterns")).toArray();
    for (const QJsonValue& pv : parr) {
        const QJsonObject p = pv.toObject();
        const QString grade = p.value(QLatin1String("grade")).toString();
        if (gradeRank(grade) < minRank)
            continue;               // 低于配置强度门槛的不采纳

        ChainPattern cp;
        for (const QJsonValue& mv : p.value(QLatin1String("markers")).toArray()) {
            const QString id = mv.toString();
            if (!id.isEmpty())
                cp.markers << id;
        }
        // 组合里任一标记不可观测 -> 整条丢弃。留着是死规则:永远凑不齐,只占内存。
        bool allKnown = !cp.markers.isEmpty();
        for (const QString& id : cp.markers)
            if (!marks.contains(id)) { allKnown = false; break; }
        if (!allKnown)
            continue;
        // 单标记「组合」不收:那等于凭一个动作定性,与本引擎「必须互证」的前提相悖。
        if (cp.markers.size() < 2)
            continue;

        // 剔掉「主体互相冲突」的组合 —— 它们在本客户端【永远不可能命中】。
        //
        // 服务器挖的是「这个样本做了什么」,而样本在沙箱里会派生子进程,故一条组合里可能同时
        // 要求 actor=*\powershell*.exe 与 actor=*\Temp\*。但客户端是【按单个进程记账】的:
        // actor 就是这个进程本身,一个进程不可能同时是两个不同的程序。留着这种组合只会白占
        // 内存、让统计数字虚高(实测 32 条里有 2 条属此,含一条 hard)。
        // 真要支持跨进程链的组合,需要按进程树累积标记 —— 那会把 explorer.exe 底下互不相关的
        // 子进程全部汇到一个账上,误报面显著变大,故不在此顺手做,先如实剔除并记账。
        {
            QSet<QString> actors;
            for (const QString& id : cp.markers) {
                const QString a = marks.value(id).matcher.actorPattern;
                if (!a.isEmpty())
                    actors.insert(a.toLower());
            }
            if (actors.size() >= 2) {
                ++unreachable;
                continue;
            }
        }

        // 剔掉「同一个条件被数了两次」的组合 —— 它们不是互证,是一个信号冒充多个。
        //
        // 标记的【标题】来自 Sigma 规则(原规则有真实的路径/命名判定),但挖到客户端的
        // 【匹配条件】会退化。实测 v9 表里就有两条标记:
        //   Files With System Process Name In Unsuspected Locations -> ProcessCreate + unsigned
        //   System File Execution Location Anomaly                  -> ProcessCreate + unsigned
        // 条件完全相同。于是「两个动作凑齐」实际只要一个未签名进程启动就成立 —— 实测
        // ripgrep 和本产品自己的 UI 都中招。同类问题还有 svchost 那对(条件都是
        // actor=*\svchost.exe,而 svchost 在 Windows 上不停启动)。
        //
        // 这直接违背本产品的底线:unsigned / 可疑路径这类【软信号】单独出现绝不该触发拦截或
        // 弹窗,必须由硬指标互证。而 applyHitToEvent 在强制模式下会把命中登记为硬指标,
        // 所以这种组合一旦生效,等于把软信号提拔成了处置依据。
        //
        // 判据:把每个标记归约成「事件类型 + 全部匹配条件」的指纹,去重后若少于标记数,
        // 说明这条组合声称的 N 个动作里有重复,整条丢弃。这条护栏对服务器每天重挖出的新
        // 组合同样有效,不需要逐条维护黑名单。
        {
            QSet<QString> fingerprints;
            for (const QString& id : cp.markers) {
                const ChainMarker& cmk = marks.value(id);
                const bulwark::DefenseRule& r = cmk.matcher;
                // 指纹【必须带上「不含」条件】。否则两个只在「不含」上不同的标记会被
                // 归约成同一个指纹 —— 而它们其实判的是两件不同的事(有 -k / 没有 -k),
                // 结果是整条组合被误当成「证据重复」剔除。
                fingerprints.insert(QStringLiteral("%1|%2|%3|%4|%5|%6|%7|%8|%9")
                                        .arg(r.type ? static_cast<int>(*r.type) : -1)
                                        .arg(r.actorPattern.toLower(),
                                             r.targetPattern.toLower(),
                                             r.commandLinePattern.toLower(),
                                             r.parentPattern.toLower())
                                        .arg(r.requireUnsigned ? 1 : 0)
                                        .arg(cmk.cmdlineAbsent.toLower(),
                                             cmk.targetAbsent.toLower(),
                                             cmk.parentAbsent.toLower()));
            }
            if (fingerprints.size() < cp.markers.size()) {
                ++redundant;
                continue;
            }
        }

        cp.markers.sort();
        // 去重键在此算一次,而不是在每次「组合凑齐」判定里现拼(见 ChainPattern::key)。
        cp.key      = cp.markers.join(QLatin1Char('|'));
        cp.support  = p.value(QLatin1String("support")).toInt();
        // serverGrade 保存原始强度;grade 是生效强度,稍后由 regradeLocked 从 serverGrade 推出。
        cp.serverGrade = grade;
        cp.grade       = grade;
        // 服务器一直在下发这个字段,此前解析时被丢掉了(见 ChainPattern::benignSupport)。
        cp.benignSupport = p.value(QLatin1String("benign_support")).toInt();
        cp.maxLevel = p.value(QLatin1String("max_level")).toString();
        cp.families = p.value(QLatin1String("families")).toString();
        pats.append(cp);
    }

    if (pats.isEmpty()) {
        log_.warning(QStringLiteral("攻击链组合表:服务器返回 %1 条组合,但可用(标记齐全且达强度门槛)的为 0,"
                                    "保持原表不变。").arg(parr.size()));
        return false;
    }
    int capped = 0;   // 本机降档的组合数(由下面持锁段里的 regradeLocked 填)

    // ---- 建索引:标记 -> 含该标记的组合 ----
    // 组合只可能在「某个标记刚刚置位」时才新凑齐,故每条事件只需检查含新置位标记的那几条组合,
    // 不必遍历全表。组合数从几十长到几百之后,这一步就是能否不拖慢裁决路径的关键。
    QHash<QString, QVector<int>> idx;
    for (int i = 0; i < pats.size(); ++i)
        for (const QString& id : pats[i].markers)
            idx[id].append(i);

    // ---- 按事件类型给标记分桶(热路径用)----
    // observe() 每条事件只需要试同类型的那一桶,不必遍历全表(见 markersByType_ 的说明)。
    // 与上面的 idx 一并在此重建,保证两份索引和 marks 永远同源。
    QHash<int, QVector<ChainMarker>> byType;
    for (auto it = marks.constBegin(); it != marks.constEnd(); ++it) {
        const ChainMarker& m = it.value();
        // 装载时已要求 event 名可解析(解析失败的标记在上面被 continue 掉),故此处必有值。
        byType[static_cast<int>(m.matcher.type.value_or(bulwark::EventType::ProcessCreate))]
            .append(m);
    }

    {
        QMutexLocker lk(&tableLock_);
        markers_       = std::move(marks);
        markersByType_ = std::move(byType);
        patterns_ = std::move(pats);
        index_    = std::move(idx);
        version_  = ver;
        label_    = lab;
        srvPatterns_   = parr.size();
        dropConflict_  = unreachable;
        dropRedundant_ = redundant;
        // 立刻按已知的覆盖面 / 正常语料定档。首次装表时覆盖面通常还不知道(要等
        // derivedRegistryWatch 之后),那时这里只应用正常语料那条;调用方随后调
        // setCoverage 会再算一遍(幂等,见 regradeLocked)。
        capped = regradeLocked();
    }

    // 落盘:下次启动 / 断网期间仍有表可用。
    QJsonDocument doc(payload);
    QFile f(cachePath_);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        f.write(doc.toJson(QJsonDocument::Compact));
        f.close();
    }

    log_.info(QStringLiteral("攻击链组合表已装载:版本 %1,组合 %2 条,可观测标记 %3 个%4%5%6%7。")
                  .arg(versionLabel()).arg(patternCount()).arg(markerCount())
                  .arg(unreachable > 0
                           ? QStringLiteral(",已剔除主体冲突(单进程不可能命中)的组合 %1 条")
                                 .arg(unreachable)
                           : QString())
                  .arg(redundant > 0
                           ? QStringLiteral(",已剔除证据重复(多个标记条件相同,不构成互证)的组合 %1 条")
                                 .arg(redundant)
                           : QString())
                  .arg(capped > 0
                           ? QStringLiteral(",已按本机情况降档 %1 条").arg(capped)
                           : QString())
                  .arg(opt_.DryRun ? QStringLiteral("(dry-run:只记录不影响裁决)")
                                   : QStringLiteral("(强制生效)")));
    return true;
}

// 按「正常语料出现率」与「本机可观测性」重算生效强度。只降不升。
//
// 幂等的关键:每次都从 serverGrade 重新算,而不是在当前 grade 上继续降 —— 否则
// applyTable 与 setCoverage 各调一次就会把同一条组合降两档。
int AttackChainEngine::regradeLocked() {
    // 每个标记只判一次(一个标记会出现在多条组合里)。无覆盖面时整段跳过。
    QHash<QString, MarkerReach> reach;
    if (haveCoverage_) {
        for (auto it = markers_.constBegin(); it != markers_.constEnd(); ++it)
            reach.insert(it.key(), classifyMarker(it.value(), coverage_).reach);
    }

    int capped = 0;
    for (ChainPattern& p : patterns_) {
        QString g = p.serverGrade;
        QStringList why;

        // ---- 1) 正常软件语料里见过 -> 不许「不问就拦」 ----
        //
        // 与服务端 _cap_by_benign 的第一条规则同口径(hits > 0 即封顶到 strong),所以
        // 【幂等】:服务端有语料时它已经降过了,这里的判定自然不成立,不会重复降;
        // 服务端语料不足 BENIGN_MIN_CORPUS 而整个环节空转时,这里补上那一刀。
        if (p.benignSupport > 0 && g == QLatin1String("hard")) {
            g = downgradeGrade(g);
            why << QStringLiteral("正常软件语料中出现过 %1 次").arg(p.benignSupport);
        }

        // ---- 2) 靠稀疏事件点亮的组合,实际强度不到服务器给的档 ----
        //
        // 服务器给 hard 的含义是「>=3 动作 + 含高危 + >=10 样本作证」,而这个信心【隐含假设
        // 那些动作会被可靠观测到】。本机的观测能力是本地事实:一个建立在「驱动偏移 0 写的
        // 全局 1/32 采样」或「模块加载只在 \Temp\ 与 \Users\Public\ 才上报」之上的动作,
        // 单次发生被看到的概率远小于 1,那么「凑齐即定性」的前提就不成立 —— 它更可能是
        // 「恰好被采到的那一次」,而不是「这个进程确实把这几件事都做了」。
        //
        // 只看 Sparse,不看 Dead:含 Dead 标记的组合永远凑不齐,降不降档都不会命中,
        // 由可达性诊断如实报出即可(analyzeReachability),不必在这里动它。
        if (!reach.isEmpty()) {
            QStringList sparseTitles;
            for (const QString& id : p.markers) {
                if (reach.value(id, MarkerReach::Reachable) != MarkerReach::Sparse)
                    continue;
                const auto mi = markers_.constFind(id);
                sparseTitles << (mi != markers_.constEnd() && !mi->title.isEmpty() ? mi->title : id);
            }
            if (!sparseTitles.isEmpty()) {
                g = downgradeGrade(g);
                why << QStringLiteral("依赖本机稀疏事件(%1)").arg(sparseTitles.join(QStringLiteral("、")));
            }
        }

        p.grade = g;
        p.capReason = why.join(QStringLiteral(";"));
        if (g != p.serverGrade)
            ++capped;
    }
    return capped;
}

int AttackChainEngine::setCoverage(const CoverageProfile& cov) {
    int capped = 0, total = 0;
    {
        QMutexLocker lk(&tableLock_);
        coverage_ = cov;
        haveCoverage_ = true;
        capped = regradeLocked();
        total = patterns_.size();
    }
    if (capped > 0)
        log_.info(QStringLiteral("攻击链:按本机可观测性与正常语料,%1/%2 条组合的生效强度已下调"
                                 "(只降不升 —— 服务器的强度假设动作会被可靠观测到,而本机能不能"
                                 "可靠看到是本地事实)。").arg(capped).arg(total));
    return capped;
}

bool AttackChainEngine::loadFromDisk() {
    QFile f(cachePath_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly))
        return false;
    const QByteArray raw = f.readAll();
    f.close();
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return false;
    // 磁盘缓存里存的是原始回包;它带 unchanged=false,故可直接走同一条装载路径。
    QJsonObject o = doc.object();
    o[QStringLiteral("unchanged")] = false;
    return applyTable(o);
}

QVector<int> AttackChainEngine::patternsFor(const QString& markerId) const {
    const auto it = index_.constFind(markerId);
    return it == index_.constEnd() ? QVector<int>() : it.value();
}

void AttackChainEngine::evictIfNeeded() {
    // 没有「进程已退出」事件可依赖(ProcessTerminate 只表示"有人要求结束"),所以记账无法在
    // 进程消失时精确回收 —— 只能按时间窗淘汰 + 容量兜底,与 ProcessChainTracker 同一取舍。
    //
    // ---- 触发节流(这一段是本函数能不能真正起作用的关键)----
    //
    // 遍历整张记账表不该每条事件都做;但原实现把本函数放在 observe() 的【末尾】、两处
    // early-return 之后,等于「只有组合命中时才淘汰」—— 而组合命中是罕见事件(那正是本
    // 引擎存在的意义)。后果:LedgerRetentionMinutes(30 分钟)与 LedgerMaxProcesses(4096)
    // 这两个配置项从未真正生效,记账表实际是只增不减的,一台机器跑一天就攒下当天出现过的
    // 每一个 PID;而真的有组合命中时,又要在持锁的裁决前置路径上一次性排序整张巨表。
    //
    // 现在由调用方【无条件】调用、节流判定收在这里:
    //   · 每 kEvictEveryEvents 条事件跑一次(常态);
    //   · 一旦已经超过容量上限就立即跑,不等计数(异常突发时的兜底,size() 是 O(1),免费)。
    const int cap = std::max(64, opt_.LedgerMaxProcesses);
    const bool overCap = ledger_.size() > cap;
    if (!overCap && ++sinceEvict_ < kEvictEveryEvents)
        return;
    sinceEvict_ = 0;

    // 按【不活动时长】淘汰,而不是按建账时长(见 ProcLedger::lastSeen 的说明):
    // 原先用 firstSeen,等于把长驻进程的证据每 30 分钟无条件抹一次,慢速攻击链永远凑不齐。
    const QDateTime cutoff =
        QDateTime::currentDateTimeUtc().addSecs(-60LL * std::max(1, opt_.LedgerRetentionMinutes));
    for (auto it = ledger_.begin(); it != ledger_.end(); ) {
        // lastSeen 为空 = 老版本留下的账(或尚未置位过标记),退回 firstSeen 判定。
        const QDateTime anchor =
            it.value().lastSeen.isValid() ? it.value().lastSeen : it.value().firstSeen;
        if (anchor < cutoff)
            it = ledger_.erase(it);
        else
            ++it;
    }
    if (ledger_.size() <= cap)
        return;
    // 仍超容量:按「最久没有活动」淘汰(LRU),而不是按建账最早 —— 后者会优先丢掉长驻
    // 进程正在累积的链条,恰好是最该留住的那些。也绝不清空:清空会把全部进行中的证据一起丢。
    // 用 nth_element 而非全排序:这里只需要知道「最旧的 excess 个是谁」,不需要把整张表排好序,
    // O(n) 就够,而全排序是 O(n log n) 且发生在持锁的裁决前置路径上。
    const int excess = ledger_.size() - cap;
    QVector<QPair<QDateTime, int>> byAge;
    byAge.reserve(ledger_.size());
    for (auto it = ledger_.constBegin(); it != ledger_.constEnd(); ++it)
        byAge.append({ it.value().lastSeen.isValid() ? it.value().lastSeen
                                                     : it.value().firstSeen,
                       it.key() });
    std::nth_element(byAge.begin(), byAge.begin() + excess, byAge.end(),
                     [](const QPair<QDateTime, int>& a, const QPair<QDateTime, int>& b) {
                         return a.first < b.first;
                     });
    for (int i = 0; i < excess; ++i)
        ledger_.remove(byAge[i].second);
}

std::optional<ChainHit> AttackChainEngine::observe(const bulwark::SecurityEvent& e) {
    if (!opt_.Enabled || e.actorPid <= 0)
        return std::nullopt;

    // 全程持锁。淘汰必须在【持锁】状态做:它会 erase/remove ledger_(可能重排哈希桶、
    // 释放节点)。只要有第二个线程读 ledger_(UI 的攻击链页面就会经 IPC 读
    // trackedProcessCount),锁外操作就是无保护的并发读写,后果是堆被写坏而且崩在
    // 毫不相干的地方。
    QMutexLocker lk(&tableLock_);
    if (patterns_.isEmpty())
        return std::nullopt;

    // 淘汰放在最前面、【无条件调用】—— 节流判定收在 evictIfNeeded 内部。
    // 原先它挂在本函数末尾、两处 early-return 之后,只有组合命中时才跑,而命中是罕见的;
    // 结果保留窗口与容量上限从未生效。详见 evictIfNeeded 开头的说明。
    evictIfNeeded();

    const QString key = e.actorPath.toLower();

    // PID 复用检测必须在「用旧标记集去跳过重复判定」【之前】做,否则会拿上一个进程的
    // 标记集来过滤本进程的匹配。
    // 这里用 find() 而不是 operator[]:后者会为不存在的键默认插入(见下方记账处的说明)。
    auto ledIt = ledger_.find(e.actorPid);
    const QDateTime nowUtc = QDateTime::currentDateTimeUtc();
    if (ledIt != ledger_.end() && !key.isEmpty() && !ledIt->actorKey.isEmpty()
        && ledIt->actorKey != key) {
        // 同一 PID 换了映像 = PID 被复用(Windows 会回收 PID)。旧账必须清掉,
        // 否则前一个进程的动作会被算到新进程头上 —— 那是最典型的误报来源。
        *ledIt = ProcLedger{};
        ledIt->actorKey = key;
        ledIt->firstSeen = nowUtc;
        ledIt->lastSeen = nowUtc;
    }

    // 本次事件命中了哪些【尚未置位】的标记。只试与本条事件同类型的那一桶
    // (见 markersByType_ 的说明:类型不符的标记在 matches() 第三步必然返回假)。
    const auto typeIt = markersByType_.constFind(static_cast<int>(e.type));
    if (typeIt == markersByType_.constEnd())
        return std::nullopt;                // 本事件类型下没有任何标记 -> 不可能有新证据
    const QSet<QString>* already = (ledIt != ledger_.end()) ? &ledIt->markers : nullptr;

    QStringList newlySet;
    for (const ChainMarker& m : typeIt.value()) {
        if (already && already->contains(m.id))
            continue;                       // 已置位,不必重复判定
        // matchesEvent 而不是 matcher.matches:后者不含「不含」条件(见 ChainMarker)。
        if (!m.matchesEvent(e))
            continue;
        newlySet << m.id;
    }
    if (newlySet.isEmpty())
        return std::nullopt;                // 没有新证据 -> 组合状态不可能改变

    // ---- 到这里才真正写记账表 ----
    //
    // 原实现一进函数就 `ProcLedger& led = ledger_[e.actorPid];`,而 QHash::operator[] 会为
    // 不存在的键【默认插入】一项。于是每个产生过任意事件的 PID 都会留下一条记账,哪怕它
    // 一个标记都没命中 —— 而绝大多数进程正是如此。配合上面那个「淘汰几乎不跑」的问题,
    // 这就是一条纯泄漏:内存随开机时长单调增长,trackedProcessCount() 报的数字也失真
    //(它本该是「正在被记账的可疑进程数」,实际成了「开机以来见过的 PID 数」)。
    ProcLedger& led = (ledIt != ledger_.end()) ? ledIt.value() : ledger_[e.actorPid];
    if (led.firstSeen.isNull()) {
        led.actorKey = key;
        led.firstSeen = nowUtc;
    }
    // lastSeen 只在【确实置位了标记】时前移(此处已确认 newlySet 非空)—— 保留窗口因此是
    // 「距上次可疑动作」而不是「距上次任何事件」,忙碌但正常的进程照旧会到期淘汰。
    led.lastSeen = nowUtc;
    for (const QString& id : newlySet)
        led.markers.insert(id);

    // 只检查「含刚置位标记」的组合(见 index_ 的说明)。
    QSet<int> toCheck;
    for (const QString& id : newlySet)
        for (int i : patternsFor(id))
            toCheck.insert(i);

    QVector<ChainPattern> candidates;
    for (int i : toCheck) {
        const ChainPattern& p = patterns_[i];
        bool complete = true;
        for (const QString& id : p.markers)
            if (!led.markers.contains(id)) { complete = false; break; }
        if (!complete)
            continue;
        // p.key 在装载时算好(见 ChainPattern::key)—— 不在这里现拼字符串。
        if (led.firedPatterns.contains(p.key))
            continue;                       // 同一进程同一组合只报一次
        led.firedPatterns.insert(p.key);
        candidates.append(p);
    }
    if (candidates.isEmpty())
        return std::nullopt;

    // 同时凑齐多条时取最强的一条上报(强度 -> 动作数 -> 支持度)。
    std::sort(candidates.begin(), candidates.end(),
              [](const ChainPattern& a, const ChainPattern& b) {
                  const int ra = gradeRank(a.grade), rb = gradeRank(b.grade);
                  if (ra != rb) return ra > rb;
                  if (a.markers.size() != b.markers.size()) return a.markers.size() > b.markers.size();
                  return a.support > b.support;
              });

    ChainHit hit;
    hit.pattern = candidates.first();
    // 只取【命中那一条】用到的标题(2~4 个)。原实现在这里把全表标记的标题拷进一个临时
    // QHash 再查,命中一次就白拷一遍整张表。
    for (const QString& id : hit.pattern.markers) {
        const auto mi = markers_.constFind(id);
        hit.titles << (mi != markers_.constEnd() ? mi->title : id);
    }
    return hit;
}

namespace {
// 把通配式实例化成一个必然被它匹配的具体串:'*' 与 '?' 都用一个填充字符替掉。
// 例:"*\\Users\\Public\\*" -> "x\\Users\\Public\\x";"*\\svchost.exe" -> "x\\svchost.exe"。
QString instantiate(const QString& pattern) {
    if (pattern.isEmpty())
        return QString();
    QString out;
    out.reserve(pattern.size());
    for (const QChar c : pattern) {
        if (c == QLatin1Char('*') || c == QLatin1Char('?'))
            out.append(QLatin1Char('x'));
        else
            out.append(c);
    }
    return out;
}
} // namespace

QPair<int, int> AttackChainEngine::selfTest(QStringList* outDetail) {
    QVector<ChainPattern> pats;
    QHash<QString, ChainMarker> marks;
    {
        QMutexLocker lk(&tableLock_);
        pats = patterns_;
        marks = markers_;
    }
    int passed = 0;
    int basePid = 900000;   // 远离真实 PID 区间,避免与在跑进程的记账串味
    for (const ChainPattern& p : pats) {
        // 组合内至多只有一种 actor 条件(冲突的已在装载时剔除),取它作为该"进程"的主体路径。
        QString actor;
        for (const QString& id : p.markers) {
            const QString a = marks.value(id).matcher.actorPattern;
            if (!a.isEmpty()) { actor = instantiate(a); break; }
        }
        if (actor.isEmpty())
            actor = QStringLiteral("C:\\x\\selftest.exe");

        const int pid = ++basePid;
        std::optional<ChainHit> hit;
        for (const QString& id : p.markers) {
            const ChainMarker& m = marks.value(id);
            bulwark::SecurityEvent e;
            e.type = m.matcher.type.value_or(bulwark::EventType::ProcessCreate);
            e.actorPid = pid;
            e.actorPath = actor;
            e.target = instantiate(m.matcher.targetPattern);
            e.commandLine = instantiate(m.matcher.commandLinePattern);
            e.parentPath = instantiate(m.matcher.parentPattern);
            // requireUnsigned 的标记要求主体未签名;其余给已签名,以确保只有该标记被点中。
            e.actorSigned = !m.matcher.requireUnsigned;
            if (const auto h = observe(e))
                hit = h;    // 最后一个动作补齐时才应命中
        }
        if (hit.has_value()) {
            ++passed;
        } else if (outDetail) {
            *outDetail << QStringLiteral("  未命中 [%1] %2")
                              .arg(p.grade).arg(p.markers.join(QStringLiteral(" + ")));
        }
        {
            // 清掉自测记账,不留痕。持锁 —— ledger_ 由 tableLock_ 保护。
            // 注意不能把锁提到循环外:上面的 observe() 自己要取同一把锁(QMutex 不可重入)。
            QMutexLocker lk(&tableLock_);
            ledger_.remove(pid);
        }
    }
    if (outDetail)
        outDetail->prepend(QStringLiteral("  合成事件自测:%1/%2 条组合按预期命中")
                               .arg(passed).arg(pats.size()));
    return { passed, pats.size() };
}

QPair<int, int> AttackChainEngine::verdictPathSelfTest(QStringList* outDetail) const {
    using bulwark::engine::ThreatDetector;
    int pass = 0, total = 0;
    const auto check = [&](bool ok, const QString& what) {
        ++total;
        if (ok) ++pass;
        if (outDetail)
            *outDetail << QStringLiteral("  %1 %2")
                              .arg(ok ? QStringLiteral("通过") : QStringLiteral("失败")).arg(what);
    };

    // ---- 支持度加分的钳位不变量 ----
    //
    // 这是本批改动里【唯一可能让处置变强】的一处,所以必须有一条断言钉住它:
    // 无论支持度多大,非 hard 档的分数都不得达到 HighRisk。否则「弹窗询问」会在某个
    // 支持度之上悄悄变成「直接拦截」—— 那是实质的处置变更,不是打分微调。
    for (const char* g : { "ask", "strong" }) {
        const int extreme = gradeScore(QString::fromLatin1(g), 100000);
        check(extreme < ThreatDetector::HighRisk,
              QStringLiteral("[%1] 支持度极大时分数 %2 仍 < 高危阈值 %3(钳位生效)")
                  .arg(QLatin1String(g)).arg(extreme).arg(ThreatDetector::HighRisk));
    }
    // 支持度确实参与打分(否则等于这条改动没生效)。
    check(gradeScore(QStringLiteral("ask"), 60) > gradeScore(QStringLiteral("ask"), 5),
          QStringLiteral("[ask] 支持度高的组合得分高于勉强达标的"));

    // ---- 降档不是装饰 ----
    //
    // 降一档,且以 ask 为地板(不降到「丢弃」——那会真的丢检出,见 downgradeGrade)。
    check(downgradeGrade(QStringLiteral("hard")) == QLatin1String("strong")
              && downgradeGrade(QStringLiteral("strong")) == QLatin1String("ask")
              && downgradeGrade(QStringLiteral("ask")) == QLatin1String("ask"),
          QStringLiteral("降档链 hard->strong->ask,并以 ask 为地板"));

    // 【这条是关键】打分必须用【生效】强度,不能用服务器原始强度。
    // 若日后有人把 applyHitToEvent 里的 hit.pattern.grade 改回 serverGrade,
    // 全套降档就变成纯装饰 —— 组合照样按 hard 直接拦,而降档理由还照样写在证据里。
    // 这里造一条「服务器给 hard、本机已降到 strong」的命中,断言它拿不到 80。
    if (!opt_.DryRun) {
        ChainHit capped;
        capped.pattern.serverGrade = QStringLiteral("hard");
        capped.pattern.grade       = QStringLiteral("strong");   // 本机降档后
        capped.pattern.support     = 12;
        capped.pattern.capReason   = QStringLiteral("自测:模拟本机降档");
        capped.pattern.markers = QStringList{ QStringLiteral("a"), QStringLiteral("b") };
        capped.titles = QStringList{ QStringLiteral("动作甲"), QStringLiteral("动作乙") };

        bulwark::SecurityEvent ce;
        ce.type = bulwark::EventType::ProcessCreate;
        ce.actorPid = 999002;
        ce.actorPath = QStringLiteral("C:\\x\\selftest.exe");
        ce.actorSigned = true;
        applyHitToEvent(ce, capped);
        check(ce.chainScore < ThreatDetector::HighRisk,
              QStringLiteral("降档后的组合按生效强度打分(%1 < %2),不会仍按服务器的 hard 直接拦")
                  .arg(ce.chainScore).arg(ThreatDetector::HighRisk));
    }

    // 造一条最小的合成命中,逐档验证贡献能不能活过 analyze 并触达闸门。
    for (const char* g : { "ask", "strong", "hard" }) {
        ChainHit hit;
        hit.pattern.grade = QString::fromLatin1(g);
        hit.pattern.serverGrade = hit.pattern.grade;   // 未降档
        hit.pattern.support = 12;
        hit.pattern.markers = QStringList{ QStringLiteral("a"), QStringLiteral("b") };
        hit.titles = QStringList{ QStringLiteral("动作甲"), QStringLiteral("动作乙") };

        bulwark::SecurityEvent e;
        e.type = bulwark::EventType::ProcessCreate;
        e.actorPid = 999001;
        e.actorPath = QStringLiteral("C:\\x\\selftest.exe");
        e.actorSigned = true;   // 刻意给「签名健康」,确保分数只可能来自组合命中

        applyHitToEvent(e, hit);
        const int wantScore = gradeScore(hit.pattern.grade, hit.pattern.support);
        if (opt_.DryRun) {
            check(!e.chainHardIndicator && e.chainScore == 0,
                  QStringLiteral("[%1] dry-run 下不产生任何裁决贡献").arg(QLatin1String(g)));
            continue;
        }
        check(e.chainHardIndicator && e.chainScore == wantScore,
              QStringLiteral("[%1] 命中后写入 chainScore=%2/硬指标")
                  .arg(QLatin1String(g)).arg(wantScore));

        // 关键一步:流水线第 3 步会跑 analyze。它复位 hasThreatIndicator、并用赋值覆盖 riskScore。
        ThreatDetector::analyze(e);
        check(e.hasThreatIndicator,
              QStringLiteral("[%1] 经 ThreatDetector::analyze 后硬指标仍在").arg(QLatin1String(g)));
        check(e.riskScore >= wantScore,
              QStringLiteral("[%1] 经 analyze 后风险分 %2 >= %3")
                  .arg(QLatin1String(g)).arg(e.riskScore).arg(wantScore));

        // 闸门(RuleEngine 第 10 步):有硬指标 -> 高危拦截,否则询问。
        const bool wantBlock = (hit.pattern.grade == QLatin1String("hard"));
        const bool gotBlock = e.riskScore >= ThreatDetector::HighRisk;
        check(gotBlock == wantBlock,
              QStringLiteral("[%1] 闸门判据得出 %2(应为 %3)")
                  .arg(QLatin1String(g))
                  .arg(gotBlock ? QStringLiteral("拦截") : QStringLiteral("询问"))
                  .arg(wantBlock ? QStringLiteral("拦截") : QStringLiteral("询问")));

        // 静默模式的降级判据:硬指标 + 分数 >= 可疑 -> 升级为拦截,而不是被降级成放行。
        // 这一条正是实测里「命中却记成 Allow」的那个环节。
        check(e.hasThreatIndicator && e.riskScore >= ThreatDetector::Suspicious,
              QStringLiteral("[%1] 静默模式下不会被降级为放行").arg(QLatin1String(g)));
    }

    if (outDetail)
        outDetail->prepend(QStringLiteral("  裁决路径自测:%1/%2 项通过").arg(pass).arg(total));
    return { pass, total };
}

// ---- 实机可达性诊断 --------------------------------------------------------- #

CoverageProfile CoverageProfile::fromOptions(const BulwarkOptions& o) {
    CoverageProfile c;
    c.driverSource = (o.EventSource.compare(QLatin1String("Driver"), Qt::CaseInsensitive) == 0)
                     && o.KernelDriverEnabled;
    // 注册表与文件的监视集口径必须与真实接线处完全一致,否则诊断结论是假的:
    //   * 驱动侧:main 把 ProtectedRegistryKeys / RegistryHardBlocks 下发为受关注键;
    //   * ETW 侧:setWatchLists(ProtectedRegistryKeys + RegistryHardBlocks,
    //                          ProtectedPaths + FileHardBlocks)。
    c.registryWatch = o.ProtectedRegistryKeys + o.RegistryHardBlocks;
    c.fileWatch     = o.ProtectedPaths + o.FileHardBlocks;
    c.etwFileEvents = o.Etw.Enabled && o.Etw.KernelFile;
    c.etwDns        = o.Etw.Enabled && o.Etw.DnsClient;
    // 「被加载模块签名」维度目前不存在:ImageLoad 事件只带主体进程的签名状态。
    // 服务器也正因此把两条 lsass / 未签名模块标记标为 unobservable。
    c.moduleSignature = false;
    // 驱动的进程创建事件已带完整命令行(TargetPath 复用,见 ProcessMonitor.c)。
    c.cmdLineInBand = c.driverSource;
    return c;
}

MarkerReachability AttackChainEngine::classifyMarker(const ChainMarker& m,
                                                     const CoverageProfile& cov) {
    MarkerReachability r;
    r.markerId = m.id;
    r.title = m.title;
    const bulwark::DefenseRule& q = m.matcher;
    const bulwark::EventType et = q.type.value_or(bulwark::EventType::ProcessCreate);

    const auto dead = [&r](const QString& why) {
        r.reach = MarkerReach::Dead;
        r.reason = why;
        return r;
    };
    const auto sparse = [&r](const QString& why) {
        r.reach = MarkerReach::Sparse;
        r.reason = why;
        return r;
    };

    switch (et) {
        case bulwark::EventType::RegistryWrite:
            // 注册表事件只在命中受关注键名单时才产生(驱动与 ETW 两侧同一模型)。
            if (cov.registryWatch.isEmpty())
                return dead(QStringLiteral("受关注注册表键名单为空 -> 不产生任何注册表事件"));
            if (!q.targetPattern.isEmpty() && !watchSetCovers(q.targetPattern, cov.registryWatch))
                return dead(QStringLiteral("target「%1」与受关注注册表键名单无交集 -> 该键的写入根本不上报")
                                .arg(q.targetPattern));
            break;

        case bulwark::EventType::FileWrite: {
            // 三条来源,按可靠性排序:
            //   1) ETW 新建文件 + 命中受保护路径监视集(不采样);
            //   2) ETW 新建文件 + 「用户可写目录下的可执行体/脚本」判据(不采样,与监视集无关);
            //   3) 驱动 IRP_MJ_WRITE 的「偏移 0 写」全局 1/32 采样(靠运气)。
            const bool etwCovered = cov.etwFileEvents && !cov.fileWatch.isEmpty()
                                    && (q.targetPattern.isEmpty()
                                        || watchSetCovers(q.targetPattern, cov.fileWatch));
            // 第 2 条:标记的 target 落在用户可写目录里 -> 投递判据会把它捞出来。
            // 判据本身是「目录 + 可执行/脚本后缀」,这里只能看目录那一半:后缀取决于样本
            // 实际落的是什么文件,不是表能决定的,故按可达计(而不是稀疏)—— 投递恶意载荷
            // 这件事本身就意味着落的是可执行体或脚本。
            bool dropCovered = false;
            if (cov.etwFileEvents && !q.targetPattern.isEmpty()) {
                static const QStringList kUserWritable = {
                    QStringLiteral("\\users\\"), QStringLiteral("\\programdata\\"),
                    QStringLiteral("\\temp\\"), QStringLiteral("\\perflogs\\"),
                };
                const QString t = q.targetPattern.toLower();
                for (const QString& d : kUserWritable) {
                    if (t.contains(d)) { dropCovered = true; break; }
                }
            }
            if (!etwCovered && !dropCovered) {
                if (!cov.driverSource)
                    return dead(QStringLiteral("target「%1」不在 ETW 新建文件监视集内,且未启用驱动 "
                                               "-> 无任何文件写入来源").arg(q.targetPattern));
                return sparse(QStringLiteral("target「%1」不在 ETW 新建文件监视集内,只能靠驱动"
                                             "「偏移 0 写」的全局 1/32 采样 -> 单次落盘约 1/32 概率被上报")
                                  .arg(q.targetPattern));
            }
            break;
        }

        case bulwark::EventType::FileDelete:
            // 删除标记 / delete-on-close 走 SetInformation 遥测,不采样;但同样受监视集限制。
            if (!q.targetPattern.isEmpty() && !cov.fileWatch.isEmpty()
                && !watchSetCovers(q.targetPattern, cov.fileWatch) && !cov.driverSource)
                return dead(QStringLiteral("target「%1」不在文件监视集内且未启用驱动")
                                .arg(q.targetPattern));
            break;

        case bulwark::EventType::ImageLoad:
            // 内核只上报 \Temp\ 与 \Users\Public\ 下的用户态模块加载(BlwPathIsSuspicious),
            // 以及用户可写目录下的 .sys(BYOVD)。其它位置的加载一律不产生事件。
            if (!cov.driverSource)
                return dead(QStringLiteral("模块加载事件仅由内核驱动产生,当前未启用驱动"));
            if (!q.targetPattern.isEmpty()) {
                const QString t = q.targetPattern.toLower();
                const bool narrow = t.contains(QLatin1String("\\temp\\"))
                                    || t.contains(QLatin1String("\\users\\public\\"))
                                    || t.endsWith(QLatin1String(".sys"));
                if (!narrow)
                    return sparse(QStringLiteral("内核仅上报 \\Temp\\ 与 \\Users\\Public\\ 下的用户态"
                                                 "模块加载,target「%1」只在恰好落在这两个位置时才可能命中")
                                      .arg(q.targetPattern));
            }
            break;

        case bulwark::EventType::DnsQuery:
            if (!cov.etwDns)
                return dead(QStringLiteral("DnsQuery 仅来自 ETW DNS-Client,该提供程序未启用"));
            break;

        case bulwark::EventType::ProcessCreate:
            break;   // 进程创建永远上报;下面再看命令行这类字段能不能拿到

        default:
            break;
    }

    // 命令行:Driver 源随事件带上(内核回调里本来就有 CreateInfo->CommandLine);
    // 纯用户态观测源不带,只能由 enrich() 按 PID 读 PEB 回填 —— 毫秒级退出的
    // LOLBin(reg.exe / schtasks.exe / cmstp.exe)读不到,该条件随之失配。
    if (!q.commandLinePattern.isEmpty() && !cov.cmdLineInBand)
        return sparse(QStringLiteral("依赖命令行(「%1」),而当前事件源不带命令行、靠读 PEB 回填 "
                                     "-> 毫秒级退出的进程读不到")
                          .arg(q.commandLinePattern));

    r.reach = MarkerReach::Reachable;
    return r;
}

QStringList AttackChainEngine::derivedRegistryWatch(const CoverageProfile& cov) const {
    // 过宽的片段一律不采纳 —— 它们会把系统组件每秒的高频写全部拉进上报通道。
    // 判据不是「长度够不够」,而是「这个片段本身有没有指向性」:\Software\ 底下什么都有,
    // 而 \CurrentVersion\Run 指向的是一件具体的事。
    static const QStringList kTooWide = {
        QStringLiteral("\\registry\\"), QStringLiteral("\\software\\"),
        QStringLiteral("\\machine\\"),  QStringLiteral("\\user\\"),
        QStringLiteral("\\microsoft\\"),QStringLiteral("\\windows\\"),
        QStringLiteral("\\currentversion\\"), QStringLiteral("\\policies\\"),
        QStringLiteral("\\control\\"),  QStringLiteral("\\classes\\"),
    };

    QStringList out;
    QSet<QString> seen;
    const QVector<ChainMarker> marks = markerSnapshot();
    for (const ChainMarker& m : marks) {
        if (m.matcher.type.value_or(bulwark::EventType::ProcessCreate)
                != bulwark::EventType::RegistryWrite)
            continue;
        if (m.matcher.targetPattern.isEmpty())
            continue;
        if (classifyMarker(m, cov).reach != MarkerReach::Dead)
            continue;   // 覆盖已经够 -> 一个字都不加

        // 取最长的字面片段:它最有指向性,也最不容易把无关键连带进来。
        QString best;
        for (const QString& run : literalRuns(m.matcher.targetPattern))
            if (run.size() > best.size())
                best = run;
        if (best.size() < 6)
            continue;
        const QString low = best.toLower();
        bool tooWide = false;
        for (const QString& w : kTooWide) {
            if (low == w || low == w.left(w.size() - 1)) { tooWide = true; break; }
        }
        if (tooWide || seen.contains(low))
            continue;
        seen.insert(low);
        out << best;
        if (out.size() >= kMaxDerivedRegKeys) {
            log_.warning(QStringLiteral("攻击链:派生受关注注册表键已达上限 %1 条,余下的标记"
                                        "仍不可观测(为防事件洪泛刻意不再追加)。")
                             .arg(kMaxDerivedRegKeys));
            break;
        }
    }
    return out;
}

QVector<ChainMarker> AttackChainEngine::markerSnapshot() const {
    QMutexLocker lk(&tableLock_);
    QVector<ChainMarker> out;
    out.reserve(markers_.size());
    for (auto it = markers_.constBegin(); it != markers_.constEnd(); ++it)
        out.append(it.value());
    return out;
}

QVector<ChainPattern> AttackChainEngine::patternSnapshot() const {
    QMutexLocker lk(&tableLock_);
    return patterns_;
}

ReachabilityReport AttackChainEngine::analyzeReachability(const CoverageProfile& cov) const {
    ReachabilityReport rep;
    QVector<ChainPattern> pats;
    QHash<QString, ChainMarker> marks;
    {
        QMutexLocker lk(&tableLock_);
        pats = patterns_;
        marks = markers_;
        rep.serverPatterns   = srvPatterns_;
        rep.droppedConflict  = dropConflict_;
        rep.droppedRedundant = dropRedundant_;
    }
    rep.loaded = pats.size();

    // 每个标记只判一次(一个标记会出现在多条组合里)。
    QHash<QString, MarkerReachability> cache;
    for (auto it = marks.constBegin(); it != marks.constEnd(); ++it)
        cache.insert(it.key(), classifyMarker(it.value(), cov));

    QStringList deadLines, sparseLines;
    for (const ChainPattern& p : pats) {
        MarkerReach worst = MarkerReach::Reachable;
        QStringList why;
        for (const QString& id : p.markers) {
            const MarkerReachability& mr = cache.value(id);
            if (mr.reach == MarkerReach::Reachable)
                continue;
            if (static_cast<int>(mr.reach) > static_cast<int>(worst))
                worst = mr.reach;
            why << QStringLiteral("      · %1:%2")
                       .arg(mr.title.isEmpty() ? mr.markerId : mr.title, mr.reason);
        }
        if (worst == MarkerReach::Reachable) {
            ++rep.reachable;
            continue;
        }
        const QString head = QStringLiteral("    [%1] %2 个动作,%3 个样本作证")
                                 .arg(p.grade).arg(p.markers.size()).arg(p.support);
        if (worst == MarkerReach::Dead) {
            ++rep.dead;
            deadLines << head << why;
        } else {
            ++rep.sparse;
            sparseLines << head << why;
        }
    }

    rep.lines << QStringLiteral("  服务器下发 %1 条;装载期剔除 %2 条(主体冲突)+ %3 条(证据重复)"
                                ";实际装载 %4 条")
                     .arg(rep.serverPatterns).arg(rep.droppedConflict)
                     .arg(rep.droppedRedundant).arg(rep.loaded);
    rep.lines << QStringLiteral("  装载的 %1 条中:可靠可达 %2 条 / 稀疏(能命中但不可靠)%3 条 / "
                                "结构性死路 %4 条")
                     .arg(rep.loaded).arg(rep.reachable).arg(rep.sparse).arg(rep.dead);
    // 「实机可达率」按服务器下发量算,而不是按装载量 —— 装载量已经把剔除的那些藏起来了,
    // 用它做分母会让数字虚高,正是本诊断要消除的那种错觉。
    const int denom = rep.serverPatterns > 0 ? rep.serverPatterns : rep.loaded;
    if (denom > 0)
        rep.lines << QStringLiteral("  ==> 实机可达率:%1%(%2/%3,只计可靠可达)")
                         .arg(QString::number(100.0 * rep.reachable / denom, 'f', 1))
                         .arg(rep.reachable).arg(denom);
    if (!deadLines.isEmpty()) {
        rep.lines << QStringLiteral("  结构性死路(永不命中):");
        rep.lines << deadLines;
    }
    if (!sparseLines.isEmpty()) {
        rep.lines << QStringLiteral("  稀疏(靠运气):");
        rep.lines << sparseLines;
    }
    return rep;
}

void AttackChainEngine::applyHitToEvent(bulwark::SecurityEvent& e, const ChainHit& hit) const {
    const QString chain = hit.titles.join(QStringLiteral(" + "));
    const QString base = QStringLiteral("攻击链组合命中(%1 个动作凑齐,%2 个真实样本作证")
                             .arg(hit.pattern.markers.size()).arg(hit.pattern.support)
                       + (hit.pattern.families.isEmpty()
                              ? QString()
                              : QStringLiteral(",常见家族:") + hit.pattern.families)
                       + QStringLiteral("):") + chain;

    if (opt_.DryRun) {
        // 只留痕、不影响裁决:不提分、不置硬指标、也不写进 riskReasons(免得看起来像已生效)。
        e.addEvidence(QStringLiteral("AttackChain"), bulwark::EvidenceKind::Info,
                      QStringLiteral("[dry-run 仅记录] ") + base, 0, /*alsoReason=*/false);
        return;
    }

    // 强制模式:按服务器给出的强度提分并置硬指标,交由既有裁决流水线得出结论。
    // 这里【刻意不直接改裁决】—— 用户信任 / 自身组件 / 已装杀软那几道放行通道在流水线中位于
    // 本引擎之前,越过它们就会造成真误伤。组合本身即是互证(N 个动作同现,且有 N 个样本作证),
    // 故按硬指标登记,而非软信号。
    //
    // 【必须写 chainScore / chainHardIndicator,不能直接写 riskScore / hasThreatIndicator】:
    // 本函数在 evaluate 之前执行,而流水线第 3 步的 ThreatDetector::analyze 会复位
    // hasThreatIndicator、并用赋值覆盖 riskScore。早先这里直接写那两个字段,结果贡献被
    // 全部擦掉 —— 组合表上线后一次都没生效过。addEvidence 的 scoreDelta 也只进证据链、
    // 不改 riskScore(见 SecurityEvent::addEvidence 的注释),所以光传它同样没有作用。
    // 分数按【生效】强度算,并在档位内计入支持度(见 gradeScore 的说明)。
    // 生效强度可能已被本机降档 —— 用 serverGrade 打分就等于把降档白做了。
    const int add = gradeScore(hit.pattern.grade, hit.pattern.support);
    e.chainHardIndicator = true;
    e.chainScore = qMax(e.chainScore, add);   // 同一事件命中多条时取最强的一条,不叠加

    // 降过档就把原因写进证据。否则服务器页面上这条组合显示 hard、端点上却只是询问,
    // 看的人无从解释这个差异,只会当成 bug 去查。
    const QString capNote =
        hit.pattern.capReason.isEmpty()
            ? QString()
            : QStringLiteral("(服务器定级 ") + gradeLabel(hit.pattern.serverGrade)
                  + QStringLiteral(",本机下调:") + hit.pattern.capReason + QStringLiteral(")");
    e.addEvidence(QStringLiteral("AttackChain"), bulwark::EvidenceKind::HardIndicator,
                  base + QStringLiteral(" [") + gradeLabel(hit.pattern.grade) + QStringLiteral("]")
                      + capNote,
                  add);
}

// ============================== AttackChainFeed ===============================

AttackChainFeed::AttackChainFeed(const AttackChainOptions& opt, const QString& baseUrlFallback)
    : opt_(opt) {
    baseUrl_ = opt.BaseUrl.trimmed();
    if (baseUrl_.isEmpty())
        baseUrl_ = baseUrlFallback.trimmed();
    while (baseUrl_.endsWith(QLatin1Char('/')))
        baseUrl_.chop(1);
    maskedUrl_ = ReputationProxyOptions::maskUrl(baseUrl_);
}

AttackChainFeed::~AttackChainFeed() { stop(); }

bool AttackChainFeed::isEnabled() const { return opt_.Enabled && !baseUrl_.isEmpty(); }

bool AttackChainFeed::sleepInterruptible(int seconds) {
    if (seconds <= 0)
        return running_.load();
    std::unique_lock<std::mutex> lk(mx_);
    cv_.wait_for(lk, std::chrono::seconds(seconds), [this] { return !running_.load(); });
    return running_.load();
}

std::optional<QJsonObject> AttackChainFeed::fetchTable() {
    const int timeout = std::max(5, opt_.QueryTimeoutSeconds);
    // 带 since= 让服务器在版本未变时只回一个 unchanged 标志,不下发规则体(省流量)。
    QString url = baseUrl_ + QStringLiteral("/v1/engine/patterns?since=")
                + QString::number(currentVersion_.load());
    const QString grade = opt_.MinGrade.trimmed().toLower();
    if (grade == QLatin1String("hard") || grade == QLatin1String("strong"))
        url += QStringLiteral("&min_grade=") + grade;

    const auto res = reputation::ReputationCurl::get(url, {}, timeout);
    if (res.first != 200) {
        log_.info(QStringLiteral("攻击链组合表拉取失败:%1 返回 HTTP %2(保持现有表)。")
                      .arg(maskedUrl_).arg(res.first));
        return std::nullopt;
    }
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(res.second.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        log_.warning(QStringLiteral("攻击链组合表拉取失败:回包不是合法 JSON(保持现有表)。"));
        return std::nullopt;
    }
    return doc.object();
}

bool AttackChainFeed::fetchOnceForCheck() {
    const std::optional<QJsonObject> table = fetchTable();
    if (!table.has_value())
        return false;
    if (onTableReady_)
        onTableReady_(*table);   // 自检模式:就在本线程调用,不编组(没有事件循环可编组过去)
    return true;
}

int AttackChainFeed::secondsUntilDailyHour(int hour) const {
    // 本机时区的下一个 hour:00。已过今天该时刻则顺延到明天。
    const QDateTime now = QDateTime::currentDateTime();
    QDateTime target(now.date(), QTime(std::clamp(hour, 0, 23), 0, 0));
    if (target <= now)
        target = target.addDays(1);
    qint64 secs = now.secsTo(target);
    // 小幅错峰(0~5 分钟):避免同一时刻全部端点一起打服务器。
    secs += QRandomGenerator::global()->bounded(300);
    return static_cast<int>(std::max<qint64>(1, secs));
}

void AttackChainFeed::loop() {
    if (!sleepInterruptible(std::max(0, opt_.InitialDelaySeconds)))
        return;

    // 启动后先立刻同步一次 —— 不能等到当天的更新时刻:机器可能关机好几天,开机时手里的表
    // 已经很旧了,却要再等到早上 6 点才更新。之后才转入每日定时。
    bool first = true;
    while (running_.load()) {
        if (!first) {
            const int wait = opt_.DailyUpdateHour >= 0
                                 ? secondsUntilDailyHour(opt_.DailyUpdateHour)
                                 : (opt_.RefreshIntervalHours > 0
                                        ? opt_.RefreshIntervalHours * 3600
                                        : 0);
            if (wait <= 0)
                break;                 // 间隔式且 <=0:仅启动时拉一次
            if (!sleepInterruptible(wait))
                return;
        }
        first = false;

        const std::optional<QJsonObject> table = fetchTable();
        if (table.has_value() && onTableReady_) {
            if (table->value(QLatin1String("unchanged")).toBool()) {
                log_.debug(QStringLiteral("攻击链组合表已是最新(版本 %1),本次不更新。")
                               .arg(currentVersion_.load()));
            } else {
                TableReadyCallback cb = onTableReady_;
                const QJsonObject payload = *table;
                // 编组回主线程再装载:记账表是主线程亲和的,装载会替换它读的那份组合表。
                QMetaObject::invokeMethod(
                    qApp, [cb, payload] { cb(payload); }, Qt::QueuedConnection);
            }
        }
    }
}

void AttackChainFeed::start() {
    if (!isEnabled()) {
        log_.info(QStringLiteral("攻击链组合引擎未启用(未开启或无端点),后台刷新不启动。"));
        return;
    }
    if (running_.exchange(true))
        return;
    worker_ = std::thread([this] { loop(); });
    log_.info(QStringLiteral("攻击链组合表后台刷新已启动(端点 %1,%2)。")
                  .arg(maskedUrl_)
                  .arg(opt_.DailyUpdateHour >= 0
                           ? QStringLiteral("每天 %1:00 自动更新")
                                 .arg(std::clamp(opt_.DailyUpdateHour, 0, 23), 2, 10, QLatin1Char('0'))
                           : QStringLiteral("每 %1 小时").arg(opt_.RefreshIntervalHours)));
}

void AttackChainFeed::stop() {
    if (!running_.exchange(false))
        return;
    {
        std::lock_guard<std::mutex> lk(mx_);
        cv_.notify_all();
    }
    if (worker_.joinable())
        worker_.join();
}

} // namespace bulwark::service
