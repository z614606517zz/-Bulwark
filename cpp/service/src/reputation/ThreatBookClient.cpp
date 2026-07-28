#include "bulwark/service/reputation/ThreatBookClient.h"
#include "bulwark/service/reputation/ReputationCurl.h"
#include "bulwark/service/AtomicFile.h"
#include "bulwark/service/Logger.h" // programDataDir()

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QMutexLocker>

#include <algorithm>
#include <optional>

namespace bulwark::service::reputation {
namespace {

using bulwark::ReputationVerdict;

inline QString u(const char* s) { return QString::fromUtf8(s); }

const QString kEicar = QStringLiteral("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

// 解析密钥:环境变量优先于配置(与其它源一致)。
QString envOr(const char* var, const QString& fallback) {
    const QString e = qEnvironmentVariable(var).trimmed();
    return !e.isEmpty() ? e : fallback.trimmed();
}

// 递归查找首个名为 name 的字符串值(对象键名不区分大小写;数组内取首个字符串)。
QString findFirstString(const QJsonValue& v, const QString& name) {
    if (v.isObject()) {
        const QJsonObject o = v.toObject();
        for (auto it = o.constBegin(); it != o.constEnd(); ++it) {
            if (it.key().compare(name, Qt::CaseInsensitive) == 0) {
                if (it.value().isString())
                    return it.value().toString();
                if (it.value().isArray()) {
                    for (const QJsonValue& e : it.value().toArray())
                        if (e.isString())
                            return e.toString();
                }
            }
            const QString r = findFirstString(it.value(), name);
            if (!r.isNull())
                return r;
        }
    } else if (v.isArray()) {
        for (const QJsonValue& e : v.toArray()) {
            const QString r = findFirstString(e, name);
            if (!r.isNull())
                return r;
        }
    }
    return QString(); // null => 未找到
}

// 递归查找首个名为 name 的布尔值。
std::optional<bool> findBool(const QJsonValue& v, const QString& name) {
    if (v.isObject()) {
        const QJsonObject o = v.toObject();
        for (auto it = o.constBegin(); it != o.constEnd(); ++it) {
            if (it.key().compare(name, Qt::CaseInsensitive) == 0 && it.value().isBool())
                return it.value().toBool();
            const auto r = findBool(it.value(), name);
            if (r.has_value())
                return r;
        }
    } else if (v.isArray()) {
        for (const QJsonValue& e : v.toArray()) {
            const auto r = findBool(e, name);
            if (r.has_value())
                return r;
        }
    }
    return std::nullopt;
}

// 威胁等级/严重度字符串 -> 结论(中英关键词)。
std::optional<ReputationVerdict> mapVerdict(const QString& s) {
    if (s.trimmed().isEmpty())
        return std::nullopt;
    const QString v = s.trimmed().toLower();
    if (v == QLatin1String("malicious") || v == QLatin1String("high") || v == QLatin1String("critical")
        || v == QLatin1String("severe") || v.contains(u("恶意")) || v.contains(u("高危")))
        return ReputationVerdict::Malicious;
    if (v == QLatin1String("suspicious") || v == QLatin1String("mid") || v == QLatin1String("medium")
        || v == QLatin1String("moderate") || v.contains(u("可疑")) || v.contains(u("中危")))
        return ReputationVerdict::Suspicious;
    if (v == QLatin1String("clean") || v == QLatin1String("safe") || v == QLatin1String("white")
        || v == QLatin1String("info") || v == QLatin1String("low") || v.contains(u("正常"))
        || v.contains(u("无威胁")) || v.contains(u("低危")))
        return ReputationVerdict::Clean;
    return std::nullopt;
}

// judgments 标签(出现 C2/Trojan/Ransom 等)-> 恶意。
std::optional<ReputationVerdict> mapJudgments(const QString& j) {
    if (j.trimmed().isEmpty())
        return std::nullopt;
    const QString v = j.toLower();
    static const char* const bad[] = { "c2", "trojan", "ransom", "backdoor", "miner", "worm",
                                       "botnet", "malware", "apt", "exploit", "spyware", "rat" };
    for (const char* k : bad)
        if (v.contains(QLatin1String(k)))
            return ReputationVerdict::Malicious;
    return std::nullopt;
}

} // namespace

ThreatBookClient::ThreatBookClient(const BulwarkOptions& options)
    : ReputationClientBase(QStringLiteral("ThreatBook"),
                           envOr(ThreatBookOptions::ApiKeyEnvVar, options.ThreatBook.ApiKey),
                           false, options.ThreatBook.RequestsPerMinute,
                           options.ThreatBook.RequestsPerDay, options.ThreatBook.QueryTimeoutSeconds) {
    reportUrl_ = options.ThreatBook.BaseUrl; // 默认 https://api.threatbook.cn/v3/file/report
    ipUrl_ = options.ThreatBook.IpIntelBaseUrl.isEmpty()
                 ? QStringLiteral("https://api.threatbook.cn/v3/scene/ip_reputation")
                 : options.ThreatBook.IpIntelBaseUrl;
    sceneLimit_ = std::max(1, options.ThreatBook.SceneRequestsPerMonth);
    enabled_ = !apiKey_.isEmpty();           // 有 Key 即可用(与 .NET ThreatBook 一致)
    loadSceneState();
}

namespace {
QString sceneStatePath() {
    return QDir(programDataDir()).filePath(QStringLiteral("tb_ip_quota.json"));
}
} // namespace

void ThreatBookClient::loadSceneState() {
    QFile f(sceneStatePath());
    if (!f.open(QIODevice::ReadOnly))
        return;                                  // 首次运行:保持 sceneMonth_=-1,下次 roll 会归零
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (!doc.isObject())
        return;
    const QJsonObject o = doc.object();
    const int m = o.value(QLatin1String("month")).toInt(-1);
    const int used = o.value(QLatin1String("used")).toInt(0);
    if (m <= 0 || used < 0)
        return;                                  // 文件坏了就当没有,宁可重新计数
    sceneMonth_ = m;
    sceneUsed_ = used;
}

void ThreatBookClient::saveSceneState() {
    // 调用方须已持 sceneMutex_。
    QJsonObject o;
    o[QStringLiteral("month")] = sceneMonth_;
    o[QStringLiteral("used")] = sceneUsed_;
    writeFileAtomically(sceneStatePath(), QJsonDocument(o).toJson(QJsonDocument::Compact),
                        QStringLiteral("微步 IP 情报月配额计数"));
}

void ThreatBookClient::rollSceneMonth() {
    // 调用方须已持 sceneMutex_。
    const QDate today = QDateTime::currentDateTimeUtc().date();
    const int m = today.year() * 100 + today.month();
    if (m != sceneMonth_) {
        sceneMonth_ = m;
        sceneUsed_ = 0;
        sceneExhaustedLogged_ = false;
    }
}

void ThreatBookClient::noteExhaustedOnce() {
    // 调用方须已持 sceneMutex_。每月只报一条:原先是每次调用都写一行,配额耗尽后就退化成纯噪声
    // —— 实测 rep_diag.log 里绝大部分内容都是这一句在反复重复(同一个 IP 一秒内出现 12 次)。
    // 但也不能一条都不报:上层现在会在入队前就短路,若这里不出声,IP 情报就"静默失效"一整月,
    // 运维完全看不出来。所以保留恰好一条。
    if (sceneExhaustedLogged_)
        return;
    sceneExhaustedLogged_ = true;
    ReputationCurl::diag(QStringLiteral("TB ip 本月情报配额已用尽(%1/%2),到下月前不再查询")
                             .arg(sceneUsed_).arg(sceneLimit_));
}

bool ThreatBookClient::trySceneQuota() {
    // 场景接口(IP)月配额极低,与文件信誉(300/天)分开计数,避免一次打爆。到月自动归零。
    QMutexLocker lock(&sceneMutex_);
    rollSceneMonth();
    if (sceneUsed_ >= sceneLimit_) {
        noteExhaustedOnce();
        return false;
    }
    ++sceneUsed_;
    saveSceneState(); // 每月最多 20 次,写盘开销可忽略
    return true;
}

bool ThreatBookClient::ipIntelBudgetSpent() {
    if (!enabled_)
        return true; // 没配 Key,别让上层白排队
    QMutexLocker lock(&sceneMutex_);
    rollSceneMonth();
    if (sceneUsed_ < sceneLimit_)
        return false;
    noteExhaustedOnce(); // 上层就是靠这个短路的,那条"配额用尽"就得从这里发出来
    return true;
}

bulwark::IpReputation ThreatBookClient::queryIp(const QString& ip) {
    bulwark::IpReputation unknown;
    unknown.resource = ip;
    unknown.verdict = ReputationVerdict::Unknown;
    if (!enabled_ || ip.trimmed().isEmpty())
        return unknown;

    if (!trySceneQuota())
        return unknown; // trySceneQuota 已按月记录一次,这里不再逐 IP 刷日志
    bucket_.wait();

    const QList<QPair<QString, QString>> form{
        { QStringLiteral("apikey"), apiKey() },
        { QStringLiteral("resource"), ip } };
    const auto res = ReputationCurl::postForm(ipUrl_, form, {}, timeoutSecs_);
    if (res.first != 200) {
        ReputationCurl::diag(QStringLiteral("TB ip %1 => HTTP %2").arg(ip).arg(res.first));
        return unknown;
    }
    const bulwark::IpReputation parsed = parseIp(ip, res.second);
    ReputationCurl::diag(QStringLiteral("TB ip %1 => v%2 (%3)")
                             .arg(ip).arg(static_cast<int>(parsed.verdict)).arg(parsed.threatLabel));
    return parsed;
}

bulwark::IpReputation ThreatBookClient::parseIp(const QString& ip, const QString& body) const {
    bulwark::IpReputation rep;
    rep.resource = ip;
    rep.verdict = ReputationVerdict::Unknown;

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return rep;
    const QJsonObject root = doc.object();

    // response_code != 0:鉴权/参数/未收录等。不视为成功(下次可重试)。
    const QJsonValue rc = root.value(QLatin1String("response_code"));
    const int code = rc.isDouble() ? rc.toInt() : -1;
    if (code != 0) {
        rep.querySucceeded = false;
        return rep;
    }
    rep.querySucceeded = true;

    const QJsonValue data =
        root.contains(QLatin1String("data")) ? root.value(QLatin1String("data")) : QJsonValue(root);

    // 明确恶意标记优先;否则由 severity / judgments 映射。
    const auto isMalicious = findBool(data, QStringLiteral("is_malicious"));
    const QString judgments = findFirstString(data, QStringLiteral("judgments"));
    const QString severity = findFirstString(data, QStringLiteral("severity"));
    const QString confidence = findFirstString(data, QStringLiteral("confidence_level"));

    std::optional<ReputationVerdict> verdict = mapVerdict(severity);
    if (!verdict.has_value())
        verdict = mapJudgments(judgments);
    if (isMalicious.has_value() && isMalicious.value()
        && (!verdict.has_value() || verdict.value() == ReputationVerdict::Clean))
        verdict = ReputationVerdict::Malicious;

    // 低置信度的恶意判定降级为可疑(降误报,交由双证据互证)。
    if (verdict.has_value() && verdict.value() == ReputationVerdict::Malicious
        && confidence.trimmed().toLower() == QLatin1String("low"))
        verdict = ReputationVerdict::Suspicious;

    rep.verdict = verdict.value_or(ReputationVerdict::Clean); // 收录但无威胁信号 -> 干净
    if (!judgments.trimmed().isEmpty())
        rep.threatLabel = judgments;
    else if (!severity.trimmed().isEmpty())
        rep.threatLabel = QStringLiteral("ThreatBook:") + severity;
    return rep;
}

bulwark::FileReputation ThreatBookClient::doQuery(const QString& sha256) {
    bulwark::FileReputation unknown = unknownRep(sha256);
    const QList<QPair<QString, QString>> form{
        { QStringLiteral("apikey"), apiKey() },
        { QStringLiteral("sha256"), sha256 } };
    const auto res = ReputationCurl::postForm(reportUrl_, form, {}, timeoutSecs_);
    if (res.first != 200) {
        ReputationCurl::diag(QStringLiteral("TB %1 => HTTP %2").arg(sha256.left(12)).arg(res.first));
        return unknown;
    }
    return parse(sha256, res.second);
}

bulwark::FileReputation ThreatBookClient::parse(const QString& sha256, const QString& body) const {
    bulwark::FileReputation rep = unknownRep(sha256);
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return rep;
    const QJsonObject root = doc.object();

    // response_code != 0:鉴权/参数/未收录等,不缓存(下次重试)。
    const QJsonValue rc = root.value(QLatin1String("response_code"));
    const int code = rc.isDouble() ? rc.toInt() : 0;
    if (code != 0) {
        rep.querySucceeded = false;
        return rep;
    }
    rep.querySucceeded = true; // 查询成功(权威结果,含"收录但未判恶意"的负结果)

    const QJsonValue data =
        root.contains(QLatin1String("data")) ? root.value(QLatin1String("data")) : QJsonValue(root);

    // 白名单 -> 干净。
    const auto whitelist = findBool(data, QStringLiteral("is_whitelist"));
    if (whitelist.has_value() && whitelist.value()) {
        rep.verdict = ReputationVerdict::Clean;
        rep.threatLabel = u("ThreatBook 白名单");
        return rep;
    }

    const QString level = findFirstString(data, QStringLiteral("threat_level"));
    const QString judgments = findFirstString(data, QStringLiteral("judgments"));
    const QString severity = findFirstString(data, QStringLiteral("severity"));
    QString family = findFirstString(data, QStringLiteral("malware_family"));
    if (family.isNull())
        family = findFirstString(data, QStringLiteral("malware_type"));

    std::optional<ReputationVerdict> verdict = mapVerdict(level);
    if (!verdict.has_value()) verdict = mapVerdict(severity);
    if (!verdict.has_value()) verdict = mapJudgments(judgments);

    rep.verdict = verdict.value_or(ReputationVerdict::Clean); // 收录但无威胁信号 -> 干净
    if (!family.isEmpty())
        rep.threatLabel = family;
    else if (!judgments.isEmpty())
        rep.threatLabel = judgments;
    else if (!level.isEmpty())
        rep.threatLabel = QStringLiteral("ThreatBook:") + level;
    return rep;
}

std::pair<bool, QString> ThreatBookClient::doTest() {
    if (apiKey_.isEmpty())
        return { false, u("服务端未配置 ThreatBook API 密钥(环境变量 BULWARK_THREATBOOK_APIKEY)") };
    bucket_.wait();
    const QList<QPair<QString, QString>> form{
        { QStringLiteral("apikey"), apiKey() },
        { QStringLiteral("sha256"), kEicar } };
    const auto res = ReputationCurl::postForm(reportUrl_, form, {}, timeoutSecs_);
    if (res.first == 0)
        return { false, u("连接失败(curl 不可用或网络不通)") };
    if (res.first != 200)
        return { false, u("返回异常状态:") + QString::number(res.first) };

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(res.second.toUtf8(), &err);
    int rcode = -999;
    QString msg;
    if (err.error == QJsonParseError::NoError && doc.isObject()) {
        const QJsonObject o = doc.object();
        const QJsonValue rc = o.value(QLatin1String("response_code"));
        rcode = rc.isDouble() ? rc.toInt() : -999;
        msg = o.value(QLatin1String("verbose_msg")).toString();
    }
    // response_code==0 表示 Key 有效(即便样本未收录)。
    if (rcode == 0)
        return { true, u("连接成功,API 密钥有效") };
    return { false, u("密钥或配额异常(response_code=") + QString::number(rcode)
                    + (msg.isEmpty() ? QString() : (u(", ") + msg)) + u(")") };
}

} // namespace bulwark::service::reputation
