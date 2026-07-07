#include "bulwark/service/reputation/HashReputationClients.h"
#include "bulwark/service/reputation/ReputationCurl.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QSet>

namespace bulwark::service::reputation {
namespace {

using bulwark::FileReputation;
using bulwark::ReputationVerdict;

inline QString u(const char* s) { return QString::fromUtf8(s); }

const QString kEicar = QStringLiteral("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

// Resolve a secret: env var (trimmed) takes precedence over the config fallback.
QString envOr(const char* var, const QString& fallback) {
    const QString e = qEnvironmentVariable(var).trimmed();
    return !e.isEmpty() ? e : fallback.trimmed();
}

QJsonObject parseObj(const QString& json) {
    QJsonParseError err{};
    const QJsonDocument d = QJsonDocument::fromJson(json.toUtf8(), &err);
    return (err.error == QJsonParseError::NoError && d.isObject()) ? d.object() : QJsonObject();
}

int jInt(const QJsonObject& o, const char* k) {
    const QJsonValue v = o.value(QLatin1String(k));
    return v.isDouble() ? v.toInt() : 0;
}

} // namespace

// ---- MalwareBazaar ----------------------------------------------------------
MalwareBazaarClient::MalwareBazaarClient(const BulwarkOptions& options)
    : ReputationClientBase(QStringLiteral("MalwareBazaar"),
                           envOr(MalwareBazaarOptions::AuthKeyEnvVar, options.MalwareBazaar.AuthKey),
                           false, options.MalwareBazaar.RequestsPerMinute,
                           options.MalwareBazaar.RequestsPerDay, options.MalwareBazaar.QueryTimeoutSeconds) {
    apiUrl_ = options.MalwareBazaar.BaseUrl;
    enabled_ = options.MalwareBazaar.Enabled && !apiKey_.isEmpty();
}

FileReputation MalwareBazaarClient::doQuery(const QString& sha256) {
    FileReputation unknown = unknownRep(sha256);
    const QList<QPair<QString, QString>> form{
        { QStringLiteral("query"), QStringLiteral("get_info") },
        { QStringLiteral("hash"), sha256 } };
    const QStringList headers{ QStringLiteral("Auth-Key: ") + apiKey() };
    const auto res = ReputationCurl::postForm(apiUrl_, form, headers, timeoutSecs_);
    const int code = res.first;
    if (code == 401) { log_.warning(u("MalwareBazaar 鉴权失败(401)")); return unknown; }
    if (code == 429) { log_.warning(u("MalwareBazaar 触发限流(429)")); return unknown; }
    if (code != 200) { ReputationCurl::diag(QStringLiteral("MB %1 => HTTP %2").arg(sha256.left(12)).arg(code)); return unknown; }
    return parse(sha256, res.second);
}

FileReputation MalwareBazaarClient::parse(const QString& sha256, const QString& json) const {
    FileReputation rep = unknownRep(sha256);
    const QJsonObject root = parseObj(json);
    const QString status = root.value(QLatin1String("query_status")).toString();
    if (status.compare(QLatin1String("ok"), Qt::CaseInsensitive) == 0) {
        rep.verdict = ReputationVerdict::Malicious;
        rep.querySucceeded = true;
        const QJsonArray data = root.value(QLatin1String("data")).toArray();
        if (!data.isEmpty() && data.first().isObject()) {
            const QJsonObject first = data.first().toObject();
            const QString sig = first.value(QLatin1String("signature")).toString();
            if (!sig.trimmed().isEmpty()) rep.threatLabel = sig;
            rep.malicious = 1;
            rep.totalEngines = 1;
            const QJsonObject vi = first.value(QLatin1String("vendor_intel")).toObject();
            if (!vi.isEmpty()) { rep.malicious = vi.size(); rep.totalEngines = vi.size(); }
        }
    } else if (status.compare(QLatin1String("hash_not_found"), Qt::CaseInsensitive) == 0 ||
               status.compare(QLatin1String("no_results"), Qt::CaseInsensitive) == 0) {
        rep.verdict = ReputationVerdict::Unknown; // authoritative negative (not "clean")
        rep.querySucceeded = true;
    }
    return rep;
}

std::pair<bool, QString> MalwareBazaarClient::doTest() {
    if (!enabled_) return { false, u("MalwareBazaar 未启用") };
    bucket_.wait();
    const QList<QPair<QString, QString>> form{
        { QStringLiteral("query"), QStringLiteral("get_info") },
        { QStringLiteral("hash"), kEicar } };
    const auto res = ReputationCurl::postForm(apiUrl_, form, { QStringLiteral("Auth-Key: ") + apiKey() }, timeoutSecs_);
    switch (res.first) {
        case 401: return { false, u("Auth-Key 无效或缺失(401)") };
        case 429: return { true, u("连接成功,但当前被限流(429)") };
        case 0:   return { false, u("连接失败(curl 不可用或网络不通)") };
        case 200: return { true, u("连接成功") };
        default:  return { false, u("返回异常状态:") + QString::number(res.first) };
    }
}

} // namespace bulwark::service::reputation

namespace bulwark::service::reputation {

// ---- OTX (AlienVault) -------------------------------------------------------
OtxClient::OtxClient(const BulwarkOptions& options)
    : ReputationClientBase(QStringLiteral("OTX"),
                           envOr(OtxOptions::ApiKeyEnvVar, options.Otx.ApiKey),
                           false, options.Otx.RequestsPerMinute,
                           options.Otx.RequestsPerDay, options.Otx.QueryTimeoutSeconds) {
    baseUrl_ = options.Otx.BaseUrl;
    maliciousPulseThreshold_ = options.Otx.MaliciousPulseThreshold;
    enabled_ = options.Otx.Enabled && !apiKey_.isEmpty();
}

FileReputation OtxClient::doQuery(const QString& sha256) {
    FileReputation unknown = unknownRep(sha256);
    const QStringList headers{ QStringLiteral("X-OTX-API-KEY: ") + apiKey() };
    const auto res = ReputationCurl::get(baseUrl_ + sha256 + QStringLiteral("/general"), headers, timeoutSecs_);
    const int code = res.first;
    if (code == 404) { FileReputation r = unknownRep(sha256); r.querySucceeded = true; return r; }
    if (code == 401 || code == 403) { log_.warning(u("OTX 鉴权失败")); return unknown; }
    if (code == 429) { log_.warning(u("OTX 触发限流(429)")); return unknown; }
    if (code != 200) return unknown;
    return parse(sha256, res.second);
}

FileReputation OtxClient::parse(const QString& sha256, const QString& json) const {
    FileReputation rep = unknownRep(sha256);
    const QJsonObject root = parseObj(json);
    int pulseCount = 0;
    const QJsonObject pi = root.value(QLatin1String("pulse_info")).toObject();
    if (!pi.isEmpty()) {
        pulseCount = jInt(pi, "count");
        const QJsonArray pulses = pi.value(QLatin1String("pulses")).toArray();
        if (!pulses.isEmpty() && pulses.first().isObject()) {
            const QString nm = pulses.first().toObject().value(QLatin1String("name")).toString();
            if (!nm.isEmpty()) rep.threatLabel = nm;
        }
    }
    rep.malicious = pulseCount;
    rep.totalEngines = pulseCount;
    if (pulseCount >= maliciousPulseThreshold_) rep.verdict = ReputationVerdict::Malicious;
    else if (pulseCount >= 1) rep.verdict = ReputationVerdict::Suspicious;
    else rep.verdict = ReputationVerdict::Clean;
    rep.querySucceeded = true;
    return rep;
}

std::pair<bool, QString> OtxClient::doTest() {
    if (apiKey_.isEmpty()) return { false, u("未配置 OTX API 密钥(环境变量 BULWARK_OTX_APIKEY)") };
    bucket_.wait();
    const auto res = ReputationCurl::get(baseUrl_ + kEicar + QStringLiteral("/general"),
                                         { QStringLiteral("X-OTX-API-KEY: ") + apiKey() }, timeoutSecs_);
    switch (res.first) {
        case 200: return { true, u("连接成功,API 密钥有效") };
        case 404: return { true, u("连接成功(测试样本无记录,密钥有效)") };
        case 401: return { false, u("API 密钥无效(401)") };
        case 403: return { false, u("API 密钥无权限(403)") };
        case 429: return { true, u("密钥有效,但当前已触发限流(429)") };
        case 0:   return { false, u("连接失败(curl 不可用或网络不通)") };
        default:  return { false, u("返回异常状态:") + QString::number(res.first) };
    }
}

} // namespace bulwark::service::reputation

namespace bulwark::service::reputation {

// ---- MetaDefender Cloud (OPSWAT) --------------------------------------------
MetaDefenderClient::MetaDefenderClient(const BulwarkOptions& options)
    : ReputationClientBase(QStringLiteral("MetaDefender"),
                           envOr(MetaDefenderOptions::ApiKeyEnvVar, options.MetaDefender.ApiKey),
                           false, options.MetaDefender.RequestsPerMinute,
                           options.MetaDefender.RequestsPerDay, options.MetaDefender.QueryTimeoutSeconds) {
    baseUrl_ = options.MetaDefender.BaseUrl;
    maliciousThreshold_ = options.MetaDefender.MaliciousThreshold;
    enabled_ = !apiKey_.isEmpty();
}

FileReputation MetaDefenderClient::doQuery(const QString& sha256) {
    FileReputation unknown = unknownRep(sha256);
    const auto res = ReputationCurl::get(baseUrl_ + sha256, { QStringLiteral("apikey: ") + apiKey() }, timeoutSecs_);
    const int code = res.first;
    if (code == 404) { FileReputation r = unknownRep(sha256); r.querySucceeded = true; return r; }
    if (code == 401 || code == 403) { log_.warning(u("MetaDefender 鉴权失败")); return unknown; }
    if (code == 429) { log_.warning(u("MetaDefender 触发限流(429)")); return unknown; }
    if (code != 200) return unknown;
    return parse(sha256, res.second);
}

FileReputation MetaDefenderClient::parse(const QString& sha256, const QString& body) const {
    FileReputation rep = unknownRep(sha256);
    const QJsonObject root = parseObj(body);
    if (root.contains(QLatin1String("error"))) { rep.querySucceeded = true; return rep; } // not indexed
    const QJsonObject sr = root.value(QLatin1String("scan_results")).toObject();
    const int detected = jInt(sr, "total_detected_avs");
    const int total = jInt(sr, "total_avs");
    rep.malicious = detected;
    rep.totalEngines = total;
    const QString tn = root.value(QLatin1String("threat_name")).toString();
    if (!tn.isEmpty()) rep.threatLabel = tn;
    else {
        const QString ra = sr.value(QLatin1String("scan_all_result_a")).toString();
        if (!ra.isEmpty()) rep.threatLabel = ra;
    }
    if (detected >= maliciousThreshold_) rep.verdict = ReputationVerdict::Malicious;
    else if (detected >= 1) rep.verdict = ReputationVerdict::Suspicious;
    else rep.verdict = ReputationVerdict::Clean;
    rep.querySucceeded = true;
    return rep;
}

std::pair<bool, QString> MetaDefenderClient::doTest() {
    if (apiKey_.isEmpty()) return { false, u("服务端未配置 MetaDefender API 密钥(环境变量 BULWARK_MDC_APIKEY)") };
    bucket_.wait();
    const auto res = ReputationCurl::get(baseUrl_ + kEicar, { QStringLiteral("apikey: ") + apiKey() }, timeoutSecs_);
    switch (res.first) {
        case 200: return { true, u("连接成功,API 密钥有效") };
        case 404: return { true, u("连接成功(测试样本未收录,密钥有效)") };
        case 401: return { false, u("API 密钥无效(401)") };
        case 403: return { false, u("API 密钥无权限(403)") };
        case 429: return { true, u("密钥有效,但当前已触发限流(429)") };
        case 0:   return { false, u("连接失败(curl 不可用或网络不通)") };
        default:  return { false, u("返回异常状态:") + QString::number(res.first) };
    }
}

// ---- Hybrid Analysis (Falcon Sandbox) ---------------------------------------
HybridAnalysisClient::HybridAnalysisClient(const BulwarkOptions& options)
    : ReputationClientBase(QStringLiteral("HybridAnalysis"),
                           envOr(HybridAnalysisOptions::ApiKeyEnvVar, options.HybridAnalysis.ApiKey),
                           false, options.HybridAnalysis.RequestsPerMinute,
                           options.HybridAnalysis.RequestsPerDay, options.HybridAnalysis.QueryTimeoutSeconds) {
    baseUrl_ = options.HybridAnalysis.BaseUrl;
    maliciousThreatScore_ = options.HybridAnalysis.MaliciousThreatScore;
    enabled_ = !apiKey_.isEmpty();
}

FileReputation HybridAnalysisClient::doQuery(const QString& sha256) {
    FileReputation unknown = unknownRep(sha256);
    const QStringList headers{ QStringLiteral("User-Agent: Falcon Sandbox"), QStringLiteral("api-key: ") + apiKey() };
    const auto res = ReputationCurl::get(baseUrl_ + sha256, headers, timeoutSecs_);
    const int code = res.first;
    if (code == 404) { FileReputation r = unknownRep(sha256); r.querySucceeded = true; return r; }
    if (code == 401 || code == 403) { log_.warning(u("Hybrid Analysis 鉴权失败")); return unknown; }
    if (code == 429) { log_.warning(u("Hybrid Analysis 触发限流(429)")); return unknown; }
    if (code != 200) return unknown;
    return parse(sha256, res.second);
}

FileReputation HybridAnalysisClient::parse(const QString& sha256, const QString& body) const {
    FileReputation rep = unknownRep(sha256);
    const QJsonObject root = parseObj(body);
    const int threatScore = jInt(root, "threat_score");
    const int multiscan = jInt(root, "multiscan_result");
    const QString verdict = root.value(QLatin1String("verdict")).toString().trimmed().toLower();
    const QString vxFamily = root.value(QLatin1String("vx_family")).toString();
    rep.malicious = multiscan;
    rep.totalEngines = 0;
    if (!vxFamily.trimmed().isEmpty()) rep.threatLabel = vxFamily;
    if (verdict == QLatin1String("malicious")) rep.verdict = ReputationVerdict::Malicious;
    else if (verdict == QLatin1String("suspicious")) rep.verdict = ReputationVerdict::Suspicious;
    else if (verdict == QLatin1String("whitelisted") || verdict == QLatin1String("no specific threat"))
        rep.verdict = ReputationVerdict::Clean;
    else if (threatScore >= maliciousThreatScore_) rep.verdict = ReputationVerdict::Malicious;
    else if (threatScore > 0) rep.verdict = ReputationVerdict::Suspicious;
    else rep.verdict = ReputationVerdict::Clean;
    rep.querySucceeded = true;
    return rep;
}

bulwark::ThreatBehaviorProfile HybridAnalysisClient::fetchBehaviorProfile(const QString& sha256) {
    bulwark::ThreatBehaviorProfile prof;
    prof.sha256 = sha256;
    prof.source = name();
    if (!enabled_ || sha256.isEmpty())
        return prof;
    bucket_.wait();
    const QStringList headers{ QStringLiteral("User-Agent: Falcon Sandbox"),
                               QStringLiteral("api-key: ") + apiKey() };
    const auto res = ReputationCurl::get(baseUrl_ + sha256, headers, timeoutSecs_);
    if (res.first != 200)
        return prof; // 404(未收录)/ 401 / 429 等一律 fail-open
    const QJsonObject root = parseObj(res.second);
    if (root.isEmpty())
        return prof;

    QSet<QString> ipSet, domSet;
    // overview 的 hosts / compromised_hosts / domains 可能是字符串数组,或对象数组(取 address/domain)。
    auto collect = [&](const char* key, QSet<QString>& dst, bool lower) {
        const QJsonArray a = root.value(QLatin1String(key)).toArray();
        for (const QJsonValue& v : a) {
            QString s;
            if (v.isString()) {
                s = v.toString();
            } else if (v.isObject()) {
                const QJsonObject o = v.toObject();
                s = o.value(QLatin1String("address")).toString();
                if (s.isEmpty()) s = o.value(QLatin1String("domain")).toString();
                if (s.isEmpty()) s = o.value(QLatin1String("host")).toString();
            }
            s = s.trimmed();
            if (lower) s = s.toLower();
            if (!s.isEmpty() && dst.size() < 100) dst.insert(s);
        }
    };
    collect("hosts", ipSet, false);
    collect("compromised_hosts", ipSet, false);
    collect("domains", domSet, true);

    prof.contactedIps = QStringList(ipSet.begin(), ipSet.end());
    prof.contactedDomains = QStringList(domSet.begin(), domSet.end());
    prof.fetched = true; // 请求成功即视为已取(即便无网络 IOC,聚合器对空画像自会跳过)
    return prof;
}

std::pair<bool, QString> HybridAnalysisClient::doTest() {
    if (apiKey_.isEmpty()) return { false, u("服务端未配置 Hybrid Analysis API 密钥(环境变量 BULWARK_HA_APIKEY)") };
    bucket_.wait();
    const QStringList headers{ QStringLiteral("User-Agent: Falcon Sandbox"), QStringLiteral("api-key: ") + apiKey() };
    const auto res = ReputationCurl::get(baseUrl_ + kEicar, headers, timeoutSecs_);
    switch (res.first) {
        case 200: return { true, u("连接成功,API 密钥有效") };
        case 404: return { true, u("连接成功(测试样本未收录,密钥有效)") };
        case 401: return { false, u("API 密钥无效(401)") };
        case 403: return { false, u("API 密钥无权限或缺少 User-Agent(403)") };
        case 429: return { true, u("密钥有效,但当前已触发限流(429)") };
        case 0:   return { false, u("连接失败(curl 不可用或网络不通)") };
        default:  return { false, u("返回异常状态:") + QString::number(res.first) };
    }
}

} // namespace bulwark::service::reputation
