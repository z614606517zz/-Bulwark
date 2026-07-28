#include "bulwark/service/reputation/ProxyReputationService.h"
#include "bulwark/service/reputation/ReputationCurl.h"
#include "bulwark/models/Enums.h"

#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QLatin1String>

#include <thread>

namespace bulwark::service::reputation {
namespace {

bulwark::ReputationVerdict parseVerdict(const QString& v) {
    const QString s = v.trimmed().toLower();
    if (s == QLatin1String("malicious"))  return bulwark::ReputationVerdict::Malicious;
    if (s == QLatin1String("suspicious")) return bulwark::ReputationVerdict::Suspicious;
    if (s == QLatin1String("clean"))      return bulwark::ReputationVerdict::Clean;
    return bulwark::ReputationVerdict::Unknown;
}

// 熔断冷却:代理被判离线后,多久才再放一个请求过去试探(半开)。
constexpr qint64 kBreakerCooldownMs = 60000;

// Minimal JSON string escaping for the sha256 payload (hex only in practice,
// but keep it correct if ever fed something odd).
QString jsonEscape(const QString& s) {
    QString out;
    out.reserve(s.size() + 2);
    for (const QChar c : s) {
        if (c == QLatin1Char('"') || c == QLatin1Char('\\'))
            out.append(QLatin1Char('\\'));
        out.append(c);
    }
    return out;
}

} // namespace

ProxyReputationService::ProxyReputationService(const BulwarkOptions& options,
                                               IHashReputationService* fallback)
    : fallback_(fallback), timeoutSecs_(8) {
    // Endpoint resolution is centralised in options: env var > plaintext BaseUrl >
    // deobfuscated BaseUrlObfuscated. Shipped/portable configs carry only the obfuscated
    // form, so the URL never sits in plaintext on disk.
    baseUrl_ = options.ReputationProxy.resolveBaseUrl().trimmed();
    while (baseUrl_.endsWith(QLatin1Char('/')))
        baseUrl_.chop(1);
    maskedUrl_ = ReputationProxyOptions::maskUrl(baseUrl_);
    token_ = options.ReputationProxy.resolveToken();
    if (options.ReputationProxy.QueryTimeoutSeconds > 0)
        timeoutSecs_ = options.ReputationProxy.QueryTimeoutSeconds;
    enabled_.store(options.ReputationProxy.Enabled && !baseUrl_.isEmpty());
    // Optional per-day cap on fresh (non-cached) server-intel lookups (portable builds).
    const int dailyFresh = options.ReputationProxy.FreshQueriesPerDay;
    if (dailyFresh > 0)
        freshBudget_ = std::make_unique<DailyQuota>(dailyFresh);
    ReputationCurl::diag(QStringLiteral("RepProxy init: enabled=%1 base=%2 token=%3 freshCap=%4")
                             .arg(enabled_.load() ? QStringLiteral("1") : QStringLiteral("0"),
                                  maskedUrl_,
                                  token_.isEmpty() ? QStringLiteral("(none)") : QStringLiteral("set"),
                                  dailyFresh > 0 ? QString::number(dailyFresh) : QStringLiteral("off")));
}

bool ProxyReputationService::isEnabled() const {
    // Enabled if the proxy is usable OR the fallback aggregate has any active source.
    return enabled_.load() || (fallback_ && fallback_->isEnabled());
}

bulwark::FileReputation ProxyReputationService::query(const QString& sha256) {
    return query(sha256, false);
}

bulwark::FileReputation ProxyReputationService::query(const QString& sha256, bool priority) {
    bulwark::FileReputation unknown;
    unknown.sha256 = sha256;
    if (sha256.isEmpty())
        return unknown;

    // Proxy first: shared server-side cache + server-held API keys. Only an
    // authoritative success short-circuits; everything else falls back so we
    // never return a weaker answer than the direct aggregate would.
    // 熔断守卫:代理已知离线时跳过这一跳,避免每次查询都白等一次超时(见 proxyLikelyUp)。
    if (enabled_.load() && proxyLikelyUp()) {
        // 每日「新鲜查询」预算(便携包 opt-in)。预算内:允许服务端触达上游情报(cacheOnly=false),
        // 若结果确为新鲜(未命中服务端共享缓存)才真正扣一个名额;命中缓存则退还(缓存查询不限)。
        // 预算耗尽:改发 cacheOnly=true,只接受服务端缓存命中(仍不限),未命中则回退本地情报源。
        bool reserved = false;
        bool cacheOnly = false;
        if (freshBudget_) {
            reserved = freshBudget_->tryConsume(priority);
            cacheOnly = !reserved; // 预算耗尽 -> 只查服务端已保存的缓存
        }

        bool ok = false;
        bool wasCached = false;
        bulwark::FileReputation rep = queryProxy(sha256, cacheOnly, &ok, &wasCached);

        if (freshBudget_ && reserved && (!ok || wasCached)) {
            // 预占了名额,但服务端未真正做新鲜的上游查询(命中共享缓存,或本次请求失败/未解析):
            // 退还名额,确保「直接查询服务器已保存的」不消耗每日新鲜配额。
            freshBudget_->release();
        }

        if (ok && rep.querySucceeded) {
            // cacheOnly 模式下只信任服务端缓存命中:若服务端仍回了新鲜结果(忽略了 cacheOnly),
            // 不越过预算采用它,转而回退本地——严格贯彻「配额用尽后仅用服务端缓存」。
            if (!cacheOnly || wasCached)
                return rep;
        }
    }

    // Fallback: direct per-source aggregate (full coverage; never regress when
    // the proxy is down / disabled / could not resolve the hash).
    if (fallback_)
        return fallback_->query(sha256, priority);
    return unknown;
}

bool ProxyReputationService::proxyLikelyUp() {
    if (health_->state.load() != 0)
        return true; // 在线(1)或尚未探测(-1):照常先走代理
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (now - health_->atMs.load() < kBreakerCooldownMs)
        return false; // 冷却期内:直接走本地直连,不为每次查询白等超时
    // 冷却到期 -> 半开:先把时间戳推到现在,这样并发的其余调用仍走本地,只有这一个去试探。
    health_->atMs.store(now);
    return true;
}

bulwark::FileReputation ProxyReputationService::queryProxy(const QString& sha256, bool cacheOnly,
                                                           bool* ok, bool* wasCached) {
    if (ok) *ok = false;
    if (wasCached) *wasCached = false;
    bulwark::FileReputation rep;
    rep.sha256 = sha256;
    rep.verdict = bulwark::ReputationVerdict::Unknown;

    const QString url = baseUrl_ + QStringLiteral("/v1/reputation/hash");
    // cacheOnly 让配合的服务端仅从共享缓存作答、绝不动用付费上游;不认识该字段的服务端会忽略它
    // (无害),客户端侧仍据回包的 cached 标记独立记账/回退,故限额不依赖服务端配合也成立。
    const QString body = QStringLiteral("{\"sha256\":\"") + jsonEscape(sha256) +
                         QStringLiteral("\",\"cacheOnly\":") +
                         (cacheOnly ? QStringLiteral("true") : QStringLiteral("false")) +
                         QStringLiteral("}");
    QStringList headers{ QStringLiteral("Content-Type: application/json") };
    if (cacheOnly)
        headers << QStringLiteral("X-Cache-Only: 1"); // 冗余提示,便于纯 header 型服务端识别
    if (!token_.isEmpty())
        headers << (QStringLiteral("Authorization: Bearer ") + token_);

    const auto res = ReputationCurl::postRaw(url, body, headers, timeoutSecs_);
    // 真实查询本身就是最好的存活探针:据结果刷新熔断状态(也让 UI 状态灯免于额外一次 /health)。
    health_->state.store(res.first == 200 ? 1 : 0);
    health_->atMs.store(QDateTime::currentMSecsSinceEpoch());
    if (res.first != 200) {
        ReputationCurl::diag(QStringLiteral("RepProxy %1 => HTTP %2 (fallback)")
                                 .arg(sha256.left(12)).arg(res.first));
        return rep; // *ok stays false -> caller falls back to the direct aggregate
    }

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(res.second.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        ReputationCurl::diag(QStringLiteral("RepProxy %1 => bad JSON (fallback)").arg(sha256.left(12)));
        return rep;
    }
    const QJsonObject o = doc.object();

    rep.verdict      = parseVerdict(o.value(QLatin1String("verdict")).toString());
    rep.malicious    = o.value(QLatin1String("malicious")).toInt();
    rep.totalEngines = o.value(QLatin1String("totalEngines")).toInt();
    rep.threatLabel  = o.value(QLatin1String("threatLabel")).toString();
    const QString src = o.value(QLatin1String("source")).toString();
    rep.source       = src.isEmpty() ? QStringLiteral("Proxy") : (QStringLiteral("Proxy:") + src);
    rep.querySucceeded = o.value(QLatin1String("querySucceeded")).toBool();
    rep.fetchedUtc   = QDateTime::currentDateTimeUtc();

    const bool cached = o.value(QLatin1String("cached")).toBool();
    if (wasCached) *wasCached = cached;

    if (ok) *ok = true;
    ReputationCurl::diag(QStringLiteral("RepProxy %1 => v%2 (%3/%4) src=%5 cacheOnly=%6 cached=%7 ok=%8")
                             .arg(sha256.left(12))
                             .arg(static_cast<int>(rep.verdict))
                             .arg(rep.malicious).arg(rep.totalEngines)
                             .arg(src.isEmpty() ? QStringLiteral("-") : src)
                             .arg(cacheOnly ? 1 : 0)
                             .arg(cached ? 1 : 0)
                             .arg(rep.querySucceeded ? 1 : 0));
    return rep;
}

std::pair<bool, QString> ProxyReputationService::testConnection() {
    if (!enabled_.load()) {
        if (fallback_) return fallback_->testConnection();
        return { false, QString::fromUtf8("信誉代理未启用") };
    }
    const auto res = ReputationCurl::get(baseUrl_ + QStringLiteral("/health"), {}, timeoutSecs_);
    if (res.first == 0)
        return { false, QString::fromUtf8("连接失败(curl 不可用或网络不通)") };
    if (res.first != 200)
        return { false, QString::fromUtf8("代理返回异常状态:") + QString::number(res.first) };
    return { true, QString::fromUtf8("信誉代理连接成功") };
}

std::pair<bool, QString> ProxyReputationService::healthCheckNonBlocking() {
    // No central proxy configured -> report the direct aggregate's connectivity
    // instead (there is nothing to be "offline"); keeps the UI pill meaningful.
    if (!enabled_.load()) {
        if (fallback_) return fallback_->testConnection();
        return { false, QString::fromUtf8("信誉代理未启用") };
    }

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    constexpr qint64 kFreshMs = 12000; // serve cached within 12s; never touch the network inline

    // Kick a background probe when we have no reading yet or the cache is stale.
    // It runs detached so the caller (service main thread / IPC handler) never
    // blocks on curl (which has a hard 5s --max-time floor).
    if (health_->state.load() == -1 || (now - health_->atMs.load()) >= kFreshMs) {
        bool expected = false;
        if (health_->probing.compare_exchange_strong(expected, true)) {
            // 只按值捕获「共享状态 + URL + 超时」,绝不捕获 this:这个线程是 detach 的,可能比
            // 本对象活得久(停机时正好在途),捕获 this 就等于 use-after-free。
            auto health = health_;
            const QString url = baseUrl_ + QStringLiteral("/health");
            const int timeout = timeoutSecs_;
            std::thread([health, url, timeout] {
                const auto res = ReputationCurl::get(url, {}, timeout);
                health->state.store(res.first == 200 ? 1 : 0);
                health->atMs.store(QDateTime::currentMSecsSinceEpoch());
                health->probing.store(false);
                ReputationCurl::diag(QStringLiteral("RepProxy health => HTTP %1 (%2)")
                                         .arg(res.first)
                                         .arg(res.first == 200 ? QStringLiteral("online")
                                                               : QStringLiteral("offline")));
            }).detach();
        }
    }

    // Return the best-known reading immediately (stale-while-revalidate).
    switch (health_->state.load()) {
        case 1:  return { true,  QString::fromUtf8("信誉服务在线") };
        case 0:  return { false, QString::fromUtf8("信誉服务离线(已回退本地直连)") };
        default: return { false, QString::fromUtf8("信誉服务检测中…") };
    }
}

bulwark::ReputationUsage ProxyReputationService::getUsage() {
    bulwark::ReputationUsage u;
    u.source = name();
    u.enabled = enabled_.load();
    if (freshBudget_) {
        const auto snap = freshBudget_->snapshot(); // {今日已用新鲜查询, 每日上限}
        u.usedToday = snap.first;
        u.dailyLimit = snap.second;
    }
    return u;
}

bulwark::ThreatBehaviorProfile ProxyReputationService::fetchBehaviorProfile(const QString& sha256) {
    if (fallback_)
        return fallback_->fetchBehaviorProfile(sha256);
    return {};
}

} // namespace bulwark::service::reputation
