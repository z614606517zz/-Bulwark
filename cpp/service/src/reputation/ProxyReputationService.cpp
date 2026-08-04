#include "bulwark/service/reputation/ProxyReputationService.h"
#include "bulwark/service/reputation/ReputationCurl.h"
#include "bulwark/service/Logger.h" // programDataDir()
#include "bulwark/models/Enums.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QLatin1String>
#include <QUuid>

#include <algorithm>
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

// parseVerdict 的逆向:回传结论时用的线上词表(与服务器 /v1/reputation/hash 的取值一致)。
QString verdictToWire(bulwark::ReputationVerdict v) {
    switch (v) {
        case bulwark::ReputationVerdict::Malicious:  return QStringLiteral("malicious");
        case bulwark::ReputationVerdict::Suspicious: return QStringLiteral("suspicious");
        case bulwark::ReputationVerdict::Clean:      return QStringLiteral("clean");
        default:                                     return QStringLiteral("unknown");
    }
}

// 熔断冷却:代理被判「传输层不可达」后,多久才再放一个请求过去试探(半开)。
constexpr qint64 kBreakerCooldownMs = 60000;

// 判「离线」所需的连续传输层失败次数。1 次就翻牌太敏感:curl 是每次请求起一个进程,一次
// DNS/TLS 抽风或进程没起来就会让状态灯红一下,用户看到的就是「老是断链」。
constexpr int kOfflineFailStreak = 2;

// 服务端没给 retry_after_seconds 时的默认限流冷却,以及冷却上限(封一小时也不必等满一小时
// 才敢试 —— 上限内周期性试探一次,恢复得更快,代价只有极少量请求)。
constexpr qint64 kThrottleDefaultCooldownMs = 60LL * 1000;
constexpr qint64 kThrottleMaxCooldownMs     = 10LL * 60 * 1000;

// 从 429 回包里取 retry_after_seconds(服务端 IPThrottle 会给 60 或 3600)。
// 解析不出来就用默认冷却;无论如何都夹在 [1s, kThrottleMaxCooldownMs]。
qint64 parseRetryAfterMs(const QString& body) {
    if (body.trimmed().isEmpty())
        return kThrottleDefaultCooldownMs;
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return kThrottleDefaultCooldownMs;
    const QJsonValue v = doc.object().value(QLatin1String("retry_after_seconds"));
    if (!v.isDouble())
        return kThrottleDefaultCooldownMs;
    const qint64 ms = static_cast<qint64>(v.toDouble() * 1000.0);
    return ms > 0 ? ms : kThrottleDefaultCooldownMs;
}

// 服务器到底「有没有收录」这个哈希 —— 这是回退本地的判据,不能只看 verdict。
//
// 实测(向 /v1/reputation/hash 提交一个随机的、从未存在过的哈希):
//   {"verdict":"clean","malicious":0,"totalEngines":0,"source":"OTX","querySucceeded":true}
// 服务器把「OTX 没有该哈希的情报」当成了 clean 回来,而不是 unknown。对照真实收录:
//   EICAR      -> {"verdict":"malicious","malicious":64,"totalEngines":67,"source":"VirusTotal"}
//   Setup.exe  -> {"verdict":"malicious","malicious":31,"totalEngines":69,"source":"VirusTotal"}
// 差别在 totalEngines:真有引擎分析过才 > 0。
//
// 所以判定规则:
//   · Malicious / Suspicious      -> 算收录。哈希黑名单类源(MalwareBazaar / ThreatFox)本来
//                                    就没有 engine 计数,拿 totalEngines 卡会把真命中当成没收录。
//   · totalEngines > 0            -> 算收录(确有引擎结论,clean 也作数)。
//   · 其余(clean/unknown + 0 引擎)-> 不算收录:这只是「没有任何源有数据」披了件 clean 的外衣。
bool serverHasRecord(const bulwark::FileReputation& rep) {
    if (rep.verdict == bulwark::ReputationVerdict::Malicious ||
        rep.verdict == bulwark::ReputationVerdict::Suspicious)
        return true;
    return rep.totalEngines > 0;
}

// 把「服务器没实据」的回复降级成 Unknown 再返回。
//
// 为什么不能原样返回:那条回复是 verdict=clean,ReputationCache 会按 CleanCacheTtlDays(7 天)
// 缓存它,于是「谁都没有数据」变成了一条 7 天有效的「此文件干净」——正是要堵的漏。降级成
// Unknown 后:① 按 UnknownCacheTtlHours(24h)缓存,更快重试;② ReputationCache 的兜底读取
// 明确拒绝用 Unknown 作结论(无信息不兜底),不会被误当成安全凭据。
// 仍保留 querySucceeded=true,这样它照样能进缓存,避免同一哈希每次事件重跑整条查询链。
bulwark::FileReputation downgradeToUnknown(const bulwark::FileReputation& rep) {
    bulwark::FileReputation out = rep;
    out.verdict = bulwark::ReputationVerdict::Unknown;
    out.malicious = 0;
    out.totalEngines = 0;
    out.threatLabel.clear();
    return out;
}

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

// 稳定的匿名机器 ID —— 只发给本项目自己的中央代理(绝不发给 VirusTotal 等第三方情报源),
// 让服务器按「机器」而非「NAT 共享出口 IP」去重在线客户端。它就是一枚随机 UUID,首次生成后
// 持久化到 %ProgramData%\Bulwark\client-id.txt;不含任何硬件/用户标识,删掉文件即换新 ID。
// 函数内静态局部量,C++11 起初始化线程安全,进程内只算一次。
QString clientId() {
    static const QString id = []() -> QString {
        const QString path = QDir(bulwark::service::programDataDir())
                                 .filePath(QStringLiteral("client-id.txt"));
        QFile f(path);
        if (f.open(QIODevice::ReadOnly)) {
            const QString existing = QString::fromUtf8(f.readAll()).trimmed();
            f.close();
            if (!existing.isEmpty())
                return existing;
        }
        const QString fresh = QUuid::createUuid().toString(QUuid::WithoutBraces);
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            f.write(fresh.toUtf8());
            f.close();
        }
        return fresh;
    }();
    return id;
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
    syncResults_ = options.ReputationProxy.SyncResultsToServer;
    enabled_.store(options.ReputationProxy.Enabled && !baseUrl_.isEmpty());
    // Optional per-day cap on fresh (non-cached) server-intel lookups (portable builds).
    const int dailyFresh = options.ReputationProxy.FreshQueriesPerDay;
    if (dailyFresh > 0)
        freshBudget_ = std::make_unique<DailyQuota>(dailyFresh);
    // 请求数预算,压在服务端 per-IP 滑窗之下(它超限就是一小时 429)。注意这与 freshBudget_
    // 是两回事:后者只管「服务端有没有真去问付费上游」,命中服务端共享缓存的查询不计数,
    // 却照样占掉一个 IP 名额 —— 所以光靠 freshBudget_ 挡不住请求数被打光。
    const int perMin = options.ReputationProxy.RequestsPerMinute;
    const int perHour = options.ReputationProxy.RequestsPerHour;
    if (perMin > 0)
        minuteBudget_ = std::make_unique<TokenBucket>(perMin, 60LL * 1000);
    if (perHour > 0)
        hourBudget_ = std::make_unique<TokenBucket>(perHour, 3600LL * 1000);
    ReputationCurl::diag(QStringLiteral("RepProxy init: enabled=%1 base=%2 token=%3 freshCap=%4 rate=%5/min %6/h")
                             .arg(enabled_.load() ? QStringLiteral("1") : QStringLiteral("0"),
                                  maskedUrl_,
                                  token_.isEmpty() ? QStringLiteral("(none)") : QStringLiteral("set"),
                                  dailyFresh > 0 ? QString::number(dailyFresh) : QStringLiteral("off"),
                                  perMin > 0 ? QString::number(perMin) : QStringLiteral("∞"),
                                  perHour > 0 ? QString::number(perHour) : QStringLiteral("∞")));
}

bool ProxyReputationService::isEnabled() const {
    // Enabled if the proxy is usable OR the fallback aggregate has any active source.
    return enabled_.load() || (fallback_ && fallback_->isEnabled());
}

bulwark::FileReputation ProxyReputationService::query(const QString& sha256) {
    return query(sha256, false);
}

// 只问服务器,不做任何本地回退。这是「服务器优先」策略的唯一实现:query() 与双击云扫描的
// 分级链路(Worker::runVtScan)都走它,避免两处各写一份而慢慢跑偏。
//   *answered  = 服务器给出了可采信的权威回复(HTTP 200 + JSON 可解析 + querySucceeded,
//                且在 cacheOnly 模式下确为服务端缓存命中);
//   *hasRecord = 在 answered 的基础上,服务器【确有实据】(见 serverHasRecord)。
bulwark::FileReputation ProxyReputationService::queryServerOnly(const QString& sha256, bool priority,
                                                                bool* hasRecord, bool* answered) {
    if (hasRecord) *hasRecord = false;
    if (answered)  *answered  = false;

    bulwark::FileReputation rep;
    rep.sha256 = sha256;
    rep.verdict = bulwark::ReputationVerdict::Unknown;
    if (sha256.isEmpty())
        return rep;
    // 熔断 / 限流冷却守卫:跳过这一跳,避免每次查询都白等一次超时(见 proxyLikelyUp)。
    if (!enabled_.load() || !proxyLikelyUp())
        return rep;

    // 请求数预算。服务端按【来源 IP】滑窗限流 /v1/reputation/hash(默认 60/min + 600/h),
    // 超限即 429 且 retry_after_seconds=3600 —— 一小时都别想用。后台信誉队列一旦集中排空
    // (未签名 + 本机首见的样本一批批来),几分钟就能把一小时的名额打光。所以自己先限住:
    // 预算用尽时安静地走本地直连,【不动存活状态】—— 服务器没毛病,是我们主动省着用。
    if (!tryConsumeRequestBudget(priority)) {
        ReputationCurl::diag(QStringLiteral("RepProxy %1 => 本机请求预算用尽(护住服务端 per-IP 限额),转本地直连")
                                 .arg(sha256.left(12)));
        return rep;
    }

    // 每日「新鲜查询」预算(便携包 opt-in)。预算内:允许服务端触达上游情报(cacheOnly=false),
    // 若结果确为新鲜(未命中服务端共享缓存)才真正扣一个名额;命中缓存则退还(缓存查询不限)。
    // 预算耗尽:改发 cacheOnly=true,只接受服务端缓存命中(仍不限),未命中则由调用方回退本地。
    bool reserved = false;
    bool cacheOnly = false;
    if (freshBudget_) {
        reserved = freshBudget_->tryConsume(priority);
        cacheOnly = !reserved; // 预算耗尽 -> 只查服务端已保存的缓存
    }

    bool ok = false;
    bool wasCached = false;
    rep = queryProxy(sha256, cacheOnly, &ok, &wasCached);

    if (freshBudget_ && reserved && (!ok || wasCached)) {
        // 预占了名额,但服务端未真正做新鲜的上游查询(命中共享缓存,或本次请求失败/未解析):
        // 退还名额,确保「直接查询服务器已保存的」不消耗每日新鲜配额。
        freshBudget_->release();
    }

    // cacheOnly 模式下只信任服务端缓存命中:若服务端仍回了新鲜结果(忽略了 cacheOnly),
    // 不越过预算采用它,转而让调用方回退本地——严格贯彻「配额用尽后仅用服务端缓存」。
    if (ok && rep.querySucceeded && (!cacheOnly || wasCached)) {
        if (answered)  *answered  = true;
        if (hasRecord) *hasRecord = serverHasRecord(rep);
    }
    return rep;
}

bulwark::FileReputation ProxyReputationService::query(const QString& sha256, bool priority) {
    bulwark::FileReputation unknown;
    unknown.sha256 = sha256;
    if (sha256.isEmpty())
        return unknown;

    // Proxy first: shared server-side cache + server-held API keys. Only an
    // authoritative success WITH AN ACTUAL RECORD short-circuits; everything else
    // (含服务器明确「未收录」)falls back so we never return a weaker answer than
    // the direct aggregate would.
    bool hasRecord = false;
    bool haveServerMiss = false; // 服务器权威作答但没有实据 -> 本地也答不出时仍要返回它
    // 服务器权威回答「未收录」时暂存该结论:本地若也给不出权威结论,仍要把它返回。
    // 理由见下方回退分支——负缓存只认 querySucceeded==true。
    const bulwark::FileReputation serverMiss =
        queryServerOnly(sha256, priority, &hasRecord, &haveServerMiss);

    // 【策略 1】服务器确实收录了该哈希 -> 就用它,不再动本地情报源配额。
    if (hasRecord)
        return serverMiss;
    // 【策略 2】服务器没有该哈希的任何实据(0 引擎的 clean / unknown)-> 不当作最终
    // 结论,继续查本地。服务端目前只聚合 VirusTotal + ThreatBook,本地直连还有
    // MalwareBazaar / OTX / MetaDefender / HybridAnalysis;服务器没有不等于这几家没有。
    if (haveServerMiss) {
        ReputationCurl::diag(
            QStringLiteral("RepProxy %1 => 未收录(v%2 %3/%4 src=%5),转本地直连查询")
                .arg(sha256.left(12))
                .arg(static_cast<int>(serverMiss.verdict))
                .arg(serverMiss.malicious).arg(serverMiss.totalEngines)
                .arg(serverMiss.source.isEmpty() ? QStringLiteral("-") : serverMiss.source));
    }

    // Fallback: direct per-source aggregate (full coverage; never regress when
    // the proxy is down / disabled / could not resolve the hash, or has no record).
    if (fallback_) {
        const bulwark::FileReputation local = fallback_->query(sha256, priority);
        // 本地拿到权威结论 -> 用本地的,它的覆盖面更广(六个源)。
        if (local.querySucceeded) {
            // 本地查到了、而服务器没有 -> 顺手回传,让整个机队共享这条结论(见 submitToServer)。
            maybeSyncToServer(local);
            return local;
        }
        // 本地也没能权威作答(全部源超时/限流/未配置):回退到服务器那条回复,但降级成 Unknown
        // 再返回(理由见 downgradeToUnknown)。不返回任何东西的话 querySucceeded==false,
        // ReputationCache::store 会拒绝缓存(仅缓存权威结果),于是同一个哈希每次事件都要把
        //「代理 + 六个本地源」重跑一遍。
        if (haveServerMiss)
            return downgradeToUnknown(serverMiss);
        return local;
    }
    if (haveServerMiss)
        return downgradeToUnknown(serverMiss);
    return unknown;
}

void ProxyReputationService::maybeSyncToServer(const bulwark::FileReputation& rep) {
    if (!enabled_.load() || !syncResults_)
        return;
    if (rep.sha256.size() != 64 || !rep.querySucceeded)
        return;
    // 只回传「确有实据」的结论。0 引擎的 clean 与 Unknown 只代表「谁都没数据」,把它灌进共享
    // 缓存等于让别的端点把「无人知晓」读成一条有效的「此文件干净」—— 正是 serverHasRecord /
    // downgradeToUnknown 一直在堵的那个漏,回传侧同样不能开这个口子。
    if (!serverHasRecord(rep))
        return;
    // 这台服务器不认回传接口(旧版本 / 已关闭):不再为每次扫描白发一次请求。
    if (health_->submitUnsupported.load())
        return;
    // 服务器已知离线:跳过。回传是「锦上添花」,不值得为它白等一次超时,也不做重试队列 ——
    // 结论已在本地分级缓存里;下次同哈希查询时若服务器仍无记录,会自然再触发一次回传。
    if (!proxyLikelyUp())
        return;

    const QString url = baseUrl_ + QStringLiteral("/v1/reputation/submit");
    const QString body = QStringLiteral("{\"sha256\":\"") + jsonEscape(rep.sha256.toLower())
                       + QStringLiteral("\",\"verdict\":\"") + verdictToWire(rep.verdict)
                       + QStringLiteral("\",\"malicious\":") + QString::number(rep.malicious)
                       + QStringLiteral(",\"totalEngines\":") + QString::number(rep.totalEngines)
                       + QStringLiteral(",\"threatLabel\":\"") + jsonEscape(rep.threatLabel)
                       + QStringLiteral("\",\"source\":\"") + jsonEscape(rep.source)
                       + QStringLiteral("\"}");
    QStringList headers{ QStringLiteral("Content-Type: application/json") };
    headers << (QStringLiteral("X-Bulwark-Client: ") + clientId()); // 匿名机器 ID,供服务器按机器去重
    if (!token_.isEmpty())
        headers << (QStringLiteral("Authorization: Bearer ") + token_);

    // 回传绝不能拖慢调用方(裁决富化 / 双击扫描都在等结论收尾):派一个 detached 线程去发。
    // 只按值捕获「URL + 负载 + 头 + 超时 + 健康状态共享指针」,绝不捕获 this —— 本对象是
    // serviceRun 栈上的局部量,detached 线程可能比它活得久(停机时正好在途),捕获 this 就是
    // use-after-free(healthCheckNonBlocking 里那个探测线程当年就踩过这个坑)。故所有前置
    // 判断都已在调用线程做完,线程体内只做纯粹的一次 HTTP + 写共享状态。
    auto health = health_;
    const int timeout = timeoutSecs_;
    const QString tag = rep.sha256.left(12);
    std::thread([health, url, body, headers, timeout, tag] {
        const auto res = ReputationCurl::postRaw(url, body, headers, timeout);
        // 存活判定只认传输层(HTTP 0 才是离线证据);收到任何状态码都说明服务器活着。这一点
        // 很关键 —— 若把 404 也记成离线,熔断会立刻打开,接下来的「服务器优先查询」全部跳过
        // 服务器:一个纯属锦上添花的回传把主链路给降级了。判定逻辑与查询侧共用 noteOutcome,
        // 免得两处各写一份而慢慢跑偏(那正是查询侧当年跑偏成「非 200 即离线」的原因)。
        noteOutcome(health, res.first, res.second);
        // 服务器明确不认这个接口 -> 记下来,后续不再尝试(直到进程重启)。
        if (res.first == 404 || res.first == 405 || res.first == 501)
            health->submitUnsupported.store(true);
        ReputationCurl::diag(QStringLiteral("RepProxy submit %1 => HTTP %2%3")
                                 .arg(tag).arg(res.first)
                                 .arg(res.first == 200 ? QString()
                                      : (res.first == 404 || res.first == 405 || res.first == 501)
                                            ? QStringLiteral(" (服务器未实现回传接口,后续不再尝试)")
                                            : QStringLiteral(" (忽略)")));
    }).detach();
}

bool ProxyReputationService::proxyLikelyUp() {
    const qint64 now = QDateTime::currentMSecsSinceEpoch();

    // 1) 服务端明确「限流中,retry_after_seconds 之后再来」:就等到那个时刻。
    //    以前不看这个值、一律 60s 就半开一次,于是对着一个 3600s 的封禁每分钟白敲一次门:
    //    既把自己刚恢复的名额又敲掉,又让状态灯每分钟被重新按回红色 —— 用户看到的正是
    //   「信誉服务反复断链」。等满冷却再试,期间全部走本地直连。
    if (health_->throttledUntilMs.load() > now)
        return false;

    // 2) 传输层不可达(HTTP 0 连续 kOfflineFailStreak 次):熔断冷却,到期放一个探子过去。
    if (health_->state.load() != 0)
        return true; // 在线(1)/ 限流已过期(2)/ 尚未探测(-1):照常先走代理
    if (now - health_->breakerAtMs.load() < kBreakerCooldownMs)
        return false; // 冷却期内:直接走本地直连,不为每次查询白等超时
    // 冷却到期 -> 半开:先把时间戳推到现在,这样并发的其余调用仍走本地,只有这一个去试探。
    // 注意推的是 breakerAtMs 而非 atMs —— 后者是 /health 探测缓存的时间戳,不能被熔断顶新,
    // 否则 UI 侧的 stale-while-revalidate 会一直以为「读数还新鲜」而不再探测。
    health_->breakerAtMs.store(now);
    return true;
}

bool ProxyReputationService::tryConsumeRequestBudget(bool priority) {
    // 两个桶都要过:分钟桶挡突发(后台队列会连着排空),小时桶挡长时间稳态超配。
    // 先问分钟桶:若小时桶没过,损失的是一枚分钟令牌(几秒就补回来),而反过来损失的是
    // 一枚小时令牌(要十几秒才补一枚,且小时预算才是被服务端封禁的那条线)。TokenBucket
    // 没有退还接口,所以用顺序把误差压到最便宜的那一边;方向上只会少用,绝不会多用。
    if (minuteBudget_ && !minuteBudget_->tryConsume(priority))
        return false;
    if (hourBudget_ && !hourBudget_->tryConsume(priority))
        return false;
    return true;
}

// 据一次代理请求的 HTTP 结果刷新存活/限流状态。
//
// 核心原则:【只有传输层失败(HTTP 0)才是「服务器离线」的证据】——收到任何状态码都说明
// 服务器活着。这条原则 maybeSyncToServer 里早就写明并遵守了,查询侧当年却漏了,直接写成
// `state = (code == 200)`,于是 429 / 400 / 404 全被记成「离线」:
//   · UI 状态灯翻红,熔断把代理关在门外;
//   · 而服务端的 per-IP 限流【不管 /health】,那条探测仍然回 200,30s 后状态灯又翻绿;
//   · 下一条哈希查询再撞 429 -> 又红。
// 于是状态灯在「在线/离线」之间无休止地来回跳 —— 这就是「信誉服务老是断链」的成因。
// 现在把「被限流」升为独立状态(2),既不谎称离线,也不假装一切正常。
void ProxyReputationService::noteOutcome(const std::shared_ptr<HealthCache>& health, int httpCode,
                                         const QString& body) {
    if (!health)
        return;
    const qint64 now = QDateTime::currentMSecsSinceEpoch();

    if (httpCode == 0) {
        // 传输层失败(curl 起不来 / DNS / TLS / 连不上 / 超时)。加一道滞回:连续几次才判离线。
        const int streak = health->transportFailStreak.fetch_add(1) + 1;
        if (streak >= kOfflineFailStreak) {
            health->state.store(0);
            health->breakerAtMs.store(now);
        }
        ReputationCurl::diag(QStringLiteral("RepProxy 传输层失败(连续 %1 次%2)")
                                 .arg(streak)
                                 .arg(streak >= kOfflineFailStreak ? QStringLiteral(",判为离线,熔断开启")
                                                                   : QStringLiteral(",尚未判离线")));
        return;
    }

    health->transportFailStreak.store(0); // 拿到状态码就说明链路是通的

    if (httpCode == 429) {
        // 服务端限流:服务器好得很,只是这个来源 IP 的滑窗满了。按它给的 retry_after_seconds
        // 冷却,期间走本地直连。这【不是断链】,状态灯要能区分出来。
        qint64 waitMs = parseRetryAfterMs(body);
        waitMs = std::max<qint64>(1000, std::min<qint64>(waitMs, kThrottleMaxCooldownMs));
        health->throttledUntilMs.store(now + waitMs);
        health->state.store(2);
        ReputationCurl::diag(QStringLiteral("RepProxy 被服务端限流(429),冷却 %1s 后再试;期间走本地直连")
                                 .arg(waitMs / 1000));
        return;
    }

    // 其余任何状态码(200 / 其他 4xx / 5xx)都证明服务器在线。非 200 只影响这一次查询的结果
    // (调用方回退本地),不该改变存活判定 —— 尤其别再让一个 404 把主链路熔断掉。
    health->state.store(1);
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
    headers << (QStringLiteral("X-Bulwark-Client: ") + clientId()); // 匿名机器 ID,供服务器按机器去重
    if (cacheOnly)
        headers << QStringLiteral("X-Cache-Only: 1"); // 冗余提示,便于纯 header 型服务端识别
    if (!token_.isEmpty())
        headers << (QStringLiteral("Authorization: Bearer ") + token_);

    const auto res = ReputationCurl::postRaw(url, body, headers, timeoutSecs_);
    // 真实查询本身就是最好的存活探针:据结果刷新存活/限流状态。注意它【不写 atMs】——
    // atMs 只属于 /health 探测缓存,查询侧去顶新它会把 UI 的重新探测饿死(见 HealthCache)。
    noteOutcome(health_, res.first, res.second);
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
                // probing 必须无条件复位:早先是在函数体最后才 store(false),中途抛异常
                // (QString 分配失败等)就永远卡在 true,之后再也不会有探测,状态灯冻在原样。
                struct ProbeGuard {
                    std::shared_ptr<HealthCache> h;
                    ~ProbeGuard() { if (h) h->probing.store(false); }
                } guard{ health };

                const auto res = ReputationCurl::get(url, {}, timeout);
                const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
                const bool throttled = health->throttledUntilMs.load() > nowMs;
                if (res.first == 200) {
                    health->transportFailStreak.store(0);
                    // 【关键】/health 不受服务端 per-IP 限流管辖,所以它回 200 并不代表限流解除。
                    // 冷却仍在期内就保持「限流中」,别把状态灯翻回全绿 —— 过去正是
                    //「查询 429 -> 红,健康 200 -> 绿」这一对相反信号在互相打架,肉眼看就是断链。
                    health->state.store(throttled ? 2 : 1);
                } else if (res.first == 0) {
                    if (health->transportFailStreak.fetch_add(1) + 1 >= kOfflineFailStreak) {
                        health->state.store(0);
                        health->breakerAtMs.store(nowMs);
                    }
                } else {
                    // /health 明确回了非 200:这是服务端自述不健康,如实记为离线。
                    health->state.store(0);
                    health->breakerAtMs.store(nowMs);
                }
                health->atMs.store(nowMs);
                ReputationCurl::diag(QStringLiteral("RepProxy health => HTTP %1 (%2)")
                                         .arg(res.first)
                                         .arg(health->state.load() == 1 ? QStringLiteral("online")
                                              : health->state.load() == 2 ? QStringLiteral("throttled")
                                                                          : QStringLiteral("offline")));
            }).detach();
        }
    }

    // Return the best-known reading immediately (stale-while-revalidate).
    switch (health_->state.load()) {
        case 1:  return { true,  QString::fromUtf8("信誉服务在线") };
        // 限流不是断链:链路正常,只是本机所在出口 IP 的服务端配额暂时用满了,本地直连情报
        // 照常兜底。success=true 让 UI 不再报「离线」,消息里带「限流」供其显示为区分色。
        case 2:  return { true,  QString::fromUtf8("信誉服务限流中(服务端配额已满,暂用本地情报)") };
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
