#pragma once
#include "bulwark/service/reputation/IHashReputationService.h"
#include "bulwark/service/reputation/RateLimiting.h"
#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/models/FileReputation.h"

#include <QString>
#include <atomic>
#include <memory>
#include <utility>

// Proxy-first decorator over the direct per-source aggregate.
//
// When the central reputation proxy is configured + enabled, file-hash lookups
// hit it FIRST: one shared server-side cache (any endpoint that already asked
// for a hash serves it back instantly) with the upstream API keys held
// server-side for the whole fleet.
//
// 查询策略(先问服务器有没有收录,没收录才查本地):
//   1. 服务器【确实收录】该哈希 -> 直接采用,不消耗任何本地源配额;
//   2. 服务器【没有实据】       -> 【继续查本地直连聚合】(六个源);
//   3. 服务器不可用 / HTTP 非 200 / JSON 解析失败 / querySucceeded == false
//      / 熔断打开 / 配额用尽且未命中服务端缓存 -> 回退本地直连聚合。
//
// 「收录」不能只看 verdict —— 实测服务器对一个随机的、从未存在过的哈希会回
//   {"verdict":"clean","malicious":0,"totalEngines":0,"source":"OTX","querySucceeded":true}
// 也就是把「OTX 没这条情报」讲成了 clean。判据见 .cpp 里的 serverHasRecord():
// Malicious/Suspicious 一律算收录(哈希黑名单源没有 engine 计数),否则要求 totalEngines > 0。
//
// 这同时堵掉一个既有漏洞:上面那条 0 引擎的 clean 原先会被 ReputationCache 按
// CleanCacheTtlDays(7 天)缓存,于是「谁都没数据」变成一条 7 天有效的「此文件干净」。
// 现在没实据时会先查本地;本地也答不出来才返回服务器那条,并降级成 Unknown
//(按 24h 缓存、且缓存兜底读取明确拒绝用 Unknown 当结论),既不谎报干净,
// 也仍能进缓存,避免同一哈希每次事件都重跑「代理 + 六个本地源」。
//
// It implements IHashReputationService so it slots in at the single
// ReputationManager choke point (queryNow / background consume loop /
// memory-protection verify / manual UI query). Results returned here flow
// through ReputationManager -> ReputationCache, so the existing tiered-TTL
// local cache transparently covers proxy verdicts too (no extra cache needed).
//
// NOTE: the server proxy currently aggregates VirusTotal + ThreatBook only.
// Until the other four sources (MalwareBazaar / OTX / MetaDefender /
// HybridAnalysis) are wired server-side, the direct aggregate remains the
// broader authority; that is why both non-authoritative proxy results AND
// authoritative "no record" replies fall back to it.
namespace bulwark::service::reputation {

class ProxyReputationService : public IHashReputationService {
public:
    // fallback must outlive this object (in main.cpp it is the AggregateReputationService,
    // declared before this decorator and destroyed after it).
    ProxyReputationService(const BulwarkOptions& options, IHashReputationService* fallback);

    bool isEnabled() const override;
    bulwark::FileReputation query(const QString& sha256) override;
    bulwark::FileReputation query(const QString& sha256, bool priority) override;
    std::pair<bool, QString> testConnection() override;

    // 只问服务器、不做本地回退 —— 「服务器优先」策略的唯一实现,query() 与双击云扫描的分级
    // 链路(Worker::runVtScan)都复用它,避免两处各写一份而慢慢跑偏。
    //   *answered  服务器给出了可采信的权威回复(HTTP 200 + JSON 可解析 + querySucceeded,
    //              且在配额耗尽的 cacheOnly 模式下确为服务端缓存命中);
    //   *hasRecord 在 answered 基础上,服务器【确有实据】(判据见 .cpp 的 serverHasRecord:
    //              恶意/可疑一律算,否则要求 totalEngines > 0)。
    // 未启用 / 熔断打开 / 请求失败 -> 返回 Unknown 且两个出参均为 false。两个出参可传 nullptr。
    bulwark::FileReputation queryServerOnly(const QString& sha256, bool priority,
                                            bool* hasRecord, bool* answered);

    // 把本地查到、而服务器尚无记录的权威结论回传给中央服务器,让整个机队共享(省各端点配额:
    // 尤其「本机首见文件上传 VT 扫出来的结论」——那是服务器凭哈希查不到、只有拿到文件的端点
    // 才能产出的新情报)。fire-and-forget:内部派 detached 线程发送,不阻塞调用方,失败即放弃
    // (不重试、不排队)。只回传确有实据的结论;0 引擎的 clean 与 Unknown 一律不回传。
    // 由 ReputationProxy.SyncResultsToServer 控制(默认开)。
    void maybeSyncToServer(const bulwark::FileReputation& rep);
    bulwark::ReputationUsage getUsage() override;
    QString name() const override { return QStringLiteral("ReputationProxy"); }

    // 中央服务器这一跳是否真的可用(已启用 + 有端点)。刻意与 isEnabled() 分开:后者在代理
    // 关闭、但本地直连聚合器可用时也返回 true(它回答的是「信誉查询整体可用吗」)。
    // 云查毒的进度文案要据此决定第一句到底能不能写「正在查询中央服务器…」—— 代理没开却这么
    // 写,就是在卡片上撒谎,而「云查是否真的服务器优先」恰恰只能从这句话看出来。
    bool isServerEnabled() const { return enabled_.load(); }

    // 【本机不动用任何第三方情报源】模式(ReputationProxy.ServerOnly)。为真时本装饰器绝不
    // 回退到本地直连聚合器,行为画像也不去拉 —— 云端只用来问中央服务器「这个哈希你收录了吗」。
    // 对外暴露是因为链路的另外几段(Worker 的分级云查毒、VT 完整报告、逐源「测试连接」)
    // 各自持有自己的客户端句柄,必须能读到同一个判据;两处各写一份开关必然跑偏。
    bool isServerOnly() const { return serverOnly_; }

    // The proxy holds keys server-side; nothing to hot-swap here. The direct
    // sources' keys keep flowing to the fallback (main.cpp calls setApiKey on
    // the aggregate directly), so this is intentionally a no-op.
    void setApiKey(const QString& /*key*/) override {}

    // Behaviour profiles are not served by the proxy yet -> delegate to fallback.
    bulwark::ThreatBehaviorProfile fetchBehaviorProfile(const QString& sha256) override;

    // 中央代理健康探测(非阻塞),供 UI「信誉服务在线/离线」状态灯用。绝不在调用线程做网络
    // I/O:命中新鲜缓存直接返回;缓存过期/首次则派发一个后台探测线程刷新缓存后即返回当前最佳
    // 已知状态(首次未知时返回「检测中」)。curl 有 5s 下限,同步探测会卡住服务主线程,故如此。
    // 代理未启用时回退反映本地直连聚合器的连通性(此时并不存在「中央服务」可离线)。
    std::pair<bool, QString> healthCheckNonBlocking();

private:
    // Queries the proxy once. Sets *ok=true only when a well-formed JSON reply
    // (HTTP 200) was parsed; the returned rep still carries querySucceeded from
    // the server (false => the proxy could not authoritatively resolve it).
    // cacheOnly=true asks the server to answer only from its shared cache (never
    // spend upstream intel); *wasCached reports whether the reply was served from
    // that cache (so the caller can keep server-cache hits off the daily budget).
    // 结果同时喂给下面的存活/限流状态机(noteOutcome)。
    bulwark::FileReputation queryProxy(const QString& sha256, bool cacheOnly, bool* ok, bool* wasCached);

    // 熔断 + 限流冷却:该跳能不能走。返回 false 表示直接走本地 —— 否则每次查询都要先白等一次
    // QueryTimeoutSeconds 超时才回退,后台信誉队列会被拖垮。
    //   · 服务端限流冷却期内(429 给的 retry_after_seconds)-> false,且【不再每 60s 白敲门】;
    //   · 传输层不可达 -> 冷却 kBreakerCooldownMs 后半开,只放一个请求去试探。
    bool proxyLikelyUp();

    // 客户端侧请求预算:两个桶(每分钟 / 每小时)都过才放行。
    //
    // 【只查收录】模式下默认【不限次数】—— 这类请求只让服务端读自己的库(绝不触达它的付费
    // 上游),既不花机队配额、也就没有理由按次数省着用;而每砍掉一次服务器查询,换来的都是
    // 一次本机 VT 密钥消耗(那才是真稀缺的:免费档 4/min、500/天)。所以预算桶建了但先【不武装】。
    //
    // 唯一会武装它们的情形:服务端真的回了 429(见 noteOutcome)。那说明对面版本较旧、仍对
    // 只读查询按 per-IP 滑窗限流,超限要封一小时 —— 此后自动收敛到 RequestsPerMinute/PerHour
    // 之内,避免「不限次数」反而把服务器这一跳整小时地打没了。武装后本进程内不再解除。
    bool tryConsumeRequestBudget(bool priority);

    struct HealthCache; // 前置声明,noteOutcome 要用
    // 据一次代理请求的 HTTP 结果刷新存活/限流状态。静态 + 只吃共享指针,是为了让 detach 出去的
    // 回传线程也能安全调用(绝不能捕获 this,理由见 HealthCache 的注释)。
    static void noteOutcome(const std::shared_ptr<HealthCache>& health, int httpCode,
                            const QString& body);

    IHashReputationService* fallback_;   // direct per-source aggregate (never null in practice)
    std::atomic<bool> enabled_;
    QString baseUrl_;                    // normalised, no trailing '/'
    QString maskedUrl_;                  // host-masked form for diagnostics/logs (never plaintext)
    QString token_;                      // bearer token (env var > appsettings)
    int timeoutSecs_;
    bool syncResults_ = true;            // 回传本地结论给服务器(ReputationProxy.SyncResultsToServer)
    // 【只查收录】常态模式:每次请求都带 lookupOnly,永不让服务端去问它的上游付费情报源;
    // 未收录即转本机密钥直连。与 freshBudget_ 互斥 —— 这个模式下不存在「新鲜的上游查询」,
    // 故不占用每日新鲜配额。见 ReputationProxyOptions::LookupOnly。
    bool lookupOnly_ = false;
    // 【本机不动用任何第三方情报源】:见 ReputationProxyOptions::ServerOnly。为真时 fallback_
    // 这条腿整条不走(查询、行为画像、连通性自检都不走),云端只剩「问服务器收录了吗」这一跳。
    bool serverOnly_ = false;

    // Daily budget of *fresh* server-intel lookups (replies the server had to fetch from its
    // paid upstream, i.e. NOT served from its shared cache). null => unlimited. When the budget
    // is exhausted the client switches to cache-only requests: server-cache hits still flow
    // (unlimited), a cache miss falls back to the local direct aggregate (local-first).
    std::unique_ptr<DailyQuota> freshBudget_;

    // 客户端侧请求数预算(压在服务端 per-IP 滑窗之下)。null => 该维不限。
    std::unique_ptr<TokenBucket> minuteBudget_;
    std::unique_ptr<TokenBucket> hourBudget_;

    // 中央服务存活缓存(UI 状态灯 + 查询侧熔断都读它),由一个 detach 出去的探测线程写入,
    // 这样调用方永不阻塞在网络上(stale-while-revalidate)。
    //
    // 之所以单独放进共享状态、而不是直接做成员:探测线程是 detach 的,curl 又有 5s 下限,
    // 完全可能比本对象活得久 —— 本对象是 serviceRun 栈上的局部量,停机时正好可能有探测在途。
    // 原先那版按裸 this 捕获、直接写成员,对象一销毁就是 use-after-free(表现为停机偶发崩溃)。
    // 改成共享状态后,迟到的探测只会写它自己持有的那份,不会踩到任何已释放内存。
    struct HealthCache {
        // -1 尚未探测 / 0 离线(传输层不可达) / 1 在线 / 2 在线但被服务端限流。
        // 「限流」必须与「离线」分开:服务端 429 时链路好得很,只是这个来源 IP 的滑窗满了。
        // 过去两者混为一谈,是「信誉服务老是断链」的直接成因(详见 .cpp 的 noteOutcome)。
        std::atomic<int>    state{-1};
        std::atomic<qint64> atMs{0};        // 最近一次 /health 探测完成时刻(ms epoch)
        std::atomic<bool>   probing{false}; // 已有探测在途(避免并发重复探)
        // 服务器不认回传接口(404/405/501:未实现或已关闭)。一旦确认就不再为每次扫描白发
        // 一次请求。放在共享状态里,才能被 detach 出去的回传线程安全写入(同 state/atMs 之理)。
        std::atomic<bool>   submitUnsupported{false};
        // 已就「服务端不认 lookupOnly」告警过(只警一次,别每条哈希刷一行)。
        // 这条很重要:开关开着而服务端是旧版时,配额照烧却看不出来 —— 正是此前 cacheOnly
        // 白发了很久都没人察觉的原因。
        std::atomic<bool>   lookupOnlyUnsupportedWarned{false};
        // 传输层连续失败次数。达到阈值才判离线 —— 单次抖动(一次 DNS/TLS 抽风、curl 进程没起来)
        // 不该让状态灯翻牌,那是用户看到的「断链」里相当一部分的来源。
        std::atomic<int>    transportFailStreak{0};
        // 服务端限流冷却截止时刻(ms epoch),取自 429 回包的 retry_after_seconds。
        std::atomic<qint64> throttledUntilMs{0};
        // 服务端确实对我们限过流(收到过 429)-> 武装客户端请求预算桶。
        // 「只查收录」模式默认不限次数(那类请求不花服务端任何上游配额),这个标记就是那份
        // 「不限」的唯一收敛条件:只对真的会限流的服务端收敛,而不是先验地假设每台都限。
        std::atomic<bool>   budgetsArmed{false};
        // 熔断半开时刻。刻意与 atMs 分开:atMs 是【/health 探测缓存】的时间戳,而
        // healthCheckNonBlocking 靠「atMs 是否过期」决定要不要再探一次。以前熔断半开和
        // 每次失败的查询都去刷 atMs,于是查询一失败就把探测窗口顶新,UI 再也发不出 /health
        // 探测,红灯就下不来了。现在只有真正的 /health 探测写 atMs。
        std::atomic<qint64> breakerAtMs{0};
    };
    std::shared_ptr<HealthCache> health_ = std::make_shared<HealthCache>();
};

} // namespace bulwark::service::reputation
