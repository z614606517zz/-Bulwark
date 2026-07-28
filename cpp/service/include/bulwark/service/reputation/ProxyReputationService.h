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
// server-side for the whole fleet. On ANY failure -- proxy disabled, network /
// HTTP / parse error, or a non-authoritative result (querySucceeded == false)
// -- it transparently delegates to the wrapped direct aggregate, so protection
// never regresses when the server is unreachable.
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
// broader authority; that is why non-authoritative proxy results fall back.
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
    bulwark::ReputationUsage getUsage() override;
    QString name() const override { return QStringLiteral("ReputationProxy"); }

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
    // Also feeds the liveness cache below (200 => online, anything else => offline).
    bulwark::FileReputation queryProxy(const QString& sha256, bool cacheOnly, bool* ok, bool* wasCached);

    // 熔断:代理已被判定离线且读数新鲜时,直接返回 false 让调用方走本地 —— 否则每次查询都要
    // 先白等一次 QueryTimeoutSeconds 超时才回退,后台信誉队列会被拖垮。冷却到期后半开:只放
    // 一个请求过去试探(通过重置 health_->atMs 让并发的其余调用继续走本地),成功即自动恢复。
    bool proxyLikelyUp();

    IHashReputationService* fallback_;   // direct per-source aggregate (never null in practice)
    std::atomic<bool> enabled_;
    QString baseUrl_;                    // normalised, no trailing '/'
    QString maskedUrl_;                  // host-masked form for diagnostics/logs (never plaintext)
    QString token_;                      // bearer token (env var > appsettings)
    int timeoutSecs_;

    // Daily budget of *fresh* server-intel lookups (replies the server had to fetch from its
    // paid upstream, i.e. NOT served from its shared cache). null => unlimited. When the budget
    // is exhausted the client switches to cache-only requests: server-cache hits still flow
    // (unlimited), a cache miss falls back to the local direct aggregate (local-first).
    std::unique_ptr<DailyQuota> freshBudget_;

    // 中央服务存活缓存(UI 状态灯 + 查询侧熔断都读它),由一个 detach 出去的探测线程写入,
    // 这样调用方永不阻塞在网络上(stale-while-revalidate)。
    //
    // 之所以单独放进共享状态、而不是直接做成员:探测线程是 detach 的,curl 又有 5s 下限,
    // 完全可能比本对象活得久 —— 本对象是 serviceRun 栈上的局部量,停机时正好可能有探测在途。
    // 原先那版按裸 this 捕获、直接写成员,对象一销毁就是 use-after-free(表现为停机偶发崩溃)。
    // 改成共享状态后,迟到的探测只会写它自己持有的那份,不会踩到任何已释放内存。
    struct HealthCache {
        std::atomic<int>    state{-1};      // -1 尚未探测 / 0 离线 / 1 在线
        std::atomic<qint64> atMs{0};        // 最近一次探测完成时刻(ms epoch)
        std::atomic<bool>   probing{false}; // 已有探测在途(避免并发重复探)
    };
    std::shared_ptr<HealthCache> health_ = std::make_shared<HealthCache>();
};

} // namespace bulwark::service::reputation
