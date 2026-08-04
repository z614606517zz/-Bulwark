#pragma once
#include "bulwark/service/reputation/IHashReputationService.h"
#include "bulwark/service/reputation/ReputationCache.h"
#include "bulwark/service/Logger.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/FileReputation.h"

#include <QQueue>
#include <QSet>
#include <QMutex>
#include <QWaitCondition>
#include <QString>

#include <atomic>
#include <functional>
#include <optional>
#include <thread>

// 信誉查询协调器:把「本地缓存(同步路径用)」与「后台限流网络查询」解耦。
//   - tryGetCached:裁决同步路径调用,只读内存缓存(含离线兜底),绝不碰网络。
//   - maybeEnqueue:对「值得查」的样本入队,后台 worker 线程限流查询并写缓存。
//   - 后台查到恶意且回调已设置时,通过 MaliciousCallback 交宿主做补偿处置。
// 这样外部信誉永远是「锦上添花」:挂了/超配额/断网都不影响本地实时防护与启发式。
// 对应 .NET Bulwark.Service/Reputation/ReputationManager.cs。
namespace bulwark::service::reputation {

class ReputationManager {
public:
    // 后台确认恶意的回调(在后台线程被调用!宿主需自行做线程 marshaling)。
    using MaliciousCallback =
        std::function<void(const bulwark::SecurityEvent&, const bulwark::FileReputation&)>;

    ReputationManager(IHashReputationService* client, ReputationCache* cache);
    ~ReputationManager();

    ReputationManager(const ReputationManager&) = delete;
    ReputationManager& operator=(const ReputationManager&) = delete;

    bool isEnabled() const;

    // 同步富化路径:读已缓存的信誉(含已过 TTL 的陈旧结论作离线兜底);Unknown -> nullopt。
    std::optional<bulwark::FileReputation> tryGetCached(const QString& sha256) const;

    // 分级 TTL 内的有效缓存(严格按 TTL,不做陈旧兜底;含「未收录」的负缓存)。
    // 供双击云扫描的分级链路在联网之前先白拿一次:命中即零往返出结论。
    std::optional<bulwark::FileReputation> tryGetFresh(const QString& sha256) const;

    // 把链路自行查到的结论写入共享分级缓存(内部按 querySucceeded 过滤,只存权威结果)。
    // 双击云扫描不经 queryNow 自行编排各级查询,故需要显式回填,否则同一哈希的后续事件
    // (以及后台信誉队列)会把整条链路重跑一遍。
    void storeResult(const bulwark::FileReputation& rep);

    // 手动查询(UI 主动触发):先缓存(含负缓存去重)后网络。网络查询在调用方线程阻塞
    // (用户主动点击「查询」可接受),命中缓存则立即返回。绝不用于事件热路径。
    // priority=true 供内存防护/反注入验证:占用 VT 预留的优先级配额,尽量不被普通查询挤占。
    bulwark::FileReputation queryNow(const QString& sha256, bool priority = false);

    // ===== 事件热路径专用:有界等待的云查询 =====
    //
    // 【为什么必须有界】此前 Worker::enrich 直接在事件线程上调 queryNow —— 也就是上面那个
    // 明写着「绝不用于事件热路径」的接口。它的实际最坏耗时是:中央代理 QueryTimeoutSeconds
    // (默认 8s)+ 回退到本地直连聚合(各源并行,收敛到最慢单源,默认 10~15s),合计二十多秒。
    // 而整条链路(出队 -> 富化 -> 裁决 -> IPC -> 弹窗)全在同一个 Qt 主线程上串行,于是
    // 【一条事件】就能把【所有后续事件】堵住二十多秒:内核事件在 4096 深的队列里堆积到丢弃
    // (=漏检)、UI 迟迟收不到拦截/询问、连弹窗超时巡检的秒级定时器都停摆。这正是「防护延迟
    // 过高」最主要的来源,且触发条件毫不苛刻 —— 代理端口不可达时每次未命中缓存都要先等满超时。
    //
    // 【语义】
    //   · 命中缓存 -> 立即返回(零等待,与旧行为一致);
    //   · 未命中 -> 交给专用「内联车道」线程去查,调用方最多等 budgetMs;
    //   · 预算内答复 -> 返回权威结论,本条事件照旧据此裁决(与旧的同步查询完全等价);
    //   · 超预算 -> 立刻返回 Unknown 让流水线继续跑。查询【不取消】,结果仍会写入缓存
    //     (同一哈希的下一条事件即零往返命中);若迟到的结论是恶意,则经 MaliciousCallback
    //     走既有补偿处置(结束进程树 + 隔离载荷 + 内核禁运),与后台队列确认恶意同一条路。
    //   · 车道正被别的哈希占着 -> 不排队,直接返回 Unknown(有界优先;该哈希由 maybeEnqueue
    //     的后台队列兜住)。
    // 于是「首次执行的已知恶意样本不漏网」这个原意保留下来了(服务器正常时 200~800ms 就回),
    // 而服务器慢/挂时的代价从「堵死整条流水线」降为「这一条事件晚一点被确认」。
    //
    // 只允许事件线程(Qt 主线程)调用:车道是单槽位、单等待者设计。
    bulwark::FileReputation queryNowBounded(const bulwark::SecurityEvent& e, int budgetMs);

    // 拉取样本行为画像:委托聚合器遍历各源并集合并(VT 释放物/注册表 + HA 网络 IOC…)。
    // 在调用方线程阻塞——仅在「后台确认恶意」后调用,用于清理释放物 + 生成主动拦截规则。
    bulwark::ThreatBehaviorProfile fetchBehaviorProfile(const QString& sha256);

    // 值得查(未签名 + 本机首见 + 启发式>=可疑)且未缓存/不在途 -> 入队后台限流查询。
    void maybeEnqueue(const bulwark::SecurityEvent& e);

    void setMaliciousConfirmed(MaliciousCallback cb) { onMalicious_ = std::move(cb); }

    void start();
    void stop();

private:
    void consumeLoop();
    void inlineLaneLoop();

    IHashReputationService* client_;
    ReputationCache* cache_;
    MaliciousCallback onMalicious_;

    mutable QMutex qmx_;
    QWaitCondition qcv_;
    QQueue<bulwark::SecurityEvent> queue_;
    QSet<QString> inflight_;
    std::atomic<bool> running_{false};
    std::thread worker_;

    // ---- 内联车道(queryNowBounded 的执行体)----
    // 单槽位 + 单等待者:调用方只有事件线程一个,故不需要队列,也不需要 waiter 计数。
    // 车道忙着的时候新来的调用直接放行(有界优先),绝不排队 —— 排队就等于把延迟又攒回来了。
    std::thread inlineWorker_;
    QMutex laneMx_;
    QWaitCondition laneReqCv_;    // 唤醒车道线程(有新活)
    QWaitCondition laneDoneCv_;   // 唤醒等待者(结论已出)
    bool laneBusy_ = false;       // 车道有在办任务(含「等待者已放弃但查询仍在跑」)
    bool laneHasResult_ = false;  // 在办任务已出结论
    bool laneWaiterGone_ = false; // 等待者已超预算放手 -> 迟到的恶意结论改走补偿处置
    QString laneHash_;
    bulwark::SecurityEvent laneEvent_;
    bulwark::FileReputation laneResult_;

    static constexpr int kCapacity = 256; // 有界去重队列;满则丢弃(本地启发式兜底)
    Logger log_{QStringLiteral("Reputation")};
};

} // namespace bulwark::service::reputation
