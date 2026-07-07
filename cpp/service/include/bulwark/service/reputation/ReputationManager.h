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

    // 手动查询(UI 主动触发):先缓存(含负缓存去重)后网络。网络查询在调用方线程阻塞
    // (用户主动点击「查询」可接受),命中缓存则立即返回。绝不用于事件热路径。
    bulwark::FileReputation queryNow(const QString& sha256);

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

    IHashReputationService* client_;
    ReputationCache* cache_;
    MaliciousCallback onMalicious_;

    mutable QMutex qmx_;
    QWaitCondition qcv_;
    QQueue<bulwark::SecurityEvent> queue_;
    QSet<QString> inflight_;
    std::atomic<bool> running_{false};
    std::thread worker_;

    static constexpr int kCapacity = 256; // 有界去重队列;满则丢弃(本地启发式兜底)
    Logger log_{QStringLiteral("Reputation")};
};

} // namespace bulwark::service::reputation
