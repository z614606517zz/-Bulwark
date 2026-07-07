#include "bulwark/service/reputation/ReputationManager.h"
#include "bulwark/engine/ThreatDetector.h"

#include <QMutexLocker>

namespace bulwark::service::reputation {

ReputationManager::ReputationManager(IHashReputationService* client, ReputationCache* cache)
    : client_(client), cache_(cache) {}

ReputationManager::~ReputationManager() { stop(); }

bool ReputationManager::isEnabled() const {
    return client_ && client_->isEnabled();
}

bulwark::ThreatBehaviorProfile ReputationManager::fetchBehaviorProfile(const QString& sha256) {
    if (!client_ || sha256.isEmpty())
        return {};
    return client_->fetchBehaviorProfile(sha256); // 聚合器遍历活跃源并集合并(VT + HA…)
}

std::optional<bulwark::FileReputation> ReputationManager::tryGetCached(const QString& sha256) const {
    if (!cache_)
        return std::nullopt;
    return cache_->tryGetForEnrichment(sha256);
}

bulwark::FileReputation ReputationManager::queryNow(const QString& sha256) {
    bulwark::FileReputation unknown;
    unknown.sha256 = sha256;
    if (sha256.isEmpty() || !client_)
        return unknown;
    // 命中缓存(含未收录的负缓存)直接复用,避免重复查询。
    if (cache_) {
        const auto cached = cache_->tryGet(sha256);
        if (cached.has_value())
            return cached.value();
    }
    bulwark::FileReputation rep = client_->query(sha256); // 阻塞(调用方线程,用户主动触发)
    rep.sha256 = sha256;
    if (cache_)
        cache_->store(rep);
    return rep;
}

void ReputationManager::maybeEnqueue(const bulwark::SecurityEvent& e) {
    if (!client_ || !client_->isEnabled())
        return;
    const QString hash = e.actorHash;
    if (hash.isEmpty())
        return;
    // 已有缓存结论(含未收录的负缓存)-> 不必再查。
    if (cache_ && cache_->tryGet(hash).has_value())
        return;
    // 只查高价值样本(省配额核心):未签名 + 本机首见 + 启发式已达可疑。
    const bool worth = !e.actorSigned && e.isFirstSeen
                       && e.riskScore >= bulwark::engine::ThreatDetector::Suspicious;
    if (!worth)
        return;

    QMutexLocker lk(&qmx_);
    if (inflight_.contains(hash))
        return;                         // 同一文件已在途
    if (queue_.size() >= kCapacity)
        return;                         // 队列满,放弃(本地启发式兜底,丢弃安全)
    inflight_.insert(hash);
    queue_.enqueue(e);
    qcv_.wakeOne();
}

void ReputationManager::start() {
    if (!isEnabled()) {
        log_.info(QStringLiteral("信誉查询未启用(无可用源 / 未配置密钥),后台 worker 不启动。"));
        return;
    }
    if (running_.exchange(true))
        return; // 已在运行
    worker_ = std::thread([this] { consumeLoop(); });
    log_.info(QStringLiteral("信誉查询后台 worker 已启动。"));
}

void ReputationManager::stop() {
    if (!running_.exchange(false))
        return;
    {
        QMutexLocker lk(&qmx_);
        qcv_.wakeAll(); // 唤醒 worker 让其看到 running_=false 并退出
    }
    if (worker_.joinable())
        worker_.join();
}

void ReputationManager::consumeLoop() {
    while (running_.load()) {
        bulwark::SecurityEvent e;
        QString hash;
        {
            QMutexLocker lk(&qmx_);
            while (running_.load() && queue_.isEmpty())
                qcv_.wait(&qmx_);
            if (!running_.load())
                break;
            e = queue_.dequeue();
            hash = e.actorHash;
        }
        if (hash.isEmpty())
            continue;

        try {
            bulwark::FileReputation rep = client_->query(hash); // 阻塞(限流 + HTTP),后台线程
            rep.sha256 = hash;
            if (cache_)
                cache_->store(rep); // 仅缓存权威成功结果(store 内部按 querySucceeded 过滤)

            if (rep.isMalicious()) {
                log_.warning(QStringLiteral("信誉查询确认恶意:%1(%2/%3)")
                                 .arg(e.actorPath).arg(rep.malicious).arg(rep.totalEngines));
                if (onMalicious_) {
                    // 注意:此处在后台线程;宿主回调需自行 marshaling 到主线程再碰 IPC/Qt 对象。
                    onMalicious_(e, rep);
                }
            }
        } catch (...) {
            // 后台查询绝不应中断 worker,吞掉异常即可(下次遇到再查)。
        }

        {
            QMutexLocker lk(&qmx_);
            inflight_.remove(hash);
        }
    }
}

} // namespace bulwark::service::reputation
