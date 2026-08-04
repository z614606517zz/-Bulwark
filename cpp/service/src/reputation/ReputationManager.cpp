#include "bulwark/service/reputation/ReputationManager.h"
#include "bulwark/engine/ThreatDetector.h"

#include <QElapsedTimer>
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

std::optional<bulwark::FileReputation> ReputationManager::tryGetFresh(const QString& sha256) const {
    if (!cache_)
        return std::nullopt;
    return cache_->tryGet(sha256);
}

void ReputationManager::storeResult(const bulwark::FileReputation& rep) {
    if (cache_)
        cache_->store(rep); // 仅缓存权威成功结果(store 内部按 querySucceeded 过滤)
}

bulwark::FileReputation ReputationManager::queryNow(const QString& sha256, bool priority) {
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
    bulwark::FileReputation rep = client_->query(sha256, priority); // 阻塞(调用方线程)
    rep.sha256 = sha256;
    if (cache_)
        cache_->store(rep);
    return rep;
}

bulwark::FileReputation ReputationManager::queryNowBounded(const bulwark::SecurityEvent& e, int budgetMs) {
    const QString sha256 = e.actorHash;
    bulwark::FileReputation unknown;
    unknown.sha256 = sha256;
    if (sha256.isEmpty() || !client_)
        return unknown;

    // 1) 缓存(含「未收录」负缓存)先白拿一次:命中即零等待,与旧行为一致。
    if (cache_) {
        const auto cached = cache_->tryGet(sha256);
        if (cached.has_value())
            return cached.value();
    }

    // 2) 预算 <= 0 表示「热路径上一律不联网」:交后台队列即可。
    if (budgetMs <= 0 || !running_.load())
        return unknown;

    QMutexLocker lk(&laneMx_);

    // 车道被上一条(已被放弃但仍在跑的)查询占着:不排队,直接放行本条。
    // 排队会让延迟重新累积成串行等待,正是本函数要消除的东西。
    if (laneBusy_)
        return unknown;

    laneBusy_        = true;
    laneHasResult_   = false;
    laneWaiterGone_  = false;
    laneHash_        = sha256;
    laneEvent_       = e;
    laneResult_      = bulwark::FileReputation();
    laneReqCv_.wakeOne();

    // 3) 有界等待。QWaitCondition 可能伪唤醒,故用 elapsed 计算剩余预算并循环。
    QElapsedTimer clock;
    clock.start();
    while (!laneHasResult_) {
        const qint64 left = static_cast<qint64>(budgetMs) - clock.elapsed();
        if (left <= 0)
            break;
        laneDoneCv_.wait(&laneMx_, static_cast<unsigned long>(left));
    }

    if (laneHasResult_) {
        // 车道线程已在写入结论时把 laneBusy_ 置回 false,这里只取结果。
        return laneResult_;
    }

    // 4) 超预算:放手。查询继续在车道线程上跑完并回填缓存;若结论是恶意,由车道线程
    //    调 onMalicious_ 走既有补偿处置(与后台队列确认恶意同一条路)。
    laneWaiterGone_ = true;
    return unknown;
}

void ReputationManager::inlineLaneLoop() {
    while (running_.load()) {
        QString hash;
        bulwark::SecurityEvent ev;
        {
            QMutexLocker lk(&laneMx_);
            // 「有活要干」= 车道已被占用(laneBusy_)且这一轮还没出结论。把 laneHasResult_
            // 也写进谓词里,是为了让「已出结论」的状态也回到 wait —— 否则一旦出现该状态
            // 就会空转刷 CPU(理论上不该出现:发起方置 laneBusy_ 时必然同时清 laneHasResult_)。
            while (running_.load() && !(laneBusy_ && !laneHasResult_))
                laneReqCv_.wait(&laneMx_);
            if (!running_.load())
                break;
            hash = laneHash_;
            ev   = laneEvent_;
        }
        if (hash.isEmpty()) {
            QMutexLocker lk(&laneMx_);
            laneBusy_ = false;
            laneDoneCv_.wakeAll();
            continue;
        }

        bulwark::FileReputation rep;
        rep.sha256 = hash;
        try {
            rep = client_->query(hash, /*priority=*/false); // 阻塞(限流 + HTTP),车道线程上
            rep.sha256 = hash;
            if (cache_)
                cache_->store(rep); // 仅缓存权威成功结果(store 内部按 querySucceeded 过滤)
        } catch (...) {
            // 单次查询异常绝不能让车道线程退出(否则此后每条事件都白等满预算)。
        }

        bool abandoned = false;
        {
            QMutexLocker lk(&laneMx_);
            laneResult_    = rep;
            laneHasResult_ = true;
            abandoned      = laneWaiterGone_;
            laneBusy_      = false; // 车道空闲,可接下一条
            laneDoneCv_.wakeAll();
        }

        // 等待者已放手 -> 这条结论对当时那次裁决已经迟到。恶意的话走既有补偿处置
        // (结束进程树 + 隔离载荷 + 清除持久化 + 内核禁运),与后台队列确认恶意同一条路。
        if (abandoned && rep.isMalicious()) {
            log_.warning(QStringLiteral("内联云查超预算后回执确认恶意,转补偿处置:%1(%2/%3)")
                             .arg(ev.actorPath).arg(rep.malicious).arg(rep.totalEngines));
            if (onMalicious_) {
                // 注意:此处在后台线程;宿主回调需自行 marshaling 到主线程再碰 IPC/Qt 对象。
                onMalicious_(ev, rep);
            }
        }
    }
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
    // 只查高价值样本(省配额核心):未签名 + 本机首见。
    // 原先还要求风险分 >= 50(可疑阈值),但这会导致已知恶意样本因启发式规则未命中而不查云端——
    // 结果服务器明明有记录却漏网。改为只要「未签名 + 首见」就查,配额靠限流器保护。
    const bool worth = !e.actorSigned && e.isFirstSeen;
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
    // 内联车道:承载 queryNowBounded 的实际网络查询,使事件线程只需有界等待而非无限期阻塞。
    inlineWorker_ = std::thread([this] { inlineLaneLoop(); });
    log_.info(QStringLiteral("信誉查询后台 worker 已启动(含事件热路径的内联查询车道)。"));
}

void ReputationManager::stop() {
    if (!running_.exchange(false))
        return;
    {
        QMutexLocker lk(&qmx_);
        qcv_.wakeAll(); // 唤醒 worker 让其看到 running_=false 并退出
    }
    {
        QMutexLocker lk(&laneMx_);
        laneReqCv_.wakeAll();  // 车道线程空闲时靠这个醒来看到 running_=false
        laneDoneCv_.wakeAll(); // 万一还有等待者,别让它把停机拖满一个预算
    }
    if (worker_.joinable())
        worker_.join();
    if (inlineWorker_.joinable())
        inlineWorker_.join();
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
