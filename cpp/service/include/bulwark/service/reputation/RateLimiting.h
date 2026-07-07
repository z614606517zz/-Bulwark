#pragma once
#include <QDateTime>
#include <QDate>
#include <QMutex>
#include <atomic>
#include <utility>

// 情报源限流原语:令牌桶(每分钟速率)+ 每日配额。线程安全。
// 注:原 C++ 头已丢失,此处按 RateLimiting.cpp 用法重建。
namespace bulwark::service::reputation {

// 令牌桶:每 periodMs 补满 tokensPerPeriod 个令牌;priority 等待者优先取令牌。
class TokenBucket {
public:
    TokenBucket(int tokensPerPeriod, qint64 periodMs);
    void wait(bool priority = false);

private:
    void refill();
    int capacity_ = 1;
    double refillIntervalMs_ = 0.0;
    double tokens_ = 0.0;
    QDateTime lastRefillUtc_;
    std::atomic<int> priorityWaiters_{0};
    QMutex mutex_;
};

// 每日配额(按 UTC 天滚动)。priorityReserve:为普通请求之外保留给优先请求的余量。
class DailyQuota {
public:
    DailyQuota(int dailyLimit, int priorityReserve = 0);
    bool tryConsume(bool priority = false);
    std::pair<int, int> snapshot();   // {今日已用, 每日上限}

private:
    int limit_ = 1;
    int priorityReserve_ = 0;
    int count_ = 0;
    QDate dayUtc_;
    QMutex lock_;
};

} // namespace bulwark::service::reputation
