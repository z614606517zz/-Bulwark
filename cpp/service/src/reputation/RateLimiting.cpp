#include "bulwark/service/reputation/RateLimiting.h"

#include <QThread>

#include <algorithm>
#include <cmath>

namespace bulwark::service::reputation {

TokenBucket::TokenBucket(int tokensPerPeriod, qint64 periodMs) {
    capacity_ = std::max(1, tokensPerPeriod);
    refillIntervalMs_ = static_cast<double>(periodMs) / capacity_;
    tokens_ = capacity_; // start full
    lastRefillUtc_ = QDateTime::currentDateTimeUtc();
}

void TokenBucket::refill() {
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const qint64 elapsedMs = lastRefillUtc_.msecsTo(now);
    if (elapsedMs <= 0) return;
    const double refill = elapsedMs / refillIntervalMs_;
    if (refill >= 1.0) {
        tokens_ = std::min<double>(capacity_, tokens_ + std::floor(refill));
        lastRefillUtc_ = now;
    }
}

bool TokenBucket::tryConsume(bool priority) {
    QMutexLocker lk(&mutex_);
    refill();
    const bool yieldToPriority = !priority && priorityWaiters_.load() > 0;
    if (tokens_ >= 1.0 && !yieldToPriority) {
        tokens_ -= 1.0;
        return true;
    }
    return false;
}

void TokenBucket::wait(bool priority) {
    if (priority) priorityWaiters_.fetch_add(1);
    for (;;) {
        qint64 delayMs = 0;
        {
            QMutexLocker lk(&mutex_);
            refill();
            const bool yieldToPriority = !priority && priorityWaiters_.load() > 0;
            if (tokens_ >= 1.0 && !yieldToPriority) {
                tokens_ -= 1.0;
                if (priority) priorityWaiters_.fetch_sub(1);
                return;
            }
            const qint64 elapsed = lastRefillUtc_.msecsTo(QDateTime::currentDateTimeUtc());
            delayMs = static_cast<qint64>(refillIntervalMs_) - elapsed;
            if (delayMs < 0) delayMs = 0;
        }
        QThread::msleep(delayMs <= 0 ? 50 : static_cast<unsigned long>(delayMs));
    }
}

DailyQuota::DailyQuota(int dailyLimit, int priorityReserve) {
    limit_ = std::max(1, dailyLimit);
    priorityReserve_ = std::max(0, std::min(priorityReserve, limit_ - 1));
    dayUtc_ = QDateTime::currentDateTimeUtc().date();
}

bool DailyQuota::tryConsume(bool priority) {
    QMutexLocker lk(&lock_);
    const QDate today = QDateTime::currentDateTimeUtc().date();
    if (today != dayUtc_) { dayUtc_ = today; count_ = 0; }
    const int effectiveLimit = priority ? limit_ : (limit_ - priorityReserve_);
    if (count_ >= effectiveLimit) return false;
    ++count_;
    return true;
}

void DailyQuota::release() {
    QMutexLocker lk(&lock_);
    const QDate today = QDateTime::currentDateTimeUtc().date();
    if (today != dayUtc_) { dayUtc_ = today; count_ = 0; return; } // 跨天后计数已归零,无可退还
    if (count_ > 0) --count_;
}

std::pair<int, int> DailyQuota::snapshot() {
    QMutexLocker lk(&lock_);
    const QDate today = QDateTime::currentDateTimeUtc().date();
    if (today != dayUtc_) { dayUtc_ = today; count_ = 0; }
    return { count_, limit_ };
}

} // namespace bulwark::service::reputation
