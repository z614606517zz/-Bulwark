#pragma once
#include "bulwark/service/reputation/IHashReputationService.h"
#include "bulwark/service/reputation/RateLimiting.h"
#include "bulwark/service/Logger.h"
#include "bulwark/models/Enums.h"

#include <QMutex>
#include <QString>

#include <algorithm>
#include <atomic>
#include <utility>

// Shared machinery for the concrete hash-reputation clients: enabled flag, token
// bucket + daily quota, usage snapshot, and the fail-open query skeleton
// (daily.tryConsume -> bucket.wait -> doQuery). Subclasses implement doQuery()
// (HTTP + parse) and doTest(). Keeps each concrete client tiny.
namespace bulwark::service::reputation {

class ReputationClientBase : public IHashReputationService {
public:
    bool isEnabled() const override { return enabled_; }
    QString name() const override { return name_; }

    bulwark::ReputationUsage getUsage() override {
        const auto snap = daily_.snapshot();
        bulwark::ReputationUsage u;
        u.source = name_;
        u.enabled = enabled_;
        u.usedToday = snap.first;
        u.dailyLimit = snap.second;
        u.perMinuteLimit = rpm_;
        return u;
    }

    bulwark::FileReputation query(const QString& sha256) override {
        bulwark::FileReputation unknown = unknownRep(sha256);
        if (!enabled_ || sha256.isEmpty()) return unknown;
        if (!daily_.tryConsume()) {
            log_.debug(name_ + QStringLiteral(" daily quota exhausted, skip ") + sha256.left(12));
            return unknown;
        }
        bucket_.wait();
        return doQuery(sha256);
    }

    std::pair<bool, QString> testConnection() override { return doTest(); }

    // Hot-swap the key from UI settings. Thread-safe vs. doQuery() on the
    // reputation worker thread (which reads via apiKey()). Empty key disables.
    void setApiKey(const QString& key) override {
        const QString k = key.trimmed();
        { QMutexLocker lk(&keyMutex_); apiKey_ = k; }
        enabled_ = !k.isEmpty();
    }

protected:
    ReputationClientBase(const QString& name, const QString& apiKey, bool enabled,
                         int rpm, int rpd, int timeoutSecs, int dailyReserve = 0)
        : name_(name), apiKey_(apiKey), enabled_(enabled),
          rpm_(std::max(1, rpm)), timeoutSecs_(timeoutSecs),
          bucket_(std::max(1, rpm), 60000), daily_(std::max(1, rpd), dailyReserve),
          log_(name) {}

    // HTTP + parse (rate-limit already acquired by query()).
    virtual bulwark::FileReputation doQuery(const QString& sha256) = 0;
    virtual std::pair<bool, QString> doTest() = 0;

    // Thread-safe snapshot of the current key (doQuery on worker threads must
    // read the key through this, never the raw apiKey_ member).
    QString apiKey() const {
        QMutexLocker lk(&keyMutex_);
        return apiKey_;
    }

    bulwark::FileReputation unknownRep(const QString& sha256) const {
        bulwark::FileReputation r;
        r.sha256 = sha256;
        r.verdict = bulwark::ReputationVerdict::Unknown;
        return r;
    }

    QString name_;
    QString apiKey_;                // empty = not configured (guard with keyMutex_)
    mutable QMutex keyMutex_;       // guards apiKey_ (hot-swapped from UI thread)
    std::atomic<bool> enabled_;     // atomic: read on worker threads, set on UI thread
    int rpm_;
    int timeoutSecs_;
    TokenBucket bucket_;
    DailyQuota daily_;
    Logger log_;
};

} // namespace bulwark::service::reputation
