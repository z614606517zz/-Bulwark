#include "bulwark/engine/EgressRateMonitor.h"
#include <QSet>
#include <algorithm>

namespace bulwark::engine {
using detail::u;

namespace {
constexpr int kHardCap = 4096;

QString normalizeRemote(const QString& target) {
    if (target.isEmpty()) return QStringLiteral("?");
    QString t = target.trimmed().toLower();
    const int colon = t.lastIndexOf(QLatin1Char(':'));
    if (colon > 0 && colon < t.size() - 1) {
        bool allDigits = true;
        for (int i = colon + 1; i < t.size(); ++i)
            if (!t.at(i).isDigit()) { allDigits = false; break; }
        if (allDigits) t = t.left(colon);
    }
    return t;
}
} // namespace

void EgressRateMonitor::ProcState::add(const QString& remote, const QDateTime& at, int windowSecs) {
    events.append({ remote, at });
    lastUtc = at;
    const QDateTime cutoff = at.addSecs(-windowSecs);
    int i = 0;
    while (i < events.size() && events.at(i).second < cutoff) ++i;
    if (i > 0) events.remove(0, i);
    if (events.size() > kHardCap) events.remove(0, events.size() - kHardCap);
}

int EgressRateMonitor::ProcState::countInWindow(const QDateTime& now, int windowSecs) const {
    const QDateTime cutoff = now.addSecs(-windowSecs);
    int n = 0;
    for (const auto& ev : events) if (ev.second >= cutoff) ++n;
    return n;
}

int EgressRateMonitor::ProcState::distinctTargetsInWindow(const QDateTime& now, int windowSecs) const {
    const QDateTime cutoff = now.addSecs(-windowSecs);
    QSet<QString> set;
    for (const auto& ev : events) if (ev.second >= cutoff) set.insert(ev.first);
    return set.size();
}

EgressRateMonitor::EgressRateMonitor(int windowSeconds, int rateThreshold, int fanoutThreshold, int maxPids) {
    windowSecs_ = windowSeconds > 0 ? windowSeconds : 10;
    rateThreshold_ = qMax(10, rateThreshold);
    fanoutThreshold_ = qMax(8, fanoutThreshold);
    maxPids_ = qMax(64, maxPids);
}

ScoreResult EgressRateMonitor::observe(const SecurityEvent& e) {
    ScoreResult r;
    if (e.type != EventType::NetworkConnect || e.actorPid <= 0) return r;

    const QString remote = normalizeRemote(e.target);
    const QDateTime now = e.timestampUtc.isValid() ? e.timestampUtc : QDateTime::currentDateTimeUtc();
    int score = 0;

    QMutexLocker locker(&gate_);
    ProcState& st = byPid_[e.actorPid];
    st.add(remote, now, windowSecs_);

    const int count = st.countInWindow(now, windowSecs_);
    const int distinct = st.distinctTargetsInWindow(now, windowSecs_);

    if (count >= rateThreshold_) {
        const int over = count - rateThreshold_;
        score += 25 + qMin(over, 40);
        r.reasons << (QString::number(windowSecs_) + u("秒内高速外联 ") + QString::number(count) +
                      u(" 次(疑似扫描/外传/C2 轮询)"));
    }
    if (distinct >= fanoutThreshold_) {
        const int over = distinct - fanoutThreshold_;
        score += 30 + qMin(over * 2, 40);
        r.reasons << (QString::number(windowSecs_) + u("秒内连向 ") + QString::number(distinct) +
                      u(" 个不同目标(疑似横移/扫描/蠕虫传播)"));
    }

    evictIfNeeded(now);
    r.score = qMin(score, 100);
    return r;
}

void EgressRateMonitor::forget(int pid) {
    QMutexLocker locker(&gate_);
    byPid_.remove(pid);
}

int EgressRateMonitor::trackedProcessCount() {
    QMutexLocker locker(&gate_);
    return byPid_.size();
}

void EgressRateMonitor::evictIfNeeded(const QDateTime& now) {
    const QDateTime stale = now.addSecs(-static_cast<qint64>(windowSecs_) * 4);
    for (auto it = byPid_.begin(); it != byPid_.end(); ) {
        if (it.value().lastUtc < stale) it = byPid_.erase(it);
        else ++it;
    }
    if (byPid_.size() > maxPids_) {
        QVector<QPair<QDateTime, int>> byAge;
        byAge.reserve(byPid_.size());
        for (auto it = byPid_.constBegin(); it != byPid_.constEnd(); ++it)
            byAge.append({ it.value().lastUtc, it.key() });
        std::sort(byAge.begin(), byAge.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        const int toRemove = byPid_.size() - maxPids_;
        for (int i = 0; i < toRemove; ++i) byPid_.remove(byAge.at(i).second);
    }
}

} // namespace bulwark::engine
