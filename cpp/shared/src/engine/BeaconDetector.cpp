#include "bulwark/engine/BeaconDetector.h"
#include <QSet>
#include <QStringList>
#include <algorithm>
#include <cmath>
#include <limits>

namespace bulwark::engine {

using detail::u;
using detail::fileNameLower;

namespace {

constexpr double kCvRegular = 0.15;
constexpr double kCvSemiRegular = 0.28;
constexpr double kMinPeriodSec = 2.0;
constexpr double kMaxPeriodSec = 3600.0;
constexpr int kMaxKeep = 64;

const QSet<QString>& scriptHosts() {
    static const QSet<QString> s = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    };
    return s;
}

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

// C# "0.#":最多 1 位小数,去掉末尾 .0。
QString fmt1opt(double x) {
    QString v = QString::number(x, 'f', 1);
    if (v.endsWith(QLatin1String(".0"))) v.chop(2);
    return v;
}

} // namespace

void BeaconDetector::Series::add(const QDateTime& at) {
    times.append(at);
    lastUtc = at;
    ++count;
    if (times.size() > kMaxKeep)
        times.remove(0, times.size() - kMaxKeep);
}

QVector<double> BeaconDetector::Series::intervalsSeconds() const {
    QVector<double> result;
    for (int i = 1; i < times.size(); ++i) {
        const double sec = times.at(i - 1).msecsTo(times.at(i)) / 1000.0;
        if (sec >= 0) result.append(sec);
    }
    return result;
}

BeaconDetector::BeaconDetector(int minSamples, int maxSeries, qint64 retentionSecs) {
    minSamples_ = qMax(3, minSamples);
    maxSeries_ = qMax(64, maxSeries);

    const qint64 floor = static_cast<qint64>(kMaxPeriodSec * 1.5);
    retentionSecs_ = retentionSecs > 0 ? retentionSecs : static_cast<qint64>(kMaxPeriodSec * 2);
    if (retentionSecs_ < floor) retentionSecs_ = floor;
}

std::pair<double, double> BeaconDetector::meanAndCv(const QVector<double>& intervals) {
    if (intervals.isEmpty()) return { 0.0, std::numeric_limits<double>::max() };
    double sum = 0.0;
    for (double x : intervals) sum += x;
    const double mean = sum / intervals.size();
    if (mean <= 0) return { 0.0, std::numeric_limits<double>::max() };
    double var = 0.0;
    for (double x : intervals) var += (x - mean) * (x - mean);
    var /= intervals.size();
    return { mean, std::sqrt(var) / mean };
}

ScoreResult BeaconDetector::observe(const SecurityEvent& e) {
    ScoreResult r;
    if (e.type != EventType::NetworkConnect || e.actorPid <= 0)
        return r;

    const QString remote = normalizeRemote(e.target);
    const QString key = QString::number(e.actorPid) + QLatin1Char('|') + remote;
    const QDateTime now = e.timestampUtc.isValid() ? e.timestampUtc : QDateTime::currentDateTimeUtc();

    QMutexLocker locker(&gate_);

    auto it = series_.find(key);
    if (it == series_.end()) {
        Series s;
        s.actorPath = e.actorPath;
        s.remote = remote;
        it = series_.insert(key, s);
    }
    Series& s = it.value();
    s.add(now);

    evictIfNeeded(now);

    const QVector<double> intervals = s.intervalsSeconds();
    if (intervals.size() < minSamples_ - 1)
        return r; // 样本不足

    const auto [mean, cv] = meanAndCv(intervals);
    if (mean < kMinPeriodSec || mean > kMaxPeriodSec)
        return r; // 周期不在信标区间

    int score = 0;
    if (cv <= kCvRegular) {
        score = 55;
        r.reasons << (u("周期性外联信标:间隔≈") + fmt1opt(mean) + u("s 抖动极低(CV=") +
                      QString::number(cv, 'f', 2) + u(",疑似 C2 回连)"));
    } else if (cv <= kCvSemiRegular) {
        score = 35;
        r.reasons << (u("近周期性外联:间隔≈") + fmt1opt(mean) + u("s(CV=") +
                      QString::number(cv, 'f', 2) + u(",疑似带抖动的 C2 信标)"));
    } else {
        return r; // 间隔不规律
    }

    if (!e.actorSigned) {
        score += 15;
        r.reasons << u("信标主体无可信签名");
    }
    const QString actor = fileNameLower(e.actorPath);
    if (scriptHosts().contains(actor)) {
        score += 20;
        r.reasons << (u("脚本解释器(") + actor + u(")周期性外联(强 C2 特征)"));
    }

    r.reasons << (u("目标 ") + remote + u(",已累计 ") + QString::number(s.count) + u(" 次外联"));
    r.score = qMin(score, 100);
    return r;
}

void BeaconDetector::forget(int pid) {
    QMutexLocker locker(&gate_);
    const QString prefix = QString::number(pid) + QLatin1Char('|');
    for (auto it = series_.begin(); it != series_.end(); ) {
        if (it.key().startsWith(prefix)) it = series_.erase(it);
        else ++it;
    }
}

int BeaconDetector::trackedSeriesCount() {
    QMutexLocker locker(&gate_);
    return series_.size();
}

void BeaconDetector::evictIfNeeded(const QDateTime& now) {
    const QDateTime cutoff = now.addSecs(-retentionSecs_);
    for (auto it = series_.begin(); it != series_.end(); ) {
        if (it.value().lastUtc < cutoff) it = series_.erase(it);
        else ++it;
    }

    if (series_.size() > maxSeries_) {
        QVector<QPair<QDateTime, QString>> byAge;
        byAge.reserve(series_.size());
        for (auto it = series_.constBegin(); it != series_.constEnd(); ++it)
            byAge.append({ it.value().lastUtc, it.key() });
        std::sort(byAge.begin(), byAge.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        const int toRemove = series_.size() - maxSeries_;
        for (int i = 0; i < toRemove; ++i) series_.remove(byAge.at(i).second);
    }
}

} // namespace bulwark::engine
