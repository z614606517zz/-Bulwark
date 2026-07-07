#pragma once
#include <QString>
#include <QDateTime>
#include <QHash>
#include <QVector>
#include <QPair>
#include <QMutex>
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 外联速率/扇出监视器(有状态):按 pid 维护滑动窗口,研判速率突发与目标扇出。
// 输出为软信号(需互证)。线程安全。对应 .NET Engine/EgressRateMonitor.cs。
class EgressRateMonitor {
public:
    explicit EgressRateMonitor(int windowSeconds = 10, int rateThreshold = 40,
                               int fanoutThreshold = 20, int maxPids = 4096);

    ScoreResult observe(const SecurityEvent& e);
    void forget(int pid);
    int trackedProcessCount();

private:
    struct ProcState {
        QDateTime lastUtc;
        QVector<QPair<QString, QDateTime>> events;
        void add(const QString& remote, const QDateTime& at, int windowSecs);
        int countInWindow(const QDateTime& now, int windowSecs) const;
        int distinctTargetsInWindow(const QDateTime& now, int windowSecs) const;
    };
    void evictIfNeeded(const QDateTime& now);

    int windowSecs_ = 10;
    int rateThreshold_ = 40;
    int fanoutThreshold_ = 20;
    int maxPids_ = 4096;
    QHash<int, ProcState> byPid_;
    QMutex gate_;
};

} // namespace bulwark::engine
