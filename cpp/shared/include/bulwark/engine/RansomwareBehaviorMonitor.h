#pragma once
#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QHash>
#include <QVector>
#include <QSet>
#include <QMutex>
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 勒索行为监视器(有状态时序):按 pid 维护滑动窗口,统计批量改写速率、扩展名同化、
// 勒索信写入、蜜罐诱饵触碰。canaryHit=true 时调用方应直接 Block。线程安全。
// 对应 .NET Engine/RansomwareBehaviorMonitor.cs。
class RansomwareBehaviorMonitor {
public:
    struct Result {
        int score = 0;
        QStringList reasons;
        bool canaryHit = false;
        bool hardSignal = false;
    };

    explicit RansomwareBehaviorMonitor(int windowSeconds = 10, int burstThreshold = 12, int maxPids = 2048);

    void addCanaryFile(const QString& path);
    Result observe(const SecurityEvent& e);
    void forget(int pid);
    int trackedProcessCount();

private:
    struct Write { QString path; QDateTime at; QString ext; };

    struct ProcState {
        QDateTime lastActivityUtc;
        int ransomNoteCount = 0;
        QVector<Write> writes;
        QHash<QString, int> pathOccur;                    // 窗口内文件路径 -> 次数
        QHash<QString, QHash<QString, int>> extPaths;     // 扩展名 -> (路径 -> 次数)

        void touch(const QString& path, const QDateTime& at, int windowSecs);
        int distinctFilesInWindow() const { return pathOccur.size(); }
        int sameExtensionCount(const QString& ext) const;

        void addCounts(const QString& path, const QString& ext);
        void removeCounts(const QString& path, const QString& ext);
    };

    void evictIfNeeded(const QDateTime& now);

    int windowSecs_ = 10;
    int burstThreshold_ = 12;
    int maxPids_ = 2048;
    QHash<int, ProcState> byPid_;
    QSet<QString> canaryPaths_;
    QMutex gate_;
};

} // namespace bulwark::engine
