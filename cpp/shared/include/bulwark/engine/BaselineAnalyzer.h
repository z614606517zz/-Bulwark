#pragma once
#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QHash>
#include <QSet>
#include <QList>
#include <QMutex>
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 单程序行为画像的可序列化快照。
struct BaselineProgram {
    QString key;
    QDateTime firstSeenUtc;
    QDateTime lastSeenUtc;
    int childObs = 0, hostObs = 0, writeObs = 0;
    QStringList children, hosts, writeDirs;
};
struct BaselineSnapshot {
    QList<BaselineProgram> programs;
};

// 行为基线 / 异常检测器(有状态画像):为每个程序建立子进程/外联/写目录的正常画像,
// 显著偏离自身历史时产出软信号(需互证)。带学习期与高基数豁免。线程安全。
// 对应 .NET Engine/BaselineAnalyzer.cs。
class BaselineAnalyzer {
public:
    struct Result {
        int score = 0;
        QStringList reasons;
        bool deviation = false;
    };

    explicit BaselineAnalyzer(int minObservationsToEstablish = 12, int promiscuousThreshold = 60,
                              int maxProfiles = 8192, int maxSetSize = 256);

    Result observe(const SecurityEvent& e);
    int trackedProgramCount();

    BaselineSnapshot exportSnapshot();
    void importSnapshot(const BaselineSnapshot& snapshot);

private:
    enum class Dim { Child, Host, WriteDir };

    struct Profile {
        QDateTime firstSeenUtc;
        QDateTime lastSeenUtc;
        int childObs = 0, hostObs = 0, writeObs = 0;
        QSet<QString> children, hosts, writeDirs;

        QSet<QString>& setFor(Dim d);
        int obsFor(Dim d) const;
        void incObs(Dim d);
    };

    Result score(const QString& programKey, Dim dim, const QString& value,
                 const QDateTime& now, int deviationScore, const QString& deviationText);
    void evictIfNeeded(const QDateTime& now);

    int minObs_ = 12;
    int promiscuous_ = 60;
    int maxProfiles_ = 8192;
    int maxSetSize_ = 256;
    QHash<QString, Profile> profiles_;
    QMutex gate_;
};

} // namespace bulwark::engine
