#pragma once
#include <QString>
#include <QDateTime>
#include <QHash>
#include <QVector>
#include <QMutex>
#include <utility>
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 有状态 C2 信标检测:按 (pid|远端) 记录外联时间序列,分析周期性/抖动(CV),
// 命中周期性回连即评分。线程安全(内部互斥)。对应 .NET Engine/BeaconDetector.cs。
class BeaconDetector {
public:
    // minSamples 默认从 4 提到 6:4 个样本只有 3 个间隔,任何定时轮询(更新检查、订阅刷新、
    // 云盘同步)都会在头几次外联就被算出「低抖动」。6 个样本 = 5 个间隔,统计上才站得住,
    // 也才拉开「程序化 C2 回连」与「正常定时任务」的差距。
    explicit BeaconDetector(int minSamples = 6, int maxSeries = 1024, qint64 retentionSecs = 0);

    ScoreResult observe(const SecurityEvent& e);
    void forget(int pid);
    int trackedSeriesCount();

    // 单个 (pid|远端) 的外联时间序列。
    struct Series {
        QVector<QDateTime> times;
        QDateTime lastUtc;
        int count = 0;
        QString actorPath;
        QString remote;
        void add(const QDateTime& at);
        QVector<double> intervalsSeconds() const;
    };

    // 返回 {均值, 变异系数 CV};空序列 CV 取极大值。
    static std::pair<double, double> meanAndCv(const QVector<double>& intervals);

private:
    void evictIfNeeded(const QDateTime& now);

    int minSamples_ = 6;
    int maxSeries_ = 1024;
    qint64 retentionSecs_ = 0;
    QHash<QString, Series> series_;
    QMutex gate_;
};

} // namespace bulwark::engine
