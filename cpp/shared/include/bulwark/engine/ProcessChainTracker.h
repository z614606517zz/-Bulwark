#pragma once
#include <QHash>
#include <QVector>
#include <QSet>
#include <QString>
#include <QDateTime>
#include <QMutex>

#include "bulwark/models/ChainEventInfo.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 进程链关联跟踪器:把孤立的安全事件按进程树聚合,使得对单个事件研判时能拿到「同一
// 攻击会话」的上下文(祖先做过什么、派生的子进程做过什么)。典型链:
//   winword.exe → powershell.exe(下载)→ dropper.exe(写 Temp)→ 改注册表启动项。
// 单看每步都不足以定性,串起来则是一次完整入侵。供 ThreatDetector/KillChainAnalyzer 整体研判。
// 线程安全:所有公共方法单锁串行;带容量上限与过期清理,避免长时间运行内存膨胀。
// 对应 .NET Bulwark.Core/Engine/ProcessChainTracker.cs。
class ProcessChainTracker {
public:
    explicit ProcessChainTracker(int maxEventsPerPid = 64, int maxPids = 4096,
                                 int retentionSeconds = 30 * 60);

    // 记录一个事件到进程链(登记 PID→父 PID 映射)。应在事件被处理时调用(无论裁决结果)。
    void record(const bulwark::SecurityEvent& e);

    // 某可执行文件是否在最近 withinSeconds 内被(其他进程)写入/释放过——识别 dropper。
    bool wasRecentlyWritten(const QString& path, int withinSeconds) const;

    // 为事件构建进程链上下文:祖先链 + 自身 + 直接子进程的事件,按时间升序去重,截断到 maxEvents。
    // 含传入事件本身(即便尚未 record),并并入事件自带的 chainContext(如富化种入的祖先链)。
    QVector<bulwark::ChainEventInfo> buildContext(const bulwark::SecurityEvent& e, int maxEvents = 12) const;

    // 收集以 rootPid 为根的整棵进程树(含后代)曾记录的全部事件,按时间升序。用于足迹清理。
    // 与 buildContext 不同:不截断、不向上回溯祖先,只向下纳入后代。
    QVector<bulwark::ChainEventInfo> collectTreeEvents(int rootPid) const;

    // 按 PID 反查最近记录到的真实映像路径。用于短命进程(如 reg.exe)在做完注册表/文件写入后
    // 立即退出、按 PID 实时反查失败时的回退:从其早先 ProcessCreate 记录里取回映像路径,
    // 使签名判定得以进行。返回该 PID 历史中最新的一条非占位映像路径;无记录则返回空。
    QString lastKnownPath(int pid) const;

    // 移除某进程的链记录(可在进程退出时调用,可选)。
    void forget(int pid);

    // 当前跟踪的进程数(诊断/测试)。
    int trackedProcessCount() const;

private:
    void evictIfNeeded();      // 需在持锁状态调用:过期 + 容量淘汰
    void removePid(int pid);   // 需在持锁状态调用
    static QString normalizePath(const QString& path);

    mutable QMutex gate_;
    QHash<int, QVector<bulwark::ChainEventInfo>> byPid_;   // PID -> 事件(时间升序)
    QHash<int, int> parent_;                               // 子 PID -> 父 PID
    QHash<int, QDateTime> firstSeen_;                      // PID -> 首见时间(过期清理)
    QHash<QString, QDateTime> recentExeWrites_;            // 规范化小写路径 -> 写入时间
    QSet<QString> executableWriteExt_;                     // 可执行/可加载落地扩展名(小写,含点)
    int maxEventsPerPid_;
    int maxPids_;
    qint64 retentionSecs_;
};

} // namespace bulwark::engine
