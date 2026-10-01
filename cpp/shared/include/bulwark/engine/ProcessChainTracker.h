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

    // 写入方身份。PID 会被复用(见 forget 的说明),故同时带上写入时的映像路径做校验。
    struct Writer {
        int pid = 0;
        QString path;   // 写入方映像路径(可能为空:短命进程未解析到)
        bool isValid() const { return pid > 0; }
    };

    // 某路径最近 withinSeconds 内的写入方(只覆盖可执行/可加载扩展名)。无记录返回 pid=0。
    Writer lastWriterOf(const QString& path, int withinSeconds) const;

    // rootPid(及其后代)在链里记录过的 FileWrite 目标 + 「最近写入」表里归属到这些 PID 的条目,
    // 去重后按首次出现顺序返回(原始大小写)。rootImagePath 非空时用它校验 rootPid 没被复用:
    // 映像路径不符的 rootPid 历史记录一律不收(占位路径 "PID N" / 空路径视为未知,照收)。
    QVector<QString> filesWrittenBy(int rootPid, const QString& rootImagePath = QString(),
                                    bool includeDescendants = true) const;

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

    //
    // 移除某进程的链记录。
    //
    // 【当前没有任何调用点,而且这不是遗漏 —— 是没有可用的信号】原注释写「可在进程退出时调用」,
    // 容易让人以为清理已经发生了。实际上本项目【没有「进程已退出」事件】:
    //   · EventType::ProcessTerminate 的语义是「有人请求结束某进程」,不是「某进程已退出」;
    //   · 驱动的进程通知在退出分支里直接 return(只摘内核 PID 集),不上报事件 —— 那是刻意的,
    //     全系统每个进程退出都发一条遥测会把事件环打满;
    //   · ETW 源只订阅了进程创建。
    // 同一结论在 AttackChainEngine.h 里也写过,那里因此改成了「时间窗 + 容量淘汰」。
    //
    // 后果(已知、有意接受):状态只按时间淘汰,故 Windows 复用 PID 时,新进程会在淘汰窗口内
    // 继承旧进程的链记录。窗口是有界的,且这些状态只用于加分/溯源而不单独定罪,影响可控。
    // 保留本方法而不删除:一旦将来引入进程退出遥测,这里就是接入点;测试也用它构造干净状态。
    //
    void forget(int pid);

    // 当前跟踪的进程数(诊断/测试)。
    int trackedProcessCount() const;

private:
    void evictIfNeeded();      // 需在持锁状态调用:过期 + 容量淘汰
    void removePid(int pid);   // 需在持锁状态调用
    QString lastKnownPathLocked(int pid) const; // 需在持锁状态调用
    static bool isPlaceholderPath(const QString& p); // 空 / "PID N" 占位
    static QString normalizePath(const QString& path);

    mutable QMutex gate_;
    QHash<int, QVector<bulwark::ChainEventInfo>> byPid_;   // PID -> 事件(时间升序)
    QHash<int, int> parent_;                               // 子 PID -> 父 PID
    QHash<int, QDateTime> firstSeen_;                      // PID -> 首见时间(过期清理)
    // 「最近写入」表的一条:时间 + 写入方(PID + 映像路径,用于释放物污点归属)+ 原始大小写路径。
    struct ExeWrite {
        QDateTime when;
        int writerPid = 0;
        QString writerPath;
        QString originalPath;
    };
    QHash<QString, ExeWrite> recentExeWrites_;             // 规范化小写路径 -> 写入记录
    QSet<QString> executableWriteExt_;                     // 可执行/可加载落地扩展名(小写,含点)
    int maxEventsPerPid_;
    int maxPids_;
    qint64 retentionSecs_;
};

} // namespace bulwark::engine
