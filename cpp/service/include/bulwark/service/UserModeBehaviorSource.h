#pragma once
#include "bulwark/service/EventSource.h"
#include "bulwark/service/Logger.h"

#include <QHash>
#include <QSet>
#include <QString>
#include <QStringList>

#include <functional>

class QFileSystemWatcher;
class QTimer;
namespace bulwark::engine { class RuleEngine; }

namespace bulwark::service {

// 用户态「持续行为监控」事件源(无需内核驱动)。补上 ETW/WMI 基础源对程序运行【之后】
// 危险行为的盲区,两类低误报的事后监控:
//   1) 自启动持久化:监视启动文件夹(用户 + 公共)新增/变更 + 轮询 Run/RunOnce/Policies
//      \Explorer\Run(HKLM+HKCU+Wow6432Node)基线增量,只报新增/变更项;
//   2) 勒索蜜罐诱饵:在文档/桌面/图片投放隐藏诱饵并登记到 RuleEngine 的勒索监视器,
//      任何进程改写/删除诱饵即强勒索信号(引擎侧 canaryHit -> Block)。
// 诚实局限:用户态拿不到"谁写的",自启动事件 ActorPid=0 以被持久化目标程序评估可信度;
// 诱饵命中只告警不结束进程。精确归因/写入前拦截需内核驱动。事件富化(签名/哈希)由
// Worker::enrich 统一完成。对应 .NET Monitoring/UserModeBehaviorSource.cs。
class UserModeBehaviorSource : public EventSource {
    Q_OBJECT
public:
    explicit UserModeBehaviorSource(bulwark::engine::RuleEngine& engine, QObject* parent = nullptr);
    ~UserModeBehaviorSource() override;

    void start() override;
    void stop() override;

    // 由 Worker 按 RuntimeSettings 实时设置(主线程)。
    void setEnabled(bool on) { enabled_ = on; }
    void setCanaryEnabled(bool on) { canaryEnabled_ = on; }

    //
    // 诱饵路径的第二个去处(可空;当前由 main 接到 ETW 源的写入归因表)。
    //
    // 存在的理由就是上面「诚实局限」里那句「用户态拿不到『谁写的』」:诱饵靠
    // QFileSystemWatcher 发现,那个通知只说「文件变了」。而引擎对 canaryHit 是无条件 Block
    // 加 100 分硬指标 —— 拿不到写入者 PID,这个 Block 就没有对象,最终只落「仅告警」。
    // 接上之后,Kernel-File 的 Write 事件(事件头 ProcessId 即写入者)会补出那一位,
    // 诱饵命中才真的能结束勒索进程树。
    //
    // 未接线,或 Etw.KernelFileWriteAttribution 未打开时,行为与从前完全一致。
    //
    using CanarySink = std::function<void(const QString& canaryPath)>;
    void setCanarySink(CanarySink fn) { canarySink_ = std::move(fn); }

private slots:
    void onDirectoryChanged(const QString& dir); // 启动文件夹变更
    void onFileChanged(const QString& path);      // 诱饵被改写/删除
    void pollRegistry();                          // 4s 轮询自启动注册表基线增量

private:
    void startStartupWatchers();
    void deployCanaries();
    void snapshotStartup();
    void scanRegistryDelta(bool emitEvents);
    void emitAutorunFile(const QString& filePath, const QString& target);
    void emitAutorunReg(const QString& regPath, const QString& valueName,
                        const QString& valueData, const QString& target);

    bulwark::engine::RuleEngine& engine_;
    CanarySink canarySink_;              // 诱饵写入归因的登记去处(可空)
    bool enabled_ = true;
    bool canaryEnabled_ = true;
    bool started_ = false;

    QFileSystemWatcher* watcher_ = nullptr;
    QTimer* regTimer_ = nullptr;

    QStringList startupDirs_;
    QSet<QString> canaryFiles_;
    // 同一次诱饵触碰的去重(见 onFileChanged)。Windows 对一次写生成多个变更通知,
    // 逐条走完整处置会把同一件事刷成 4 条拦截 + 3 次清理(0.5 实测)。
    QHash<QString, qint64> canaryLastEventMs_;
    qint64 canarySuppressed_ = 0;
    static constexpr qint64 kCanaryDebounceMs = 3000;
    QHash<QString, QSet<QString>> startupBaseline_;       // dir -> {name|size|mtime}
    QHash<QString, QHash<QString, QString>> regBaseline_; // keyId -> (valueName -> data)

    Logger log_{QStringLiteral("bulwark.service.Behavior")};
};

} // namespace bulwark::service
