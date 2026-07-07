#pragma once
#include "bulwark/service/EventSource.h"
#include "bulwark/service/Logger.h"

#include <QHash>
#include <QSet>
#include <QString>
#include <QStringList>

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
    bool enabled_ = true;
    bool canaryEnabled_ = true;
    bool started_ = false;

    QFileSystemWatcher* watcher_ = nullptr;
    QTimer* regTimer_ = nullptr;

    QStringList startupDirs_;
    QSet<QString> canaryFiles_;
    QHash<QString, QSet<QString>> startupBaseline_;       // dir -> {name|size|mtime}
    QHash<QString, QHash<QString, QString>> regBaseline_; // keyId -> (valueName -> data)

    Logger log_{QStringLiteral("bulwark.service.Behavior")};
};

} // namespace bulwark::service
