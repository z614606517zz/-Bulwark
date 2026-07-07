#pragma once
#include <QString>
#include <QStringList>
#include <QJsonObject>
#include <optional>

namespace bulwark {

// 自启动持久化点类别(对应不同 ATT&CK 持久化技战术)。
enum class PersistenceCategory {
    RegistryRun = 0,   // ...\CurrentVersion\Run(T1547.001)
    RegistryRunOnce,   // ...\RunOnce(T1547.001)
    StartupFolder,     // 启动文件夹(T1547.001)
    ScheduledTask,     // 计划任务(T1053.005)
    Service,           // Windows 服务(T1543.003)
    WmiSubscription,   // WMI 事件订阅(T1546.003)
    IfeoDebugger,      // 映像劫持 IFEO Debugger(T1546.012)
    Winlogon,          // Winlogon Userinit/Shell(T1547.004)
    AppInitDll,        // AppInit_DLLs(T1546.010)
    Other,
};

// 一条自启动持久化项快照(供持久化审计视图)。对应 .NET Models/PersistenceEntry.cs。
struct PersistenceEntry {
    QString id;                       // 稳定标识(类别+位置+名称哈希)
    PersistenceCategory category = PersistenceCategory::Other;
    QString name;
    QString location;
    QString command;
    QString imagePath;                // 可空
    std::optional<bool> isSigned;     // .NET bool? Signed;未采集为 nullopt
    QString publisher;                // 可空
    int riskScore = 0;
    QStringList riskReasons;
    QStringList techniques;

    QJsonObject toJson() const;
    static PersistenceEntry fromJson(const QJsonObject& o);
};

} // namespace bulwark
