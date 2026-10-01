#pragma once
#include <QString>
#include <QStringList>
#include <QList>
#include <utility>

#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/ChainEventInfo.h"
#include "bulwark/models/PersistenceEntry.h"
#include "bulwark/models/ThreatBehaviorProfile.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/QuarantineManager.h"

namespace bulwark::service {

// 足迹清理报告:已隔离文件 / 已移除的注册表持久化项 / 未能处理的残留(供 UI「重试」)。
struct RemediationReport {
    QStringList quarantinedFiles;
    QStringList removedRegistryValues;
    QList<bulwark::ipc::RemediationSkippedItem> skipped;
    // 持久化反重建:已成功清理的自启动项对应的【内核 RegHardBlock 就绪子串】(controlset/hive 无关的
    // "键\值" 尾段,如 SOFTWARE\...\Run\Evil、\Services\Evil\)。由 Worker 下发内核注册表硬拦,使恶意
    // 软件【无法立刻重建】刚被清掉的持久化(补上"清理→守护进程秒级重写"的竞态窗口)。非展示字段,
    // 不计入 totalActions(展示仍用 removedRegistryValues,那是带中文装饰的人读串)。
    QStringList hardenedRegTargets;
    int totalActions() const { return quarantinedFiles.size() + removedRegistryValues.size(); }
};

// 威胁清理器:对确认恶意的进程树,隔离其释放/关联文件(仅用户可写落地区、未签名),
// 并移除指向恶意文件的注册表自启动 / IFEO / 服务持久化(必要时夺取所有权强删);
// 也支持按持久化条目分类清理。Windows 专用。对应 .NET Storage/ThreatRemediator.cs。
class ThreatRemediator {
public:
    ThreatRemediator(QuarantineManager& quarantine, Logger logger);

    // profile:情报源(如 VT)提供的样本行为画像。其「已知释放文件路径」会被翻译到本机
    // 各用户目录后并入清理候选(补齐本地未观测到的释放物);沿用同样的落地区/签名护栏。
    RemediationReport remediate(const bulwark::SecurityEvent& malicious,
                                const QList<bulwark::ChainEventInfo>& footprint,
                                const bulwark::ThreatBehaviorProfile& profile = {});
    std::pair<bool, QString> forceQuarantine(const QString& path);
    RemediationReport cleanupPersistenceEntry(const bulwark::PersistenceEntry& entry);

    // 据「已知恶意 sha256」在本机用户可写落地区(Temp/Roaming/Downloads/Desktop/Public/
    // ProgramData/Windows\Temp)按哈希精确定位实际落地的样本/释放物。只读磁盘扫描,有界
    // (限深度/文件数/大小,跳过 node_modules 等大目录),【须在后台线程调用】——绝不碰主线程。
    // 返回命中的本机绝对路径,交由 remediate(profile.locatedLocalPaths) 隔离(绕过签名护栏)。
    static QStringList locateDroppedFilesByHash(const QStringList& maliciousHashes);

    // 位置护栏(不含签名判定):路径是否落在用户可写落地区、且不是系统目录 / 安装目录 /
    // 系统关键工具。与足迹清理的 isSafeToRemove 共用同一份名单 —— 释放物污点标记用它
    // 决定「哪些文件有资格被标」,不另抄一份。reason 非空时回填不合格原因。
    static bool isInUserDropZone(const QString& path, QString* reason = nullptr);

    // 登记本产品自己投放的勒索诱饵文件(2.4)。位置护栏会把它们一律判为「不可清理」。
    //
    // 为什么必须有:诱饵是刻意放在 Documents / Desktop / Pictures 里的普通文档,位置护栏
    // 看它就是「用户可写落地区里的一个文件」,完全合格。0.5 实测中同一次诱饵触碰导致足迹
    // 清理把【诱饵本身】搬进隔离区 3 次 —— 金库里堆进用户自己的文件、下次启动要重投,
    // 而且在重投之前蜜罐是空的:恰好是刚检出勒索、最不该失去这道防线的时刻。
    // 由 UserModeBehaviorSource 在每次投放后调用(整表替换,不累加)。
    static void setOwnCanaryFiles(const QStringList& paths);

private:
    void removeAutostartPersistence(const QStringList& maliciousFiles, RemediationReport& report);
    void removeIfeoPersistence(const QStringList& maliciousFiles, RemediationReport& report);
    void removeServicePersistence(const QStringList& maliciousFiles, RemediationReport& report);
    // 计划任务持久化。原先【整类不在自动足迹清理范围内】—— remediate() 只清 Run / IFEO / 服务
    // 三项,而 deleteScheduledTask 只挂在「用户从 UI 点清理某个持久化条目」那条路上。
    // 实测(2026-09-30):样本落 %APPDATA%\Microsoft\Windows\pigggggg.exe 后用 schtasks 注册了
    // 登录时触发的 \pigggggg,载荷被隔离了,任务却一直留着 —— 日志每次都说「移除自启动项 0 个」。
    void removeScheduledTaskPersistence(const QStringList& maliciousFiles, RemediationReport& report);

    void tryQuarantinePayload(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void removeRunValue(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void removeIfeoDebugger(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void resetWinlogonValue(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void clearAppInitDlls(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void quarantineStartupFile(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void deleteScheduledTask(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void disableService(const bulwark::PersistenceEntry& entry, RemediationReport& report);

    QuarantineManager& quarantine_;
    Logger log_;
};

} // namespace bulwark::service
