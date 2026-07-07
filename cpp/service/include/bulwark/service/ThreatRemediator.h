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

private:
    void removeAutostartPersistence(const QStringList& maliciousFiles, RemediationReport& report);
    void removeIfeoPersistence(const QStringList& maliciousFiles, RemediationReport& report);
    void removeServicePersistence(const QStringList& maliciousFiles, RemediationReport& report);

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
