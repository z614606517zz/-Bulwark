#pragma once
#include <optional>
#include <QString>
#include <QVector>
#include <QMutex>
#include "bulwark/models/VtScanRecord.h"

namespace bulwark::service {

// VirusTotal 扫描历史持久化(JSON)。%ProgramData%\Bulwark\vt_scan_history.json。
// 去重记忆 + 持久展示;按 id upsert,容量上限裁剪。线程安全。
// 对应 .NET Storage/VtScanHistoryStore.cs。
class VtScanHistoryStore {
public:
    VtScanHistoryStore();

    // 按 SHA-256 取最近一次「已完成」记录用于去重。确定性结论永久去重;Unknown 仅在
    // unknownTtlSeconds 内去重(<0 表示不去重 Unknown);Error/Pending 永不去重。
    std::optional<bulwark::VtScanRecord> tryGetFinishedByHash(const QString& sha256,
                                                              qint64 unknownTtlSeconds = -1);
    void upsert(const bulwark::VtScanRecord& record);
    QVector<bulwark::VtScanRecord> getAll(); // 按时间倒序

private:
    void load();
    void save();

    static constexpr int kMaxRecords = 1000;
    QString path_;
    QVector<bulwark::VtScanRecord> records_;
    QMutex lock_;
};

} // namespace bulwark::service
