#include "bulwark/service/VtScanHistoryStore.h"
#include "bulwark/service/Logger.h"

#include <QDir>
#include <QFile>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <algorithm>

namespace bulwark::service {
using bulwark::VtScanRecord;
using bulwark::VtScanStage;
using bulwark::VtScanOutcome;

VtScanHistoryStore::VtScanHistoryStore() {
    path_ = QDir(programDataDir()).filePath(QStringLiteral("vt_scan_history.json"));
    load();
}

void VtScanHistoryStore::load() {
    QFile f(path_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly)) return;
    const QByteArray data = f.readAll();
    f.close();
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (err.error != QJsonParseError::NoError || !doc.isArray()) return;
    const QJsonArray arr = doc.array();
    records_.clear();
    records_.reserve(arr.size());
    int dropped = 0;
    for (const QJsonValue& v : arr) {
        if (!v.isObject()) continue;
        const VtScanRecord r = VtScanRecord::fromJson(v.toObject());
        // 只保留「有结论的终态」记录。丢弃:①非终态(进行中)幽灵——历史里不该有仍在
        // 进行的扫描;②既无哈希又无路径的空壳记录——曾因压测/中途重启污染过历史,在
        // UI 里表现为一堆空白「进行中」条目。
        if (!r.isTerminal() || (r.sha256.isEmpty() && r.filePath.isEmpty())) {
            ++dropped;
            continue;
        }
        records_.append(r);
    }
    // 若本次载入清理掉了污染记录,立即回写一份干净历史,避免每次启动重复过滤、并让
    // 磁盘上的历史文件恢复整洁。
    if (dropped > 0)
        save();
}

std::optional<VtScanRecord> VtScanHistoryStore::tryGetFinishedByHash(const QString& sha256,
                                                                     qint64 unknownTtlSeconds) {
    if (sha256.isEmpty()) return std::nullopt;
    QMutexLocker lk(&lock_);
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const VtScanRecord* best = nullptr;
    for (const VtScanRecord& r : records_) {
        if (r.sha256.compare(sha256, Qt::CaseInsensitive) != 0) continue;
        if (r.stage != VtScanStage::Completed) continue;

        const bool conclusive = r.outcome == VtScanOutcome::Clean ||
                                r.outcome == VtScanOutcome::Suspicious ||
                                r.outcome == VtScanOutcome::Malicious;
        const bool unknown = r.outcome == VtScanOutcome::Unknown;
        if (!conclusive && !unknown) continue;

        if (unknown) {
            if (unknownTtlSeconds < 0) continue;
            if (r.timestampUtc.secsTo(now) > unknownTtlSeconds) continue;
        }
        if (!best || r.timestampUtc > best->timestampUtc) best = &r;
    }
    if (!best) return std::nullopt;
    return *best;
}

void VtScanHistoryStore::upsert(const VtScanRecord& record) {
    {
        QMutexLocker lk(&lock_);
        int idx = -1;
        for (int i = 0; i < records_.size(); ++i)
            if (records_.at(i).id == record.id) { idx = i; break; }
        if (idx >= 0) records_[idx] = record;
        else records_.append(record);

        if (records_.size() > kMaxRecords) {
            std::sort(records_.begin(), records_.end(),
                      [](const VtScanRecord& a, const VtScanRecord& b) { return a.timestampUtc < b.timestampUtc; });
            records_.remove(0, records_.size() - kMaxRecords);
        }
    }
    save();
}

QVector<VtScanRecord> VtScanHistoryStore::getAll() {
    QMutexLocker lk(&lock_);
    QVector<VtScanRecord> out = records_;
    std::sort(out.begin(), out.end(),
              [](const VtScanRecord& a, const VtScanRecord& b) { return a.timestampUtc > b.timestampUtc; });
    return out;
}

void VtScanHistoryStore::save() {
    QJsonArray arr;
    {
        QMutexLocker lk(&lock_);
        for (const VtScanRecord& r : records_) arr.append(r.toJson());
    }
    QFile f(path_);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        f.write(QJsonDocument(arr).toJson(QJsonDocument::Compact));
        f.close();
    }
}

} // namespace bulwark::service
