#include "ai/AiScanHistoryStore.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <algorithm>

AiScanHistoryStore::AiScanHistoryStore()
{
    const QString base = qEnvironmentVariable("ProgramData", QStringLiteral("C:/ProgramData"))
                         + QStringLiteral("/Bulwark");
    QDir().mkpath(base);
    path_ = base + QStringLiteral("/ai_scan_history.json");
    load();
}

void AiScanHistoryStore::load()
{
    QFile f(path_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly))
        return;
    const QByteArray data = f.readAll();
    f.close();
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (err.error != QJsonParseError::NoError || !doc.isArray())
        return;
    const QJsonArray arr = doc.array();
    records_.clear();
    records_.reserve(arr.size());
    for (const QJsonValue& v : arr)
        if (v.isObject())
            records_.append(AiScanResult::fromJson(v.toObject()));
}

void AiScanHistoryStore::append(const AiScanResult& record)
{
    {
        QMutexLocker lk(&lock_);
        records_.append(record);
        if (records_.size() > kMaxRecords) {
            // Trim oldest first: sort ascending by time, drop the front overflow.
            std::sort(records_.begin(), records_.end(),
                      [](const AiScanResult& a, const AiScanResult& b) {
                          return a.timestampUtc < b.timestampUtc;
                      });
            records_.remove(0, records_.size() - kMaxRecords);
        }
    }
    save();
}

QList<AiScanResult> AiScanHistoryStore::getAll() const
{
    QMutexLocker lk(&lock_);
    QList<AiScanResult> out = records_;
    std::sort(out.begin(), out.end(),
              [](const AiScanResult& a, const AiScanResult& b) {
                  return a.timestampUtc > b.timestampUtc; // newest first
              });
    return out;
}

void AiScanHistoryStore::clear()
{
    {
        QMutexLocker lk(&lock_);
        records_.clear();
    }
    save(); // 写入空数组,清空落盘历史
}

void AiScanHistoryStore::save()
{
    QJsonArray arr;
    {
        QMutexLocker lk(&lock_);
        for (const AiScanResult& r : records_)
            arr.append(r.toJson());
    }
    QFile f(path_);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        f.write(QJsonDocument(arr).toJson(QJsonDocument::Compact));
        f.close();
    }
}
