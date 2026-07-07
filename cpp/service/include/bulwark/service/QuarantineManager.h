#pragma once
#include <QString>
#include <QList>
#include <QUuid>
#include <QDateTime>
#include <QMutex>
#include <QJsonObject>
#include <optional>

namespace bulwark::service {

// 隔离区条目(金库副本 + 元数据)。
struct QuarantineEntry {
    QUuid id = QUuid::createUuid();
    QString originalPath;
    QString fileName;
    QDateTime quarantinedUtc = QDateTime::currentDateTimeUtc();
    qint64 size = 0;
    QString sha256;
    QString reason;
    int actorPid = 0;

    QJsonObject toJson() const;
    static QuarantineEntry fromJson(const QJsonObject& o);
};

// 文件隔离管理:XOR 中和拷贝到 %ProgramData%\Bulwark\quarantine\ 金库(可逆还原),
// 删除原文件(锁定则计划重启删除),index.json 原子落盘。线程安全。
// 注:原 C++ 头已丢失,此处按 QuarantineManager.cpp 用法重建。
class QuarantineManager {
public:
    QuarantineManager();

    std::optional<QuarantineEntry> quarantine(const QString& filePath, const QString& reason,
                                              int actorPid, const QString& sha256 = QString());
    QList<QuarantineEntry> list();
    bool restore(const QUuid& id);
    bool purge(const QUuid& id);

    static QString tryComputeSha256(const QString& path);

private:
    QString storePathFor(const QUuid& id) const;
    void ensureLoaded();
    void saveIndex();

    static constexpr unsigned char kXorKey = 0x5A;
    QString dir_;
    QString indexPath_;
    QList<QuarantineEntry> entries_;
    bool loaded_ = false;
    QMutex io_;
};

} // namespace bulwark::service
