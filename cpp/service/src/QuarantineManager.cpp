#include "bulwark/service/QuarantineManager.h"
#include "bulwark/service/Logger.h" // programDataDir()
#include "bulwark/json/JsonSupport.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QThread>

#include <algorithm>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace bulwark::service {
namespace {

// Streaming XOR copy: read src, XOR each byte with key, write dest. Reversible.
bool neutralizeCopy(const QString& src, const QString& dest, unsigned char key) {
    QFile in(src);
    if (!in.open(QIODevice::ReadOnly)) return false;
    QFile out(dest);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    constexpr qint64 kBuf = 1 << 16; // 64 KB
    QByteArray buf;
    buf.resize(kBuf);
    for (;;) {
        const qint64 n = in.read(buf.data(), kBuf);
        if (n < 0) return false;
        if (n == 0) break;
        for (qint64 i = 0; i < n; ++i)
            buf[i] = static_cast<char>(static_cast<unsigned char>(buf[i]) ^ key);
        if (out.write(buf.constData(), n) != n) return false;
    }
    out.close();
    in.close();
    return true;
}

// XOR-neutralize an in-memory buffer to the vault file. Used when user-mode can't read the
// original (exclusive lock / mapped image) and the kernel read it for us — we still produce
// the reversible vault copy in user mode. XOR is its own inverse, so restore works unchanged.
bool writeNeutralizedBuffer(const QByteArray& raw, const QString& dest, unsigned char key) {
    QFile out(dest);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    constexpr qint64 kBuf = 1 << 16; // 64 KB
    QByteArray buf;
    buf.resize(kBuf);
    const qint64 total = raw.size();
    qint64 pos = 0;
    while (pos < total) {
        const qint64 n = qMin<qint64>(kBuf, total - pos);
        for (qint64 i = 0; i < n; ++i)
            buf[i] = static_cast<char>(static_cast<unsigned char>(raw[static_cast<int>(pos + i)]) ^ key);
        if (out.write(buf.constData(), n) != n) return false;
        pos += n;
    }
    out.close();
    return true;
}

// Best-effort: schedule deletion on next reboot (payload was quarantined but the
// original is locked). Mirrors ProcessInspector.TryScheduleDeleteOnReboot.
void scheduleDeleteOnReboot(const QString& path) {
    MoveFileExW(reinterpret_cast<const wchar_t*>(path.utf16()), nullptr,
                MOVEFILE_DELAY_UNTIL_REBOOT);
}

} // namespace

QJsonObject QuarantineEntry::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o[QStringLiteral("id")] = guidToString(id);
    o[QStringLiteral("originalPath")] = originalPath;
    o[QStringLiteral("fileName")] = fileName;
    o[QStringLiteral("quarantinedUtc")] = dateTimeToIso(quarantinedUtc);
    o[QStringLiteral("size")] = static_cast<qint64>(size);
    o[QStringLiteral("sha256")] = sha256;
    o[QStringLiteral("reason")] = reason;
    o[QStringLiteral("actorPid")] = actorPid;
    return o;
}

QuarantineEntry QuarantineEntry::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    QuarantineEntry e;
    const QUuid id = guidFromString(getStr(o, "id"));
    if (!id.isNull()) e.id = id;
    e.originalPath = getStr(o, "originalPath");
    e.fileName = getStr(o, "fileName");
    const QDateTime t = dateTimeFromIso(getStr(o, "quarantinedUtc"));
    if (t.isValid()) e.quarantinedUtc = t;
    e.size = getI64(o, "size");
    e.sha256 = getStr(o, "sha256");
    e.reason = getStr(o, "reason");
    e.actorPid = getInt(o, "actorPid");
    return e;
}

QuarantineManager::QuarantineManager() {
    dir_ = QDir(programDataDir()).filePath(QStringLiteral("quarantine"));
    QDir().mkpath(dir_);
    indexPath_ = QDir(dir_).filePath(QStringLiteral("index.json"));
}

QString QuarantineManager::storePathFor(const QUuid& id) const {
    // 32-hex, no dashes (matches C# Guid "N" format); no extension.
    return QDir(dir_).filePath(id.toString(QUuid::WithoutBraces).remove(QLatin1Char('-')));
}

QString QuarantineManager::tryComputeSha256(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return QString();
    QCryptographicHash h(QCryptographicHash::Sha256);
    if (!h.addData(&f)) return QString();
    return QString::fromLatin1(h.result().toHex());
}

} // namespace bulwark::service

namespace bulwark::service {

void QuarantineManager::ensureLoaded() {
    if (loaded_) return;
    loaded_ = true; // even on failure, start empty (don't retry-thrash)
    QFile f(indexPath_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly)) return;
    const QByteArray raw = f.readAll();
    f.close();
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
    if (err.error != QJsonParseError::NoError || !doc.isArray()) return;
    const QJsonArray arr = doc.array();
    entries_.clear();
    entries_.reserve(arr.size());
    for (const QJsonValue& v : arr)
        if (v.isObject()) entries_.append(QuarantineEntry::fromJson(v.toObject()));
}

void QuarantineManager::saveIndex() {
    QJsonArray arr;
    for (const QuarantineEntry& e : entries_) arr.append(e.toJson());
    const QByteArray bytes = QJsonDocument(arr).toJson(QJsonDocument::Indented);
    // Atomic write: temp file then replace, so a half-write can't corrupt the index.
    const QString tmp = indexPath_ + QStringLiteral(".tmp");
    QFile tf(tmp);
    if (!tf.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    tf.write(bytes);
    tf.close();
    QFile::remove(indexPath_);
    if (!QFile::rename(tmp, indexPath_)) QFile::remove(tmp);
}

std::optional<QuarantineEntry> QuarantineManager::quarantine(
    const QString& filePath, const QString& reason, int actorPid, const QString& sha256,
    bool waitForUnlock) {
    if (filePath.trimmed().isEmpty()) return std::nullopt;

    QMutexLocker lk(&io_);
    ensureLoaded();
    if (!QFileInfo::exists(filePath)) return std::nullopt;

    // Already quarantined the same original path and the vault copy still exists.
    for (const QuarantineEntry& x : entries_)
        if (x.originalPath.compare(filePath, Qt::CaseInsensitive) == 0 &&
            QFileInfo::exists(storePathFor(x.id)))
            return x;

    const QFileInfo fi(filePath);
    QuarantineEntry entry;
    entry.originalPath = filePath;
    entry.fileName = fi.fileName();
    entry.size = fi.size();
    entry.sha256 = sha256;
    entry.reason = reason;
    entry.actorPid = actorPid;

    const QString dest = storePathFor(entry.id);
    // 1) 制作可逆金库副本(读原文件 -> XOR 中和 -> 写金库)。用户态因共享冲突 / 映像占用打不开读时,
    //    委托内核以「忽略共享访问检查」读出整文件,用户态照常中和写金库 —— 保住可逆隔离(非驱动
    //    做不到这一步)。内核不可用 / 旧驱动 / 仍失败则如常返回 nullopt(交后台重试或用户手动重试)。
    bool vaulted = neutralizeCopy(filePath, dest, kXorKey);
    if (!vaulted && kernelReader_) {
        QByteArray raw;
        if (kernelReader_(filePath, raw))
            vaulted = writeNeutralizedBuffer(raw, dest, kXorKey);
    }
    if (!vaulted) return std::nullopt;

    // 2) 金库副本已就绪 -> 删除原始载荷。先试用户态删除(锁定则重试;waitForUnlock=false 时只试一次
    //    绝不睡眠,避免卡主线程);仍删不掉且有内核委托时,请内核 POSIX 强制删除(可删被占用 / 已映射
    //    运行镜像的文件);再不行才回退「计划重启删除」。这一层内核强删正是「避免老是失败」的关键。
    bool deleted = false;
    const int attempts = waitForUnlock ? 5 : 1;
    for (int attempt = 0; attempt < attempts; ++attempt) {
        if (attempt > 0) QThread::msleep(static_cast<unsigned long>(attempt) * 500);
        if (QFile::remove(filePath)) { deleted = true; break; }
    }
    if (!deleted && kernelDeleter_ && kernelDeleter_(filePath))
        deleted = true;
    if (!deleted) scheduleDeleteOnReboot(filePath);

    entries_.append(entry);
    saveIndex();
    return entry;
}

QList<QuarantineEntry> QuarantineManager::list() {
    QMutexLocker lk(&io_);
    ensureLoaded();
    QList<QuarantineEntry> out = entries_;
    std::sort(out.begin(), out.end(), [](const QuarantineEntry& a, const QuarantineEntry& b) {
        return a.quarantinedUtc > b.quarantinedUtc; // newest first
    });
    return out;
}

bool QuarantineManager::restore(const QUuid& id) {
    QMutexLocker lk(&io_);
    ensureLoaded();
    int idx = -1;
    for (int i = 0; i < entries_.size(); ++i)
        if (entries_[i].id == id) { idx = i; break; }
    if (idx < 0) return false;

    const QuarantineEntry entry = entries_[idx];
    const QString src = storePathFor(entry.id);
    if (!QFileInfo::exists(src)) return false;

    QString target = entry.originalPath;
    const QString parent = QFileInfo(target).absolutePath();
    if (!parent.isEmpty()) QDir().mkpath(parent);
    if (QFileInfo::exists(target)) target += QStringLiteral(".restored");

    if (!neutralizeCopy(src, target, kXorKey)) return false; // XOR is its own inverse
    QFile::remove(src);
    entries_.removeAt(idx);
    saveIndex();
    return true;
}

bool QuarantineManager::purge(const QUuid& id) {
    QMutexLocker lk(&io_);
    ensureLoaded();
    int idx = -1;
    for (int i = 0; i < entries_.size(); ++i)
        if (entries_[i].id == id) { idx = i; break; }
    if (idx < 0) return false;

    QFile::remove(storePathFor(entries_[idx].id));
    entries_.removeAt(idx);
    saveIndex();
    return true;
}

} // namespace bulwark::service
