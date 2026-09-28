#include "bulwark/service/QuarantineManager.h"
#include "bulwark/service/Logger.h" // programDataDir()
#include "bulwark/service/AtomicFile.h"
#include "bulwark/json/JsonSupport.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QThread>

#include <algorithm>

// 与 main.cpp / IpcClientAuth.cpp 一致地加 #ifndef 守卫:这两个宏很可能已由先包含的
// 头文件(或 /D 命令行)定义过,无守卫的重定义在 /W4 下是 C4005,配 /WX 直接编译失败。
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace bulwark::service {
namespace {

Logger& log() { static Logger l(QStringLiteral("QuarantineManager")); return l; }

// Streaming XOR copy: read src, XOR each byte with key, write dest. Reversible.
// 中途失败【必须删掉半截的目标文件】。两个方向都致命:
//   · 隔离方向:金库里留下一个没进索引的残块,永远不会被清理;
//   · 还原方向:目标就是用户的原始路径,留下的是一个截断且仍被 XOR 打乱的文件,
//     而函数返回 false、上层报「还原失败」—— 用户看到的是"失败了却多出一个坏文件"。
bool neutralizeCopy(const QString& src, const QString& dest, unsigned char key) {
    QFile in(src);
    if (!in.open(QIODevice::ReadOnly)) return false;
    QFile out(dest);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;

    auto fail = [&out, &dest]() {
        out.close();
        QFile::remove(dest);   // 不留半截文件
        return false;
    };

    constexpr qint64 kBuf = 1 << 16; // 64 KB
    QByteArray buf;
    buf.resize(kBuf);
    for (;;) {
        const qint64 n = in.read(buf.data(), kBuf);
        if (n < 0) return fail();
        if (n == 0) break;
        for (qint64 i = 0; i < n; ++i)
            buf[i] = static_cast<char>(static_cast<unsigned char>(buf[i]) ^ key);
        if (out.write(buf.constData(), n) != n) return fail();
    }
    if (!out.flush()) return fail();   // 落盘失败同样算失败,别把它当成功
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
    auto fail = [&out, &dest]() {
        out.close();
        QFile::remove(dest);   // 同 neutralizeCopy:不留半截文件
        return false;
    };
    constexpr qint64 kBuf = 1 << 16; // 64 KB
    QByteArray buf;
    buf.resize(kBuf);
    const qint64 total = raw.size();
    qint64 pos = 0;
    while (pos < total) {
        const qint64 n = qMin<qint64>(kBuf, total - pos);
        for (qint64 i = 0; i < n; ++i)
            buf[i] = static_cast<char>(static_cast<unsigned char>(raw[static_cast<int>(pos + i)]) ^ key);
        if (out.write(buf.constData(), n) != n) return fail();
        pos += n;
    }
    if (!out.flush()) return fail();
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

    QFile f(indexPath_);
    if (!f.exists()) {
        loaded_ = true;                 // 首次运行:空隔离区是正确状态
        return;
    }
    if (!f.open(QIODevice::ReadOnly)) {
        // 【不要在这里置 loaded_】索引文件存在却打不开(共享冲突 / 权限 / 杀软占用)是
        // 【暂时性】失败。原实现在读之前就把 loaded_ 置成 true,于是本次内存态是空表,
        // 紧接着任何一次 quarantine() 都会 saveIndex() 把这张空表写回去 —— 之前所有
        // 隔离条目就此消失。金库文件是以 GUID 命名的 XOR 块、不含元数据,索引一丢,
        // 那些文件就永远还原不回去了,而且全过程无任何报错。
        // 保持 loaded_=false:本次调用按空表工作但【不落盘覆盖】,下次调用再重试读取。
        log().error(QStringLiteral("隔离区索引存在但无法打开,本次不加载且【不会覆盖】索引文件:%1")
                        .arg(indexPath_));
        return;
    }
    const QByteArray raw = f.readAll();
    f.close();
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
    if (err.error != QJsonParseError::NoError || !doc.isArray()) {
        // 内容确实损坏:留一份 .corrupt 备份再按空表继续,至少让人能手工抢救。
        const QString bak = indexPath_ + QStringLiteral(".corrupt");
        QFile::remove(bak);
        QFile::copy(indexPath_, bak);
        log().error(QStringLiteral("隔离区索引解析失败(%1),已备份为 %2 后按空表继续")
                        .arg(err.errorString(), bak));
        loaded_ = true;
        return;
    }
    const QJsonArray arr = doc.array();
    entries_.clear();
    entries_.reserve(arr.size());
    for (const QJsonValue& v : arr)
        if (v.isObject()) entries_.append(QuarantineEntry::fromJson(v.toObject()));
    loaded_ = true;
}

void QuarantineManager::saveIndex() {
    // 没成功加载过就绝不落盘:否则会用一张空表覆盖掉真实索引(见 ensureLoaded 的说明)。
    if (!loaded_) {
        log().error(QStringLiteral("隔离区索引尚未成功加载,跳过本次保存以免覆盖已有索引"));
        return;
    }
    QJsonArray arr;
    for (const QuarantineEntry& e : entries_) arr.append(e.toJson());
    const QByteArray bytes = QJsonDocument(arr).toJson(QJsonDocument::Indented);
    // 真正的原子替换(QSaveFile:写临时文件 + ReplaceFile 语义),而不是「先删再改名」。
    //
    // 原实现注释写着 "Atomic write",做的却是 remove(index) -> rename(tmp, index),而且
    // rename 失败时还把 tmp 也删掉 —— 两份都没了。index.json 是隔离文件唯一的元数据,
    // 丢了就等于所有已隔离文件永久无法还原。writeFileAtomically 本来就在同一个目录里
    // 摆着(SettingsStore / RuleStore 都在用),这里绕过它没有任何理由。
    if (!writeFileAtomically(indexPath_, bytes, QStringLiteral("隔离区索引")))
        log().error(QStringLiteral("隔离区索引落盘失败,内存态仍有效:%1").arg(indexPath_));
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
