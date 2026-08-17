#include "bulwark/models/JunkEntry.h"
#include "bulwark/json/JsonSupport.h"
#include <QJsonArray>

namespace bulwark {
using namespace bulwark::json;

namespace junk {

namespace {
// 键名与枚举一一对应。新增类别时【必须】同时在这里补一项 —— 漏补会让审计日志退化成
// "unknown",但不会让功能出错(categoryFromKey 的回落见下)。
struct KeyMap { Category c; const char* key; };
const KeyMap kKeys[] = {
    { Category::WindowsTemp,          "windows-temp" },
    { Category::RecycleBin,           "recycle-bin" },
    { Category::WindowsUpdateCache,   "windows-update-cache" },
    { Category::DeliveryOptimization, "delivery-optimization" },
    { Category::ErrorReports,         "error-reports" },
    { Category::ThumbnailCache,       "thumbnail-cache" },
    { Category::Prefetch,             "prefetch" },
    { Category::FontCache,            "font-cache" },
    { Category::SystemLogs,           "system-logs" },
    { Category::BrowserCache,         "browser-cache" },
    { Category::RecentDocs,           "recent-docs" },
    { Category::SelfLogs,             "self-logs" },
    { Category::WindowsOld,           "windows-old" },
    { Category::InstallerPatchCache,  "installer-patch-cache" },
    { Category::DefenderHistory,      "defender-history" },
    { Category::UpgradeLeftovers,     "upgrade-leftovers" },
    { Category::InternetCache,        "internet-cache" },
    { Category::ShaderCache,          "shader-cache" },
    { Category::PackageManagerCache,  "package-manager-cache" },
    { Category::GameLauncherCache,    "game-launcher-cache" },
    { Category::OfficeCache,          "office-cache" },
    { Category::SystemReserved,       "system-reserved" },
    { Category::SelfCache,            "self-cache" },
};
} // namespace

QString categoryKey(Category c) {
    for (const KeyMap& m : kKeys)
        if (m.c == c) return QString::fromLatin1(m.key);
    return QStringLiteral("unknown");
}

Category categoryFromKey(const QString& key) {
    const QString k = key.trimmed().toLower();
    for (const KeyMap& m : kKeys)
        if (k == QLatin1String(m.key)) return m.c;
    // 回落到 WindowsTemp 而不是抛异常:这个函数只服务于诊断入口的字符串解析,
    // 真正的 IPC 路径走序号。回落到一个【最保守的 Safe 类别】比拒绝服务更合适。
    return Category::WindowsTemp;
}

} // namespace junk

// ============================ JunkLocation ============================

QJsonObject JunkLocation::toJson() const {
    QJsonObject o;
    o["path"] = path;
    o["note"] = note;
    o["bytes"] = static_cast<double>(bytes);
    o["fileCount"] = fileCount;
    o["skipped"] = skipped;
    o["unreadable"] = unreadable;
    return o;
}

JunkLocation JunkLocation::fromJson(const QJsonObject& o) {
    JunkLocation l;
    l.path = getStr(o, "path");
    l.note = getStr(o, "note");
    l.bytes = getI64(o, "bytes");
    l.fileCount = getInt(o, "fileCount");
    l.skipped = getInt(o, "skipped");
    l.unreadable = getInt(o, "unreadable");
    return l;
}

// ============================ JunkCategoryResult ============================

QJsonObject JunkCategoryResult::toJson() const {
    QJsonObject o;
    o["category"] = static_cast<int>(category);
    // 键名与序号一起写:序号是机器读的契约,键名让审计与排障时人眼能直接看懂。
    o["categoryKey"] = junk::categoryKey(category);
    o["risk"] = static_cast<int>(risk);
    o["title"] = title;
    o["description"] = description;
    o["recommended"] = recommended;
    o["available"] = available;
    o["cleanable"] = cleanable;
    o["bytes"] = static_cast<double>(bytes);
    o["fileCount"] = fileCount;
    o["skipped"] = skipped;
    o["unreadable"] = unreadable;
    o["elapsedMs"] = static_cast<double>(elapsedMs);
    o["message"] = message;
    QJsonArray arr;
    for (const JunkLocation& l : locations) arr.append(l.toJson());
    o["locations"] = arr;
    return o;
}

JunkCategoryResult JunkCategoryResult::fromJson(const QJsonObject& o) {
    JunkCategoryResult r;
    r.category = static_cast<junk::Category>(getInt(o, "category"));
    r.risk = static_cast<junk::Risk>(getInt(o, "risk"));
    r.title = getStr(o, "title");
    r.description = getStr(o, "description");
    r.recommended = getBool(o, "recommended");
    r.available = getBool(o, "available", true);
    r.cleanable = getBool(o, "cleanable");
    r.bytes = getI64(o, "bytes");
    r.fileCount = getInt(o, "fileCount");
    r.skipped = getInt(o, "skipped");
    r.unreadable = getInt(o, "unreadable");
    r.elapsedMs = getI64(o, "elapsedMs");
    r.message = getStr(o, "message");
    for (const QJsonValue& v : o.value(QLatin1String("locations")).toArray())
        if (v.isObject()) r.locations.append(JunkLocation::fromJson(v.toObject()));
    return r;
}

// ============================ LargeFileEntry ============================

QJsonObject LargeFileEntry::toJson() const {
    QJsonObject o;
    o["path"] = path;
    o["bytes"] = static_cast<double>(bytes);
    o["lastModifiedUtc"] = dateTimeToIso(lastModifiedUtc);
    o["suffix"] = suffix;
    return o;
}

LargeFileEntry LargeFileEntry::fromJson(const QJsonObject& o) {
    LargeFileEntry e;
    e.path = getStr(o, "path");
    e.bytes = getI64(o, "bytes");
    e.lastModifiedUtc = dateTimeFromIso(getStr(o, "lastModifiedUtc"));
    e.suffix = getStr(o, "suffix");
    return e;
}

// ============================ JunkCleanOutcome ============================

QJsonObject JunkCleanOutcome::toJson() const {
    QJsonObject o;
    o["category"] = static_cast<int>(category);
    o["categoryKey"] = junk::categoryKey(category);
    o["title"] = title;
    o["success"] = success;
    o["freedBytes"] = static_cast<double>(freedBytes);
    o["deletedFiles"] = deletedFiles;
    o["deletedDirs"] = deletedDirs;
    o["skipped"] = skipped;
    o["message"] = message;
    return o;
}

JunkCleanOutcome JunkCleanOutcome::fromJson(const QJsonObject& o) {
    JunkCleanOutcome r;
    r.category = static_cast<junk::Category>(getInt(o, "category"));
    r.title = getStr(o, "title");
    r.success = getBool(o, "success");
    r.freedBytes = getI64(o, "freedBytes");
    r.deletedFiles = getInt(o, "deletedFiles");
    r.deletedDirs = getInt(o, "deletedDirs");
    r.skipped = getInt(o, "skipped");
    r.message = getStr(o, "message");
    return r;
}

} // namespace bulwark
