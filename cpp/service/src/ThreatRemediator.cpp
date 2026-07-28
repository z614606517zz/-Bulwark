#include "bulwark/service/ThreatRemediator.h"
#include "bulwark/service/RegSurgery.h"
#include "bulwark/service/monitoring/ProcessInspector.h"

#include <QDir>
#include <QFileInfo>
#include <QProcess>
#include <QSet>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace bulwark::service {
namespace {

using bulwark::EventType;
namespace mon = bulwark::service::monitoring;

// Chinese literals as UTF-8 (relies on /utf-8), matching the rest of the port.
inline QString u(const char* s) { return QString::fromUtf8(s); }

const wchar_t* wstr(const QString& s) {
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

HKEY hiveToHkey(RegHive h) {
    switch (h) {
        case RegHive::LocalMachine:  return HKEY_LOCAL_MACHINE;
        case RegHive::CurrentUser:   return HKEY_CURRENT_USER;
        case RegHive::ClassesRoot:   return HKEY_CLASSES_ROOT;
        case RegHive::Users:         return HKEY_USERS;
        case RegHive::CurrentConfig: return HKEY_CURRENT_CONFIG;
    }
    return HKEY_LOCAL_MACHINE;
}

REGSAM viewToSam(RegView v) {
    switch (v) {
        case RegView::Registry32: return KEY_WOW64_32KEY;
        case RegView::Registry64: return KEY_WOW64_64KEY;
        default:                  return 0;
    }
}

// .NET opens WOW6432Node paths with the 64-bit view; everything else default.
RegView viewForSubKey(const QString& subKey) {
    return subKey.contains(QLatin1String("WOW6432Node"), Qt::CaseInsensitive)
               ? RegView::Registry64 : RegView::Default;
}

// Open a key; returns a handle (caller closes with RegCloseKey) or nullptr.
HKEY openKey(RegHive hive, const QString& subKey, RegView view, REGSAM access) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(hiveToHkey(hive), wstr(subKey), 0, access | viewToSam(view), &hk) == ERROR_SUCCESS)
        return hk;
    return nullptr;
}

// Read a string value (REG_SZ / REG_EXPAND_SZ); empty if absent or not a string.
QString readString(HKEY hk, const QString& name) {
    DWORD type = 0, cb = 0;
    if (RegQueryValueExW(hk, wstr(name), nullptr, &type, nullptr, &cb) != ERROR_SUCCESS) return QString();
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || cb == 0) return QString();
    QByteArray buf(static_cast<int>(cb), '\0');
    if (RegQueryValueExW(hk, wstr(name), nullptr, &type,
                         reinterpret_cast<BYTE*>(buf.data()), &cb) != ERROR_SUCCESS)
        return QString();
    const wchar_t* w = reinterpret_cast<const wchar_t*>(buf.constData());
    int wlen = static_cast<int>(cb / sizeof(wchar_t));
    while (wlen > 0 && w[wlen - 1] == L'\0') --wlen; // strip trailing null(s)
    return QString::fromWCharArray(w, wlen);
}

QStringList enumValueNames(HKEY hk) {
    QStringList out;
    wchar_t name[16384];
    for (DWORD idx = 0;; ++idx) {
        DWORD cch = 16384;
        const LSTATUS s = RegEnumValueW(hk, idx, name, &cch, nullptr, nullptr, nullptr, nullptr);
        if (s == ERROR_SUCCESS) out << QString::fromWCharArray(name, static_cast<int>(cch));
        else break; // ERROR_NO_MORE_ITEMS or error
    }
    return out;
}

QStringList enumSubKeyNames(HKEY hk) {
    QStringList out;
    wchar_t name[256];
    for (DWORD idx = 0;; ++idx) {
        DWORD cch = 256;
        const LSTATUS s = RegEnumKeyExW(hk, idx, name, &cch, nullptr, nullptr, nullptr, nullptr);
        if (s == ERROR_SUCCESS) out << QString::fromWCharArray(name, static_cast<int>(cch));
        else break;
    }
    return out;
}

// User-writable "drop zones" (lower-case). Only files here are cleaned.
// v2.0.2 扩展:增加更多常见恶意软件落地区(用户根目录、C盘根、公共目录)
const char* const kDropZones[] = {
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\appdata\\roaming\\",
    "\\appdata\\local\\", "\\downloads\\", "\\desktop\\", "\\documents\\",
    "\\users\\public\\", "\\programdata\\", "\\$recycle.bin\\", "\\perflogs\\",
    "\\users\\",        // 用户目录根(如 C:\Users\admin\malware.exe)
    "c:\\temp\\",       // C盘临时目录
    "c:\\tmp\\",        // C盘 tmp 目录
    "\\music\\",        // 音乐文件夹
    "\\videos\\",       // 视频文件夹
    "\\pictures\\",     // 图片文件夹
};

// Protected (never cleaned) zones - system and legit install dirs.
const char* const kProtectedZones[] = {
    "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\",
    "\\program files\\", "\\program files (x86)\\",
};

// System executables that must NEVER be cleaned (even if reported as dropped files).
// These are critical Windows utilities - deleting them breaks the system.
const char* const kSystemExecutables[] = {
    "cmd.exe", "powershell.exe", "pwsh.exe",           // Shells
    "conhost.exe", "taskmgr.exe", "regedit.exe",       // System tools
    "notepad.exe", "explorer.exe", "rundll32.exe",     // Core utilities
    "mshta.exe", "wscript.exe", "cscript.exe",         // Script hosts
    "reg.exe", "sc.exe", "net.exe", "netsh.exe",       // Admin tools
    "svchost.exe", "services.exe", "lsass.exe",        // System services
    "winlogon.exe", "csrss.exe", "smss.exe",           // Critical processes
    "wininit.exe", "dwm.exe", "taskhostw.exe",         // Desktop
    "msiexec.exe", "dllhost.exe", "runtimebroker.exe", // Runtime
};

struct RegLoc { RegHive hive; const char* subKey; };

// Autostart keys (enumerate values, delete those pointing at malicious files).
const RegLoc kAutostartKeys[] = {
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { RegHive::LocalMachine, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { RegHive::LocalMachine, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" },
    { RegHive::CurrentUser,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { RegHive::CurrentUser,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { RegHive::CurrentUser,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" },
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" },
};

// IFEO roots: a child's Debugger value pointing at a malicious file is a hijack.
const RegLoc kIfeoRoots[] = {
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" },
    { RegHive::LocalMachine, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" },
};

QString hiveName(RegHive h) {
    switch (h) {
        case RegHive::LocalMachine: return QStringLiteral("HKLM");
        case RegHive::CurrentUser:  return QStringLiteral("HKCU");
        case RegHive::Users:        return QStringLiteral("HKU");
        default:                    return QStringLiteral("HKLM");
    }
}

} // namespace
} // namespace bulwark::service

namespace bulwark::service {
namespace {

bulwark::ipc::RemediationSkippedItem mkSkip(const QString& target, const QString& reason, bool isFile) {
    bulwark::ipc::RemediationSkippedItem s;
    s.target = target;
    s.reason = reason;
    s.isFile = isFile;
    return s;
}

// 枚举本机真实用户配置目录(%SystemDrive%\Users\* 下的目录,排除公共/默认桩)。
QStringList localUserProfiles() {
    QStringList out;
    const QString drive = qEnvironmentVariable("SystemDrive", QStringLiteral("C:"));
    QDir usersDir(drive + QStringLiteral("\\Users"));
    for (const QFileInfo& fi : usersDir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        const QString name = fi.fileName();
        if (name.compare(QLatin1String("Public"), Qt::CaseInsensitive) == 0
            || name.compare(QLatin1String("Default"), Qt::CaseInsensitive) == 0
            || name.compare(QLatin1String("Default User"), Qt::CaseInsensitive) == 0
            || name.compare(QLatin1String("All Users"), Qt::CaseInsensitive) == 0)
            continue;
        out << fi.absoluteFilePath().replace(QLatin1Char('/'), QLatin1Char('\\'));
    }
    return out;
}

// 把沙箱报告里的释放路径翻译为本机候选路径:
//  - 含 "\Users\<name>\<tail>" 的,把 <tail> 重挂到本机每个用户目录下(沙箱用户名与本机不同);
//  - 其余(ProgramData / Windows / 具体盘符)视为机器无关,原样返回。
QStringList localCandidatesForDroppedPath(const QString& vtPath, const QStringList& userProfiles) {
    QStringList out;
    QString p = vtPath.trimmed();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (p.size() < 4) return out;
    const int usersIdx = p.toLower().indexOf(QStringLiteral("\\users\\"));
    if (usersIdx >= 0) {
        const int nameStart = usersIdx + 7; // 越过 "\Users\"
        const int nameEnd = p.indexOf(QLatin1Char('\\'), nameStart);
        if (nameEnd > nameStart) {
            const QString tail = p.mid(nameEnd + 1); // 例如 "AppData\Roaming\...\x.exe"
            if (!tail.isEmpty())
                for (const QString& prof : userProfiles)
                    out << (prof + QLatin1Char('\\') + tail);
        }
    } else if (p.size() > 2 && p[1] == QLatin1Char(':')) {
        out << p; // 机器无关的绝对路径(ProgramData / Windows / 盘符根)
    }
    return out;
}

// Rough check: does the string look like a local file path (drive/UNC + rooted)?
bool looksLikeFilePath(const QString& s) {
    if (s.size() < 4) return false;
    const bool hasRoot =
        (s.size() > 2 && s[1] == QLatin1Char(':') &&
         (s[2] == QLatin1Char('\\') || s[2] == QLatin1Char('/'))) ||
        s.startsWith(QLatin1String("\\\\"));
    if (!hasRoot) return false;
    if (s.startsWith(QLatin1String("\\REGISTRY"), Qt::CaseInsensitive)) return false; // kernel reg path
    return true;
}

// Does value data reference any malicious file (full-path substring, case-insensitive)?
bool referencesMalware(const QString& data, const QStringList& maliciousFiles) {
    if (data.isEmpty()) return false;
    for (const QString& mf : maliciousFiles)
        if (!mf.isEmpty() && data.contains(mf, Qt::CaseInsensitive)) return true;
    return false;
}

bool isInProtectedZone(const QString& path) {
    const QString lower = path.toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
    for (const char* z : kProtectedZones)
        if (lower.contains(QLatin1String(z))) return true;
    return false;
}

bool isSystemExecutable(const QString& path) {
    const QFileInfo fi(path);
    const QString fname = fi.fileName().toLower();
    for (const char* sysExe : kSystemExecutables)
        if (fname == QLatin1String(sysExe)) return true;
    return false;
}

// Safe to clean iff in a user-writable drop zone, not a system/install dir, and
// (unless the signature guard is bypassed) not trusted-signed.
bool isSafeToRemove(const QString& path, bool bypassSignatureGuard, QString& reason) {
    reason.clear();
    
    // 1) 系统可执行文件白名单 - 绝对不能删（即使被 VT 报告为释放物）
    if (isSystemExecutable(path)) { 
        reason = u("系统关键工具,绝对保护"); 
        return false; 
    }
    
    const QString lower = path.toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
    for (const char* z : kProtectedZones)
        if (lower.contains(QLatin1String(z))) { reason = u("位于系统/安装目录,保护不动"); return false; }
    bool inDrop = false;
    for (const char* z : kDropZones)
        if (lower.contains(QLatin1String(z))) { inDrop = true; break; }
    if (!inDrop) { reason = u("不在用户可写落地区,谨慎起见不清理"); return false; }
    if (!bypassSignatureGuard) {
        if (mon::ProcessInspector::isSigned(path)) { reason = u("带可信数字签名,保护不动"); return false; }
    }
    return true;
}

// Parse a persistence Location prefix (HKLM/HKCU/HKU) into a hive + subkey.
bool tryParseHive(const QString& location, RegHive& hive, QString& subKey) {
    hive = RegHive::LocalMachine;
    subKey.clear();
    const QString loc = location.trimmed();
    if (loc.isEmpty()) return false;
    const int slash = loc.indexOf(QLatin1Char('\\'));
    const QString prefix = slash < 0 ? loc : loc.left(slash);
    subKey = slash < 0 ? QString() : loc.mid(slash + 1);
    const QString up = prefix.toUpper();
    if (up == QLatin1String("HKLM") || up == QLatin1String("HKEY_LOCAL_MACHINE")) { hive = RegHive::LocalMachine; return true; }
    if (up == QLatin1String("HKCU") || up == QLatin1String("HKEY_CURRENT_USER")) { hive = RegHive::CurrentUser; return true; }
    if (up == QLatin1String("HKU")  || up == QLatin1String("HKEY_USERS"))        { hive = RegHive::Users; return true; }
    return false;
}

// Run a short command (schtasks/sc); returns (exitCode, stderr). Best-effort.
std::pair<int, QString> runProcess(const QString& fileName, const QStringList& args) {
    QProcess p;
    p.start(fileName, args);
    if (!p.waitForStarted(5000)) return { -1, u("无法启动进程") };
    if (!p.waitForFinished(15000)) { p.kill(); p.waitForFinished(1000); return { -2, u("执行超时") }; }
    const QString err = QString::fromLocal8Bit(p.readAllStandardError());
    return { p.exitCode(), err };
}

} // namespace
} // namespace bulwark::service

namespace bulwark::service {

ThreatRemediator::ThreatRemediator(QuarantineManager& quarantine, Logger logger)
    : quarantine_(quarantine), log_(std::move(logger)) {}

RemediationReport ThreatRemediator::remediate(const bulwark::SecurityEvent& malicious,
                                              const QList<bulwark::ChainEventInfo>& footprint,
                                              const bulwark::ThreatBehaviorProfile& profile) {
    RemediationReport report;

    // 1) collect the malicious-file set: files the tree dropped/wrote + the actor.
    QStringList maliciousFiles;
    QSet<QString> seenLower;
    auto consider = [&](const QString& path) {
        if (path.trimmed().isEmpty()) return;
        if (path.startsWith(QLatin1String("PID "))) return;
        if (!looksLikeFilePath(path)) return;
        const QString t = path.trimmed();
        const QString low = t.toLower();
        if (!seenLower.contains(low)) { seenLower.insert(low); maliciousFiles << t; }
    };

    consider(malicious.actorPath);

    // If the actor's own signature is untrusted (revoked/mismatch/signed-after-expiry),
    // the malicious verdict is based on signature abuse - do NOT let "has a signature"
    // exempt the actor from cleanup.
    const bool actorSignatureUntrusted =
        malicious.certRevoked || malicious.signatureMismatch || malicious.signedAfterCertExpiry;
    const QString actorPath = malicious.actorPath.trimmed();

    for (const bulwark::ChainEventInfo& ev : footprint)
        if (ev.type == EventType::FileWrite || ev.type == EventType::FileDelete)
            consider(ev.target);

    // 情报画像:把样本「已知释放文件」翻译到本机用户目录后并入清理候选,补齐本地未观测到的
    // 释放物(例如 Bulwark 在样本落地前就拦下、footprint 为空的情形)。
    // ⚠️ 这些文件虽有签名,但 VT 沙箱已确认为恶意释放物 → 绕过签名保护!
    QSet<QString> vtDroppedLower; // VT 确认的释放物(绕过签名护栏)
    if (!profile.droppedFilePaths.isEmpty()) {
        const QStringList userProfiles = localUserProfiles();
        for (const QString& vtPath : profile.droppedFilePaths) {
            for (const QString& cand : localCandidatesForDroppedPath(vtPath, userProfiles)) {
                consider(cand);
                vtDroppedLower.insert(cand.toLower());
            }
        }
    }

    // 据「已知恶意 sha256」在本机实际定位到的文件(哈希精确确认恶意):并入清理候选并标记。
    // 这些即使带合法数字签名(BYOVD 常见,如被滥用的 Adlice/TrueSight 驱动)也照隔离
    // —— 下方对其绕过「签名即豁免」护栏;但仍受落地区约束,绝不碰系统/安装目录。
    QSet<QString> hashConfirmedLower;
    for (const QString& p : profile.locatedLocalPaths) {
        const QString t = p.trimmed();
        if (t.isEmpty() || !looksLikeFilePath(t)) continue;
        consider(t);
        hashConfirmedLower.insert(t.toLower());
    }

    // 2) file cleanup: quarantine (not delete) drop-zone files.
    // 绕过签名保护的 3 种情况:
    //   1. 主体自身签名异常(revoked/mismatch/signed-after-expiry)
    //   2. 哈希精确匹配恶意(locatedLocalPaths)
    //   3. VT 沙箱确认的释放物(droppedFilePaths) ⭐ 新增
    for (const QString& path : maliciousFiles) {
        if (!QFileInfo::exists(path)) continue;
        const bool bypass = (actorSignatureUntrusted && path.compare(actorPath, Qt::CaseInsensitive) == 0)
                            || hashConfirmedLower.contains(path.toLower())
                            || vtDroppedLower.contains(path.toLower());
        QString why;
        if (!isSafeToRemove(path, bypass, why)) {
            report.skipped.append(mkSkip(path, why, true));
            continue;
        }
        const QString hash = QuarantineManager::tryComputeSha256(path);
        // waitForUnlock=false:不在本(可能是主/事件)线程上为被占用文件睡眠重试(否则多个残留会
        // 累计卡住数秒)。被独占锁定 / 已映射运行的镜像改由 QuarantineManager 内部委托内核
        // 「忽略共享访问检查」读取(做可逆金库副本)+ POSIX 强制删除即时清除,无需前台多次重试。
        const auto entry = quarantine_.quarantine(
            path,
            u("恶意进程释放/关联文件的足迹清理(主体 PID ") + QString::number(malicious.actorPid) + u(")"),
            malicious.actorPid, hash, /*waitForUnlock=*/false);
        if (entry.has_value()) {
            report.quarantinedFiles.append(path);
            log_.warning(u("足迹清理:已隔离恶意释放文件 ") + path);
        } else {
            report.skipped.append(mkSkip(path, u("隔离失败,可能被占用"), true));
        }
    }

    // 3) registry persistence pointing at the malicious files.
    removeAutostartPersistence(maliciousFiles, report);
    removeIfeoPersistence(maliciousFiles, report);
    removeServicePersistence(maliciousFiles, report);

    if (report.totalActions() > 0)
        log_.warning(u("足迹清理完成:隔离文件 ") + QString::number(report.quarantinedFiles.size())
                     + u(" 个,移除自启动项 ") + QString::number(report.removedRegistryValues.size()) + u(" 个。"));
    return report;
}

std::pair<bool, QString> ThreatRemediator::forceQuarantine(const QString& path) {
    if (path.trimmed().isEmpty()) return { false, u("路径为空") };
    if (!QFileInfo::exists(path)) return { false, u("文件不存在(可能已被移动或删除)") };
    const QString hash = QuarantineManager::tryComputeSha256(path);
    const auto entry = quarantine_.quarantine(path, u("用户手动强制隔离(清理报告重试)"), 0, hash);
    if (entry.has_value()) {
        log_.warning(u("手动强制隔离成功:") + path);
        return { true, u("已移入隔离区") };
    }
    return { false, u("隔离失败(文件可能被占用或权限不足)") };
}

// 据已知恶意 sha256 在本机落地区按哈希精确定位实际落地的文件(样本副本 / 释放物)。
// 只读、有界、后台线程调用:限深度 4、最多枚举 15 万文件 / 算 5000 次哈希、单文件 <=64MB,
// 仅对可执行/常被伪装的扩展名算哈希(图片/文本类仅小体积才算),跳过 node_modules 等大目录。
QStringList ThreatRemediator::locateDroppedFilesByHash(const QStringList& maliciousHashes) {
    QSet<QString> targets;
    for (const QString& h : maliciousHashes)
        if (h.size() == 64) targets.insert(h.toLower());
    if (targets.isEmpty()) return {};

    QStringList roots;
    for (const QString& prof : localUserProfiles()) {
        roots << prof + QStringLiteral("\\AppData\\Local")
              << prof + QStringLiteral("\\AppData\\Local\\Temp")
              << prof + QStringLiteral("\\AppData\\LocalLow")
              << prof + QStringLiteral("\\AppData\\Roaming")
              << prof + QStringLiteral("\\Downloads")
              << prof + QStringLiteral("\\Desktop")
              << prof + QStringLiteral("\\Documents");
    }
    const QString drive = qEnvironmentVariable("SystemDrive", QStringLiteral("C:"));
    roots << drive + QStringLiteral("\\Windows\\Temp")
          << drive + QStringLiteral("\\Users\\Public")
          << drive + QStringLiteral("\\ProgramData");

    static const QSet<QString> kHashExts = {
        QStringLiteral("exe"), QStringLiteral("dll"), QStringLiteral("sys"), QStringLiteral("scr"),
        QStringLiteral("ocx"), QStringLiteral("cpl"), QStringLiteral("com"), QStringLiteral("bin"),
        QStringLiteral("dat"), QStringLiteral("tmp"), QStringLiteral("jpg"), QStringLiteral("png"),
        QStringLiteral("gif"), QStringLiteral("ico"), QStringLiteral("txt"), QStringLiteral("log"),
        QStringLiteral("dmp"), QStringLiteral("db"),
    };
    static const QSet<QString> kSkipDirs = {
        QStringLiteral("node_modules"), QStringLiteral(".git"), QStringLiteral("cache"),
        QStringLiteral("gpucache"), QStringLiteral("code cache"), QStringLiteral("service worker"),
        QStringLiteral("blob_storage"), QStringLiteral("__bulwark_quarantine"),
    };
    const int kMaxDepth = 5, kMaxExamined = 200000, kMaxHash = 8000;
    const qint64 kMaxSize = 64LL * 1024 * 1024, kMediaCap = 8LL * 1024 * 1024;

    QStringList found;
    QSet<QString> foundLower;
    int examined = 0, hashed = 0;

    QStringList dirStack;
    QList<int> depthStack;
    for (const QString& r : roots)
        if (QFileInfo::exists(r)) { dirStack << r; depthStack << 0; }

    while (!dirStack.isEmpty() && examined < kMaxExamined && hashed < kMaxHash) {
        const QString dir = dirStack.takeLast();
        const int depth = depthStack.takeLast();
        QDir d(dir);
        const QFileInfoList files =
            d.entryInfoList(QDir::Files | QDir::NoSymLinks | QDir::Hidden | QDir::System);
        for (const QFileInfo& fi : files) {
            if (examined >= kMaxExamined || hashed >= kMaxHash) break;
            ++examined;
            const qint64 sz = fi.size();
            if (sz <= 0 || sz > kMaxSize) continue;
            const QString ext = fi.suffix().toLower();
            if (!kHashExts.contains(ext)) continue;
            const bool media = (ext == QLatin1String("jpg") || ext == QLatin1String("png")
                                || ext == QLatin1String("gif") || ext == QLatin1String("ico")
                                || ext == QLatin1String("txt") || ext == QLatin1String("log"));
            if (media && sz > kMediaCap) continue; // 真实照片/日志通常更大,跳过以省成本
            const QString h = QuarantineManager::tryComputeSha256(fi.absoluteFilePath()).toLower();
            ++hashed;
            if (!h.isEmpty() && targets.contains(h)) {
                QString p = fi.absoluteFilePath();
                p.replace(QLatin1Char('/'), QLatin1Char('\\'));
                if (!foundLower.contains(p.toLower())) { foundLower.insert(p.toLower()); found << p; }
            }
        }
        if (depth < kMaxDepth) {
            const QFileInfoList subs = d.entryInfoList(
                QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks | QDir::Hidden | QDir::System);
            for (const QFileInfo& sub : subs) {
                if (kSkipDirs.contains(sub.fileName().toLower())) continue;
                dirStack << sub.absoluteFilePath();
                depthStack << (depth + 1);
            }
        }
    }
    return found;
}

} // namespace bulwark::service

namespace bulwark::service {

void ThreatRemediator::removeAutostartPersistence(const QStringList& maliciousFiles, RemediationReport& report) {
    for (const RegLoc& loc : kAutostartKeys) {
        const QString subKey = QString::fromLatin1(loc.subKey);
        const RegView view = viewForSubKey(subKey);
        HKEY hk = openKey(loc.hive, subKey, view, KEY_READ | KEY_SET_VALUE);
        if (!hk) continue; // not present / not writable -> skip (matches .NET outer catch)

        for (const QString& valueName : enumValueNames(hk)) {
            const QString data = readString(hk, valueName);
            if (data.isEmpty() || !referencesMalware(data, maliciousFiles)) continue;

            const QString full = hiveName(loc.hive) + QLatin1Char('\\') + subKey + QLatin1Char('\\') + valueName;
            const LSTATUS st = RegDeleteValueW(hk, wstr(valueName));
            if (st == ERROR_SUCCESS) {
                report.removedRegistryValues.append(full);
                report.hardenedRegTargets.append(subKey + QLatin1Char('\\') + valueName);
                log_.warning(u("足迹清理:已删除自启动持久化项 ") + full);
            } else if (st == ERROR_ACCESS_DENIED) {
                if (RegSurgery::forceDeleteValue(loc.hive, subKey, valueName, view)) {
                    report.removedRegistryValues.append(full + u("(夺取所有权后删除)"));
                    report.hardenedRegTargets.append(subKey + QLatin1Char('\\') + valueName);
                    log_.warning(u("足迹清理:夺取所有权后删除自启动项 ") + full);
                } else {
                    report.skipped.append(mkSkip(full, u("受 ACL 保护,夺取所有权仍失败(建议手动删除)"), false));
                }
            } else {
                report.skipped.append(mkSkip(subKey + QLatin1Char('\\') + valueName, u("删除失败"), false));
            }
        }
        RegCloseKey(hk);
    }
}

void ThreatRemediator::removeIfeoPersistence(const QStringList& maliciousFiles, RemediationReport& report) {
    for (const RegLoc& loc : kIfeoRoots) {
        const QString root = QString::fromLatin1(loc.subKey);
        const RegView view = viewForSubKey(root);
        HKEY rootKey = openKey(loc.hive, root, view, KEY_READ);
        if (!rootKey) continue;

        for (const QString& sub : enumSubKeyNames(rootKey)) {
            const QString childPath = root + QLatin1Char('\\') + sub;
            HKEY child = openKey(loc.hive, childPath, view, KEY_READ);
            if (!child) continue;
            const QString dbg = readString(child, QStringLiteral("Debugger"));
            RegCloseKey(child);
            if (!referencesMalware(dbg, maliciousFiles)) continue;

            const QString full = hiveName(loc.hive) + QLatin1Char('\\') + childPath + u("\\Debugger");
            bool done = false;
            HKEY wk = openKey(loc.hive, childPath, view, KEY_SET_VALUE);
            if (wk) {
                if (RegDeleteValueW(wk, L"Debugger") == ERROR_SUCCESS) {
                    report.removedRegistryValues.append(full);
                    report.hardenedRegTargets.append(childPath + u("\\Debugger"));
                    log_.warning(u("足迹清理:已删除映像劫持(IFEO)项 ") + full);
                    done = true;
                }
                RegCloseKey(wk);
            }
            if (done) continue;

            if (RegSurgery::forceDeleteValue(loc.hive, childPath, QStringLiteral("Debugger"), view)) {
                report.removedRegistryValues.append(full + u("(夺取所有权后删除)"));
                report.hardenedRegTargets.append(childPath + u("\\Debugger"));
                log_.warning(u("足迹清理:夺取所有权后删除映像劫持项 ") + full);
            } else {
                report.skipped.append(mkSkip(
                    full, u("受 ACL 保护,夺取所有权仍失败(建议关闭 Defender 篡改保护后手动删除)"), false));
            }
        }
        RegCloseKey(rootKey);
    }
}

void ThreatRemediator::removeServicePersistence(const QStringList& maliciousFiles, RemediationReport& report) {
    const QString servicesPath = QStringLiteral("SYSTEM\\CurrentControlSet\\Services");
    HKEY servicesKey = openKey(RegHive::LocalMachine, servicesPath, RegView::Default, KEY_READ | DELETE);
    if (!servicesKey) return;

    for (const QString& svc : enumSubKeyNames(servicesKey)) {
        HKEY sk = openKey(RegHive::LocalMachine, servicesPath + QLatin1Char('\\') + svc, RegView::Default, KEY_READ);
        if (!sk) continue;
        const QString imagePath = readString(sk, QStringLiteral("ImagePath"));
        QString serviceDll;
        HKEY param = openKey(RegHive::LocalMachine,
                             servicesPath + QLatin1Char('\\') + svc + u("\\Parameters"), RegView::Default, KEY_READ);
        if (param) { serviceDll = readString(param, QStringLiteral("ServiceDll")); RegCloseKey(param); }
        RegCloseKey(sk);

        if (!referencesMalware(imagePath, maliciousFiles) && !referencesMalware(serviceDll, maliciousFiles))
            continue;

        const QString full = u("HKLM\\SYSTEM\\CurrentControlSet\\Services\\") + svc;
        const LSTATUS st = RegDeleteTreeW(servicesKey, wstr(svc));
        if (st == ERROR_SUCCESS) {
            report.removedRegistryValues.append(full);
            report.hardenedRegTargets.append(u("\\Services\\") + svc + QLatin1Char('\\'));
            log_.warning(u("足迹清理:已删除指向恶意文件的服务 ") + full);
        } else if (st == ERROR_ACCESS_DENIED) {
            if (RegSurgery::forceDeleteSubKeyTree(RegHive::LocalMachine, servicesPath, svc, RegView::Default)) {
                report.removedRegistryValues.append(full + u("(夺取所有权后删除)"));
                report.hardenedRegTargets.append(u("\\Services\\") + svc + QLatin1Char('\\'));
                log_.warning(u("足迹清理:夺取所有权后删除恶意服务 ") + full);
            } else {
                report.skipped.append(mkSkip(full, u("受 ACL 保护,夺取所有权仍失败(建议手动删除该服务)"), false));
            }
        } else {
            report.skipped.append(mkSkip(u("Services\\") + svc, u("删除失败"), false));
        }
    }
    RegCloseKey(servicesKey);
}

} // namespace bulwark::service

namespace bulwark::service {

RemediationReport ThreatRemediator::cleanupPersistenceEntry(const bulwark::PersistenceEntry& entry) {
    RemediationReport report;
    using PC = bulwark::PersistenceCategory;

    // 1) quarantine the payload (reversible), except StartupFolder (its branch handles it).
    if (entry.category != PC::StartupFolder)
        tryQuarantinePayload(entry, report);

    // 2) remove the autostart hook, category by category (safe handling).
    switch (entry.category) {
        case PC::RegistryRun:
        case PC::RegistryRunOnce: removeRunValue(entry, report); break;
        case PC::IfeoDebugger:    removeIfeoDebugger(entry, report); break;
        case PC::Winlogon:        resetWinlogonValue(entry, report); break;
        case PC::AppInitDll:      clearAppInitDlls(entry, report); break;
        case PC::StartupFolder:   quarantineStartupFile(entry, report); break;
        case PC::ScheduledTask:   deleteScheduledTask(entry, report); break;
        case PC::Service:         disableService(entry, report); break;
        default:
            report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name,
                                         u("暂不支持自动清理该类别,请手动处理"), false));
            break;
    }

    if (report.totalActions() > 0)
        log_.warning(u("用户清理自启动项:隔离文件 ") + QString::number(report.quarantinedFiles.size())
                     + u(" 个,处理持久化 ") + QString::number(report.removedRegistryValues.size()) + u(" 项。"));
    return report;
}

void ThreatRemediator::tryQuarantinePayload(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    const QString path = entry.imagePath;
    if (path.trimmed().isEmpty() || !QFileInfo::exists(path)) return;
    if (isInProtectedZone(path)) {
        report.skipped.append(mkSkip(path, u("位于系统/安装目录,保护不动(仅移除自启动挂钩)"), true));
        return;
    }
    const QString hash = QuarantineManager::tryComputeSha256(path);
    const auto q = quarantine_.quarantine(path, u("用户手动清理自启动项载荷"), 0, hash);
    if (q.has_value()) report.quarantinedFiles.append(path);
    else report.skipped.append(mkSkip(path, u("隔离失败(可能被占用)"), true));
}

void ThreatRemediator::removeRunValue(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    RegHive hive; QString subKey;
    if (!tryParseHive(entry.location, hive, subKey)) {
        report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("无法解析注册表位置"), false));
        return;
    }
    const QString valueName = entry.name;
    bool removed = false, sawValue = false;
    for (RegView view : { RegView::Registry64, RegView::Registry32 }) {
        HKEY hk = openKey(hive, subKey, view, KEY_READ | KEY_SET_VALUE);
        if (hk) {
            bool exists = false;
            for (const QString& n : enumValueNames(hk))
                if (n.compare(valueName, Qt::CaseInsensitive) == 0) { exists = true; break; }
            if (exists) {
                sawValue = true;
                const LSTATUS st = RegDeleteValueW(hk, wstr(valueName));
                if (st == ERROR_SUCCESS) removed = true;
                else if (st == ERROR_ACCESS_DENIED && RegSurgery::forceDeleteValue(hive, subKey, valueName, view)) removed = true;
            }
            RegCloseKey(hk);
        } else if (RegSurgery::forceDeleteValue(hive, subKey, valueName, view)) {
            sawValue = true; removed = true; // ACL-locked key: blind force-delete
        }
    }
    if (removed) report.removedRegistryValues.append(entry.location + QLatin1Char('\\') + valueName);
    else report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name,
             sawValue ? u("受 ACL 保护,删除失败(建议手动删除)") : u("值不存在(可能已被移除)"), false));
}

void ThreatRemediator::removeIfeoDebugger(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    RegHive hive; QString subKey;
    if (!tryParseHive(entry.location, hive, subKey)) {
        report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("无法解析注册表位置"), false));
        return;
    }
    bool removed = false, sawValue = false;
    HKEY hk = openKey(hive, subKey, RegView::Registry64, KEY_READ | KEY_SET_VALUE);
    if (hk) {
        if (RegQueryValueExW(hk, L"Debugger", nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            sawValue = true;
            const LSTATUS st = RegDeleteValueW(hk, L"Debugger");
            if (st == ERROR_SUCCESS) removed = true;
            else if (st == ERROR_ACCESS_DENIED &&
                     RegSurgery::forceDeleteValue(hive, subKey, QStringLiteral("Debugger"), RegView::Registry64))
                removed = true;
        }
        RegCloseKey(hk);
    } else if (RegSurgery::forceDeleteValue(hive, subKey, QStringLiteral("Debugger"), RegView::Registry64)) {
        sawValue = true; removed = true;
    }
    if (removed) report.removedRegistryValues.append(entry.location + u("\\Debugger"));
    else report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name,
             sawValue ? u("受 ACL 保护,删除失败(建议手动删除)") : u("Debugger 值不存在(可能已被移除)"), false));
}

} // namespace bulwark::service

namespace bulwark::service {

void ThreatRemediator::resetWinlogonValue(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    RegHive hive; QString subKey;
    if (!tryParseHive(entry.location, hive, subKey)) {
        report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("无法解析注册表位置"), false));
        return;
    }
    const QString valueName = entry.name;
    QString def;
    if (valueName.compare(QLatin1String("Userinit"), Qt::CaseInsensitive) == 0) {
        wchar_t sysdir[MAX_PATH] = {};
        GetSystemDirectoryW(sysdir, MAX_PATH);
        def = QString::fromWCharArray(sysdir) + u("\\userinit.exe,");
    } else if (valueName.compare(QLatin1String("Shell"), Qt::CaseInsensitive) == 0) {
        def = QStringLiteral("explorer.exe");
    } else {
        report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name,
                                     u("未知 Winlogon 值,未改动(避免破坏登录)"), false));
        return;
    }
    HKEY hk = openKey(hive, subKey, RegView::Registry64, KEY_SET_VALUE);
    if (!hk) { report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("Winlogon 键不可写"), false)); return; }
    const QByteArray data(reinterpret_cast<const char*>(def.utf16()),
                          static_cast<int>((def.size() + 1) * sizeof(ushort)));
    const LSTATUS st = RegSetValueExW(hk, wstr(valueName), 0, REG_SZ,
                                      reinterpret_cast<const BYTE*>(data.constData()),
                                      static_cast<DWORD>(data.size()));
    RegCloseKey(hk);
    if (st == ERROR_SUCCESS)
        report.removedRegistryValues.append(entry.location + QLatin1Char('\\') + valueName + u("(已重置为默认:") + def + u(")"));
    else
        report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("重置失败"), false));
}

void ThreatRemediator::clearAppInitDlls(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    RegHive hive; QString subKey;
    if (!tryParseHive(entry.location, hive, subKey)) {
        report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("无法解析注册表位置"), false));
        return;
    }
    bool cleared = false;
    for (RegView view : { RegView::Registry64, RegView::Registry32 }) {
        HKEY hk = openKey(hive, subKey, view, KEY_READ | KEY_SET_VALUE);
        if (!hk) continue;
        const QString cur = readString(hk, QStringLiteral("AppInit_DLLs"));
        if (!cur.isEmpty()) {
            const wchar_t empty[1] = { L'\0' };
            if (RegSetValueExW(hk, L"AppInit_DLLs", 0, REG_SZ,
                               reinterpret_cast<const BYTE*>(empty), sizeof(empty)) == ERROR_SUCCESS)
                cleared = true;
            DWORD zero = 0;
            RegSetValueExW(hk, L"LoadAppInit_DLLs", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&zero), sizeof(zero));
        }
        RegCloseKey(hk);
    }
    if (cleared) report.removedRegistryValues.append(entry.location + u("\\AppInit_DLLs(已清空)"));
    else report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("清空失败或已为空"), false));
}

void ThreatRemediator::quarantineStartupFile(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    QString path = !entry.imagePath.trimmed().isEmpty() ? entry.imagePath : entry.command;
    if (path.trimmed().isEmpty() || !QFileInfo::exists(path)) {
        report.skipped.append(mkSkip(
            path.trimmed().isEmpty() ? (entry.location + QLatin1Char('\\') + entry.name) : path,
            u("启动项文件不存在(可能已被移除)"), true));
        return;
    }
    const QString hash = QuarantineManager::tryComputeSha256(path);
    const auto q = quarantine_.quarantine(path, u("用户手动清理启动文件夹项"), 0, hash);
    if (q.has_value()) report.quarantinedFiles.append(path);
    else report.skipped.append(mkSkip(path, u("隔离失败(可能被占用)"), true));
}

void ThreatRemediator::deleteScheduledTask(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    QString name = QString(entry.name).replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (name.startsWith(QLatin1Char('\\'))) name = name.mid(1);
    const QString tn = QStringLiteral("\\") + name;
    const auto r = runProcess(QStringLiteral("schtasks.exe"),
                              { QStringLiteral("/delete"), QStringLiteral("/tn"), tn, QStringLiteral("/f") });
    if (r.first == 0) {
        report.removedRegistryValues.append(u("计划任务 ") + tn + u("(已删除)"));
    } else {
        const QString extra = r.second.trimmed().isEmpty() ? QString() : (u(":") + r.second.trimmed());
        report.skipped.append(mkSkip(u("计划任务 ") + tn,
            u("schtasks 失败(退出码 ") + QString::number(r.first) + u(")") + extra, false));
    }
}

void ThreatRemediator::disableService(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    const QString name = entry.name;
    runProcess(QStringLiteral("sc.exe"), { QStringLiteral("stop"), name }); // best-effort stop
    HKEY hk = openKey(RegHive::LocalMachine,
                      u("SYSTEM\\CurrentControlSet\\Services\\") + name, RegView::Default, KEY_SET_VALUE);
    if (!hk) {
        report.skipped.append(mkSkip(u("服务 ") + name, u("服务键不存在或不可写"), false));
        return;
    }
    DWORD four = 4; // SERVICE_DISABLED
    const LSTATUS st = RegSetValueExW(hk, L"Start", 0, REG_DWORD,
                                      reinterpret_cast<const BYTE*>(&four), sizeof(four));
    RegCloseKey(hk);
    if (st == ERROR_SUCCESS)
        report.removedRegistryValues.append(u("服务 ") + name + u("(已停止并禁用,可在服务管理器恢复)"));
    else
        report.skipped.append(mkSkip(u("服务 ") + name, u("禁用失败"), false));
}

} // namespace bulwark::service
