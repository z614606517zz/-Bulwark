#include "bulwark/service/ThreatRemediator.h"
#include "bulwark/service/RegSurgery.h"
#include "bulwark/service/monitoring/ProcessInspector.h"

#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QSet>

#include <atomic>
#include <iterator>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
// 计划任务的删除走 COM(ITaskService),不 spawn schtasks.exe —— 理由与 SystemHardening 头部
// 那条「不用 icacls / reg」完全相同:本产品自带命令行硬拦,一个安全产品去起 schtasks 来清
// 持久化,既会被自己的检测盯上(实测日志里就有一条「执行前拦截已跳过…schtasks.exe」),
// 又给「劫持 schtasks.exe」这种绕过递上一个现成入口。ole32/oleaut32 已在 CMake 里链着
// (ProcessOriginResolver 早就在用 ITaskService)。
#include <oleauto.h>
#include <taskschd.h>

namespace bulwark::service {
namespace {

using bulwark::EventType;
namespace mon = bulwark::service::monitoring;

// 「本进程是否已经报过一次覆盖面」。见 removeAutostartPersistence / removeScheduledTaskPersistence
// 末尾:第一次用 info(服务默认不落 debug,写成 debug 的可观测性等于没有),之后降到 debug
// (每次清理都 info 一行会让它自己变成噪声源)。用 atomic 而不是裸 bool:清理路径目前只在
// 主线程跑,但「目前只在主线程」是个会过期的前提,而这里用 atomic 的代价是零。
std::atomic<bool> g_loggedAutostartScope{false};
std::atomic<bool> g_loggedTaskScope{false};

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

// 同上,但直接给原始 HKEY 根。HKEY_USERS 下按 SID 展开的每用户键没有对应的 RegHive 枚举值,
// 而下面的每用户自启动清理必须走那条路(理由见 autostartTargets)。
HKEY openKeyRaw(HKEY root, const QString& subKey, RegView view, REGSAM access) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, subKey.isEmpty() ? nullptr : wstr(subKey), 0,
                      access | viewToSam(view), &hk) == ERROR_SUCCESS)
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

// 提到这里(原先在 kIfeoRoots 之后):下面的 autostartTargets() 要用它拼显示名。
QString hiveName(RegHive h) {
    switch (h) {
        case RegHive::LocalMachine: return QStringLiteral("HKLM");
        case RegHive::CurrentUser:  return QStringLiteral("HKCU");
        case RegHive::Users:        return QStringLiteral("HKU");
        default:                    return QStringLiteral("HKLM");
    }
}

// 机器范围的自启动键(枚举值,删掉指向恶意文件的那些)。
//
// 【这里刻意【没有】HKEY_CURRENT_USER】原来有 3 条 RegHive::CurrentUser 的条目,而本服务以
// LocalSystem 运行 —— HKCU 在这个身份下解析到 S-1-5-18(服务账户的 hive),那里的 Run 键
// 几乎永远是空的。于是这 3 条不是「没找到恶意项」,是【压根没看那个用户的 hive】,而日志
// 每次都如实打出「移除自启动项 0 个」,看上去和「确实没有持久化」一模一样。
//
// 实测(2026-09-30):powershell 往真实用户 hive 写了
// HKU\S-1-5-21-…\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate
// (值 = conhost.exe --headless "%APPDATA%\Microsoft\Windows.bat"),载荷被隔离掉了,
// 但这个 Run 值在 11 次足迹清理之后依然在注册表里。
//
// 这与 nodriver-hardening 第 11 条是同一个错误:那一次修的是【扫描侧】
// (UserModeBehaviorSource::autorunRegLocations 改为枚举 HKEY_USERS),清理侧漏了。
const RegLoc kAutostartKeys[] = {
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { RegHive::LocalMachine, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { RegHive::LocalMachine, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" },
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" },
};

// 每用户自启动键(相对某个用户 hive 的子路径)。会在 HKEY_USERS 下【每个已加载的 hive】上各查一遍。
const char* const kPerUserAutostartSubKeys[] = {
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
};

// 一个待清理的自启动位置。root 用原始 HKEY 是必须的:HKEY_USERS 下按 SID 展开的路径
// 没有对应的 RegHive 枚举值。
struct AutostartTarget {
    HKEY root = HKEY_LOCAL_MACHINE;
    QString subKey;    // 相对 root 的完整子路径(每用户时含 SID 前缀)
    QString display;   // 人读 / 日志用的完整路径("HKLM\…" / "HKU\<SID>\…")
};

// 每轮重新枚举 HKEY_USERS —— 不缓存。服务启动之后才登录的用户,他的 hive 是那之后才挂上来的;
// 缓存一次就会把这些用户永久漏掉(与 nodriver-hardening 第 11 条同一条理由)。
QList<AutostartTarget> autostartTargets() {
    QList<AutostartTarget> out;
    for (const RegLoc& loc : kAutostartKeys) {
        AutostartTarget t;
        t.root = hiveToHkey(loc.hive);
        t.subKey = QString::fromLatin1(loc.subKey);
        t.display = hiveName(loc.hive) + QLatin1Char('\\') + t.subKey;
        out.append(t);
    }

    HKEY usersRoot = openKeyRaw(HKEY_USERS, QString(), RegView::Default, KEY_READ);
    if (!usersRoot)
        return out;
    for (const QString& sid : enumSubKeyNames(usersRoot)) {
        // *_Classes 是同一个用户 hive 的类注册分支,不含 Run 项,跳过可省掉一半的无效打开。
        // 【.DEFAULT 与 S-1-5-18/19/20 刻意保留】:往默认用户模板或服务账户 hive 里写 Run 项
        // 同样是持久化手段,把它们当成「不是真人所以不用管」会留下一个干净的空子。
        if (sid.endsWith(QStringLiteral("_Classes"), Qt::CaseInsensitive))
            continue;
        for (const char* sub : kPerUserAutostartSubKeys) {
            AutostartTarget t;
            t.root = HKEY_USERS;
            t.subKey = sid + QLatin1Char('\\') + QString::fromLatin1(sub);
            t.display = QStringLiteral("HKU\\") + t.subKey;
            out.append(t);
        }
    }
    RegCloseKey(usersRoot);
    return out;
}

// IFEO roots: a child's Debugger value pointing at a malicious file is a hijack.
const RegLoc kIfeoRoots[] = {
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" },
    { RegHive::LocalMachine, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" },
};

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

// 是否为「绝不能删」的系统可执行文件。
//
// 判据 = 文件名命中名单【且】文件真的位于系统目录。两个条件必须同时成立。
//
// 只按文件名判会让「改名成系统程序」直接变成免清理护身符 —— 实测机器上
// C:\Users\<u>\AppData\Local\DBG\csrss.exe(SalatStealer,情报已确认恶意)每分钟都被
// 足迹清理跳过一次,日志固定输出「隔离文件 0 个 … 未清理 1 项」,原因就是这里只比了文件名。
// 而本函数要防的是「把真的 C:\Windows\System32\cmd.exe 删掉」,那个场景本来就带系统路径,
// 加上路径条件一分保护都不会少。
bool isSystemExecutable(const QString& path) {
    const QFileInfo fi(path);
    const QString fname = fi.fileName().toLower();
    bool nameHit = false;
    for (const char* sysExe : kSystemExecutables)
        if (fname == QLatin1String(sysExe)) { nameHit = true; break; }
    if (!nameHit) return false;

    // 系统目录判定与 ProcessInspector::isSystemImageDir 同义(WRP + 高 ACL,普通用户写不进去)。
    // 刻意不含 \Program Files\:那里第三方安装程序能落文件,不足以证明「这是 Windows 自己那份」。
    const QString lower = path.toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
    return lower.contains(QLatin1String("\\windows\\system32\\"))
        || lower.contains(QLatin1String("\\windows\\syswow64\\"))
        || lower.contains(QLatin1String("\\windows\\winsxs\\"));
}

// Safe to clean iff in a user-writable drop zone, not a system/install dir, and
// (unless the signature guard is bypassed) not trusted-signed.
// 位置护栏(不含签名):非系统关键工具、不在系统/安装目录、且落在用户可写落地区。
// isSafeToRemove 与释放物污点(ThreatRemediator::isInUserDropZone)共用这一份,名单只有一处。
// 本产品自己投放的勒索诱饵文件。由 UserModeBehaviorSource 在投放后登记。
//
// 【为什么需要这道护栏(2.4)】诱饵就是刻意放在 Documents / Desktop / Pictures 里的普通
// 文档,位置护栏看它是「用户可写落地区里的一个文件」,完全合格。于是勒索诱饵一被触碰,
// 足迹清理把【诱饵本身】当成恶意释放物搬进了隔离区 —— 0.5 的实测里同一次触碰发生了 3 次。
// 后果有三层:金库里堆进本来属于用户的文件、下次启动要重新投放、而且蜜罐在重投之前是空的
// (刚检出勒索的那一刻,恰好是蜜罐防线最不该消失的时候)。
QStringList g_canaryFiles;
QMutex g_canaryMx;

bool isOwnCanaryFile(const QString& path) {
    const QString p = path.trimmed().toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (p.isEmpty())
        return false;
    QMutexLocker lk(&g_canaryMx);
    for (const QString& c : g_canaryFiles) {
        if (c == p)
            return true;
    }
    return false;
}

bool passesLocationGuard(const QString& path, QString& reason) {
    reason.clear();

    // 0) 本产品自己的勒索诱饵 —— 绝不清理。放在最前面:它比下面任何一条都更不该被误判,
    //    而且诱饵路径天生满足「用户可写落地区」。
    if (isOwnCanaryFile(path)) {
        reason = u("这是本产品自己投放的勒索诱饵文件,不是释放物(清掉它等于自毁蜜罐)");
        return false;
    }

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
    return true;
}

bool isSafeToRemove(const QString& path, bool bypassSignatureGuard, QString& reason) {
    if (!passesLocationGuard(path, reason))
        return false;
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

// ============================ 计划任务(ScheduledTask)============================

// 从任务 XML 里取一对标签之间的内容。任务 XML 的 <Exec> 段结构固定,用不着拉 QXmlStreamReader:
// 与 ProcessOriginResolver 的任务索引同一手法(那边已经这么读了几个月)。
QString xmlBetween(const QString& s, const QString& a, const QString& b) {
    const int i = s.indexOf(a, 0, Qt::CaseInsensitive);
    if (i < 0) return QString();
    const int from = i + a.size();
    const int j = s.indexOf(b, from, Qt::CaseInsensitive);
    return j < 0 ? QString() : s.mid(from, j - from).trimmed();
}

// %VAR% 展开。任务 XML 的 <Command> 常写成 %windir%\... 这类形态,不展开就与我们手里的绝对
// 路径对不上。
//
// 【诚实的边界】本服务是 LocalSystem,所以 %LOCALAPPDATA% / %APPDATA% 会展开到
// C:\Windows\system32\config\systemprofile\… 而不是真实用户目录 —— 一个把恶意体写成
// %APPDATA%\x.exe 的任务,这里展开出来的路径不会命中,只能靠原始串直接包含绝对路径时匹配上。
// 这是已知缺口,不是「展开了就覆盖到了」;要真正覆盖得按每个用户 hive 逐一展开,那与
// removeAutostartPersistence 的每用户展开是同一件事,留作后续。
QString expandEnvVars(const QString& s) {
    if (!s.contains(QLatin1Char('%')))
        return s;
    wchar_t buf[2048] = {};
    const DWORD n = ExpandEnvironmentStringsW(reinterpret_cast<const wchar_t*>(s.utf16()), buf,
                                              static_cast<DWORD>(std::size(buf)));
    if (n == 0 || n > std::size(buf))
        return s;   // 展开失败 / 缓冲不够 -> 保持原样,绝不返回半截串
    return QString::fromWCharArray(buf, static_cast<int>(n - 1)); // n 含结尾的 NUL
}

// 每线程一次 COM 初始化,且【绝不 CoUninitialize】——与 ProcessOriginResolver::ensureCom 同一
// 理由:反复 init/uninit 会把同线程上其它 COM 用法(IShellLink / ITaskService)拆掉。
bool ensureComForTasks() {
    thread_local int state = 0; // 0=未试 1=可用 2=不可用
    if (state != 0)
        return state == 1;
    const HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    state = (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) ? 1 : 2;
    return state == 1;
}

// 删除一个计划任务。fullPath 形如 "\Folder\Name" 或 "\Name"。
// 失败时 err 回填原因(HRESULT 十六进制),由调用方如实记进「未清理」。
bool deleteScheduledTaskByPath(const QString& fullPath, QString& err) {
    err.clear();
    QString p = fullPath;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (p.startsWith(QLatin1Char('\\'))) p = p.mid(1);
    if (p.isEmpty()) { err = u("任务路径为空"); return false; }

    const int cut = p.lastIndexOf(QLatin1Char('\\'));
    const QString folder = cut < 0 ? QStringLiteral("\\") : (QStringLiteral("\\") + p.left(cut));
    const QString name = cut < 0 ? p : p.mid(cut + 1);

    if (!ensureComForTasks()) { err = u("COM 初始化失败"); return false; }

    ITaskService* svc = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(TaskScheduler), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(ITaskService), reinterpret_cast<void**>(&svc));
    if (FAILED(hr) || !svc) {
        err = u("无法创建 TaskScheduler(0x") + QString::number(static_cast<quint32>(hr), 16) + u(")");
        return false;
    }
    VARIANT empty;
    VariantInit(&empty);
    hr = svc->Connect(empty, empty, empty, empty);
    if (FAILED(hr)) {
        svc->Release();
        err = u("连接任务计划服务失败(0x") + QString::number(static_cast<quint32>(hr), 16) + u(")");
        return false;
    }
    BSTR bFolder = SysAllocString(reinterpret_cast<const wchar_t*>(folder.utf16()));
    ITaskFolder* tf = nullptr;
    hr = svc->GetFolder(bFolder, &tf);
    if (bFolder) SysFreeString(bFolder);
    if (FAILED(hr) || !tf) {
        svc->Release();
        err = u("找不到任务文件夹 ") + folder + u("(0x") + QString::number(static_cast<quint32>(hr), 16) + u(")");
        return false;
    }
    BSTR bName = SysAllocString(reinterpret_cast<const wchar_t*>(name.utf16()));
    hr = tf->DeleteTask(bName, 0);
    if (bName) SysFreeString(bName);
    tf->Release();
    svc->Release();
    if (FAILED(hr)) {
        err = u("DeleteTask 失败(0x") + QString::number(static_cast<quint32>(hr), 16) + u(")");
        return false;
    }
    return true;
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

void ThreatRemediator::setOwnCanaryFiles(const QStringList& paths) {
    QStringList norm;
    norm.reserve(paths.size());
    for (const QString& p : paths) {
        const QString t = p.trimmed().toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
        if (!t.isEmpty() && !norm.contains(t))
            norm << t;
    }
    QMutexLocker lk(&g_canaryMx);
    g_canaryFiles = norm;
}

bool ThreatRemediator::isInUserDropZone(const QString& path, QString* reason) {
    QString why;
    const bool ok = looksLikeFilePath(path.trimmed()) && passesLocationGuard(path.trimmed(), why);
    if (reason)
        *reason = why;
    return ok;
}

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
    int alreadyVaulted = 0;   // 此前已隔离、本轮无事可做的(见下面那段)
    for (const QString& path : maliciousFiles) {
        if (!QFileInfo::exists(path)) continue;
        //
        // 【已经隔离过的路径要在最前面短路掉】
        //
        // QuarantineManager::quarantine 开头就有同路径去重(原路径相同且金库副本还在 -> 直接
        // 返回已有条目),所以重复调用本来就不会重做隔离。问题在于走到那句之前,这里已经无条件
        // 付了两次全文件开销:
        //   · isSafeToRemove -> ProcessInspector::isSigned -> WinVerifyTrust(Authenticode 要把
        //     整个 PE 过一遍哈希);
        //   · QuarantineManager::tryComputeSha256。
        // 本机实测:对那个 233MB 的样本,前者 1.22s、后者 0.45s。
        //
        // 后果不是「慢一点」,是把事件流水线堵死。2026-09-30 的实测:样本被 kill 之后,它那两个
        // 已死 PID 还有 20 条事件排在队列里,每条都走一遍完整足迹清理 —— 每条约 2.0 秒,
        // 21:19:12 到 21:19:54 之间整条流水线只在处理这一个文件,别的进程的事件全堵在后面,
        // 最后在 21:19:54 一次性涌出。而这 20 次里有 19 次【什么都没做】,却照样每次打一行
        // 「足迹清理:已隔离恶意释放文件 …」——日志说做了 20 次隔离,实际只有 1 次。
        //
        // 这里既省掉那两次哈希,也不再把它算成一次「隔离动作」:report 两侧都不记,于是
        // publishRemediation 的 totalActions()==0 && skipped.isEmpty() 早退生效,重复事件彻底安静。
        if (quarantine_.isAlreadyQuarantined(path)) {
            ++alreadyVaulted;
            continue;
        }
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

    if (alreadyVaulted > 0) {
        log_.debug(u("足迹清理:") + QString::number(alreadyVaulted)
                   + u(" 个候选文件此前已隔离(金库副本仍在),本轮跳过 —— 未重复计算签名/哈希。"));
    }

    // 3) persistence pointing at the malicious files:注册表三类 + 计划任务。
    //
    // 计划任务此前【整类缺失】:remediate 只清 Run / IFEO / 服务,deleteScheduledTask 只挂在
    // 用户手动清理那条路上。实测样本用 schtasks 注册登录触发任务指向 %APPDATA% 下的副本,
    // 载荷被隔离、任务却留着(日志固定写「移除自启动项 0 个」)。
    removeAutostartPersistence(maliciousFiles, report);
    removeIfeoPersistence(maliciousFiles, report);
    removeServicePersistence(maliciousFiles, report);
    removeScheduledTaskPersistence(maliciousFiles, report);

    if (report.totalActions() > 0)
        log_.warning(u("足迹清理完成:隔离文件 ") + QString::number(report.quarantinedFiles.size())
                     + u(" 个,移除持久化 ") + QString::number(report.removedRegistryValues.size()) + u(" 项。"));
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
    const QList<AutostartTarget> targets = autostartTargets();
    for (const AutostartTarget& loc : targets) {
        const RegView view = viewForSubKey(loc.subKey);
        HKEY hk = openKeyRaw(loc.root, loc.subKey, view, KEY_READ | KEY_SET_VALUE);
        if (!hk) continue; // not present / not writable -> skip (matches .NET outer catch)

        for (const QString& valueName : enumValueNames(hk)) {
            const QString data = readString(hk, valueName);
            if (data.isEmpty() || !referencesMalware(data, maliciousFiles)) continue;

            const QString full = loc.display + QLatin1Char('\\') + valueName;
            const LSTATUS st = RegDeleteValueW(hk, wstr(valueName));
            if (st == ERROR_SUCCESS) {
                report.removedRegistryValues.append(full);
                report.hardenedRegTargets.append(loc.subKey + QLatin1Char('\\') + valueName);
                log_.warning(u("足迹清理:已删除自启动持久化项 ") + full);
            } else if (st == ERROR_ACCESS_DENIED) {
                // RegSurgery 走 RegHive 枚举:HKEY_USERS 下的每用户键对应 RegHive::Users,
                // 而它的子路径已经带了 SID 前缀,所以直接传 loc.subKey 就是对的。
                const RegHive surgeryHive =
                    loc.root == HKEY_USERS ? RegHive::Users : RegHive::LocalMachine;
                if (RegSurgery::forceDeleteValue(surgeryHive, loc.subKey, valueName, view)) {
                    report.removedRegistryValues.append(full + u("(夺取所有权后删除)"));
                    report.hardenedRegTargets.append(loc.subKey + QLatin1Char('\\') + valueName);
                    log_.warning(u("足迹清理:夺取所有权后删除自启动项 ") + full);
                } else {
                    report.skipped.append(mkSkip(full, u("受 ACL 保护,夺取所有权仍失败(建议手动删除)"), false));
                }
            } else {
                report.skipped.append(mkSkip(full, u("删除失败"), false));
            }
        }
        RegCloseKey(hk);
    }
    // 查了多少个位置必须可观测。原先这个函数只会打「删除了某项」—— 一条都没命中时完全静默,
    // 于是「没有恶意自启动项」和「压根没看对 hive」在日志上长得一模一样,而后者恰好是这次
    // 实测踩到的缺陷(修复前固定输出「移除自启动项 0 个」)。
    //
    // 【为什么第一次用 info、之后才降到 debug】服务默认不落 debug 级,写成 debug 等于白加一行
    // 没人看得见的日志 —— 与它要修的那个「沉默」是同一类错误。但每次足迹清理都 info 一行也不行
    // (会变成新的噪声源)。折中:每个进程生命周期内报一次真实覆盖面,之后转 debug。
    const QString scope = u("足迹清理:自启动位置共 ") + QString::number(targets.size())
                          + u(" 处(机器范围 ")
                          + QString::number(static_cast<int>(std::size(kAutostartKeys)))
                          + u(" + HKEY_USERS 已加载 hive 展开 ")
                          + QString::number(targets.size() - static_cast<int>(std::size(kAutostartKeys)))
                          + u(")。");
    if (!g_loggedAutostartScope.exchange(true))
        log_.info(scope);
    else
        log_.debug(scope);
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

void ThreatRemediator::removeScheduledTaskPersistence(const QStringList& maliciousFiles,
                                                     RemediationReport& report) {
    if (maliciousFiles.isEmpty())
        return;
    const QString windir = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
    const QString tasksRoot = windir + QStringLiteral("\\System32\\Tasks");
    QDir rootDir(tasksRoot);
    if (!rootDir.exists())
        return;

    // 上限护栏:极端环境下任务目录可能被塞进上万个文件,足迹清理不能因此变成一次全盘遍历。
    // 4000 与 ProcessOriginResolver 的任务索引取同一个数,两处口径一致。
    constexpr int kMaxTaskFiles = 4000;
    int seen = 0, hit = 0;
    QDirIterator it(tasksRoot, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext() && seen < kMaxTaskFiles) {
        const QString file = it.next();
        ++seen;
        QFile f(file);
        if (!f.open(QIODevice::ReadOnly))
            continue;
        // 任务 XML 通常几 KB;读前 64KB 足够覆盖 <Exec><Command>/<Arguments>。
        const QString xml = QString::fromUtf8(f.read(64 * 1024));
        f.close();
        if (xml.isEmpty() || !xml.contains(QStringLiteral("<Exec"), Qt::CaseInsensitive))
            continue;

        // 判据要同时看 Command 与 Arguments:样本常把恶意体写在参数里,
        // Command 反而是 cmd.exe / conhost.exe / powershell.exe 这类系统程序
        //(实测的 Run 项就是 `conhost.exe --headless "…\Windows.bat"` 这个形态)。
        const QString cmd = xmlBetween(xml, QStringLiteral("<Command>"), QStringLiteral("</Command>"));
        const QString args = xmlBetween(xml, QStringLiteral("<Arguments>"), QStringLiteral("</Arguments>"));
        const QString expanded = expandEnvVars(QString(cmd).remove(QLatin1Char('"')));
        if (!referencesMalware(cmd, maliciousFiles) && !referencesMalware(args, maliciousFiles)
            && !referencesMalware(expanded, maliciousFiles))
            continue;

        ++hit;
        const QString taskPath = QStringLiteral("\\") + rootDir.relativeFilePath(file);
        const QString display = u("计划任务 ") + taskPath;
        QString err;
        if (deleteScheduledTaskByPath(taskPath, err)) {
            report.removedRegistryValues.append(display + u("(已删除)"));
            // 反重建:任务名在 TaskCache\Tree 下是它独占的一个键,挡住这个键就挡住了
            // 「用同一个名字立刻把任务注册回来」。与 Run 值同一个目的(补清理→重写的竞态),
            // 但比 Run 安全得多 —— Run 是所有安装程序共享的键,这个不是。
            QString leaf = taskPath;
            while (leaf.startsWith(QLatin1Char('\\'))) leaf = leaf.mid(1);
            if (!leaf.isEmpty())
                report.hardenedRegTargets.append(u("\\TaskCache\\Tree\\") + leaf);
            log_.warning(u("足迹清理:已删除指向恶意文件的计划任务 ") + taskPath);
        } else {
            report.skipped.append(mkSkip(display, err, false));
            log_.warning(u("足迹清理:计划任务删除失败 ") + taskPath + u(" —— ") + err);
        }
    }
    if (seen >= kMaxTaskFiles) {
        log_.warning(u("足迹清理:计划任务目录文件数已达上限 ") + QString::number(kMaxTaskFiles)
                     + u(" 个,本轮未看完 —— 可能有指向恶意文件的任务被漏过。"));
    }
    // 与上面同理:整类此前【压根不在清理范围内】,所以「检查了多少个任务」必须至少报一次,
    // 否则没人能区分「没有恶意任务」与「这一维根本没跑」。
    const QString scope = u("足迹清理:已检查计划任务 ") + QString::number(seen) + u(" 个,命中 ")
                          + QString::number(hit) + u(" 个。");
    if (!g_loggedTaskScope.exchange(true))
        log_.info(scope);
    else
        log_.debug(scope);
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
