// ProcessEnumerator.cpp — 在跑进程快照实现。
//
// 取证事实的来源(逐项都尽量用最可靠的 API,拿不到就留空,绝不编):
//   PID / 父 PID / 线程数 / 映像名 : Toolhelp32 快照(一次遍历)
//   映像完整路径                  : QueryFullProcessImageName(比 MainModule 可靠)
//   命令行                        : PEB 读取(ProcessInspector)
//   启动时间                      : GetProcessTimes
//   内存占用                      : K32GetProcessMemoryInfo(kernel32 导出,动态取,不额外链 psapi)
//   会话 / 位数 / 提权 / 用户      : ProcessIdToSessionId / IsWow64Process / TokenElevation / TokenUser
//   文件描述                      : version.dll 版本资源(动态加载,不额外链 version)
//   签名 / 发布者 / 失配           : ProcessInspector(带文件身份缓存)
//   启动来源(服务 / 计划任务)     : ProcessOriginResolver
//
// 一个进程失败绝不影响整份快照 —— 系统上永远有几个打不开的受保护进程,那是常态而非错误。

#include "bulwark/service/monitoring/ProcessEnumerator.h"
#include "bulwark/service/monitoring/ProcessInspector.h"
#include "bulwark/service/monitoring/ProcessOriginResolver.h"

#include <QDateTime>
#include <QFileInfo>
#include <QHash>
#include <QSet>
#include <QTimeZone>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <vector>

using namespace bulwark::service::monitoring;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

const wchar_t* wcstr(const QString& s)
{
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

QDateTime fileTimeToUtc(const FILETIME& ft)
{
    ULARGE_INTEGER v;
    v.LowPart = ft.dwLowDateTime;
    v.HighPart = ft.dwHighDateTime;
    if (v.QuadPart == 0)
        return QDateTime();
    constexpr quint64 kEpochDiffMs = 11644473600000ULL;
    const qint64 ms = static_cast<qint64>(v.QuadPart / 10000ULL) - static_cast<qint64>(kEpochDiffMs);
    return QDateTime::fromMSecsSinceEpoch(ms, QTimeZone::UTC);
}

// ---- 内存占用:K32GetProcessMemoryInfo(kernel32 导出),动态取以免多链一个 psapi ----
struct MemCounters {
    DWORD cb;
    DWORD PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivateUsage; // _EX 版本才有
};
using GetProcMemFn = BOOL(WINAPI*)(HANDLE, MemCounters*, DWORD);

GetProcMemFn getProcMemFn()
{
    static GetProcMemFn fn = [] {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        return k32 ? reinterpret_cast<GetProcMemFn>(
                         GetProcAddress(k32, "K32GetProcessMemoryInfo"))
                   : nullptr;
    }();
    return fn;
}

// ---- 文件描述:版本资源(动态加载 version.dll) ----
using GetVerSizeFn = DWORD(WINAPI*)(LPCWSTR, LPDWORD);
using GetVerFn = BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD, LPVOID);
using VerQueryFn = BOOL(WINAPI*)(LPCVOID, LPCWSTR, LPVOID*, PUINT);

struct VersionApi {
    GetVerSizeFn size = nullptr;
    GetVerFn get = nullptr;
    VerQueryFn query = nullptr;
    bool ok() const { return size && get && query; }
};

const VersionApi& versionApi()
{
    static VersionApi api = [] {
        VersionApi a;
        HMODULE m = LoadLibraryExW(L"version.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (m) {
            a.size = reinterpret_cast<GetVerSizeFn>(GetProcAddress(m, "GetFileVersionInfoSizeW"));
            a.get = reinterpret_cast<GetVerFn>(GetProcAddress(m, "GetFileVersionInfoW"));
            a.query = reinterpret_cast<VerQueryFn>(GetProcAddress(m, "VerQueryValueW"));
        }
        return a;
    }();
    return api;
}

QString fileDescriptionOf(const QString& path)
{
    if (path.isEmpty())
        return QString();
    const VersionApi& api = versionApi();
    if (!api.ok())
        return QString();
    DWORD dummy = 0;
    const DWORD sz = api.size(wcstr(path), &dummy);
    if (sz == 0 || sz > 4 * 1024 * 1024)
        return QString();
    std::vector<BYTE> buf(sz, 0);
    if (!api.get(wcstr(path), 0, sz, buf.data()))
        return QString();

    // 按版本资源里声明的语言/代码页取 FileDescription;取不到翻译表就退回 en-US + Unicode。
    // (VerQueryValueW 对子块名大小写不敏感,故用小写十六进制拼接即可。)
    struct LangCp { WORD lang; WORD cp; };
    LangCp* trans = nullptr;
    UINT transBytes = 0;
    QString sub = QStringLiteral("\\StringFileInfo\\040904b0\\FileDescription");
    if (api.query(buf.data(), L"\\VarFileInfo\\Translation",
                  reinterpret_cast<void**>(&trans), &transBytes)
        && trans && transBytes >= sizeof(LangCp)) {
        sub = QStringLiteral("\\StringFileInfo\\%1%2\\FileDescription")
                  .arg(static_cast<uint>(trans->lang), 4, 16, QLatin1Char('0'))
                  .arg(static_cast<uint>(trans->cp), 4, 16, QLatin1Char('0'));
    }
    wchar_t* value = nullptr;
    UINT valueLen = 0;
    if (api.query(buf.data(), wcstr(sub), reinterpret_cast<void**>(&value), &valueLen)
        && value && valueLen > 0)
        return QString::fromWCharArray(value, static_cast<int>(valueLen)).trimmed();
    return QString();
}

// ---- 令牌信息:运行用户 + 是否提权 ----
void readTokenInfo(HANDLE proc, QString& userName, bool& elevated)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(proc, TOKEN_QUERY, &token))
        return;

    TOKEN_ELEVATION elev{};
    DWORD ret = 0;
    if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &ret))
        elevated = elev.TokenIsElevated != 0;

    DWORD need = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &need);
    if (need > 0 && need < 64 * 1024) {
        std::vector<BYTE> buf(need, 0);
        if (GetTokenInformation(token, TokenUser, buf.data(), need, &ret)) {
            auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
            wchar_t name[256], domain[256];
            DWORD nameLen = 256, domainLen = 256;
            SID_NAME_USE use{};
            if (LookupAccountSidW(nullptr, tu->User.Sid, name, &nameLen, domain, &domainLen, &use)) {
                const QString d = QString::fromWCharArray(domain, static_cast<int>(domainLen));
                const QString n = QString::fromWCharArray(name, static_cast<int>(nameLen));
                userName = d.isEmpty() ? n : (d + QLatin1Char('\\') + n);
            }
        }
    }
    CloseHandle(token);
}

// ---- 静态风险提示(只用于排序/着色,绝不据此自动处置)----
const QSet<QString>& systemImageNames()
{
    static const QSet<QString> s = {
        QStringLiteral("svchost.exe"), QStringLiteral("services.exe"),
        QStringLiteral("lsass.exe"),   QStringLiteral("csrss.exe"),
        QStringLiteral("wininit.exe"), QStringLiteral("winlogon.exe"),
        QStringLiteral("smss.exe"),    QStringLiteral("explorer.exe"),
        QStringLiteral("taskhostw.exe"), QStringLiteral("dwm.exe"),
        QStringLiteral("spoolsv.exe"), QStringLiteral("conhost.exe"),
    };
    return s;
}

bool isUserWritableDir(const QString& lowerPath)
{
    static const char* marks[] = {
        "\\appdata\\", "\\temp\\", "\\tmp\\", "\\downloads\\", "\\users\\public\\",
        "\\programdata\\", "\\windows\\temp\\", "\\recycle", "\\music\\", "\\videos\\",
    };
    for (const char* m : marks)
        if (lowerPath.contains(QLatin1String(m)))
            return true;
    return false;
}

bool isSystemDir(const QString& lowerPath)
{
    return lowerPath.contains(QLatin1String("\\windows\\system32\\"))
        || lowerPath.contains(QLatin1String("\\windows\\syswow64\\"))
        || lowerPath.contains(QLatin1String("\\windows\\winsxs\\"));
}

void scoreStatic(bulwark::ProcessEntry& e)
{
    if (e.isTrusted) {
        e.riskScore = 0;
        e.riskReasons.clear();
        e.riskReasons << u("已在用户信任名单(该程序不再被检测)");
        return;
    }
    int score = 0;
    const QString lower = e.imagePath.toLower();

    if (e.imagePath.isEmpty()) {
        score += 5;
        e.riskReasons << u("无法解析映像路径(受保护进程或已退出)");
    } else {
        if (e.signatureMismatch) {
            score += 30;
            e.riskReasons << u("签名失配:内嵌了数字签名但校验不通过(篡改 / 盗用证书特征)");
        } else if (!e.isSigned) {
            score += 15;
            e.riskReasons << u("无有效数字签名");
        }
        if (isUserWritableDir(lower)) {
            score += 20;
            e.riskReasons << u("运行于用户可写目录");
        }
        if (systemImageNames().contains(e.name.toLower()) && !isSystemDir(lower)) {
            score += 35;
            e.riskReasons << u("使用系统进程名但不在系统目录(伪装特征)");
        }
    }
    if (!e.isSigned && e.elevated) {
        score += 10;
        e.riskReasons << u("以高完整性(提权)运行且无有效签名");
    }
    if (!e.isSigned
        && (e.originKind == bulwark::ProcessOriginKind::ScheduledTask
            || e.originKind == bulwark::ProcessOriginKind::Service)) {
        score += 10;
        e.riskReasons << u("由%1启动且无有效签名")
                             .arg(e.originKind == bulwark::ProcessOriginKind::ScheduledTask
                                      ? u("计划任务") : u("服务"));
    }
    e.riskScore = std::min(100, score);
}

} // namespace

QList<bulwark::ProcessEntry> ProcessEnumerator::snapshot(
    const Options& opt, const std::function<bool(int)>& isProtectedSelf,
    const std::function<bool(const QString&)>& isTrustedImage)
{
    QList<bulwark::ProcessEntry> out;

    ProcessInspector::ensureDebugPrivilege(); // 尽量拿到更多进程的命令行 / 令牌

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return out;

    struct Raw {
        int pid = 0;
        int parentPid = 0;
        int threads = 0;
        QString name;
    };
    QList<Raw> raws;
    QHash<int, QString> nameByPid;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            Raw r;
            r.pid = static_cast<int>(pe.th32ProcessID);
            r.parentPid = static_cast<int>(pe.th32ParentProcessID);
            r.threads = static_cast<int>(pe.cntThreads);
            r.name = QString::fromWCharArray(pe.szExeFile);
            if (r.pid <= 0)
                continue;
            nameByPid.insert(r.pid, r.name);
            raws.append(r);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    out.reserve(raws.size());
    for (const Raw& r : raws) {
        bulwark::ProcessEntry e;
        try {
            e.pid = r.pid;
            e.parentPid = r.parentPid;
            e.threadCount = r.threads;
            e.name = r.name;
            e.parentName = nameByPid.value(r.parentPid);

            if (r.pid > 4) {
                e.imagePath = ProcessInspector::tryGetProcessImagePath(r.pid);
                if (opt.includeCommandLine) {
                    const QString cmd = ProcessInspector::tryGetCommandLine(r.pid);
                    e.commandLine = cmd.size() > 1024 ? (cmd.left(1024) + u("…")) : cmd;
                }
            }

            // 句柄类事实:启动时间 / 内存 / 位数 / 令牌。打不开就跳过(受保护进程是常态)。
            if (HANDLE h = (r.pid > 4)
                    ? OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                  static_cast<DWORD>(r.pid))
                    : nullptr) {
                FILETIME create{}, exit{}, kernel{}, user{};
                if (GetProcessTimes(h, &create, &exit, &kernel, &user))
                    e.startTimeUtc = fileTimeToUtc(create);
                if (GetProcMemFn fn = getProcMemFn()) {
                    MemCounters mc{};
                    mc.cb = sizeof(mc);
                    if (fn(h, &mc, sizeof(mc)))
                        e.workingSetBytes = static_cast<qint64>(mc.PrivateUsage != 0
                                                                    ? mc.PrivateUsage
                                                                    : mc.WorkingSetSize);
                }
                BOOL wow = FALSE;
                if (IsWow64Process(h, &wow))
                    e.is64Bit = (wow == FALSE);
                readTokenInfo(h, e.userName, e.elevated);
                CloseHandle(h);
            }

            DWORD session = 0;
            if (ProcessIdToSessionId(static_cast<DWORD>(r.pid), &session))
                e.sessionId = static_cast<int>(session);

            if (opt.verifySignature && !e.imagePath.isEmpty()) {
                e.isSigned = ProcessInspector::isSigned(e.imagePath);
                e.publisher = ProcessInspector::tryGetPublisher(e.imagePath);
                if (!e.isSigned)
                    e.signatureMismatch = ProcessInspector::hasEmbeddedSignature(e.imagePath);
                e.fileDescription = fileDescriptionOf(e.imagePath);
            }

            if (opt.resolveOrigin && r.pid > 4) {
                const ProcessOrigin origin =
                    ProcessOriginResolver::resolve(r.pid, e.imagePath, r.parentPid, e.commandLine);
                e.originKind = origin.kind;
                e.originService = origin.serviceName;
                e.originServiceDisplay = origin.serviceDisplayName;
                e.originTask = origin.taskPath;
                e.originDetail = origin.detail;
            }

            e.isCritical = ProcessInspector::isCriticalProcess(r.pid);
            e.isProtectedSelf = isProtectedSelf ? isProtectedSelf(r.pid) : false;
            e.isTrusted = (isTrustedImage && !e.imagePath.isEmpty()) ? isTrustedImage(e.imagePath)
                                                                     : false;
            scoreStatic(e);
        } catch (...) {
            // 单个进程取证失败:保留已拿到的字段,继续下一个。
        }
        out.append(e);
    }

    // 默认按风险分降序、其次 PID 升序 —— 打开页面第一眼就落在最值得看的进程上。
    std::sort(out.begin(), out.end(),
              [](const bulwark::ProcessEntry& a, const bulwark::ProcessEntry& b) {
                  if (a.riskScore != b.riskScore) return a.riskScore > b.riskScore;
                  return a.pid < b.pid;
              });
    return out;
}
