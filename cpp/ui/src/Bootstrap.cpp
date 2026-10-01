#include "Bootstrap.h"

#include "bulwark/ipc/PipeNames.h"

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QLocalSocket>
#include "design/Confirm.h"
#include <QProcess>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h> // ShellExecuteExW(runas 提权)

namespace bulwark::ui::bootstrap {
namespace {

inline QString u(const char* s) { return QString::fromUtf8(s); }

// 当前进程是否已提权(已提权则无需再弹 UAC,直接跑子进程)。
bool isElevated() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION info = {};
    DWORD size = 0;
    const bool ok = ::GetTokenInformation(token, TokenElevation, &info, sizeof(info), &size) != 0;
    ::CloseHandle(token);
    return ok && info.TokenIsElevated != 0;
}

// 与 UI 同目录的服务可执行文件(打包分发时二者始终同目录)。
QString serviceExePath() {
    const QString p = QDir(QCoreApplication::applicationDirPath())
                          .filePath(QStringLiteral("bulwark_service.exe"));
    return QFileInfo::exists(p) ? QDir::toNativeSeparators(p) : QString();
}

enum class RunResult { Ok, Refused, Failed };

// 以管理员身份同步执行,等它退出(自举里含等服务 RUNNING,给足 3 分钟)。
RunResult runElevated(const QString& exe, const QString& args) {
    const std::wstring wexe = exe.toStdWString();
    const std::wstring wargs = args.toStdWString();

    SHELLEXECUTEINFOW si = {};
    si.cbSize = sizeof(si);
    si.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    si.lpVerb = L"runas";              // 触发 UAC
    si.lpFile = wexe.c_str();
    si.lpParameters = wargs.c_str();
    si.lpDirectory = nullptr;
    si.nShow = SW_HIDE;                // 无控制台窗口闪现

    if (!::ShellExecuteExW(&si)) {
        // 1223 = ERROR_CANCELLED:用户在 UAC 弹窗点了「否」。
        return (::GetLastError() == ERROR_CANCELLED) ? RunResult::Refused : RunResult::Failed;
    }
    if (si.hProcess) {
        ::WaitForSingleObject(si.hProcess, 180000);
        ::CloseHandle(si.hProcess);
    }
    return RunResult::Ok;
}

// 已提权时走这条:直接起子进程,不弹 UAC。
RunResult runDirect(const QString& exe, const QStringList& args) {
    QProcess p;
    p.start(exe, args);
    if (!p.waitForStarted(10000))
        return RunResult::Failed;
    if (!p.waitForFinished(180000)) {
        p.kill();
        p.waitForFinished(2000);
        return RunResult::Failed;
    }
    return RunResult::Ok;
}

// 自举子进程留下的人类可读状态(失败时直接摊给用户看,免得让人去翻日志)。
QString bootstrapStatus() {
    QString base = qEnvironmentVariable("BULWARK_DATA_DIR").trimmed();
    if (base.isEmpty()) {
        base = qEnvironmentVariable("ProgramData");
        if (base.isEmpty()) base = QStringLiteral("C:/ProgramData");
        base += QStringLiteral("/Bulwark");
    }
    QFile f(QDir(base).filePath(QStringLiteral("bootstrap-status.txt")));
    if (!f.open(QIODevice::ReadOnly))
        return QString();
    return QString::fromUtf8(f.readAll()).trimmed();
}

// 轮询等管道起来。等待期间抽事件,避免界面/UAC 期间无响应。
bool waitForBackend(int totalMs) {
    QElapsedTimer t;
    t.start();
    while (t.elapsed() < totalMs) {
        if (backendReachable(200))
            return true;
        QCoreApplication::processEvents();
        ::Sleep(300);
    }
    return false;
}

} // namespace

bool backendReachable(int timeoutMs) {
    QLocalSocket probe;
    probe.connectToServer(bulwark::ipc::controlPipe());
    const bool ok = probe.waitForConnected(timeoutMs);
    if (ok)
        probe.disconnectFromServer();
    return ok;
}

bool ensureBackendRunning(QWidget* parent) {
    if (backendReachable())
        return true; // 常态:服务已开机自启,什么都不用做

    const QString exe = serviceExePath();
    if (exe.isEmpty()) {
        ::ui::notice(parent, ::ui::NoticeTone::Warning, u("找不到防护服务"),
            u("找不到 bulwark_service.exe。请确保它与本程序在同一目录,"
              "否则界面无法连上防护服务。界面会以「未连接」状态打开。"));
        return false;
    }

    const RunResult r = isElevated()
        ? runDirect(exe, { QStringLiteral("--bootstrap") })
        : runElevated(exe, QStringLiteral("--bootstrap"));

    if (r == RunResult::Refused) {
        ::ui::notice(parent, ::ui::NoticeTone::Info, u("已跳过启动防护服务"),
            u("需要管理员权限才能启动防护服务与内核驱动。"
              "本次已跳过 —— 界面会以「未连接」状态打开,不影响你查看历史记录。"
              "想启用防护,重新打开本程序并在提权提示里选「是」即可。"));
        return false;
    }

    // 服务进 RUNNING 后管道还要一小会儿才监听上,再宽限一段。
    if (waitForBackend(30000))
        return true;

    const QString detail = bootstrapStatus();
    ::ui::notice(parent, ::ui::NoticeTone::Danger, u("防护服务未能启动"),
        u("界面将以「未连接」状态打开,系统此刻不受本软件保护。"),
        detail.isEmpty() ? u("详见 %ProgramData%\\Bulwark\\service.log。") : detail);
    return false;
}

// shutdownBackend() 已移除 —— 理由见 Bootstrap.h。简言之:关界面【默认】不关防护;想要
// 「关界面即停防护」的用户走设置里的 protectionFollowsUi,那一条由服务侧按管道断开来执行,
// 不需要界面去停服务(界面没那个权限,硬做就得每次退出弹 UAC)。

bool ensureUiAutoStart() {
    const QString exe = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
    if (exe.isEmpty())
        return false;
    // --tray:登录时静默驻留托盘,不把主窗口糊到用户脸上(见 ui/main.cpp 对该参数的处理)。
    const std::wstring want = (QLatin1Char('"') + exe + QStringLiteral("\" --tray")).toStdWString();

    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER,
                        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key) != ERROR_SUCCESS) {
        return false;
    }

    // 先读:已经是期望值就不写。注册表写入会被本产品自己的自启动项监控看到,常态下不该有动静。
    bool same = false;
    {
        wchar_t cur[1024] = {};
        DWORD size = sizeof(cur);
        DWORD type = 0;
        if (::RegQueryValueExW(key, L"Bulwark", nullptr, &type,
                               reinterpret_cast<LPBYTE>(cur), &size) == ERROR_SUCCESS
            && type == REG_SZ) {
            same = (::_wcsicmp(cur, want.c_str()) == 0);
        }
    }
    bool ok = same;
    if (!same) {
        // 路径变了(换目录 / 重新部署)也走这条,顺带把陈旧路径纠正过来。
        ok = ::RegSetValueExW(key, L"Bulwark", 0, REG_SZ,
                              reinterpret_cast<const BYTE*>(want.c_str()),
                              static_cast<DWORD>((want.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
    }
    ::RegCloseKey(key);
    return ok;
}

} // namespace bulwark::ui::bootstrap
