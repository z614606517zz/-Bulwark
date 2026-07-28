#include "Bootstrap.h"

#include "bulwark/ipc/PipeNames.h"

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QLocalSocket>
#include <QMessageBox>
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
        QMessageBox::warning(parent, u("磐垒主动防御"),
            u("找不到 bulwark_service.exe。请确保它与本程序在同一目录,"
              "否则界面无法连上防护服务。"));
        return false;
    }

    const RunResult r = isElevated()
        ? runDirect(exe, { QStringLiteral("--bootstrap") })
        : runElevated(exe, QStringLiteral("--bootstrap"));

    if (r == RunResult::Refused) {
        QMessageBox::information(parent, u("磐垒主动防御"),
            u("需要管理员权限才能启动防护服务与内核驱动。\n\n"
              "本次已跳过 —— 界面会以「未连接」状态打开,不影响你查看历史记录。"
              "想启用防护,重新打开本程序并在提权提示里选「是」即可。"));
        return false;
    }

    // 服务进 RUNNING 后管道还要一小会儿才监听上,再宽限一段。
    if (waitForBackend(30000))
        return true;

    const QString detail = bootstrapStatus();
    QMessageBox::warning(parent, u("磐垒主动防御"),
        u("防护服务未能启动,界面将以「未连接」状态打开。\n\n")
            + (detail.isEmpty() ? u("详见 %ProgramData%\\Bulwark\\service.log。") : detail));
    return false;
}

bool shutdownBackend() {
    // 静默停止服务和驱动,不弹任何提示框
    
    // 1. 停止服务
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = ::OpenServiceW(scm, L"BulwarkService", SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS st = {};
            ::ControlService(svc, SERVICE_CONTROL_STOP, &st);
            // 等待服务停止(最多5秒)
            for (int i = 0; i < 10; ++i) {
                DWORD needed = 0;
                if (::QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_STOPPED)
                    break;
                ::Sleep(500);
            }
            ::CloseServiceHandle(svc);
        }
        ::CloseServiceHandle(scm);
    }

    // 2. 卸载驱动
    ::Sleep(1000); // 给服务1秒时间完全退出
    
    scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE driver = ::OpenServiceW(scm, L"Bulwark", SERVICE_STOP);
        if (driver) {
            SERVICE_STATUS st = {};
            ::ControlService(driver, SERVICE_CONTROL_STOP, &st);
            ::CloseServiceHandle(driver);
        }
        ::CloseServiceHandle(scm);
    }

    return true;
}

} // namespace bulwark::ui::bootstrap
