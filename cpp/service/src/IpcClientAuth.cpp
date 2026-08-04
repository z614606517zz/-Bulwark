#include "bulwark/service/IpcClientAuth.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/monitoring/ProcessInspector.h"

#include <QDir>
#include <QFileInfo>
#include <QMutex>
#include <QMutexLocker>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>   // GetNamedPipeClientProcessId / OpenProcess / QueryFullProcessImageNameW

namespace bulwark::service {

namespace {

Logger& log() { static Logger l(QStringLiteral("IpcAuth")); return l; }

QMutex& gate() { static QMutex m; return m; }

IpcClientAuth::Policy& policy() {
    static IpcClientAuth::Policy p;
    return p;
}

// 路径归一:小写 + 反斜杠。用于前缀比较,与 main / RuleEngine 里的自身目录判定同口径。
QString normPath(const QString& p) {
    QString s = p.trimmed();
    s.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return s.toLower();
}

// 指纹归一:去掉空格与冒号后转大写。证书指纹在不同工具里的书写差异(空格分组、冒号分隔、
// 大小写)非常常见,若按原样比较,白名单几乎必然「填了但不生效」——那是最坏的一种失效,
// 因为管理员会以为加固已经打开。
QString normThumbprint(const QString& t) {
    QString s;
    s.reserve(t.size());
    for (const QChar c : t) {
        if (c == QLatin1Char(' ') || c == QLatin1Char(':') || c == QLatin1Char('-'))
            continue;
        s.append(c.toUpper());
    }
    return s;
}

// 从命名管道的【服务端】句柄取对端 PID。失败返回 0。
quint32 clientPidOf(qintptr socketDescriptor) {
    if (socketDescriptor == -1 || socketDescriptor == 0)
        return 0;
    ULONG pid = 0;
    if (!::GetNamedPipeClientProcessId(reinterpret_cast<HANDLE>(socketDescriptor), &pid))
        return 0;
    return static_cast<quint32>(pid);
}

//
// 用【一次打开的进程句柄】解析映像路径,而不是先拿 PID 再单独 OpenProcess 两次。
//
// 这里有一个必须收窄的 TOCTOU:GetNamedPipeClientProcessId 给出的是「连接建立时的 PID」,
// 而 PID 是可复用的。若先记 PID、稍后再按 PID 去查路径,理论上能被「原进程退出 + 新进程
// 抢到同一 PID」偷换。窗口极窄,而且攻击者还得同时把一个同名映像塞进受 SelfGuard 保护的
// 安装目录才能通过强制层,但既然只是把两次调用并成一次就能消掉,就不留这个缺口。
//
QString imagePathOf(quint32 pid) {
    if (pid == 0)
        return QString();
    // PROCESS_QUERY_LIMITED_INFORMATION:比 QUERY_INFORMATION 权限要求低,跨会话/跨用户
    // (服务以 SYSTEM、UI 以普通用户)也能拿到,且足够查映像路径。
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (h == nullptr)
        return QString();
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD sz = static_cast<DWORD>(sizeof(buf) / sizeof(buf[0]));
    QString out;
    if (::QueryFullProcessImageNameW(h, 0, buf, &sz))
        out = QString::fromWCharArray(buf, static_cast<int>(sz));
    ::CloseHandle(h);
    return out;
}

} // namespace

void IpcClientAuth::configure(const Policy& p) {
    QMutexLocker lk(&gate());
    Policy norm;

    norm.installDir = normPath(p.installDir);
    if (!norm.installDir.isEmpty() && !norm.installDir.endsWith(QLatin1Char('\\')))
        norm.installDir += QLatin1Char('\\');

    for (const QString& n : p.allowedImageNames) {
        const QString t = n.trimmed().toLower();
        if (!t.isEmpty())
            norm.allowedImageNames << t;
    }
    if (norm.allowedImageNames.isEmpty())
        norm.allowedImageNames << QStringLiteral("bulwark_ui.exe");

    norm.enforceSignature = p.enforceSignature;
    for (const QString& t : p.allowedThumbprints) {
        const QString v = normThumbprint(t);
        if (!v.isEmpty())
            norm.allowedThumbprints << v;
    }
    for (const QString& s : p.allowedPublishers) {
        const QString v = s.trimmed();
        if (!v.isEmpty())
            norm.allowedPublishers << v;
    }

    policy() = norm;

    if (norm.installDir.isEmpty()) {
        // 这会让强制层无法判定,从而拒绝所有连接(fail-closed)。必须让它在日志里非常显眼。
        log().error(QStringLiteral(
            "控制管道认证:安装目录为空,将拒绝所有客户端连接。这是配置/接线错误,请检查 configure 调用。"));
    } else {
        log().info(QStringLiteral("控制管道认证已启用:%1").arg(policySummary()));
    }
}

QString IpcClientAuth::policySummary() {
    const Policy& p = policy();
    QString s = QStringLiteral("强制层=映像须位于「%1」且文件名属于 {%2}")
                    .arg(p.installDir.isEmpty() ? QStringLiteral("(未设置)") : p.installDir,
                         p.allowedImageNames.join(QStringLiteral(", ")));
    if (!p.enforceSignature) {
        s += QStringLiteral(";签名加固=关(当前构建的 UI 未做代码签名)");
    } else {
        s += QStringLiteral(";签名加固=开");
        if (!p.allowedThumbprints.isEmpty())
            s += QStringLiteral("(指纹白名单 %1 条)").arg(p.allowedThumbprints.size());
        else if (!p.allowedPublishers.isEmpty())
            s += QStringLiteral("(发布者白名单 %1 条)").arg(p.allowedPublishers.size());
        else
            s += QStringLiteral("(仅要求签名有效)");
    }
    return s;
}

IpcClientAuth::Result IpcClientAuth::authenticate(qintptr socketDescriptor) {
    Result r;

    Policy p;
    {
        QMutexLocker lk(&gate());
        p = policy();
    }

    // ---- 1) 对端 PID ----
    r.pid = clientPidOf(socketDescriptor);
    if (r.pid == 0) {
        r.reason = QStringLiteral("无法确定连接方进程(GetNamedPipeClientProcessId 失败,错误 %1)")
                       .arg(::GetLastError());
        return r;   // fail-closed
    }

    // ---- 2) 对端映像路径 ----
    r.imagePath = imagePathOf(r.pid);
    if (r.imagePath.trimmed().isEmpty()) {
        r.reason = QStringLiteral("无法解析连接方 PID %1 的映像路径(进程已退出或权限不足)").arg(r.pid);
        return r;   // fail-closed
    }

    // ---- 3) 强制层:安装目录 + 文件名 ----
    if (p.installDir.isEmpty()) {
        r.reason = QStringLiteral("服务未配置安装目录,认证无法进行(拒绝)");
        return r;
    }
    const QString lower = normPath(r.imagePath);
    if (!lower.startsWith(p.installDir)) {
        r.reason = QStringLiteral("连接方不在本产品安装目录内(PID %1:%2)").arg(r.pid).arg(r.imagePath);
        return r;
    }
    const QString name = QFileInfo(lower).fileName();
    if (!p.allowedImageNames.contains(name)) {
        r.reason = QStringLiteral("连接方映像名不在允许清单内(PID %1:%2)").arg(r.pid).arg(name);
        return r;
    }

    // ---- 4) 可选加固层:签名 ----
    if (p.enforceSignature) {
        using monitoring::ProcessInspector;
        if (!ProcessInspector::isSigned(r.imagePath)) {
            r.reason = QStringLiteral("已开启签名加固,但连接方无可信数字签名(PID %1:%2)")
                           .arg(r.pid).arg(r.imagePath);
            return r;
        }
        const bool haveAllowlist = !p.allowedThumbprints.isEmpty() || !p.allowedPublishers.isEmpty();
        if (haveAllowlist) {
            bool hit = false;
            if (!p.allowedThumbprints.isEmpty()) {
                const QString tp = normThumbprint(ProcessInspector::getCertInfo(r.imagePath).thumbprint);
                hit = !tp.isEmpty() && p.allowedThumbprints.contains(tp);
            }
            if (!hit && !p.allowedPublishers.isEmpty()) {
                const QString pub = ProcessInspector::tryGetPublisher(r.imagePath);
                if (!pub.isEmpty()) {
                    for (const QString& allowed : p.allowedPublishers) {
                        if (pub.contains(allowed, Qt::CaseInsensitive)) { hit = true; break; }
                    }
                }
            }
            if (!hit) {
                r.reason = QStringLiteral("连接方签名不在指纹/发布者白名单内(PID %1:%2)")
                               .arg(r.pid).arg(r.imagePath);
                return r;
            }
        }
    }

    r.ok = true;
    r.reason = QStringLiteral("PID %1 · %2").arg(r.pid).arg(QFileInfo(r.imagePath).fileName());
    return r;
}

} // namespace bulwark::service
