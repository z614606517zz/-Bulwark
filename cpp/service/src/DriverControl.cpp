#include "bulwark/service/DriverControl.h"
#include "bulwark/service/Logger.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QProcess>
#include <QStringList>

namespace bulwark::service {

namespace {

Logger& log() {
    static Logger l(QStringLiteral("bulwark.service.Driver"));
    return l;
}

const QString kServiceName = QStringLiteral("Bulwark");
const QString kAltitude    = QStringLiteral("385201");
const QString kInstance    = QStringLiteral("Bulwark Instance");

// 同步执行一条命令,返回 (退出码, 合并的 stdout+stderr)。失败(启动不了)返回 (-1, "")。
struct ExecResult { int code = -1; QString output; };

ExecResult exec(const QString& program, const QStringList& args, int timeoutMs = 15000) {
    QProcess p;
    p.setProcessChannelMode(QProcess::MergedChannels);
    p.start(program, args);
    if (!p.waitForStarted(5000))
        return {};
    if (!p.waitForFinished(timeoutMs)) {
        p.kill();
        p.waitForFinished(2000);
    }
    ExecResult r;
    r.code = (p.exitStatus() == QProcess::NormalExit) ? p.exitCode() : -1;
    r.output = QString::fromLocal8Bit(p.readAll());
    return r;
}

// 服务是否已在 SCM 注册(sc query 不返回 1060 / does not exist / 未安装)。
bool isRegistered() {
    const ExecResult r = exec(QStringLiteral("sc.exe"), { QStringLiteral("query"), kServiceName });
    if (r.code < 0)
        return false;
    return !r.output.contains(QStringLiteral("1060"))
        && !r.output.contains(QStringLiteral("does not exist"), Qt::CaseInsensitive)
        && !r.output.contains(QString::fromUtf8("\xE6\x9C\xAA\xE5\xAE\x89\xE8\xA3\x85")); // 未安装
}

// 若未注册则自动注册 minifilter 服务(sc create + Instances/Altitude 注册表)。
void ensureRegistered() {
    if (isRegistered())
        return;

    const QString sys = DriverControl::locateSys();
    if (sys.isEmpty()) {
        log().warning(QStringLiteral("未找到 Bulwark.sys,无法注册内核驱动(将降级为用户态观测)。"));
        return;
    }

    // 1) 创建 minifilter 服务(type=filesys, 依赖 FltMgr, demand 启动)。
    //    sc.exe 语法要求 "key= value" 中的 '=' 紧跟键、值为独立参数。
    const ExecResult create = exec(QStringLiteral("sc.exe"), {
        QStringLiteral("create"), kServiceName,
        QStringLiteral("type="),   QStringLiteral("filesys"),
        QStringLiteral("binPath="), QDir::toNativeSeparators(sys),
        QStringLiteral("start="),  QStringLiteral("demand"),
        QStringLiteral("depend="), QStringLiteral("FltMgr"),
        QStringLiteral("group="),  QStringLiteral("FSFilter Activity Monitor"),
    });
    if (create.code != 0 && !create.output.contains(QStringLiteral("1073"))) { // 1073=已存在
        log().warning(QStringLiteral("注册内核驱动失败(sc create code=%1):%2")
                          .arg(create.code).arg(create.output.trimmed()));
        return;
    }

    // 2) 写 Minifilter 实例配置:Instances\DefaultInstance + <实例>\Altitude/Flags。
    const QString base = QStringLiteral("HKLM\\SYSTEM\\CurrentControlSet\\Services\\%1\\Instances").arg(kServiceName);
    exec(QStringLiteral("reg.exe"), { QStringLiteral("add"), base,
        QStringLiteral("/v"), QStringLiteral("DefaultInstance"),
        QStringLiteral("/t"), QStringLiteral("REG_SZ"),
        QStringLiteral("/d"), kInstance, QStringLiteral("/f") });
    const QString instKey = base + QStringLiteral("\\") + kInstance;
    exec(QStringLiteral("reg.exe"), { QStringLiteral("add"), instKey,
        QStringLiteral("/v"), QStringLiteral("Altitude"),
        QStringLiteral("/t"), QStringLiteral("REG_SZ"),
        QStringLiteral("/d"), kAltitude, QStringLiteral("/f") });
    exec(QStringLiteral("reg.exe"), { QStringLiteral("add"), instKey,
        QStringLiteral("/v"), QStringLiteral("Flags"),
        QStringLiteral("/t"), QStringLiteral("REG_DWORD"),
        QStringLiteral("/d"), QStringLiteral("0"), QStringLiteral("/f") });

    log().info(QStringLiteral("内核驱动已自动注册(minifilter,Altitude=%1,binPath=%2)。")
                   .arg(kAltitude, QDir::toNativeSeparators(sys)));
}

bool runFltmc(const QString& verb) {
    const ExecResult r = exec(QStringLiteral("fltmc.exe"), { verb, kServiceName });
    if (r.code == 0) {
        log().info(QStringLiteral("内核驱动 fltmc %1 成功。").arg(verb));
        return true;
    }
    log().info(QStringLiteral("fltmc %1 返回 code=%2(将尝试 sc 回退):%3")
                   .arg(verb).arg(r.code).arg(r.output.trimmed()));
    return false;
}

bool runSc(const QString& verb) {
    const ExecResult r = exec(QStringLiteral("sc.exe"), { verb, kServiceName });
    const bool ok = r.code == 0
        || r.output.contains(QStringLiteral("1056"))                                  // already running
        || (verb == QStringLiteral("stop") && r.output.contains(QStringLiteral("1062"))); // not started
    if (ok)
        log().info(QStringLiteral("内核驱动 sc %1 成功。").arg(verb));
    else
        log().warning(QStringLiteral("内核驱动 sc %1 失败(code=%2):%3")
                          .arg(verb).arg(r.code).arg(r.output.trimmed()));
    return ok;
}

} // namespace

QString DriverControl::locateSys() {
    QStringList candidates;
    const QString sysRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
    candidates << QDir(sysRoot).filePath(QStringLiteral("System32/drivers/Bulwark.sys"));
    candidates << QStringLiteral("C:/BulwarkDrv/Bulwark.sys");
    candidates << QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("Bulwark.sys"));
    for (const QString& c : candidates) {
        if (QFileInfo::exists(c))
            return QDir::cleanPath(c);
    }
    return QString();
}

bool DriverControl::isRunning() {
    const ExecResult r = exec(QStringLiteral("sc.exe"), { QStringLiteral("query"), kServiceName });
    return r.code >= 0 && r.output.contains(QStringLiteral("RUNNING"), Qt::CaseInsensitive);
}

bool DriverControl::ensureLoaded() {
    if (isRunning())
        return true;
    ensureRegistered();                       // 首次或被清理后自动注册
    if (runFltmc(QStringLiteral("load")) || runSc(QStringLiteral("start")))
        return true;
    return isRunning();
}

bool DriverControl::tryStop() {
    return runFltmc(QStringLiteral("unload")) || runSc(QStringLiteral("stop"));
}

} // namespace bulwark::service
