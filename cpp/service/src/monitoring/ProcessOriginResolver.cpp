// ProcessOriginResolver.cpp — 进程启动来源溯源实现(服务名 / 计划任务名)。
//
// 设计要点见头文件。这里补充几条实现层面的取舍:
//  * 全部缓存都是「按 TTL 整体重建」而不是逐项失效 —— 服务与任务的注册变动频率极低,
//    整体重建的代码简单得多,也不会有半新半旧的中间态。
//  * SCM / 任务计划程序 COM 都是对其它进程的 RPC。之所以敢在事件富化路径上调用:驱动侧
//    是 fire-and-forget 异步上报(FltSendMessage 0 超时),被创建的进程【不会】阻塞等我们
//    的裁决,因此不存在「对方在等我们、我们又在等对方」的死锁。即便如此仍加了 TTL 缓存和
//    「像不像服务/任务宿主」的前置判断,把这类调用压到极低频。
//  * 任何一步失败都降级返回,绝不让溯源影响裁决。

#include "bulwark/service/monitoring/ProcessOriginResolver.h"
#include "bulwark/service/monitoring/ProcessInspector.h"

#include <QDateTime>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QMutex>
#include <QMutexLocker>
#include <QRegularExpression>
#include <QSet>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsvc.h>
#include <oleauto.h>
#include <taskschd.h>

#include <algorithm>
#include <vector>

using namespace bulwark::service::monitoring;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

const wchar_t* wcstr(const QString& s)
{
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

QString fromWide(const wchar_t* w)
{
    return w ? QString::fromWCharArray(w) : QString();
}

qint64 nowMs() { return QDateTime::currentMSecsSinceEpoch(); }

QString lowerFileName(const QString& path)
{
    return QFileInfo(path).fileName().toLower();
}

// 展开 %SystemRoot% 之类的环境变量(任务 XML / 服务 ImagePath 里很常见)。
QString expandEnv(const QString& raw)
{
    if (raw.isEmpty() || !raw.contains(QLatin1Char('%')))
        return raw;
    wchar_t buf[1024];
    const DWORD n = ExpandEnvironmentStringsW(wcstr(raw), buf, 1024);
    if (n == 0 || n > 1024)
        return raw;
    return QString::fromWCharArray(buf);
}

// 从一条命令行里抠出可执行体路径(带引号取引号内,否则取到 .exe 结束或首个空格)。
QString extractImagePath(const QString& commandLine)
{
    QString s = commandLine.trimmed();
    if (s.isEmpty())
        return QString();
    if (s.startsWith(QLatin1Char('"'))) {
        const int end = s.indexOf(QLatin1Char('"'), 1);
        if (end > 1)
            return expandEnv(s.mid(1, end - 1));
    }
    // \??\C:\... 这种 NT 前缀在服务 ImagePath 里会出现。
    if (s.startsWith(QLatin1String("\\??\\")))
        s = s.mid(4);
    const int exeAt = s.indexOf(QLatin1String(".exe"), 0, Qt::CaseInsensitive);
    if (exeAt > 0)
        return expandEnv(s.left(exeAt + 4));
    const int sp = s.indexOf(QLatin1Char(' '));
    return expandEnv(sp > 0 ? s.left(sp) : s);
}

// svchost.exe -k <group> 里的分组名(共享宿主的分组标识)。
QString svchostGroup(const QString& commandLine)
{
    if (commandLine.isEmpty())
        return QString();
    static const QRegularExpression re(QStringLiteral("-k\\s+([A-Za-z0-9_.-]+)"),
                                       QRegularExpression::CaseInsensitiveOption);
    const auto m = re.match(commandLine);
    return m.hasMatch() ? m.captured(1) : QString();
}

// ============================ SCM:PID -> 服务名 ============================
struct ServiceRec {
    QString name;
    QString displayName;
};

struct ScmSnapshot {
    QHash<int, QList<ServiceRec>> byPid;
    qint64 builtAtMs = 0;
};

QMutex g_scmMx;
ScmSnapshot g_scm;
qint64 g_scmLastForcedMs = 0;
constexpr qint64 kScmTtlMs = 3000;         // 常规 TTL
constexpr qint64 kScmForceThrottleMs = 250; // 「刚启动的服务」强制刷新节流

ScmSnapshot buildScmSnapshot()
{
    ScmSnapshot snap;
    snap.builtAtMs = nowMs();

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm)
        return snap;

    DWORD needed = 0, returned = 0, resume = 0;
    // 先探大小(必然失败并给出 needed),再一次性枚举。
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
                          nullptr, 0, &needed, &returned, &resume, nullptr);
    if (needed == 0) {
        CloseServiceHandle(scm);
        return snap;
    }
    std::vector<BYTE> buf(needed + 64, 0);
    resume = 0;
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
                              buf.data(), static_cast<DWORD>(buf.size()), &needed, &returned,
                              &resume, nullptr)) {
        auto* arr = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < returned; ++i) {
            const DWORD pid = arr[i].ServiceStatusProcess.dwProcessId;
            if (pid == 0)
                continue;
            ServiceRec rec;
            rec.name = fromWide(arr[i].lpServiceName);
            rec.displayName = fromWide(arr[i].lpDisplayName);
            if (rec.name.isEmpty())
                continue;
            snap.byPid[static_cast<int>(pid)].append(rec);
        }
    }
    CloseServiceHandle(scm);
    return snap;
}

// force=true:忽略 TTL 强制重建一次(用于「服务进程刚创建、快照还没它」的竞态),
// 但仍有 250ms 节流,防止进程风暴下反复 RPC。
QList<ServiceRec> scmServicesFor(int pid, bool force)
{
    QMutexLocker lk(&g_scmMx);
    const qint64 t = nowMs();
    bool rebuild = (g_scm.builtAtMs == 0) || (t - g_scm.builtAtMs > kScmTtlMs);
    if (!rebuild && force && !g_scm.byPid.contains(pid)
        && (t - g_scmLastForcedMs > kScmForceThrottleMs)) {
        rebuild = true;
        g_scmLastForcedMs = t;
    }
    if (rebuild) {
        lk.unlock();
        ScmSnapshot fresh = buildScmSnapshot();
        lk.relock();
        // 只有拿到内容才替换,避免一次瞬时失败把好快照清空。
        if (!fresh.byPid.isEmpty() || g_scm.builtAtMs == 0)
            g_scm = std::move(fresh);
        else
            g_scm.builtAtMs = t;
    }
    return g_scm.byPid.value(pid);
}

// ============ 注册表:映像路径 / svchost 分组 -> 服务名(SCM 未命中时的回退)============
struct ServiceRegIndex {
    QHash<QString, QList<ServiceRec>> byImageName;  // 小写 exe 文件名 -> 服务
    QHash<QString, QList<ServiceRec>> byGroup;      // 小写 svchost -k 分组 -> 服务
    qint64 builtAtMs = 0;
};

QMutex g_regMx;
ServiceRegIndex g_reg;
constexpr qint64 kRegTtlMs = 5 * 60 * 1000;

ServiceRegIndex buildServiceRegIndex()
{
    ServiceRegIndex idx;
    idx.builtAtMs = nowMs();

    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_READ | KEY_WOW64_64KEY, &root) != ERROR_SUCCESS)
        return idx;

    for (DWORD i = 0;; ++i) {
        wchar_t nameBuf[256];
        DWORD nameLen = 256;
        if (RegEnumKeyExW(root, i, nameBuf, &nameLen, nullptr, nullptr, nullptr, nullptr)
            != ERROR_SUCCESS)
            break;
        const QString svcName = QString::fromWCharArray(nameBuf, static_cast<int>(nameLen));

        HKEY sub = nullptr;
        if (RegOpenKeyExW(root, nameBuf, 0, KEY_READ | KEY_WOW64_64KEY, &sub) != ERROR_SUCCESS)
            continue;

        auto readStr = [&sub](const wchar_t* value) -> QString {
            DWORD type = 0, cb = 0;
            if (RegQueryValueExW(sub, value, nullptr, &type, nullptr, &cb) != ERROR_SUCCESS || cb == 0)
                return QString();
            if (type != REG_SZ && type != REG_EXPAND_SZ)
                return QString();
            std::vector<BYTE> data(cb + sizeof(wchar_t), 0);
            if (RegQueryValueExW(sub, value, nullptr, &type, data.data(), &cb) != ERROR_SUCCESS)
                return QString();
            return QString::fromWCharArray(reinterpret_cast<const wchar_t*>(data.data()));
        };

        const QString imagePath = readStr(L"ImagePath");
        if (!imagePath.trimmed().isEmpty()) {
            ServiceRec rec;
            rec.name = svcName;
            rec.displayName = readStr(L"DisplayName");
            const QString exe = extractImagePath(imagePath);
            const QString key = lowerFileName(exe);
            if (!key.isEmpty())
                idx.byImageName[key].append(rec);
            const QString group = svchostGroup(imagePath);
            if (!group.isEmpty())
                idx.byGroup[group.toLower()].append(rec);
        }
        RegCloseKey(sub);
    }
    RegCloseKey(root);
    return idx;
}

ServiceRegIndex regIndex()
{
    QMutexLocker lk(&g_regMx);
    const qint64 t = nowMs();
    if (g_reg.builtAtMs == 0 || t - g_reg.builtAtMs > kRegTtlMs) {
        lk.unlock();
        ServiceRegIndex fresh = buildServiceRegIndex();
        lk.relock();
        if (!fresh.byImageName.isEmpty() || g_reg.builtAtMs == 0)
            g_reg = fresh;
        else
            g_reg.builtAtMs = t;
    }
    return g_reg;
}

// ============ 任务计划程序:运行中任务 EnginePID -> 任务路径(精确) ============
struct RunningTaskSnapshot {
    QHash<int, QString> pathByPid;
    qint64 builtAtMs = 0;
    bool comUsable = true;
};

QMutex g_taskMx;
RunningTaskSnapshot g_runningTasks;
constexpr qint64 kRunningTaskTtlMs = 1500;

// 每线程一次 COM 初始化。服务进程生命周期内不 CoUninitialize —— 反复 init/uninit 会把
// 同线程上其它 COM 用法(如 IShellLink)拆掉。
bool ensureCom()
{
    thread_local int state = 0; // 0=未试 1=可用 2=不可用
    if (state != 0)
        return state == 1;
    const HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    // 已被本线程以其它模式初始化过也算可用(RPC_E_CHANGED_MODE)。
    state = (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) ? 1 : 2;
    return state == 1;
}

RunningTaskSnapshot buildRunningTaskSnapshot()
{
    RunningTaskSnapshot snap;
    snap.builtAtMs = nowMs();
    if (!ProcessOriginResolver::taskComEnabled || !ensureCom()) {
        snap.comUsable = false;
        return snap;
    }

    ITaskService* svc = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(TaskScheduler), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(ITaskService), reinterpret_cast<void**>(&svc));
    if (FAILED(hr) || !svc) {
        snap.comUsable = false;
        return snap;
    }

    VARIANT empty;
    VariantInit(&empty);
    hr = svc->Connect(empty, empty, empty, empty);
    if (FAILED(hr)) {
        svc->Release();
        snap.comUsable = false;
        return snap;
    }

    IRunningTaskCollection* tasks = nullptr;
    hr = svc->GetRunningTasks(TASK_ENUM_HIDDEN, &tasks);
    if (SUCCEEDED(hr) && tasks) {
        LONG count = 0;
        tasks->get_Count(&count);
        for (LONG i = 1; i <= count; ++i) { // COM 集合下标从 1 开始
            IRunningTask* rt = nullptr;
            VARIANT idx;
            VariantInit(&idx);
            idx.vt = VT_I4;
            idx.lVal = i;
            if (FAILED(tasks->get_Item(idx, &rt)) || !rt)
                continue;
            DWORD enginePid = 0;
            BSTR path = nullptr;
            if (SUCCEEDED(rt->get_EnginePID(&enginePid)) && enginePid != 0
                && SUCCEEDED(rt->get_Path(&path)) && path) {
                snap.pathByPid.insert(static_cast<int>(enginePid), QString::fromWCharArray(path));
            }
            if (path)
                SysFreeString(path);
            rt->Release();
        }
        tasks->Release();
    }
    svc->Release();
    return snap;
}

QString runningTaskPathFor(int pid)
{
    QMutexLocker lk(&g_taskMx);
    const qint64 t = nowMs();
    if (g_runningTasks.builtAtMs == 0 || t - g_runningTasks.builtAtMs > kRunningTaskTtlMs) {
        lk.unlock();
        RunningTaskSnapshot fresh = buildRunningTaskSnapshot();
        lk.relock();
        g_runningTasks = fresh;
    }
    return g_runningTasks.pathByPid.value(pid);
}

// ============ 任务 XML 索引:映像路径 -> 任务路径候选(COM 不可用时的回退) ============
struct TaskFileIndex {
    QHash<QString, QStringList> byImageName; // 小写 exe 文件名 -> 任务路径列表
    qint64 builtAtMs = 0;
};

QMutex g_taskFileMx;
TaskFileIndex g_taskFiles;
constexpr qint64 kTaskFileTtlMs = 5 * 60 * 1000;
constexpr int kMaxTaskFiles = 4000; // 上限护栏:极端环境下任务目录可能被塞满

QString between(const QString& s, const QString& a, const QString& b)
{
    const int i = s.indexOf(a, 0, Qt::CaseInsensitive);
    if (i < 0)
        return QString();
    const int from = i + a.size();
    const int j = s.indexOf(b, from, Qt::CaseInsensitive);
    return j < 0 ? QString() : s.mid(from, j - from).trimmed();
}

TaskFileIndex buildTaskFileIndex()
{
    TaskFileIndex idx;
    idx.builtAtMs = nowMs();
    const QString windir = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
    const QString tasksRoot = windir + QStringLiteral("\\System32\\Tasks");
    if (!QDir(tasksRoot).exists())
        return idx;

    int seen = 0;
    QDirIterator it(tasksRoot, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext() && seen < kMaxTaskFiles) {
        const QString file = it.next();
        ++seen;
        QFile f(file);
        if (!f.open(QIODevice::ReadOnly))
            continue;
        // 任务 XML 通常几 KB;只读前 64KB 足够拿到 <Exec><Command>。
        const QString xml = QString::fromUtf8(f.read(64 * 1024));
        f.close();
        if (xml.isEmpty() || !xml.contains(QStringLiteral("<Exec")))
            continue;
        const QString cmd = between(xml, QStringLiteral("<Command>"), QStringLiteral("</Command>"));
        if (cmd.trimmed().isEmpty())
            continue;
        QString exe = expandEnv(QString(cmd).trimmed().remove(QLatin1Char('"')));
        const QString key = lowerFileName(exe);
        if (key.isEmpty())
            continue;
        const QString taskPath = QStringLiteral("\\") + QDir(tasksRoot).relativeFilePath(file);
        QStringList& list = idx.byImageName[key];
        if (!list.contains(taskPath))
            list.append(taskPath);
    }
    return idx;
}

QStringList taskCandidatesFor(const QString& imagePath)
{
    const QString key = lowerFileName(imagePath);
    if (key.isEmpty())
        return {};
    QMutexLocker lk(&g_taskFileMx);
    const qint64 t = nowMs();
    if (g_taskFiles.builtAtMs == 0 || t - g_taskFiles.builtAtMs > kTaskFileTtlMs) {
        lk.unlock();
        TaskFileIndex fresh = buildTaskFileIndex();
        lk.relock();
        if (!fresh.byImageName.isEmpty() || g_taskFiles.builtAtMs == 0)
            g_taskFiles = fresh;
        else
            g_taskFiles.builtAtMs = t;
    }
    return g_taskFiles.byImageName.value(key);
}

// ============================ 父进程角色判定 ============================
enum class HostRole {
    Other = 0,
    Scm,           // services.exe
    TaskEngine,    // taskeng.exe(Win7)
    TaskHost,      // 承载 Schedule 服务的 svchost.exe(Win8+)
    ServiceHost,   // 其它 svchost.exe
    WmiProvider,   // wmiprvse.exe
    Userinit,      // userinit.exe(登录自启动)
    SystemBoot,    // smss / wininit / csrss / winlogon
};

HostRole classifyParent(int parentPid, const QString& parentImage)
{
    const QString name = lowerFileName(parentImage);
    if (name == QLatin1String("services.exe"))
        return HostRole::Scm;
    if (name == QLatin1String("taskeng.exe"))
        return HostRole::TaskEngine;
    if (name == QLatin1String("wmiprvse.exe"))
        return HostRole::WmiProvider;
    if (name == QLatin1String("userinit.exe"))
        return HostRole::Userinit;
    if (name == QLatin1String("smss.exe") || name == QLatin1String("wininit.exe")
        || name == QLatin1String("csrss.exe") || name == QLatin1String("winlogon.exe"))
        return HostRole::SystemBoot;
    if (name == QLatin1String("svchost.exe")) {
        // 关键一步:这个 svchost 里跑的是不是 Schedule(任务计划程序)?是则它派生的进程
        // 就是计划任务拉起来的。用 SCM 权威快照判定,不靠命令行分组名猜。
        for (const ServiceRec& r : scmServicesFor(parentPid, false))
            if (r.name.compare(QLatin1String("Schedule"), Qt::CaseInsensitive) == 0)
                return HostRole::TaskHost;
        return HostRole::ServiceHost;
    }
    return HostRole::Other;
}

QString joinServiceNames(const QList<ServiceRec>& recs)
{
    QStringList names;
    for (const ServiceRec& r : recs)
        names << r.name;
    return names.join(QStringLiteral(", "));
}

// ============================ 结果备忘缓存 ============================
// 事件富化会对同一个进程反复调用(它每写一个文件、每发一次连接都要溯源一次)。底层数据源
// 已各自带 TTL 缓存,但分类本身还要几次 OpenProcess,所以把最终结论也记下来。
// 缓存键带上映像文件名:PID 被复用给别的程序时键不同,自然不会拿到上一个进程的结论。
struct OriginMemo {
    ProcessOrigin origin;
    qint64 atMs = 0;
};

QMutex g_memoMx;
QHash<QString, OriginMemo> g_memo;
constexpr qint64 kMemoTtlMs = 60 * 1000;
constexpr int kMemoCapacity = 4096;

QString memoKey(int pid, const QString& imagePath)
{
    return QString::number(pid) + QLatin1Char('|') + lowerFileName(imagePath);
}

} // namespace

// ============================================================================

QStringList ProcessOriginResolver::servicesHostedBy(int pid)
{
    QStringList out;
    if (pid <= 4)
        return out;
    for (const ServiceRec& r : scmServicesFor(pid, false))
        out << r.name;
    return out;
}

void ProcessOriginResolver::invalidateCaches()
{
    { QMutexLocker lk(&g_scmMx);      g_scm = ScmSnapshot{}; }
    { QMutexLocker lk(&g_regMx);      g_reg = ServiceRegIndex{}; }
    { QMutexLocker lk(&g_taskMx);     g_runningTasks = RunningTaskSnapshot{}; }
    { QMutexLocker lk(&g_taskFileMx); g_taskFiles = TaskFileIndex{}; }
    { QMutexLocker lk(&g_memoMx);     g_memo.clear(); }
}

void ProcessOriginResolver::invalidateMemo() { QMutexLocker lk(&g_memoMx); g_memo.clear(); }

ProcessOrigin ProcessOriginResolver::resolve(int pid, const QString& imagePathIn, int parentPidIn,
                                            const QString& commandLineIn)
{
    ProcessOrigin origin;
    if (pid <= 4)
        return origin;

    try {
        QString imagePath = imagePathIn;
        if (imagePath.isEmpty() || imagePath.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
            imagePath = ProcessInspector::tryGetProcessImagePath(pid);

        // 备忘缓存:同一进程在事件富化里会被反复问到,结论 60 秒内复用。
        const QString key = memoKey(pid, imagePath);
        {
            QMutexLocker lk(&g_memoMx);
            auto it = g_memo.constFind(key);
            if (it != g_memo.constEnd() && nowMs() - it.value().atMs < kMemoTtlMs)
                return it.value().origin;
        }
        // 各出口都要落缓存,用一个作用域守卫统一做,免得漏。
        struct MemoGuard {
            QString key;
            const ProcessOrigin* origin;
            ~MemoGuard() {
                QMutexLocker lk(&g_memoMx);
                if (g_memo.size() >= kMemoCapacity)
                    g_memo.clear();
                g_memo.insert(key, OriginMemo{ *origin, nowMs() });
            }
        } memoGuard{ key, &origin };

        int parentPid = parentPidIn;
        if (parentPid < 0)
            parentPid = ProcessInspector::tryGetParentPid(pid);
        const QString parentImage = parentPid > 0
                                        ? ProcessInspector::tryGetProcessImagePath(parentPid)
                                        : QString();

        // ---- 1) 本进程自己就是服务进程?SCM 快照是权威答案(svchost 会给出多个服务)。----
        //      仅当父进程是 services.exe 时才允许「强制刷新一次」:那正是「服务进程刚被 SCM
        //      创建、快照还没登记它」的竞态场景。对普通进程强制刷新只是白做 RPC —— 一次进程
        //      快照要问几百个 PID,不设这个条件会把 SCM 反复敲一遍。
        const bool freshServiceLikely =
            lowerFileName(parentImage) == QLatin1String("services.exe");
        const QList<ServiceRec> own = scmServicesFor(pid, freshServiceLikely);
        if (!own.isEmpty()) {
            origin.kind = bulwark::ProcessOriginKind::Service;
            origin.serviceName = joinServiceNames(own);
            origin.serviceDisplayName = own.first().displayName;
            origin.highConfidence = true;
            origin.detail = own.size() > 1
                ? u("SCM 权威映射:该进程为共享服务宿主,承载 %1 个服务").arg(own.size())
                : u("SCM 权威映射:该进程即服务 %1 的宿主").arg(own.first().name);
            return origin;
        }

        const HostRole role = classifyParent(parentPid, parentImage);

        switch (role) {
        case HostRole::TaskEngine:
        case HostRole::TaskHost: {
            // 「是计划任务拉起的」这一步已经确定(父进程就是任务宿主),下面只是定名。
            origin.kind = bulwark::ProcessOriginKind::ScheduledTask;
            const QString exact = runningTaskPathFor(pid);
            if (!exact.isEmpty()) {
                origin.taskPath = exact;
                origin.highConfidence = true;
                origin.detail = u("任务计划程序运行中任务按 EnginePID 精确匹配");
                return origin;
            }
            const QStringList cands = taskCandidatesFor(imagePath);
            if (cands.size() == 1) {
                origin.taskPath = cands.first();
                origin.detail = u("按任务定义中的映像路径反查,唯一命中(中置信)");
            } else if (cands.size() > 1) {
                origin.taskPath = cands.first();
                origin.detail = u("由计划任务启动;按映像路径反查到 %1 个候选任务:%2")
                                    .arg(cands.size())
                                    .arg(cands.mid(0, 4).join(QStringLiteral(" | ")));
            } else {
                origin.detail = (role == HostRole::TaskEngine)
                    ? u("父进程为 taskeng.exe,确定由计划任务启动,但未能确定具体任务")
                    : u("父进程为承载 Schedule 服务的 svchost.exe,确定由计划任务启动,"
                        "但未能确定具体任务");
            }
            return origin;
        }
        case HostRole::Scm: {
            // 父进程是 SCM,但 SCM 快照里没有本 PID —— 典型是「服务进程刚创建、还没登记」或
            // 服务已启动失败退出。注册表 ImagePath 反查:服务的注册一定早于进程启动,拿得到。
            origin.kind = bulwark::ProcessOriginKind::Service;
            const ServiceRegIndex idx = regIndex();
            QList<ServiceRec> cands = idx.byImageName.value(lowerFileName(imagePath));
            const QString group = svchostGroup(commandLineIn);
            if (cands.isEmpty() && !group.isEmpty())
                cands = idx.byGroup.value(group.toLower());
            if (cands.size() == 1) {
                origin.serviceName = cands.first().name;
                origin.serviceDisplayName = cands.first().displayName;
                origin.detail = u("父进程为 services.exe;按服务注册表 ImagePath 反查,唯一命中(中置信)");
            } else if (cands.size() > 1) {
                origin.serviceName = joinServiceNames(cands.mid(0, 6));
                origin.serviceDisplayName = cands.first().displayName;
                origin.detail = u("父进程为 services.exe;按 ImagePath%1 反查到 %2 个候选服务")
                                    .arg(group.isEmpty() ? QString()
                                                         : u(" / 分组 %1").arg(group))
                                    .arg(cands.size());
            } else {
                origin.detail = u("父进程为 services.exe,确定由 SCM 启动,但未能确定具体服务");
            }
            return origin;
        }
        case HostRole::WmiProvider:
            origin.kind = bulwark::ProcessOriginKind::WmiProvider;
            origin.detail = u("父进程为 WMI 提供者宿主 wmiprvse.exe(WMI 远程/本地调用派生)");
            return origin;
        case HostRole::Userinit:
            origin.kind = bulwark::ProcessOriginKind::LogonAutostart;
            origin.detail = u("父进程为 userinit.exe(用户登录初始化链)");
            return origin;
        case HostRole::SystemBoot:
            origin.kind = bulwark::ProcessOriginKind::SystemBoot;
            origin.detail = u("父进程为系统启动组件 %1").arg(lowerFileName(parentImage));
            return origin;
        case HostRole::ServiceHost: {
            // 父进程是别的 svchost(不是 Schedule):本进程是某服务派生的子进程。
            // 把「哪个服务的宿主」标出来,溯源链上就能看到是哪个服务在派生进程。
            const QList<ServiceRec> hosted = scmServicesFor(parentPid, false);
            origin.kind = bulwark::ProcessOriginKind::Service;
            if (!hosted.isEmpty()) {
                origin.serviceName = joinServiceNames(hosted.mid(0, 6));
                origin.serviceDisplayName = hosted.first().displayName;
                origin.highConfidence = hosted.size() == 1;
                origin.detail = u("由服务宿主 svchost.exe(PID %1,承载 %2)派生")
                                    .arg(parentPid)
                                    .arg(joinServiceNames(hosted.mid(0, 6)));
            } else {
                origin.detail = u("由 svchost.exe(PID %1)派生,未能确定具体服务").arg(parentPid);
            }
            return origin;
        }
        case HostRole::Other:
        default:
            break;
        }

        // ---- 其它情况:普通父进程。不硬凑分类,只在能确定时标 Interactive。----
        if (!parentImage.isEmpty()) {
            origin.kind = bulwark::ProcessOriginKind::Interactive;
            origin.detail = u("由 %1(PID %2)启动").arg(lowerFileName(parentImage)).arg(parentPid);
        }
        return origin;
    } catch (...) {
        return ProcessOrigin{}; // 溯源永远不许影响裁决
    }
}
