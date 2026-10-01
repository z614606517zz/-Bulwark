#include "bulwark/service/EtwProcessEventSource.h"
#include "bulwark/service/Logger.h"
#include "bulwark/engine/DgaDomainAnalyzer.h" // SuspiciousOnly DNS 预过滤
#include "bulwark/service/monitoring/ProcessInspector.h" // NetworkUntrustedOnly 主体验签(按 PID 记忆)

#include <QTimer>
#include <QMutex>
#include <QMutexLocker>
#include <QFileInfo>
#include <QMap>
#include <QHash>
#include <QSet>
#include <QString>
#include <QStringList>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <thread>

// krabs 需要 windows.h;放到 Qt 头之后,并抑制会与 Qt/标准库冲突的宏。
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <krabs.hpp>

namespace bulwark::service {

namespace {

// Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
const wchar_t* const kKernelProcessGuid = L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}";
constexpr USHORT    kProcessStartEventId = 1;    // manifest: ProcessStart
constexpr USHORT    kThreadStartEventId  = 3;    // manifest: ThreadStart(负载 ProcessID/ThreadID)
constexpr USHORT    kImageLoadEventId    = 5;    // manifest: ImageLoad(负载 ImageName/ProcessID)
constexpr ULONGLONG kKeywordProcess      = 0x10; // WINEVENT_KEYWORD_PROCESS
constexpr ULONGLONG kKeywordThread       = 0x20; // WINEVENT_KEYWORD_THREAD(连带投递 ThreadStop=4)
constexpr ULONGLONG kKeywordImage        = 0x40; // WINEVENT_KEYWORD_IMAGE(连带投递 ImageUnload=6)
constexpr int       kQueueMax            = 4096; // 队列上限,防止事件风暴撑爆内存
// 「刚诞生的进程」登记表的软上限。超过即按年龄裁剪(见 Impl::notePidBirth 的说明)。
constexpr int       kProcBirthSoftMax    = 512;

// Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88}
// 事件 12 = ConnectionAttempted(出站 TCP 连接);字段 PID/daddr/dport(IPv4)。
// 事件 ID/字段名依据公开 provider manifest(repnz/etw-providers-docs)与 Velociraptor
// 的 Windows.ETW.KernelNetwork 实现(10=DataSent 11=DataReceived 12=ConnectionAttempted
// 15=ConnectionAccepted 42/43=UDP)。
const wchar_t* const kKernelNetworkGuid  = L"{7DD42A49-5329-4832-8DFD-43D979153A88}";
constexpr USHORT     kNetConnectEventId  = 12;

// Microsoft-Windows-DNS-Client {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
// 事件 3006 = 发起查询;字段 QueryName。DNS-Client 在调用方进程内触发,PID 取事件头。
const wchar_t* const kDnsClientGuid      = L"{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}";
constexpr USHORT     kDnsQueryEventId    = 3006;

// Microsoft-Windows-Kernel-Registry {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
// 事件 1=CreateKey 2=OpenKey 3=DeleteKey 4=QueryKey 5=SetValueKey 6=DeleteValueKey …
// create/open 事件带 KeyObject + RelativeName;写事件(delete/setvalue)只带 KeyObject,故用
// KeyObject->名 关联缓存(create/open 填充)解析键路径。keyword 0x7720 与字段名依据 Velociraptor
// 的 Windows.ETW.Registry 实现。注:该提供程序官方并不完全可靠、可能漏事件(尽力而为)。
const wchar_t* const kKernelRegistryGuid = L"{70EB4F03-C1DE-4F73-A051-33D13D5413BD}";
constexpr ULONGLONG  kKeywordRegistry    = 0x7720;
constexpr USHORT     kRegCreateKey       = 1;
constexpr USHORT     kRegOpenKey         = 2;
constexpr USHORT     kRegDeleteKey       = 3;
constexpr USHORT     kRegSetValueKey     = 5;
constexpr USHORT     kRegDeleteValueKey  = 6;
constexpr int        kRegNameCacheMax    = 8192; // KeyObject->名 关联缓存上限(满则粗放清空)

// Microsoft-Windows-Kernel-File {EDD08927-9CC4-4E65-B970-C2560FB5C289}
// 事件 30=CreateNewFile(新建文件,带 FileName)-> FileWrite;26=DeletePath(带 FilePath)-> FileDelete。
// 二者都直接带路径,无需 FileObject->名 关联。keyword 0x1400 = CREATE_NEW_FILE|DELETE_PATH:刻意
// 只投递这两类,排除海量 open/read/write(既避免洪泛,又规避 Write 事件只带 FileObject 的关联复杂度)。
// 事件 ID / keyword / 字段名依据公开 provider manifest(repnz/etw-providers-docs)。
// 覆盖:受保护目录内「新建文件」+「删除受保护文件」;就地改写已存在文件(Write,需 FileObject 关联)
// 为更重的后续增强,暂不覆盖。路径为 \Device\HarddiskVolumeN 形式,经 deviceToDrive 归一为盘符。
const wchar_t* const kKernelFileGuid     = L"{EDD08927-9CC4-4E65-B970-C2560FB5C289}";
constexpr ULONGLONG  kKeywordFile        = 0x1400;
constexpr USHORT     kFileDeletePath     = 26;
constexpr USHORT     kFileCreateNew      = 30;
//
// 写入归因(Etw.KernelFileWriteAttribution,默认关)用到的两类事件。实机核对的结果:
//   事件 12 Create        keyword 0xA0  (CREATE 0x80 | FILEIO 0x20)
//                         字段 Irp / FileObject / IssuingThreadId / CreateOptions /
//                              CreateAttributes / ShareAccess / FileName
//   事件 16 Write         keyword 0x220 (WRITE 0x200 | FILEIO 0x20)
//                         字段 ByteOffset / Irp / FileObject / FileKey / IssuingThreadId /
//                              IOSize / IOFlags / ExtraFlags   —— 【不带路径】
//   事件 30 CreateNewFile keyword 0x1000,字段同 12(带 FileName)
// 所以「谁改写了这个文件」只能靠 Create/CreateNewFile 记下 FileObject -> 路径,再由 Write
// 反查;而 Write 的事件头 ProcessId 就是写入者(已核对:探针 pid 24200 写诱饵,事件 16 的
// header_pid 正是 24200)。
//
// 注:FileKey 是 FsContext(按【文件】稳定、跨句柄共享),比 FileObject 更稳,但 Create 事件
// 【不带】这个字段,所以建表只能用 FileObject。
//
constexpr USHORT     kFileCreate         = 12;
constexpr USHORT     kFileWrite          = 16;
constexpr ULONGLONG  kKeywordFileCreate  = 0x80;
constexpr ULONGLONG  kKeywordFileWrite   = 0x200;
// FileObject -> 路径 映射的条数上限。只收归因路径,正常只有个位数条目;这个上限是防御
// 「归因路径配得很多 + 每条被反复打开」的极端情况。
constexpr int        kFileObjMapMax      = 4096;

// 目标是否命中监视集(任一子串,大小写不敏感)。空监视集 => 不命中(即不上报)。
inline bool matchesWatch(const QString& target, const QStringList& watch) {
    for (const QString& w : watch)
        if (!w.isEmpty() && target.contains(w, Qt::CaseInsensitive))
            return true;
    return false;
}

// 「往用户可写目录里新建了一个可执行体 / 脚本」—— 投递(dropper)最有辨识度的那一个动作。
//
// 为什么要单独一条判据、而不是往 fileWatch_ 里加目录:
//   * fileWatch_ 是【纯子串】匹配,表达不了「在 \Temp\ 里 且 后缀是 .exe」。往里加
//     "\Temp\" 会把每个程序的临时文件全量收进来 —— 那是真正的洪泛。
//   * 而「新建可执行体/脚本」本身是极低频事件:空闲机器上每分钟个位数,安装器/更新器
//     会有突发,但 EmitGate 的每进程每分钟上限已经压住了。
// 这条判据补上的是本产品好几处能力的共同前提:攻击链的「往 Public / Temp 落文件」类标记
// 原先只能靠驱动「偏移 0 写」的全局 1/32 采样(单次落盘约 1/32 概率被看到),而
// Worker::maybeScanDroppedInstaller(落盘即扫 VT)同样挂在 FileWrite 上,一起形同虚设。
inline bool isDroppedExecutable(const QString& path) {
    static const QStringList kExt = {
        QStringLiteral(".exe"), QStringLiteral(".dll"), QStringLiteral(".sys"),
        QStringLiteral(".scr"), QStringLiteral(".cpl"), QStringLiteral(".ocx"),
        QStringLiteral(".msi"), QStringLiteral(".msp"), QStringLiteral(".jar"),
        QStringLiteral(".bat"), QStringLiteral(".cmd"), QStringLiteral(".ps1"),
        QStringLiteral(".vbs"), QStringLiteral(".vbe"), QStringLiteral(".js"),
        QStringLiteral(".jse"), QStringLiteral(".wsf"), QStringLiteral(".wsh"),
        QStringLiteral(".hta"), QStringLiteral(".lnk"), QStringLiteral(".pif"),
        QStringLiteral(".com"),
    };
    // 用户可写位置。\Users\ 一并覆盖 AppData / Downloads / Desktop / Public;
    // 另加 ProgramData 与 \Windows\Temp\(服务与提权后的投递常落在那里)。
    static const QStringList kDirs = {
        QStringLiteral("\\Users\\"), QStringLiteral("\\ProgramData\\"),
        QStringLiteral("\\Windows\\Temp\\"), QStringLiteral("\\Temp\\"),
        QStringLiteral("\\PerfLogs\\"),
    };
    bool extOk = false;
    for (const QString& x : kExt) {
        if (path.endsWith(x, Qt::CaseInsensitive)) { extOk = true; break; }
    }
    if (!extOk)
        return false;
    for (const QString& d : kDirs) {
        if (path.contains(d, Qt::CaseInsensitive))
            return true;
    }
    return false;
}

// 这个模块加载值不值得上报。ImageLoad 是高频事件流,过滤【必须在 ETW 回调内做完】——
// 放到富化阶段就等于每条都要付一次 Authenticode 验签 + SHA-256。
//
// 实测依据(本机 5.5 秒抓取,含一次 notepad 冷启动):161 条 ImageLoad,全部落在
// \Windows\ 与 \Program Files\ 下,本判据挡掉 100%。所以这里刻意只用纯字符串判断,
// 一次验签都不做。
//
// 为什么不是简单的「不在系统目录就报」:
//   * \Windows\Temp\ 【必须保留】—— 它带着 \Windows\,但那是服务/提权后投递最常用的落点,
//     一刀切掉等于在最需要看见的位置上瞎掉;所以落地区判据放在系统目录判据【之前】。
//   * 扩展名收窄到模块类(.dll/.sys/...)并【排除 .exe】:主映像自己也会触发一条 ImageLoad,
//     而那件事已经由 ProcessCreate 覆盖,收进来只是把同一个动作报两遍。
inline bool isSuspectModulePath(const QString& path) {
    static const QStringList kModExt = {
        QStringLiteral(".dll"), QStringLiteral(".sys"), QStringLiteral(".ocx"),
        QStringLiteral(".cpl"), QStringLiteral(".drv"), QStringLiteral(".acm"),
        QStringLiteral(".ax"),  QStringLiteral(".efi"), QStringLiteral(".scr"),
    };
    bool extOk = false;
    for (const QString& x : kModExt) {
        if (path.endsWith(x, Qt::CaseInsensitive)) { extOk = true; break; }
    }
    if (!extOk)
        return false;

    // ① 用户可写落地区:一律上报(侧载 / BYOVD 的模块几乎只从这些地方来)。
    static const QStringList kDropDirs = {
        QStringLiteral("\\Users\\"), QStringLiteral("\\ProgramData\\"),
        QStringLiteral("\\Windows\\Temp\\"), QStringLiteral("\\Temp\\"),
        QStringLiteral("\\PerfLogs\\"),
    };
    for (const QString& d : kDropDirs) {
        if (path.contains(d, Qt::CaseInsensitive))
            return true;
    }
    // ② 其余:系统目录与安装目录下的模块不报(那是每个进程启动都要加载的几十上百条)。
    static const QStringList kSystemDirs = {
        QStringLiteral("\\Windows\\"), QStringLiteral("\\Program Files\\"),
        QStringLiteral("\\Program Files (x86)\\"),
    };
    for (const QString& d : kSystemDirs) {
        if (path.contains(d, Qt::CaseInsensitive))
            return false;
    }
    // ③ 既不在落地区、也不在系统/安装目录(例如 D:\ 根、第三方自建目录):上报。
    return true;
}

// System32 的真实绝对路径(取一次)。用于把下面那张豁免表锚定到系统目录。
inline QString system32Dir() {
    static const QString dir = [] {
        wchar_t buf[MAX_PATH] = {};
        const UINT n = ::GetSystemDirectoryW(buf, MAX_PATH);
        return (n > 0 && n < MAX_PATH)
            ? QString::fromWCharArray(buf, static_cast<int>(n))
            : QStringLiteral("C:\\Windows\\System32");
    }();
    return dir;
}

// 这个「跨进程建线程」的发起方是不是操作系统自己的正常机制。
//
// 不是猜的,是实测:一次无驱动验证里抓到
//   放行 RemoteThread C:\Windows\System32\csrss.exe -> ...\powershell.exe(风险 30)
// 那是控制台的 Ctrl+C / Ctrl+Break 处理线程(CtrlRoutine)—— 每开一个控制台就来一次。
// 它不到拦截线,但会污染活动日志,更要紧的是会作为一个「注入」动作点亮攻击链组合。
//
// 【为什么必须按完整路径、不能按文件名】RuleDsl.h 里记着一个同类教训:步骤 6 的 isDevTool
// 是纯文件名匹配,样本改名成 setup.exe 就能让所有 Ask 规则失效。这里若只比 "csrss.exe",
// 把载荷改名成 csrss.exe 扔进任意目录就能白拿一张注入豁免。锚定到 System32 的绝对路径后,
// 冒名者因为写不进 System32(WRP 保护,需要 TrustedInstaller)而拿不到豁免。
//
// 【这张表刻意只收有实测证据的条目】要加新的,先拿到「该进程在本机确实这么干」的抓取记录
// 再加;凭印象往里塞等于给注入检测开一个按路径的后门。
inline bool isOsThreadInjector(const QString& creatorPath) {
    if (creatorPath.isEmpty())
        return false;
    static const QString kCsrss = system32Dir() + QStringLiteral("\\csrss.exe");
    return creatorPath.compare(kCsrss, Qt::CaseInsensitive) == 0;
}

// ETW 以网络序存 InAddr:小端机器上 uint32 的最低字节即首个八位组。
inline QString ipv4ToString(quint32 addr) {
    return QStringLiteral("%1.%2.%3.%4")
        .arg(addr & 0xFF).arg((addr >> 8) & 0xFF)
        .arg((addr >> 16) & 0xFF).arg((addr >> 24) & 0xFF);
}

// dport 以网络序(大端)存储,换算为主机序端口号。
inline quint16 netToHostPort(quint16 p) {
    return static_cast<quint16>((p << 8) | (p >> 8));
}

// 出射限流闸:每进程每分钟上限 + (进程,目标) 去重窗口。仅在单一 ETW 消费线程上
// 调用,故无需加锁。用于压制富化管线洪泛(C# 侧由内核驱动在内核内过滤)。
struct EmitGate {
    int    perMinCap     = 0; // 每进程每分钟上限(<=0 不限)
    qint64 dedupWindowMs = 0; // (进程,目标) 去重窗口毫秒(<=0 不去重)
    qint64 minStart      = 0;
    qint64 dedupStart    = 0;
    QHash<quint32, int> perPid; // 当前分钟窗口内各进程计数
    QSet<QString>       dedup;  // 当前去重窗口内的 "pid|target"

    bool allow(quint32 pid, const QString& target, qint64 nowMs) {
        if (nowMs - minStart >= 60000) { minStart = nowMs; perPid.clear(); }
        if (dedupWindowMs > 0 && nowMs - dedupStart >= dedupWindowMs) {
            dedupStart = nowMs;
            dedup.clear();
        }
        QString key;
        if (dedupWindowMs > 0) {
            key = QString::number(pid) + QLatin1Char('|') + target;
            if (dedup.contains(key)) return false; // 窗口内已上报过,丢弃
        }
        if (perMinCap > 0 && perPid.value(pid, 0) >= perMinCap) return false; // 超速丢弃
        if (perMinCap > 0) ++perPid[pid];
        if (dedupWindowMs > 0) dedup.insert(key);
        return true;
    }
};

// 构建 \Device\HarddiskVolumeN -> 盘符 的映射(进程启动时构建一次)。
QMap<QString, QString> buildDeviceMap() {
    QMap<QString, QString> map;
    wchar_t drives[512] = {};
    const DWORD n = GetLogicalDriveStringsW(511, drives);
    for (DWORD i = 0; i < n;) {
        const wchar_t* d = drives + i;
        const size_t len = wcslen(d);
        if (len >= 2) {
            wchar_t letter[3] = { d[0], d[1], 0 };   // 例如 "C:"
            wchar_t target[1024] = {};
            if (QueryDosDeviceW(letter, target, 1024) != 0)
                map.insert(QString::fromWCharArray(target), QString::fromWCharArray(letter));
        }
        i += static_cast<DWORD>(len) + 1;
    }
    return map;
}

// \Device\HarddiskVolume3\Windows\... -> C:\Windows\...
QString deviceToDrive(const QString& p) {
    if (p.isEmpty() || p.at(0) != QLatin1Char('\\'))
        return p; // 已是盘符路径或空,原样返回
    static const QMap<QString, QString> map = buildDeviceMap();
    for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
        if (p.startsWith(it.key(), Qt::CaseInsensitive))
            return it.value() + p.mid(it.key().size());
    }
    return p;
}

} // namespace

struct EtwProcessEventSource::Impl {
    // provider 必须比 trace 活得久:trace 按引用持有 provider。
    std::unique_ptr<krabs::user_trace> trace;
    std::unique_ptr<krabs::provider<>> provider;    // Kernel-Process(核心,始终开启)
    std::unique_ptr<krabs::provider<>> netProvider; // Kernel-Network(可选)
    std::unique_ptr<krabs::provider<>> dnsProvider; // DNS-Client(可选)
    std::unique_ptr<krabs::provider<>> regProvider;  // Kernel-Registry(可选)
    std::unique_ptr<krabs::provider<>> fileProvider; // Kernel-File(可选)
    std::thread                        worker;
    std::atomic<bool>                  running{false};
    QMutex                             mutex;
    QVector<bulwark::SecurityEvent>    queue;
    Logger                             log{QStringLiteral("bulwark.service.Etw")};

    EtwOptions etw;
    quint32    selfPid = 0; // 跳过本进程 PID,避免自身 curl/查询造成噪声

    // ---- Etw.NetworkUntrustedOnly:只上报「非可信签名主体」的外联 ----
    //
    // 该配置项此前只被解析、无人消费(名字承诺的过滤根本不存在,所有外联一律上报)。
    // 现在生效,但绝不能按连接去验签 —— Authenticode 验签是重操作,而外联事件是高频流。
    // 故按 PID 记忆:每个进程最多验一次,结果缓存复用。进程退出后 PID 可能复用,这里靠
    // 「缓存超上限即整表清空」自然过期;误判的后果只是多上报/少上报一条遥测,不影响拦截
    //(拦截由规则与情报链路决定,不依赖这条预过滤)。
    QHash<quint32, bool> netTrustCache;   // pid -> 主体是否为可信签名
    QMutex               netTrustMx;

    bool actorIsTrustedSigned(quint32 pid) {
        {
            QMutexLocker lk(&netTrustMx);
            const auto it = netTrustCache.constFind(pid);
            if (it != netTrustCache.constEnd())
                return it.value();
        }
        const QString path = monitoring::ProcessInspector::tryGetProcessImagePath(static_cast<int>(pid));
        // 解析不出映像路径 -> 按【不可信】处理(照常上报)。宁可多上报一条,也不要因为拿不到
        // 路径就把可能恶意的外联静默丢掉 —— 短命进程恰恰是最需要看到的那一类。
        const bool trusted = !path.isEmpty() && monitoring::ProcessInspector::isSigned(path);
        {
            QMutexLocker lk(&netTrustMx);
            if (netTrustCache.size() > 4096)
                netTrustCache.clear();   // 有界 + 顺带让 PID 复用导致的陈旧条目过期
            netTrustCache.insert(pid, trusted);
        }
        return trusted;
    }
    EmitGate   netGate;
    EmitGate   dnsGate;
    EmitGate   regGate;
    EmitGate   fileGate;
    EmitGate   imageGate;
    EmitGate   threadGate;
    QStringList regWatch_;                // 注册表监视集(受保护键 + 硬拦;子串匹配)
    QStringList fileWatch_;               // 文件监视集(受保护路径 + 硬拦;供后续文件源)
    QHash<quint64, QString> regKeyNames_; // KeyObject -> 键名(create/open 填充,仅 ETW 线程访问)

    // ---- 跨进程线程注入判别用的「刚诞生进程」登记表 --------------------------
    //
    // pid -> 看到其 ProcessStart 的时刻(GetTickCount64)。只有 ETW 消费线程访问
    //(krabs 在单线程上串行触发同一会话的所有回调),故与 regKeyNames_ 同理无需加锁。
    QHash<quint32, qint64> procBirthMs;
    qint64 sessionStartMs = 0;       // 会话启动时刻:用于处理「表里查不到」的那一类
    int    minTargetAgeMs = 500;     // = EtwOptions::RemoteThreadMinTargetAgeMs

    // pid -> 映像路径。跨进程建线程的判别要拿发起方的【完整路径】(见 isOsThreadInjector
    // 为什么不能只比文件名),而 QueryFullProcessImageName 是系统调用,csrss 这类高频发起方
    // 会被反复问到。同上:只有 ETW 消费线程访问,无需加锁;满了整表清空。
    //
    // PID 复用会不会让豁免被冒用?对本表当前唯一的豁免项不会:csrss.exe 是关键进程,结束它
    // 会直接 bugcheck,所以它的 PID 在一次开机期间不会被回收再分配。若将来往豁免表里加了
    // 会正常退出的进程,这条前提就不成立了,届时必须改成「每次重新解析、不吃缓存」。
    QHash<quint32, QString> pidPathCache;

    // ---- 写入归因(Etw.KernelFileWriteAttribution)----------------------------
    //
    // attribPaths_ 由主线程随时追加(诱饵是 start() 之后才投放的),ETW 消费线程只读,
    // 故必须加锁 —— 与 regWatch_/fileWatch_「start 前设好、之后只读」的模型不同。
    bool        attribEnabled = false;
    int         attribPathMax = 256;
    QSet<QString> attribPaths_;          // 小写完整路径
    QMutex        attribMx_;
    // FileObject -> 归因路径。只有 ETW 消费线程访问,无需加锁。
    QHash<quint64, QString> fileObjPath_;

    void addAttributionPath(const QString& path) {
        if (path.trimmed().isEmpty())
            return;
        QMutexLocker lk(&attribMx_);
        if (attribPaths_.size() >= attribPathMax)
            return;                       // 有上限:归因表不该无界增长
        attribPaths_.insert(path.toLower());
    }

    bool isAttributionPath(const QString& lowerPath) {
        QMutexLocker lk(&attribMx_);
        return attribPaths_.contains(lowerPath);
    }

    bool hasAttributionPaths() {
        QMutexLocker lk(&attribMx_);
        return !attribPaths_.isEmpty();
    }

    QString imagePathOf(quint32 pid) {
        const auto it = pidPathCache.constFind(pid);
        if (it != pidPathCache.constEnd())
            return it.value();
        const QString p =
            monitoring::ProcessInspector::tryGetProcessImagePath(static_cast<int>(pid));
        if (pidPathCache.size() > 2048)
            pidPathCache.clear();
        pidPathCache.insert(pid, p);
        return p;
    }

    // 登记一个刚诞生的进程,并把表维持在有界大小。
    //
    // 【裁剪是语义免费的】这张表只用来回答一个问题:「目标进程是不是刚刚才诞生」。对已经
    // 诞生很久的 pid,查到(年龄大 -> 判为注入)和查不到(见 isLikelyInitialThread 的第 ②
    // 条,同样判为注入)结论完全一致。所以按年龄丢掉老条目不会改变任何判定 —— 这也是为什么
    // 这里【不能】像 regKeyNames_ 那样满了就整表清空:清空会把「刚诞生」的记录一起抹掉,
    // 于是紧随其后的初始线程全部变成「查不到」-> 被判成注入,正好制造一波误报。
    void notePidBirth(quint32 pid, qint64 nowMs) {
        procBirthMs.insert(pid, nowMs);   // insert 覆盖旧值,顺带处理 PID 复用
        if (procBirthMs.size() <= kProcBirthSoftMax)
            return;
        const qint64 keepMs = std::max<qint64>(minTargetAgeMs * 4, 5000);
        for (auto it = procBirthMs.begin(); it != procBirthMs.end();)
            it = (nowMs - it.value() > keepMs) ? procBirthMs.erase(it) : ++it;
    }

    // 这条「跨进程 ThreadStart」是否其实只是目标进程的【初始线程】。
    //
    // 这是本维度唯一重要的误报护栏:子进程的初始线程由创建方建立,所以每一次正常的
    // CreateProcess 都会产生一条 header != payload 的 ThreadStart。实测一次 5.5 秒抓取里
    // 13 条跨进程 ThreadStart,只有 1 条是真注入。
    bool isLikelyInitialThread(quint32 targetPid, qint64 nowMs) const {
        const auto it = procBirthMs.constFind(targetPid);
        // ① 见过它诞生:年龄小于阈值 => 这是初始线程,不是注入。
        if (it != procBirthMs.constEnd())
            return (nowMs - it.value()) < minTargetAgeMs;
        // ② 没见过它诞生 => 它在本会话开始【之前】就存在,不可能是初始线程。
        //    explorer.exe / lsass.exe 这些最重要的注入目标恰恰全属于这一类,所以绝不能
        //    把「查不到」当成「可疑,丢弃」—— 那等于把这一维最有价值的部分关掉。
        //    唯一的例外是会话刚起来那一瞬:此时确实可能漏掉了目标的 ProcessStart,故在
        //    启动后的一个阈值窗口内保守跳过。
        return (nowMs - sessionStartMs) < minTargetAgeMs;
    }

    // ---- Kernel-Process 三类事件的处理(均在 ETW 消费线程,串行)---------------

    // 事件 1:ProcessStart -> ProcessCreate。
    void onProcessStart(const EVENT_RECORD& record, const krabs::trace_context& ctx) {
        krabs::schema schema(record, ctx.schema_locator);
        krabs::parser parser(schema);
        uint32_t pid = 0, ppid = 0;
        std::wstring image;
        parser.try_parse(L"ProcessID", pid);
        parser.try_parse(L"ParentProcessID", ppid);
        parser.try_parse(L"ImageName", image);
        // 先登记诞生时刻,再产出事件 —— 登记这一步【不能】受后面任何过滤影响:
        // 跨进程线程判别靠的就是这张表,漏登记一个 pid 就会让它的初始线程被误判成注入。
        if (pid > 0)
            notePidBirth(pid, static_cast<qint64>(::GetTickCount64()));
        bulwark::SecurityEvent e;
        e.type      = bulwark::EventType::ProcessCreate;
        e.actorPid  = static_cast<int>(pid);
        e.parentPid = static_cast<int>(ppid);
        e.actorPath = deviceToDrive(QString::fromWCharArray(image.c_str()));
        e.target    = e.actorPath;
        // ETW 为用户态观测源(非驱动 pre-action 拦截):无法在动作前阻断,
        // 故标记为用户态观测,拦截时由 Worker 事后补偿(结束进程树)。
        e.userModeObserved = true;
        // Kernel-Process 提供程序不含命令行;后续由 ProcessInspector 按 PID 回填。
        enqueue(std::move(e));
    }

    // 事件 5:ImageLoad -> ImageLoad(白加黑侧载 / BYOVD 的观测面)。
    //
    // 字段名经实机抓取核对:ImageBase / ImageSize / ProcessID / ImageCheckSum /
    // TimeDateStamp / DefaultBase / ImageName。ImageName 为 \Device\HarddiskVolumeN\...。
    void onImageLoad(const EVENT_RECORD& record, const krabs::trace_context& ctx) {
        krabs::schema schema(record, ctx.schema_locator);
        krabs::parser parser(schema);
        uint32_t host = 0;
        std::wstring image;
        // 负载 ProcessID 是权威的宿主进程;实测它与事件头 ProcessId 一致,头部作兜底。
        if (!parser.try_parse(L"ProcessID", host) || host == 0)
            host = record.EventHeader.ProcessId;
        if (host == 0 || host == selfPid)
            return;
        if (!parser.try_parse(L"ImageName", image) || image.empty())
            return;
        const QString path = deviceToDrive(QString::fromWCharArray(image.c_str()));
        // 过滤必须在这里做完(见 isSuspectModulePath 的说明):放到富化阶段等于每条模块
        // 加载都付一次验签 + 哈希,而正常机器上这是每秒几十条的流。
        if (!isSuspectModulePath(path))
            return;
        if (!imageGate.allow(host, path, static_cast<qint64>(::GetTickCount64())))
            return;
        bulwark::SecurityEvent e;
        e.type     = bulwark::EventType::ImageLoad;
        e.actorPid = static_cast<int>(host);
        // actorPath 置 "PID n" 占位,由 Worker::enrich 第 1 步按 PID 回填宿主映像路径 ——
        // 与 DriverEventSource 的 ImageLoad 分支完全一致的口径。
        e.actorPath = QStringLiteral("PID %1").arg(e.actorPid);
        e.target    = path;
        e.userModeObserved = true;
        e.detail = QStringLiteral("用户态观测 · 加载模块 %1").arg(QFileInfo(path).fileName());
        // 被加载模块【自身】的签名由 Worker::enrich 第 3.9 步求(targetSigned /
        // targetSignatureMismatch)—— 那才是 requireTargetSigned 系规则要看的东西,
        // actorSigned 说的是宿主进程,两者不是一回事。
        enqueue(std::move(e));
    }

    // 事件 3:ThreadStart -> RemoteThread(仅跨进程的那些)。
    void onThreadStart(const EVENT_RECORD& record, const krabs::trace_context& ctx) {
        // 事件头 ProcessId = 建线程的发起方(已实机验证:探针以 CreateRemoteThread 注入
        // 自己的子进程,抓到的正是 header=注入方 / 负载=目标)。
        const quint32 creator = record.EventHeader.ProcessId;
        // System(4)与 Idle(0)建到别的进程里的线程是内核线程,不是用户态注入。实测一次
        // 5.5 秒抓取里 13 条跨进程 ThreadStart 有 8 条来自 PID 4 —— 不排掉这一维基本只出噪声。
        if (creator <= 4 || creator == selfPid)
            return;
        krabs::schema schema(record, ctx.schema_locator);
        krabs::parser parser(schema);
        uint32_t owner = 0, tid = 0;
        if (!parser.try_parse(L"ProcessID", owner) || owner <= 4)
            return;
        if (owner == creator)
            return;   // 进程给自己建线程 —— 绝大多数事件都是这一类
        const qint64 nowMs = static_cast<qint64>(::GetTickCount64());
        if (isLikelyInitialThread(owner, nowMs))
            return;
        // 操作系统自己的跨进程建线程机制(实测:csrss.exe 的控制台 Ctrl+C 处理线程)。
        // 按发起方【完整路径】豁免,详见 isOsThreadInjector。
        const QString creatorPath = imagePathOf(creator);
        if (isOsThreadInjector(creatorPath))
            return;
        parser.try_parse(L"ThreadID", tid);
        // 目标映像路径:规则用 TargetPattern 匹配受害进程(如 *\lsass.exe),所以这里必须
        // 解析成完整路径。单次 OpenProcess + QueryFullProcessImageName,而且只有通过上面
        // 全部过滤的事件才会走到这里(过滤后是稀疏事件),不构成消费线程的负担。
        const QString victimPath =
            monitoring::ProcessInspector::tryGetProcessImagePath(static_cast<int>(owner));
        const QString target = victimPath.isEmpty()
            ? QStringLiteral("PID %1").arg(owner)
            : victimPath;
        if (!threadGate.allow(creator, target, nowMs))
            return;
        bulwark::SecurityEvent e;
        e.type     = bulwark::EventType::RemoteThread;
        e.actorPid = static_cast<int>(creator);
        // 发起方路径上面为了做豁免判定已经解析过了,直接用 —— 省掉 Worker::enrich 第 1 步
        // 再问一次同一个 PID,而且短命注入方(解析完就退出)在这里还拿得到、到 enrich 时
        // 可能已经查不到了。解析失败才退回 "PID n" 占位交给 enrich(它还有进程链历史兜底)。
        e.actorPath = creatorPath.isEmpty() ? QStringLiteral("PID %1").arg(e.actorPid)
                                           : creatorPath;
        e.target    = target;
        // parentPid/parentPath 放【受害进程】—— 这是刻意与 DriverEventSource 的 RemoteThread
        // 分支保持一致(它把受害 PID 放在 ev.ParentPid)。RuleDsl 的注释说非 ProcessCreate 事件
        // 的 parentPath 是「发起方的父进程」,与驱动这里的实际行为不符;两种口径里必须选驱动那种,
        // 否则同一条规则在有驱动/无驱动下行为不同 —— 那比口径与文档不一致糟糕得多。
        // 现有 thread 规则只用 actor/target/unsignedOnly,没有一条读 parent,故此处无实际歧义。
        e.parentPid  = static_cast<int>(owner);
        e.parentPath = victimPath;   // 直接给出,省掉 enrich 第 3 步重复解析同一个 PID
        e.userModeObserved = true;
        e.detail = QStringLiteral("用户态观测 · 跨进程线程注入 -> %1(PID %2,TID %3)")
                       .arg(QFileInfo(target).fileName()).arg(owner).arg(tid);
        enqueue(std::move(e));
    }

    // 原始事件中继容量(appsettings 的 Etw.RawChannelCapacity)。此前该配置项只被解析、
    // 无人消费,容量恒为编译期常量 kQueueMax —— 也就是说这个「可调」的旋钮是假的。
    // 现在由它决定;<=0 或异常值回退到 kQueueMax。
    int queueCap = kQueueMax;

    void enqueue(bulwark::SecurityEvent&& e) {
        QMutexLocker lock(&mutex);
        if (queue.size() >= queueCap) return; // 满则丢弃,保护内存
        queue.push_back(std::move(e));
    }
};

EtwProcessEventSource::EtwProcessEventSource(const EtwOptions& etw, QObject* parent)
    : EventSource(parent), d_(std::make_unique<Impl>()) {
    d_->etw = etw;
    d_->selfPid = static_cast<quint32>(::GetCurrentProcessId());
    const qint64 dedupMs = static_cast<qint64>(std::max(0, etw.DedupWindowSeconds)) * 1000;
    d_->netGate.perMinCap     = etw.PerProcessNetPerMinute;
    d_->netGate.dedupWindowMs = dedupMs;
    // 原始事件中继容量:夹到 [256, 65536],避免一个手抖的配置值让队列近乎无效或吃光内存。
    d_->queueCap = (etw.RawChannelCapacity > 0)
                       ? std::clamp(etw.RawChannelCapacity, 256, 65536)
                       : kQueueMax;
    d_->dnsGate.perMinCap     = etw.PerProcessDnsPerMinute;
    d_->dnsGate.dedupWindowMs = dedupMs;
    d_->regGate.perMinCap     = etw.PerProcessRegPerMinute;
    d_->regGate.dedupWindowMs = dedupMs;
    d_->fileGate.perMinCap     = etw.PerProcessFilePerMinute;
    d_->fileGate.dedupWindowMs = dedupMs;
    d_->imageGate.perMinCap     = etw.PerProcessImagePerMinute;
    d_->imageGate.dedupWindowMs = dedupMs;
    // 跨进程建线程【不去重】。去重窗口会把「同一个注入方反复往同一个目标注入」压成一条 ——
    // 而那个重复本身就是最强的证据之一(单次可能是调试器/输入法,连续多次不是)。频率由
    // perMinCap 兜住就够了。
    d_->threadGate.perMinCap     = etw.PerProcessThreadPerMinute;
    d_->threadGate.dedupWindowMs = 0;
    d_->minTargetAgeMs = std::clamp(etw.RemoteThreadMinTargetAgeMs, 50, 10000);
    d_->attribEnabled = etw.Enabled && etw.KernelFile && etw.KernelFileWriteAttribution;
    d_->attribPathMax = std::clamp(etw.AttributionPathMax, 1, 4096);

    // 把消费线程收集的事件搬到主线程。这个间隔是【空闲时第一条事件的延迟地板】,由
    // Bulwark:EventDrainIntervalMs 统一控制(默认 20ms;原先硬编码 200ms)。突发时不受它影响:
    // drain() 一次搬有上限的一批,还有积压就立刻再排一批,不等下一个 tick。
    drainTimer_ = new QTimer(this);
    drainTimer_->setInterval(kDefaultDrainMs);
    connect(drainTimer_, &QTimer::timeout, this, &EtwProcessEventSource::drain);
}

EtwProcessEventSource::~EtwProcessEventSource() { stop(); }

void EtwProcessEventSource::setDrainIntervalMs(int ms) {
    // 夹到 [1, 1000]:0 会让定时器每次事件循环空转都跑一遍,过大则等于把延迟又加回来。
    if (drainTimer_)
        drainTimer_->setInterval(qBound(1, ms, 1000));
}

void EtwProcessEventSource::setWatchLists(const QStringList& registryKeys, const QStringList& filePaths) {
    d_->regWatch_ = registryKeys;
    d_->fileWatch_ = filePaths;
}

void EtwProcessEventSource::addAttributionPath(const QString& path) {
    // 与 setWatchLists 不同,本接口【允许 start() 之后调用】:勒索诱饵是
    // UserModeBehaviorSource::start() 里才投放的,那时 ETW 会话已经在跑了。
    // 因此 attribPaths_ 受互斥量保护(见 Impl 里的说明)。
    d_->addAttributionPath(path);
}

bool EtwProcessEventSource::writeAttributionEnabled() const {
    return d_->attribEnabled;
}

void EtwProcessEventSource::start() {
    if (d_->running.load()) return;

    Impl* impl = d_.get();
    bool netOn = false, dnsOn = false, regOn = false, fileOn = false;
    bool imageOn = false, threadOn = false;
    try {
        const std::wstring sessionName = impl->etw.SessionName.isEmpty()
            ? std::wstring(L"Bulwark-ETW")
            : impl->etw.SessionName.toStdWString();
        impl->trace = std::make_unique<krabs::user_trace>(sessionName);

        // (1) Kernel-Process:进程创建(核心,始终开启)+ 模块加载 + 跨进程建线程(可选)。
        //
        // 【三维必须合并成一个 provider + 一个 keyword 掩码】同一个 ETW 会话对同一个
        // provider GUID 只能 enable 一次:给 Kernel-Process 再建第二个 provider 对象并
        // enable,后一次的 MatchAnyKeyword 会【覆盖】前一次 —— 表现是「加了模块加载之后
        // 进程创建事件全没了」,而且日志里一切正常。所以 0x10 / 0x40 / 0x20 一起下发,
        // 在回调里按事件 ID 分派。
        //
        // 以临时 lambda 传入 -> 绑定到 const U& 重载 -> 被拷贝进 provider(不悬挂)。
        impl->sessionStartMs = static_cast<qint64>(::GetTickCount64());
        ULONGLONG kpMask = kKeywordProcess;
        if (impl->etw.Enabled && impl->etw.KernelImageLoad)    kpMask |= kKeywordImage;
        if (impl->etw.Enabled && impl->etw.KernelRemoteThread) kpMask |= kKeywordThread;
        imageOn  = (kpMask & kKeywordImage)  != 0;
        threadOn = (kpMask & kKeywordThread) != 0;
        impl->provider = std::make_unique<krabs::provider<>>(krabs::guid(kKernelProcessGuid));
        impl->provider->any(kpMask);
        impl->provider->add_on_event_callback(
            [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                try {
                    // 先看事件头再决定要不要构造 schema。keyword 0x40 会连带投递
                    // ImageUnload(6)、0x20 会连带投递 ThreadStop(4),都在这里被挡掉 ——
                    // 它们加起来比我们要的两类还多(实测 ImageUnload 109 : ImageLoad 161)。
                    switch (record.EventHeader.EventDescriptor.Id) {
                        case kProcessStartEventId: impl->onProcessStart(record, ctx); break;
                        case kImageLoadEventId:    impl->onImageLoad(record, ctx);    break;
                        case kThreadStartEventId:  impl->onThreadStart(record, ctx);  break;
                        default: break;
                    }
                } catch (...) {
                    // 单条事件解析异常不应中断整个会话。
                }
            });
        impl->trace->enable(*impl->provider);

        // (2) Kernel-Network:出站 TCP 连接(可选)。不设 keyword(MatchAnyKeyword=0 => 收全部
        // 事件),回调内按事件 ID 12 过滤 —— 规避「猜错 keyword 位 => 静默零事件」,与
        // Velociraptor 的做法一致;非 12 事件仅付出一次事件头判断的代价。
        if (impl->etw.Enabled && impl->etw.KernelNetwork) {
            impl->netProvider = std::make_unique<krabs::provider<>>(krabs::guid(kKernelNetworkGuid));
            impl->netProvider->add_on_event_callback(
                [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                    try {
                        if (record.EventHeader.EventDescriptor.Id != kNetConnectEventId)
                            return;
                        krabs::schema schema(record, ctx.schema_locator);
                        krabs::parser parser(schema);
                        uint32_t pid = 0, daddr = 0;
                        uint16_t dport = 0;
                        parser.try_parse(L"PID", pid);
                        // daddr 解析失败(如 IPv6 的 16 字节)或为 0 则跳过 —— 仅处理 IPv4 出站。
                        if (!parser.try_parse(L"daddr", daddr) || daddr == 0)
                            return;
                        parser.try_parse(L"dport", dport);
                        if (pid == 0 || pid == impl->selfPid)
                            return; // 跳过系统空闲/本进程
                        const QString target = ipv4ToString(daddr) + QLatin1Char(':')
                            + QString::number(netToHostPort(dport)); // "ip:port",匹配情报 IP 规则 "ip*"
                        if (!impl->netGate.allow(pid, target, static_cast<qint64>(::GetTickCount64())))
                            return;
                        // NetworkUntrustedOnly:可信签名主体的外联不上报(压制正常软件的
                        // 更新/心跳洪泛)。按 PID 记忆验签结果,不会每条连接都验一次。
                        if (impl->etw.NetworkUntrustedOnly && impl->actorIsTrustedSigned(pid))
                            return;
                        bulwark::SecurityEvent e;
                        e.type     = bulwark::EventType::NetworkConnect;
                        e.actorPid = static_cast<int>(pid);
                        e.target   = target;
                        e.userModeObserved = true; // 用户态观测:拦截由 Worker 事后补偿
                        impl->enqueue(std::move(e));
                    } catch (...) {}
                });
            impl->trace->enable(*impl->netProvider);
            netOn = true;
        }

        // (3) DNS-Client:域名查询(可选)。同样不设 keyword,回调内按事件 ID 3006 过滤。
        if (impl->etw.Enabled && impl->etw.DnsClient) {
            impl->dnsProvider = std::make_unique<krabs::provider<>>(krabs::guid(kDnsClientGuid));
            impl->dnsProvider->add_on_event_callback(
                [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                    try {
                        if (record.EventHeader.EventDescriptor.Id != kDnsQueryEventId)
                            return;
                        krabs::schema schema(record, ctx.schema_locator);
                        krabs::parser parser(schema);
                        std::wstring qname;
                        parser.try_parse(L"QueryName", qname);
                        // DNS-Client 在调用方进程内触发,PID 取事件头。
                        const uint32_t pid = record.EventHeader.ProcessId;
                        if (pid == 0 || pid == impl->selfPid)
                            return;
                        QString domain = QString::fromWCharArray(qname.c_str()).trimmed();
                        while (domain.endsWith(QLatin1Char('.'))) domain.chop(1);
                        if (domain.isEmpty())
                            return;
                        // SuspiciousOnly:仅上报 DGA 随机度分析预判可疑(>0)的域名,压制洪泛。
                        if (impl->etw.SuspiciousOnly
                            && bulwark::engine::DgaDomainAnalyzer::analyze(domain).score <= 0)
                            return;
                        if (!impl->dnsGate.allow(pid, domain, static_cast<qint64>(::GetTickCount64())))
                            return;
                        bulwark::SecurityEvent e;
                        e.type     = bulwark::EventType::DnsQuery;
                        e.actorPid = static_cast<int>(pid);
                        e.target   = domain;
                        e.userModeObserved = true;
                        impl->enqueue(std::move(e));
                    } catch (...) {}
                });
            impl->trace->enable(*impl->dnsProvider);
            dnsOn = true;
        }

        // (4) Kernel-Registry:持久化/受保护键写(可选)。keyword 0x7720(Velociraptor 一致)。
        // 回调内:1/2(create/open)填充 KeyObject->名 缓存;3/5/6(delete/setvalue/deletevalue)据缓存
        // 解析键路径,仅上报命中监视集(受保护键)的写 —— 避免全量注册表事件洪泛。跳过高频的 4(query)。
        // 空监视集(未配置受保护键)=> 不上报任何注册表事件(与「只对确有危险行为动作」一致)。
        if (impl->etw.Enabled && impl->etw.KernelRegistry && !impl->regWatch_.isEmpty()) {
            impl->regProvider = std::make_unique<krabs::provider<>>(krabs::guid(kKernelRegistryGuid));
            impl->regProvider->any(kKeywordRegistry);
            impl->regProvider->add_on_event_callback(
                [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                    try {
                        const USHORT id = record.EventHeader.EventDescriptor.Id;
                        const bool isName = (id == kRegCreateKey || id == kRegOpenKey);
                        const bool isWrite = (id == kRegDeleteKey || id == kRegSetValueKey
                                              || id == kRegDeleteValueKey);
                        if (!isName && !isWrite)
                            return; // 跳过 query/enumerate 等读操作(仅付一次事件头判断)

                        krabs::schema schema(record, ctx.schema_locator);
                        krabs::parser parser(schema);
                        uint64_t keyObject = 0;
                        parser.try_parse(L"KeyObject", keyObject);

                        // create/open:登记 KeyObject -> 相对键名(供后续写事件解析键路径)。
                        if (isName) {
                            std::wstring rel;
                            if (keyObject != 0 && parser.try_parse(L"RelativeName", rel) && !rel.empty()) {
                                if (impl->regKeyNames_.size() >= kRegNameCacheMax)
                                    impl->regKeyNames_.clear(); // 满则粗放清空(有界内存)
                                impl->regKeyNames_.insert(keyObject, QString::fromWCharArray(rel.c_str()));
                            }
                            return;
                        }

                        // delete/setvalue/deletevalue:解析键路径 -> 命中监视集才上报 RegistryWrite。
                        QString keyName = impl->regKeyNames_.value(keyObject);
                        if (keyName.isEmpty()) {
                            std::wstring kn;
                            if (parser.try_parse(L"KeyName", kn))
                                keyName = QString::fromWCharArray(kn.c_str());
                        }
                        if (keyName.isEmpty())
                            return; // 无法解析键路径 -> 放弃(避免误报)

                        std::wstring valName;
                        if (id == kRegSetValueKey || id == kRegDeleteValueKey)
                            parser.try_parse(L"ValueName", valName);
                        QString target = keyName;
                        if (!valName.empty())
                            target += QLatin1Char('\\') + QString::fromWCharArray(valName.c_str());

                        if (!matchesWatch(target, impl->regWatch_))
                            return; // 仅上报持久化/受保护键(避免全量注册表洪泛)

                        const uint32_t pid = record.EventHeader.ProcessId;
                        if (pid == 0 || pid == impl->selfPid)
                            return;
                        if (!impl->regGate.allow(pid, target, static_cast<qint64>(::GetTickCount64())))
                            return;
                        bulwark::SecurityEvent e;
                        e.type     = bulwark::EventType::RegistryWrite;
                        e.actorPid = static_cast<int>(pid);
                        e.target   = target;
                        e.userModeObserved = true; // 用户态观测:拦截由 Worker 事后补偿
                        impl->enqueue(std::move(e));
                    } catch (...) {}
                });
            impl->trace->enable(*impl->regProvider);
            regOn = true;
        }

        // (5) Kernel-File:受保护路径的新建/删除 + 用户可写目录下的可执行体投递(可选)。
        // keyword 0x1400 只投递 CreateNewFile(30)与 DeletePath(26)——二者都直接带路径,无需关联,
        // 也排除了海量 open/read/write。
        //
        // 【不再要求 fileWatch_ 非空】:原先空监视集就整个不开这个提供程序。现在回调里多了一条
        // 与监视集无关的判据(isDroppedExecutable:往用户可写目录新建可执行体/脚本),那是投递
        // 动作本身,不该因为「用户没配受保护路径」而看不到。
        if (impl->etw.Enabled && impl->etw.KernelFile) {
            impl->fileProvider = std::make_unique<krabs::provider<>>(krabs::guid(kKernelFileGuid));
            //
            // 写入归因(默认关,见 EtwOptions::KernelFileWriteAttribution):再加 CREATE(0x80)
            // 与 WRITE(0x200)。这两位把本提供程序的回调频率从约 12/s 抬到约 3000/s(实测),
            // 所以它是一个【要部署方明确选择】的开关,不是默认行为。
            //
            ULONGLONG kfMask = kKeywordFile;
            if (impl->attribEnabled)
                kfMask |= kKeywordFileCreate | kKeywordFileWrite;
            impl->fileProvider->any(kfMask);
            impl->fileProvider->add_on_event_callback(
                [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                    try {
                        const USHORT id = record.EventHeader.EventDescriptor.Id;
                        //
                        // ---- 写入归因:Create/CreateNewFile 建表,Write 反查 --------------
                        //
                        // 只在开关打开时走这一段。Create(12)是本提供程序最高频的事件
                        //(实测 1.6 秒 4493 条),所以这里的顺序是刻意的:先取 FileObject
                        // (指针字段,便宜)做「复用擦除」,再取 FileName 判断要不要入表。
                        //
                        if (impl->attribEnabled && (id == kFileCreate || id == kFileWrite
                                                    || id == kFileCreateNew)) {
                            krabs::schema sch(record, ctx.schema_locator);
                            krabs::parser par(sch);
                            uint64_t fobj = 0;
                            if (par.try_parse(L"FileObject", fobj) && fobj != 0) {
                                if (id == kFileWrite) {
                                    const auto it = impl->fileObjPath_.constFind(fobj);
                                    if (it != impl->fileObjPath_.constEnd()) {
                                        const uint32_t wpid = record.EventHeader.ProcessId;
                                        // 写入者 = 事件头 ProcessId(已实机核对)。这正是
                                        // QFileSystemWatcher 给不出、而诱饵命中必须要的那一位。
                                        if (wpid != 0 && wpid != impl->selfPid
                                            && impl->fileGate.allow(
                                                   wpid, it.value(),
                                                   static_cast<qint64>(::GetTickCount64()))) {
                                            bulwark::SecurityEvent e;
                                            e.type     = bulwark::EventType::FileWrite;
                                            e.actorPid = static_cast<int>(wpid);
                                            e.target   = it.value();
                                            e.userModeObserved = true;
                                            e.detail = QStringLiteral("用户态观测 · 改写受监视文件 %1")
                                                           .arg(QFileInfo(it.value()).fileName());
                                            impl->enqueue(std::move(e));
                                        }
                                    }
                                    return;   // Write 不走下面的新建/删除逻辑
                                }
                                // Create / CreateNewFile:
                                // ① 【必须先擦】FileObject 是按句柄的地址,句柄关闭后会被复用到
                                //    无关文件上(实测:同一个值 1.6 秒内被 17 个事件用过,分属 5 个
                                //    进程)。任何 Create 拿到这个地址,就说明旧映射已经死了。不擦的
                                //    后果是把别人的写入报成「诱饵被改写」—— 而那条路的终点是杀进程。
                                impl->fileObjPath_.remove(fobj);
                                std::wstring cname;
                                if (par.try_parse(L"FileName", cname) && !cname.empty()) {
                                    const QString cpath =
                                        deviceToDrive(QString::fromWCharArray(cname.c_str()));
                                    // ② 只有归因路径(诱饵)才入表,所以表恒定很小。
                                    if (impl->isAttributionPath(cpath.toLower())) {
                                        if (impl->fileObjPath_.size() >= kFileObjMapMax)
                                            impl->fileObjPath_.clear();
                                        impl->fileObjPath_.insert(fobj, cpath);
                                    }
                                }
                            }
                            if (id == kFileCreate)
                                return;   // 事件 12 只用于建表,本身不产出事件
                        }

                        if (id != kFileCreateNew && id != kFileDeletePath)
                            return;
                        krabs::schema schema(record, ctx.schema_locator);
                        krabs::parser parser(schema);

                        QString path;
                        bulwark::EventType type;
                        if (id == kFileCreateNew) {
                            std::wstring fname;
                            if (!parser.try_parse(L"FileName", fname) || fname.empty())
                                return;
                            path = deviceToDrive(QString::fromWCharArray(fname.c_str()));
                            type = bulwark::EventType::FileWrite; // 新建文件视为写
                        } else { // DeletePath
                            std::wstring fpath;
                            if (!parser.try_parse(L"FilePath", fpath) || fpath.empty())
                                return;
                            path = deviceToDrive(QString::fromWCharArray(fpath.c_str()));
                            type = bulwark::EventType::FileDelete;
                        }
                        // 两条放行判据(其一即可):
                        //   1) 命中受保护路径监视集 —— 原有语义,覆盖启动目录 / hosts / \Tasks\ 等;
                        //   2) 【新建】了用户可写目录下的可执行体 / 脚本 —— 投递动作本身。
                        // 第 2 条只对 CreateNewFile 生效:删除一个 exe 不是投递,按原有监视集判就够了,
                        // 放开会把卸载器 / 更新器的清理动作大量收进来。
                        if (!matchesWatch(path, impl->fileWatch_)
                            && !(id == kFileCreateNew && isDroppedExecutable(path)))
                            return; // 仅上报受保护路径 + 可执行体投递(避免全量文件事件洪泛)

                        const uint32_t pid = record.EventHeader.ProcessId;
                        if (pid == 0 || pid == impl->selfPid)
                            return;
                        if (!impl->fileGate.allow(pid, path, static_cast<qint64>(::GetTickCount64())))
                            return;
                        bulwark::SecurityEvent e;
                        e.type     = type;
                        e.actorPid = static_cast<int>(pid);
                        e.target   = path;
                        e.userModeObserved = true; // 用户态观测:拦截由 Worker 事后补偿
                        impl->enqueue(std::move(e));
                    } catch (...) {}
                });
            impl->trace->enable(*impl->fileProvider);
            fileOn = true;
        }

        impl->trace->open(); // 主线程:StartTrace + OpenTrace(非管理员/失败在此同步抛出)
    } catch (const std::exception& ex) {
        available_ = false;
        impl->trace.reset();
        impl->provider.reset();
        impl->netProvider.reset();
        impl->dnsProvider.reset();
        impl->regProvider.reset();
        impl->fileProvider.reset();
        impl->log.warning(
            QStringLiteral("ETW 会话启动失败(需要以管理员身份运行?):%1")
                .arg(QString::fromUtf8(ex.what())));
        return;
    }

    available_ = true;
    impl->running.store(true);
    impl->worker = std::thread([impl] {
        try {
            impl->trace->process(); // 阻塞消费,直到 stop() 停止会话
        } catch (const std::exception& ex) {
            impl->log.warning(
                QStringLiteral("ETW 处理线程结束:%1").arg(QString::fromUtf8(ex.what())));
        }
    });
    drainTimer_->start();
    QStringList active{ QStringLiteral("Kernel-Process") };
    // 模块加载/跨进程线程这两维单独列出来:它们补的是「无内核驱动时完全看不见」的盲区,
    // 所以日志必须能一眼看出它们到底有没有生效 —— 否则又回到「以为在防、其实没有」。
    if (imageOn) active << QStringLiteral("ImageLoad(模块加载)");
    if (threadOn) active << QStringLiteral("ThreadStart(跨进程注入)");
    if (netOn) active << QStringLiteral("Kernel-Network");
    if (dnsOn) active << QStringLiteral("DNS-Client");
    if (regOn) active << QStringLiteral("Kernel-Registry");
    if (fileOn) active << QStringLiteral("Kernel-File");
    // 写入归因同样单列:它默认关,而「诱饵命中能不能结束进程」完全取决于它开没开 ——
    // 这件事必须在日志里一眼可见,不能让人对着一条「诱饵被触碰」纳闷为什么没处置。
    if (fileOn && impl->attribEnabled)
        active << QStringLiteral("FileWrite归因(诱饵可定位写入者)");
    impl->log.info(QStringLiteral("ETW 实时会话已启动(%1)。").arg(active.join(QStringLiteral(", "))));
}

void EtwProcessEventSource::stop() {
    if (drainTimer_) drainTimer_->stop();
    if (d_->running.exchange(false)) {
        if (d_->trace) {
            // 从主线程停止会话 -> 消费线程的 ProcessTrace 返回(krabs 支持跨线程停止)。
            try { d_->trace->stop(); } catch (...) {}
        }
        if (d_->worker.joinable()) d_->worker.join();
    }
    d_->provider.reset();
    d_->netProvider.reset();
    d_->dnsProvider.reset();
    d_->regProvider.reset();
    d_->fileProvider.reset();
    d_->trace.reset();
    available_ = false;
}

void EtwProcessEventSource::drain() {
    QVector<bulwark::SecurityEvent> batch;
    {
        QMutexLocker lock(&d_->mutex);
        if (d_->queue.isEmpty()) return;
        batch.swap(d_->queue);
    }
    for (const auto& e : batch)
        emit eventProduced(e);
}

} // namespace bulwark::service
