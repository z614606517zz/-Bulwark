#include "bulwark/service/EtwProcessEventSource.h"
#include "bulwark/service/Logger.h"
#include "bulwark/engine/DgaDomainAnalyzer.h" // SuspiciousOnly DNS 预过滤

#include <QTimer>
#include <QMutex>
#include <QMutexLocker>
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
constexpr ULONGLONG kKeywordProcess      = 0x10; // WINEVENT_KEYWORD_PROCESS
constexpr int       kQueueMax            = 4096; // 队列上限,防止事件风暴撑爆内存

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

// 目标是否命中监视集(任一子串,大小写不敏感)。空监视集 => 不命中(即不上报)。
inline bool matchesWatch(const QString& target, const QStringList& watch) {
    for (const QString& w : watch)
        if (!w.isEmpty() && target.contains(w, Qt::CaseInsensitive))
            return true;
    return false;
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
    EmitGate   netGate;
    EmitGate   dnsGate;
    EmitGate   regGate;
    EmitGate   fileGate;
    QStringList regWatch_;                // 注册表监视集(受保护键 + 硬拦;子串匹配)
    QStringList fileWatch_;               // 文件监视集(受保护路径 + 硬拦;供后续文件源)
    QHash<quint64, QString> regKeyNames_; // KeyObject -> 键名(create/open 填充,仅 ETW 线程访问)

    void enqueue(bulwark::SecurityEvent&& e) {
        QMutexLocker lock(&mutex);
        if (queue.size() >= kQueueMax) return; // 满则丢弃,保护内存
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
    d_->dnsGate.perMinCap     = etw.PerProcessDnsPerMinute;
    d_->dnsGate.dedupWindowMs = dedupMs;
    d_->regGate.perMinCap     = etw.PerProcessRegPerMinute;
    d_->regGate.dedupWindowMs = dedupMs;
    d_->fileGate.perMinCap     = etw.PerProcessFilePerMinute;
    d_->fileGate.dedupWindowMs = dedupMs;

    drainTimer_ = new QTimer(this);
    drainTimer_->setInterval(200); // 每 200ms 把消费线程收集的事件搬到主线程
    connect(drainTimer_, &QTimer::timeout, this, &EtwProcessEventSource::drain);
}

EtwProcessEventSource::~EtwProcessEventSource() { stop(); }

void EtwProcessEventSource::setWatchLists(const QStringList& registryKeys, const QStringList& filePaths) {
    d_->regWatch_ = registryKeys;
    d_->fileWatch_ = filePaths;
}

void EtwProcessEventSource::start() {
    if (d_->running.load()) return;

    Impl* impl = d_.get();
    bool netOn = false, dnsOn = false, regOn = false, fileOn = false;
    try {
        const std::wstring sessionName = impl->etw.SessionName.isEmpty()
            ? std::wstring(L"Bulwark-ETW")
            : impl->etw.SessionName.toStdWString();
        impl->trace = std::make_unique<krabs::user_trace>(sessionName);

        // (1) Kernel-Process:进程创建(核心源,始终开启)。keyword 过滤 + 事件头预判。
        // 以临时 lambda 传入 -> 绑定到 const U& 重载 -> 被拷贝进 provider(不悬挂)。
        impl->provider = std::make_unique<krabs::provider<>>(krabs::guid(kKernelProcessGuid));
        impl->provider->any(kKeywordProcess);
        impl->provider->add_on_event_callback(
            [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                try {
                    // 先看事件头,避免为非 ProcessStart 事件构造 schema 的开销。
                    if (record.EventHeader.EventDescriptor.Id != kProcessStartEventId)
                        return;
                    krabs::schema schema(record, ctx.schema_locator);
                    krabs::parser parser(schema);
                    uint32_t pid = 0, ppid = 0;
                    std::wstring image;
                    parser.try_parse(L"ProcessID", pid);
                    parser.try_parse(L"ParentProcessID", ppid);
                    parser.try_parse(L"ImageName", image);
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
                    impl->enqueue(std::move(e));
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

        // (5) Kernel-File:受保护路径的新建/删除(可选)。keyword 0x1400 只投递 CreateNewFile(30)与
        // DeletePath(26)——二者都直接带路径,无需关联,也排除了海量 open/read/write。仅上报命中监视集者。
        // 空监视集(未配置受保护路径)=> 不上报任何文件事件。
        if (impl->etw.Enabled && impl->etw.KernelFile && !impl->fileWatch_.isEmpty()) {
            impl->fileProvider = std::make_unique<krabs::provider<>>(krabs::guid(kKernelFileGuid));
            impl->fileProvider->any(kKeywordFile);
            impl->fileProvider->add_on_event_callback(
                [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                    try {
                        const USHORT id = record.EventHeader.EventDescriptor.Id;
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
                        if (!matchesWatch(path, impl->fileWatch_))
                            return; // 仅上报命中受保护路径者(避免全量文件事件洪泛)

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
    if (netOn) active << QStringLiteral("Kernel-Network");
    if (dnsOn) active << QStringLiteral("DNS-Client");
    if (regOn) active << QStringLiteral("Kernel-Registry");
    if (fileOn) active << QStringLiteral("Kernel-File");
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
