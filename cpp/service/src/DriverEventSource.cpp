#include "bulwark/service/DriverEventSource.h"
#include "bulwark/service/Logger.h"

#include <QTimer>
#include <QMutex>
#include <QMutexLocker>
#include <QVector>
#include <QHash>
#include <QSet>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QFileInfo>

#include <atomic>
#include <thread>
#include <vector>

// Windows / Filter Manager 用户态头。放在 Qt 头之后并抑制会与 Qt/标准库冲突的宏。
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <fltuser.h>   // FilterConnectCommunicationPort / FilterGetMessage / FilterReplyMessage / FilterSendMessage
#include <tlhelp32.h>  // CreateToolhelp32Snapshot(内存防护:登记现存目标进程)

// 直接复用内核驱动的协议头(单一事实来源:内核与用户态用同一份结构体定义,
// 彻底消除 .NET DriverStructs 那层手工重声明的内存布局漂移风险)。
#include "Protocol.h"

// 服务创建「真凶」溯源(SCM 代写服务键时还原真实发起者)。
#include "bulwark/service/ServiceControlTracer.h"

namespace bulwark::service {

namespace {

// FilterGetMessage 实际收到的:Filter Manager 头 + 驱动事件体(布局对应 .NET BlwGetMessage)。
struct BlwGetMessage {
    FILTER_MESSAGE_HEADER Header;
    BLW_EVENT_MESSAGE     Event;
};

// FilterReplyMessage 发送的:回复头 + 裁决体(布局对应 .NET BlwReplyMessage)。
struct BlwReplyMessage {
    FILTER_REPLY_HEADER Header;
    BLW_VERDICT_REPLY   Reply;
};

// 断开类良性错误码(驱动卸载 / 端口关闭 / 操作中止 / 服务停用):当作正常断开,静默退出读循环。
inline bool isBenignDisconnect(HRESULT hr) {
    const DWORD e = static_cast<DWORD>(hr);
    return e == 0x80070103u   // ERROR_NO_MORE_ITEMS
        || e == 0x800704CDu   // ERROR_CONNECTION_INVALID
        || e == 0x800703E3u   // ERROR_OPERATION_ABORTED
        || e == 0x80070006u;  // ERROR_INVALID_HANDLE
}

// \Device\HarddiskVolumeN -> 盘符 映射(进程内构建一次,与 ETW 源做法一致)。
QMap<QString, QString> buildDeviceMap() {
    QMap<QString, QString> map;
    wchar_t drives[512] = {};
    const DWORD n = GetLogicalDriveStringsW(511, drives);
    for (DWORD i = 0; i < n;) {
        const wchar_t* d = drives + i;
        const size_t len = wcslen(d);
        if (len >= 2) {
            wchar_t letter[3] = { d[0], d[1], 0 };  // 例如 "C:"
            wchar_t target[1024] = {};
            if (QueryDosDeviceW(letter, target, 1024) != 0)
                map.insert(QString::fromWCharArray(target), QString::fromWCharArray(letter));
        }
        i += static_cast<DWORD>(len) + 1;
    }
    return map;
}

// 把内核传来的 NT 设备路径尽量规范化为可读 Win32 路径(移植 .NET DriverEventSource.NormalizePath)。
QString normalizeNtPath(const QString& raw) {
    if (raw.isEmpty())
        return raw;
    if (raw.startsWith(QLatin1String("\\??\\")))
        return raw.mid(4);

    // \SystemRoot\... -> C:\Windows\...
    if (raw.startsWith(QLatin1String("\\SystemRoot\\"), Qt::CaseInsensitive)) {
        const QString winDir = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
        return winDir + raw.mid(QStringLiteral("\\SystemRoot").size());
    }
    // \Windows\...(无盘符)-> 系统盘符 + 原串
    if (raw.startsWith(QLatin1String("\\Windows\\"), Qt::CaseInsensitive)) {
        const QString winDir = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
        const QString sysDrive = winDir.left(2); // "C:"
        return sysDrive + raw;
    }
    // \Device\HarddiskVolumeN\... -> 盘符:\...
    if (raw.startsWith(QLatin1String("\\Device\\"), Qt::CaseInsensitive)) {
        static const QMap<QString, QString> map = buildDeviceMap();
        for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
            if (raw.startsWith(it.key(), Qt::CaseInsensitive))
                return it.value() + raw.mid(it.key().size());
        }
    }
    return raw;
}

// 主机字节序 IPv4 -> 点分十进制(移植 .NET FormatIpV4)。
QString formatIpv4Host(quint32 ipHostOrder) {
    return QStringLiteral("%1.%2.%3.%4")
        .arg((ipHostOrder >> 24) & 0xFF).arg((ipHostOrder >> 16) & 0xFF)
        .arg((ipHostOrder >> 8) & 0xFF).arg(ipHostOrder & 0xFF);
}

// 解析 "a.b.c.d" 或 "a.b.c.d:port" 为主机字节序 IPv4 + 端口(0=任意)。非 IPv4 返回 false。
bool parseIpEndpoint(const QString& entry, quint32& ipHostOrder, quint16& port) {
    ipHostOrder = 0;
    port = 0;
    const QString t = entry.trimmed();
    if (t.isEmpty())
        return false;
    const QStringList hp = t.split(QLatin1Char(':'));
    const QStringList oct = hp.at(0).split(QLatin1Char('.'));
    if (oct.size() != 4)
        return false;
    quint32 v = 0;
    for (const QString& o : oct) {
        bool ok = false;
        const int n = o.toInt(&ok);
        if (!ok || n < 0 || n > 255)
            return false;
        v = (v << 8) | static_cast<quint32>(n);
    }
    ipHostOrder = v;
    if (hp.size() > 1) {
        bool ok = false;
        const int p = hp.at(1).toInt(&ok);
        if (ok && p > 0 && p <= 0xFFFF)
            port = static_cast<quint16>(p);
    }
    return true;
}

// 轻量解析 PID 的映像路径(OpenProcess + QueryFullProcessImageNameW)。用于注入 / 结束进程
// 等事件的「受害者」目标路径,使 TargetPattern 规则(如 *\explorer.exe)可匹配。低频事件,
// 读线程上直接调用可接受;进程创建走 ImagePath 无需解析。失败返回空串。
QString resolvePidImagePath(quint32 pid) {
    if (pid == 0)
        return QString();
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h == nullptr)
        return QString();
    wchar_t buf[BLW_MAX_PATH] = {};
    DWORD sz = BLW_MAX_PATH;
    QString out;
    if (::QueryFullProcessImageNameW(h, 0, buf, &sz))
        out = QString::fromWCharArray(buf, static_cast<int>(sz));
    ::CloseHandle(h);
    return out;
}

// 内核事件类型 -> 引擎 EventType(移植 .NET MapType)。
bulwark::EventType mapType(ULONG t) {
    switch (t) {
        case BlwEventProcessTerminate:     return bulwark::EventType::ProcessTerminate;
        case BlwEventFileDelete:           return bulwark::EventType::FileDelete;
        case BlwEventFileRename:           return bulwark::EventType::FileWrite;
        case BlwEventRegistrySetValue:     return bulwark::EventType::RegistryWrite;
        case BlwEventRegistryDeleteValue:  return bulwark::EventType::RegistryWrite;
        case BlwEventRegistryDeleteKey:    return bulwark::EventType::RegistryWrite;
        case BlwEventSelfProtect:          return bulwark::EventType::SelfProtect;
        case BlwEventMemoryProtect:        return bulwark::EventType::SelfProtect;
        case BlwEventNetworkConnect:       return bulwark::EventType::NetworkConnect;
        case BlwEventImageLoad:            return bulwark::EventType::ImageLoad;
        case BlwEventImageBlocked:         return bulwark::EventType::ImageLoad;
        case BlwEventRemoteThread:         return bulwark::EventType::RemoteThread;
        case BlwEventFileModify:           return bulwark::EventType::FileWrite;
        default:                           return bulwark::EventType::ProcessCreate;
    }
}

// 该内核事件是否为「内核同步等待裁决」类型(需回写 FilterReplyMessage)。当前驱动为
// fire-and-forget,回写为尽力而为(内核未等待则无害失败);仅这几类进行追踪回写。
inline bool needsVerdict(ULONG t) {
    return t == BlwEventFileDelete || t == BlwEventFileRename
        || t == BlwEventRegistrySetValue || t == BlwEventRegistryDeleteValue
        || t == BlwEventRegistryDeleteKey || t == BlwEventProcessTerminate;
}

} // namespace

// ---- pImpl:把 windows.h / fltuser.h / Protocol.h 细节挡在头文件外 ----------
struct DriverEventSource::Impl {
    HANDLE port = nullptr;
    std::thread readThread;
    std::atomic<bool> running{false};
    std::atomic<bool> connected{false};
    std::atomic<bool> protocolMismatch{false};

    QMutex queueMutex;
    QVector<bulwark::SecurityEvent> queue;

    QMutex portMutex; // 保护 port 上的 Send/Reply 与关闭,避免与读线程 / 主线程竞态

    // 裁决回写映射(仅同步等待类事件):事件 Id -> 内核 EventId -> 内核 MessageId。
    QMutex mapMutex;
    QHash<QUuid, quint64> eventToDriverId;
    QHash<quint64, quint64> driverIdToMsgId;

    // 配置快照(构造时从 options 拷贝,避免依赖其生命周期)。
    QStringList protectedPaths, fileHardBlocks, protectedRegKeys, regHardBlocks, blockedEndpoints;
    QStringList memProtTargets;

    quint32 selfPid = 0;
    QSet<int> protectedPids;   // 自我保护:本服务 + UI 等
    QSet<int> pendingPids;     // 连接前排队的受保护 PID
    QSet<QString> memProtNames;// 内存防护目标进程名(小写),空=未启用

    static constexpr int kQueueMax = 4096;
    Logger log{QStringLiteral("bulwark.service.Driver")};

    void enqueue(bulwark::SecurityEvent&& e) {
        QMutexLocker lock(&queueMutex);
        if (queue.size() >= kQueueMax) return; // 满则丢弃(遥测可丢,稳定性优先)
        queue.push_back(std::move(e));
    }

    // ---- 实现细节(全部定义在本 .cpp,不出现在头文件)----
    bool connectPort();   // FilterConnectCommunicationPort(带短重试:load 后端口可能略滞后)
    bool handshake();     // 协议握手:校验版本 + 三个关键结构体大小一致,不一致拒绝拦截
    void sendConfig(ULONG command, const QString& path = QString(),
                    ULONG pid = 0, ULONG blockIp = 0, USHORT blockPort = 0);
    void pushInitialConfig();   // 连接后下发受保护路径/键、硬拦名单、黑名单、自保 PID、文件遥测
    void initMemoryProtection();// 反注入:登记目标进程名集合 + 现存匹配 PID
    void addMemProtPidToKernel(int pid);
    void closePort();
    void readLoop();            // 后台线程:阻塞收消息 -> 轻量映射 + NT 路径归一 -> 入队
    void buildAndQueue(const BLW_EVENT_MESSAGE& ev, ULONG64 messageId);
    void reply(ULONG64 messageId, ULONG64 eventId, ULONG verdict);
};

} // namespace bulwark::service

namespace bulwark::service {

bool DriverEventSource::Impl::connectPort() {
    // load 后端口可能略滞后就绪:短重试若干次(总计约 1.5s),避免刚加载驱动即连接失败。
    for (int attempt = 0; attempt < 5; ++attempt) {
        HANDLE h = nullptr;
        const HRESULT hr = ::FilterConnectCommunicationPort(
            BLW_PORT_NAME, 0, nullptr, 0, nullptr, &h);
        if (hr == S_OK && h != nullptr && h != INVALID_HANDLE_VALUE) {
            QMutexLocker lock(&portMutex);
            port = h;
            connected.store(true);
            log.info(QStringLiteral("已连接内核驱动通信端口 %1。").arg(QString::fromWCharArray(BLW_PORT_NAME)));
            return true;
        }
        ::Sleep(300);
    }
    log.warning(QStringLiteral("无法连接内核驱动端口 %1(驱动未加载 / 无管理员权限 / 测试签名未开?)。")
                    .arg(QString::fromWCharArray(BLW_PORT_NAME)));
    return false;
}

bool DriverEventSource::Impl::handshake() {
    BLW_CONFIG_MESSAGE cfg;
    ZeroMemory(&cfg, sizeof(cfg));
    cfg.Command = BLW_CMD_HANDSHAKE;

    BLW_HANDSHAKE_REPLY reply;
    ZeroMemory(&reply, sizeof(reply));
    DWORD returned = 0;
    HRESULT hr;
    {
        QMutexLocker lock(&portMutex);
        if (port == nullptr) return false;
        hr = ::FilterSendMessage(port, &cfg, sizeof(cfg), &reply, sizeof(reply), &returned);
    }
    if (FAILED(hr)) {
        log.warning(QStringLiteral("协议握手发送失败 0x%1(驱动可能为旧版,不支持握手命令)。")
                        .arg(static_cast<quint32>(hr), 8, 16, QLatin1Char('0')));
        return false;
    }
    if (returned < sizeof(reply)) {
        log.warning(QStringLiteral("协议握手应答长度异常:%1/%2。").arg(returned).arg((int)sizeof(reply)));
        return false;
    }

    const ULONG expectEvent   = static_cast<ULONG>(sizeof(BLW_EVENT_MESSAGE));
    const ULONG expectConfig  = static_cast<ULONG>(sizeof(BLW_CONFIG_MESSAGE));
    const ULONG expectVerdict = static_cast<ULONG>(sizeof(BLW_VERDICT_REPLY));
    // 版本兼容:v3/v4 均与当前 v5 【线布局完全一致】——真正的内存安全保证是下面三个结构体大小
    // 必须逐一相等(不等则拒绝,防错位误判蓝屏)。v4->v5 仅【移除】了影子/沙盒命令与事件,而 v5
    // 服务从不下发这些命令,故 v4 驱动的相关代码永远休眠、绝不发影子事件 —— 因此接受 v4 安全。
    // (避免用户升级服务却因驱动仍是旧 v4 而整体降级为无文件遥测的用户态观测。)
    const bool ok =
        (reply.ProtocolVersion == BLW_PROTOCOL_VERSION ||
         reply.ProtocolVersion == 4 || reply.ProtocolVersion == 3) && // 兼容旧版(v3/v4,布局一致)
        reply.EventMessageSize == expectEvent &&
        reply.ConfigMessageSize == expectConfig &&
        reply.VerdictReplySize == expectVerdict;
    if (!ok) {
        log.error(QStringLiteral(
            "内核/服务协议不一致:内核(ver=%1 event=%2 config=%3 verdict=%4) vs "
            "服务(ver=%5 event=%6 config=%7 verdict=%8) —— 已拒绝启用内核拦截以防误判。")
            .arg(reply.ProtocolVersion).arg(reply.EventMessageSize)
            .arg(reply.ConfigMessageSize).arg(reply.VerdictReplySize)
            .arg(BLW_PROTOCOL_VERSION).arg(expectEvent).arg(expectConfig).arg(expectVerdict));
        return false;
    }
    log.info(QStringLiteral("协议握手通过(ver=%1 event=%2 config=%3 verdict=%4)。")
                 .arg(reply.ProtocolVersion).arg(reply.EventMessageSize)
                 .arg(reply.ConfigMessageSize).arg(reply.VerdictReplySize));
    return true;
}

void DriverEventSource::Impl::sendConfig(ULONG command, const QString& path,
                                         ULONG pid, ULONG blockIp, USHORT blockPort) {
    BLW_CONFIG_MESSAGE cfg;
    ZeroMemory(&cfg, sizeof(cfg));
    cfg.Command = command;
    cfg.Pid = pid;
    cfg.BlockIpV4 = blockIp;
    cfg.BlockPort = blockPort;

    QString p = path;
    const int maxChars = BLW_MAX_PATH - 1;
    if (p.size() > maxChars) p = p.left(maxChars);
    cfg.PathLength = static_cast<USHORT>(p.size());
    const int copied = p.isEmpty() ? 0 : p.toWCharArray(cfg.Path);
    cfg.Path[copied] = L'\0';

    QMutexLocker lock(&portMutex);
    if (port == nullptr) return;
    DWORD returned = 0;
    const HRESULT hr = ::FilterSendMessage(port, &cfg, sizeof(cfg), nullptr, 0, &returned);
    if (FAILED(hr))
        log.warning(QStringLiteral("FilterSendMessage(config=%1) 失败 0x%2")
                        .arg(command).arg(static_cast<quint32>(hr), 8, 16, QLatin1Char('0')));
}

void DriverEventSource::Impl::pushInitialConfig() {
    // 受保护文件路径(命中的删除/重命名会被拦截 / 上报)。
    sendConfig(BLW_CMD_CLEAR_PATHS);
    for (const QString& s : protectedPaths)
        if (!s.trimmed().isEmpty()) sendConfig(BLW_CMD_ADD_PATH, s.trimmed());

    // 文件硬拦截(命中即内核本地 STATUS_ACCESS_DENIED,防内容篡改)。
    sendConfig(BLW_CMD_CLEAR_FILEHARD);
    for (const QString& s : fileHardBlocks)
        if (!s.trimmed().isEmpty()) sendConfig(BLW_CMD_ADD_FILEHARD, s.trimmed());

    // 受保护注册表键。
    sendConfig(BLW_CMD_CLEAR_REGKEYS);
    for (const QString& s : protectedRegKeys)
        if (!s.trimmed().isEmpty()) sendConfig(BLW_CMD_ADD_REGKEY, s.trimmed());

    // 注册表硬拦截(必须精确键值,命中即内核本地拒绝)。
    sendConfig(BLW_CMD_CLEAR_REGHARD);
    for (const QString& s : regHardBlocks)
        if (!s.trimmed().isEmpty()) sendConfig(BLW_CMD_ADD_REGHARD, s.trimmed());

    // 网络黑名单(IPv4[:port])。
    sendConfig(BLW_CMD_CLEAR_BLOCKIP);
    for (const QString& s : blockedEndpoints) {
        quint32 bip = 0; quint16 bport = 0;
        if (parseIpEndpoint(s, bip, bport))
            sendConfig(BLW_CMD_ADD_BLOCKIP, QString(), 0, bip, bport);
        else if (!s.trimmed().isEmpty())
            log.warning(QStringLiteral("忽略无法解析的网络黑名单条目:%1").arg(s));
    }

    // 自我保护:本服务 + 连接前排队的 UI 进程一并下发。
    {
        protectedPids.insert(static_cast<int>(::GetCurrentProcessId()));
        for (int pid : pendingPids)
            protectedPids.insert(pid);
        pendingPids.clear();
        sendConfig(BLW_CMD_CLEAR_PIDS);
        for (int pid : protectedPids)
            if (pid > 0) sendConfig(BLW_CMD_ADD_PID, QString(), static_cast<ULONG>(pid));
    }

    // 内存防护(反注入):登记目标进程名 + 现存匹配 PID。
    initMemoryProtection();

    // 文件行为遥测:开启内核对删除/重命名的观测上报(勒索时序聚合数据源)。
    sendConfig(BLW_CMD_SET_FILETELEMETRY, QString(), 1u);

    log.info(QStringLiteral("已向内核下发初始配置(受保护项 / 硬拦名单 / 黑名单 / 自保 PID / 文件遥测)。"));
}

void DriverEventSource::Impl::addMemProtPidToKernel(int pid) {
    if (pid <= 4) return;
    sendConfig(BLW_CMD_ADD_MEMPROT, QString(), static_cast<ULONG>(pid));
}

void DriverEventSource::Impl::initMemoryProtection() {
    sendConfig(BLW_CMD_CLEAR_MEMPROT);
    memProtNames.clear();
    if (memProtTargets.isEmpty())
        return;
    for (const QString& t : memProtTargets) {
        const QString name = QFileInfo(t.trimmed()).fileName().toLower();
        if (!name.isEmpty()) memProtNames.insert(name);
    }
    if (memProtNames.isEmpty())
        return;

    // 枚举现存进程,按名匹配把命中 PID 下发内核(新建进程由 readLoop 增量登记)。
    int count = 0;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        ZeroMemory(&pe, sizeof(pe));
        pe.dwSize = sizeof(pe);
        if (::Process32FirstW(snap, &pe)) {
            do {
                const QString exe = QString::fromWCharArray(pe.szExeFile).toLower();
                if (pe.th32ProcessID > 4 && memProtNames.contains(exe)) {
                    addMemProtPidToKernel(static_cast<int>(pe.th32ProcessID));
                    ++count;
                }
            } while (::Process32NextW(snap, &pe));
        }
        ::CloseHandle(snap);
    }
    log.info(QStringLiteral("内存防护(反注入)已启用,目标进程名 %1 个,已登记现存进程 %2 个。")
                 .arg(memProtNames.size()).arg(count));
}

void DriverEventSource::Impl::closePort() {
    QMutexLocker lock(&portMutex);
    if (port != nullptr) {
        ::CloseHandle(port); // 关闭句柄会中止读线程阻塞中的 FilterGetMessage
        port = nullptr;
    }
    connected.store(false);
}

} // namespace bulwark::service

namespace bulwark::service {

void DriverEventSource::Impl::reply(ULONG64 messageId, ULONG64 eventId, ULONG verdict) {
    BlwReplyMessage msg;
    ZeroMemory(&msg, sizeof(msg));
    msg.Header.Status = 0;              // STATUS_SUCCESS
    msg.Header.MessageId = messageId;   // 必须与收到的 MessageId 一致
    msg.Reply.EventId = eventId;
    msg.Reply.Verdict = verdict;

    QMutexLocker lock(&portMutex);
    if (port == nullptr) return;
    const HRESULT hr = ::FilterReplyMessage(port, &msg.Header, sizeof(msg));
    if (FAILED(hr))
        log.info(QStringLiteral("FilterReplyMessage 失败 0x%1(内核未等待 / 已超时,无害)。")
                     .arg(static_cast<quint32>(hr), 8, 16, QLatin1Char('0')));
}

// 把一条内核消息做轻量映射(类型 + NT 路径归一 + 目标解析),入队。昂贵的签名/哈希/命令行/
// 祖先链富化由主线程 Worker::enrich 统一完成——读线程务必快进快出。对应 .NET BuildAndQueueEvent
// 的「轻量部分」;取证部分已下放 Worker。
void DriverEventSource::Impl::buildAndQueue(const BLW_EVENT_MESSAGE& ev, ULONG64 messageId) {
    bulwark::SecurityEvent e;
    e.type = mapType(ev.Type);
    e.actorPid = static_cast<int>(ev.ActorPid);

    const QString imagePath = ev.ImagePathLength > 0
        ? normalizeNtPath(QString::fromWCharArray(ev.ImagePath, ev.ImagePathLength))
        : QString();
    const QString targetPath = ev.TargetPathLength > 0
        ? normalizeNtPath(QString::fromWCharArray(ev.TargetPath, ev.TargetPathLength))
        : QString();
    // 非进程创建事件:actorPath 先置 "PID n" 占位,Worker::enrich 会按 PID 回填真实映像路径。
    const QString actorPlaceholder = QStringLiteral("PID %1").arg(e.actorPid);

    switch (ev.Type) {
        case BlwEventProcessCreate:
            // 进程创建(fire-and-forget 遥测)。标记用户态观测:Block 时 Worker 结束进程树。
            e.actorPath = imagePath;
            e.target = imagePath;
            e.parentPid = static_cast<int>(ev.ParentPid);
            e.detail = QStringLiteral("内核遥测 · 进程创建(父PID %1)").arg(ev.ParentPid);
            e.userModeObserved = true;
            // 内存防护增量登记:命中目标名单的新进程立即获得反注入保护。
            if (!memProtNames.isEmpty() && !imagePath.isEmpty()) {
                const QString name = QFileInfo(imagePath).fileName().toLower();
                if (memProtNames.contains(name))
                    addMemProtPidToKernel(e.actorPid);
            }
            break;

        case BlwEventFileDelete:
        case BlwEventFileRename:
            e.actorPath = actorPlaceholder;
            e.target = targetPath;
            e.detail = (ev.Type == BlwEventFileDelete)
                ? QStringLiteral("内核拦截 · 删除受保护文件")
                : QStringLiteral("内核拦截 · 重命名/移动受保护文件");
            break;

        case BlwEventFileModify:
            // 文件行为遥测(未命中名单的正常删/改名,内核未拦截)。原始操作类型由内核打包在
            // ParentPid 字段(2=删除标记,3=重命名)。映射到引擎可聚合的类型,标记用户态观测。
            e.type = (ev.ParentPid == BlwEventFileDelete)
                ? bulwark::EventType::FileDelete
                : bulwark::EventType::FileWrite;
            e.actorPath = actorPlaceholder;
            e.target = targetPath;
            e.detail = QStringLiteral("文件行为遥测 · %1")
                           .arg(ev.ParentPid == BlwEventFileDelete ? QStringLiteral("删除")
                                                                   : QStringLiteral("重命名/移动"));
            e.userModeObserved = true;
            break;

        case BlwEventRegistrySetValue:
        case BlwEventRegistryDeleteValue:
        case BlwEventRegistryDeleteKey:
            e.actorPath = actorPlaceholder;
            e.target = targetPath;
            e.detail = (ev.Type == BlwEventRegistrySetValue)
                ? QStringLiteral("内核拦截 · 写入受保护注册表键")
                : (ev.Type == BlwEventRegistryDeleteValue)
                      ? QStringLiteral("内核拦截 · 删除受保护注册表值")
                      : QStringLiteral("内核拦截 · 删除受保护注册表键");
            // 创建服务经 SCM(services.exe)代写服务键,内核归因为 SCM。尝试还原真实 RPC 发起者
            // (发起线程此刻阻塞在 WrLpcReply)。仅高置信唯一候选才改写主体,否则保守留 SCM。
            if (ServiceControlTracer::isServiceDatabaseKey(targetPath)) {
                const ServiceOriginator orig = ServiceControlTracer::trace(e.actorPid);
                if (orig.highConfidence()) {
                    e.actorPid = orig.originatorPid;
                    e.actorPath = orig.originatorPath;
                    e.detail += QStringLiteral(" · 真凶溯源:%1(PID %2)")
                                    .arg(QFileInfo(orig.originatorPath).fileName()).arg(orig.originatorPid);
                }
            }
            break;

        case BlwEventSelfProtect:
            e.actorPath = actorPlaceholder;
            e.target = QStringLiteral("受保护进程 PID %1").arg(ev.ParentPid);
            e.detail = QStringLiteral("内核自保 · 已剥离对本软件的危险访问权限");
            break;

        case BlwEventMemoryProtect: {
            // 反注入:已剥离 actor 对高价值进程(ParentPid=受害者)的写内存/远程线程权限。
            const int victim = static_cast<int>(ev.ParentPid);
            const QString victimPath = resolvePidImagePath(ev.ParentPid);
            e.actorPath = actorPlaceholder;
            e.target = victimPath.isEmpty() ? QStringLiteral("PID %1").arg(victim) : victimPath;
            e.memoryInjection = true;
            e.detail = QStringLiteral("内核内存防护 · 已阻止跨进程注入 -> %1(PID %2)")
                           .arg(QFileInfo(e.target).fileName()).arg(victim);
            break;
        }

        case BlwEventNetworkConnect:
            e.actorPath = actorPlaceholder;
            e.target = QStringLiteral("%1:%2").arg(formatIpv4Host(ev.RemoteIpV4)).arg(ev.RemotePort);
            e.detail = QStringLiteral("内核拦截 · 已阻断对黑名单地址的外联");
            break;

        case BlwEventImageLoad: {
            // 映像加载(BYOVD / DLL 侧载)。仅记录型。ActorPid==0 表示内核驱动加载。
            const bool kernelModule = (e.actorPid == 0);
            e.actorPath = kernelModule ? QStringLiteral("内核(驱动加载)") : actorPlaceholder;
            e.target = targetPath;
            e.detail = kernelModule
                ? QStringLiteral("内核监控 · 加载驱动模块 %1").arg(QFileInfo(targetPath).fileName())
                : QStringLiteral("内核监控 · 加载模块 %1").arg(QFileInfo(targetPath).fileName());
            break;
        }

        case BlwEventImageBlocked:
            e.actorPath = e.actorPid > 0 ? actorPlaceholder : QStringLiteral("(加载方未知)");
            e.target = targetPath;
            e.detail = QStringLiteral("内核拦截 · 已阻止加载禁用模块 %1(白加黑防护)")
                           .arg(QFileInfo(targetPath).fileName());
            break;

        case BlwEventRemoteThread: {
            // 远程线程注入:Actor=注入发起进程,目标进程 PID 在 ParentPid,解析为完整路径供
            // 规则 TargetPattern 匹配(如 *\explorer.exe)。
            const int victim = static_cast<int>(ev.ParentPid);
            const QString victimPath = resolvePidImagePath(ev.ParentPid);
            e.actorPath = actorPlaceholder;
            e.target = victimPath.isEmpty() ? QStringLiteral("PID %1").arg(victim) : victimPath;
            e.detail = QStringLiteral("内核监控 · 跨进程线程注入 -> %1(PID %2)")
                           .arg(QFileInfo(e.target).fileName()).arg(victim);
            break;
        }

        case BlwEventProcessTerminate: {
            // 结束进程:Actor=发起者,Target=被结束进程(规则以 TargetPattern 匹配被结束进程)。
            e.actorPath = actorPlaceholder;
            QString victimPath = targetPath;
            if (victimPath.isEmpty())
                victimPath = resolvePidImagePath(ev.ParentPid);
            e.target = victimPath;
            e.detail = QStringLiteral("内核拦截 · 结束进程 %1").arg(QFileInfo(e.target).fileName());
            break;
        }

        default:
            e.actorPath = imagePath.isEmpty() ? actorPlaceholder : imagePath;
            e.target = e.actorPath;
            break;
    }

    // 仅内核实际等待裁决的事件(文件/注册表/结束进程)记录 Id 映射,供 submitVerdict 回写。
    if (needsVerdict(ev.Type)) {
        QMutexLocker lock(&mapMutex);
        eventToDriverId.insert(e.id, ev.EventId);
        driverIdToMsgId.insert(ev.EventId, messageId);
    }

    enqueue(std::move(e));
}

void DriverEventSource::Impl::readLoop() {
    const DWORD msgSize = static_cast<DWORD>(sizeof(BlwGetMessage));
    std::vector<unsigned char> buffer(msgSize);

    while (running.load()) {
        HANDLE p;
        {
            QMutexLocker lock(&portMutex);
            p = port;
        }
        if (p == nullptr)
            break;

        BlwGetMessage* msg = reinterpret_cast<BlwGetMessage*>(buffer.data());
        ZeroMemory(msg, msgSize);

        // 同步阻塞读取。快进快出:只读消息 + 轻量映射,取证富化交主线程 Worker::enrich。
        const HRESULT hr = ::FilterGetMessage(p, &msg->Header, msgSize, nullptr);
        if (hr != S_OK) {
            if (!running.load()) break;
            if (isBenignDisconnect(hr))
                log.info(QStringLiteral("FilterGetMessage 返回 0x%1(连接已断开),退出读取循环。")
                             .arg(static_cast<quint32>(hr), 8, 16, QLatin1Char('0')));
            else
                log.warning(QStringLiteral("FilterGetMessage 返回 0x%1,退出读取循环(将由主线程重连)。")
                                .arg(static_cast<quint32>(hr), 8, 16, QLatin1Char('0')));
            break;
        }

        try {
            buildAndQueue(msg->Event, msg->Header.MessageId);
        } catch (...) {
            // 单条事件处理异常绝不能中断读取循环(否则管道断开,UI 表现为"保存无效")。
        }
    }
    connected.store(false);
}

} // namespace bulwark::service

namespace bulwark::service {

DriverEventSource::DriverEventSource(const BulwarkOptions& options, QObject* parent)
    : EventSource(parent), d_(std::make_unique<Impl>()) {
    // 拷贝配置快照(不依赖 options 生命周期)。
    d_->protectedPaths    = options.ProtectedPaths;
    d_->fileHardBlocks    = options.FileHardBlocks;
    d_->protectedRegKeys  = options.ProtectedRegistryKeys;
    d_->regHardBlocks     = options.RegistryHardBlocks;
    d_->blockedEndpoints  = options.BlockedRemoteEndpoints;
    d_->memProtTargets    = options.MemoryProtectionTargets;
    d_->selfPid           = static_cast<quint32>(::GetCurrentProcessId());

    drainTimer_ = new QTimer(this);
    drainTimer_->setInterval(150); // 每 150ms 把读线程收集的事件搬到主线程 emit(裁决路径尽量低延迟)
    connect(drainTimer_, &QTimer::timeout, this, &DriverEventSource::drain);
}

DriverEventSource::~DriverEventSource() { stop(); }

void DriverEventSource::start() {
    if (d_->running.load())
        return;

    // 连接 + 协议握手(同步)。任一失败即降级:isAvailable() 返回 false,服务其余部分照常。
    if (!d_->connectPort())
        return;
    if (!d_->handshake()) {
        d_->protocolMismatch.store(true);
        d_->closePort();
        return;
    }

    d_->pushInitialConfig();

    d_->running.store(true);
    Impl* impl = d_.get();
    d_->readThread = std::thread([impl] {
        try { impl->readLoop(); }
        catch (...) { impl->log.warning(QStringLiteral("驱动读取线程异常退出。")); }
    });
    drainTimer_->start();
    d_->log.info(QStringLiteral("内核驱动事件源已就绪(行为前拦截 + 用户态补偿)。"));
}

void DriverEventSource::stop() {
    if (drainTimer_)
        drainTimer_->stop();
    d_->running.store(false);
    d_->closePort();            // 关闭句柄以中止读线程阻塞中的 FilterGetMessage
    if (d_->readThread.joinable())
        d_->readThread.join();
    // 排空剩余队列(不再 emit,避免停机后触达已失效对象)。
    QMutexLocker lock(&d_->queueMutex);
    d_->queue.clear();
}

bool DriverEventSource::isAvailable() const { return d_->connected.load(); }
bool DriverEventSource::isConnected() const { return d_->connected.load(); }
bool DriverEventSource::protocolMismatch() const { return d_->protocolMismatch.load(); }

void DriverEventSource::submitVerdict(const bulwark::SecurityEvent& e, bulwark::VerdictAction action) {
    // 仅对内核实际等待裁决的事件(文件/注册表/结束进程)回写;其余为 fire-and-forget,
    // 映射表中不存在该 Id,直接返回(no-op)。与 .NET SubmitVerdict 语义一致。
    quint64 driverEventId = 0, messageId = 0;
    {
        QMutexLocker lock(&d_->mapMutex);
        auto it = d_->eventToDriverId.find(e.id);
        if (it == d_->eventToDriverId.end())
            return;
        driverEventId = it.value();
        d_->eventToDriverId.erase(it);
        auto mit = d_->driverIdToMsgId.find(driverEventId);
        if (mit == d_->driverIdToMsgId.end())
            return;
        messageId = mit.value();
        d_->driverIdToMsgId.erase(mit);
    }
    d_->reply(messageId, driverEventId,
              action == bulwark::VerdictAction::Block ? BlwVerdictBlock : BlwVerdictAllow);
}

void DriverEventSource::addProtectedPid(int pid) {
    if (pid <= 0)
        return;
    if (d_->connected.load()) {
        bool added = false;
        {
            QMutexLocker lock(&d_->queueMutex); // 复用一把锁保护 protectedPids 集合
            added = !d_->protectedPids.contains(pid);
            if (added) d_->protectedPids.insert(pid);
        }
        if (added) {
            d_->sendConfig(BLW_CMD_ADD_PID, QString(), static_cast<ULONG>(pid));
            d_->log.info(QStringLiteral("已将进程 PID %1 加入内核自我保护。").arg(pid));
        }
    } else {
        QMutexLocker lock(&d_->queueMutex);
        d_->pendingPids.insert(pid); // 端口连接后由 pushInitialConfig 一并下发
    }
}

void DriverEventSource::addBlockedIp(const QString& ip, quint16 port) {
    quint32 ipHost = 0; quint16 p = 0;
    const QString entry = port > 0 ? QStringLiteral("%1:%2").arg(ip).arg(port) : ip;
    if (parseIpEndpoint(entry, ipHost, p))
        d_->sendConfig(BLW_CMD_ADD_BLOCKIP, QString(), 0, ipHost, p);
}

bool DriverEventSource::blockModuleLoad(const QString& modulePath) {
    const QString p = modulePath.trimmed();
    if (p.isEmpty() || !d_->connected.load())
        return false;
    d_->sendConfig(BLW_CMD_ADD_NOLOAD, p);
    d_->log.warning(QStringLiteral("已下发内核「禁止加载」名单:%1").arg(p));
    return true;
}

void DriverEventSource::drain() {
    QVector<bulwark::SecurityEvent> batch;
    {
        QMutexLocker lock(&d_->queueMutex);
        if (d_->queue.isEmpty())
            return;
        batch.swap(d_->queue);
    }
    for (const auto& e : batch)
        emit eventProduced(e);
}

} // namespace bulwark::service
