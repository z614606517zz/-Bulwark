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
#include <QByteArray>
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

// 去掉盘符前缀(如 "C:"),返回盘符无关的路径子串。内核文件硬拦按子串匹配,而文件在内核侧的规范化名
// 可能是 \Device\HarddiskVolumeN\... 或 \??\C:\... 形式,去盘符后二者都含同一子串,从而稳定命中
//(与 ProcessMonitor 系统目录白名单用盘符无关子串同理)。同时把 '/' 归一为 '\\';UNC(\\host\..)本就无盘符。
QString driveAgnostic(const QString& path) {
    QString p = path.trimmed();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (p.size() >= 2 && p[1] == QLatin1Char(':'))
        p = p.mid(2);
    return p;
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
        // 命令行硬拦:本质就是一次【被拒绝的进程创建】,故映射为 ProcessCreate ——
        // 主体是发起方(父进程,仍在运行且可解析),规则可用 ActorPattern 命中真凶。
        case BlwEventCommandBlocked:       return bulwark::EventType::ProcessCreate;
        // hive 转储:注册表维度事件,规则可用 RegistryWrite + TargetPattern(如 *\SAM)命中。
        case BlwEventRegistryHiveDump:     return bulwark::EventType::RegistryWrite;
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
    // 读线程的原生句柄。停机时要用 CancelSynchronousIo 定向取消它阻塞中的同步 I/O ——
    // 光靠关端口句柄是唤不醒它的(见 stop() 里的说明)。
    HANDLE readThreadNative = nullptr;
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
    QStringList cmdHardBlocks;          // 命令行硬拦:用户追加的模式
    bool cmdHardBaseline = true;        // 是否下发内置反勒索 / 反凭据窃取基线

    quint32 selfPid = 0;
    QSet<int> protectedPids;   // 自我保护:本服务 + UI 等
    QSet<int> pendingPids;     // 连接前排队的受保护 PID
    QSet<QString> memProtNames;// 内存防护(反注入)目标进程名(小写),空=未启用
    QSet<QString> credProtNames;// 凭据保护(反转储)目标进程名(小写,硬编 lsass.exe;始终启用)

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
    void pushInitialConfig();   // 连接后下发受保护路径/键、硬拦名单、命令行硬拦、黑名单、自保 PID、文件遥测
    void initMemoryProtection();// 反注入 + 凭据反转储:登记目标进程名集合 + 现存匹配 PID
    void addMemProtPidToKernel(int pid);
    void addCredProtPidToKernel(int pid);// 凭据反转储:把 lsass PID 下发内核(额外剥 VM_READ)
    void closePort();
    void readLoop();            // 后台线程:阻塞收消息 -> 轻量映射 + NT 路径归一 -> 入队
    void buildAndQueue(const BLW_EVENT_MESSAGE& ev, ULONG64 messageId);
    void reply(ULONG64 messageId, ULONG64 eventId, ULONG verdict);
    // 内核级足迹清理(v6):以「忽略共享访问检查」读整文件 / 强制删除被占用文件。
    bool kernelReadFile(const QString& path, QByteArray& out);
    bool kernelForceDelete(const QString& path);
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
    // 版本兼容:v3..v8 均与当前 v9 【线布局完全一致】——真正的内存安全保证是下面三个结构体
    // 大小必须逐一相等(不等则拒绝,防错位误判蓝屏)。v5->v6->v7->v8->v9 都只是【新增】复用现有
    // BLW_CONFIG_MESSAGE 的命令(足迹清理 / 驱动级结束进程 / 执行前拦截 / 凭据反转储),未改动任何握手
    // 结构体布局,故各版本握手线布局完全一致;本服务同时接受 v9 与旧 v3..v8 驱动,避免因单端升级而整体降级。
    const bool ok =
        (reply.ProtocolVersion == BLW_PROTOCOL_VERSION ||
         reply.ProtocolVersion == 8 || reply.ProtocolVersion == 7 ||
         reply.ProtocolVersion == 6 || reply.ProtocolVersion == 5 ||
         reply.ProtocolVersion == 4 || reply.ProtocolVersion == 3) && // 兼容旧版(v3-v8,布局一致)
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

    // 自我保护(反篡改)· 文件:改由下方「自保护足迹 SelfGuard」统一覆盖本产品【完整内容】
    //(安装目录全部文件 + %ProgramData%\Bulwark 数据目录 + 驱动 .sys),owner-aware(仅放行本产品
    // 自身进程写入),故既能覆盖持续写入的数据目录、又不像 FileHardBlock 那样把本产品自己也挡在外面。
    // 见 pushInitialConfig 末尾(须在受保护 PID 下发之后登记,以保证属主判定就绪)。

    // 受保护注册表键。
    sendConfig(BLW_CMD_CLEAR_REGKEYS);
    for (const QString& s : protectedRegKeys)
        if (!s.trimmed().isEmpty()) sendConfig(BLW_CMD_ADD_REGKEY, s.trimmed());

    // 注册表硬拦截(必须精确键值,命中即内核本地拒绝)。
    sendConfig(BLW_CMD_CLEAR_REGHARD);
    for (const QString& s : regHardBlocks)
        if (!s.trimmed().isEmpty()) sendConfig(BLW_CMD_ADD_REGHARD, s.trimmed());

    // 自我保护(反篡改)· 注册表:把本产品服务键纳入内核注册表硬拦(命中即拒绝写入),防 sc config /
    // sc delete / 改 ImagePath / 置 Start=disabled 等「先禁服务再作案」。子串 "\Services\Bulwark" 同时
    // 覆盖驱动服务(Bulwark)与用户态服务(BulwarkService);仅匹配本产品自己的键,绝不触碰系统高频键。
    // 运行期本产品不写这些键(启停/加载走 SCM/FltMgr 运行态,不改键值),故不影响正常功能。
    // 注意:合法卸载/重配需先卸载驱动以解除该硬拦。
    sendConfig(BLW_CMD_ADD_REGHARD, QStringLiteral("\\Services\\Bulwark"));
    log.info(QStringLiteral("自我保护 · 注册表:已把服务键(\\Services\\Bulwark*)纳入内核注册表硬拦(防禁用/劫持)。"));

    //
    // ===== 命令行硬拦(执行前拦截·按用法)=====
    //
    // 这一维补的是本项目原先最大的一处能力浪费:LOLBin(vssadmin / wmic / bcdedit / wbadmin /
    // fsutil / reg ...)本体位于 System32、签名可信、路径受 WRP 保护 —— 无论怎么按「身份」判定
    // 都是可信的,威胁完全来自「用法」。原先只能把它们放行给用户态看命令行,于是回到「事后 kill」:
    // `vssadmin delete shadows /all /quiet` 在毫秒级就完成不可逆破坏,等裁决回来卷影早已没了。
    // 现在内核在进程创建回调里直接读 CreateInfo->CommandLine 本地查表,命中即拒绝创建 ——
    // 命令一次都不会执行,且名单持久化到 \Policy,服务没起来 / 被杀 / 刚重启时同样生效。
    //
    // 模式语法:'+' 分隔的 token 合取,每个 token 都必须作为大小写不敏感子串出现。
    // 因此参数顺序、空格数量、大小写、是否带全路径全都绕不过去。
    //
    // 【选取原则】只收「几乎不存在良性用法」的破坏性动作,严格遵循最小化误报:
    //   * 每个 token >= 4 字符 —— token 是纯子串,像 "cl" 这种短 token 会命中无关单词造成误报;
    //   * 宁可少收一条,也不放宽成可能拦到正常运维的模式(如不用单独的 DELETE、不用单独的 REG);
    //   * 命中会被内核直接拒绝且不弹窗,故每一条都必须是「一旦发生基本等同于攻击」的动作。
    //
    {
        sendConfig(BLW_CMD_CLEAR_CMDBLOCK);

        QStringList patterns;
        if (cmdHardBaseline) {
            patterns = QStringList{
                // ---- 反勒索:摧毁备份 / 恢复能力,是勒索软件加密前的标准前置动作 ----
                QStringLiteral("VSSADMIN+DELETE+SHADOWS"),           // 删除卷影副本(最经典的一条)
                QStringLiteral("VSSADMIN+RESIZE+SHADOWSTORAGE"),     // 把卷影存储压到极小以清空全部还原点
                QStringLiteral("WMIC+SHADOWCOPY+DELETE"),            // 走 WMI 删卷影
                QStringLiteral("WIN32_SHADOWCOPY+DELETE"),           // PowerShell/WMI 对象方式删卷影
                QStringLiteral("WBADMIN+DELETE+CATALOG"),            // 删除 Windows 备份目录
                QStringLiteral("WBADMIN+DELETE+SYSTEMSTATEBACKUP"),  // 删除系统状态备份
                QStringLiteral("BCDEDIT+RECOVERYENABLED"),           // 关闭 Windows 恢复环境
                QStringLiteral("BCDEDIT+BOOTSTATUSPOLICY"),          // 关闭启动失败自动修复
                QStringLiteral("FSUTIL+DELETEJOURNAL"),              // 删 USN 变更日志(反取证 + 阻碍恢复)

                // ---- 反凭据窃取:导出注册表 hive 后离线破解,这条路完全绕开 lsass ----
                // 与内核 RegNtPreSaveKey 的内置硬拦构成双重保险:这里连 reg.exe 都起不来,
                // 那里兜住任何其它调用 ZwSaveKey 的程序。
                //
                // 必须把根键的【长写法】一并列出。实测发现:`reg save HKEY_LOCAL_MACHINE\SAM out.hiv`
                // 不含子串 "HKLM\SAM",只用短写法这一条就被绕过了 —— 当时全靠内核 SaveKey 那层兜住,
                // 说明纵深防御是对的,但外层这个口子该堵。reg.exe 对两种写法等价接受,攻击者自然会选
                // 没被覆盖的那个。(注:命令行层是【可选外层】,真正的兜底始终是内核内置 hive 硬拦 ——
                // 它按【解析后的键路径】判定,任何写法、任何调用 ZwSaveKey 的程序都跑不掉。)
                QStringLiteral("SAVE+HKLM\\SAM"),                    // 导出 SAM(本机账户口令哈希)
                QStringLiteral("SAVE+HKLM\\SECURITY"),               // 导出 SECURITY(LSA 机密)
                QStringLiteral("SAVE+HKEY_LOCAL_MACHINE\\SAM"),      // 同上,根键长写法
                QStringLiteral("SAVE+HKEY_LOCAL_MACHINE\\SECURITY"), // 同上,根键长写法
            };
        }
        // 用户追加的模式(appsettings.json 的 CommandHardBlocks)。
        for (const QString& s : cmdHardBlocks) {
            const QString t = s.trimmed();
            if (!t.isEmpty() && !patterns.contains(t, Qt::CaseInsensitive))
                patterns.append(t);
        }

        for (const QString& p : patterns)
            sendConfig(BLW_CMD_ADD_CMDBLOCK, p);

        if (patterns.isEmpty()) {
            log.info(QStringLiteral("命令行硬拦:名单为空(基线已关闭且无自定义模式),该维度未启用。"));
        } else {
            log.info(QStringLiteral("命令行硬拦(执行前拦截):已下发 %1 条模式(内置基线%2,自定义 %3 条)"
                                    " —— 命中即内核拒绝创建进程,危险命令一次都不会执行,且跨重启/杀服务持续生效。")
                         .arg(patterns.size())
                         .arg(cmdHardBaseline ? QStringLiteral("已启用") : QStringLiteral("已关闭"))
                         .arg(cmdHardBlocks.size()));
        }
    }

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

    // 自我保护(反勒索)· 完整内容:把本产品的「完整足迹」下发内核自保护名单 SelfGuard ——
    // 此后【非本产品自身受保护进程】对这些路径的写/删/改名一律被内核本地拒绝(勒索病毒无法加密/
    // 篡改/删除本产品任何文件),而本产品自身进程(上面刚下发的受保护 PID)仍可正常读写自己的数据。
    // 必须在受保护 PID 下发【之后】登记,以保证内核属主判定(BlwPidIsProtected)已就绪,不误伤自身写入。
    // owner-aware + 断连即清除:更新/卸载本产品只需停服务(内核随断连清除 SelfGuard)即可,无需先卸载驱动。
    {
        sendConfig(BLW_CMD_CLEAR_SELFGUARD);
        int guarded = 0;
        // 1) 安装目录(本产品全部可执行体 / Qt 运行库 / appsettings.json 等):去盘符的目录子串,
        //    覆盖目录下所有文件;兼容内核 \Device\HarddiskVolumeN\... 与 \??\C:\... 两种规范化形式。
        wchar_t selfBuf[BLW_MAX_PATH] = {};
        const DWORD selfN = ::GetModuleFileNameW(nullptr, selfBuf, BLW_MAX_PATH);
        if (selfN > 0) {
            const QString selfExe = QString::fromWCharArray(selfBuf, static_cast<int>(selfN));
            QString dir = driveAgnostic(QFileInfo(selfExe).absolutePath());  // 去盘符的安装目录
            if (!dir.endsWith(QLatin1Char('\\'))) dir += QLatin1Char('\\');  // 加尾分隔符,精确到目录内所有文件
            if (dir.size() >= 4) { sendConfig(BLW_CMD_ADD_SELFGUARD, dir); ++guarded; }
        }
        // 2) 数据目录 %ProgramData%\Bulwark\(规则/设置/隔离区/日志/历史/信誉缓存/基线 等):本产品持续
        //    写入,故必须用 owner-aware 的 SelfGuard(而非 FileHardBlock)才能既护住又不把自己锁在外面。
        {
            const QString pd = qEnvironmentVariable("ProgramData", QStringLiteral("C:\\ProgramData"));
            QString dataDir = driveAgnostic(pd);
            if (!dataDir.endsWith(QLatin1Char('\\'))) dataDir += QLatin1Char('\\');
            dataDir += QStringLiteral("Bulwark\\");
            if (dataDir.size() >= 4) { sendConfig(BLW_CMD_ADD_SELFGUARD, dataDir); ++guarded; }
        }
        // 3) 内核驱动文件(部署位置):精确子串,护住已部署驱动不被删/换(构建产物在别处,不误伤)。
        sendConfig(BLW_CMD_ADD_SELFGUARD, QStringLiteral("\\System32\\drivers\\Bulwark.sys"));
        ++guarded;
        log.info(QStringLiteral("自我保护(反勒索)· 完整内容:已把本产品足迹纳入内核 SelfGuard(%1 项;"
                                "仅放行本产品自身进程写入,其余进程写/删/改名一律拒绝)。").arg(guarded));
    }

    // 内存防护(反注入):登记目标进程名 + 现存匹配 PID。
    initMemoryProtection();

    // 文件行为遥测:开启内核对删除/重命名的观测上报(勒索时序聚合数据源)。
    sendConfig(BLW_CMD_SET_FILETELEMETRY, QString(), 1u);

    log.info(QStringLiteral("已向内核下发初始配置(受保护项 / 硬拦名单 / 命令行硬拦 / 黑名单 / 自保 PID / 文件遥测)。"));
}

void DriverEventSource::Impl::addMemProtPidToKernel(int pid) {
    if (pid <= 4) return;
    sendConfig(BLW_CMD_ADD_MEMPROT, QString(), static_cast<ULONG>(pid));
}

void DriverEventSource::Impl::addCredProtPidToKernel(int pid) {
    if (pid <= 4) return;
    sendConfig(BLW_CMD_ADD_CREDPROT, QString(), static_cast<ULONG>(pid));
}

void DriverEventSource::Impl::initMemoryProtection() {
    sendConfig(BLW_CMD_CLEAR_MEMPROT);
    sendConfig(BLW_CMD_CLEAR_CREDPROT);
    memProtNames.clear();
    for (const QString& t : memProtTargets) {
        const QString name = QFileInfo(t.trimmed()).fileName().toLower();
        if (!name.isEmpty()) memProtNames.insert(name);
    }
    // 凭据反转储目标(硬编码,始终启用,独立于用户可配的 MemoryProtectionTargets):lsass 是凭据
    // 存储,永远反转储 —— 在反注入基础上额外剥 PROCESS_VM_READ(挡 mimikatz 读 lsass 内存偷凭据)。
    // 即便用户清空了反注入名单,lsass 仍受凭据保护。
    credProtNames.clear();
    credProtNames.insert(QStringLiteral("lsass.exe"));

    // 枚举现存进程,按名匹配把命中 PID 下发内核(反注入 + 凭据反转储);新建进程由 readLoop 增量登记。
    // 注意:即使 memProtNames 为空也要枚举(credProtNames 恒非空,lsass 必须被登记)。
    int memCount = 0, credCount = 0;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        ZeroMemory(&pe, sizeof(pe));
        pe.dwSize = sizeof(pe);
        if (::Process32FirstW(snap, &pe)) {
            do {
                const QString exe = QString::fromWCharArray(pe.szExeFile).toLower();
                if (pe.th32ProcessID > 4) {
                    if (memProtNames.contains(exe)) {
                        addMemProtPidToKernel(static_cast<int>(pe.th32ProcessID));
                        ++memCount;
                    }
                    if (credProtNames.contains(exe)) {
                        addCredProtPidToKernel(static_cast<int>(pe.th32ProcessID));
                        ++credCount;
                    }
                }
            } while (::Process32NextW(snap, &pe));
        }
        ::CloseHandle(snap);
    }
    log.info(QStringLiteral("内存防护:反注入目标名 %1 个(现存 %2)、凭据反转储目标名 %3 个(现存 %4,含 lsass,额外剥 VM_READ)。")
                 .arg(memProtNames.size()).arg(memCount).arg(credProtNames.size()).arg(credCount));
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
            // 内存防护增量登记:命中目标名单的新进程立即获得反注入 / 凭据反转储保护。
            if (!imagePath.isEmpty()) {
                const QString name = QFileInfo(imagePath).fileName().toLower();
                if (!memProtNames.isEmpty() && memProtNames.contains(name))
                    addMemProtPidToKernel(e.actorPid);
                if (credProtNames.contains(name)) // lsass 罕见重启,但仍增量登记以防万一
                    addCredProtPidToKernel(e.actorPid);
            }
            break;

        case BlwEventFileDelete:
        case BlwEventFileRename:
            e.actorPath = actorPlaceholder;
            e.target = targetPath;
            // 这两类仅由内核 FileMonitor 的「命中硬拦名单 / 受保护路径」阻断分支上报——
            // 上报即代表内核已在动作前 STATUS_ACCESS_DENIED,故标记真前拦。
            e.kernelBlocked = true;
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
            // 注意:受保护注册表键(\Run/\Winlogon/\Services 等宽子串)在内核是【上报后放行】
            // (无条件拦截会打死系统),仅「注册表硬拦名单」才真前拦。二者事件类型相同,内核未
            // 附带 blocked 标志,故此处保守标记为「观测」(kernelBlocked 保持 false),由 Worker
            // 事后补偿处置(结束发起进程)并如实记录结果——绝不谎称"内核拦截"。
            e.detail = (ev.Type == BlwEventRegistrySetValue)
                ? QStringLiteral("内核监控 · 写入受保护注册表键(观测,事后处置)")
                : (ev.Type == BlwEventRegistryDeleteValue)
                      ? QStringLiteral("内核监控 · 删除受保护注册表值(观测,事后处置)")
                      : QStringLiteral("内核监控 · 删除受保护注册表键(观测,事后处置)");
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
            // 内核 ObCallback 已在句柄打开时剥离危险权限(结束/写内存/远程线程),攻击在发生前失效。
            e.kernelBlocked = true;
            e.detail = QStringLiteral("内核自保 · 已剥离对本软件的危险访问权限");
            break;

        case BlwEventMemoryProtect: {
            // 反注入:已剥离 actor 对高价值进程(ParentPid=受害者)的写内存/远程线程权限。
            const int victim = static_cast<int>(ev.ParentPid);
            const QString victimPath = resolvePidImagePath(ev.ParentPid);
            e.actorPath = actorPlaceholder;
            e.target = victimPath.isEmpty() ? QStringLiteral("PID %1").arg(victim) : victimPath;
            e.memoryInjection = true;
            // 内核 ObCallback 已在句柄打开时剥离「写内存/远程线程」权限,跨进程注入在发生前失效。
            e.kernelBlocked = true;
            e.detail = QStringLiteral("内核内存防护 · 已阻止跨进程注入 -> %1(PID %2)")
                           .arg(QFileInfo(e.target).fileName()).arg(victim);
            break;
        }

        case BlwEventNetworkConnect:
            e.actorPath = actorPlaceholder;
            e.target = QStringLiteral("%1:%2").arg(formatIpv4Host(ev.RemoteIpV4)).arg(ev.RemotePort);
            // 内核 WFP 仅对命中黑名单的外联上报本类事件,且已 FWP_ACTION_BLOCK 真前拦。
            e.kernelBlocked = true;
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
            // 命中内核「禁止加载」名单,执行/映射打开已被 STATUS_ACCESS_DENIED 前拦。
            e.kernelBlocked = true;
            e.detail = QStringLiteral("内核拦截 · 已阻止加载禁用模块 %1(白加黑防护)")
                           .arg(QFileInfo(targetPath).fileName());
            break;

        case BlwEventCommandBlocked: {
            //
            // 命令行硬拦:内核在进程创建回调里已把 CreationStatus 置为 STATUS_ACCESS_DENIED,
            // 危险命令【一次都没执行过】。内核填 ImagePath=被拒映像、TargetPath=被拦下的完整命令行。
            //
            // 主体刻意取【父进程】而不是被拒的新 PID:那个 PID 的进程根本没起来,按它解析映像路径
            // 只会拿到空值,甚至在 PID 被复用后错误地指向另一个无关进程。父进程才是真正的发起方,
            // 它仍在运行、可解析,也正是规则/评分应该盯住的对象。
            //
            const int initiator = static_cast<int>(ev.ParentPid);
            e.actorPid = initiator;
            e.parentPid = initiator;
            e.actorPath = initiator > 0 ? QStringLiteral("PID %1").arg(initiator)
                                        : QStringLiteral("(发起方未知)");
            // target 用【被拒映像的真实路径】而非命令行:它是一个真实存在的文件,规则的
            // TargetPattern(如 *\vssadmin.exe)可以匹配,签名/哈希富化也能正常工作。
            // 完整命令行放进专用的 commandLine 字段 —— 那才是它的语义位置。
            e.target = imagePath;
            e.commandLine = targetPath;
            e.kernelBlocked = true;   // 真·执行前阻断,绝不是事后补偿
            e.detail = QStringLiteral("内核拦截 · 已在执行前阻断危险命令:%1")
                           .arg(targetPath.isEmpty() ? QFileInfo(imagePath).fileName() : targetPath);
            break;
        }

        case BlwEventRegistryHiveDump:
            //
            // 注册表 hive 导出(ZwSaveKey / reg save)。内核【只在实际拒绝时】才产生本事件
            //(命中内置凭据 hive \REGISTRY\MACHINE\SAM|SECURITY,或命中注册表硬拦名单),
            // 故这里可以无歧义地标记真前拦 —— 这与普通注册表事件不同,那些是「上报后放行」。
            //
            e.actorPath = actorPlaceholder;
            e.target = targetPath;
            e.kernelBlocked = true;
            e.detail = QStringLiteral("内核拦截 · 已阻止导出注册表 hive %1(凭据窃取防护)")
                           .arg(targetPath);
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
    d_->cmdHardBlocks     = options.CommandHardBlocks;
    d_->cmdHardBaseline   = options.CommandHardBlockBaseline;
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
    d_->readThreadNative = static_cast<HANDLE>(d_->readThread.native_handle());
    drainTimer_->start();
    d_->log.info(QStringLiteral("内核驱动事件源已就绪(行为前拦截 + 用户态补偿)。"));
}

void DriverEventSource::stop() {
    if (drainTimer_)
        drainTimer_->stop();
    d_->running.store(false);

    // 读线程没起来(未连上驱动/协议不符),直接收尾即可。
    if (!d_->readThread.joinable()) {
        d_->closePort();
        QMutexLocker lock(&d_->queueMutex);
        d_->queue.clear();
        return;
    }

    // 读线程阻塞在【同步】的 FilterGetMessage 上。原先这里靠 closePort() 去"顺便"把它唤醒,
    // 那个假设是错的:Windows 并不保证关闭句柄能中止另一个线程里已挂起的同步 I/O。于是
    // join() 永久阻塞 —— 服务卡死在 STOP_PENDING,每次升级都得先 fltmc unload 才能停下来。
    // 顺带还有个更隐蔽的隐患:先关句柄、读线程却仍拿着那个句柄值在用,句柄号一旦被进程内
    // 其它 CreateFile 复用,读线程就会打到无关的内核对象上。
    //
    // 正确姿势:CancelSynchronousIo 定向取消该线程的同步 I/O,确认线程真的退出之后再关端口。
    // 线程可能还没进到 I/O(比如正在 buildAndQueue),故循环重试 —— 每轮之间读线程都会重新
    // 检查 running=false 并自行退出。
    const HANDLE th = d_->readThreadNative;
    bool exited = false;
    if (th != nullptr) {
        for (int i = 0; i < 60 && !exited; ++i) {          // 最多约 6 秒
            ::CancelSynchronousIo(th);                     // 未处于 I/O 时会失败,忽略即可
            exited = (::WaitForSingleObject(th, 100) == WAIT_OBJECT_0);
        }
    }

    if (!exited) {
        // 兜到这里说明取消不掉。绝不能让停机永久卡住(这是安全工具,用户必须随时能停/卸)。
        // 放弃该线程,并【故意保留】Impl 不析构 —— 否则被放弃的线程会访问已释放内存,
        // 端口句柄同理不能关。换一个干净的 Impl 让后续调用(析构 / isAvailable)安全。
        d_->log.warning(QStringLiteral("驱动读取线程未能在 6s 内退出:放弃等待以保证服务可正常停止"
                                       "(该线程及其状态被有意保留,随进程退出由系统回收)。"));
        d_->readThread.detach();
        (void)d_.release();
        d_ = std::make_unique<Impl>();
        return;
    }

    d_->readThread.join();      // 已确认退出,join 不会阻塞
    d_->readThreadNative = nullptr;
    d_->closePort();            // 线程已退出,此刻关句柄才是安全的
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

// 内核级足迹清理·读:分块请内核以「忽略共享访问检查」读出整文件(供用户态做可逆金库副本)。
// 旧驱动不支持该命令(FilterSendMessage 返回 STATUS_INVALID_PARAMETER)或打开/读取失败 -> 返回
// false,调用方回退到用户态清理。为防异常大文件占满内存,设 512MB 上限。
bool DriverEventSource::Impl::kernelReadFile(const QString& path, QByteArray& out) {
    out.clear();
    const QString p0 = path.trimmed();
    if (p0.isEmpty()) return false;

    constexpr int kChunk = 64 * 1024;
    constexpr qint64 kMaxTotal = 512LL * 1024 * 1024;
    QByteArray chunk(kChunk, Qt::Uninitialized);
    quint64 offset = 0;

    for (;;) {
        BLW_CONFIG_MESSAGE cfg;
        ZeroMemory(&cfg, sizeof(cfg));
        cfg.Command = BLW_CMD_QUARANTINE_READ;
        cfg.Pid = static_cast<ULONG>(offset & 0xFFFFFFFFull);        // 偏移低 32 位
        cfg.BlockIpV4 = static_cast<ULONG>((offset >> 32) & 0xFFFFFFFFull); // 偏移高 32 位
        QString p = p0;
        const int maxChars = BLW_MAX_PATH - 1;
        if (p.size() > maxChars) p = p.left(maxChars);
        cfg.PathLength = static_cast<USHORT>(p.size());
        const int copied = p.isEmpty() ? 0 : p.toWCharArray(cfg.Path);
        cfg.Path[copied] = L'\0';

        DWORD returned = 0;
        HRESULT hr;
        {
            QMutexLocker lock(&portMutex);
            if (port == nullptr) return false;
            hr = ::FilterSendMessage(port, &cfg, sizeof(cfg), chunk.data(), kChunk, &returned);
        }
        if (FAILED(hr)) return false;   // 旧驱动不支持 / 打开或读取失败 -> 回退
        if (returned == 0) break;       // 文件尾
        out.append(chunk.constData(), static_cast<int>(returned));
        offset += returned;
        if (static_cast<qint64>(out.size()) > kMaxTotal) return false; // 异常大,放弃
    }
    return true;
}

// 内核级足迹清理·删:请内核 POSIX 强制删除被占用/已映射文件。reply.Status==0 即删除成功。
bool DriverEventSource::Impl::kernelForceDelete(const QString& path) {
    const QString p0 = path.trimmed();
    if (p0.isEmpty()) return false;

    BLW_CONFIG_MESSAGE cfg;
    ZeroMemory(&cfg, sizeof(cfg));
    cfg.Command = BLW_CMD_FORCE_DELETE;
    QString p = p0;
    const int maxChars = BLW_MAX_PATH - 1;
    if (p.size() > maxChars) p = p.left(maxChars);
    cfg.PathLength = static_cast<USHORT>(p.size());
    const int copied = p.isEmpty() ? 0 : p.toWCharArray(cfg.Path);
    cfg.Path[copied] = L'\0';

    BLW_FILEOP_REPLY reply;
    ZeroMemory(&reply, sizeof(reply));
    DWORD returned = 0;
    HRESULT hr;
    {
        QMutexLocker lock(&portMutex);
        if (port == nullptr) return false;
        hr = ::FilterSendMessage(port, &cfg, sizeof(cfg), &reply, sizeof(reply), &returned);
    }
    if (FAILED(hr) || returned < sizeof(reply)) return false; // 旧驱动不支持 / 发送失败 -> 回退
    const bool ok = (reply.Status == 0);
    if (ok)
        log.warning(QStringLiteral("内核级强制删除成功(忽略共享/映像占用):%1").arg(p0));
    else
        log.info(QStringLiteral("内核级强制删除未成功(0x%1),将回退用户态处置:%2")
                     .arg(static_cast<quint32>(reply.Status), 8, 16, QLatin1Char('0')).arg(p0));
    return ok;
}

bool DriverEventSource::blockModuleLoad(const QString& modulePath) {
    const QString p = modulePath.trimmed();
    if (p.isEmpty() || !d_->connected.load())
        return false;
    d_->sendConfig(BLW_CMD_ADD_NOLOAD, p);
    d_->log.warning(QStringLiteral("已下发内核「禁止加载」名单:%1").arg(p));
    return true;
}

// 执行前拦截:把已确认恶意的可执行映像路径下发内核「禁止执行」名单(BLW_CMD_ADD_EXECBLOCK)。
// 进程创建回调命中该路径子串即内核本地 CreationStatus=STATUS_ACCESS_DENIED,样本根本无法启动。
// v8 驱动受理;旧驱动不支持该命令(sendConfig 内部 FilterSendMessage 返回失败,仅记日志,无害),
// 此时执行前拦截静默不可用,事后 kill 仍生效。未连接时安全 no-op 返回 false。
bool DriverEventSource::blockExecPath(const QString& imagePath) {
    const QString p = imagePath.trimmed();
    if (p.isEmpty() || !d_->connected.load())
        return false;
    d_->sendConfig(BLW_CMD_ADD_EXECBLOCK, p);
    d_->log.warning(QStringLiteral("已下发内核「禁止执行」名单(执行前拦截):%1").arg(p));
    return true;
}

// ---- 加白对账:整表清空 + 权威读回 -----------------------------------------
// 「禁止执行 / 禁止加载」两份名单在协议上只有 ADD 与 CLEAR,没有「删除单条」,也没有查询命令。
// 要解除某个已加白程序的钉死,只能「整表清空 -> 重下发其余条目」;而重下发前必须知道内核当前钉了
// 什么 —— 内核每次 ADD/CLEAR 后都会 BlwPersistListToRegistry 写回 \Services\Bulwark\Policy 下的
// REG_MULTI_SZ 值(见 Bulwark.Driver/Policy.c),那份就是权威基线,直接读它。内核对
// \Services\Bulwark 的注册表硬拦只拦【写】(RegistryMonitor 对 KernelMode 发起的写豁免,故内核能
// 写自己的 Policy 子键),用户态读取不受影响。
namespace {

// 驱动服务名与 DriverControl.cpp 的 kServiceName 一致(minifilter 服务名 "Bulwark")。
constexpr wchar_t kPolicyKeyPath[] =
    L"SYSTEM\\CurrentControlSet\\Services\\Bulwark\\Policy";

// 读取一个 REG_MULTI_SZ 值,拆成字符串列表(空项跳过)。值不存在 / 类型不符时返回空表。
QStringList readMultiSz(const wchar_t* valueName) {
    DWORD type = 0, bytes = 0;
    // 先问长度。RRF_RT_REG_MULTI_SZ 限定类型,避免把别的类型误当多字符串解析。
    LSTATUS st = ::RegGetValueW(HKEY_LOCAL_MACHINE, kPolicyKeyPath, valueName,
                                RRF_RT_REG_MULTI_SZ, &type, nullptr, &bytes);
    if (st != ERROR_SUCCESS || bytes < sizeof(wchar_t) || bytes > 0x100000)
        return {};
    QVector<wchar_t> buf(static_cast<int>(bytes / sizeof(wchar_t)) + 2, L'\0');
    st = ::RegGetValueW(HKEY_LOCAL_MACHINE, kPolicyKeyPath, valueName,
                        RRF_RT_REG_MULTI_SZ, &type, buf.data(), &bytes);
    if (st != ERROR_SUCCESS)
        return {};
    QStringList out;
    const wchar_t* p = buf.constData();
    const wchar_t* end = buf.constData() + buf.size();
    while (p < end && *p != L'\0') {
        const QString s = QString::fromWCharArray(p);
        if (!s.trimmed().isEmpty())
            out << s.trimmed();
        p += s.size() + 1; // 跳过本项与其结尾 NUL
    }
    return out;
}

} // namespace

bool DriverEventSource::clearExecBlock() {
    if (!d_->connected.load())
        return false;
    d_->sendConfig(BLW_CMD_CLEAR_EXECBLOCK, QString());
    d_->log.warning(QStringLiteral("已请求内核清空「禁止执行」名单(加白对账,随后重下发未加白条目)。"));
    return true;
}

bool DriverEventSource::clearModuleNoLoad() {
    if (!d_->connected.load())
        return false;
    d_->sendConfig(BLW_CMD_CLEAR_NOLOAD, QString());
    d_->log.warning(QStringLiteral("已请求内核清空「禁止加载」名单(加白对账,随后重下发未加白条目)。"));
    return true;
}

bool DriverEventSource::clearBannedProcesses() {
    if (!d_->connected.load())
        return false;
    d_->sendConfig(BLW_CMD_CLEAR_BANNED, QString());
    d_->log.warning(QStringLiteral("已请求内核清空「已封禁主体」PID 集(加白对账:解除对已加白进程的全维拒绝)。"));
    return true;
}

QStringList DriverEventSource::persistedExecBlockList() const {
    return readMultiSz(L"FileExecBlock");
}

QStringList DriverEventSource::persistedModuleNoLoadList() const {
    return readMultiSz(L"FileNoLoad");
}

// 持久化反重建:把刚清理掉的恶意自启动项(注册表「键\值」子串)下发内核注册表硬拦(BLW_CMD_ADD_REGHARD)。
// 内核对该子串按「键」及「键\值」两种形式匹配,命中即本地拒绝写入 —— 恶意软件无法立刻重建刚被清掉的
// 持久化。子串为 controlset/hive 无关的尾段(如 SOFTWARE\...\Run\Evil、\Services\Evil\),精确到恶意
// 项本身,不影响其它合法自启动。未连接时安全 no-op 返回 false。
bool DriverEventSource::hardenRegistryKey(const QString& keyOrValue) {
    const QString k = keyOrValue.trimmed();
    if (k.isEmpty() || !d_->connected.load())
        return false;
    d_->sendConfig(BLW_CMD_ADD_REGHARD, k);
    d_->log.warning(QStringLiteral("已下发内核注册表硬拦(持久化反重建):%1").arg(k));
    return true;
}

bool DriverEventSource::readLockedFile(const QString& path, QByteArray& out) {
    if (!d_->connected.load())
        return false;
    return d_->kernelReadFile(path, out);
}

bool DriverEventSource::forceDeleteFile(const QString& path) {
    if (!d_->connected.load())
        return false;
    return d_->kernelForceDelete(path);
}

// 驱动级结束进程:下发 BLW_CMD_KILL_PID,内核 ZwTerminateProcess 结束目标(带内核护栏)。
// v7 驱动处理该命令回 STATUS_SUCCESS(SUCCEEDED);旧驱动回 STATUS_INVALID_PARAMETER(FAILED),
// 据此返回 false 让调用方回退到用户态结束进程。fire-and-forget,不写 OutputBuffer。
bool DriverEventSource::killProcess(int pid) {
    if (pid <= 4 || !d_->connected.load())
        return false;
    BLW_CONFIG_MESSAGE cfg;
    ZeroMemory(&cfg, sizeof(cfg));
    cfg.Command = BLW_CMD_KILL_PID;
    cfg.Pid = static_cast<ULONG>(pid);
    DWORD returned = 0;
    HRESULT hr;
    {
        QMutexLocker lock(&d_->portMutex);
        if (d_->port == nullptr) return false;
        hr = ::FilterSendMessage(d_->port, &cfg, sizeof(cfg), nullptr, 0, &returned);
    }
    if (SUCCEEDED(hr)) {
        d_->log.info(QStringLiteral("已请求内核级结束进程 PID=%1(驱动级 ZwTerminateProcess)。").arg(pid));
        return true;
    }
    return false;
}

// 封禁主体:下发 BLW_CMD_ADD_BANNED —— 内核对该 PID 的任何文件写/删/改、注册表写、网络外联、
// 创建子进程一律 STATUS_ACCESS_DENIED。与 killProcess 配对:ban 先断其一切行为(不依赖杀进程的
// 时机),kill 再收拾进程本身。旧驱动不认此命令时 sendConfig 内部 FilterSendMessage 失败仅记日志、
// 无害降级(执行前拦截 + 事后 kill 仍在)。未连接时安全 no-op 返回 false。
bool DriverEventSource::banProcess(int pid) {
    if (pid <= 4 || !d_->connected.load())
        return false;
    d_->sendConfig(BLW_CMD_ADD_BANNED, QString(), static_cast<ULONG>(pid));
    d_->log.warning(QStringLiteral("已下发内核封禁主体(情报确认恶意,全维拒绝其行为):PID=%1").arg(pid));
    return true;
}

void DriverEventSource::drain() {
    // 高并发拦截风暴下(勒索批量改文件 / 进程爆发),队列一次可积压数千事件,而每个事件在
    // Worker::onEvent 里要做签名校验 / SHA-256 / 祖先链富化 + IPC + 落盘。若一次性 emit 整批,
    // 服务主线程会被同步打爆数秒(表现为「卡死」),IPC/定时器/裁决全部停摆。故每个 tick 只搬运
    // 有上限的一批,emit 完若仍有积压就立刻(下一轮事件循环)再排一批 —— 把「一次性卡死」变成
    // 「稳定流式处理」,期间事件循环持续得到服务(IPC 心跳、裁决回复、其它定时器均不受阻)。
    constexpr int kMaxPerDrain = 32;
    QVector<bulwark::SecurityEvent> batch;
    bool more = false;
    {
        QMutexLocker lock(&d_->queueMutex);
        if (d_->queue.isEmpty())
            return;
        const int n = qMin(d_->queue.size(), kMaxPerDrain);
        batch = d_->queue.mid(0, n);
        d_->queue.remove(0, n);
        more = !d_->queue.isEmpty();
    }
    for (const auto& e : batch)
        emit eventProduced(e);
    if (more) // 还有积压:让出事件循环后立即再排下一批(既快速清空又不阻塞)。
        QTimer::singleShot(0, this, &DriverEventSource::drain);
}

} // namespace bulwark::service
