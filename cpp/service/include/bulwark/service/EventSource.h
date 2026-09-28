 #pragma once
#include <QObject>
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::service {

// 事件源抽象:持续产出安全事件(Qt 信号驱动,无需后台线程)。
// 对应 .NET Monitoring/IEventSource.cs。
class EventSource : public QObject {
    Q_OBJECT
public:
    explicit EventSource(QObject* parent = nullptr) : QObject(parent) {}
    ~EventSource() override = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    // 源是否成功就绪(如 ETW 实时会话需管理员;失败时返回 false,服务其余部分照常)。
    virtual bool isAvailable() const { return true; }

    // ---- 同步裁决回写 ----------------------------------------------------------
    //
    // 【这段注释以前描述的是一个已经不存在的模型,必须纠正】
    //
    // 原文写的是「内核驱动在动作发生前同步等待用户态裁决:引擎判定后必须把 Allow/Block 回写
    // 内核(FilterReplyMessage),否则内核超时兜底」。当前(协议 v9)的驱动【不是这样】:
    //   · 内核的 BlwReportEvent 用 FltSendMessage(..., timeout = 0) 且【不传回复缓冲】;
    //   · BlwMessageNotify 里没有任何 BLW_VERDICT_REPLY 的处理分支;
    //   · 驱动源自己也承认「当前驱动为 fire-and-forget,回写为尽力而为」
    //     (DriverEventSource.cpp 的 needsVerdict 注释)。
    // 也就是说 FilterReplyMessage 恒失败,回写没有任何效果。
    //
    // 由此必须明确的架构事实:【用户态规则引擎没有行为前拦截能力】。引擎产出的每一个 Block
    // 都是事后补偿(结束进程树 / 加内核禁运名单)。真正的 pre-action 阻断只来自内核自持的
    // 那几份本地名单(FileHardBlock / SelfGuard / FileNoLoad / FileExecBlock / CmdHardBlock /
    // RegHardBlock)、WFP 黑名单、以及 ObCallbacks 的权限剥离。
    //
    // 这个接口保留下来(而不是删掉):若将来重新引入「内核等待裁决」的通道,这里就是接入点。
    // 但默认必须是 false —— 让每条文件/注册表事件都去做一次注定失败的 FilterReplyMessage
    // (还要取一次端口互斥),是纯粹的浪费,也会让人误以为拦截是同步生效的。
    virtual bool wantsVerdict() const { return false; }
    virtual void submitVerdict(const bulwark::SecurityEvent& /*e*/,
                               bulwark::VerdictAction /*action*/) {}

    // 把已确认恶意的侧载 DLL/EXE 加入内核「禁止加载」名单(命中即内核前拦执行/映射打开)。
    // 仅内核驱动源真正实现;纯观测源保持空实现返回 false。用于镜像加载 Block 的真实前拦(下次)。
    virtual bool blockModuleLoad(const QString& /*modulePath*/) { return false; }

    // 把已确认恶意的可执行映像加入内核「禁止执行」名单(进程创建命中即内核前拦,样本无法启动)。
    // 仅内核驱动源真正实现;纯观测源保持空实现返回 false。补「事后 kill 让样本先跑几十毫秒」的短板:
    // kill 收拾正在跑的实例,exec-block 挡住其再次(及重启后)启动。返回 true 表示内核已受理该命令。
    virtual bool blockExecPath(const QString& /*imagePath*/) { return false; }

    // 把刚清理掉的恶意自启动项(注册表「键\值」子串,controlset/hive 无关)加入内核注册表硬拦,
    // 使恶意软件【无法立刻重建】该持久化 —— 补上「清理 → 守护进程秒级重写」的竞态窗口。
    // 仅内核驱动源真正实现;纯观测源保持空实现返回 false。返回 true 表示内核已受理该命令。
    virtual bool hardenRegistryKey(const QString& /*keyOrValue*/) { return false; }

    // 驱动级结束进程(内核 ZwTerminateProcess,比用户态 TerminateProcess 更强、难被反杀)。
    // 仅内核驱动源真正实现;纯观测源保持空实现返回 false(调用方据此回退到用户态结束进程)。
    // 返回 true 表示内核已【受理】该结束命令(v7 驱动);false 表示未连接 / 旧驱动不支持。
    virtual bool killProcess(int /*pid*/) { return false; }
    // 封禁主体:情报/规则确认恶意后,把该 PID 下发内核「已封禁主体」集 —— 其任何文件/注册表/
    // 网络/子进程行为此后被内核各回调一律拒绝(不依赖结束进程的时机)。默认 no-op(非驱动源)。
    virtual bool banProcess(int /*pid*/) { return false; }

    // ---- 加白对账用:内核「禁止执行 / 禁止加载」名单的整表清空 + 权威读回 ----
    // 这两份名单由内核写回注册表持久化、跨重启续拦,且只有「追加 / 整表清空」没有「删除单条」。
    // 因此解除某个已加白程序的钉死只能走「清空 -> 重下发其余条目」,而重下发前必须知道内核当前
    // 到底钉了什么 —— 协议没有查询命令,故改为直接读内核写的注册表基线(只读,不受自保写拦影响)。
    // 纯观测源无内核名单,保持空实现。
    virtual bool clearExecBlock() { return false; }
    virtual bool clearModuleNoLoad() { return false; }
    // 清空内核「已封禁主体」PID 集。killMalicious 每次都会先 banProcess(pid) —— 内核此后拒绝该 PID
    // 的一切文件/注册表/网络/子进程行为。加白撤不掉它,表现为「进程活着但什么都干不了」。PID 本身
    // 是短命的(进程退出即无意义),故整表清空代价极低:真正恶意的主体在下一个动作就会被重新封禁。
    virtual bool clearBannedProcesses() { return false; }
    virtual QStringList persistedExecBlockList() const { return {}; }
    virtual QStringList persistedModuleNoLoadList() const { return {}; }

    // 内存防护(反注入 + 凭据反转储)总开关。关闭时内核两份目标 PID 集被清空、此后不再登记,
    // 防护【真正停止】;重新开启时按当前目标名单重新登记现存进程。
    // 仅内核驱动源真正实现;纯观测源无内核名单,保持空实现。
    //
    // 之所以要有这个接口:RuntimeSettings::memoryProtectionEnabled 此前在服务端从未被读取,
    // 设置页的开关与仪表盘的维度指示灯都只是摆设 —— 真实反注入完全由 appsettings.json 的
    // MemoryProtectionTargets 驱动,用户关掉开关后防护照旧生效而指示灯变灰,显示与实际相反。
    virtual void setMemoryProtectionEnabled(bool /*on*/) {}

signals:
    void eventProduced(const bulwark::SecurityEvent& e);
};

} // namespace bulwark::service
