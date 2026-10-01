#include "bulwark/service/EventSourceCoordinator.h"
#include "bulwark/service/DriverEventSource.h"
#include "bulwark/service/DriverControl.h"
#include "bulwark/service/UserModeBehaviorSource.h"
#include "bulwark/service/UserModeExecBlock.h"
#include "bulwark/service/UserModeNetworkBlock.h"

#include "bulwark/models/Enums.h"

#include <QTimer>

namespace bulwark::service {

EventSourceCoordinator::EventSourceCoordinator(EventSource* base, UserModeBehaviorSource* behavior,
                                               const BulwarkOptions& options, QObject* parent)
    : EventSource(parent), base_(base), behavior_(behavior), options_(options) {
    if (base_)
        connect(base_, &EventSource::eventProduced, this, &EventSourceCoordinator::onBaseEvent);
    if (behavior_)
        connect(behavior_, &EventSource::eventProduced, this, &EventSourceCoordinator::onBehaviorEvent);
    kernelRetry_ = new QTimer(this);
    kernelRetry_->setInterval(10000); // 内核连不上时每 10s 自愈重试
    connect(kernelRetry_, &QTimer::timeout, this, &EventSourceCoordinator::onKernelRetry);
    // 用户态执行前拦截:总是建好待用(驱动随时可能掉线,那一刻必须已经有地方下发)。
    // 部署方显式关掉时保持 nullptr —— 所有相关调用退回改动前的「返回 false / 空表」。
    if (options_.UserModeExecBlockEnabled)
        execBlock_ = new UserModeExecBlock(options_.UserModeExecBlockMax, this);
    if (options_.UserModeNetworkBlockEnabled)
        netBlock_ = new UserModeNetworkBlock(options_.UserModeNetworkBlockMax);
}

EventSourceCoordinator::~EventSourceCoordinator() {
    stop();
    // 非 QObject,没有父子关系代管。析构即关 WFP 引擎句柄 -> 动态会话的过滤器随之全部消失。
    delete netBlock_;
    netBlock_ = nullptr;
}

void EventSourceCoordinator::start() {
    if (started_) return;
    started_ = true;
    if (base_) base_->start();
    if (behavior_) behavior_->start();
    // 重放上次的用户态禁止执行名单。句柄随进程消失,故【必须】在启动时重新加锁;replay 内部
    // 会把「服务未运行期间这些文件可以被执行」这个空窗如实写进日志。
    if (execBlock_) execBlock_->replay();

    //
    // 用户态出站封禁:开引擎 -> 按【当前配置】下发出站黑名单。
    //
    // 修掉一个真实缺口:BlockedRemoteEndpoints 原先【只】在 DriverEventSource 的
    // pushInitialConfig 里被下发,也就是说 EventSource=Wmi 或驱动掉线时,部署方在配置里写的
    // 出站黑名单是完全无效的 —— 配了等于没配,而且没有任何提示。现在无论有没有驱动都生效。
    //
    // 刻意没有「重放上次名单」这一步:配置就是每次启动的唯一权威。初版做过落盘清单 + 重放,
    // 那会造出一个撤不掉的封禁 —— 部署方从配置里删掉某地址、重启,重放却照旧把它封上。
    // 详见 UserModeNetworkBlock.h 里「纯会话内,配置是唯一权威」那一节。
    //
    pushConfiguredIpBlocks();
    // 内核开关由 main 在应用初始设置时调用 setKernelEnabled(...)。
}

// 按【当前配置】重建用户态出站黑名单。抽成独立函数是因为它有两个调用点:首次 start(),
// 以及「退出界面即停止防护」待机后的唤醒 —— 待机时过滤器被 clearAll() 清掉了,唤醒必须原样
// 重建。两处若各写一遍,迟早只改一处。
int EventSourceCoordinator::pushConfiguredIpBlocks() {
    if (!netBlock_ || !netBlock_->open())
        return 0;
    int pushed = 0, refused = 0;
    for (const QString& raw : options_.BlockedRemoteEndpoints) {
        const QString s = raw.trimmed();
        if (s.isEmpty())
            continue;
        // "ip" 或 "ip:port"(与内核侧 parseIpEndpoint 同一口径)。
        QString ip = s;
        quint16 port = 0;
        const int colon = s.lastIndexOf(QLatin1Char(':'));
        if (colon > 0) {
            bool ok = false;
            const int p = s.mid(colon + 1).toInt(&ok);
            if (ok && p > 0 && p <= 65535) {
                ip = s.left(colon);
                port = static_cast<quint16>(p);
            }
        }
        if (netBlock_->blockIp(ip, port)) ++pushed; else ++refused;
    }
    if (pushed > 0 || refused > 0) {
        log_.info(QStringLiteral("用户态出站黑名单(appsettings BlockedRemoteEndpoints):已生效 %1 条%2。"
                                 "此前该配置仅在内核驱动连上时才被下发,无驱动时形同未配。")
                      .arg(pushed)
                      .arg(refused > 0 ? QStringLiteral(",被拒 %1 条(不可整段封禁的地址,原因见逐条警告)")
                                             .arg(refused)
                                       : QString()));
    }
    return pushed;
}

void EventSourceCoordinator::stop() {
    if (kernelRetry_) kernelRetry_->stop();
    if (driver_) driver_->stop();
    if (behavior_) behavior_->stop();
    if (base_) base_->stop();
    started_ = false;
}

bool EventSourceCoordinator::isAvailable() const {
    return base_ && base_->isAvailable();
}

bool EventSourceCoordinator::kernelConnected() const {
    return driver_ && driver_->isConnected();
}

bool EventSourceCoordinator::kernelProtocolMismatch() const {
    return driver_ && driver_->protocolMismatch();
}

QStringList EventSourceCoordinator::kernelMissingCapabilities() const {
    return driver_ ? driver_->missingCapabilities() : QStringList{};
}

// ---- 2.5 显式防护能力集 ----------------------------------------------------------
//
// 每一项的 inForce 都从【运行时状态】导出,不从配置意图导出:配置说「启用」而对象没建起来
// (例如部署方把 UserModeExecBlockEnabled 置了 false)时,这里必须报 false。
QVector<EventSourceCoordinator::ProtectionCapability>
EventSourceCoordinator::protectionCapabilities() const {
    //
    // 待机中(「退出界面即停止防护」且界面不在跑):每一维都不成立。
    //
    // 这一句不是保险,是必需的。下面 umExec / umNet 判的是【对象存不存在】,那几条「结束进程 /
    // 冻结 / 断子 / 读删被占用文件」更是直接写死 true —— 待机时对象都还在,于是这张表会照报
    // 「用户态拦截生效」,而实际上句柄已放开、过滤器已清、事件源已停。那就又造出一次
    // 「把没有防护说成有防护」,恰恰是这张表当初被引入要解决的问题。
    //
    const bool sus = suspended_;
    const bool k = kernelConnected();
    const QStringList missing = kernelMissingCapabilities();
    // 驱动在线但版本偏旧时,某些维度会被它的 default 分支静默拒掉 —— 那种维度不能算成立。
    const auto kernelHas = [&k, &missing](const QString& capKey) {
        if (!k)
            return false;
        for (const QString& m : missing) {
            if (m.contains(capKey, Qt::CaseInsensitive))
                return false;
        }
        return true;
    };
    const bool umExec = (execBlock_ != nullptr) && !sus;
    const bool umNet = (netBlock_ != nullptr) && !sus;

    QVector<ProtectionCapability> caps;
    const auto add = [&caps](const QString& dim, bool on, const QString& who,
                            const QString& limit = QString()) {
        ProtectionCapability c;
        c.dimension = dim;
        c.inForce = on;
        c.provider = on ? who : QStringLiteral("无");
        c.limit = limit;
        caps.push_back(c);
    };

    // 进程【创建前】阻断:只有内核回调能在映像跑起来之前否掉它。用户态拿到 ETW 事件时
    // 进程已经在跑了 —— 这一条刻意不让用户态冒充,否则整个「无驱动到底差什么」就说不清了。
    add(QStringLiteral("进程创建前阻断"), kernelHas(QStringLiteral("进程")),
        QStringLiteral("内核驱动"),
        k ? QString() : QStringLiteral("无驱动时不存在:用户态最早只能在进程已启动后介入"));
    // 再次启动阻断:独占句柄让同一路径起不来,是对上一条的部分补偿(不是等价物)。
    add(QStringLiteral("按路径阻断再次启动"), umExec || kernelHas(QStringLiteral("执行")),
        k ? QStringLiteral("内核驱动") : QStringLiteral("用户态"),
        (!k && umExec) ? QStringLiteral("独占句柄,不跨重启;按路径不按内容") : QString());
    add(QStringLiteral("模块加载阻断"), umExec || kernelHas(QStringLiteral("加载")),
        k ? QStringLiteral("内核驱动") : QStringLiteral("用户态"),
        (!k && umExec) ? QStringLiteral("独占句柄,不跨重启") : QString());
    add(QStringLiteral("出站连接阻断"), umNet || kernelHas(QStringLiteral("网络")),
        k ? QStringLiteral("内核驱动") : QStringLiteral("用户态"),
        (!k && umNet) ? QStringLiteral("WFP 动态会话,不跨重启;仅 IPv4") : QString());
    add(QStringLiteral("命令行硬拦"), kernelHas(QStringLiteral("命令行")),
        QStringLiteral("内核驱动"),
        k ? QString() : QStringLiteral("无驱动时不存在:命令行要等进程起来后读 PEB,"
                                       "与毫秒级退出的 LOLBin 赛跑"));
    // 注册表【写入前】阻断仍然只有内核做得到。下面单列一行回滚,因为那是完全不同的东西:
    // 一个是写不进去,一个是写进去了再被还原。把后者算进前者会把能力说高。
    add(QStringLiteral("注册表写入阻断(写入前)"), kernelHas(QStringLiteral("注册表")),
        QStringLiteral("内核驱动"),
        k ? QString() : QStringLiteral("无驱动时不存在 —— 替代手段是下一行的即时回滚,"
                                       "但那是事后还原,不是阻断"));
    add(QStringLiteral("注册表持久化即时回滚"), regRollbackActive_ && !sus,
        QStringLiteral("用户态"),
        QStringLiteral("RegNotifyChangeKeyValue 唤醒后还原被改写的自启动项;"
                       "【事后还原不是阻断】,恶意软件仍能写进去,只是会被立刻改回来。"
                       "不跨重启;只覆盖已加载的用户 hive;指向已加白程序的改动不动。"));
    // 待机时这一位报假指的是「不会再给新文件加 ACE」;【已经加上的 ACE 仍然在生效】——
    // 待机不回滚已落地的东西(见 setSuspended)。这点由 protectionSummary 的待机文案说明。
    add(QStringLiteral("跨重启的执行阻断"), crossRebootDenyOn_ && !sus,
        QStringLiteral("用户态"),
        QStringLiteral("文件 DACL 上的 DENY Everyone:FILE_EXECUTE,开机即生效 —— "
                       "独占句柄「不跨重启」的补位。按文件不按路径:复制一份即可绕过。"
                       "本位为真只表示该功能已启用,不表示当前有条目生效。"));
    add(QStringLiteral("结束进程"), !sus,
        k ? QStringLiteral("内核驱动 + 用户态") : QStringLiteral("用户态"),
        k ? QString() : QStringLiteral("TerminateProcess,可能被高级样本对抗"));
    // 下面两条是阶段 2 新增的,也是无驱动时「杀不掉」情形下唯一还成立的处置。
    add(QStringLiteral("冻结进程(可恢复)"), !sus, QStringLiteral("用户态"),
        QStringLiteral("挂起线程;不跨重启;已做过的动作不回滚"));
    add(QStringLiteral("阻断其创建子进程"), !sus, QStringLiteral("用户态"),
        QStringLiteral("Job 配额;【不可撤销】,仅用于即将结束该进程时"));
    add(QStringLiteral("读取/删除被占用文件"), !sus,
        k ? QStringLiteral("内核驱动 + 用户态") : QStringLiteral("用户态"),
        k ? QString()
          : QStringLiteral("备份特权只能绕 DACL 拒绝(错误 5),绕不过共享冲突(错误 32)"));
    add(QStringLiteral("自身进程/文件自保护"), kernelHas(QStringLiteral("自保")),
        QStringLiteral("内核驱动"),
        k ? QString() : QStringLiteral("无驱动时不存在:管理员权限的样本可停服务、删文件。"
                                       "阶段 3 的服务 DACL 收紧只是把门槛从「任意进程」提到"
                                       "「需要管理员」,且需用户显式确认,不是自保护的等价物"));
    return caps;
}

void EventSourceCoordinator::setHardeningState(bool registryRollbackActive,
                                              bool crossRebootExecDeny) {
    regRollbackActive_ = registryRollbackActive;
    crossRebootDenyOn_ = crossRebootExecDeny;
}

QString EventSourceCoordinator::protectionTier() const {
    // 待机自成一档。它既不是 ObserveOnly(那一档至少还在观测、还在落事件)也不是任何程度的
    // 防护 —— 按 ObserveOnly 记档会让审计里「待机」和「有观测无拦截」长得一样。
    if (suspended_)
        return QStringLiteral("Standby");
    if (kernelConnected())
        return QStringLiteral("Driver");
    // 三档而不是两档:有用户态拦截原语与只有观测,是完全不同的处境。
    if (execBlock_ || netBlock_)
        return QStringLiteral("UserModeEnforcement");
    return QStringLiteral("ObserveOnly");
}

QString EventSourceCoordinator::protectionSummary() const {
    if (suspended_) {
        // 待机是一句完整的结论,不走下面那套「生效 N/M 个维度」—— 分母里逐条写「未生效」
        // 只是把同一件事说了十几遍,反而埋掉唯一要紧的那句:此刻没有防护。
        return QStringLiteral("待机中(界面已退出)· 本软件此刻不提供任何防护:事件源已停、"
                              "内核驱动已卸载、用户态拦截已放开。"
                              "已隔离的文件不会被放回,已施加的「拒绝执行」ACE 仍然拦着 —— "
                              "待机只是不再做新的处置,不撤销做过的。打开界面即恢复。");
    }
    const QVector<ProtectionCapability> caps = protectionCapabilities();
    QStringList on, off;
    for (const ProtectionCapability& c : caps) {
        if (c.inForce)
            on << c.dimension;
        else
            off << c.dimension;
    }
    const QString tier = protectionTier();
    QString head;
    if (tier == QLatin1String("Driver"))
        head = QStringLiteral("内核驱动已连接");
    else if (tier == QLatin1String("UserModeEnforcement"))
        head = QStringLiteral("用户态防护(内核驱动未启用/掉线)");
    else
        head = QStringLiteral("仅观测(用户态拦截原语也已关闭)");
    // 「未生效」那一半必须一并说出来 —— 只报生效项就是在把降级说成正常。
    return QStringLiteral("%1 · 生效 %2/%3 个维度:%4%5")
        .arg(head)
        .arg(on.size())
        .arg(caps.size())
        .arg(on.join(QStringLiteral("、")))
        .arg(off.isEmpty() ? QString()
                           : QStringLiteral(";未生效:") + off.join(QStringLiteral("、")));
}

void EventSourceCoordinator::submitVerdict(const bulwark::SecurityEvent& e, bulwark::VerdictAction action) {
    // 仅内核源支持「行为前」回写;其余源为观测,submitVerdict 对它们无意义。内核源的
    // submitVerdict 内部会判断该事件是否为其追踪的等待类事件(否则 no-op)。
    if (driver_ && driver_->wantsVerdict())
        driver_->submitVerdict(e, action);
}

void EventSourceCoordinator::setKernelEnabled(bool on) {
    //
    // 待机期间只记下意图,绝不真的去装/卸驱动。
    //
    // 必须有这道守卫:main 的 settingsUpdated 每次都会无条件调一次
    // setKernelEnabled(settings.kernelDriverEnabled)。没有它,用户在待机窗口里改任何一项设置
    // (哪怕是某个 API Key)都会把 Bulwark.sys 装回来,而 suspended_ 仍是 true —— 于是
    // 「界面已退出、不该有防护」和「驱动在载、正在拦」同时成立,状态就分裂了,
    // 而且这种分裂只在日志里看得出来,用户侧表现成「关了还在拦」,正是本次要修的那个现象。
    //
    // 待机 / 唤醒自己走 applyKernelEnabled(),不经过这道守卫。
    //
    if (suspended_) {
        kernelWantedBeforeSuspend_ = on;
        log_.info(QStringLiteral("待机中:内核驱动开关的改动(%1)已记下,唤醒时生效。")
                      .arg(on ? QStringLiteral("启用") : QStringLiteral("停用")));
        return;
    }
    applyKernelEnabled(on);
}

void EventSourceCoordinator::applyKernelEnabled(bool on) {
    if (on == kernelEnabled_) return;
    kernelEnabled_ = on;
    if (on) {
        if (!driver_) {
            driver_ = new DriverEventSource(options_, this);
            connect(driver_, &EventSource::eventProduced, this, &EventSourceCoordinator::onDriverEvent);
        }
        DriverControl::ensureLoaded();     // 按需注册 + 加载 Bulwark.sys(幂等)
        // 内存防护状态必须在 start() 【之前】补给内核源:start() 内的 pushInitialConfig 会调
        // initMemoryProtection,那时才读这个标志。放到 start() 之后就会先按默认(开)登记一遍,
        // 用户明明关着开关却仍被登记一次。
        driver_->setMemoryProtectionEnabled(memProtEnabled_);
        driver_->start();                  // 连接 + 握手(同步)
        for (int pid : protectedPids_)     // 补发受保护 UI PID
            driver_->addProtectedPid(pid);
        // 无论首次是否连上,都把看护定时器开起来(见 onKernelRetry 的说明):
        // 连上了它负责发现"中途掉线",没连上它负责持续重试。
        kernelRetry_->start();
        if (driver_->isAvailable()) {
            attachFailed_ = false;
            log_.info(QStringLiteral("内核驱动事件源已连接(行为前拦截 + 用户态补偿)。"));
            notifyKernelState(true, QStringLiteral("内核驱动已连接 · 行为前拦截生效"));
        } else {
            attachFailed_ = true;
            log_.warning(QStringLiteral("内核驱动暂不可用,已降级为用户态观测,后台将持续重试。"));
            notifyKernelState(false, QStringLiteral("内核驱动不可用(首次连接失败)· 已降级为"
                                                   "用户态观测,后台每 10 秒重试"));
        }
    } else {
        kernelRetry_->stop();
        attachFailed_ = false;
        if (driver_) driver_->stop();      // 释放通信端口(便于驱动卸载/重启)
        log_.info(QStringLiteral("内核驱动事件源已停用(切回用户态观测)。"));
        // 这一条是【用户主动关的】,不是故障。审计里必须能区分二者:否则复盘时看到一条
        // 「没有内核防护」无法判断是被攻击卸载的还是运维自己关的。
        // 待机(界面退出)与「用户在设置里关掉内核驱动」也必须分开说:前者是整套防护都停了,
        // 后者只是少了内核这一层、用户态照旧在拦 —— 合成一句话会让复盘时分不清那段时间有没有防护。
        notifyKernelState(false,
                          suspended_
                              ? QStringLiteral("已进入待机(界面已退出)· 内核驱动已卸载,"
                                               "本软件此刻不提供任何防护")
                              : QStringLiteral("内核驱动已按用户设置停用 · 切回用户态观测"));
    }
}

//
// 待机 / 唤醒(「退出界面即停止防护」)。
//
// 顺序是刻意的,每一步都有理由:
//   待机:先关通信端口(内核据此清掉自保护足迹 BlwClearSelfGuard,不清就卸不动)-> 再卸驱动 ->
//         再停用户态各源与拦截原语。驱动先走,是因为它是唯一「服务死了也照样拦」的那一层,
//         留着它就等于没停。
//   唤醒:反过来,用户态先就位,最后才把驱动装回来 —— 驱动一连上就会开始上报事件,那时
//         接收端必须已经在跑。
//
// 【不回滚已经落地的东西】:已加的「拒绝执行」ACE、已隔离的文件、内核写进注册表的基线都保持
// 原样(基线要等驱动下次加载才重新生效)。待机的语义是「不再做新的事」,不是「撤销做过的事」——
// 后者会把一次误开关变成一次不可逆的防护清空。
//
void EventSourceCoordinator::setSuspended(bool on) {
    if (suspended_ == on)
        return;
    suspended_ = on;

    if (on) {
        kernelWantedBeforeSuspend_ = kernelEnabled_;
        applyKernelEnabled(false);  // 停重试表 + 关端口(内部会按 suspended_ 派发待机专用的状态文案)
        if (kernelWantedBeforeSuspend_) {
            // 真正把 Bulwark.sys 卸掉。只关端口是不够的:内核的「自足基线」(禁止执行名单 /
            // 命令行硬拦 / 已知恶意哈希 / 内置凭据 hive 硬拦)恰恰是设计成「用户态不在也生效」的,
            // 驱动在载就还在拦 —— 这正是「软件退出了还是会拦截隔离」的直接原因。
            if (DriverControl::tryStop())
                log_.info(QStringLiteral("待机:内核驱动已卸载(内核侧自足基线随之全部停止生效)。"));
            else
                log_.warning(QStringLiteral("待机:内核驱动卸载失败 —— 内核侧的禁止执行名单 / 命令行硬拦 / "
                                            "已知恶意哈希【仍在生效】,待机并不完整。"
                                            "原因见上一条 fltmc / sc 日志。"));
        }
        if (behavior_) behavior_->stop();   // 自启动监视 + 勒索诱饵巡检
        if (base_) base_->stop();           // ETW 实时会话
        if (execBlock_) execBlock_->setSuspended(true);
        const int netCleared = netBlock_ ? netBlock_->clearAll() : 0;
        started_ = false;
        log_.warning(QStringLiteral("已进入待机:ETW 会话已停、行为监控已停、用户态独占句柄已放开、"
                                    "出站封禁已清 %1 条%2。本软件此刻【不提供任何防护】,"
                                    "已隔离的文件与已施加的拒绝执行 ACE 保持原样。")
                         .arg(netCleared)
                         .arg(kernelWantedBeforeSuspend_ ? QStringLiteral("、内核驱动已卸载") : QString()));
        return;
    }

    // 必须先解除 execBlock_ 的待机标志:它在待机时把重试表停了,不解除的话下面重放上来的
    // 条目一旦抢不到句柄就永远停在「待武装」,再也没有人去重试。
    if (execBlock_) execBlock_->setSuspended(false);
    // 唤醒刻意走【完整的 start()】而不是逐个 start 子对象:待机把 started_ 置回了 false,
    // 所以这一句会把 ETW、行为源、禁止执行名单重放、出站黑名单重建全部按启动时的同一条路径做完。
    // 分开写就会漏 —— 首次待机发生在「启动即待机」时,start() 从来没跑过,禁止执行名单也就从未
    // 重放;而那正是最常见的那条路径(开机后还没打开过界面)。
    start();
    if (kernelWantedBeforeSuspend_)
        applyKernelEnabled(true);  // 内部 DriverControl::ensureLoaded() 会把 Bulwark.sys 装回来
    log_.info(QStringLiteral("已退出待机:防护已恢复(%1)。").arg(protectionSummary()));
}

void EventSourceCoordinator::setKernelWantedOnResume(bool on) {
    kernelWantedBeforeSuspend_ = on;
}

// 内核连接看护。
//
// 【原实现连上就把定时器停了】—— 只能自愈"启动时没连上"这一种情况。一旦驱动在运行期间掉了
// (被 fltmc unload、被升级脚本卸载、驱动自身重载、或外部工具卸载),就再也没有人发现:
// 服务还活着、界面还显示"防护开启",但内核前置拦截已经没了,而且要等到下次重启服务才恢复。
// 这是「防护静默失效」——比服务直接挂掉更难察觉。
// 现在只要启用了内核驱动,这个定时器就一直跑;已连上时每轮只做一次极轻的句柄检查。
void EventSourceCoordinator::onKernelRetry() {
    if (!kernelEnabled_ || !driver_) { kernelRetry_->stop(); return; }
    if (driver_->isAvailable()) {
        // 连接正常:清掉失败标记但【不停表】,继续看护掉线。
        if (attachFailed_) {
            attachFailed_ = false;
            log_.info(QStringLiteral("内核驱动连接已恢复。"));
        }
        // notifyKernelState 自带去重,所以这里每轮都报是安全的 —— 它的作用是补上一种漏报:
        // 若首次连接就成功、之后从未掉线,上面那个 if 永远不进,状态也就从没派发过。
        notifyKernelState(true, QStringLiteral("内核驱动已连接 · 行为前拦截生效"));
        return;
    }
    // 走到这里说明「本该有内核却没有」:要么从没连上,要么中途掉了。两种都按同一条路自愈。
    if (!attachFailed_) {
        attachFailed_ = true;
        log_.warning(QStringLiteral("内核驱动连接已断开(驱动被卸载或重载),正在尝试重新加载并接回。"));
    }
    // 掉线这一刻就报,不等重连结果 —— 「防护空窗从什么时候开始」正是复盘要的那个时刻。
    // 下面重连成功会紧接着再报一条 connected,两条时间戳之差就是空窗时长。
    notifyKernelState(false, QStringLiteral("内核驱动连接已断开(被卸载 / 重载)· 已降级为"
                                           "用户态观测,正在尝试接回"));
    DriverControl::ensureLoaded();
    driver_->setMemoryProtectionEnabled(memProtEnabled_); // 同上:必须早于 start()
    driver_->start();
    if (driver_->isAvailable()) {
        attachFailed_ = false;
        for (int pid : protectedPids_)
            driver_->addProtectedPid(pid);
        log_.info(QStringLiteral("内核驱动连接已恢复。"));
        notifyKernelState(true, QStringLiteral("内核驱动连接已恢复 · 行为前拦截重新生效"));
    }
}

void EventSourceCoordinator::notifyKernelState(bool connected, const QString& detail) {
    if (!stateChanged_)
        return;
    if (notifiedConnected_.has_value() && *notifiedConnected_ == connected)
        return;   // 状态没变,不重复派发(否则 10 秒一条把审计刷满)
    notifiedConnected_ = connected;
    stateChanged_(connected, detail);
}

void EventSourceCoordinator::configureBehaviorMonitor(bool enabled, bool canaryEnabled) {
    if (!behavior_) return;
    behavior_->setEnabled(enabled);
    behavior_->setCanaryEnabled(canaryEnabled);
}

void EventSourceCoordinator::setMemoryProtectionEnabled(bool on) {
    memProtEnabled_ = on;   // 记住:内核源可能还没创建(懒创建),届时由 setKernelEnabled 补发
    if (driver_)
        driver_->setMemoryProtectionEnabled(on);
}

void EventSourceCoordinator::addProtectedUiPid(int pid) {
    if (pid <= 0) return;
    protectedPids_.insert(pid);
    if (driver_) driver_->addProtectedPid(pid);
}

// 两侧都下发,返回「至少一侧真的装上了」。
//
// 内核侧的 addBlockedIp 是 void —— 协议上 sendConfig 不回执,拿不到真实结果,故只能按
// 「已连接就算受理」计。用户态侧有确切结果(FwpmFilterAdd0 的返回码),这也是本函数能给出
// 诚实布尔值的原因。
bool EventSourceCoordinator::addBlockedIp(const QString& ip, quint16 port) {
    bool any = false;
    if (driver_ && driver_->isConnected()) {
        driver_->addBlockedIp(ip, port);
        any = true;
    }
    if (netBlock_ && netBlock_->blockIp(ip, port))
        any = true;
    return any;
}

int EventSourceCoordinator::unblockIp(const QString& ip, quint16 port) {
    return netBlock_ ? netBlock_->unblockIp(ip, port) : 0;
}

int EventSourceCoordinator::clearUserModeIpBlocks() {
    return netBlock_ ? netBlock_->clearAll() : 0;
}

QStringList EventSourceCoordinator::userModeBlockedIpList() const {
    return netBlock_ ? netBlock_->blockedList() : QStringList{};
}

// 内核优先:驱动在线时由内核名单前拦(更强,且跨重启续拦)。驱动未连接 / 旧驱动不受理时
// (blockExecPath 返回 false)才落到用户态独占句柄锁 —— 这是无驱动模式下唯一的执行前拦截。
bool EventSourceCoordinator::blockModuleLoad(const QString& modulePath) {
    if (driver_ && driver_->blockModuleLoad(modulePath))
        return true;
    return execBlock_ ? execBlock_->blockModuleLoad(modulePath) : false;
}

bool EventSourceCoordinator::blockExecPath(const QString& imagePath) {
    if (driver_ && driver_->blockExecPath(imagePath))
        return true;
    return execBlock_ ? execBlock_->blockExecPath(imagePath) : false;
}

// 清空【两侧都做】,且返回值是「或」。
//
// 这里绝不能写成「内核成功就不管用户态」:加白撤销要求撤掉一切拦截(约束 3)。设想驱动掉线期间
// 用户态锁住了 evil.exe,之后驱动接上、用户再加白 —— 若只清内核那侧,那个独占句柄还握着,
// 用户加白之后文件依然打不开、依然删不掉,而日志会显示「加白对账已完成」。这正是该约束要防的
// 事故形态:加白了却还是起不来,且找不到原因。
bool EventSourceCoordinator::clearExecBlock() {
    const bool k = driver_ ? driver_->clearExecBlock() : false;
    const bool u = execBlock_ ? execBlock_->clearExecBlock() : false;
    return k || u;
}

bool EventSourceCoordinator::clearModuleNoLoad() {
    const bool k = driver_ ? driver_->clearModuleNoLoad() : false;
    const bool u = execBlock_ ? execBlock_->clearModuleNoLoad() : false;
    return k || u;
}

int EventSourceCoordinator::suspendUserModeLock(const QString& absPath) {
    return execBlock_ ? execBlock_->suspendForRemediation(absPath) : 0;
}

bool EventSourceCoordinator::clearBannedProcesses() {
    return driver_ ? driver_->clearBannedProcesses() : false;
}

// 两侧并集(去重)。加白对账靠这份表算出「哪些条目会挡住已加白程序」,漏报一侧就等于那一侧的
// 拦截永远撤不掉。
QStringList EventSourceCoordinator::persistedExecBlockList() const {
    QStringList out = driver_ ? driver_->persistedExecBlockList() : QStringList{};
    if (execBlock_) {
        for (const QString& e : execBlock_->persistedExecBlockList())
            if (!out.contains(e, Qt::CaseInsensitive))
                out << e;
    }
    return out;
}

QStringList EventSourceCoordinator::persistedModuleNoLoadList() const {
    QStringList out = driver_ ? driver_->persistedModuleNoLoadList() : QStringList{};
    if (execBlock_) {
        for (const QString& e : execBlock_->persistedModuleNoLoadList())
            if (!out.contains(e, Qt::CaseInsensitive))
                out << e;
    }
    return out;
}

bool EventSourceCoordinator::hardenRegistryKey(const QString& keyOrValue) {
    return driver_ ? driver_->hardenRegistryKey(keyOrValue) : false;
}

bool EventSourceCoordinator::readLockedFile(const QString& path, QByteArray& out) {
    return driver_ ? driver_->readLockedFile(path, out) : false;
}

bool EventSourceCoordinator::forceDeleteFile(const QString& path) {
    return driver_ ? driver_->forceDeleteFile(path) : false;
}

bool EventSourceCoordinator::killProcess(int pid) {
    return driver_ ? driver_->killProcess(pid) : false;
}

bool EventSourceCoordinator::banProcess(int pid) {
    return driver_ ? driver_->banProcess(pid) : false;
}

void EventSourceCoordinator::onBaseEvent(const bulwark::SecurityEvent& e) {
    if (kernelConnected()) {
        switch (e.type) {
            // 内核已接管进程事件时,丢弃基础源的进程创建/退出,避免与内核源重复上报。
            case bulwark::EventType::ProcessCreate:
            case bulwark::EventType::ProcessTerminate:
            //
            // 模块加载 / 跨进程线程注入同理 —— 这两维是 ETW 侧【为了补无驱动盲区】新加的
            // (见 EtwProcessEventSource.h),而驱动自己也会上报它们:
            //   · ImageLoad:驱动报 \Temp\ 与 \Users\Public\ 下的用户态模块 + 用户可写目录的 .sys;
            //   · RemoteThread:驱动经 ObCallbacks 报向其内存防护目标(MemoryProtectionTargets)
            //     的注入,而且那一类是【真前拦】(kernelBlocked=true)。
            // 两边口径有重叠,不去重就会出现「一个动作两条事件」:证据链重复、审计重复、
            // 攻击链组合被同一个动作点亮两次(而组合命中在强制模式下按硬指标登记)。
            //
            // 这里选择「内核在线就整类丢弃 ETW 侧」而不是逐条按路径/目标去重,理由:
            //   1) 与上面两类沿用同一条规则,不给协调器引入第二套去重语义;
            //   2) 内核在线时驱动的口径是权威的 —— 它能在动作前拒绝,ETW 只能事后观测;
            //   3) 保证 Driver 模式下行为【零变化】,这一轮改动的回归面因此只剩无驱动路径。
            // 代价要说清楚:Driver 模式下就拿不到 ETW 那份更宽的模块加载口径(驱动只报两个目录)。
            // 那是驱动侧上报口径的问题,应当在驱动里改,不该靠用户态重复上报来掩盖。
            //
            // 收益是顺带的:驱动一旦掉线(fltmc unload / 升级 / 被外部卸载),kernelConnected()
            // 立刻变假,这两维【自动接管】,不需要任何额外的降级开关。
            case bulwark::EventType::ImageLoad:
            case bulwark::EventType::RemoteThread:
                return;
            default:
                break;
        }
    }
    emit eventProduced(e);
}

void EventSourceCoordinator::onDriverEvent(const bulwark::SecurityEvent& e) {
    emit eventProduced(e); // 裁决回写经 submitVerdict 直接路由到 driver_
}

void EventSourceCoordinator::onBehaviorEvent(const bulwark::SecurityEvent& e) {
    emit eventProduced(e);
}

} // namespace bulwark::service
