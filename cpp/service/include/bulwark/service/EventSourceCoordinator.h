#pragma once
#include "bulwark/service/EventSource.h"
#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/service/Logger.h"

#include <QSet>
#include <QStringList>

#include <functional>
#include <optional>

class QTimer;
class QByteArray;

namespace bulwark::service {

class DriverEventSource;
class UserModeBehaviorSource;
class UserModeExecBlock;
class UserModeNetworkBlock;

// 事件源协调器。始终运行一个用户态基础源(ETW)用于观测,并可在运行时按用户开关
// 动态启动/停止内核驱动源(Bulwark.sys);始终并行一个用户态持续行为源(自启动 + 勒索诱饵)。
// 三路事件合并后对外统一 emit,作为 Worker 的唯一事件源。
//
// 设计要点(移植 .NET Monitoring/EventSourceCoordinator.cs):
//  - 内核源默认不连接,仅当开关开启后才尝试连接;连不上则后台按退避自愈重试,期间降级为
//    用户态观测,绝不因内核不可用影响 IPC/规则链路;
//  - 内核连接后抑制基础源的进程创建/退出事件,避免与内核源重复上报;
//  - 裁决回写(submitVerdict)只路由到内核源(唯一支持回写的源);
//  - 记录已连接 UI 的 PID,内核源(重)启动时补发以维持自我保护。
class EventSourceCoordinator : public EventSource {
    Q_OBJECT
public:
    // base / behavior 由调用方(main)持有;driver 由本类懒创建并拥有(parent=this)。
    EventSourceCoordinator(EventSource* base, UserModeBehaviorSource* behavior,
                           const BulwarkOptions& options, QObject* parent = nullptr);
    ~EventSourceCoordinator() override;

    void start() override;
    void stop() override;
    bool isAvailable() const override;              // 取决于基础源
    bool wantsVerdict() const override { return true; } // 路由到产生事件的源
    void submitVerdict(const bulwark::SecurityEvent& e, bulwark::VerdictAction action) override;

    //
    // 内核防护状态迁移回调(由 main 接线;只在【状态真的变了】时调用,不是每轮重试都叫)。
    //
    // 【为什么必须有】事故复盘时第一个要问的就是「出事那会儿到底有没有内核前拦」,而这件事
    // 此前只存在于设置页的一行实时派生文字里 —— 服务一重启就没了,SettingsStore 还会刻意
    // 把它读入即丢弃(那是对的,陈旧状态比没状态更坏)。日志里也只有一条 info,会被几 MB 的
    // 事件流冲走。
    //
    // .kiro/specs/architecture-rewrite/requirements.md 里记着上一次复盘的结论:
    // 「当时 Bulwark 是否在运行、跑的是 Driver 还是 Wmi 模式 —— 无证据」。
    // 这条回调把每一次迁移(接上 / 掉线 / 恢复 / 被用户关掉)落进审计日志,使那个问题
    // 此后一定能回答。这是本回调唯一的存在理由,不要把它扩成通用事件总线。
    //
    // detail 是给人读的一句话;connected 是机器判定用的那一位。
    using KernelStateHandler = std::function<void(bool connected, const QString& detail)>;
    void setKernelStateChanged(KernelStateHandler fn) { stateChanged_ = std::move(fn); }

    // 运行时控制(由 main 据设置调用)。
    void setKernelEnabled(bool on);                 // 启停内核驱动源
    void configureBehaviorMonitor(bool enabled, bool canaryEnabled);

    //
    // 整体待机 / 唤醒(RuntimeSettings::protectionFollowsUi:「退出界面即停止防护」)。
    //
    // 待机 = 停 ETW 会话、停行为监控与勒索诱饵、放开用户态独占句柄、清掉 WFP 出站封禁,
    // 并【真的把 Bulwark.sys 卸掉】。最后那一条是这个接口存在的理由:setKernelEnabled(false)
    // 只关通信端口,而内核的自足基线(禁止执行名单 / 命令行硬拦 / 已知恶意哈希 / 内置凭据 hive
    // 硬拦)本来就是设计成「用户态不在也照样拦」的 —— 驱动在载,它就还在拦。
    //
    // 待机【不回滚已经落地的东西】(已隔离文件、已加的拒绝执行 ACE、内核写进注册表的基线)。
    // 语义是「不再做新的事」,不是「撤销做过的事」—— 后者会把一次误开关变成不可逆的防护清空。
    //
    // 唤醒按相反顺序恢复,并把待机前的内核开关意图原样装回来。
    void setSuspended(bool on);
    bool isSuspended() const { return suspended_; }

    // 「唤醒后要不要内核驱动」。通常由 setSuspended 自己从待机前的状态记下来,只有【启动即待机】
    // 那条路径需要显式告知:那时 setKernelEnabled 一次都没被调用过,协调器无从知道配置要不要内核,
    // 默认值 false 会让唤醒后永远停在无驱动状态 —— 而那是一次静默的能力丢失,不会有任何报错。
    void setKernelWantedOnResume(bool on);
    // 内存防护总开关:转发到内核源,并记住状态以便内核源(重)创建后补发。
    void setMemoryProtectionEnabled(bool on) override;
    void addProtectedUiPid(int pid);

    //
    // ---- 出站封禁:内核 + 用户态 WFP 双下发 ----
    //
    // 返回值从 void 改成 bool:原先调用方无从知道封禁到底有没有生效,而「以为封住了其实没封」
    // 是本项目最不能接受的一类失真。true = 至少一侧真的装上了拦截。
    //
    // 两侧都下发(而不是内核优先):两者封的是同一份地址,内核那份在驱动重连时会被
    // BLW_CMD_CLEAR_BLOCKIP 清掉重建,用户态这份在驱动掉线期间仍然挡着 —— 互为兜底。
    bool addBlockedIp(const QString& ip, quint16 port = 0);
    // 撤销(加白撤销的抓手)。内核侧协议只有「整表清空」,故解除单条目前只作用于用户态一侧;
    // 内核那份会在下次驱动重连时按配置重建,不会保留运行时加进去的条目。
    int unblockIp(const QString& ip, quint16 port = 0);
    int clearUserModeIpBlocks();
    QStringList userModeBlockedIpList() const;
    //
    // ---- 执行前拦截:内核优先,内核不可用时落到用户态独占句柄锁 ----
    //
    // 这一组以前是「driver_ ? 转发 : 返回 false」—— 即 EventSource=Wmi 或驱动掉线时,
    // 执行前拦截【完全不存在】,每个 Block 都只是事后 kill,样本重启后照旧运行。
    // 现在未连接内核时改走 UserModeExecBlock(长期持有 share-mode-0 独占句柄,使
    // CreateProcess 与加载器的那次打开直接失败)。
    //
    // 清空与读回【刻意同时作用于两侧】,而不是「只管当前生效的那一侧」:
    // 加白撤销(约束 3)要求撤掉【一切】拦截。若只清内核那侧,曾由用户态锁住的文件会继续
    // 锁着,用户加白后仍然打不开,还找不到原因 —— 那正是这条约束要防的事故形态。
    bool blockModuleLoad(const QString& modulePath) override;
    bool blockExecPath(const QString& imagePath) override;
    bool clearExecBlock() override;     // 内核 + 用户态两侧都清
    bool clearModuleNoLoad() override;  // 同上
    bool clearBannedProcesses() override;
    QStringList persistedExecBlockList() const override;     // 两侧并集
    QStringList persistedModuleNoLoadList() const override;  // 两侧并集

    // 处置协议:隔离 / 取哈希 / 强删【之前】必须先放开用户态独占锁,否则那些操作会撞共享
    // 冲突而失败(share-mode-0 连读取都挡,包括我们自己)。内核那侧没有这个问题,故此接口
    // 只作用于用户态一侧。absPath 为空 = 全部挂起。返回放开的句柄数。
    int suspendUserModeLock(const QString& absPath);
    bool hardenRegistryKey(const QString& keyOrValue) override; // 持久化反重建:转发到内核驱动源(未连接则 no-op)

    // 内核级足迹清理(v6):转发到内核驱动源(以「忽略共享访问检查」读被占用文件 / POSIX 强制删除)。
    // 内核未连接 / 旧驱动不支持时返回 false,调用方(QuarantineManager)据此回退到用户态清理。
    bool readLockedFile(const QString& path, QByteArray& out);
    bool forceDeleteFile(const QString& path);
    bool killProcess(int pid) override; // 驱动级结束进程:转发到内核驱动源(未连接/旧驱动返回 false)
    bool banProcess(int pid) override;  // 封禁主体:转发到内核驱动源(未连接/旧驱动 no-op)

    // 状态(供设置页回报)。
    bool kernelConnected() const;
    bool kernelAttachFailed() const { return attachFailed_; }
    bool kernelProtocolMismatch() const;
    // 已连接驱动不支持的防护维度(空 = 全就绪 / 未连接)。转发到内核源;
    // 用于把「驱动比服务旧 -> 若干维度静默失效」这一状态如实反映到设置页,详见
    // DriverEventSource::missingCapabilities 的说明。
    QStringList kernelMissingCapabilities() const;

    //
    // ---- 2.5 显式防护能力集 ----------------------------------------------------
    //
    // 为什么需要它:此前「当前有哪些防护」是靠 main.cpp 里几条手写字符串表达的,
    // 无驱动分支写死为「用户态观测(ETW,内核驱动未启用)」。那句话在阶段 1 之前是准确的,
    // 现在【反过来变成了低报】—— 用户态已经有执行前拦截(独占句柄)、出站封禁(WFP)、
    // 进程冻结与断子三种真实的拦截手段,却仍被告知自己只有观测能力。
    //
    // 手写字符串的问题不是文案不好,而是它和真实能力之间没有任何连接:任何一侧变了,
    // 另一侧不会自动跟上,而且没有测试能发现。这里改成从【运行时状态】导出的结构化清单,
    // 每一项都要回答「这个维度此刻到底成立不成立、由谁提供、边界在哪」。
    struct ProtectionCapability {
        QString dimension;   // 防护维度
        bool inForce = false;// 此刻是否真的成立(不是配置意图)
        QString provider;    // 内核驱动 / 用户态 / 无
        QString limit;       // 诚实的边界(空 = 无额外边界)
    };
    QVector<ProtectionCapability> protectionCapabilities() const;

    // 阶段 3 的两项能力由 SystemHardening 持有,协调器不认识那个类型 —— 所以用注入的探针
    // 去问【运行时状态】,而不是读配置意图:配置写着开、而监视线程没起来的话,这一位必须报假。
    // 这两行是补上一个我自己造出来的低报:2.5 的能力表写在阶段 3 之前,那时回滚与跨重启
    // 拒绝执行都还不存在,表里因此根本没有它们的位置 —— 与原先那句「已降级为用户态观测」
    // 是同一种错,只是换了个地方。
    //
    // 【刻意不用 std::function 捕获 SystemHardening 的引用】第一版是两个
    // `std::function<bool()>`,各自捕获 `&hardening`。那是一个真实的悬垂:`hardening` 在
    // main 里声明在 coordinator 之后,于是析构时它【先】死,而协调器还活着 —— 关停路径上
    // 任何一次能力查询(内核状态迁移会触发)都会调用捕获了已死对象的 lambda。
    // 改成两个普通 bool 由 main 推进来:没有捕获、没有生命周期耦合,也就没有这一类错误。
    // 值仍然取【运行时状态】(main 在 startWatching() 之后才读 isWatching()),不是配置意图。
    void setHardeningState(bool registryRollbackActive, bool crossRebootExecDeny);
    // 防护档位标识。刻意有三档而不是两档:「无驱动但用户态拦截可用」与「什么都只有观测」
    // 对用户是完全不同的处境,合成一档就是把前者说低、或把后者说高。
    QString protectionTier() const;
    // 一行人类可读摘要,供设置页 / 审计直接使用。
    QString protectionSummary() const;

private slots:
    void onBaseEvent(const bulwark::SecurityEvent& e);
    void onDriverEvent(const bulwark::SecurityEvent& e);
    void onBehaviorEvent(const bulwark::SecurityEvent& e);
    void onKernelRetry();

private:
    // 状态迁移去重后派发给 stateChanged_。同一个状态连续报两次会被丢掉 —— 重试定时器
    // 每 10 秒跑一轮,不去重的话审计日志会被同一条「仍然没连上」刷满,反而把真正的
    // 迁移时刻埋掉。
    void notifyKernelState(bool connected, const QString& detail);

    // 按【当前配置】重建用户态出站黑名单(appsettings 的 BlockedRemoteEndpoints)。
    // 两个调用点:start() 与待机唤醒。返回真正装上的过滤器数。
    int pushConfiguredIpBlocks();

    // 内核源启停的实际动作。setKernelEnabled() 是它的【带待机守卫】的包装:待机期间外部调用
    // 只记意图,而待机/唤醒自己必须能真的动手,所以走这个未加守卫的版本。
    void applyKernelEnabled(bool on);

    // 阶段 3 能力状态(见 setHardeningState)。默认 false = 如实报「未生效」。
    bool regRollbackActive_ = false;
    bool crossRebootDenyOn_ = false;

    EventSource* base_ = nullptr;                // 基础源(ETW),非拥有
    UserModeBehaviorSource* behavior_ = nullptr; // 行为源,非拥有(可空)
    DriverEventSource* driver_ = nullptr;        // 内核源,拥有(懒创建)
    // 用户态执行前拦截(拥有)。与内核源不同,这个【总是】创建:驱动可能在任何时刻掉线,
    // 那一刻就得立刻有地方下发拦截,不能等懒创建。空转成本仅一个 30s 空表定时器。
    UserModeExecBlock* execBlock_ = nullptr;
    // 用户态出站封禁(拥有;非 QObject,故用 unique_ptr 语义手工管理于 .cpp)。
    UserModeNetworkBlock* netBlock_ = nullptr;
    const BulwarkOptions& options_;
    QTimer* kernelRetry_ = nullptr;              // 内核连接自愈重试
    QSet<int> protectedPids_;                    // 待补发的受保护 UI PID
    KernelStateHandler stateChanged_;            // 状态迁移回调(可空 = 未接线)
    std::optional<bool> notifiedConnected_;      // 上次派发出去的状态(nullopt = 还没派发过)
    bool kernelEnabled_ = false;
    bool attachFailed_ = false;
    bool started_ = false;
    bool suspended_ = false;                 // 待机中(见 setSuspended)
    // 待机前「用户/配置是否要内核驱动」。唤醒时要恢复的是这个意图,而不是「当时连上了没有」——
    // 若在驱动掉线的瞬间进了待机,按后者恢复就会把内核这一层永久丢掉。
    bool kernelWantedBeforeSuspend_ = false;
    // 内存防护总开关的当前状态。内核源是懒创建的,故这里必须自己记一份,
    // 在内核源(重)创建 / 重连时补发 —— 否则用户关掉的开关会在下次重连时悄悄恢复。
    bool memProtEnabled_ = true;
    Logger log_{QStringLiteral("bulwark.service.Coordinator")};
};

} // namespace bulwark::service
