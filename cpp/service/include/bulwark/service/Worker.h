#pragma once
#include <QObject>
#include <QHash>
#include <QUuid>
#include <QQueue>
#include <QSet>
#include <QMutex>
#include <QWaitCondition>
#include <QDateTime>
#include <QPair>
#include <QString>
#include <memory>
#include <thread>
#include <vector>
#include <atomic>
#include <functional>
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/ThreatBehaviorProfile.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/models/VtScanRecord.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/engine/RuleEngine.h"
#include "bulwark/engine/ProcessChainTracker.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/reputation/RateLimiting.h"

namespace bulwark::service {

class IpcServer;
class EventSource;
class RuleStore;
class AuditLog;
class FirstSeenStore;
class QuarantineManager;
class ThreatRemediator;
struct RemediationReport; // 定义在 ThreatRemediator.h;此处仅需前置声明以按 const 引用传参(.cpp 已含完整定义)
class VtScanHistoryStore;
class EventHistoryStore;
namespace reputation { class ReputationManager; class ThreatBookClient; class VirusTotalClient; }

// 精简编排器:事件源 -> 富化(签名/哈希/命令行/首见)-> RuleEngine 评估 -> 按裁决路由到
// IPC(放行记日志 / 拦截通知 / 询问弹窗),并对用户态观测源的拦截执行补偿性处置(结束
// 作恶进程树),对确定性恶意进程主体进一步隔离载荷 + 清除自启动持久化。处理 UI 回传的
// 裁决(含「记住」落规则)。对应 .NET Worker.cs 的核心链路。
class Worker : public QObject {
    Q_OBJECT
public:
    Worker(bulwark::engine::RuleEngine* engine, IpcServer* ipc, EventSource* source,
           RuleStore* ruleStore, AuditLog* audit, FirstSeenStore* firstSeen,
           QuarantineManager* quarantine, reputation::ReputationManager* reputation,
           const bulwark::RuntimeSettings* settings, QObject* parent = nullptr);
    ~Worker();

    // 注入具体微步客户端并启动后台 IP 情报 worker(网络外联情报互证)。为空则不启用。
    // 由 main 在构造后调用(IP 信誉是接口外的 ThreatBook 专有方法,不经聚合器)。
    void setIpIntel(reputation::ThreatBookClient* tb);

    // 注入具体 VirusTotal 客户端 + 扫描历史,启动后台"双击/释放载荷"病毒扫描 worker。为空则不启用。
    // 由 main 在构造后调用(上传扫描是接口外的 VT 专有方法,不经聚合器)。
    void setVtScan(reputation::VirusTotalClient* vt, VtScanHistoryStore* history);

    // 注入结构化事件历史存储:每条已处置事件都落库,供 UI 打开活动日志/拦截记录时回填。为空则不落库。
    void setEventHistory(EventHistoryStore* history) { eventHistory_ = history; }

    // 注入「情报行为规则」注入器:确认恶意后据行为画像 IOC 生成的拦截规则经此加入引擎并落盘
    // (累加去重)。返回新增规则数。由 main 在主线程侧接线(内部触碰引擎/规则库须在主线程)。
    void setIntelRuleInjector(std::function<int(const QVector<bulwark::DefenseRule>&)> fn) {
        injectIntelRules_ = std::move(fn);
    }

    // 启动「兜底扫描」后台线程:定期枚举在跑进程,按【已确认恶意情报】(引擎记住的恶意哈希 +
    // 信誉缓存判恶意)比对,漏网的补封禁+结束+隔离 —— 防实时链路漏检(遥测丢包 / 云端确认迟到 /
    // 进程在防护启动前就在跑)。由 main 在接线完成后调用。
    void startMaliciousSweep();

    // 加白后与内核名单对账:内核「禁止执行(FileExecBlock)/ 禁止加载(FileNoLoad)」两份名单由
    // 【内核自己】写回注册表持久化,跨杀服务与重启由内核独立续拦,且协议上只有「追加 / 整表清空」
    // 没有「删除单条」。后果:一个程序只要被确认恶意过一次,路径子串就永久钉在内核里 —— 此后用户
    // 在 UI 加白【完全无效】,因为内核在进程创建 / 映像加载回调里就地 STATUS_ACCESS_DENIED,事件
    // 根本到不了用户态引擎(这正是「加白不彻底、时不时还拦」的首要根因)。
    //
    // 故加白后走一次对账:从注册表读回内核当前的权威名单 -> 剔掉会命中【已加白目标】的条目 ->
    // 整表清空后把其余条目重新下发。读注册表而不是只用本进程的下发记录,是为了不丢失【上次运行】
    // 钉进去的条目(那些才是用户最可能撞上的);内核对 \Services\Bulwark 的注册表硬拦只挡写,不挡读。
    // 须在主线程调用(由 main 的 trustAddRequested 回调触发,触碰引擎规则集)。
    void reconcileKernelBlocksAfterTrust();

private slots:
    void onEvent(const bulwark::SecurityEvent& e);
    void onPromptResponse(const QUuid& eventId, bulwark::VerdictAction action,
                          bool remember, bulwark::RememberScope scope);
    // UI 回传的 AI 研判结果:按 AiDecisionPolicy 折叠,恶意则补偿处置(结束进程树 + 隔离)。
    void onAiScanResponse(const bulwark::ipc::AiScanResponsePayload& resp);

private:
    // 按 PID 回填签名/发布者/哈希/证书画像/命令行/父路径/首见等,供规则引擎裁决。
    void enrich(bulwark::SecurityEvent& e);
    // 用 OS API 回溯完整父进程祖先链,种入 e.chainContext(即便跟踪器无历史也保证溯源完整)。
    void seedAncestryChain(bulwark::SecurityEvent& e);
    // 拦截的实际执行,并【返回真实结果】。内核已前拦的事件(kernelBlocked)直接如实返回
    // KernelBlocked 不再补杀;观测型事件(动作已发生)结束作恶进程树(带关键进程防护),对侧载
    // 模块额外加入内核禁止加载名单。返回值供 UI 如实显示处置,杜绝假拦截。
    bulwark::EnforcementOutcome enforceBlock(const bulwark::SecurityEvent& e);
    // 恶意进程终结:用户态结束进程树 + 驱动级(内核 ZwTerminateProcess)兜底补刀(难被反杀)。
    // 返回是否已结束。关键系统进程由内核+用户态双重护栏保护。
    bool killMalicious(int pid);
    // 执行前拦截:把已确认恶意进程的映像路径加入内核「禁止执行」名单(与 killMalicious 配对)——
    // kill 收拾正在运行的实例,exec-block 挡住其(被守护进程/持久化/重启后规则命中拉起时)再次启动。
    // 仅对确认恶意的可执行主体调用(信誉/AI/规则确认的进程创建),不对网络外联发起进程调用(可能是合法程序)。
    // 下发【盘符无关】的路径子串以兼容内核收到的 \??\C:\... 与 \Device\HarddiskVolumeN\... 两种映像路径形式。
    void blacklistExec(const QString& imagePath);
    // 延迟处置前复查加白:后台补偿路径(外部信誉 / VT / 微步 IP / AI / 兜底扫描)在事件求值
    // 【之后】才回执,那时 e.userTrusted 只是旧快照 —— 期间用户完全可能刚把该程序加白。动手前
    // 重查一次,命中就放弃本次处置并记一条日志。返回 true = 已加白,调用方应立即 return。
    // 不这么做的话,「加白之前排队的扫描」回来照样结束进程,还会顺手把路径钉进内核禁运名单。
    bool abortIfTrustedNow(const bulwark::SecurityEvent& e, const QString& stage);
    // 持久化反重建:把本次清理产出的 hardenedRegTargets(已清掉的恶意自启动项)去重+长度护栏后
    // 下发内核注册表硬拦,使恶意软件无法立刻重建刚被清掉的持久化(补「清理→守护进程秒级重写」竞态)。
    void applyRegHardening(const RemediationReport& report);
    // 对确定性恶意(命中规则 / 启发式)的进程主体:隔离磁盘载荷 + 清除自启动持久化。
    void remediateIfMalicious(const bulwark::SecurityEvent& e, const bulwark::Verdict& v);
    // 后台线程:确认恶意后顺带拉取样本行为画像(VT 沙箱报告),再编组回主线程处置。
    void confirmReputationMaliciousAsync(const bulwark::SecurityEvent& e, const bulwark::FileReputation& rep);
    // 后台信誉查询确认恶意时的主线程处置(结束进程 + 隔离 + 清除持久化 + 据画像清释放物/注规则 + 告警)。
    void onReputationMalicious(const bulwark::SecurityEvent& e, const bulwark::FileReputation& rep,
                               const bulwark::ThreatBehaviorProfile& profile = {});
    // AI 研判判定恶意时的补偿处置(结束进程树 + 隔离载荷 + 清除持久化 + 告警)。
    void onAiMalicious(const bulwark::SecurityEvent& e, const QString& summary);

    // ---- 兜底扫描(catch-all sweep):防漏检的最后一道网 ----
    void sweepLoop();                                                     // 后台线程主体
    void handleSweptMalicious(const bulwark::SecurityEvent& e, bulwark::VerdictSource source); // 主线程处置
    void rememberMaliciousHash(const QString& sha256);                    // 线程安全登记已确认恶意哈希(小写)
    void seedMaliciousHashesFromRules();                                  // 启动时从引擎规则 seed(含持久化记忆哈希)
    static bool isSweepExemptPath(const QString& path);                   // 系统目录/本软件 -> 免扫

    // 网络外联 IP 情报互证(后台限流查询 + 恶意即补偿):合格外联入队 -> 后台查微步 IP 信誉 ->
    // 确认恶意再编组回主线程做补偿处置(结束外联进程树)。仅可疑外联才查(保护极低月配额)。
    void maybeQueryEgressIp(const bulwark::SecurityEvent& e);
    void ipConsumeLoop();
    void onEgressMalicious(const bulwark::SecurityEvent& e, const QString& ip, const QString& label);
    static QString extractRemoteIpv4(const QString& target); // "ip"/"ip:port" -> IPv4;非 IPv4 返回空
    static bool isPrivateOrReserved(const QString& ipv4);     // 私网/环回/保留:不查云端情报

    // ---- 双击 / 释放载荷 VirusTotal 病毒扫描(后台上传扫描 + 恶意即补偿)----
    // 用户双击启动或释放器派生的可疑新样本:后台先按哈希查 VT,未收录则上传整文件云端多引擎
    // 扫描,进度经 sendVtScanUpdate 推 UI 卡片、结果落 VtScanHistoryStore 去重;确认恶意再补偿
    // 结束进程树(复用 onReputationMalicious)。C# 侧内联 await(驱动挂起动作),此处改后台。
    bool shouldAiScan(const bulwark::SecurityEvent& e);
    bool isDoubleClickLaunch(const bulwark::SecurityEvent& e) const;
    bool isDropperSpawnedPayload(const bulwark::SecurityEvent& e) const;
    bool isRecentlyDroppedExecutable(const bulwark::SecurityEvent& e); // 用 chain_.wasRecentlyWritten
    void maybeScanDoubleClick(const bulwark::SecurityEvent& e);        // 合格进程创建入队后台扫描
    void maybeScanInstallerPackage(const bulwark::SecurityEvent& e);  // 双击 MSI/MSP:扫描安装包本身(msiexec 仅宿主)
    void maybeScanDroppedInstaller(const bulwark::SecurityEvent& e);  // 落盘即扫:写入用户目录的安装包/可执行体送 VT(PID 清零,只隔离不杀进程)
    void maybeVerifyMemoryInjection(const bulwark::SecurityEvent& e); // 内存防护:限流查 VT 确认注入源恶意性
    void vtScanLoop();                                                 // 后台线程:逐个跑扫描
    void runVtScan(bulwark::SecurityEvent e);                          // 后台:去重->冻结->查/传->落结论
    void publishVtQueued(const bulwark::SecurityEvent& e);             // 入队即推「排队中」卡片(双击后即时反馈)
    void finalizeVtRecord(bulwark::VtScanRecord& record, const bulwark::FileReputation& rep); // 映射终态
    // persistTerminal=false:只推 UI 不落历史(命中去重收尾卡片时用——结论已在历史里,不重复落盘)。
    void publishVtRecord(const bulwark::VtScanRecord& record, bool persistTerminal = true); // 落历史 + 编组回主线程推 UI

    // 把已处置事件登记到结构化事件历史(events.jsonl,供 UI「拦截记录 / 活动日志」回填)
    // 并实时推送一条 EventLogEntry。同步派发外的路径——异步补偿处置(信誉 / AI / IP 判恶)
    // 与用户裁决——都必须经此,否则它们只发了拦截 toast、写了审计,却不会出现在拦截记录里。
    void recordEvent(const bulwark::SecurityEvent& e, bulwark::VerdictAction action,
                     bulwark::VerdictSource source,
                     bulwark::EnforcementOutcome enforcement =
                         bulwark::EnforcementOutcome::NotApplicable);
    void writeAudit(const bulwark::SecurityEvent& e, bulwark::VerdictAction action,
                    bulwark::VerdictSource source);
    QString describe(const bulwark::SecurityEvent& e, bulwark::VerdictAction action) const;
    // 某事件类型对应的防护维度是否启用(据 RuntimeSettings 的分项开关)。
    bool isDimensionEnabled(bulwark::EventType type) const;

    bulwark::engine::RuleEngine* engine_;
    IpcServer* ipc_;
    EventSource* source_ = nullptr; // 事件源(阻塞式内核驱动源需回写裁决;观测源为 no-op)
    RuleStore* ruleStore_;
    AuditLog* audit_;
    FirstSeenStore* firstSeen_;
    QuarantineManager* quarantine_ = nullptr;
    std::unique_ptr<ThreatRemediator> remediator_;
    reputation::ReputationManager* reputation_ = nullptr;
    EventHistoryStore* eventHistory_ = nullptr;          // 结构化事件历史(落库,供 UI 回填)
    std::function<int(const QVector<bulwark::DefenseRule>&)> injectIntelRules_; // 情报行为规则注入器(主线程)
    const bulwark::RuntimeSettings* settings_ = nullptr; // 实时设置(主线程只读:总开关/维度/静默)
    bulwark::engine::ProcessChainTracker chain_; // 进程链关联(溯源上下文 + 足迹清理)
    QHash<QUuid, bulwark::SecurityEvent> pending_;
    QHash<QUuid, bulwark::SecurityEvent> aiPending_; // 已请求 UI AI 研判、等待回执的事件
    Logger log_{QStringLiteral("Worker")};

    // ---- 网络外联 IP 情报互证(微步场景 API)。C# 侧内联 await(驱动挂起动作);ETW 用户态
    // 观测源只能事后观测,故改为后台限流查询、确认恶意再补偿处置(结束外联进程树)。月配额
    // 极低,仅可疑外联才查 + 7 天强缓存 + 在途去重。 ----
    struct IpJob { QString ip; bulwark::SecurityEvent e; };
    reputation::ThreatBookClient* ipIntel_ = nullptr;
    std::thread ipWorker_;
    std::atomic<bool> ipRunning_{false};
    QMutex ipMx_;
    QWaitCondition ipCv_;
    QQueue<IpJob> ipQueue_;
    QSet<QString> ipInflight_;                                             // 在途去重(ip)
    QHash<QString, QPair<bulwark::ReputationVerdict, QDateTime>> ipCache_; // 结果强缓存

    // ---- 双击 / 释放载荷 VirusTotal 病毒扫描后台 worker ----
    reputation::VirusTotalClient* vt_ = nullptr;
    VtScanHistoryStore* vtHistory_ = nullptr;
    // 多个后台扫描线程(线程池):单个未收录文件的「上传 + 轮询」最长阻塞约 4 分钟,若只有
    // 一条线程,期间其它双击文件只能在队列里干等,导致「VT 查询中」状态数分钟后才出现。用一个
    // 小线程池并行处理,长耗时上传不再饿死其它文件的状态推送。
    std::vector<std::thread> vtWorkers_;
    std::atomic<bool> vtRunning_{false};
    QMutex vtMx_;
    QWaitCondition vtCv_;
    QQueue<bulwark::SecurityEvent> vtQueue_;
    QSet<QString> vtInflight_;   // 在途去重(哈希优先,回退路径)
    QSet<QUuid> vtQueuedIds_;    // 入队时已推「排队中」卡片的扫描 id;命中去重短路时据此用缓存结论收尾该卡片

    // ---- 内存防护 VT 验证(限流) ----
    QMutex memVtMx_;                        // 保护 memVtCachedMalicious_
    reputation::TokenBucket memVtBucket_;    // MemoryProtectionVtVerifyPerHour 限流
    QSet<QString> memVtCachedMalicious_;     // 已确认恶意的哈希缓存(避免重复查)

    // ---- 兜底扫描后台 worker ----
    std::thread sweepWorker_;
    std::atomic<bool> sweepRunning_{false};
    QMutex maliciousHashMx_;                  // 保护 confirmedMaliciousHashes_
    QSet<QString> confirmedMaliciousHashes_;  // 已确认恶意 SHA-256(小写):sweep 线程只读 + 主线程写
};

} // namespace bulwark::service
