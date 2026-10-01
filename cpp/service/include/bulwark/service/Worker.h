#pragma once
#include <QObject>
#include <QHash>
#include <QUuid>
#include <QQueue>
#include <QSet>
#include <QMutex>
#include <QWaitCondition>
#include <QDateTime>
#include <QTimer>
#include <QPair>
#include <QString>
#include <QThreadPool>
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
class AlertExporter;
struct RemediationReport; // 定义在 ThreatRemediator.h;此处仅需前置声明以按 const 引用传参(.cpp 已含完整定义)
class VtScanHistoryStore;
class EventHistoryStore;
class ThreatIntelContribStore;
class AttackChainEngine;
class UserModeProcessContainment;
class SystemHardening;
namespace reputation {
class ReputationManager;
class ThreatBookClient;
class VirusTotalClient;
class ProxyReputationService;
class AggregateReputationService;
}

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

    // 注入云扫描分级链路的两个具体句柄:中央信誉代理 + 本地直连聚合器。二者都为空时,
    // 云扫描退化为「VT 按哈希查 -> 上传扫描」(仍可用,只是没有服务器优先与其他源兜底)。
    // 需要具体类型而非 IHashReputationService:分级链路要「只问服务器不回退」
    //(queryServerOnly)、「排除 VT 只查其他源」(queryExcluding)、「回传结论」
    //(maybeSyncToServer)这三个接口外的能力。
    void setCloudScanChain(reputation::ProxyReputationService* proxy,
                           reputation::AggregateReputationService* aggregate);

    // 注入威胁情报共享的本机暂存队列。为空则不收集。真正是否收集还要看运行时开关
    // cloudBehaviorUploadEnabled(默认关),故注入本身不改变默认行为。
    void setIntelContribStore(ThreatIntelContribStore* store) { intelContrib_ = store; }

    // 注入结构化事件历史存储:每条已处置事件都落库,供 UI 打开活动日志/拦截记录时回填。为空则不落库。
    void setEventHistory(EventHistoryStore* history) { eventHistory_ = history; }

    // 事件热路径上「同步云信誉查询」的等待预算(毫秒)。<=0 = 热路径一律不联网,全交后台。
    // 见 enrich 第 6 步与 ReputationManager::queryNowBounded 的说明:这个预算是整条防护链路
    // 延迟的硬上限,原实现没有它,一条事件就能把流水线堵住二十多秒。
    void setInlineReputationBudgetMs(int ms) { inlineRepBudgetMs_ = ms; }

    // 把「防护总开关」的当前值发布给后台兜底扫描线程。主线程每次应用设置后调用一次。
    // 见 sweepProtectionEnabled_ 的说明:后台线程不能直接读那个会被整体赋值的结构体。
    void publishProtectionEnabled(bool enabled) { sweepProtectionEnabled_.store(enabled); }

    // 防护待机(RuntimeSettings::protectionFollowsUi:「退出界面即停止防护」,且界面不在跑)。
    //
    // 刻意【不是】改 settings_->protectionEnabled:那个值是用户在设置页里拨的开关,是要落盘、
    // 要回显给界面的用户意图。待机是运行时状态,两者混用会造出「界面显示防护已关闭、用户却
    // 从没关过」和「待机一次就把用户的开关改掉」这两种失真。
    //
    // 待机期间 onEvent 在最前面直接返回:不富化、不评估、不处置,也【不落日志与审计】——
    // 与总开关关闭那条路径不同,那条还要把每条事件记成「放行」。待机时事件源本该已经停了,
    // 这个判据是兜住「停之前已经入队、或某个源没停干净」的残余,给它逐条记账只会污染事件历史。
    void setProtectionSuspended(bool on) { protectionSuspended_.store(on); }
    bool protectionSuspended() const { return protectionSuspended_.load(); }

    // 注入 ECS 告警导出器(appsettings 的 ExportEcsAlerts 开启时才由 main 构造并注入)。
    // 为空则不导出。此前 AlertExporter / EcsAlertFormatter / ExportEcsAlerts 三者互相引用但
    // 没有任何外部入口,整条 SIEM 导出链是死的 —— 这个 setter 是它接入产品的唯一途径。
    void setAlertExporter(AlertExporter* exporter) { alertExporter_ = exporter; }

    // 注入「情报行为规则」注入器:确认恶意后据行为画像 IOC 生成的拦截规则经此加入引擎并落盘
    // (累加去重)。返回新增规则数。由 main 在主线程侧接线(内部触碰引擎/规则库须在主线程)。
    void setIntelRuleInjector(std::function<int(const QVector<bulwark::DefenseRule>&)> fn) {
        injectIntelRules_ = std::move(fn);
    }

    // 注入攻击链组合引擎:给每个进程记「它触发过哪些动作」的账,凑齐服务器下发的某个组合即定性。
    // 为空则该能力不参与(与未启用等价)。引擎内部记账表是主线程亲和的 —— 只在 onEvent 里用。
    void setAttackChainEngine(AttackChainEngine* engine) { attackChain_ = engine; }

    // 注入用户态进程收容器(阶段 2.1/2.2/2.3)。为空则处置退化为原先的「结束进程树 + 内核补刀」,
    // 行为与注入前完全一致 —— 所以它是纯增量,不改变已有路径的默认结果。
    //
    // 它补的是两段既有实现没有的东西:
    //   · 杀之前先【冻结 + 断子】,压掉「从决定要杀到真的杀掉」之间样本还能起子进程、
    //     把自己重新拉起来的窗口;
    //   · 【杀不掉时仍然有处置】。无驱动时 banProcess 是 no-op,原先那条「已封禁主体,
    //     其行为仍被内核全维拒绝」的日志在无驱动下是假的 —— 什么都没发生。
    void setContainment(UserModeProcessContainment* c) { containment_ = c; }
    // 阶段 3 加固器。denyExecute 决定是否【加】跨重启的「拒绝执行」ACE(默认 false);
    // 【撤销】不受它约束 —— 加白对账无条件尝试移除,否则把开关关掉会让此前加上的 ACE
    // 变成谁也解不开的孤儿(它跨重启,而且卸载本产品也不会消失)。
    // regHarden 管的是「注册表反重建的用户态补位」(3.1 即时回滚 + 3.2 恶意独占键 DENY ACE)。
    // 与 denyExecute 分开是因为两者的副作用性质不同:一个改文件 ACL,一个改注册表并会自主
    // 还原别人的写入。两个都默认关,但【关掉时必须把「没做到」说出来】—— 内核那条路在无驱动时
    // 本来就是 no-op 且原先一个字不说,这才是那段代码真正的问题。
    void setHardening(SystemHardening* h, bool denyExecute, bool regHarden) {
        hardening_ = h;
        denyExecuteEnabled_ = denyExecute;
        regHardenEnabled_ = regHarden;
    }
    // 「检出即挂起」(2.3)。弹窗期间把带硬恶意指标的主体冻住,补偿无驱动时「事件到达时
    // 动作已经在发生」这一段。置 false 后该行为整项消失,与改动前逐字一致。
    void setFreezeOnDetect(bool on) { freezeOnDetect_ = on; }

    // 启动「兜底扫描」后台线程:定期枚举在跑进程,按【已确认恶意情报】(引擎记住的恶意哈希 +
    // 信誉缓存判恶意)比对,漏网的补封禁+结束+隔离 —— 防实时链路漏检(遥测丢包 / 云端确认迟到 /
    // 进程在防护启动前就在跑)。由 main 在接线完成后调用。
    void startMaliciousSweep();

    // 登记「本产品自身」的目录(安装目录 + %ProgramData%\Bulwark\),供兜底扫描与
    // 「拦截时隔离」的免扫判定使用。
    //
    // 【为什么必须由 main 显式登记,而不是在函数里判断名字】原实现用 path.contains("bulwark")
    // 判定「是不是本产品」,于是任何路径里带这个子串的文件都免于兜底扫描与隔离 —— 建一个
    // 名叫 bulwark 的目录就能让样本躲过最后一道网。真实路径只有 main 知道,所以只能由它传进来。
    static void setSelfExemptDirs(const QStringList& dirs);

    // 手动强制隔离某文件(UI 在清理报告里点「重试隔离」)。
    // 转发到 ThreatRemediator::forceQuarantine —— 那个方法原本无人调用,而 main 里另写了一份
    // 逐行相同的逻辑,是纯重复实现。统一走这里,隔离动作只有一份代码、日志口径也一致。
    std::pair<bool, QString> forceQuarantine(const QString& path);

    // 清理一条自启动持久化项(UI 在自启动项页显式点击 -> IPC -> 此处)。
    //
    // 走 Worker 而不是让 main 自己建一个 ThreatRemediator:隔离区、清理器、内核注册表反重建
    // (applyRegHardening)本来就都挂在 Worker 上,另建一份会出现两个 QuarantineManager 视图、
    // 也拿不到内核硬拦下发通道。必须在主线程调用(触碰隔离区与内核下发)。
    bulwark::ipc::PersistenceCleanupResultPayload cleanupPersistence(
        const bulwark::ipc::PersistenceCleanupRequestPayload& req);

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

    // 加白后撤销释放物污点:删掉「主体路径已被加白」的污点规则并落盘。
    //
    // 可执行体污点靠管线第 1 步(用户信任早于显式规则)天然可撤销;但模块污点
    // (ImageLoad 规则,主体是宿主进程、目标才是 DLL)与脚本污点(按命令行匹配)
    // 在「只加白 DLL / 脚本本身」时不会被第 1 步盖住。故加白后显式清一遍。
    // 须在主线程调用(触碰引擎规则集与规则库),由 main 的 trustAddedHook 触发。
    void purgeTaintRulesAfterTrust();

private slots:
    void onEvent(const bulwark::SecurityEvent& e);
    void onPromptResponse(const QUuid& eventId, bulwark::VerdictAction action,
                          bool remember, bulwark::RememberScope scope);
    // 弹窗超时巡检(每秒):把超过 promptTimeoutSeconds 仍未回执的待裁决事件按默认策略收尾。
    void onPromptTimeoutTick();

private:
    // 按 PID 回填签名/发布者/哈希/证书画像/命令行/父路径/首见等,供规则引擎裁决。
    void enrich(bulwark::SecurityEvent& e);
    // 用 OS API 回溯完整父进程祖先链,种入 e.chainContext(即便跟踪器无历史也保证溯源完整)。
    void seedAncestryChain(bulwark::SecurityEvent& e);
    // 拦截的实际执行,并【返回真实结果】。内核已前拦的事件(kernelBlocked)直接如实返回
    // KernelBlocked 不再补杀;观测型事件(动作已发生)结束作恶进程树(带关键进程防护),对侧载
    // 模块额外加入内核禁止加载名单。返回值供 UI 如实显示处置,杜绝假拦截。
    //
    // persistentBlacklist=false 时【跳过】两份会被内核写回注册表、跨重启续拦的持久名单
    // (禁止执行 / 禁止加载),只做当次可逆处置(结束进程树 + 运行期封禁 PID)。
    // 用于「并非已确认恶意、只是按策略拦这一次」的路径(弹窗超时兜底)。
    // 这类路径若也钉进内核名单,等于用户离开键盘一会儿,就把正常程序永久拦死 ——
    // 而协议上没有「删除单条」,只能整表清空重下发,代价极不对称。
    bulwark::EnforcementOutcome enforceBlock(const bulwark::SecurityEvent& e,
                                            bool persistentBlacklist = true);
    // 恶意进程终结:用户态结束进程树 + 驱动级(内核 ZwTerminateProcess)兜底补刀(难被反杀)。
    // 返回是否已结束。关键系统进程由内核+用户态双重护栏保护。
    bool killMalicious(int pid);
    // killedByUs_ 的写入口 / 查询口(该成员的设计理由见其声明处)。
    // 查询要求 pid 与映像路径【都】对上且在时间窗内 —— 只对 PID 会因 PID 复用认错进程。
    void rememberTerminated(int pid, const QString& imagePath);
    bool wasTerminatedByUs(int pid, const QString& imagePath) const;
    // 执行前拦截:把已确认恶意进程的映像路径加入内核「禁止执行」名单(与 killMalicious 配对)——
    // kill 收拾正在运行的实例,exec-block 挡住其(被守护进程/持久化/重启后规则命中拉起时)再次启动。
    // 仅对确认恶意的可执行主体调用(信誉/规则确认的进程创建),不对网络外联发起进程调用(可能是合法程序)。
    // 下发【盘符无关】的路径子串以兼容内核收到的 \??\C:\... 与 \Device\HarddiskVolumeN\... 两种映像路径形式。
    //
    // 【返回值】true = 该映像现在【确实处于禁止启动状态】(内核禁止执行名单受理成功,
    // 和/或文件上已有「拒绝执行」ACE)。enforceBlock 需要它:两道护栏(已加白 / 系统目录)
    // 与过短子串都会让本函数什么都不做,那种情况下不能对用户声称「下次启动会被拦」。
    bool blacklistExec(const QString& imagePath);
    // 执行前拦截的【可撤销版本】:只加文件 DACL 的「拒绝执行」ACE,不碰任何内核名单。
    //
    // 【为什么必须单独有这一条】命中「[污点-释放物]」规则的 Block 刻意不走 blacklistExec ——
    // 污点是「和某次拦截有关联」推出来的,不是对这个文件本身的确认,所以不能进只加不减、
    // 跨重启由内核独立续拦的 FileExecBlock(理由见 onEvent 的 Block 分支)。但原先的结果是
    // 这类拦截【一点执行前拦截都没有】:实测双击 14 个污点兄弟文件,每一个都先跑起来
    // 1-3 秒、干完释放/写注册表/外联再被 kill,只有唯一那个被云端哈希确认恶意的样本
    // (走 blacklistExec)真正没起来。
    //
    // 拒绝执行 ACE 恰好补上这个缺口而不破坏污点的语义:
    //   · 可撤销 —— 用户加白后由 reconcileKernelBlocksAfterTrust 的 ①c 段移除(那一段刻意
    //     不看 denyExecuteEnabled_,所以关掉开关也仍然能解);
    //   · 按文件不按路径 —— 不会像子串名单那样牵连无关进程;
    //   · 只拒执行、不拒读 —— 我们自己的金库拷贝 / 取哈希 / 删除照常(这是它比 share-mode-0
    //     独占句柄严格更好的地方)。
    // 诚实的边界两条,都必须随功能一起说出来:① 复制一份副本即可绕过(ACE 不被副本继承);
    // ② 污点规则 30 天到期,而 ACE 不会自己到期 —— 撤销入口只有加白。
    //
    // 【返回值】true = 该映像现在起不来了(本次刚加上 ACE,或先前已加过)。
    // 这个返回值是必需的,不是锦上添花:实测 2026-09-30 21:45,一次污点命中【成功加上了】
    // 跨重启的拒绝执行 ACE,但紧随其后的 killMalicious 因为进程已不在快照里而失败,
    // enforceBlock 于是返回 AlertedOnly(「未做任何实际阻断」)—— 右下角弹出「检测到危险行为,
    // 未能拦截」、语音念「请手动处理」。我们刚刚做成的那件事被自己否认了。
    bool denyExecuteRevocable(const QString& imagePath, const QString& why);
    // 延迟处置前复查加白:后台补偿路径(外部信誉 / VT / 微步 IP / 兜底扫描)在事件求值
    // 【之后】才回执,那时 e.userTrusted 只是旧快照 —— 期间用户完全可能刚把该程序加白。动手前
    // 重查一次,命中就放弃本次处置并记一条日志。返回 true = 已加白,调用方应立即 return。
    // 不这么做的话,「加白之前排队的扫描」回来照样结束进程,还会顺手把路径钉进内核禁运名单。
    bool abortIfTrustedNow(const bulwark::SecurityEvent& e, const QString& stage);
    // 「拦截时一并隔离主体载荷」(RuntimeSettings::quarantineOnBlock)。带加白 / 系统目录 /
    // 健康签名三道护栏,详见 .cpp。此前该设置项在服务端与 UI 都无任何消费点。
    void maybeQuarantineOnBlock(const bulwark::SecurityEvent& e);
    // 持久化反重建:把本次清理产出的 hardenedRegTargets(已清掉的恶意自启动项)去重+长度护栏后
    // 下发内核注册表硬拦,使恶意软件无法立刻重建刚被清掉的持久化(补「清理→守护进程秒级重写」竞态)。
    void applyRegHardening(const RemediationReport& report);
    // 对确定性恶意(命中规则 / 启发式)的进程主体:隔离磁盘载荷 + 清除自启动持久化。
    void remediateIfMalicious(const bulwark::SecurityEvent& e, const bulwark::Verdict& v);
    // 本次 Block 是否「确定性恶意」(引擎自判)。写类事件(FileWrite / RegistryWrite)额外要求
    // 硬指标或情报/污点规则 —— 那两类最常见的 Block 规则是「保护某个目标」,拦的是动作,
    // 不代表发起方恶意,不能因此去清它的足迹、标它的释放物。
    static bool isDeterministicMaliciousBlock(const bulwark::SecurityEvent& e, const bulwark::Verdict& v);
    // 硬指标子进程被确认恶意拦下时,一并处置那个【把它派生出来的】进程。
    //
    // 【原实现错在哪】enforceBlock 结束的是 `originatorPid > 0 ? originatorPid : actorPid`,
    // 而 ProcessCreate 事件的 actor 是【新建的那个子进程】(语义见 RuleDsl.h 头部的事件表)。
    // 于是样本派生 vssadmin.exe / comsvcs.dll 被拦时,死的是那个系统程序 —— 样本本体照常
    // 继续跑,下一秒再派生一次;足迹清理的对象也成了那个系统程序,又会被 isSafeToRemove 的
    // 系统目录护栏整批跳过,等于一次都没清。
    //
    // 只在 onEvent 的 Block 分支里、isDeterministicMaliciousBlock 为真时调用(与
    // taintDroppedFiles 同一道闸)。【刻意不接】onPromptResponse 与 resolvePromptByDefault:
    // 用户裁决与超时兜底都不是「引擎确认恶意」,拿它们去连带处置一个【没有被直接判过】的
    // 进程,推理链两头都不成立。
    // 护栏与 blacklistExec 的取舍见 .cpp 实现处。
    void maybeHandleLaunchingParent(const bulwark::SecurityEvent& e);
    // 用户在弹窗点「阻止」后的足迹清理。remediateIfMalicious 刻意拒绝 UserPrompt 来源,这里
    // 另开一条:用户是显式选择,隔离又是可还原的,所以可以做;落地区 + 签名护栏全部保留。
    void remediateOnUserBlock(const bulwark::SecurityEvent& e);
    // 足迹清理结果的统一出口:service.log + UI 实时日志 + 「清理报告」+ 审计(action=Remediate)。
    void publishRemediation(const bulwark::SecurityEvent& e, const RemediationReport& report,
                            const QString& reason, bulwark::VerdictSource source);

    // ---- 释放物污点(dropped-file taint)----
    //
    // 拦截只处理主体进程本身;它被拦之前释放的文件,之后运行时和这次拦截毫无关联(引擎从零评估,
    // 未签名/首见只是软信号 → 放行)。银狐这类投递链(安装包/dropper 落一批白加黑 + 载荷)正是
    // 从这里漏掉的。污点标记把「被拦」这件事传给它的释放物:
    //   · 候选 = 被拦主体(及后代)写过的文件 ∪ 「写出被拦主体的那个 dropper」同批写出的文件;
    //   · 载体是用户态 DefenseRule(不是内核名单):用户加白一定能撤销,且有到期时间;
    //   · 分级【逐条】而不是整批:
    //       - 被拦主体(及后代)亲手写出来的、以及未签名的 dropper 自身 → 跟随 grade
    //         (确定性恶意 = Block + hardOverride,30 天);
    //       - 只是和它同一批被【第三方】写出来的兄弟文件(压缩软件 / 浏览器 / 安装器解包出来的)
    //         → 一律降为 Ask(7 天)。「和恶意文件同一次解包」是一条关联,不是对这个文件的判定;
    //         原来两者共用 grade,结果一个压缩包里混进一份恶意样本就会让同目录其它文件全部被
    //         结束进程 + 隔离 + 加上跨重启拒绝执行 ACE(见 TaintResult::byAssociation 的实测记录)。
    //       - 用户点阻止 / 超时兜底 → Ask(7 天),与原来一致;
    //   · 护栏:已加白 / 系统目录与本产品 / 不在落地区 / 带可信签名(除非哈希已确认恶意)一律跳过,
    //     单次最多 kTaintMaxPerBlock 条、总量最多 kTaintMaxTotal 条(超出淘汰最旧的污点规则);
    //   · 命中污点规则的拦截绝不下发内核 FileExecBlock / FileNoLoad(见 onEvent)。
    // grade 只接受 Block / Ask。候选收集在主线程;验签 + SHA-256 在 taintPool_ 后台跑,
    // 算完编组回主线程注入(injectIntelRules_ 只能在主线程调)。
    void taintDroppedFiles(const bulwark::SecurityEvent& e, bulwark::VerdictAction grade,
                           const QString& why);
public:
    // 污点规则 note 的统一前缀,也是识别 / 去重 / 整批撤销的唯一依据。
    static QString taintRuleTag();
    static bool isTaintRuleNote(const QString& note);
private:
    // 用户对一条「命中污点规则」的询问点了放行:删掉命中本事件的污点规则(用户已亲自判过)。
    // 否则用户的「记住放行」规则与污点 Ask 规则同层同具体度,按动作强度 Ask 反而压过 Allow。
    void dropTaintRulesMatching(const bulwark::SecurityEvent& e);
    // 规则库里污点规则总量超限时,按创建时间淘汰最旧的,腾出 incoming 条的位置。返回删除条数。
    int evictOldTaintRules(int incoming);
    QThreadPool taintPool_;   // 污点候选的验签 + 哈希(磁盘 IO / WinVerifyTrust,不上主线程)
    // 后台线程:确认恶意后顺带拉取样本行为画像(VT 沙箱报告),再编组回主线程处置。
    void confirmReputationMaliciousAsync(const bulwark::SecurityEvent& e, const bulwark::FileReputation& rep);
    // 后台信誉查询确认恶意时的主线程处置(结束进程 + 隔离 + 清除持久化 + 据画像清释放物/注规则 + 告警)。
    void onReputationMalicious(const bulwark::SecurityEvent& e, const bulwark::FileReputation& rep,
                               const bulwark::ThreatBehaviorProfile& profile = {});

    // ---- 兜底扫描(catch-all sweep):防漏检的最后一道网 ----
    void sweepLoop();                                                     // 后台线程主体
    void handleSweptMalicious(const bulwark::SecurityEvent& e, bulwark::VerdictSource source); // 主线程处置
    void rememberMaliciousHash(const QString& sha256);                    // 线程安全登记已确认恶意哈希(小写)
    void seedMaliciousHashesFromRules();                                  // 启动时从引擎规则 seed(含持久化记忆哈希)
    static bool isSweepExemptPath(const QString& path);                   // 系统目录/本软件 -> 免扫
    // 免扫目录集合(安装目录 + 数据目录),由 main 启动时登记。static 是因为 isSweepExemptPath
    // 本身是 static(sweep 线程与 maybeQuarantineOnBlock 都要用它,且不持有 Worker 实例)。
    static QStringList s_sweepExemptDirs;
    static QMutex s_sweepExemptMx;

    // 网络外联 IP 情报互证(后台限流查询 + 恶意即补偿):合格外联入队 -> 后台查微步 IP 信誉 ->
    // 确认恶意再编组回主线程做补偿处置(结束外联进程树)。仅可疑外联才查(保护极低月配额)。
    void maybeQueryEgressIp(const bulwark::SecurityEvent& e);
    void ipConsumeLoop();
    void onEgressMalicious(const bulwark::SecurityEvent& e, const QString& ip, const QString& label);
    static QString extractRemoteIpv4(const QString& target); // "ip"/"ip:port" -> IPv4;非 IPv4 返回空
    static bool isPrivateOrReserved(const QString& ipv4);     // 私网/环回/保留:不查云端情报

    // ---- 侧载模块篡改检测(「白加黑」)---------------------------------------
    // 主体目录内是否存在「内嵌厂商签名但校验不过」的模块。命中即写
    // e.tamperedModulePath,由 ThreatDetector 记为硬指标(见该字段的说明)。
    // 只在主体位于【非标准安装目录】时才扫,结果按目录缓存 —— 详见实现处的成本说明。
    void detectSideloadedTamperedModule(bulwark::SecurityEvent& e);
    // 一次目录扫描的结论(两种侧载形态各一个字段,都空 = 扫过且干净)。
    struct SideloadScan {
        QString tamperedPath;   // 形态 1:内嵌签名校验不过的模块
        QString unsignedPath;   // 形态 2:未签名 + 已互证的模块
        QString unsignedWhy;    // 形态 2 的互证理由
    };
    // 「目录|目录mtime」-> 扫描结论。避免每 19 分钟拉起一次就重扫一遍;键里带 mtime 是为了
    // 让「先扫过干净、之后才放进来的黑件」能被重新发现(详见实现处第 5 条)。
    QHash<QString, SideloadScan> tamperScanCache_;

    // ---- 脚本文件正文扫描 ------------------------------------------------------
    // 宿主(cmd/powershell/wscript/cscript/mshta)要执行的脚本文件,读正文跑判据。
    // 结论写 e.scriptFile*,由 ThreatDetector 消费(见那些字段的说明)。
    // 有界:正文只读前 256KB;仅超大 WSH 脚本才为结构统计再完整流式读一遍。
    void scanScriptFileBody(bulwark::SecurityEvent& e);
    // 一次正文扫描的结论(与 ScriptAnalyzer::FileScan 一一对应,拆成可缓存的小结构)。
    struct ScriptBodyScan {
        int score = 0;
        bool hard = false;
        QStringList hits;
        QStringList reasons;
    };
    // 「脚本路径|大小|mtime」-> 扫描结论。同一个脚本被反复拉起(计划任务、循环调用)
    // 是常态,键里带大小与 mtime 才能在脚本被改写后重新扫。与 tamperScanCache_ 同策略:
    // 超过上限整体清空,不做 LRU —— 简单且上限明确。
    QHash<QString, ScriptBodyScan> scriptBodyCache_;

    // ---- 双击 / 释放载荷 VirusTotal 病毒扫描(后台上传扫描 + 恶意即补偿)----
    // 用户双击启动或释放器派生的可疑新样本:后台先按哈希查 VT,未收录则上传整文件云端多引擎
    // 扫描,进度经 sendVtScanUpdate 推 UI 卡片、结果落 VtScanHistoryStore 去重;确认恶意再补偿
    // 结束进程树(复用 onReputationMalicious)。C# 侧内联 await(驱动挂起动作),此处改后台。
    bool shouldCloudScan(const bulwark::SecurityEvent& e); // 这次进程创建是否值得送云查杀
    bool isDoubleClickLaunch(const bulwark::SecurityEvent& e) const;
    bool isDropperSpawnedPayload(const bulwark::SecurityEvent& e) const;
    bool isRecentlyDroppedExecutable(const bulwark::SecurityEvent& e); // 用 chain_.wasRecentlyWritten
    void maybeScanDoubleClick(const bulwark::SecurityEvent& e);        // 合格进程创建入队后台扫描
    void maybeScanInstallerPackage(const bulwark::SecurityEvent& e);  // 双击 MSI/MSP:扫描安装包本身(msiexec 仅宿主)
    void maybeScanDroppedInstaller(const bulwark::SecurityEvent& e);  // 落盘即扫:写入用户目录的安装包/可执行体送 VT(PID 清零,只隔离不杀进程)
    void maybeVerifyMemoryInjection(const bulwark::SecurityEvent& e); // 内存防护:限流查 VT 确认注入源恶意性
    void vtScanLoop();                                                 // 后台线程:逐个跑扫描
    void runVtScan(bulwark::SecurityEvent e);
    // 威胁情报共享:把一次云查杀确认的「病毒信息 + 行为数据」脱敏后存入本机暂存队列,
    // 等夜间上传。仅在开关开启且判定为恶意/可疑时收集;脱敏与筛选由 ContribStore 执行。
    // 在后台线程调用(不碰 Qt 对象)。
    void retainThreatIntel(const bulwark::FileReputation& rep,
                           const bulwark::ThreatBehaviorProfile& profile);                          // 后台:去重->冻结->查/传->落结论
    void publishVtQueued(const bulwark::SecurityEvent& e);             // 入队即推「排队中」卡片(双击后即时反馈)
    void finalizeVtRecord(bulwark::VtScanRecord& record, const bulwark::FileReputation& rep); // 映射终态
    // persistTerminal=false:只推 UI 不落历史(命中去重收尾卡片时用——结论已在历史里,不重复落盘)。
    void publishVtRecord(const bulwark::VtScanRecord& record, bool persistTerminal = true); // 落历史 + 编组回主线程推 UI

    // 把已处置事件登记到结构化事件历史(events.jsonl,供 UI「拦截记录 / 活动日志」回填)
    // 并实时推送一条 EventLogEntry。同步派发外的路径——异步补偿处置(信誉 / IP 判恶)
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
    UserModeProcessContainment* containment_ = nullptr;  // 进程收容/冻结/断子(可为空)
    bool freezeOnDetect_ = true;                         // 2.3 检出即挂起(部署可关)
    SystemHardening* hardening_ = nullptr;               // 阶段 3 加固器(可为空)
    bool denyExecuteEnabled_ = false;                    // 3.5 是否加跨重启 ACE(撤销不受此约束)
    bool regHardenEnabled_ = false;                      // 3.1/3.2 注册表反重建的用户态补位
    std::unique_ptr<ThreatRemediator> remediator_;
    reputation::ReputationManager* reputation_ = nullptr;
    EventHistoryStore* eventHistory_ = nullptr;          // 结构化事件历史(落库,供 UI 回填)
    AlertExporter* alertExporter_ = nullptr;             // ECS/SIEM 告警导出(可空 = 未启用)
    std::function<int(const QVector<bulwark::DefenseRule>&)> injectIntelRules_; // 情报行为规则注入器(主线程)
    const bulwark::RuntimeSettings* settings_ = nullptr; // 实时设置(主线程只读:总开关/维度/静默)
    bulwark::engine::ProcessChainTracker chain_; // 进程链关联(溯源上下文 + 足迹清理)
    int inlineRepBudgetMs_ = 800;                // 热路径同步云查的等待预算(见 setter 说明)

    // ---- 本产品自己结束过的进程(PID -> {映像路径, 结束时刻})----
    //
    // 【为什么需要】事件源到裁决之间有延迟(驱动/ETW 队列 + 云查回执),所以同一个主体被结束
    // 【之后】,它生前排队的其它动作还会继续走完整条流水线。那些事件的 killMalicious 必然失败
    // (进程真的没了),而原先这一律落 AlertedOnly ——「未做任何实际阻断,需要人工关注」。
    // 实测(service.log,2026-09-30):21:46:39.119 结束 PID=23676,3.45 秒后同一 PID 的
    // ImageLoad(%TEMP% 侧载)走完流水线,于是弹出第二条「检测到危险行为,未能拦截」+
    // 语音「请手动处理」—— 而那个威胁三秒前就已经被我们杀掉了。让用户去手动处理一个
    // 已经不存在的进程,和漏报一样有害:它会训练用户无视这条通知。
    //
    // 键里【必须带映像路径】:本项目没有进程退出事件,PID 会被复用(ProcessChainTracker.h
    // 第 48-62 行有完整说明)。只按 PID 认的话,将来某个无辜进程会被当成「我们杀过的那个」,
    // 它的危险行为于是被说成「已处置」—— 那个方向比谎报未拦截更坏。
    //
    // 生命周期:kKilledMemoryTtlSecs 内有效(只用于消化同一波排队事件,不需要长期记忆),
    // 条数上限 kKilledMemoryMax,写入时顺带按时间清理 —— 不引入定时器。
    static constexpr int kKilledMemoryTtlSecs = 300;
    static constexpr int kKilledMemoryMax = 256;
    QHash<int, QPair<QString, QDateTime>> killedByUs_;

    // ---- 待用户裁决的事件 ----
    //
    // 【为什么必须带截止时间并在服务端超时】原实现只有 insert(onEvent)与用户回执时的 erase,
    // 既无上限也无超时,于是:
    //   * UI 未启动 / 已退出 / 崩了 / 用户就是不点 -> 条目永久滞留。每条 SecurityEvent 带完整
    //     证据链与进程链上下文,不是小结构,属于单向增长的泄漏(没有任何上限护栏);
    //   * 配置项 PromptTimeoutSeconds 与 RuntimeSettings::defaultBlock 在服务端【从未被使用】,
    //     超时兜底只存在于 UI 的 PromptDialog 倒计时里 —— 也就是说 UI 不在场时根本没有兜底;
    //   * 枚举值 VerdictSource::Timeout 全仓仅出现在 RuleEngine 的显示文案 switch 中,
    //     从未被产生过,是个永远走不到的分支。
    // 现在由服务端自己按截止时间收尾,上述三点一并落地:UI 在不在场都有确定性的兜底行为。
    struct PendingPrompt {
        bulwark::SecurityEvent event;
        QDateTime deadlineUtc;   // 无效 = 不超时(promptTimeoutSeconds <= 0,等用户点到底)
    };
    QHash<QUuid, PendingPrompt> pending_;
    QTimer* promptTimer_ = nullptr;                  // 每秒巡检 pending_ 的截止时间
    // 按默认策略(defaultBlock ? Block : Allow)收尾一条待裁决事件,来源标 Timeout。
    // 供超时巡检与超量驱逐共用,保证两条路径的处置与记录完全一致。
    void resolvePromptByDefault(const bulwark::SecurityEvent& e, const QString& why);

    Logger log_{QStringLiteral("Worker")};

    // ---- 零风险放行的文本日志折叠 ----
    //
    // 【起因·实测】共存放行的第三方安全软件会产生极高频的临时文件行为:火绒 HipsDaemon 每秒
    // 几十次创建/删除 C:\Windows\Temp\swapfs-*。这些事件在管线第 2 步(已安装安全软件共存放行)
    // 就被判成 Allow / 风险 0,没有任何调查价值,但每一条都照写 service.log 与 UI 实时日志。
    // 后果不是「日志变长」而是【日志失效】:5MB 的滚动上限几秒钟就被刷满,启动过程、驱动握手、
    // 真实告警全部被挤出文件 —— 出问题时最需要的那几行恰好永远读不到。
    //
    // 【折叠条件】只在完全没有调查信号时生效:Allow + 风险 0 + 无硬指标 + 未命中规则。
    // 首次出现整条记录,窗口内的重复只累加计数,窗口结束补一条带次数的汇总。于是:
    //   · 换主体、换事件类型、风险非 0、命中任意规则 —— 任一项变化都立刻整条记录,
    //     攻击者无法把一个新行为藏在别人的折叠窗口后面;
    //   · churn 规模仍然可查(汇总行带条数与窗口长度),信息是被压缩而不是被丢弃。
    //
    // 【刻意不折叠的】结构化事件历史(recordEvent)与审计日志(writeAudit)仍逐条完整落盘:
    // 前者是 UI 统计与「活动日志」回填的数据源,折叠会让 ALLOWED 计数变小;后者是取证/合规
    // 轨迹,悄悄变稀不可接受。本折叠只作用于两个纯文本滚动面:service.log 与 UI 实时日志。
    struct AllowBurst {
        qint64  firstMs = 0;  // 本窗口首条的时间戳
        quint32 folded  = 0;  // 窗口内被折叠掉的条数(不含首条)
    };
    static constexpr qint64 kAllowFoldWindowMs = 60000; // 折叠窗口:60 秒
    static constexpr int    kAllowFoldMaxKeys  = 512;   // 有界上限,超出即整表清空
    QHash<QString, AllowBurst> allowBursts_;
    // 返回 true = 本条应写入文本日志;false = 已折叠(仅累加计数)。
    // 若上一窗口刚到期且有折叠积压,汇总文本写入 summaryOut(调用方先落汇总再落本条)。
    bool shouldLogAllow(const bulwark::SecurityEvent& e, bulwark::VerdictAction action,
                        QString* summaryOut);

    // 攻击链组合引擎(可空 = 不参与)。仅在 onEvent 主线程路径上使用。
    AttackChainEngine* attackChain_ = nullptr;

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
    // ipCache_ 的上限。TTL 只在【读】的时候判,过期条目从不被删除,所以没有这道闸时这张表
    // 是单调增长的(旁边的 ipQueue_/vtQueue_ 都有 kIpQueueMax/kVtQueueMax,只有它漏了)。
    // 长时间运行 + 外联目标多的机器上,这就是一处稳定的内存泄漏。
    static constexpr int kIpCacheMax = 4096;
    void pruneIpCacheLocked();   // 调用方须已持有 ipMx_

    // ---- 双击 / 释放载荷 VirusTotal 病毒扫描后台 worker ----
    reputation::VirusTotalClient* vt_ = nullptr;
    VtScanHistoryStore* vtHistory_ = nullptr;
    // 云扫描分级链路句柄(可空 = 该级跳过):服务器优先查 + 排除 VT 的其他源兜底 + 结论回传。
    reputation::ProxyReputationService* repProxy_ = nullptr;
    reputation::AggregateReputationService* repAggregate_ = nullptr;
    // 威胁情报共享的本机暂存队列(可空 = 功能未接入)。是否真的收集由运行时开关
    // cloudBehaviorUploadEnabled 决定(默认关);夜间上传由 ThreatIntelUploader 负责。
    ThreatIntelContribStore* intelContrib_ = nullptr;
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
    static constexpr int kMemVtCacheMax   = 1024; // 已确认恶意哈希缓存上限
    static constexpr int kMemVtCacheEvict = 128;  // 超限时一次淘汰多少条(最早进来的)
    QMutex memVtMx_;                        // 保护 memVtCachedMalicious_ / memVtCacheOrder_
    reputation::TokenBucket memVtBucket_;    // MemoryProtectionVtVerifyPerHour 限流
    QSet<QString> memVtCachedMalicious_;     // 已确认恶意的哈希缓存(避免重复查)
    // 插入顺序台账。QSet 自身没有顺序(Qt6 每进程随机化桶序),没有这份台账就做不到
    // 「淘汰最早的」—— 原实现从 begin() 删 N 条,删掉的是任意一批,可能正是刚确认的那条。
    QQueue<QString> memVtCacheOrder_;

    // ---- 兜底扫描后台 worker ----
    std::thread sweepWorker_;
    std::atomic<bool> sweepRunning_{false};
    // 总开关的【无锁镜像】,供 sweep 线程读取。
    //
    // sweepLoop 原先直接读 settings_->protectionEnabled。settings_ 指向 main 里的那个
    // RuntimeSettings,而主线程在 ipc.settingsUpdated 里对它整体赋值(settings = updated)。
    // RuntimeSettings 内含 QString / QStringList,整体拷贝赋值不是原子操作 —— 与后台线程
    // 的并发读构成实打实的数据竞争(读到半更新的 QString 内部指针即崩溃或读脏)。
    // 主线程每次应用设置时调 publishProtectionEnabled(),后台线程只读这个 atomic。
    std::atomic<bool> sweepProtectionEnabled_{true};
    // 待机标志(见 setProtectionSuspended)。主线程写、onEvent(主线程)与 sweep 线程读,故同样是 atomic。
    std::atomic<bool> protectionSuspended_{false};
    QMutex maliciousHashMx_;                  // 保护 confirmedMaliciousHashes_
    QSet<QString> confirmedMaliciousHashes_;  // 已确认恶意 SHA-256(小写):sweep 线程只读 + 主线程写
};

} // namespace bulwark::service
