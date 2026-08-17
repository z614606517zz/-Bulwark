#pragma once
#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/service/Logger.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/SecurityEvent.h"

#include <QDateTime>
#include <QHash>
#include <QJsonObject>
#include <QMutex>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVector>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>

// 攻击链组合引擎(客户端侧)。
//
// 与「按文件认病毒」的思路互补:本引擎认的是【一串动作】。中央服务器从每日采集的真实样本
// 沙箱记录里数出「哪几个动作凑在一起就是病毒」(见 server/bulwark-intel/engine_build.py),
// 客户端下载这张组合表,给每个进程记账 —— 它到目前为止触发过哪些动作标记,凑齐某个组合即定性。
//
// 为什么需要它:引擎原本是【一条事件一条事件单独判】的。「写 Run 键」正常安装程序也干、
// 「落个 exe」也干、「加 Defender 排除项」单独看也还不够定性 —— 于是三件事各自被放过,
// 而它们【同时出现在一个进程身上】时其实已经足以定性。本引擎补的正是这个「把证据攒起来」的能力。
//
// 三个刻意的设计:
//   1. 匹配复用 DefenseRule —— 服务器下发的条件字段(actor/target/cmdline/parent/unsigned)
//      与 DefenseRule 同名同义,故直接构造一条「只含条件」的 DefenseRule 当匹配器,
//      不再写第二套通配匹配逻辑(也就不会与主引擎的匹配语义跑偏)。
//   2. 不改裁决流程,只【喂证据】。命中组合时写入 evidence + 提分 + 置硬指标,由既有裁决
//      流水线自己得出结论。因此用户信任 / 自身组件 / 已装杀软那几道放行通道仍在本引擎【之前】
//      生效 —— 组合命中绝不会越过它们,这是误报控制的关键一环。
//   3. 默认 dry-run(只记录不影响裁决)。库里全是恶意样本、没有正常文件作对照,所以先在真机上
//      观察几天有没有冤枉正常软件,确认后再开强制。
namespace bulwark::service {

// 一个行为标记:服务器下发的「一个可观测动作」的定义。
struct ChainMarker {
    QString id;                     // 稳定标记 ID(服务器生成)
    QString title;                  // 可读标题(原 Sigma 规则名),写进证据链给人看
    QString level;                  // medium / high / critical
    bulwark::DefenseRule matcher;   // 只含条件的规则,直接用 matches() 判定

    // ---- 「不含」条件 -------------------------------------------------------
    //
    // 为什么必须有它:一整类 Sigma 规则的信号是【缺少某个东西】,而 DefenseRule 只能
    // 表达「含有」。最典型的是 "Uncommon Svchost Command Line Parameter" —— 真正的
    // svchost 永远由 services.exe 带 `-k <组名>` 启动,该规则命中的正是【没有 -k】的
    // 那种。服务器此前只能下发肯定的那一半(actor=*\svchost.exe),而那一半在 Windows 上
    // 恒真:实测 v19 的 26 条装载组合里有 12 条依赖它,等于「一个动作 + 一个恒真项」
    // 冒充互证,而组合命中在强制模式下是按【硬指标】登记的。
    //
    // 刻意【不】改 DefenseRule 加字段:那个结构体被主规则引擎共用、还要落盘序列化,
    // 为攻击链一个用途去动它,风险远大于在这里多两个判断。通配匹配仍复用
    // DefenseRule::wildcardMatch(它已是 public static),因此语义与主引擎不会跑偏。
    QString cmdlineAbsent;          // 命令行【不得】命中此通配式,空=不限
    QString targetAbsent;           // 目标【不得】命中此通配式,空=不限
    QString parentAbsent;           // 父进程【不得】命中此通配式,空=不限

    // 完整判定 = matcher.matches() 且全部「不含」条件都不命中。
    //
    // 单独提供这个方法而不是让调用方各自补两行:标记匹配有两个调用点(observe 的热路径
    // 与 selfTest 的合成事件),漏掉任何一处都会让「不含」条件静默失效 —— 而那种失效
    // 的表现恰好是「规则变宽」,也就是误报,最不容易被发现的方向。
    bool matchesEvent(const bulwark::SecurityEvent& e) const;
};

// 一条攻击链组合:这些标记同时出现即定性。
struct ChainPattern {
    QStringList markers;   // 标记 ID(已排序)
    int support = 0;        // 有多少真实样本作证(恶意侧)
    QString grade;          // 【生效】强度:hard / strong / ask,可能已被本机降档
    // 服务器下发的原始强度。降档【必须】从它算,不能就地改 grade ——
    // 否则 setCoverage / applyTable 重复调用会把同一条组合一路降到底(hard->strong->ask)。
    QString serverGrade;
    // 这条组合在【正常软件语料】里出现过几次。服务器一直在下发(engine_patterns 的
    // benign_support),此前客户端解析时直接丢掉了。现在用作独立于服务端封顶的第二道保险:
    // 服务端语料不足 BENIGN_MIN_CORPUS(50)时它那边整个区分度环节是空转的,
    // 而这个数字本身照样有值,客户端据此仍能把「正常软件里见过」的组合压住。
    int benignSupport = 0;
    // 降档原因(可读)。空 = 未降档。写进证据链 —— 否则服务器页面上显示 hard、
    // 端点上却只是询问,看的人无从解释这个差异。
    QString capReason;
    QString maxLevel;       // 组合内最高严重度
    QString families;       // 常见家族(展示用)
    // 「本进程已报过这条组合」的去重键,装载时算一次(= markers 以 '|' 连接)。
    //
    // 刻意用【内容】而不是 patterns_ 里的下标:记账(ledger_)要跨越组合表更新继续存活,
    // 而表一换下标就全部错位 —— 那会让「已报过」指向另一条组合,同一条链既可能重复刷屏、
    // 也可能被永久静音。放在这里预先算好,是为了不在每次「组合凑齐」判定里现拼字符串。
    QString key;
};

// 组合命中结果。
struct ChainHit {
    ChainPattern pattern;
    QStringList titles;     // 组合内各动作的可读标题(按 markers 顺序)
};

// 一条命中记录(供 UI「攻击链」页面展示)。
//
// 与 evidenceChain 分开存:证据链是挂在【单条事件】上的,而攻击链命中天然跨多条事件
// (凑齐组合的那几个动作分散在不同事件里),放进某一条事件的证据里就查不到全貌了。
// 故独立成一份带上限的记录 + JSONL 落盘,重启后仍可回看。
struct ChainHitRecord {
    QDateTime whenUtc;
    QString actorPath;
    int actorPid = 0;
    // 命中的是【哪一条】组合 —— 稳定标识(= ChainPattern::key,由标记 ID 连接而成)。
    //
    // 为什么必须记它:排查「哪条组合在刷误报」时,titles 顶不上用 —— 那些标题来自 Sigma
    // 规则名,服务器侧改个规则名,整段历史记录就与新表对不上号了;而且多条组合可以共用
    // 同一批标记标题的子集,肉眼分不开。有了 patternKey,才能把 attackchain_hits.jsonl
    // 按组合聚合,回答「这条组合命中 20 次、19 次被用户放行」这类问题。
    // 在此之前这个能力是零 —— 也就无从按结果决定要不要停用某条组合或某一档。
    QString patternKey;
    QStringList titles;      // 凑齐的那几个动作(可读)
    QString grade;           // 【生效】强度(已计入本机降档)
    QString serverGrade;     // 服务器原始强度 —— 与 grade 不同即说明本机压过档
    QString capReason;       // 降档原因(空 = 未降档)
    QString maxLevel;
    int support = 0;
    int benignSupport = 0;   // 正常软件语料里出现过几次
    QString families;
    bool dryRun = true;      // 命中当时是否处于「只记录不拦截」
    QString action;          // 最终裁决(Allow/Block/Ask);dry-run 下为本次事件的实际裁决
    QString eventType;       // 触发补齐的那条事件类型(可读)

    QJsonObject toJson() const;
    static ChainHitRecord fromJson(const QJsonObject& o);
};

// ---- 实机可达性诊断 --------------------------------------------------------- #
//
// 为什么必须有这一层:组合逻辑自测(selfTest)用【合成事件】跑,它永远能全绿 —— 它证明的是
// 「装载 + 记账 + 命中」这段逻辑没写错,证明不了「这些组合在真机上有机会被点亮」。二者的
// 差距实测极大,因为标记依赖的事件维度本身是【有条件才上报】的:
//   * 注册表:驱动与 ETW 都只上报命中「受关注键名单」的键(RegistryMonitor.c 里 BlwReportRegOp
//     的三个调用点全在名单命中分支内;ETW 侧见 regWatch_ 判空即不上报)。名单外的键
//     ——比如 Defender 排除项——根本不产生事件,对应标记结构性永不点亮。
//   * 文件写入:只有两个来源。ETW 的 Kernel-File CreateNewFile(不采样,但同样受
//     fileWatch_ = ProtectedPaths + FileHardBlocks 限制),以及驱动 IRP_MJ_WRITE 里
//     「偏移 0 起写」的全局 1/32 采样(BLW_WRITE_SAMPLE_RATE)。两者都不覆盖时,
//     「往某目录落个 exe」这一动作被上报的概率只有约 1/32。
//   * 用户态模块加载:内核只上报 \Temp\ 与 \Users\Public\ 下的加载(BlwPathIsSuspicious),
//     其余位置一律忽略。
//   * 命令行:内核/ETW 的进程创建事件不带命令行,由服务读 PEB 回填;毫秒级退出的
//     LOLBin(reg.exe / schtasks.exe)读不到,cmdline 条件随之失配。
// 于是一条组合可以「自测通过」却在真机上永不命中,而界面上的组合计数仍显示它已生效。
// 本诊断把这层差距量化出来 —— 它是判断本引擎「是否真实有用」的唯一客观标尺。

// 一条标记在【本机当前配置】下的可观测性。
enum class MarkerReach {
    Reachable,   // 事件维度覆盖到,且匹配条件用到的字段拿得到
    Sparse,      // 能命中但不可靠(采样 / 竞态 / 位置极窄),不能当作稳定防线
    Dead,        // 结构性不可能命中
};

// 判定可达性所需的本机覆盖面。刻意由调用方从 BulwarkOptions 组装后传入,而不是让引擎
// 自己去读配置 —— 这样自检看到的输入与真实运行时完全同源,不会出现「自检说可达、
// 实际配置里那条名单是空的」这种偏差。
struct CoverageProfile {
    bool driverSource = true;          // Driver 源(false = 纯用户态观测)
    QStringList registryWatch;         // 注册表受关注键(ProtectedRegistryKeys + RegistryHardBlocks)
    QStringList fileWatch;             // ETW 新建文件监视集(ProtectedPaths + FileHardBlocks)
    bool etwFileEvents = true;         // ETW Kernel-File 是否启用(不采样的新建文件来源)
    bool etwDns = true;                // ETW DNS-Client 是否启用(DnsQuery 的唯一来源)
    bool moduleSignature = false;      // ImageLoad 事件是否带「被加载模块签名」维度
    // 命令行是否【随事件一起到达】。驱动在进程创建回调里把 CreateInfo->CommandLine 放进
    // TargetPath 一并上报,故 Driver 源为真;纯用户态观测源不带命令行,只能按 PID 读 PEB,
    // 与毫秒级退出的 LOLBin 赛跑,依赖命令行的标记因此只能算「稀疏」。
    bool cmdLineInBand = false;

    static CoverageProfile fromOptions(const BulwarkOptions& o);
};

struct MarkerReachability {
    QString markerId;
    QString title;
    MarkerReach reach = MarkerReach::Reachable;
    QString reason;                    // Sparse / Dead 的原因(可读,指向具体代码事实)
};

struct ReachabilityReport {
    int serverPatterns   = 0;   // 服务器本次下发的组合数
    int droppedConflict  = 0;   // 装载期剔除:主体互相冲突(单进程不可能同时是两个程序)
    int droppedRedundant = 0;   // 装载期剔除:证据重复(多个标记条件相同,不构成互证)
    int loaded           = 0;   // 实际装载的组合数
    int reachable        = 0;   // 全部标记可达
    int sparse           = 0;   // 最差为「稀疏」
    int dead             = 0;   // 含至少一个结构性死路标记
    QStringList lines;          // 逐条可读说明(死路优先,其次稀疏)
};

class AttackChainEngine {
public:
    // dataDirOverride:把磁盘缓存(attackchain.json)与命中记录(attackchain_hits.jsonl)
    // 改放到指定目录。仅回归测试用 —— 测试必须完全隔离于真实状态:
    //   * applyTable 成功后会把回包写进缓存,拿测试表跑一次就会把机器上真正的表冲掉;
    //   * recordHit 会往 jsonl 追加,测试数据会混进真实命中历史里。
    // 留空 = 用 %ProgramData%\Bulwark(生产行为,与本参数加入前逐字节相同)。
    explicit AttackChainEngine(const AttackChainOptions& opt,
                               const QString& dataDirOverride = QString());

    bool isEnabled() const { return opt_.Enabled; }
    bool isDryRun() const { return opt_.DryRun; }

    // ---- 组合表 ----
    // 载入服务器回包(/v1/engine/patterns 的 JSON)。成功则替换当前表并落盘。
    bool applyTable(const QJsonObject& payload);
    // 从磁盘缓存载入(启动时调用):使断网 / 服务器不可达时仍有上一次的表可用。
    bool loadFromDisk();

    // 告知本机覆盖面,并据此重算各组合的【生效强度】(只会降档,绝不升档)。
    //
    // 为什么要单独一个入口、而不是在 applyTable 里一并做:正确的覆盖面要等
    // derivedRegistryWatch 把派生键补进名单之后才知道,而那一步又需要表已经装好 ——
    // 顺序是「装表 -> 派生键 -> 补进 options -> 才有最终覆盖面」。故装表与定档分开,
    // 由调用方在补齐名单之后调用本函数收尾(见 main.cpp 的接线)。
    //
    // 幂等:降档一律从 ChainPattern::serverGrade 算起,重复调用结果相同。
    // 未调用时按「不掌握覆盖面」处理 —— 不做任何稀疏降档(安全默认:不凭空猜测)。
    // 返回被降档的组合数(供自检直接打印,免得再为此开一个枚举组合的公开接口)。
    int setCoverage(const CoverageProfile& cov);

    // 内部整数版本号。仍是「要不要向服务器重新拉表」的唯一判据(单调递增)。
    int version() const;

    // 给人看的版本号(服务器侧 0.1 起、每次内容变化 +0.1)。服务器没给时回退成 "v<整数>",
    // 保证界面与日志永远有个能念的版本号,不会出现空白。
    QString versionLabel() const;
    int patternCount() const;
    int markerCount() const;

    // ---- 记账与判定 ----
    // 对一条【已富化】的事件:置位它命中的标记,再检查该进程是否因此凑齐了某个组合。
    // 返回 nullopt = 没凑齐。同一进程同一组合只报一次(避免刷屏)。
    //
    // 只应在主线程(Worker::onEvent)调用 —— 记账表无锁,靠单线程亲和保证正确性。
    std::optional<ChainHit> observe(const bulwark::SecurityEvent& e);

    // 把命中写进事件(证据 + 提分 + 硬指标),供既有裁决流水线消费。
    // dry-run 时只写一条中性证据、不提分不置硬指标 —— 对裁决零影响。
    void applyHitToEvent(bulwark::SecurityEvent& e, const ChainHit& hit) const;

    // 当前记账的进程数(诊断用)。
    // 实现放在 .cpp:要取 tableLock_。UI 的攻击链页面经 IPC 线程读这个数,而记账由主线程
    // 写(observe/evictIfNeeded),不加锁就是无保护的跨线程读写 QHash。
    int trackedProcessCount() const;

    // ---- 命中记录(供 UI 展示)----
    // 记一条命中。在【裁决已知之后】调用,这样能一并记下最终处置是放行/拦截/询问。
    // 内存里保留最近 kMaxRecords 条,同时追加到 %ProgramData%\Bulwark\attackchain_hits.jsonl。
    // 返回刚落下的那条记录 —— 调用方(Worker)要用同一份内容发即时通知,避免两处各拼一遍。
    ChainHitRecord recordHit(const ChainHit& hit, const bulwark::SecurityEvent& e,
                             const QString& action);
    // 最近的命中记录(最新在前)。线程安全。
    QVector<ChainHitRecord> recentHits(int limit = 200) const;
    void clearHits();

    static constexpr int kMaxRecords = 500;   // 内存上限;落盘文件另有轮转

    // 自测(--attackchain-check):用【合成事件】走一遍「标记置位 -> 记账累积 -> 组合命中」。
    //
    // 为什么必须有它:实机触发不可靠 —— 驱动对文件写入做 1/32 采样(BLW_WRITE_SAMPLE_RATE),
    // 实测连写 60 次只有 1 次被上报,靠真实操作去凑齐一条组合纯属运气。合成事件让这条逻辑
    // 变成确定性可验证的,且完全不碰机器。
    // 返回 {成功命中的组合数, 参与自测的组合数};outDetail 收走可读过程说明。
    QPair<int, int> selfTest(QStringList* outDetail);

    // 裁决路径自测(--attackchain-check 的第二段):验证命中【之后】那份贡献能不能活到裁决闸门。
    //
    // 为什么单独要这一段:上面的 selfTest 只证明「组合能凑齐」,证明不了「凑齐之后有用」。
    // 实测踩过的坑:applyHitToEvent 直接写 riskScore / hasThreatIndicator,而流水线第 3 步的
    // ThreatDetector::analyze 会复位前者、用赋值覆盖后者 —— 于是组合表上线后一次都没生效过,
    // 而组合逻辑自测始终 28/28 全绿,完全看不出问题。
    // 这一段把「命中 -> analyze -> 闸门判据」串起来跑,让那类"擦掉"必然被测出来。
    // 返回 {通过项, 总项};outDetail 收走逐项说明。
    QPair<int, int> verdictPathSelfTest(QStringList* outDetail) const;

    // 实机可达性诊断(见上方 CoverageProfile 处的长注释)。纯只读:不碰机器、不改记账。
    ReachabilityReport analyzeReachability(const CoverageProfile& cov) const;

    // 单个标记在给定覆盖面下的可观测性。公开是为了让上层(派生内核监视集的那一步)
    // 复用同一份判据 —— 「哪些标记因为覆盖不到而点不亮」与「该给内核补哪些监视项」
    // 本来就是同一个问题的两面,两处各写一遍必然跑偏。
    static MarkerReachability classifyMarker(const ChainMarker& m, const CoverageProfile& cov);

    // 当前表内全部标记的快照(供上层派生监视集)。
    QVector<ChainMarker> markerSnapshot() const;

    // 当前已装载组合的快照。供回归测试断言【生效强度】与降档原因 ——
    // 那两样是本引擎处置强度的直接决定因素,却没有任何对外可观测的出口,
    // 以致「降档到底有没有真的发生」只能靠读日志猜。
    QVector<ChainPattern> patternSnapshot() const;

    // 为「因注册表覆盖不到而结构性死掉」的标记,派生出恰好够用的受关注键片段。
    //
    // 【自限设计】只为当前判定为 Dead 的标记派生 —— 覆盖已经够的标记一个字都不加。
    // 所以在表内容没变时,这个函数返回空表,机器上的事件量与改动前逐条相同;
    // 只有当服务器新挖出一条「键不在名单里」的标记时,它才补上那一条。
    // 这解决的是一类静默退化:那种标记会让整条组合永远凑不齐,而界面上组合计数照常显示。
    //
    // 上限 kMaxDerivedRegKeys 是硬护栏:这份名单直接决定内核上报的注册表事件量,
    // 一张畸形/过宽的表不能把机器变成事件消防栓。
    QStringList derivedRegistryWatch(const CoverageProfile& cov) const;
    static constexpr int kMaxDerivedRegKeys = 24;

private:
    // 单个进程的行为账。
    struct ProcLedger {
        QString actorKey;            // 小写主体路径:用于识别 PID 复用
        QDateTime firstSeen;
        // 最近一次【置位标记】的时刻 —— 即「这个进程上次做可疑动作」是什么时候。
        //
        // 保留窗口据此计算,而不是据 firstSeen。原先按 firstSeen 算,含义是「这条账建立
        // 超过 30 分钟就清掉」,于是一个长驻进程的证据每 30 分钟被无条件抹平一次:
        // 后门先落文件、过一小时再写 Run 键、再过一小时加 Defender 排除项 —— 这是真实的
        // 慢速攻击链形态,而按 firstSeen 计时永远凑不齐,因为账早被清了。
        //
        // 改成按 lastSeen(不活动才淘汰)之后,窗口的含义变为「距上次可疑动作 30 分钟」,
        // 动作间隔在窗口内的链条无论总时长多久都能累积。
        // 【关键约束】lastSeen 只在真的置位了标记时才前移,不随普通事件前移 —— 所以一个
        // 忙碌但正常的进程照旧会到期淘汰,不会因为「一直在干活」就把账无限续下去。
        QDateTime lastSeen;
        QSet<QString> markers;       // 已置位的标记
        QSet<QString> firedPatterns; // 已报过的组合(按 markers 连接的键),避免重复上报
    };

    void evictIfNeeded();            // 过期 + 容量淘汰(无进程退出事件可依赖,只能靠这个)
    QVector<int> patternsFor(const QString& markerId) const;
    void loadHits();                 // 启动时回读命中记录(JSONL)

    // 按「正常语料出现率」与「本机可观测性」重算 patterns_ 的生效强度。
    // 调用方必须已持 tableLock_。返回被降档的组合数。
    int regradeLocked();

    AttackChainOptions opt_;
    mutable QMutex tableLock_;                     // 保护 markers_/markersByType_/patterns_/index_/version_
    QHash<QString, ChainMarker> markers_;
    // 事件类型 -> 该类型下的标记。热路径(observe)只遍历与本条事件同类型的那几个。
    //
    // 为什么值得单独存一份:DefenseRule::matches() 的第三步就是事件类型判定,类型不符的
    // 标记必然返回假。原先每条事件都对【全表】标记逐个调用 matches(),于是一条 DnsQuery
    // 也要挨个试过所有 RegistryWrite / FileWrite / ProcessCreate 标记 —— 纯白做功,而且是
    // 在持锁的裁决前置路径上做。这份索引把它收窄到同类型的那一桶。
    // 与 markers_ 是同一批数据的两种组织方式,由 applyTable 一并重建,不会走偏。
    QHash<int, QVector<ChainMarker>> markersByType_;
    QVector<ChainPattern> patterns_;
    QHash<QString, QVector<int>> index_;           // 标记 ID -> 含该标记的组合下标

    // 本机覆盖面。haveCoverage_ 为假时不做任何稀疏降档 —— CoverageProfile 的默认值
    // (driverSource=true、监视集全空)会让 FileWrite 类标记被误判成稀疏,凭默认值降档
    // 等于凭空削弱检出,故必须由调用方显式告知才生效。
    CoverageProfile coverage_;
    bool haveCoverage_ = false;
    int version_ = 0;
    QString label_;                                // 展示用版本号(如 "0.3");服务器未提供则为空
    // 装载期的剔除计数。原先只写进一条日志就丢掉了,于是「服务器给了 32 条、真正装上 27 条」
    // 这个差额在事后无从查证。可达性诊断要把它和运行期的死路一起报出来,故留存。
    int srvPatterns_ = 0;
    int dropConflict_ = 0;
    int dropRedundant_ = 0;

    // PID -> 行为账。【由 tableLock_ 保护】—— 原先注释是「仅主线程访问」且全程不加锁,
    // 后来 UI 攻击链页面经 IPC 线程读 trackedProcessCount(),该前提就不成立了:主线程
    // 正在 rehash / erase 时另一线程在读,QHash 无并发保证,表现为堆被写坏后崩在别处。
    QHash<int, ProcLedger> ledger_;

    // 淘汰触发节流计数。
    //
    // 淘汰要遍历整张记账表,所以不能每条事件都做;但更不能像原先那样【只在组合命中时】做——
    // 命中是罕见事件(那正是本引擎的设计目标),于是 LedgerRetentionMinutes 与
    // LedgerMaxProcesses 这两个配置项实际上从未生效过:机器跑一天,记账表里会攒下当天
    // 出现过的每一个 PID。现在改为每 kEvictEveryEvents 条事件跑一次,另外一旦超过容量
    // 上限就立即跑(见 evictIfNeeded 开头的节流判定)。
    int sinceEvict_ = 0;
    static constexpr int kEvictEveryEvents = 512;

    QString cachePath_;

    // 命中记录:内存最近 N 条 + JSONL 落盘。UI 请求可能来自 IPC 回调线程,故单独加锁。
    mutable QMutex hitsLock_;
    QVector<ChainHitRecord> hits_;                 // 新的在后,取用时反转
    QString hitsPath_;
    Logger log_{QStringLiteral("AttackChain")};
};

// 组合表刷新服务。照抄 IntelFeedService 的形制:自有线程 + 可中断睡眠 + 编组回主线程。
// 先取 manifest 比版本号,版本没变就不拉规则体(省流量);变了才拉全量并回调。
class AttackChainFeed {
public:
    using TableReadyCallback = std::function<void(const QJsonObject&)>;

    // baseUrlFallback:未单独配置 BaseUrl 时使用的端点(通常传中央信誉代理的地址,
    // 二者本来就是同一台服务器,不必在配置里把混淆后的 URL 写两遍)。
    AttackChainFeed(const AttackChainOptions& opt, const QString& baseUrlFallback);
    ~AttackChainFeed();
    AttackChainFeed(const AttackChainFeed&) = delete;
    AttackChainFeed& operator=(const AttackChainFeed&) = delete;

    bool isEnabled() const;
    void setTableReady(TableReadyCallback cb) { onTableReady_ = std::move(cb); }
    // 已装载的版本号。设置后拉取时带 ?since=,服务器据此可回 unchanged 而不下发规则体。
    void setCurrentVersion(int v) { currentVersion_.store(v); }
    void start();
    void stop();

    // 自检用(--attackchain-check):在【调用线程】同步拉一次并直接调用回调,不起后台线程、
    // 不做主线程编组 —— 自检模式没有 Qt 事件循环,编组过去的回调永远不会被执行。
    // 返回是否成功取到回包。
    bool fetchOnceForCheck();

private:
    void loop();
    bool sleepInterruptible(int seconds);
    std::optional<QJsonObject> fetchTable();
    // 距本机时区下一个 hour:00 还有多少秒(含 0~5 分钟随机错峰)。
    int secondsUntilDailyHour(int hour) const;

    AttackChainOptions opt_;
    QString baseUrl_;
    QString maskedUrl_;                  // 日志里只出现掩码形式,不泄露端点
    TableReadyCallback onTableReady_;
    std::atomic<int> currentVersion_{0};
    std::atomic<bool> running_{false};
    std::thread worker_;
    std::mutex mx_;
    std::condition_variable cv_;
    Logger log_{QStringLiteral("AttackChain")};
};

} // namespace bulwark::service
