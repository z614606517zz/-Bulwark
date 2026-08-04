#pragma once
#include <QHash>
#include <QSet>
#include <QVector>
#include <QUuid>
#include <QString>
#include <QDateTime>
#include <QReadWriteLock>
#include <QMutex>
#include <optional>
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/Verdict.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/engine/RansomwareBehaviorMonitor.h"
#include "bulwark/engine/BeaconDetector.h"
#include "bulwark/engine/EgressRateMonitor.h"
#include "bulwark/engine/BaselineAnalyzer.h"

namespace bulwark::engine {

// 规则具体度(越大越优先);薄封装 DefenseRule::specificityScore()。
inline int specificity(const DefenseRule& r) { return r.specificityScore(); }

// 决策中心。评估顺序(命中即返回):自身组件 -> 共存安全软件 -> 威胁检测 +
// 时序/基线监视器(蜜罐命中即拦) -> 显式规则(层级>具体度>动作强度>最近) ->
// 强可信签名 -> 吊销/过期签名拦截 -> 健康签名放行 -> 硬指标处置 -> 默认策略。
// 对应 .NET Engine/RuleEngine.cs。
class RuleEngine {
public:
    RuleEngine() = default;

    // 运行时开关(由服务据 RuntimeSettings 调整)。
    bool enableBaseline = true;
    bool trustSignedActors = true;

    // 自身目录登记(用于「本软件自身组件无条件放行」)。
    void addSelfDirectory(const QString& dir);
    bool matchesSelf(const QString& path) const;
    bool isSelfComponent(const SecurityEvent& e) const;

    // 规则排序辅助:层级(用户精确加白>硬覆盖>普通)、动作强度(Block>Ask>Allow)。
    static int ruleTier(const DefenseRule& r);
    static int rulePriority(VerdictAction a);

    // 规则集管理(线程安全;读取时跳过已到期规则)。
    void loadRules(const QVector<DefenseRule>& rules);
    QVector<DefenseRule> getRules() const;
    int pruneExpired();
    void addRule(const DefenseRule& rule);
    bool removeRule(const QUuid& id);

    // 评估一个事件,给出裁决(并把决策证据 + ATT&CK 注解写回事件)。
    Verdict evaluate(SecurityEvent& e);

    // 从事件生成一条规则并登记(用户「记住我的选择」)。
    DefenseRule createRuleFrom(SecurityEvent& e, VerdictAction action,
                               std::optional<QDateTime> expiresUtc = std::nullopt,
                               bool sessionOnly = false);

    // 行为基线画像的导出 / 导入(转发到内部 BaselineAnalyzer,内部自带锁)。
    //
    // 之所以要暴露:BaselineAnalyzer 早就实现了 exportSnapshot/importSnapshot,服务侧也早就有
    // BaselineStore(带 load/save、原子写),但 BaselineStore 从未被构造过 —— 基线因此纯内存、
    // 每次服务重启清零,「行为偏离自身历史基线」这条检测在重启后要重新经历学习期。
    // 分析器是 RuleEngine 的私有成员,没有这两个转发口,main 就没法把它接到存储上。
    BaselineSnapshot exportBaseline() { return baseline_.exportSnapshot(); }
    void importBaseline(const BaselineSnapshot& snapshot) { baseline_.importSnapshot(snapshot); }

    // 登记勒索诱饵文件(用户态行为源投放蜜罐时调用):任何进程改写/删除该路径即被
    // 时序监视器判为强勒索信号(canaryHit -> 直接 Block)。转发到内部勒索监视器。
    void addCanaryFile(const QString& path) { ransomware_.addCanaryFile(path); }

    // 按【路径】查用户信任(不需要完整 SecurityEvent):命中用户明确信任(文件精确 / 目录通配)
    // 或本软件自身组件时返回其备注,否则 nullopt。语义与 matchedUserTrust 一致,只是入口是路径。
    //
    // 为什么需要这个:evaluate() 只在事件【当次】把结果记在 e.userTrusted 上,而服务侧有两类
    // 动作发生在那之后,拿着的是过期快照:
    //   ① 后台补偿处置(外部信誉 / VirusTotal / 微步 IP 情报 / AI 研判 / 兜底扫描)—— 回执可能
    //      比事件晚几十秒到几分钟,期间用户完全可能刚把该程序加白;
    //   ② 向内核下发「禁止执行 / 禁止加载」名单 —— 这两份名单由内核写回注册表持久化
    //      (\Services\Bulwark\Policy\FileExecBlock / FileNoLoad),跨杀服务与重启由内核独立续拦。
    //      一旦对已加白的程序下发,用户在 UI 再怎么加白也不生效:内核在进程创建回调就地拒绝,
    //      事件根本到不了本引擎。
    // 两处都必须在动手前用本方法重查一次,否则表现就是「加白不彻底、时不时还拦」。
    std::optional<QString> trustNoteForPath(const QString& path) const;

private:
    Verdict evaluateInternal(SecurityEvent& e);
    void appendDecisionEvidence(SecurityEvent& e, const Verdict& v);

    // 命中用户明确信任(带信任标记的 Allow 项,文件精确或目录通配)则返回其备注,否则 nullopt。
    // 信任项在威胁检测之前提前放行——"信任以后所有检测都不做"。
    std::optional<QString> matchedUserTrust(const SecurityEvent& e) const;

    QHash<QUuid, DefenseRule> rules_;
    mutable QReadWriteLock rulesLock_;
    QSet<QString> selfDirectories_;
    mutable QMutex selfDirLock_;

    // 有状态时序/基线监视器(随引擎生命周期,内部各自加锁)。
    RansomwareBehaviorMonitor ransomware_;
    BeaconDetector beacon_;
    EgressRateMonitor egress_;
    BaselineAnalyzer baseline_;
};

} // namespace bulwark::engine
