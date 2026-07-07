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

    // 登记勒索诱饵文件(用户态行为源投放蜜罐时调用):任何进程改写/删除该路径即被
    // 时序监视器判为强勒索信号(canaryHit -> 直接 Block)。转发到内部勒索监视器。
    void addCanaryFile(const QString& path) { ransomware_.addCanaryFile(path); }

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
