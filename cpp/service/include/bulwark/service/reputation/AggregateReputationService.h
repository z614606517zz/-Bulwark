#pragma once
#include "bulwark/service/reputation/IHashReputationService.h"
#include "bulwark/service/Logger.h"

#include <QVector>
#include <QHash>
#include <QMutex>
#include <QString>

#include <memory>
#include <vector>

// 多源信誉聚合器:对上层(ReputationManager)实现统一的 IHashReputationService,内部
// 并行查询所有已启用的下游信誉源(MalwareBazaar / OTX / MetaDefender / HybridAnalysis…),
// 再按「取最强可信结论」合并(Malicious > Suspicious > Clean > Unknown)。并行使总延迟
// 收敛到「最慢的单源」而非各源之和,缩短 VT 未收录时的回退等待;合并与完成顺序无关。
// 单源失败/超时不影响其他源,整体是「锦上添花」。对应 .NET Bulwark.Service/Reputation/AggregateReputationService.cs。
namespace bulwark::service::reputation {

class AggregateReputationService : public IHashReputationService {
public:
    // 接管各下游源的所有权(构造时传入,已排除聚合器自身)。
    explicit AggregateReputationService(std::vector<std::unique_ptr<IHashReputationService>> sources);

    bool isEnabled() const override;
    bulwark::FileReputation query(const QString& sha256) override;
    bulwark::FileReputation query(const QString& sha256, bool priority) override;
    // 排除指定源后查询其余活跃源(名称比较不区分大小写;空名等价于 query)。
    // 用于双击云扫描的分级链路:VirusTotal 已在上一级单独查过且未给出结论时,这一级只查
    // 「其他源」,既不重复消耗 VT 配额(聚合器里的 VT 与双击扫描用的是同一个客户端实例,
    // 重复查会真的扣两次额度),也保持「VT 优先、其他兜底」的顺序语义。
    bulwark::FileReputation queryExcluding(const QString& sha256, bool priority,
                                           const QString& excludeSource);
    // 遍历活跃源拉取行为画像并合并(各源结果取并集,去重)。供确认恶意后清理 + 生成规则。
    bulwark::ThreatBehaviorProfile fetchBehaviorProfile(const QString& sha256) override;
    std::pair<bool, QString> testConnection() override;
    bulwark::ReputationUsage getUsage() override;
    QString name() const override { return QStringLiteral("Aggregate"); }

    // 逐源用量快照(enabled 以「配置可用 且 运行时开关未关」为准)。
    QVector<bulwark::ReputationUsage> getUsages();
    // 按名称测试指定源(VirusTotal / MalwareBazaar / OTX …)。
    std::pair<bool, QString> testConnection(const QString& source);
    // 按运行时设置更新各源开关(Worker 在设置变更时调用;未持有的源为无害空操作)。
    void setRuntimeEnabled(bool virusTotal, bool malwareBazaar, bool otx,
                           bool threatBook, bool metaDefender, bool hybridAnalysis);
    // 按名热更新某源 API Key(UI 设置变更 / 启动时应用有效 Key)。未持有该名则为空操作。
    void setApiKey(const QString& sourceName, const QString& key);

private:
    // 某源当前是否真正参与查询:配置可用 且 运行时开关未关闭。
    bool isActive(IHashReputationService* s) const;
    // query / queryExcluding 的共同实现:取活跃源快照(可排除一个)后并行查询并合并。
    bulwark::FileReputation queryFiltered(const QString& sha256, bool priority,
                                          const QString& excludeSource);
    static int rank(bulwark::ReputationVerdict v);
    static bulwark::FileReputation merge(const QString& sha256,
                                         const QVector<bulwark::FileReputation>& results);

    std::vector<std::unique_ptr<IHashReputationService>> sources_;
    mutable QMutex runtimeLock_;
    QHash<QString, bool> runtimeEnabled_; // 源名(规范化) -> 运行时开关
    Logger log_{QStringLiteral("Aggregate")};
};

} // namespace bulwark::service::reputation
