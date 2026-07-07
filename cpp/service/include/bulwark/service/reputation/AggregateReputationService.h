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
// 顺序查询所有已启用的下游信誉源(MalwareBazaar / OTX / MetaDefender / HybridAnalysis…),
// 再按「取最强可信结论」合并(Malicious > Suspicious > Clean > Unknown)。单源失败/超时
// 不影响其他源,整体是「锦上添花」。对应 .NET Bulwark.Service/Reputation/AggregateReputationService.cs。
namespace bulwark::service::reputation {

class AggregateReputationService : public IHashReputationService {
public:
    // 接管各下游源的所有权(构造时传入,已排除聚合器自身)。
    explicit AggregateReputationService(std::vector<std::unique_ptr<IHashReputationService>> sources);

    bool isEnabled() const override;
    bulwark::FileReputation query(const QString& sha256) override;
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
    static int rank(bulwark::ReputationVerdict v);
    static bulwark::FileReputation merge(const QString& sha256,
                                         const QVector<bulwark::FileReputation>& results);

    std::vector<std::unique_ptr<IHashReputationService>> sources_;
    mutable QMutex runtimeLock_;
    QHash<QString, bool> runtimeEnabled_; // 源名(规范化) -> 运行时开关
    Logger log_{QStringLiteral("Aggregate")};
};

} // namespace bulwark::service::reputation
