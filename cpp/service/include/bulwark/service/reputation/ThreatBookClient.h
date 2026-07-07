#pragma once
#include "bulwark/service/reputation/ReputationClientBase.h"
#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/models/IpReputation.h"

#include <QMutex>

// 微步在线 ThreatBook 云 API 客户端。作为第 6 个 IHashReputationService 源接入聚合器,
// 提供两条路径:
//   - 哈希信誉(POST v3/file/report,按 SHA-256)—— IHashReputationService 接口路径;
//   - IP 信誉(POST v3/scene/ip_reputation)—— 供网络外联情报互证的独立方法 queryIp()。
// 微步返回无完整公开 schema,故解析采用防御式(递归查找 threat_level / judgments /
// is_whitelist / severity / is_malicious 等)。场景接口(IP)月配额极低,独立月度计数守护。
// 对应 .NET Bulwark.Service/Reputation/ThreatBookClient.cs。
namespace bulwark::service::reputation {

class ThreatBookClient : public ReputationClientBase {
public:
    explicit ThreatBookClient(const BulwarkOptions& options);

    // 查询公网 IP 信誉(微步场景 API v3/scene/ip_reputation)。供网络防护对「已可疑的外联」
    // 做情报互证 —— 严禁逐连接调用(月配额极低,由 trySceneQuota + 上层缓存+仅可疑才查 守护)。
    // 阻塞(令牌桶 + 一次 curl),故应在后台线程/非裁决热路径调用。任何失败/超配额 -> Unknown。
    // 忠实移植自 .NET ThreatBookClient.QueryIpAsync。
    bulwark::IpReputation queryIp(const QString& ip);

protected:
    bulwark::FileReputation doQuery(const QString& sha256) override;
    std::pair<bool, QString> doTest() override;

private:
    bulwark::FileReputation parse(const QString& sha256, const QString& body) const;
    bulwark::IpReputation parseIp(const QString& ip, const QString& body) const;
    bool trySceneQuota(); // 本月场景接口(IP)是否还有额度;到月自动归零

    QString reportUrl_;
    QString ipUrl_;
    int     sceneLimit_ = 20; // 场景接口月配额(极低)
    QMutex  sceneMutex_;
    int     sceneMonth_ = -1; // 当前计数所属月份键 = year*100 + month(UTC)
    int     sceneUsed_  = 0;
};

} // namespace bulwark::service::reputation
