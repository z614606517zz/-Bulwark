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

    // 本月 IP 情报配额是否已用尽(或压根没 Key)。给上层在【入队之前】短路用。
    // 为什么需要:配额用尽时 queryIp 返回的 Unknown 带 querySucceeded=false,上层按「失败可重试」
    // 语义**不会缓存**它 —— 于是同一个 IP 在整月剩余时间里被反复入队、反复唤醒后台线程、反复写
    // 诊断日志(实测同一 IP 一秒内 12 次)。配额耗尽是个确定状态,提前问一次就能全省掉。
    bool ipIntelBudgetSpent();

protected:
    bulwark::FileReputation doQuery(const QString& sha256) override;
    std::pair<bool, QString> doTest() override;

private:
    bulwark::FileReputation parse(const QString& sha256, const QString& body) const;
    bulwark::IpReputation parseIp(const QString& ip, const QString& body) const;
    bool trySceneQuota();      // 本月场景接口(IP)是否还有额度;到月自动归零
    void rollSceneMonth();     // 需已持 sceneMutex_:跨月则归零计数与「已告知」标记
    void noteExhaustedOnce();  // 需已持 sceneMutex_:配额用尽每月只记一条(不能一条都不记)
    // 月配额只有 20 次,而计数原先纯在内存里 —— 服务每重启一次就白送 20 次,开机/升级几轮就把
    // 微步那边真正的月额度打穿(之后云端直接拒答,IP 情报静默失效)。所以必须落盘。
    void loadSceneState();     // 构造时读回 {月份, 已用}
    void saveSceneState();     // 需已持 sceneMutex_

    QString reportUrl_;
    QString ipUrl_;
    int     sceneLimit_ = 20; // 场景接口月配额(极低)
    QMutex  sceneMutex_;
    int     sceneMonth_ = -1; // 当前计数所属月份键 = year*100 + month(UTC)
    int     sceneUsed_  = 0;
    bool    sceneExhaustedLogged_ = false; // 配额耗尽每月只记一条,避免刷爆 rep_diag.log
};

} // namespace bulwark::service::reputation
