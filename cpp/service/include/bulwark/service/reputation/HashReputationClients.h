#pragma once
#include "bulwark/service/reputation/ReputationClientBase.h"
#include "bulwark/service/BulwarkOptions.h"

// The four "generic" hash-reputation clients (curl + JSON parse). Faithful to
// Bulwark.Service/Reputation/{MalwareBazaar,Otx,MetaDefender,HybridAnalysis}Client.cs.
namespace bulwark::service::reputation {

// MalwareBazaar (abuse.ch): POST get_info&hash; hit => Malicious. Needs Auth-Key.
class MalwareBazaarClient : public ReputationClientBase {
public:
    explicit MalwareBazaarClient(const BulwarkOptions& options);
protected:
    bulwark::FileReputation doQuery(const QString& sha256) override;
    std::pair<bool, QString> doTest() override;
private:
    bulwark::FileReputation parse(const QString& sha256, const QString& json) const;
    QString apiUrl_;
};

// AlienVault OTX: GET file/{hash}/general; pulse_count -> Clean/Suspicious/Malicious.
class OtxClient : public ReputationClientBase {
public:
    explicit OtxClient(const BulwarkOptions& options);
protected:
    bulwark::FileReputation doQuery(const QString& sha256) override;
    std::pair<bool, QString> doTest() override;
private:
    bulwark::FileReputation parse(const QString& sha256, const QString& json) const;
    QString baseUrl_;
    int maliciousPulseThreshold_;
};

// MetaDefender Cloud (OPSWAT): GET hash/{sha256}; total_detected_avs threshold.
class MetaDefenderClient : public ReputationClientBase {
public:
    explicit MetaDefenderClient(const BulwarkOptions& options);
protected:
    bulwark::FileReputation doQuery(const QString& sha256) override;
    std::pair<bool, QString> doTest() override;
private:
    bulwark::FileReputation parse(const QString& sha256, const QString& body) const;
    QString baseUrl_;
    int maliciousThreshold_;
};

// Hybrid Analysis (Falcon Sandbox): GET overview/{sha256}; verdict / threat_score.
class HybridAnalysisClient : public ReputationClientBase {
public:
    explicit HybridAnalysisClient(const BulwarkOptions& options);
    // 拉取沙箱行为画像:从 HA overview 提取网络 IOC(外联 IP / 域名),与 VT 的释放文件/
    // 注册表画像互补(聚合器会并集合并)。任何失败 / 无数据 -> fail-open 空画像。
    bulwark::ThreatBehaviorProfile fetchBehaviorProfile(const QString& sha256) override;
protected:
    bulwark::FileReputation doQuery(const QString& sha256) override;
    std::pair<bool, QString> doTest() override;
private:
    bulwark::FileReputation parse(const QString& sha256, const QString& body) const;
    QString baseUrl_;
    int maliciousThreatScore_;
};

} // namespace bulwark::service::reputation
