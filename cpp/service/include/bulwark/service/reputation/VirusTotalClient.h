#pragma once
#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/reputation/IHashReputationService.h"
#include "bulwark/service/reputation/RateLimiting.h"
#include "bulwark/models/VtScanRecord.h" // VtScanStage
#include "bulwark/models/ThreatBehaviorProfile.h"
#include "bulwark/ipc/Payloads.h" // VtDetailResponsePayload

#include <QMutex>
#include <QString>
#include <atomic>
#include <functional>
#include <utility>

// VirusTotal v3 hash-reputation + file-upload-scan client. Faithful to
// Bulwark.Service/Reputation/VirusTotalClient.cs: HTTPS via curl.exe, self
// rate-limited (token bucket + daily quota with a reserve for priority verifies),
// fail-open (any failure/404/401/429 -> Unknown). API key precedence:
// env BULWARK_VT_APIKEY > config > built-in default (works out of the box).
namespace bulwark::service::reputation {

class VirusTotalClient : public IHashReputationService {
public:
    static QString builtInApiKey();

    explicit VirusTotalClient(const BulwarkOptions& options);

    bool isEnabled() const override { return enabled_; }
    QString name() const override { return QStringLiteral("VirusTotal"); }
    bulwark::ReputationUsage getUsage() override;
    bulwark::FileReputation query(const QString& sha256) override { return query(sha256, false); }
    std::pair<bool, QString> testConnection() override;

    // Hot-swap the key from UI settings. An empty key falls back to the built-in
    // default (VT works out of the box). Thread-safe vs. query()/uploadAndScan()
    // on the background workers, which read the key through apiKey().
    void setApiKey(const QString& key) override;

    // Priority query for memory-protection / anti-injection verifies: gets
    // preference on both the token bucket and the reserved daily quota.
    bulwark::FileReputation query(const QString& sha256, bool priority);

    // Progress sink for uploadAndScan (staged, for the UI scan card): the
    // percent is only meaningful for the Uploading stage.
    using ProgressFn = std::function<void(bulwark::VtScanStage, int)>;

    // Upload a file to VirusTotal for multi-engine scanning, poll to completion,
    // then fetch the full report by SHA-256. For high-value new samples only
    // (double-click / dropped payload) since it uploads the whole file. Any
    // failure -> Unknown (never throws). Blocks (upload + up to ~4 min polling),
    // so call off the decision hot-path / on a background thread.
    // Faithful port of VirusTotalClient.UploadAndScanAsync.
    bulwark::FileReputation uploadAndScan(const QString& filePath, const QString& sha256,
                                          const ProgressFn& progress = {});

    // 拉取该样本的沙箱行为画像(VT /files/{id}/behaviour_summary):释放文件(名+哈希)、
    // 写入的注册表键、创建的进程、外联 IP / 域名、服务、互斥体。供「确认恶意」后做
    // 释放物清理 + IOC 拦截规则生成。无沙箱数据 / 任何失败 -> fetched=false 的空画像
    // (fail-open,绝不抛入主流程)。阻塞(一次网络往返),后台线程调用。
    bulwark::ThreatBehaviorProfile fetchBehaviorProfile(const QString& sha256) override;

    // 拉取某哈希的 VT 完整报告(GET /files/{sha256}):文件元数据 + 每引擎具体检出名 + 建议威胁名。
    // 供「云信誉详情」弹窗按需展示更全面信息。阻塞(一次网络往返),后台线程调用;失败 fail-open
    // (success=false + message 说明)。行为画像由调用方另经 fetchBehaviorProfile 合并。
    bulwark::ipc::VtDetailResponsePayload fetchDetailReport(const QString& sha256);

private:
    bulwark::FileReputation parse(const QString& sha256, const QString& json) const;
    void parseBehaviour(const QString& json, bulwark::ThreatBehaviorProfile& prof) const;
    void parseDetail(const QString& json, bulwark::ipc::VtDetailResponsePayload& d) const;
    static void diag(const QString& line);
    QString apiKey() const; // thread-safe snapshot (guards apiKey_)

    VirusTotalOptions opt_;
    QString apiKey_;
    mutable QMutex keyMutex_;   // guards apiKey_ (hot-swapped from UI thread)
    std::atomic<bool> enabled_; // atomic: read on worker threads, set on UI thread
    TokenBucket bucket_;
    DailyQuota daily_;
    Logger log_;
};

} // namespace bulwark::service::reputation
