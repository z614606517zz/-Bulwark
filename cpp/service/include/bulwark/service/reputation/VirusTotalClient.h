#pragma once
#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/reputation/IHashReputationService.h"
#include "bulwark/service/reputation/RateLimiting.h"
#include "bulwark/models/VtScanRecord.h" // VtScanStage
#include "bulwark/models/ThreatBehaviorProfile.h"
#include "bulwark/ipc/Payloads.h" // VtDetailResponsePayload

#include <QDateTime>
#include <QMutex>
#include <QString>
#include <atomic>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

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
    bulwark::FileReputation query(const QString& sha256, bool priority) override;

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
    // 每个 API Key 独立的限流状态:自己的分钟令牌桶 + 每日配额 + 冷却态(429/鉴权失败时
    // 临时禁用,让后续请求自动跳过它)。这样多 Key 的额度是真正叠加的(总量 = ΣKey 日配额),
    // 且能混用免费/Premium(各自不同的 rpm/rpd)。含 QMutex/TokenBucket/DailyQuota,不可拷贝/移动,
    // 只经 shared_ptr 持有——请求全程持有一份,即便期间 setApiKey 重建池也不会悬空。
    struct KeyState {
        QString key;
        int rpm = 4;                // 该 Key 的每分钟上限(仅供 getUsage 汇总展示)
        int rpd = 500;              // 该 Key 的每日上限(仅供展示)
        TokenBucket bucket;         // 分钟速率
        DailyQuota daily;           // 每日配额(含优先保留)
        QMutex stateMx;             // guards disabledUntilUtc
        QDateTime disabledUntilUtc; // 429/鉴权失败冷却截止(UTC);无效=可用
        KeyState(QString k, int rpmVal, int rpdVal, int reserve)
            : key(std::move(k)), rpm(rpmVal), rpd(rpdVal),
              bucket(rpmVal, 60000), daily(rpdVal, reserve) {}
    };

    bulwark::FileReputation parse(const QString& sha256, const QString& json) const;
    void parseBehaviour(const QString& json, bulwark::ThreatBehaviorProfile& prof) const;
    void parseDetail(const QString& json, bulwark::ipc::VtDetailResponsePayload& d) const;
    static void diag(const QString& line);

    // 按 "KEY[:RPD[:RPM]]" 逐条解析(逗号分隔多 Key),重建每 Key 独立限流池并更新 enabled_。
    // 未标注 RPD/RPM 的 Key 沿用 opt_ 里的默认(VT 免费档 500/天、4/分)。
    void rebuildPool(const QString& raw);
    // 选一个「有日配额且未冷却」的 Key:先占用其日配额,再等其分钟令牌;轮询起点均衡分摊。
    // 所有 Key 日配额耗尽/冷却中则返回 nullptr(调用方 fail-open 返回 Unknown)。
    std::shared_ptr<KeyState> acquireKey(bool priority);
    // 测试连接用:轮询取一个 Key(不占日配额、不跳过冷却,以便探测 Key 是否已修复)。
    std::shared_ptr<KeyState> acquireProbeKey();
    // 据 HTTP 结果标注该 Key:429 短冷却(60s)、401/403 长冷却(6h)、2xx/404 清除冷却。
    static void noteHttpResult(const std::shared_ptr<KeyState>& ks, int httpCode);
    int keyCount() const;

    VirusTotalOptions opt_;
    std::vector<std::shared_ptr<KeyState>> keys_; // 每 Key 独立令牌桶 + 日配额 + 冷却态
    mutable QMutex keyMutex_;                     // guards keys_ + rrCursor_
    mutable int rrCursor_ = 0;                    // 轮询游标(均衡分摊各 Key)
    std::atomic<bool> enabled_;                   // atomic: read on worker threads, set on UI thread
    Logger log_;
};

} // namespace bulwark::service::reputation
