#pragma once
#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/service/Logger.h"
#include "bulwark/models/DefenseRule.h"

#include <QString>
#include <QVector>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

// ThreatFox(abuse.ch)情报 feed:定期批量拉取最近已知恶意 IOC(get_iocs),转换成一批
// DefenseRule 灌入引擎,提供【主动】拦截(已知恶意哈希禁跑 / 恶意 IP 禁外联),与【被动】
// 信誉查询互补。网络经系统 curl.exe(ReputationCurl),任何失败都不抛断主防护流程。
// 对应 .NET Bulwark.Service/Reputation/ThreatFoxFeed.cs(ThreatFoxFeedClient + IntelRuleGenerator)。
namespace bulwark::service::reputation {

// ThreatFox 返回的一条 IOC(仅取生成规则所需字段)。
struct ThreatFoxIoc {
    QString ioc;         // IOC 值(如 "1.2.3.4:443"、"evil.com"、sha256)
    QString iocType;     // ip:port / domain / sha256_hash …(小写)
    QString malware;     // 恶意家族可读名(可空)
    QString threatType;  // 威胁类型(可空)
    int confidence = 0;  // 置信度 0-100
};

// ThreatFox feed 客户端:拉取最近 N 天、置信度达标的 IOC。失败返回空。
class ThreatFoxFeedClient {
public:
    ThreatFoxFeedClient(const ThreatFoxFeedOptions& opt, const QString& malwareBazaarKey);
    bool isEnabled() const;
    QVector<ThreatFoxIoc> fetchRecent();

private:
    QVector<ThreatFoxIoc> parse(const QString& json) const;
    ThreatFoxFeedOptions opt_;
    QString authKey_;
};

// 把 IOC 批量转换成防护规则(纯函数:去重、上限、TTL、来源标记)。
QVector<bulwark::DefenseRule> generateIntelRules(const QVector<ThreatFoxIoc>& iocs,
                                                 const ThreatFoxFeedOptions& opt);

// 后台情报 feed 刷新服务:定时 拉取 IOC -> 生成规则 -> 编组回主线程回调注入引擎。
// 回调在主线程被调用(内部经 QMetaObject::invokeMethod 编组),宿主可安全操作引擎/存储。
class IntelFeedService {
public:
    using RulesReadyCallback = std::function<void(const QVector<bulwark::DefenseRule>&)>;

    IntelFeedService(const ThreatFoxFeedOptions& opt, const QString& malwareBazaarKey);
    ~IntelFeedService();
    IntelFeedService(const IntelFeedService&) = delete;
    IntelFeedService& operator=(const IntelFeedService&) = delete;

    bool isEnabled() const;
    void setRulesReady(RulesReadyCallback cb) { onRulesReady_ = std::move(cb); }
    void start();
    void stop();

private:
    void loop();
    bool sleepInterruptible(int seconds); // 睡眠中被 stop 唤醒返回 false

    ThreatFoxFeedClient client_;
    ThreatFoxFeedOptions opt_;
    RulesReadyCallback onRulesReady_;
    std::atomic<bool> running_{false};
    std::thread worker_;
    std::mutex mx_;
    std::condition_variable cv_;
    Logger log_{QStringLiteral("ThreatFox")};
};

} // namespace bulwark::service::reputation
