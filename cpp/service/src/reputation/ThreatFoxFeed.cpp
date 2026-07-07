#include "bulwark/service/reputation/ThreatFoxFeed.h"
#include "bulwark/service/reputation/ReputationCurl.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QSet>

#include <algorithm>
#include <chrono>

namespace bulwark::service::reputation {
namespace {
inline QString u(const char* s) { return QString::fromUtf8(s); }
} // namespace

// ============================ ThreatFoxFeedClient ============================

ThreatFoxFeedClient::ThreatFoxFeedClient(const ThreatFoxFeedOptions& opt, const QString& malwareBazaarKey)
    : opt_(opt), authKey_(opt.resolveAuthKey(malwareBazaarKey)) {}

bool ThreatFoxFeedClient::isEnabled() const {
    return opt_.Enabled && !authKey_.trimmed().isEmpty();
}

QVector<ThreatFoxIoc> ThreatFoxFeedClient::fetchRecent() {
    if (!isEnabled())
        return {};

    const int days = std::clamp(opt_.Days, 1, 7);
    QJsonObject req;
    req[QStringLiteral("query")] = QStringLiteral("get_iocs");
    req[QStringLiteral("days")] = days;
    const QString body = QString::fromUtf8(QJsonDocument(req).toJson(QJsonDocument::Compact));

    const QStringList headers{
        QStringLiteral("Auth-Key: ") + authKey_,
        QStringLiteral("Content-Type: application/json") };
    const QString url = opt_.BaseUrl.isEmpty() ? QStringLiteral("https://threatfox-api.abuse.ch/api/v1/")
                                               : opt_.BaseUrl;
    const auto res = ReputationCurl::postRaw(url, body, headers, std::max(10, opt_.QueryTimeoutSeconds));
    if (res.first != 200)
        return {};
    return parse(res.second);
}

QVector<ThreatFoxIoc> ThreatFoxFeedClient::parse(const QString& json) const {
    QVector<ThreatFoxIoc> list;
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return list;
    const QJsonObject root = doc.object();
    if (root.value(QLatin1String("query_status")).toString().compare(QLatin1String("ok"), Qt::CaseInsensitive) != 0)
        return list;
    const QJsonArray data = root.value(QLatin1String("data")).toArray();
    for (const QJsonValue& v : data) {
        const QJsonObject it = v.toObject();
        const QString ioc = it.value(QLatin1String("ioc")).toString().trimmed();
        const QString iocType = it.value(QLatin1String("ioc_type")).toString().trimmed().toLower();
        if (ioc.isEmpty() || iocType.isEmpty())
            continue;
        const QJsonValue confVal = it.value(QLatin1String("confidence_level"));
        const int conf = confVal.isDouble() ? confVal.toInt() : 0;
        if (conf < opt_.MinConfidence)
            continue;
        ThreatFoxIoc rec;
        rec.ioc = ioc;
        rec.iocType = iocType;
        rec.malware = it.value(QLatin1String("malware_printable")).toString();
        if (rec.malware.isEmpty())
            rec.malware = it.value(QLatin1String("malware")).toString();
        rec.threatType = it.value(QLatin1String("threat_type")).toString();
        rec.confidence = conf;
        list.append(rec);
    }
    return list;
}

// ============================ IntelRuleGenerator =============================

QVector<bulwark::DefenseRule> generateIntelRules(const QVector<ThreatFoxIoc>& iocs,
                                                 const ThreatFoxFeedOptions& opt) {
    QVector<bulwark::DefenseRule> rules;
    if (iocs.isEmpty())
        return rules;

    QSet<QString> seen;
    const QDateTime expires = QDateTime::currentDateTimeUtc().addDays(std::max(1, opt.RuleTtlDays));
    const int maxRules = std::max(1, opt.MaxRules);
    const QString tag = ThreatFoxFeedOptions::ruleNoteTag();

    const auto label = [&tag](const ThreatFoxIoc& i) -> QString {
        const QString fam = !i.malware.trimmed().isEmpty()   ? i.malware
                          : !i.threatType.trimmed().isEmpty() ? i.threatType
                                                              : QStringLiteral("malicious");
        return tag + QLatin1Char(' ') + fam + QStringLiteral(" (") + QString::number(i.confidence)
             + QStringLiteral("%)");
    };

    for (const ThreatFoxIoc& i : iocs) {
        if (rules.size() >= maxRules)
            break;
        const QString key = i.iocType + QLatin1Char('|') + i.ioc;
        if (seen.contains(key))
            continue;
        seen.insert(key);

        bulwark::DefenseRule rule;
        bool ok = false;
        if (i.iocType == QLatin1String("sha256_hash") && opt.GenerateHashRules) {
            // 按哈希 Block:type 留空(任意行为都拦),改名无效;硬覆盖优先级最高。
            rule.actorHashes.insert(i.ioc.toUpper());
            rule.action = bulwark::VerdictAction::Block;
            rule.hardOverride = true;
            ok = true;
        } else if (i.iocType == QLatin1String("ip:port") && opt.GenerateIpRules) {
            QString ip = i.ioc;
            const int colon = ip.lastIndexOf(QLatin1Char(':'));
            if (colon > 0)
                ip = ip.left(colon); // 去 :port,拦该 IP 任意端口
            rule.type = bulwark::EventType::NetworkConnect;
            rule.targetPattern = ip.trimmed() + QLatin1Char('*');
            rule.action = bulwark::VerdictAction::Block;
            ok = true;
        } else if (i.iocType == QLatin1String("domain") && opt.GenerateDomainRules) {
            rule.type = bulwark::EventType::NetworkConnect;
            rule.targetPattern = QLatin1Char('*') + i.ioc.trimmed() + QLatin1Char('*');
            rule.action = bulwark::VerdictAction::Block;
            ok = true;
        }
        if (ok) {
            rule.expiresUtc = expires;
            rule.note = label(i);
            rules.append(rule);
        }
    }
    return rules;
}

// ============================ IntelFeedService ===============================

IntelFeedService::IntelFeedService(const ThreatFoxFeedOptions& opt, const QString& malwareBazaarKey)
    : client_(opt, malwareBazaarKey), opt_(opt) {}

IntelFeedService::~IntelFeedService() { stop(); }

bool IntelFeedService::isEnabled() const { return client_.isEnabled(); }

bool IntelFeedService::sleepInterruptible(int seconds) {
    if (seconds <= 0)
        return running_.load();
    std::unique_lock<std::mutex> lk(mx_);
    cv_.wait_for(lk, std::chrono::seconds(seconds), [this] { return !running_.load(); });
    return running_.load();
}

void IntelFeedService::loop() {
    // 首次延迟(避开开机拥塞),期间被 stop 唤醒则直接退出。
    if (!sleepInterruptible(std::max(0, opt_.InitialDelaySeconds)))
        return;

    while (running_.load()) {
        const QVector<ThreatFoxIoc> iocs = client_.fetchRecent();
        if (!iocs.isEmpty() && onRulesReady_) {
            const QVector<bulwark::DefenseRule> rules = generateIntelRules(iocs, opt_);
            if (!rules.isEmpty()) {
                log_.info(u("ThreatFox 情报:拉取 ") + QString::number(iocs.size())
                          + u(" 条 IOC,生成 ") + QString::number(rules.size()) + u(" 条规则,编组注入。"));
                RulesReadyCallback cb = onRulesReady_;
                // 编组回主线程再注入引擎/落盘(避免跨线程碰 RuleStore / 保持与其它引擎变更一致)。
                QMetaObject::invokeMethod(
                    qApp, [cb, rules] { cb(rules); }, Qt::QueuedConnection);
            }
        }
        if (opt_.RefreshIntervalHours <= 0)
            break; // 仅启动时拉一次
        if (!sleepInterruptible(opt_.RefreshIntervalHours * 3600))
            return;
    }
}

void IntelFeedService::start() {
    if (!client_.isEnabled()) {
        log_.info(u("ThreatFox 情报 feed 未启用(未开启或无 Auth-Key),后台服务不启动。"));
        return;
    }
    if (running_.exchange(true))
        return;
    worker_ = std::thread([this] { loop(); });
    log_.info(u("ThreatFox 情报 feed 后台服务已启动。"));
}

void IntelFeedService::stop() {
    if (!running_.exchange(false))
        return;
    {
        std::lock_guard<std::mutex> lk(mx_);
        cv_.notify_all();
    }
    if (worker_.joinable())
        worker_.join();
}

} // namespace bulwark::service::reputation
