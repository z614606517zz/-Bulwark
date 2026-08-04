#include "bulwark/service/reputation/ThreatIntelUploader.h"
#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/service/reputation/ReputationCurl.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QRandomGenerator>
#include <QStringList>
#include <QTime>

#include <algorithm>
#include <chrono>

namespace bulwark::service {
namespace {

// 单个请求的负载上限。ReputationCurl 走 curl.exe 的 --data-raw,负载是【命令行参数】,
// Windows 整条命令行硬上限约 32767 字符 —— 攒满一晚的队列一次发完必然超限并被静默截断,
// 所以必须分批。留足余量取 16KB。
constexpr int kMaxBodyChars = 16000;
// 单批条数上限(再加一道,免得极小记录攒出上千条一个请求)。
constexpr int kMaxBatchRecords = 25;

} // namespace

ThreatIntelUploader::ThreatIntelUploader(ThreatIntelContribStore* store, QString baseUrl,
                                         QString token, int uploadHour, int timeoutSeconds)
    : store_(store), baseUrl_(std::move(baseUrl)), token_(std::move(token)),
      uploadHour_(std::clamp(uploadHour, 0, 23)),
      timeoutSecs_(timeoutSeconds > 0 ? timeoutSeconds : 15) {
    baseUrl_ = baseUrl_.trimmed();
    while (baseUrl_.endsWith(QLatin1Char('/')))
        baseUrl_.chop(1);
    maskedUrl_ = ReputationProxyOptions::maskUrl(baseUrl_); // 同在 bulwark::service 下,无需限定
}

ThreatIntelUploader::~ThreatIntelUploader() { stop(); }

bool ThreatIntelUploader::sleepInterruptible(int seconds) {
    if (seconds <= 0)
        return running_.load();
    std::unique_lock<std::mutex> lk(mx_);
    cv_.wait_for(lk, std::chrono::seconds(seconds), [this] { return !running_.load(); });
    return running_.load();
}

int ThreatIntelUploader::secondsUntilDailyHour(int hour) const {
    // 本机时区的下一个 hour:00;已过今天该时刻则顺延到明天。
    const QDateTime now = QDateTime::currentDateTime();
    QDateTime target(now.date(), QTime(std::clamp(hour, 0, 23), 0, 0));
    if (target <= now)
        target = target.addDays(1);
    qint64 secs = now.secsTo(target);
    // 小幅错峰(0~5 分钟):避免同一时刻全部端点一起打服务器。
    secs += QRandomGenerator::global()->bounded(300);
    return static_cast<int>(std::max<qint64>(1, secs));
}

int ThreatIntelUploader::uploadNow() {
    if (!enabled_.load() || baseUrl_.isEmpty() || !store_)
        return 0;
    if (unsupported_.load())
        return 0;

    const QVector<ThreatIntelContribStore::Record> pending = store_->snapshot();
    if (pending.isEmpty())
        return 0;

    const QString url = baseUrl_ + QStringLiteral("/v1/intel/contribute");
    QStringList headers{ QStringLiteral("Content-Type: application/json") };
    if (!token_.isEmpty())
        headers << (QStringLiteral("Authorization: Bearer ") + token_);
    // 刻意【不】带 X-Bulwark-Client 匿名机器 ID:情报按哈希去重,服务器并不需要知道是哪台机器
    // 报的。少送一个标识,「不涉及任何个人隐私信息」这句话就更站得住。

    int uploaded = 0;
    int i = 0;
    // 不以 running_ 作循环条件:uploadNow() 也支持在 worker 未启动时被手动/自检调用。
    while (i < pending.size()) {
        // 攒一批:同时受条数与负载字节数约束。
        QJsonArray arr;
        QStringList batchHashes;
        int bodyChars = 32; // {"records":[]} 的开销
        while (i < pending.size() && arr.size() < kMaxBatchRecords) {
            const QJsonObject o = pending.at(i).toJson();
            const int oChars =
                QJsonDocument(o).toJson(QJsonDocument::Compact).size() + 1; // +1 逗号
            if (!arr.isEmpty() && bodyChars + oChars > kMaxBodyChars)
                break;              // 这批满了,剩下的下一批发
            arr.append(o);
            batchHashes << pending.at(i).sha256;
            bodyChars += oChars;
            ++i;
        }
        if (arr.isEmpty())
            break; // 单条就超限(理论上不会,IOC 列表已按 kMaxPerList 截断):跳出,避免死循环

        QJsonObject root;
        root[QStringLiteral("records")] = arr;
        const QByteArray body = QJsonDocument(root).toJson(QJsonDocument::Compact);

        // 本类在 bulwark::service 下,ReputationCurl 在 bulwark::service::reputation 下,需限定。
        const auto res =
            reputation::ReputationCurl::postRaw(url, QString::fromUtf8(body), headers, timeoutSecs_);
        if (res.first == 404 || res.first == 405 || res.first == 501) {
            // 服务器没这个接口(旧版本 / 已关闭共享):记下来,今后不再尝试。本地暂存保留 ——
            // 用户若关掉开关,会由 purgeAll 清掉;不会悄悄堆积到无限大(队列本身有 500 条上限)。
            unsupported_.store(true);
            log_.info(QStringLiteral("服务器未提供情报共享接口(HTTP %1),本次不再尝试上传。")
                          .arg(res.first));
            break;
        }
        if (res.first != 200) {
            log_.info(QStringLiteral("威胁情报上传失败(%1 返回 HTTP %2),保留本地暂存待下次重试。")
                          .arg(maskedUrl_).arg(res.first));
            break; // 失败即停:大概率是网络/服务端问题,后面几批也白试
        }

        // 服务器若回了 accepted 列表就按它精确删除(它可能只收了一部分);没回则整批视为已收。
        QStringList toRemove = batchHashes;
        QJsonParseError err{};
        const QJsonDocument doc = QJsonDocument::fromJson(res.second.toUtf8(), &err);
        if (err.error == QJsonParseError::NoError && doc.isObject()) {
            const QJsonValue acc = doc.object().value(QLatin1String("accepted"));
            if (acc.isArray()) {
                QStringList only;
                const QJsonArray a = acc.toArray();
                for (const QJsonValue& v : a)
                    if (v.isString())
                        only << v.toString();
                toRemove = only; // 空数组 -> 什么都不删,留着下次重试
            }
        }
        // 上传成功即删除本地暂存 —— 这是「上传以后自动删除本地信息」那一条。
        uploaded += store_->removeUploaded(toRemove);
    }

    if (uploaded > 0)
        log_.info(QStringLiteral("威胁情报已上传 %1 条并清除本地暂存(剩余待传 %2 条)。")
                      .arg(uploaded).arg(store_->count()));
    return uploaded;
}

void ThreatIntelUploader::loop() {
    while (running_.load()) {
        // 先等到今晚的上传时刻。刻意【不】在启动时立刻上传:那会让每次重启服务都对外发一次
        // 请求,而这个功能的语义就是「每天晚上传一次」。开机很久没到点也无妨,队列在磁盘上。
        const int wait = secondsUntilDailyHour(uploadHour_);
        if (!sleepInterruptible(wait))
            return; // stop() 被调用
        if (!running_.load())
            return;
        if (!enabled_.load())
            continue; // 开关此刻是关的:跳过这一晚(不收集也不上传)
        uploadNow();
    }
}

void ThreatIntelUploader::start() {
    if (baseUrl_.isEmpty()) {
        log_.info(QStringLiteral("威胁情报共享未启动:未配置中央服务器端点。"));
        return;
    }
    if (running_.exchange(true))
        return;
    worker_ = std::thread([this] { loop(); });
    log_.info(QStringLiteral("威胁情报共享后台上传已就绪(端点 %1,每天 %2:00 上传;当前开关:%3)。")
                  .arg(maskedUrl_)
                  .arg(uploadHour_, 2, 10, QLatin1Char('0'))
                  .arg(enabled_.load() ? QStringLiteral("开") : QStringLiteral("关")));
}

void ThreatIntelUploader::stop() {
    if (!running_.exchange(false))
        return;
    {
        std::lock_guard<std::mutex> lk(mx_);
        cv_.notify_all();
    }
    if (worker_.joinable())
        worker_.join();
}

} // namespace bulwark::service
