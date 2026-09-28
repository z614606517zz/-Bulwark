#include "bulwark/service/reputation/ReputationCache.h"
#include "bulwark/service/AtomicFile.h"
#include "bulwark/service/Logger.h"

#include <QDir>
#include <QFile>
#include <QList>
#include <QPair>
#include <QTextStream>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>

#include <algorithm>

namespace bulwark::service::reputation {

namespace { constexpr qint64 kDayMs = 86400000LL; }

ReputationCache::ReputationCache(qint64 cleanTtlMs, qint64 unknownTtlMs, qint64 suspiciousTtlMs) {
    cleanTtlMs_ = cleanTtlMs;
    unknownTtlMs_ = unknownTtlMs > 0 ? unknownTtlMs : kDayMs;
    // 可疑不应比干净缓存得更久:默认取 min(cleanTtl, 1 天)。
    suspiciousTtlMs_ = suspiciousTtlMs > 0 ? suspiciousTtlMs : std::min<qint64>(cleanTtlMs, kDayMs);
    path_ = QDir(programDataDir()).filePath(QStringLiteral("reputation.jsonl"));
    load();
}

void ReputationCache::load() {
    QFile f(path_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QTextStream in(&f);
    while (!in.atEnd()) {
        const QString line = in.readLine().trimmed();
        if (line.isEmpty()) continue;
        QJsonParseError err{};
        const QJsonDocument doc = QJsonDocument::fromJson(line.toUtf8(), &err);
        if (err.error != QJsonParseError::NoError || !doc.isObject()) continue;
        const bulwark::FileReputation rep = bulwark::FileReputation::fromJson(doc.object());
        if (!rep.sha256.isEmpty()) cache_.insert(rep.sha256.toLower(), rep); // 后写覆盖先写
    }
    f.close();
    // 历史文件可能已经远超上限(此前没有任何界)。启动时压实一次:既把内存降到上限内,
    // 也顺带把文件里同一哈希的重复行清掉。ctor 期间无并发,可直接调 *Locked。
    if (cache_.size() > kMaxEntries)
        compactLocked();
}

std::optional<bulwark::FileReputation> ReputationCache::tryGet(const QString& sha256) {
    if (sha256.isEmpty()) return std::nullopt;
    QMutexLocker lk(&lock_);
    auto it = cache_.constFind(sha256.toLower());
    if (it == cache_.constEnd()) return std::nullopt;
    const bulwark::FileReputation& rep = it.value();
    const qint64 ageMs = rep.fetchedUtc.msecsTo(QDateTime::currentDateTimeUtc());

    switch (rep.verdict) {
        case bulwark::ReputationVerdict::Malicious:
            return rep; // 恶意永久有效
        case bulwark::ReputationVerdict::Unknown:
            if (ageMs > unknownTtlMs_) return std::nullopt;
            return rep;
        case bulwark::ReputationVerdict::Suspicious:
            if (ageMs > suspiciousTtlMs_) return std::nullopt;
            return rep;
        case bulwark::ReputationVerdict::Clean:
        default:
            if (ageMs > cleanTtlMs_) return std::nullopt;
            return rep;
    }
}

std::optional<bulwark::FileReputation> ReputationCache::tryGetForEnrichment(const QString& sha256) {
    if (sha256.isEmpty()) return std::nullopt;
    QMutexLocker lk(&lock_);
    auto it = cache_.constFind(sha256.toLower());
    if (it == cache_.constEnd()) return std::nullopt;
    if (it.value().verdict == bulwark::ReputationVerdict::Unknown) return std::nullopt; // 无信息不兜底
    return it.value(); // 陈旧兜底:即便过 TTL 也返回最近已知结论
}

void ReputationCache::store(const bulwark::FileReputation& rep) {
    if (rep.sha256.isEmpty() || !rep.querySucceeded) return; // 仅缓存权威结果
    QMutexLocker lk(&lock_);
    const bool isNewKey = !cache_.contains(rep.sha256.toLower());
    cache_.insert(rep.sha256.toLower(), rep);

    // 内存与文件都要设界。原实现两头都是【只增不减】的:
    //   · cache_ 从不淘汰 —— 过了 TTL 的条目只是在 tryGet 里被判为未命中,对象仍占着内存;
    //   · reputation.jsonl 只追加,而且按设计"后写覆盖先写"(见 load()),同一个哈希每次
    //     刷新都留一条新行,旧行永久留在文件里。启动时这个文件要整份解析。
    // 到阈值就压实:丢掉已过期条目,再整份重写文件(重写后文件里每个哈希只剩一条)。
    if (cache_.size() > kMaxEntries) {
        compactLocked();
        return;   // compactLocked 已整份重写,不必再追加本条
    }

    QFile f(path_);
    if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
        f.write(QJsonDocument(rep.toJson()).toJson(QJsonDocument::Compact));
        f.write("\r\n");
        f.close();
    }
    // 追加次数攒够了也压实一次,把历史重复行清掉(否则文件会远大于条目数)。
    if (isNewKey && ++appendsSinceCompact_ >= kCompactEveryAppends)
        compactLocked();
}

// 是否已过期(与 tryGet 的分档判据保持一致;恶意永久有效)。
bool ReputationCache::isExpiredLocked(const bulwark::FileReputation& rep, const QDateTime& now) const {
    const qint64 ageMs = rep.fetchedUtc.msecsTo(now);
    switch (rep.verdict) {
        case bulwark::ReputationVerdict::Malicious: return false;
        case bulwark::ReputationVerdict::Unknown:   return ageMs > unknownTtlMs_;
        case bulwark::ReputationVerdict::Suspicious:return ageMs > suspiciousTtlMs_;
        case bulwark::ReputationVerdict::Clean:
        default:                                    return ageMs > cleanTtlMs_;
    }
}

// 丢弃过期条目 + 整份重写文件(每哈希一条)。调用方须持 lock_。
void ReputationCache::compactLocked() {
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const int before = cache_.size();

    for (auto it = cache_.begin(); it != cache_.end();) {
        // 「陈旧兜底」(tryGetForEnrichment)要求过期的非 Unknown 结论仍可读,所以只真正删掉
        // Unknown 过期项;Clean/Suspicious 过期项保留结论以便兜底,除非总量还是超限。
        if (it.value().verdict == bulwark::ReputationVerdict::Unknown && isExpiredLocked(it.value(), now))
            it = cache_.erase(it);
        else
            ++it;
    }
    // 清完过期的仍超限:说明活跃条目本身太多,按取回时间丢最旧的(恶意结论优先保留)。
    if (cache_.size() > kMaxEntries) {
        QList<QPair<QDateTime, QString>> byAge;
        byAge.reserve(cache_.size());
        for (auto it = cache_.constBegin(); it != cache_.constEnd(); ++it)
            if (it.value().verdict != bulwark::ReputationVerdict::Malicious)
                byAge.append({ it.value().fetchedUtc, it.key() });
        std::sort(byAge.begin(), byAge.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        const int drop = std::min<int>(cache_.size() - kMaxEntries, byAge.size());
        for (int i = 0; i < drop; ++i)
            cache_.remove(byAge.at(i).second);
    }

    QByteArray out;
    for (auto it = cache_.constBegin(); it != cache_.constEnd(); ++it) {
        out += QJsonDocument(it.value().toJson()).toJson(QJsonDocument::Compact);
        out += "\r\n";
    }
    if (!writeFileAtomically(path_, out, QStringLiteral("信誉缓存"))) {
        Logger(QStringLiteral("bulwark.service.ReputationCache"))
            .warning(QStringLiteral("信誉缓存压实落盘失败(内存已压实):%1").arg(path_));
        return;
    }
    appendsSinceCompact_ = 0;
    Logger(QStringLiteral("bulwark.service.ReputationCache"))
        .info(QStringLiteral("信誉缓存已压实:%1 -> %2 条").arg(before).arg(cache_.size()));
}

} // namespace bulwark::service::reputation
