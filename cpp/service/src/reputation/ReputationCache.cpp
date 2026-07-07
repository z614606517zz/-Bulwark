#include "bulwark/service/reputation/ReputationCache.h"
#include "bulwark/service/Logger.h"

#include <QDir>
#include <QFile>
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
    cache_.insert(rep.sha256.toLower(), rep);
    QFile f(path_);
    if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
        f.write(QJsonDocument(rep.toJson()).toJson(QJsonDocument::Compact));
        f.write("\r\n");
        f.close();
    }
}

} // namespace bulwark::service::reputation
