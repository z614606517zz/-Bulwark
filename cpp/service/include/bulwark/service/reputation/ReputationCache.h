#pragma once
#include "bulwark/models/FileReputation.h"

#include <QDateTime>
#include <QHash>
#include <QMutex>
#include <QString>

#include <optional>

// File-reputation cache (by SHA-256): in-memory map + JSONL persistence at
// %ProgramData%\Bulwark\reputation.jsonl (survives restarts). Tiered TTL:
// malicious = permanent, clean = cleanTtl, suspicious = shorter, unknown = short
// negative cache. tryGetForEnrichment returns the last-known non-unknown verdict
// even past TTL (stale fallback for the sync path). Thread-safe.
namespace bulwark::service::reputation {

class ReputationCache {
public:
    // TTLs in ms; pass <=0 for unknown/suspicious to use defaults.
    explicit ReputationCache(qint64 cleanTtlMs, qint64 unknownTtlMs = -1, qint64 suspiciousTtlMs = -1);

    // Hit + not expired -> verdict; miss or expired -> nullopt (caller may re-query).
    std::optional<bulwark::FileReputation> tryGet(const QString& sha256);

    // Enrichment read (sync path): last-known verdict even if stale; unknown -> nullopt.
    std::optional<bulwark::FileReputation> tryGetForEnrichment(const QString& sha256);

    // Store an authoritative (querySucceeded) result and append to disk.
    void store(const bulwark::FileReputation& rep);

private:
    void load();
    // 丢弃过期条目并整份重写 reputation.jsonl(每哈希一条)。调用方须持 lock_。
    void compactLocked();
    bool isExpiredLocked(const bulwark::FileReputation& rep, const QDateTime& now) const;

    // 内存条目上限,以及"追加多少条新哈希后压实一次文件"。
    //
    // 两者都是原先缺失的界:cache_ 从不淘汰(过期项只是查不中,对象还在),
    // reputation.jsonl 只追加且同一哈希每次刷新都留一条新行 —— 文件与内存都随使用时间
    // 单调增长,而启动时这个文件要整份解析。
    static constexpr int kMaxEntries          = 50000;
    static constexpr int kCompactEveryAppends = 2000;

    QString path_;
    QHash<QString, bulwark::FileReputation> cache_; // keys lower-cased
    QMutex lock_;
    int appendsSinceCompact_ = 0;
    qint64 cleanTtlMs_;
    qint64 unknownTtlMs_;
    qint64 suspiciousTtlMs_;
};

} // namespace bulwark::service::reputation
