#pragma once
#include "bulwark/models/FileReputation.h"

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

    QString path_;
    QHash<QString, bulwark::FileReputation> cache_; // keys lower-cased
    QMutex lock_;
    qint64 cleanTtlMs_;
    qint64 unknownTtlMs_;
    qint64 suspiciousTtlMs_;
};

} // namespace bulwark::service::reputation
