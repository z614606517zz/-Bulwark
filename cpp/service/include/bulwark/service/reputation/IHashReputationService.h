#pragma once
#include "bulwark/models/FileReputation.h"
#include "bulwark/models/ReputationUsage.h"
#include "bulwark/models/ThreatBehaviorProfile.h"

#include <QString>
#include <utility>

// File-hash reputation source abstraction (query external intel by SHA-256).
// Faithful to Bulwark.Core/Engine/IHashReputationService.cs. Implementations must
// self-rate-limit + time out, and return an Unknown FileReputation on any failure
// (fail-open, never throw into the main flow).
namespace bulwark::service::reputation {

class IHashReputationService {
public:
    virtual ~IHashReputationService() = default;
    virtual bool isEnabled() const = 0;
    virtual bulwark::FileReputation query(const QString& sha256) = 0;
    virtual std::pair<bool, QString> testConnection() = 0;
    virtual bulwark::ReputationUsage getUsage() = 0;
    virtual QString name() const = 0;

    // Hot-swap the API key at runtime (UI settings). Default no-op for sources
    // without a key (e.g. the aggregator itself). Implementations must make this
    // thread-safe vs. their query() running on background workers.
    virtual void setApiKey(const QString& /*key*/) {}

    // Fetch a sandbox behavior profile (dropped files, registry, network IOCs) for
    // a sample. Default empty for sources that don't provide one. Implementations
    // must self-rate-limit + fail-open (never throw). Called on a background thread.
    virtual bulwark::ThreatBehaviorProfile fetchBehaviorProfile(const QString& /*sha256*/) {
        return {};
    }
};

} // namespace bulwark::service::reputation
