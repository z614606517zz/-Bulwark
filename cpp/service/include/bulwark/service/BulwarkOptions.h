#pragma once
#include "bulwark/models/Enums.h"

#include <QString>
#include <QStringList>

// Service configuration, bound from the "Bulwark" section of appsettings.json.
// Faithful port of Bulwark.Service/BulwarkOptions.cs: same field names (so the
// existing appsettings.json binds unchanged), same defaults, same env-var
// resolution precedence for secrets. Binding is tolerant (missing keys keep
// their defaults) and case-insensitive, matching .NET's Configuration.Bind.
namespace bulwark::service {

using bulwark::VerdictAction;

// --- ETW telemetry source ("Bulwark:Etw") -----------------------------------
struct EtwOptions {
    bool Enabled = true;                 // master switch; degrades gracefully on failure
    bool DnsClient = true;               // Microsoft-Windows-DNS-Client (per-process DNS)
    bool KernelNetwork = true;           // Microsoft-Windows-Kernel-Network TCP egress
    bool KernelRegistry = true;          // Microsoft-Windows-Kernel-Registry (persistence-key writes)
    bool KernelFile = true;              // Microsoft-Windows-Kernel-File (watched-path writes/deletes)
    bool NetworkUntrustedOnly = true;    // only report egress from untrusted-signed actors
    int PerProcessNetPerMinute = 600;    // per-process TCP egress flood cap
    int PerProcessRegPerMinute = 240;    // per-process registry write report cap
    int PerProcessFilePerMinute = 240;   // per-process file write/delete report cap
    bool SuspiciousOnly = true;          // only report DNS the DGA analyzer pre-flags (>0)
    QString SessionName = QStringLiteral("Bulwark-ETW");
    int RawChannelCapacity = 8192;       // raw event relay capacity; overflow is dropped
    int PerProcessDnsPerMinute = 120;    // per-process DNS report cap
    int DedupWindowSeconds = 60;         // (process, domain/key/path) dedup window
};

// --- Large-model (AI) access ("Bulwark:Ai"), OpenAI-compatible ---------------
struct AiOptions {
    static constexpr const char* ApiKeyEnvVar = "BULWARK_AI_APIKEY";
    QString BaseUrl;   // OpenAI-compatible base (must include /v1)
    QString ApiKey;    // Bearer; prefer the env var over storing here
    QString Model;
    // Env var takes precedence over the config field, then trimmed.
    QString resolveApiKey() const;
};

// --- MalwareBazaar (abuse.ch) ("Bulwark:MalwareBazaar") ----------------------
struct MalwareBazaarOptions {
    static constexpr const char* AuthKeyEnvVar = "BULWARK_MB_AUTHKEY";
    QString BaseUrl = QStringLiteral("https://mb-api.abuse.ch/api/v1/");
    bool Enabled = false;
    QString AuthKey;   // env var BULWARK_MB_AUTHKEY takes precedence
    int RequestsPerMinute = 10;
    int RequestsPerDay = 2000;
    int QueryTimeoutSeconds = 10;
};

// --- AlienVault OTX ("Bulwark:Otx") ------------------------------------------
struct OtxOptions {
    static constexpr const char* ApiKeyEnvVar = "BULWARK_OTX_APIKEY";
    QString BaseUrl = QStringLiteral("https://otx.alienvault.com/api/v1/indicators/file/");
    bool Enabled = false;
    QString ApiKey;
    int RequestsPerMinute = 10;
    int RequestsPerDay = 1000;
    int QueryTimeoutSeconds = 10;
    int MaliciousPulseThreshold = 3; // pulses >= this => Malicious
};

// --- ThreatBook (微步在线) ("Bulwark:ThreatBook") ----------------------------
struct ThreatBookOptions {
    static constexpr const char* ApiKeyEnvVar = "BULWARK_THREATBOOK_APIKEY";
    QString BaseUrl = QStringLiteral("https://api.threatbook.cn/v3/file/report");
    QString IpIntelBaseUrl = QStringLiteral("https://api.threatbook.cn/v3/scene/ip_reputation");
    bool Enabled = false;
    QString ApiKey;
    int RequestsPerMinute = 3;
    int RequestsPerDay = 300;
    int SceneRequestsPerMonth = 20;   // IP-reputation monthly quota (very low)
    bool NetworkIntelEnabled = false; // use IP intel for egress corroboration
    int QueryTimeoutSeconds = 10;
};

// --- MetaDefender Cloud (OPSWAT) ("Bulwark:MetaDefender") --------------------
struct MetaDefenderOptions {
    static constexpr const char* ApiKeyEnvVar = "BULWARK_MDC_APIKEY";
    QString BaseUrl = QStringLiteral("https://api.metadefender.com/v4/hash/");
    bool Enabled = false;
    QString ApiKey;
    int RequestsPerMinute = 6;
    int RequestsPerDay = 100;
    int QueryTimeoutSeconds = 10;
    int MaliciousThreshold = 3; // detecting engines >= this => Malicious
};

// --- Hybrid Analysis (Falcon Sandbox) ("Bulwark:HybridAnalysis") -------------
struct HybridAnalysisOptions {
    static constexpr const char* ApiKeyEnvVar = "BULWARK_HA_APIKEY";
    QString BaseUrl = QStringLiteral("https://www.hybrid-analysis.com/api/v2/overview/");
    bool Enabled = false;
    QString ApiKey;
    int RequestsPerMinute = 5;
    int RequestsPerDay = 200;
    int QueryTimeoutSeconds = 10;
    int MaliciousThreatScore = 70; // threat_score >= this => Malicious
};

} // namespace bulwark::service

namespace bulwark::service {

// --- VirusTotal ("Bulwark:VirusTotal") ---------------------------------------
struct VirusTotalOptions {
    static constexpr const char* ApiKeyEnvVar = "BULWARK_VT_APIKEY";
    QString BaseUrl = QStringLiteral("https://www.virustotal.com/api/v3/files/");
    QString UploadUrl = QStringLiteral("https://www.virustotal.com/api/v3/files");
    QString BigUploadUrlEndpoint = QStringLiteral("https://www.virustotal.com/api/v3/files/upload_url");
    QString AnalysesUrl = QStringLiteral("https://www.virustotal.com/api/v3/analyses/");
    bool Enabled = false;
    QString ApiKey; // env var BULWARK_VT_APIKEY takes precedence
    int RequestsPerMinute = 4;
    int RequestsPerDay = 500;
    int PriorityDailyReserve = 50; // daily quota reserved for memory-protection verifies
    int QueryTimeoutSeconds = 10;
    int MaliciousThreshold = 5;    // detecting engines >= this => Malicious
    int CleanCacheTtlDays = 7;
    int SuspiciousCacheTtlHours = 24;
    int UnknownCacheTtlHours = 24;
};

// --- ThreatFox (abuse.ch) intel feed ("Bulwark:ThreatFoxFeed") ---------------
// Batch-pulls recent malicious IOCs and auto-generates a batch of block rules.
struct ThreatFoxFeedOptions {
    static constexpr const char* AuthKeyEnvVar = "BULWARK_ABUSECH_AUTHKEY";
    // Source tag prefix written into DefenseRule.Note (identify/dedup/refresh).
    static QString ruleNoteTag() { return QString::fromUtf8("[\xE6\x83\x85\xE6\x8A\xA5-ThreatFox]"); }
    QString BaseUrl = QStringLiteral("https://threatfox-api.abuse.ch/api/v1/");
    bool Enabled = false;
    QString AuthKey; // env var > this field > MalwareBazaar's key (same abuse.ch account)
    int Days = 3;               // pull IOCs from the last N days (1..7)
    int MinConfidence = 75;     // only trust IOCs with confidence >= this
    int MaxRules = 500;         // cap rules generated per pull
    int RuleTtlDays = 7;        // generated rules expire after this
    bool GenerateHashRules = true;
    bool GenerateIpRules = true;
    bool GenerateDomainRules = false;
    int InitialDelaySeconds = 60;
    int RefreshIntervalHours = 12; // <=0 => pull once at startup only
    int QueryTimeoutSeconds = 30;
    // Env var > this field > caller-supplied MalwareBazaar fallback key.
    QString resolveAuthKey(const QString& malwareBazaarFallback) const;
};

// --- Central reputation proxy ("Bulwark:ReputationProxy") --------------------
// Optional shared server-side intel cache/aggregator. When Enabled, file-hash
// lookups go to this proxy FIRST (one shared cache + upstream API keys held
// server-side for the whole fleet); on ANY failure the client transparently
// falls back to the direct per-source aggregate, so protection never regresses.
struct ReputationProxyOptions {
    static constexpr const char* TokenEnvVar = "BULWARK_REPPROXY_TOKEN";
    static constexpr const char* UrlEnvVar = "BULWARK_REPPROXY_URL";
    QString BaseUrl;                 // plaintext endpoint (dev builds); empty => use obfuscated/env
    QString BaseUrlObfuscated;       // obfuscated endpoint for shipped/portable configs (base64 of XOR);
                                     // decoded by resolveBaseUrl() so the URL never sits in plaintext config
    QString BearerToken;             // env var BULWARK_REPPROXY_TOKEN takes precedence
    bool Enabled = false;
    int QueryTimeoutSeconds = 8;
    // Daily budget of *fresh* server-intel lookups (server had to touch its paid upstream,
    // i.e. the reply was NOT served from the server-side shared cache). <=0 => unlimited
    // (dev/internal builds). Shipped/portable builds ship a small cap (e.g. 30) so the
    // package leans on local intel + the server's existing cache and only sparingly spends
    // the fleet's shared upstream quota. Server-cache hits never count against this.
    int FreshQueriesPerDay = 0;
    QString resolveToken() const;    // env var > this field
    // Effective endpoint, precedence: env var (BULWARK_REPPROXY_URL) > plaintext BaseUrl >
    // deobfuscated BaseUrlObfuscated. Empty result => proxy disabled (fail-open to local).
    QString resolveBaseUrl() const;
    // Host-masked form for logs/diagnostics (e.g. "https://***:8787") so the endpoint is
    // never emitted in plaintext, matching the "hidden endpoint" intent of shipped builds.
    static QString maskUrl(const QString& url);
    // Produce the BaseUrlObfuscated value for a plaintext URL (inverse of the decode in
    // resolveBaseUrl): XOR with a fixed in-binary key then base64. Used by the
    // `--obfuscate-url` build helper to generate the value baked into shipped configs.
    static QString obfuscateUrl(const QString& plain);
    // Reverse of obfuscateUrl(); empty on malformed input. Exposed for tests/tools.
    static QString deobfuscateUrl(const QString& obfuscated);
};

// --- Root options ("Bulwark") ------------------------------------------------
struct BulwarkOptions {
    static constexpr const char* SectionName = "Bulwark";

    QString EventSource = QStringLiteral("Wmi"); // "Wmi" (ETW observation) or "Driver" (kernel + ETW)
    bool KernelDriverEnabled = true;             // full-dimension protection needs the driver on
    bool TrustSignedActors = true;
    VerdictAction DefaultAction = VerdictAction::Allow;
    int PromptTimeoutSeconds = 30;
    bool ExportEcsAlerts = false;                // ECS jsonl alerts for SIEM
    bool EnforceUiClientSignature = false;       // require signed UI over the named pipe
    QStringList UiClientAllowedThumbprints;      // SHA-1 thumbprint allowlist (normalized)
    QStringList UiClientAllowedPublishers;       // subject/CN substring allowlist
    bool OnlineCertRevocationCheck = false;      // online CRL/OCSP (may block seconds)

    // Driver-mode-only enforcement lists (substring match, case-insensitive).
    QStringList ProtectedPaths;          // block delete/rename on match
    QStringList FileHardBlocks;          // kernel-deny any write/delete/rename open
    QStringList ProtectedRegistryKeys;   // block set/delete value/key on match
    QStringList RegistryHardBlocks;      // kernel-deny writes (must be precise!)
    // Command-line hard block: kernel denies process creation when the full command line
    // matches. Patterns are '+'-separated token conjunctions - EVERY token must appear as a
    // case-insensitive substring (see BLW_CMD_ADD_CMDBLOCK). This is what stops LOLBin abuse
    // (vssadmin/wmic/bcdedit ...) BEFORE the command runs, instead of killing the process
    // afterwards - by which time the damage (deleted shadow copies) is already irreversible.
    // Keep every token >= 4 chars: tokens are plain substrings, so short ones like "cl"
    // would hit unrelated words and cause false positives.
    QStringList CommandHardBlocks;       // extra user patterns, appended to the built-in baseline
    bool CommandHardBlockBaseline = true;// push the built-in ransomware/credential-theft baseline
    QStringList MemoryProtectionTargets; // anti-injection target process names
    int MemoryProtectionVtVerifyPerHour = 4; // VT verify rate for injection sources
    QStringList BlockedRemoteEndpoints;  // "ip" or "ip:port" egress blacklist

    VirusTotalOptions VirusTotal;
    MalwareBazaarOptions MalwareBazaar;
    OtxOptions Otx;
    ThreatBookOptions ThreatBook;
    MetaDefenderOptions MetaDefender;
    HybridAnalysisOptions HybridAnalysis;
    ThreatFoxFeedOptions ThreatFoxFeed;
    ReputationProxyOptions ReputationProxy; // central shared intel proxy (proxy-first, fail-open)

    QString ProxyUrl;                    // global HTTP proxy for all intel sources
    QStringList TrustedDirectories;      // wildcard dirs whose executables are fully allowed
    AiOptions Ai;
    EtwOptions Etw;

    // Load from an appsettings.json file: reads its top-level "Bulwark" object.
    // Missing file / missing keys keep defaults. Returns false only on parse error.
    bool loadFromFile(const QString& appsettingsPath);
};

} // namespace bulwark::service
