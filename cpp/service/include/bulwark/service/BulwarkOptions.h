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

    QString ProxyUrl;                    // global HTTP proxy for all intel sources
    QStringList TrustedDirectories;      // wildcard dirs whose executables are fully allowed
    AiOptions Ai;
    EtwOptions Etw;

    // Load from an appsettings.json file: reads its top-level "Bulwark" object.
    // Missing file / missing keys keep defaults. Returns false only on parse error.
    bool loadFromFile(const QString& appsettingsPath);
};

} // namespace bulwark::service
