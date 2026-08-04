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
    // 客户端侧【请求数】预算,压在服务端 per-IP 滑窗限流之下。<=0 => 不限(不建议)。
    //
    // 为什么必须有这一层:服务端对 /v1/reputation/hash 按【来源 IP】滑窗限流(app.py 的
    // IPThrottle,默认 60/min + 600/h),超限直接回 429 且 retry_after_seconds=3600 —— 一小时
    // 起不来。而下面的 FreshQueriesPerDay 只统计「服务端真去问了付费上游」的那部分,命中服务端
    // 共享缓存的查询不计数,却照样占掉一个 IP 窗口名额。所以光有 FreshQueriesPerDay 完全挡不住
    // 请求数被耗尽:后台信誉队列排空时能在几分钟内把一小时的名额打光,之后整整一小时的查询
    // 全是 429。默认取服务端限额的一半,给同 IP 的网页端 / 其他工具留出余量。
    int RequestsPerMinute = 30;
    int RequestsPerHour = 300;
    // Daily budget of *fresh* server-intel lookups (server had to touch its paid upstream,
    // i.e. the reply was NOT served from the server-side shared cache). <=0 => unlimited
    // (dev/internal builds). Shipped/portable builds ship a small cap (e.g. 30) so the
    // package leans on local intel + the server's existing cache and only sparingly spends
    // the fleet's shared upstream quota. Server-cache hits never count against this.
    int FreshQueriesPerDay = 0;
    // 把本地查到、而服务器尚无记录的权威结论回传给服务器,让整个机队共享一份情报。
    // 最有价值的一类:本机首见文件上传 VirusTotal 扫出来的结论 —— 服务器凭哈希查不到,
    // 只有拿到文件的端点才能产出。回传只带结论(哈希 + verdict + 引擎计数 + 威胁名),
    // 不含文件内容、路径或任何机器标识。设为 false 可完全关闭回传(只读不写)。
    bool SyncResultsToServer = true;
    // 威胁情报共享的每日上传时刻(本机时区整点,0~23;默认凌晨 3 点,实际执行带 0~5 分钟
    // 错峰抖动)。是否真的收集与上传另由运行时开关 cloudBehaviorUploadEnabled 决定(默认关)。
    int ContributionUploadHour = 3;
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

// --- 攻击链组合引擎 ("Bulwark:AttackChainEngine") -----------------------------
// 从中央服务器下载「行为组合表」:哪几个动作凑在一起就足以定性(表由服务器从每日采集的
// 真实样本沙箱记录里数出来,见 server/bulwark-intel/engine_build.py)。客户端给每个进程记账,
// 凑齐组合即喂证据给既有裁决流水线。无模型、无训练,纯查表。
struct AttackChainOptions {
    bool Enabled = false;
    // 【默认只记录不拦截】。特征来自纯恶意样本库、没有正常文件作对照,故先在真机观察几天
    // 有无冤枉正常软件,确认后再把此项关掉转入强制。dry-run 下对裁决零影响。
    bool DryRun = true;
    // 端点。留空则复用 ReputationProxy 解析出的地址(本来就是同一台服务器,
    // 避免把混淆后的 URL 在配置里写两遍)。
    QString BaseUrl;
    int InitialDelaySeconds = 90;    // 避开开机拥塞;之后立刻同步一次(不必等到当天的更新时刻)
    // 每天几点(本机时区)自动更新,0-23。服务器在北京时间 00:00 重挖组合,故默认 6 点来取,
    // 留足余量。设为 -1 则改用下面的 RefreshIntervalHours 间隔式。
    int DailyUpdateHour = 6;
    // 间隔式刷新(仅当 DailyUpdateHour < 0 时生效)。<=0 => 仅启动时拉一次。
    int RefreshIntervalHours = 12;
    int QueryTimeoutSeconds = 15;
    // 记账保留窗口。没有「进程退出」事件可依赖(EventType::ProcessTerminate 是"有人要求结束",
    // 不是"进程已退出"),故只能靠时间窗 + 容量淘汰,与 ProcessChainTracker 同一思路取 30 分钟。
    int LedgerRetentionMinutes = 30;
    int LedgerMaxProcesses = 4096;
    // 只采纳到此强度为止的组合:hard(仅最强) / strong / ask(全部)。
    // 想更保守可设为 "strong" 或 "hard",服务器会据此少下发规则。
    QString MinGrade = QStringLiteral("ask");
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

    // --- 防护链路延迟(detection -> verdict)的两个硬上限 ------------------------
    // 内核事件出队间隔(毫秒)。读线程把事件放进队列,主线程按这个节拍取走再富化/裁决,
    // 所以它就是【空闲时第一条事件的延迟地板】,也是一条因果链上每一跳都要重付的固定成本。
    // 原来硬编码 150ms —— 对「行为发生到被拦下/弹窗」来说太贵,而空转一个 20ms 定时器的代价
    // 只是每秒 50 次「加锁看一眼队列空不空」,可以忽略。突发时不受此值影响:一次 tick 搬 32 条,
    // 还有积压就立刻(singleShot 0)再排一批,不等下一个 tick。
    int EventDrainIntervalMs = 20;
    // 事件热路径上「同步云信誉查询」的等待预算(毫秒)。<=0 = 热路径一律不联网(全交后台队列)。
    // 见 Worker::enrich 与 ReputationManager::queryNowBounded:这是单条事件能拖慢整条流水线的
    // 硬上限。原实现没有这个上限,一次缓存未命中就可能把流水线堵住二十多秒(代理超时 8s + 本地
    // 聚合最慢单源 10~15s),期间内核事件堆积到丢弃。服务器正常时 200~800ms 即回,故 800ms
    // 既能保住「首次执行的已知恶意不漏网」,又不会让服务器抖动传导成系统卡顿。
    int InlineReputationBudgetMs = 800;

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
    AttackChainOptions AttackChainEngine;   // 攻击链组合引擎(服务器挖组合,客户端记账对号)

    QString ProxyUrl;                    // global HTTP proxy for all intel sources
    QStringList TrustedDirectories;      // wildcard dirs whose executables are fully allowed
    AiOptions Ai;
    EtwOptions Etw;

    // Load from an appsettings.json file: reads its top-level "Bulwark" object.
    // Missing file / missing keys keep defaults. Returns false only on parse error.
    bool loadFromFile(const QString& appsettingsPath);
};

} // namespace bulwark::service
