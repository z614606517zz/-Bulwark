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
    // 客户端侧【请求数】预算,压在服务端 per-IP 滑窗限流之下。<=0 => 该维不限。
    //
    // 【LookupOnly=true 时默认不生效:查询服务器收录不限次数。】那类请求只让服务端读自己的库,
    // 不花机队任何上游配额;而每挡掉一次「服务器收录了吗」,换来的都是客户端多烧一次自己的
    // VirusTotal 免费额度(4/min、500/天)—— 拿免费通路去省付费通路的钱,方向是反的。
    //
    // 这两个数字只在两种情况下才真正起作用:
    //   ① LookupOnly=false(允许服务端触达它的付费上游,那才是真要省的东西);
    //   ② 服务端真的回过一次 429 —— 说明对面是旧版 app.py,仍对只读查询按【来源 IP】滑窗限流
    //      (默认 60/min + 600/h,超限 retry_after_seconds=3600,一小时起不来)。此时客户端
    //      自动武装预算桶并收敛到这里的值(见 ProxyReputationService::tryConsumeRequestBudget),
    //      免得「不限次数」反过来把服务器这一跳整小时地打没,那比限住更差。
    // 新版服务端对 lookupOnly 的查询已旁路 per-IP 滑窗,故常态下这两项形同虚设 —— 保留它们是
    // 为了对着旧服务端仍有收敛手段。默认取服务端限额的一半,给同 IP 的网页端 / 其他工具留余量。
    int RequestsPerMinute = 30;
    int RequestsPerHour = 300;
    // Daily budget of *fresh* server-intel lookups (server had to touch its paid upstream,
    // i.e. the reply was NOT served from the server-side shared cache). <=0 => unlimited
    // (dev/internal builds). Shipped/portable builds ship a small cap (e.g. 30) so the
    // package leans on local intel + the server's existing cache and only sparingly spends
    // the fleet's shared upstream quota. Server-cache hits never count against this.
    int FreshQueriesPerDay = 0;
    // 【只查收录】把中央服务器只当成「这条哈希你收录了吗」的查询,永不请求它去问自己的上游
    // 付费情报源;未收录时改由本机密钥直连各情报源(见 ProxyReputationService::query 的回退)。
    //
    // 为什么不能用 FreshQueriesPerDay 表达这件事:那是【预算】语义 —— 预算内照样让服务端触达
    // 上游,耗尽后才降级;而且 <=0 表示「不限」,恰好是反的。两者是不同的轴:这个开关管
    // 「允不允许服务端问上游」,那个管「允许多少次」。
    //
    // ⚠ 生效需要服务端配合(app.py 读取 lookupOnly/cacheOnly 并直接返回库内结果)。老服务端
    //   会忽略该字段照样去问上游,此时客户端会在诊断日志里明确告警一次(见 .cpp)。
    bool LookupOnly = false;
    // 【本机端不动用任何第三方情报源:云端只用来查「这个哈希你收录了吗」】。
    //
    // 与 LookupOnly 是两条不同的轴,别搞混:
    //   · LookupOnly  管【服务端】要不要去问它自己的上游付费情报源;
    //   · ServerOnly  管【本机】要不要用自己的密钥直连第三方 —— 为真时:
    //       - 不用本机密钥查 VirusTotal / MalwareBazaar / OTX / 微步 / MetaDefender /
    //         HybridAnalysis(哈希查询、行为画像、VT 完整报告、逐源"测试连接"一并不发);
    //       - 【绝不上传文件】到 VirusTotal 云端扫描(那是最重的一次外发,也是隐私暴露面);
    //       - 云查毒链路因此只剩两级:本机分级缓存 -> 中央服务器是否已收录。
    //
    // 代价必须说清楚(这是个策略选择,不是优化):服务器没收录的文件就【没有云端结论】,
    // 只剩本地启发式/规则/内核基线兜底;服务器不可达时云端这一维直接为零。所以它默认 false,
    // 由部署方在 appsettings 里显式打开。
    //
    // 「服务器权威地答了『没有收录』」在这个模式下是一个【有效结论】(未收录),不是查询失败 ——
    // 卡片、历史与本地负缓存都按 Unknown 如实记账,不写成「查询失败」(见 Worker::runVtScan)。
    //
    // 不在本开关管辖内(刻意):外联 IP 情报仍走微步本机密钥(ThreatBookClient::queryIp)。
    // 服务端虽有 /v1/reputation/ip/<ip>,但客户端尚未接那条路;直接关掉它等于白白丢掉外联
    // 情报互证这一维,故留待单独接管,不在这里悄悄砍掉。
    bool ServerOnly = false;
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

// --- 在线更新 ("Bulwark:Update") ---------------------------------------------
// 软件内更新:UI 点「检查更新」-> 服务取清单 -> 弹窗给用户看版本与更新说明 ->
// 用户点下载 -> 服务下载并逐文件校验 -> 提权脚本换文件并重启。
//
// 端点刻意复用 ReputationProxy 解析出的地址(留空时),与 AttackChainEngine 同一套做法:
// 本来就是同一台服务器,把混淆后的 URL 在配置里写第二遍只会多一处会跑偏的地方。
//
// 安全边界见 bulwark/UpdateTrust.h —— 这里的任何开关都【不能】放宽签名校验:
// 那是这条通路唯一的信任锚点,做成可配置就等于没有。
struct UpdateOptions {
    bool Enabled = true;
    // 端点留空 => 复用 ReputationProxy 的地址。
    QString BaseUrl;
    // 更新通道。服务器按这个名字给不同的清单(stable / beta)。
    QString Channel = QStringLiteral("stable");
    int QueryTimeoutSeconds = 15;
    // 单个文件的下载超时。驱动和 exe 都是几 MB 量级,给足余量。
    int DownloadTimeoutSeconds = 180;
    // 启动后多久做一次静默检查(只查、不下载,有新版本时在 UI 上给个提示)。
    // <=0 => 不自动检查,只有用户手动点「检查更新」才发请求。
    // 默认 3 分钟:开机后头一两分钟机器最忙、网络常常还没真正通,立刻查的典型结果是
    // 查失败,而自动检查每个服务生命周期只做一次 —— 失败一次就等于这次开机没查。
    // 配置文件里没有 Update 段时用的就是这个值,所以它决定了「开箱是否会自动检查」。
    int AutoCheckDelayMinutes = 3;
    // 追加的签名者指纹(证书轮换期同时接受新旧两张)。只能追加,内置那一条永远有效,
    // 详见 UpdateTrust.h 里 pinnedThumbprints 的说明。
    QStringList AllowedThumbprints;
    // 有效端点:BaseUrl 优先,留空则由调用方传入 ReputationProxy 的地址。
    QString resolveBaseUrl(const QString& reputationProxyBaseUrl) const;
};

// --- 磁盘垃圾清理 -------------------------------------------------------------
// 功能本身的范围(哪些目录算垃圾)是【编译期写死】的,不在配置里 —— 一个能删文件的功能
// 如果从配置读路径,那份配置就成了任意文件删除的输入。这里只放「要不要开、留多久、扫多久」
// 这类不改变删除范围的旋钮,以及一份【只会让范围变小】的额外排除表。
struct DiskCleanupOptions {
    bool Enabled = true;
    // 只清理「最后修改时间早于 N 小时」的文件。正在被安装程序使用的临时文件通常刚写下 ——
    // 这个阈值就是为了不把别人正在进行的安装弄坏,是本功能最重要的一个旋钮。
    // 0 表示不按时间过滤(不建议:实测装大型软件时 %TEMP% 里确有正在使用的解压中间文件)。
    int MinFileAgeHours = 24;
    // 单类别的条数上限与单次操作的时间上限。防一个病态目录树(几百万文件 / 极深嵌套)把
    // 服务卡住;命中上限时结果标记为「下限估计」,如实告诉用户而不是假装扫完了。
    int MaxFilesPerCategory = 300000;
    int MaxSeconds = 120;
    // 额外排除(不区分大小写的路径子串)。只能【缩小】清理范围,加进来的路径永远不会被动。
    QStringList ExcludePaths;
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
    UpdateOptions Update;                   // 在线更新(签名钉死,见 bulwark/UpdateTrust.h)
    DiskCleanupOptions DiskCleanup;         // 磁盘垃圾清理(范围写死在代码里,这里只有旋钮)

    QString ProxyUrl;                    // global HTTP proxy for all intel sources
    QStringList TrustedDirectories;      // wildcard dirs whose executables are fully allowed
    AiOptions Ai;
    EtwOptions Etw;

    // Load from an appsettings.json file: reads its top-level "Bulwark" object.
    // Missing file / missing keys keep defaults. Returns false only on parse error.
    bool loadFromFile(const QString& appsettingsPath);
};

} // namespace bulwark::service
