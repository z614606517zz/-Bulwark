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
    //
    // Kernel-Process ImageLoad (event 5, keyword 0x40) -> ImageLoad events.
    //
    // 为什么必须有:这一维在【没有内核驱动】时原本完全不存在 —— EventType::ImageLoad 的唯一
    // 产出点是 DriverEventSource。于是 EventSource=Wmi(或驱动掉线)时,整条白加黑 / BYOVD
    // 检测线是空转的:DefenseRule 的 requireTargetSigned / requireTargetUnsigned 规则、
    // InjectionAnalyzer::analyzeImageLoad、RemoteControlAnalyzer::analyzeImModuleLoad、
    // KillChainAnalyzer 对 .sys 加载的判定,一条都不会被求值。那不是「少一个动作」,是看不见。
    //
    //
    // Kernel-File Create(12)+ Write(16) 关联,用于给【勒索诱饵被改写】找出真正的写入者。
    //
    // 【它补的洞】无驱动时诱饵命中靠 QFileSystemWatcher,那个通知不带写入者 —— 所以
    // UserModeBehaviorSource 自己在头注释里写着「诱饵命中只告警不结束进程」。而引擎侧
    // RuleEngine 对 canaryHit 是【无条件 Block + 硬指标 100 分】。两边一合,结果是产品里
    // 最强的勒索信号在无驱动模式下产出一个【没人可杀的 Block】,最终只落 AlertedOnly。
    // 打开本项后 Write 事件的事件头 ProcessId 就是写入者(已实机核对),诱饵命中能直接
    // 走 killMalicious 结束勒索进程树。
    //
    // 【为什么默认关】实测代价:现有 keyword 0x1400(DeletePath + CreateNewFile)在一个
    // 1.6 秒窗口里产 19 条事件(约 12/s);加上 CREATE(0x80)与 WRITE(0x200)后同一窗口
    // 4823 条(约 3000/s)—— 回调次数涨约 250 倍。Create 事件(12)占了其中 4493 条,而
    // 其中绝大多数是与诱饵毫无关系的文件。这是【全局遥测换一个窄用途】,所以必须由部署方
    // 明确选择,不能默认替所有人付这个账。开之前请先看本机 bulwark_service.exe 的 CPU 占用。
    //
    // 【精度前提·别删】FileObject 是【按句柄】的地址,句柄关闭后会被复用到无关文件上
    //(实测:同一个 FileObject 值在 1.6 秒里被 17 个事件用过,分属 5 个不同进程)。所以
    // FileObject -> 路径 的映射必须在「任何 Create 复用了同一个地址」时立刻擦除,否则会把
    // 别人的写入误报成诱饵被改写 —— 而那条路径的终点是杀进程。实现见 EtwProcessEventSource。
    //
    bool KernelFileWriteAttribution = false;
    // 参与写入归因的路径条数上限(诱饵通常个位数;留余量并防止无界增长)。
    int AttributionPathMax = 256;
    bool KernelImageLoad = true;
    //
    // Kernel-Process ThreadStart (event 3, keyword 0x20) -> RemoteThread events.
    //
    // 同上:RemoteThread 事件此前也只有驱动能产出,所以无驱动时 InjectionAnalyzer::
    // analyzeRemoteThread 与 CredentialAccessAnalyzer 里「RemoteThread 且目标是 lsass」这条
    // 凭据窃取判定恒不成立,RuleDsl 的全部 s.thread(...) 规则都是死规则。
    //
    // 判别方式经实机 ETW 抓取验证:事件头 ProcessId = 建线程的【发起方】,负载 ProcessID =
    // 线程所属进程,两者不等即跨进程。误报护栏见 RemoteThreadMinTargetAgeMs。
    //
    bool KernelRemoteThread = true;
    bool NetworkUntrustedOnly = true;    // only report egress from untrusted-signed actors
    int PerProcessNetPerMinute = 600;    // per-process TCP egress flood cap
    int PerProcessRegPerMinute = 240;    // per-process registry write report cap
    int PerProcessFilePerMinute = 240;   // per-process file write/delete report cap
    int PerProcessImagePerMinute = 120;  // per-process module-load report cap
    int PerProcessThreadPerMinute = 60;  // per-process cross-process thread report cap
    //
    // 跨进程 ThreadStart 判为「注入」所要求的【目标进程最小存活时长】(毫秒)。
    //
    // 这条护栏不是保守起见加的,是实测必需:子进程的初始线程也由创建方建立,所以【每一次
    // 正常的进程创建】都会产生一条「事件头 PID != 负载 PID」的 ThreadStart。一次 5.5 秒的
    // 抓取里 13 条跨进程 ThreadStart,只有 1 条是真注入 —— 其余是初始线程与 System(PID 4)
    // 的内核线程。区分办法是时间差:初始线程与目标的 ProcessStart 同刻,真注入晚得多
    // (探针里晚 1.5 秒)。500ms 取的是「进程创建到初始线程」与「注入」之间那道很宽的沟。
    //
    int RemoteThreadMinTargetAgeMs = 500;
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

// --- 自有端点(信誉代理 / 更新服务器)的 TLS 信任锚 ---------------------------
//
// 本类存在的唯一原因:自有端点可能用自签证书,而本产品出网的每一条通道(情报查询、
// 情报上传、文件上传、更新清单、更新载荷下载)都要在这条链上跑。
//
// 【为什么不能靠关掉校验解决】原实现给每一条 curl 命令都加了 -k(--insecure),于是所有
// 请求头里的 bearer token 与各家 API 密钥、上传的用户文件、以及「取下来要以 SYSTEM 执行」
// 的更新载荷,全部暴露在任意中间人面前。详见 ReputationCurl.h 里 TlsMode 的说明。
//
// 【为什么这两项不算「可配置地放宽安全」】它们不是开关,是【指定信任谁】:
//   · CaBundlePath 收窄信任根(比默认的公网 CA 池更严);
//   · PinnedPublicKeys 把连接钉死在指定公钥上(证书被换掉就连不上)。
// 两项都不填时行为是「按公网 CA 完整校验」,即最严的默认值 —— 配错只会连不上,不会静默降级。
struct SelfHostedTlsOptions {
    // 自有端点证书链的 PEM 文件(推荐)。非空时只信这一份锚,链与主机名校验全部保留。
    QString CaBundlePath;
    // 公钥固定值,形如 "sha256//base64=="(可多条,证书轮换期同时接受新旧)。
    // 仅在 CaBundlePath 为空时使用。取法见 ReputationCurl.h。
    QStringList PinnedPublicKeys;
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

    // --- 被盗用 / 被滥用的代码签名证书(见 bulwark/engine/TrustPolicy.h 的 isAbusedSigner)---
    //
    // 「有签名就默认放过」唯一的失效方式,是签名来自一张被偷走的证书:链完整、未吊销,于是
    // 全部信任档都会放行。银狐(ValleyRAT / Winos)一类团伙长期这么干。吊销要等 CA 反应,而
    // 本机默认只读缓存 CRL(OnlineCertRevocationCheck 默认 false),空窗期很长 —— 这两项就是
    // 那段空窗期里按【签名者】拒绝的手段。粒度选签名者而不是哈希:一张被盗证书签出的变种是
    // 无穷的,指纹与主体名才是不变的那一头。
    //
    // 命中的语义是【撤销该主体的全部签名信任档】,不是直接拦截:事件回到正常的行为检测与
    // 规则流水线,并记一个硬指标。
    QStringList AbusedSignerThumbprints;         // SHA-1 指纹,可带空格/冒号(内部归一)
    QStringList AbusedSignerPublishers;          // 证书主体名,按词边界匹配;每条须 >= 4 字符

    // 自有端点的 TLS 信任锚(见 SelfHostedTlsOptions 的说明)。留空 = 按公网 CA 完整校验。
    SelfHostedTlsOptions SelfHostedTls;

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

    QString ProxyUrl;                    // global HTTP proxy for all intel sources
    QStringList TrustedDirectories;      // wildcard dirs whose executables are fully allowed

    //
    // --- 用户态执行前拦截(无内核驱动时的替代)-----------------------------------
    //
    // 对已确认恶意的映像长期持有 share-mode-0 独占句柄,使 CreateProcess 与加载器的那次打开
    // 直接失败。这是 EventSource=Wmi / 驱动掉线时唯一的「行为前」拦截手段;在它之前用户态的
    // 每个 Block 都只是事后 kill,样本下次启动照旧运行。
    //
    // 【为什么需要一个关闭开关】share-mode-0 不只挡执行,还挡读取:被钉住的文件在解锁前
    // 连备份软件和别的杀软都读不了(我们自己的隔离也读不了,故内部有显式放手协议)。这对
    // 某些部署环境是不可接受的副作用,必须留逃生口 —— 关掉后行为与改动前完全一致。
    bool UserModeExecBlockEnabled = true;
    // 名单条数上限(约束:规则注入必须有上限)。超限时拒绝新增并大声记录,绝不静默挤掉旧条目。
    int UserModeExecBlockMax = 256;

    //
    // --- 用户态进程收容(阶段 2:处置编排)---------------------------------------
    //
    // 同时被冻结 / 断子的进程数上限。刻意比执行名单小一个量级:这两种状态都直接作用在
    // 【正在运行的进程】上,量大了对系统可用性的影响远比多几条文件名单严重。
    int UserModeContainmentMax = 64;
    // 「等裁决」型冻结的自动解冻时限(毫秒)。这类冻结的对象尚未确认恶意,没人来裁决时
    // 必须自己放手 —— 否则用户看到的只是「程序卡住了」,连一条安全提示都没有。
    // 已确认恶意且杀不掉的那种冻结【不受此限制】(见 UserModeProcessContainment::freeze
    // 的 autoThaw 参数),对那种进程到期放行等于自己撤销自己的处置。
    int UserModeFreezeTtlMs = 120000;
    // 「检出即挂起」(2.3):弹窗待裁决期间把主体冻住。
    //
    // 补的是无驱动时最不容易被看见的那一段:有驱动时进程创建/命令行是在内核回调里【阻塞等
    // 裁决】的,样本压根还没开始跑;无驱动时事件是 ETW 事后观测,弹窗的同时它正在全速工作,
    // 用户思考的那几秒就是它的可用时间。能力表上写着「有检测」,实际检测到了也拦不住这一次。
    //
    // 默认开,但有三道收窄(见 Worker 里 Ask 分支的注释):仅在内核不等裁决时、仅对已凑到
    // 硬恶意指标的事件、且冻结带自动解冻兜底。关掉后该行为整项消失。
    bool UserModeFreezeOnDetect = true;

    //
    // --- 阶段 3:用户确认型加固 ------------------------------------------------------
    //
    // 这一组与上面所有开关有一个本质区别:它们改的是【跨重启的系统状态】。所以默认全关,
    // 且刻意不做成「装上就生效」—— 任务定义本身就是「用户显式确认型」。
    // 只读体检(SystemHardening::inspect)不受这些开关约束,启动时总会跑一次并记进日志:
    // 让部署方看到「有哪些加固可做、各自的代价是什么」不需要任何授权。
    //
    // 【撤销侧永远是接上的】:哪怕这些开关后来被关掉,此前已经加上的 ACE 仍然要能被
    // 「用户加白」撤销。否则关掉开关会把已有的跨重启封堵变成永久孤儿。
    //
    // 3.5 对已确认恶意的映像加「拒绝执行」ACE(DENY Everyone:FILE_EXECUTE)。
    // 这是 UserModeExecBlock 独占句柄「不跨重启」的真正补位,两者可叠加。
    // 实测:执行失败 winerr 5,读取不受影响(所以不妨碍本产品自己的隔离),可撤销;
    // 但按文件不按路径 —— 复制一份即可绕过。
    bool FileDenyExecuteEnabled = false;
    // 3.1 注册表即时监视 + 自动回滚。监视本身无副作用,【自动回滚】才是系统改动,
    // 故整项默认关。打开后:被监视键里指向未加白程序的新增/修改值会被立刻还原。
    bool RegistryInstantRollbackEnabled = false;

    // 3.3 / 3.4 的「用户显式确认」入口。
    //
    // 这两项原本只有只读体检、没有任何地方能让用户确认执行 —— 功能齐备而交互路径缺一半。
    // 加 UI 入口需要新增 IPC 消息类型,而那条路被并行工作线占着;但「用户确认」并不必须是
    // 一次点击:**把这个键从 false 改成 true 本身就是一次显式的、留痕的、可回退的确认**,
    // 而且它比一个弹窗更适合这两件事 —— 它们改的是跨重启的机器状态,本来就该由管理配置的人
    // 决定,而不是由碰巧坐在这台机器前的人点一下。
    //
    // 两项都在【每次启动时】核对现状,已达标就跳过并记一行,不重复写。
    bool ApplyLsaRunAsPpl = false;        // 写 RunAsPPL=2(代码只接受 2,见 SystemHardening)
    bool ApplySelfServiceDacl = false;    // 收紧本服务 DACL(保留 SYSTEM + Administrators)

    //
    // --- 用户态出站封禁(无内核驱动时的替代)-------------------------------------
    //
    // 在 WFP 的 ALE_AUTH_CONNECT_V4 层挂 BLOCK 过滤器,命中的出站 connect 当场失败
    // (WSAEACCES)。用动态会话:过滤器随服务进程退出自动清除,不跨重启 —— 刻意如此,因为
    // 本产品目前没有任何地方能撤销 IP 封禁,持久过滤器一旦下错就是「连不上网且查不出原因」。
    //
    // 顺带修掉一个真实缺口:BlockedRemoteEndpoints 此前【只在内核驱动连上时才生效】,
    // EventSource=Wmi 或驱动掉线时部署方配的出站黑名单是完全无效的(配了等于没配)。
    bool UserModeNetworkBlockEnabled = true;
    int UserModeNetworkBlockMax = 256;

    AiOptions Ai;
    EtwOptions Etw;

    // Load from an appsettings.json file: reads its top-level "Bulwark" object.
    // Missing file / missing keys keep defaults. Returns false only on parse error.
    bool loadFromFile(const QString& appsettingsPath);
};

} // namespace bulwark::service
