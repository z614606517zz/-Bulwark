using Bulwark.Core.Models;

namespace Bulwark.Service;

/// <summary>服务配置(绑定 appsettings.json 的 "Bulwark" 节)。</summary>
public sealed class BulwarkOptions
{
    public const string SectionName = "Bulwark";

    /// <summary>事件源:"Wmi"(真实进程监控)或 "Simulated"(模拟演示)。</summary>
    public string EventSource { get; set; } = "Wmi";

    /// <summary>
    /// 内核驱动事件源默认是否启用。默认 true —— 全维度实时防护(文件/注册表/网络/
    /// 反注入/自我保护,以及内核本地硬拦截)全部依赖驱动事件源,只有它常开,
    /// 已运行进程的后续行为才会被监控与处置。基础 WMI 源只能产生「进程创建」事件,
    /// 无法覆盖已运行进程,因此驱动源必须默认开启,否则防护形同只对新进程生效。
    /// 仅在首次运行(无持久化设置)时作为初值;之后以用户在 UI 的开关为准。
    /// 若运行环境未加载 Bulwark.sys,协调器会自动重试连接并降级展示,不影响基础源。
    /// </summary>
    public bool KernelDriverEnabled { get; set; } = true;

    /// <summary>是否自动信任带可信签名的主体。</summary>
    public bool TrustSignedActors { get; set; } = true;

    /// <summary>无规则/超时时的兜底动作。</summary>
    public VerdictAction DefaultAction { get; set; } = VerdictAction.Allow;

    /// <summary>用户裁决等待超时(秒)。</summary>
    public int PromptTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// 是否导出 ECS(Elastic Common Schema)结构化告警到
    /// %ProgramData%\Bulwark\alerts\alerts-yyyyMMdd.jsonl(每行一条 JSON),供 SIEM 采集。
    /// 默认关闭;开启后每个已处置事件都会额外写一条含证据链与 ATT&CK 技战术的 ECS 文档。
    /// </summary>
    public bool ExportEcsAlerts { get; set; }

    /// <summary>
    /// 是否强制校验 UI 客户端(命名管道连接方)的数字签名。
    ///
    /// 命名管道 ACL 已限定为 SYSTEM/Administrators 可连,但这只挡住非管理员进程。
    /// 开启本项后,服务端在接受连接时还会要求对端可执行文件【带可信数字签名】,
    /// 否则拒绝连接——堵住「任意管理员级进程冒充 UI 关防护/加白/还原隔离」的口子。
    ///
    /// 默认 false:开发/调试态 UI 多为未签名(或经 dotnet run 启动),强制校验会阻断正常联调。
    /// 正式发布(UI 已带签名)应在 appsettings 中置 true 启用纵深防御第二道。
    /// </summary>
    public bool EnforceUiClientSignature { get; set; }

    /// <summary>
    /// 是否对主体文件证书做【在线】吊销校验(CRL/OCSP)。默认 false:仅用本机已缓存 CRL,
    /// 绝不联网、不阻塞富化。开启后能命中"被盗证书已被 CA 吊销"的样本(对应 RuleEngine 的
    /// CertRevoked 硬拦),代价是每次校验可能因网络往返耗时数秒——建议仅在用户态(WMI)
    /// 富化模式、可接受该延迟时开启。映射到 <see cref="Monitoring.ProcessInspector.OnlineRevocationCheck"/>。
    /// </summary>
    public bool OnlineCertRevocationCheck { get; set; }

    /// <summary>
    /// 受保护文件路径列表(子串匹配,大小写不敏感)。
    /// 仅在 EventSource=Driver 时生效:对命中的删除/重命名进行拦截。
    /// 例如:"C:\\Important" 或 "\\Documents\\".
    /// </summary>
    public string[] ProtectedPaths { get; set; } = System.Array.Empty<string>();

    /// <summary>
    /// 文件「硬拦截」名单(子串匹配,大小写不敏感)。仅在 EventSource=Driver 时生效。
    /// 命中的文件,任何【写/删/重命名/覆盖】打开都被【内核本地直接拒绝】(STATUS_ACCESS_DENIED),
    /// 只读打开放行;原地阻断、零延迟、不经用户态、不可绕过。
    ///
    /// 比 ProtectedPaths 更强:ProtectedPaths 仅拦删除/重命名,这里连内容篡改(带写权限的打开)
    /// 也拦。适用于「绝不允许被改一次」的关键文件,典型如:
    ///   "\\drivers\\etc\\hosts"(DNS 劫持)
    ///   "\\System32\\sethc.exe"、"\\System32\\utilman.exe"(粘滞键/辅助功能后门)
    ///   "\\System32\\config\\SAM"、"\\System32\\config\\SECURITY"(凭据库)
    /// 名单应尽量精确,避免误伤正常写入(如不要放整个 \\System32\\)。
    /// </summary>
    public string[] FileHardBlocks { get; set; } = System.Array.Empty<string>();

    /// <summary>
    /// 受保护注册表键列表(子串匹配,大小写不敏感)。
    /// 仅在 EventSource=Driver 时生效:对命中键的写值/删值/删键进行拦截。
    /// 内核键路径形如 "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"。
    /// </summary>
    public string[] ProtectedRegistryKeys { get; set; } = System.Array.Empty<string>();

    /// <summary>
    /// 注册表「硬拦截」名单(精确子串匹配,大小写不敏感)。仅在 EventSource=Driver 时生效。
    /// 命中的注册表写入会被【内核本地直接拒绝】(STATUS_ACCESS_DENIED),原地阻断、零延迟,
    /// 不经用户态、不可被绕过。
    ///
    /// ⚠ 必须是精确键值,绝不可放宽到 "\\Services" 这类系统高频写入的宽子串(会拦死系统)。
    /// 适用于「绝不允许被改一次」的极少数关键键值,典型如:
    ///   "\\Winlogon\\Shell"、"\\Winlogon\\Userinit"(Shell/登录劫持)
    ///   "\\Image File Execution Options\\sethc.exe\\Debugger"(粘滞键后门)
    ///   "\\Image File Execution Options\\utilman.exe\\Debugger"
    /// 与 ProtectedRegistryKeys(宽松监控 + 启动后处置)互补:这里是硬底线,那里是广覆盖。
    /// </summary>
    public string[] RegistryHardBlocks { get; set; } = System.Array.Empty<string>();

    /// <summary>
    /// 内存防护(反注入)目标进程名列表(文件名,大小写不敏感)。仅在 EventSource=Driver 时生效。
    /// 当非可信进程试图对这些进程申请「写内存 / 远程线程」类权限时,内核(ObCallbacks)
    /// 剥离这些权限,使跨进程代码注入写不进去;只剥写类权限,保留读/查询/结束,尽量不误伤
    /// 正常工具。典型目标:lsass.exe(防抓密码)、winlogon.exe、浏览器、微信/QQ 等被注入高发进程。
    ///
    /// 工作方式:服务在连接后枚举现有进程、并在每次进程创建事件时,按名匹配本列表,
    /// 把命中进程的 PID 下发给内核(BLW_CMD_ADD_MEMPROT)。本软件自身进程已由自我保护覆盖。
    /// </summary>
    public string[] MemoryProtectionTargets { get; set; } = System.Array.Empty<string>();

    /// <summary>
    /// 网络黑名单。仅在 EventSource=Driver 时生效:命中的外发连接将被内核阻断。
    /// 条目格式 "1.2.3.4" 或 "1.2.3.4:443"(省略端口表示任意端口)。
    /// </summary>
    public string[] BlockedRemoteEndpoints { get; set; } = System.Array.Empty<string>();

    /// <summary>VirusTotal 威胁情报集成配置。</summary>
    public VirusTotalOptions VirusTotal { get; set; } = new();

    /// <summary>MalwareBazaar(abuse.ch)哈希信誉集成配置。免费,需一个免费 Auth-Key。</summary>
    public MalwareBazaarOptions MalwareBazaar { get; set; } = new();

    /// <summary>AlienVault OTX 哈希信誉集成配置。免费,需 API Key。</summary>
    public OtxOptions Otx { get; set; } = new();

    /// <summary>微步在线 ThreatBook 哈希信誉集成配置(国内威胁情报,按哈希查询文件信誉)。</summary>
    public ThreatBookOptions ThreatBook { get; set; } = new();

    /// <summary>MetaDefender Cloud(OPSWAT)多引擎哈希信誉集成配置。</summary>
    public MetaDefenderOptions MetaDefender { get; set; } = new();

    /// <summary>Hybrid Analysis(Falcon Sandbox)哈希信誉集成配置。需服务端配置 API Key。</summary>
    public HybridAnalysisOptions HybridAnalysis { get; set; } = new();

    /// <summary>ThreatFox(abuse.ch)情报 feed 配置:定期拉取最近恶意 IOC,自动生成一批防护规则。</summary>
    public ThreatFoxFeedOptions ThreatFoxFeed { get; set; } = new();

    /// <summary>大模型(AI)接入配置。用于双击启动 AI 病毒扫描、AI 规则生成等。</summary>
    public AiOptions Ai { get; set; } = new();
}

/// <summary>
/// 大模型(AI)接入配置(OpenAI 兼容协议)。仅 UI 侧使用 —— 服务不直连大模型,
/// 而是经 IPC 把扫描请求转交 UI 完成,确保 API Key 不需要在服务层暴露/落盘到管理员权限的位置。
/// 这里仅作为「首次运行的默认值」推给 UI;用户可在 UI 设置页随时覆盖,落盘到运行时设置。
/// </summary>
public sealed class AiOptions
{
    /// <summary>环境变量名:优先从此环境变量读取 API Key(覆盖配置文件中的 ApiKey)。</summary>
    public const string ApiKeyEnvVar = "BULWARK_AI_APIKEY";

    /// <summary>OpenAI 兼容 API 基址(需含 /v1)。</summary>
    public string BaseUrl { get; set; } = string.Empty;

    /// <summary>
    /// API Key(Bearer)。空表示未配置。
    /// 出于安全考虑,强烈建议留空并改用环境变量 <see cref="ApiKeyEnvVar"/>,
    /// 不要把密钥硬编码到配置文件(会随仓库泄露)。
    /// </summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>模型名称(如 mimo-v2.5-pro)。</summary>
    public string Model { get; set; } = string.Empty;

    /// <summary>
    /// 解析最终生效的 API Key:环境变量 <see cref="ApiKeyEnvVar"/> 优先,其次配置文件中的 <see cref="ApiKey"/>。
    /// 与 VirusTotal/OTX/MalwareBazaar 的密钥解析策略一致。
    /// </summary>
    public string ResolveApiKey()
    {
        var env = System.Environment.GetEnvironmentVariable(ApiKeyEnvVar);
        if (!string.IsNullOrWhiteSpace(env)) return env.Trim();
        return ApiKey?.Trim() ?? string.Empty;
    }
}

/// <summary>
/// MalwareBazaar(abuse.ch)哈希信誉查询配置。绑定 "Bulwark:MalwareBazaar" 节。
/// 完全免费、无需付费配额;命中即代表样本被收录为已知恶意,高可信。
/// 新版 abuse.ch API 强制要求一个免费的 Auth-Key(环境变量 BULWARK_MB_AUTHKEY),
/// 未配置 Auth-Key 时本源不启用(匿名请求会被拒 401)。
/// </summary>
public sealed class MalwareBazaarOptions
{
    /// <summary>环境变量名:优先从此环境变量读取 Auth-Key。</summary>
    public const string AuthKeyEnvVar = "BULWARK_MB_AUTHKEY";

    /// <summary>是否启用 MalwareBazaar 信誉查询。</summary>
    public bool Enabled { get; set; }

    /// <summary>Auth-Key(回退用)。优先级:环境变量 BULWARK_MB_AUTHKEY > 此字段。</summary>
    public string? AuthKey { get; set; }

    /// <summary>每分钟最大请求数。</summary>
    public int RequestsPerMinute { get; set; } = 10;

    /// <summary>每日最大请求数。</summary>
    public int RequestsPerDay { get; set; } = 2000;

    /// <summary>单次查询的 HTTP 超时(秒)。</summary>
    public int QueryTimeoutSeconds { get; set; } = 10;
}

/// <summary>
/// AlienVault OTX 哈希信誉查询配置。绑定 "Bulwark:Otx" 节。
/// 免费,需要一个 OTX API Key(环境变量 BULWARK_OTX_APIKEY)。
/// 返回关联的 pulse(威胁情报报告)数量与标签,用于富化威胁名称。
/// </summary>
public sealed class OtxOptions
{
    /// <summary>环境变量名:优先从此环境变量读取 API Key。</summary>
    public const string ApiKeyEnvVar = "BULWARK_OTX_APIKEY";

    /// <summary>是否启用 OTX 信誉查询。</summary>
    public bool Enabled { get; set; }

    /// <summary>API Key(回退用)。优先级:环境变量 BULWARK_OTX_APIKEY > 此字段。</summary>
    public string? ApiKey { get; set; }

    /// <summary>每分钟最大请求数。</summary>
    public int RequestsPerMinute { get; set; } = 10;

    /// <summary>每日最大请求数。</summary>
    public int RequestsPerDay { get; set; } = 1000;

    /// <summary>单次查询的 HTTP 超时(秒)。</summary>
    public int QueryTimeoutSeconds { get; set; } = 10;

    /// <summary>"恶意"判定阈值:关联 pulse 数 >= 此值判为 Malicious。</summary>
    public int MaliciousPulseThreshold { get; set; } = 3;
}

/// <summary>
/// 微步在线 ThreatBook 哈希信誉查询配置。绑定 "Bulwark:ThreatBook" 节。
/// 调用 https://api.threatbook.cn/v3/file/report,按 SHA-256 查询文件信誉(恶意/可疑/正常)。
/// 需要一个 API Key(环境变量 BULWARK_THREATBOOK_APIKEY 优先,其次配置 ApiKey)。
/// 免费档常见配额:300/天、30 分钟内 100 次,故默认限流保守。
/// </summary>
public sealed class ThreatBookOptions
{
    /// <summary>环境变量名:优先从此环境变量读取 API Key。</summary>
    public const string ApiKeyEnvVar = "BULWARK_THREATBOOK_APIKEY";

    /// <summary>是否启用微步 ThreatBook 信誉查询。</summary>
    public bool Enabled { get; set; }

    /// <summary>API Key(回退用)。优先级:环境变量 BULWARK_THREATBOOK_APIKEY > 此字段。</summary>
    public string? ApiKey { get; set; }

    /// <summary>每分钟最大请求数(配合 30 分钟 100 次配额,保守取 3)。</summary>
    public int RequestsPerMinute { get; set; } = 3;

    /// <summary>每日最大请求数(免费档约 300)。</summary>
    public int RequestsPerDay { get; set; } = 300;

    /// <summary>
    /// 场景接口(IP 信誉 / 失陷检测)的每月配额上限。免费档极低(常见 20/月),
    /// 故与文件信誉配额分开计数。仅对「已可疑的外联」做情报互证时消耗。
    /// </summary>
    public int SceneRequestsPerMonth { get; set; } = 20;

    /// <summary>
    /// 是否允许在网络防护里用微步 IP 信誉对可疑外联做情报互证。
    /// 因场景接口月配额极低,默认关闭,由用户显式开启。
    /// </summary>
    public bool NetworkIntelEnabled { get; set; }

    /// <summary>单次查询的 HTTP 超时(秒)。</summary>
    public int QueryTimeoutSeconds { get; set; } = 10;
}

/// <summary>
/// MetaDefender Cloud(OPSWAT)多引擎哈希信誉查询配置。绑定 "Bulwark:MetaDefender" 节。
/// 调用 GET https://api.metadefender.com/v4/hash/{sha256},返回多引擎检出结果。
/// API Key:环境变量 BULWARK_MDC_APIKEY 优先,其次配置 ApiKey。
/// </summary>
public sealed class MetaDefenderOptions
{
    /// <summary>环境变量名:优先从此环境变量读取 API Key。</summary>
    public const string ApiKeyEnvVar = "BULWARK_MDC_APIKEY";

    /// <summary>是否启用 MetaDefender Cloud 信誉查询。</summary>
    public bool Enabled { get; set; }

    /// <summary>API Key(回退用)。优先级:环境变量 BULWARK_MDC_APIKEY > 此字段。</summary>
    public string? ApiKey { get; set; }

    /// <summary>每分钟最大请求数(免费档保守取 6)。</summary>
    public int RequestsPerMinute { get; set; } = 6;

    /// <summary>每日最大请求数(免费档约 100)。</summary>
    public int RequestsPerDay { get; set; } = 100;

    /// <summary>单次查询的 HTTP 超时(秒)。</summary>
    public int QueryTimeoutSeconds { get; set; } = 10;

    /// <summary>"恶意"判定阈值:检出引擎数 >= 此值判为 Malicious。</summary>
    public int MaliciousThreshold { get; set; } = 3;
}

/// <summary>
/// Hybrid Analysis(Falcon Sandbox)哈希信誉查询配置。绑定 "Bulwark:HybridAnalysis" 节。
/// 调用 GET https://www.hybrid-analysis.com/api/v2/overview/{sha256},按 SHA-256 查询样本概览,
/// 读取 verdict(malicious/suspicious/whitelisted/no specific threat)、threat_score(0~100)、
/// vx_family、multiscan_result。作为与 VirusTotal 互证的第二权威源(双证据)。
///
/// HA 要求请求头携带 api-key 与固定 User-Agent("Falcon Sandbox"),否则返回 403。
/// API Key:环境变量 BULWARK_HA_APIKEY 优先,其次配置 ApiKey。免费档配额有限,默认限流保守。
/// </summary>
public sealed class HybridAnalysisOptions
{
    /// <summary>环境变量名:优先从此环境变量读取 API Key。</summary>
    public const string ApiKeyEnvVar = "BULWARK_HA_APIKEY";

    /// <summary>是否启用 Hybrid Analysis 信誉查询。</summary>
    public bool Enabled { get; set; }

    /// <summary>API Key(回退用)。优先级:环境变量 BULWARK_HA_APIKEY > 此字段。</summary>
    public string? ApiKey { get; set; }

    /// <summary>每分钟最大请求数(免费档保守取 5)。</summary>
    public int RequestsPerMinute { get; set; } = 5;

    /// <summary>每日最大请求数(免费档约 200)。</summary>
    public int RequestsPerDay { get; set; } = 200;

    /// <summary>单次查询的 HTTP 超时(秒)。</summary>
    public int QueryTimeoutSeconds { get; set; } = 10;

    /// <summary>"恶意"判定的 threat_score 阈值:verdict 非明确恶意时,threat_score >= 此值判为 Malicious。</summary>
    public int MaliciousThreatScore { get; set; } = 70;
}

/// <summary>
/// VirusTotal 哈希信誉查询配置。绑定 appsettings.json 的 "Bulwark:VirusTotal" 节。
/// API Key 强烈建议通过环境变量 BULWARK_VT_APIKEY 提供,不要硬编码到配置文件。
/// </summary>
public sealed class VirusTotalOptions
{
    /// <summary>环境变量名:优先从此环境变量读取 API Key(覆盖配置文件中的 ApiKey)。</summary>
    public const string ApiKeyEnvVar = "BULWARK_VT_APIKEY";

    /// <summary>是否启用 VirusTotal 信誉查询。默认关闭,需用户显式开启并提供 Key。</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// API Key(回退用)。优先级:环境变量 BULWARK_VT_APIKEY > 此字段。
    /// 出于安全考虑,建议留空并改用环境变量。
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>每分钟最大请求数(免费层为 4)。</summary>
    public int RequestsPerMinute { get; set; } = 4;

    /// <summary>每日最大请求数(免费层为 500)。</summary>
    public int RequestsPerDay { get; set; } = 500;

    /// <summary>单次哈希查询的 HTTP 超时(秒)。</summary>
    public int QueryTimeoutSeconds { get; set; } = 10;

    /// <summary>"恶意"判定阈值:检出引擎数 >= 此值判为 Malicious。</summary>
    public int MaliciousThreshold { get; set; } = 5;

    /// <summary>干净结论的缓存有效期(天)。恶意结论永久缓存。</summary>
    public int CleanCacheTtlDays { get; set; } = 7;

    /// <summary>可疑结论的缓存有效期(小时)。应短于干净缓存:可疑样本更易在短期内升级为已知恶意。</summary>
    public int SuspiciousCacheTtlHours { get; set; } = 24;

    /// <summary>Unknown(VT 未收录/查询失败)的负缓存有效期(小时)。避免反复查同一未收录文件。</summary>
    public int UnknownCacheTtlHours { get; set; } = 24;
}

/// <summary>
/// ThreatFox(abuse.ch)情报 feed 配置。绑定 "Bulwark:ThreatFoxFeed" 节。
///
/// 与「信誉源(逐条查询某 IOC 好不好)」不同,本 feed 是【批量拉取最近已知恶意 IOC】,
/// 用来【一次性生成一批防护规则】——主动防御的「情报订阅 → 自动布防」。
///
/// 数据来源:POST https://threatfox-api.abuse.ch/api/v1/  body {"query":"get_iocs","days":N}
///   鉴权:请求头 Auth-Key(abuse.ch 账号密钥,与 MalwareBazaar 同一个;留空则回退用 MalwareBazaar 的)。
/// 生成规则:
///   · sha256_hash → 按哈希 Block 规则(该文件任何行为都拦,改名无效);
///   · ip:port     → NetworkConnect Block 规则(拦截外联到该 IP);
///   · domain(可选)→ NetworkConnect Block 规则(TargetPattern 含该域名)。
/// 生成的规则统一带来源标记 <see cref="RuleNoteTag"/> 和过期时间(随 feed 刷新,避免无限堆积)。
/// </summary>
public sealed class ThreatFoxFeedOptions
{
    /// <summary>情报生成规则的来源标记前缀(写入 DefenseRule.Note,便于识别/去重/刷新)。</summary>
    public const string RuleNoteTag = "[情报-ThreatFox]";

    /// <summary>环境变量名:优先从此环境变量读取 abuse.ch Auth-Key。</summary>
    public const string AuthKeyEnvVar = "BULWARK_ABUSECH_AUTHKEY";

    /// <summary>是否启用 ThreatFox 情报 feed 自动生成规则。默认关闭。</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// abuse.ch Auth-Key(回退用)。优先级:环境变量 BULWARK_ABUSECH_AUTHKEY &gt; 此字段 &gt;
    /// 复用 MalwareBazaar 的 AuthKey(同一个 abuse.ch 账号)。
    /// </summary>
    public string? AuthKey { get; set; }

    /// <summary>拉取最近多少天的 IOC(ThreatFox 支持 1~7)。</summary>
    public int Days { get; set; } = 3;

    /// <summary>只采信置信度 &gt;= 此值的 IOC(0~100),降低误报。</summary>
    public int MinConfidence { get; set; } = 75;

    /// <summary>单次最多生成多少条规则(防止一次性灌入过多)。</summary>
    public int MaxRules { get; set; } = 500;

    /// <summary>生成规则的有效期(天)。到期自动失效(feed 会刷新),避免规则无限堆积。</summary>
    public int RuleTtlDays { get; set; } = 7;

    /// <summary>是否生成「按 SHA-256 哈希拦截」规则。</summary>
    public bool GenerateHashRules { get; set; } = true;

    /// <summary>是否生成「拦截外联到恶意 IP」规则。</summary>
    public bool GenerateIpRules { get; set; } = true;

    /// <summary>是否生成「拦截外联到恶意域名」规则(域名匹配较弱,默认关闭)。</summary>
    public bool GenerateDomainRules { get; set; }

    /// <summary>启动后首次拉取的延迟(秒),避开服务启动高峰。</summary>
    public int InitialDelaySeconds { get; set; } = 60;

    /// <summary>自动刷新周期(小时);&lt;=0 表示只在启动时拉一次,不周期刷新。</summary>
    public int RefreshIntervalHours { get; set; } = 12;

    /// <summary>单次请求 HTTP 超时(秒)。</summary>
    public int QueryTimeoutSeconds { get; set; } = 30;

    /// <summary>解析最终生效的 Auth-Key:环境变量 &gt; 本字段 &gt; 回退调用方传入的 MalwareBazaar key。</summary>
    public string ResolveAuthKey(string? malwareBazaarFallback)
    {
        var env = System.Environment.GetEnvironmentVariable(AuthKeyEnvVar);
        if (!string.IsNullOrWhiteSpace(env)) return env.Trim();
        if (!string.IsNullOrWhiteSpace(AuthKey)) return AuthKey!.Trim();
        return malwareBazaarFallback?.Trim() ?? string.Empty;
    }
}
