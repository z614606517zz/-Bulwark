namespace Bulwark.Core.Models;

/// <summary>
/// 运行时可调设置。UI 通过 IPC 读取/更新,服务据此调整规则引擎与防护行为。
/// 这是面向用户的设置快照(不含敏感内部状态)。
/// </summary>
public sealed class RuntimeSettings
{
    // ===== 总开关 =====
    /// <summary>总防护开关。关闭后所有事件直接放行。</summary>
    public bool ProtectionEnabled { get; set; } = true;

    // ===== 各防护维度开关(对应内核各回调 / 事件类型)=====
    public bool ProcessProtection { get; set; } = true;
    public bool FileProtection { get; set; } = true;
    public bool RegistryProtection { get; set; } = true;
    public bool SelfProtection { get; set; } = true;
    public bool NetworkProtection { get; set; } = true;

    // ===== 决策策略 =====
    /// <summary>自动放行带可信数字签名的主体。</summary>
    public bool TrustSignedActors { get; set; } = true;

    /// <summary>无规则/超时时的兜底动作(true=阻止,false=放行)。</summary>
    public bool DefaultBlock { get; set; } = false;

    /// <summary>
    /// 静默模式(默认信任·不弹窗)。开启后,所有原本需要"询问用户"的操作一律自动放行,
    /// 不再弹出裁决窗口;但对规则/启发式判定的**确定性高危恶意行为**仍照常拦截,
    /// 避免完全失去防护。适合不想被频繁打扰的用户。默认关闭。
    /// </summary>
    public bool SilentMode { get; set; }

    /// <summary>用户裁决弹窗等待超时(秒)。</summary>
    public int PromptTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// 是否启用 VirusTotal 威胁情报(哈希信誉查询)。开启后,对未签名+本机首见+
    /// 启发式可疑的新样本,后台限流查询 VT 哈希信誉;命中恶意则结束进程并固化拦截规则。
    /// 全程不阻塞实时裁决,只读哈希不上传文件。默认关闭(需在配置中提供 API Key)。
    /// </summary>
    public bool VirusTotalEnabled { get; set; }

    /// <summary>
    /// 是否启用 MalwareBazaar(abuse.ch)哈希信誉源。与 VirusTotal 并联,免费、无需付费配额。
    /// 命中即代表样本被收录为已知恶意。默认关闭。
    /// </summary>
    public bool MalwareBazaarEnabled { get; set; }

    /// <summary>
    /// 是否启用 AlienVault OTX 哈希信誉源。与 VirusTotal 并联,免费,需 API Key。
    /// 按关联威胁情报报告(pulse)数量给出结论。默认关闭。
    /// </summary>
    public bool OtxEnabled { get; set; }

    /// <summary>
    /// 是否启用微步在线 ThreatBook 哈希信誉源。与其它源并联,按 SHA-256 查询文件信誉;
    /// 命中恶意即结束进程并固化哈希拦截规则。需在服务端配置 API Key。默认关闭。
    /// </summary>
    public bool ThreatBookEnabled { get; set; }

    /// <summary>
    /// 是否启用微步 ThreatBook「IP 信誉」对网络防护里的可疑外联做情报互证。
    /// 因场景接口月配额极低(常见 20/月),默认关闭,由用户显式开启;
    /// 且仅对「已可疑的外联」查询、结果强缓存,绝不逐连接调用。
    /// </summary>
    public bool ThreatBookNetworkIntelEnabled { get; set; }

    /// <summary>
    /// 是否启用 MetaDefender Cloud(OPSWAT)多引擎哈希信誉源。与其它源并联。需服务端配置 API Key。默认关闭。
    /// </summary>
    public bool MetaDefenderEnabled { get; set; }

    /// <summary>
    /// 是否启用 Hybrid Analysis(Falcon Sandbox)哈希信誉源。与 VirusTotal 互证(双证据);
    /// 按 SHA-256 查询样本概览(verdict/threat_score/vx_family)。需服务端配置 API Key。默认关闭。
    /// </summary>
    public bool HybridAnalysisEnabled { get; set; }

    /// <summary>是否启用任一威胁情报源(任意一个开启即触发后台信誉查询流程)。</summary>
    public bool AnyReputationEnabled => VirusTotalEnabled || MalwareBazaarEnabled || OtxEnabled || ThreatBookEnabled || MetaDefenderEnabled || HybridAnalysisEnabled;

    /// <summary>
    /// 是否对「用户双击启动的应用」启用 AI 病毒扫描。
    /// 开启后,当用户经资源管理器(父进程为 explorer.exe)双击启动一个程序、
    /// 且规则引擎判定为放行时,额外调用大模型对该程序做一次病毒研判;
    /// 模型判定恶意则结束其进程树并告警。
    /// 大模型不可用 / 超时 / 未给出明确恶意结论时一律放行(fail-open),遵循低误报原则。
    /// 仅作用于「双击启动」这一用户主动行为,不打扰后台/子进程,避免噪音。默认开启。
    /// </summary>
    public bool AiScanDoubleClickEnabled { get; set; } = true;

    /// <summary>
    /// AI 研判期间是否挂起(冻结)被研判的进程,直到出结论再放行/查杀。
    /// 开启后:双击启动的程序在 AI 研判完成前不会真正运行(挂起其所有线程);
    /// 判定恶意则直接结束,判定安全/超时则恢复运行。默认开启。
    /// 注:WMI 模式下进程已创建后才被挂起,存在极短的"已执行几条指令"窗口;
    /// Driver 模式可做到更接近零执行的预拦截。
    /// </summary>
    public bool AiScanSuspendDuringScan { get; set; } = true;

    /// <summary>
    /// AI 研判失败/超时/不可用时的处置策略:
    /// false(默认)= fail-open,放行(遵循低误报、不打扰原则);
    /// true = fail-closed,拦截(更安全,但 AI 网络/配额抖动时可能误拦合法程序)。
    /// </summary>
    public bool AiScanBlockOnFailure { get; set; }

    // ===== AI(大模型)接入配置 =====
    /// <summary>
    /// 大模型 API 基址(OpenAI 兼容,需含 /v1)。例:https://token-plan-sgp.xiaomimimo.com/v1。
    /// 留空表示沿用 UI 内置默认值。UI 侧据此调用 /chat/completions 做病毒研判与规则生成。
    /// </summary>
    public string AiBaseUrl { get; set; } = string.Empty;

    /// <summary>大模型 API Key(Bearer)。留空表示未配置 —— AI 功能视为不可用(fail-open)。</summary>
    public string AiApiKey { get; set; } = string.Empty;

    /// <summary>大模型名称。例:mimo-v2.5-pro。留空表示沿用 UI 内置默认值。</summary>
    public string AiModel { get; set; } = string.Empty;

    // ===== AI 文件扫描内容提取上限(可配置,控制喂给大模型的体积/token)=====
    /// <summary>脚本/文本类文件读取源码的上限(KB)。默认 12(省 Credits;旧默认 32)。范围 1~512。</summary>
    public int AiScanScriptTextLimitKb { get; set; } = 12;

    /// <summary>二进制文件采样读取的上限(MB,取头+尾)。默认 4。范围 1~64。</summary>
    public int AiScanBinarySampleLimitMb { get; set; } = 4;

    /// <summary>从二进制提取可打印字符串的最大条数。默认 120(省 Credits;旧默认 400)。范围 50~2000。</summary>
    public int AiScanMaxStrings { get; set; } = 120;

    /// <summary>AI 配置是否完整可用(已填 Key,基址/模型可走默认)。</summary>
    public bool AiConfigured => !string.IsNullOrWhiteSpace(AiApiKey);

    /// <summary>
    /// 是否启用内核驱动防护(用户可控开关)。
    /// 开启后服务会尝试连接已加载的 Bulwark.sys 通信端口,实现内核级拦截;
    /// 关闭则仅用用户态事件源(WMI/模拟)观测。默认关闭,需用户显式开启。
    /// </summary>
    public bool KernelDriverEnabled { get; set; }

    /// <summary>
    /// 是否启用「用户态持续行为监控」。开启后,即使没有内核驱动(WMI 模式),
    /// 也能持续监视程序运行【之后】的危险行为:自启动持久化(启动文件夹落地、
    /// Run/RunOnce 注册表新增项)与勒索式批量改写(诱饵蜜罐 + 用户目录高速改写)。
    /// 这弥补了 WMI 模式只能观测「进程创建」、对事后恶意行为完全失明的盲区。
    /// 受各维度开关约束(文件类受 <see cref="FileProtection"/>、注册表类受
    /// <see cref="RegistryProtection"/> 控制)。默认开启。
    ///
    /// 局限(诚实说明):用户态无法把文件/注册表写入精确归因到发起进程的 PID,
    /// 故对勒索的处置以「告警 + 尽力而为」为主;真正的预拦截需连接同源内核驱动。
    /// </summary>
    public bool UserModeBehaviorMonitor { get; set; } = true;

    /// <summary>
    /// 是否在用户文档/桌面/图片目录投放「诱饵蜜罐(canary)」文件用于勒索早期发现。
    /// 任何进程改写/删除这些诱饵几乎可确认为勒索行为,是误报极低的强信号。
    /// 依赖 <see cref="UserModeBehaviorMonitor"/> 开启。默认开启。
    /// </summary>
    public bool RansomwareCanaryEnabled { get; set; } = true;

    /// <summary>
    /// 是否启用「行为基线异常检测」。开启后,引擎为每个程序建立正常行为画像(子进程 /
    /// 外联目标 / 写入目录),当程序出现显著偏离自身历史的行为时升分。偏离基线恒为软信号,
    /// 单独不触发拦截或弹窗,仅在与硬指标共现时升格(互证),直接服务"只对真正危险行为动手、
    /// 最小化打扰"的原则。关闭后仍持续学习画像,但不产出偏离信号。默认开启。
    /// </summary>
    public bool BehaviorBaselineEnabled { get; set; } = true;

    /// <summary>
    /// 是否启用「AI 灰区研判」。开启后,当规则引擎对一个事件判定为「询问」(灰区:既非确定性
    /// 恶意、也非强可信)时,先调用大模型研判再决定:AI 判恶意则升格拦截;AI 判干净且无硬指标
    /// 则降级放行(减少打扰);AI 不可用/超时则维持原弹窗(fail-open,绝不因 AI 抖动影响实时防护)。
    /// AI 单独不得压制硬恶意指标。默认关闭(会增加大模型调用,按需开启)。
    /// </summary>
    public bool AiGrayZoneConsultEnabled { get; set; }

    // ===== AI Credits 预算护栏 =====
    /// <summary>
    /// 是否启用「AI 月度 Credits 预算护栏」。开启后,本地按官方计费(输入 300 / 输出 600 Credits/token)
    /// 累计估算每月已消耗 Credits,接近 <see cref="AiMonthlyCreditBudget"/> 时自动停止调用大模型,
    /// 各功能 fail-open 退回本地引擎,硬性防止刷爆套餐额度。默认开启。
    /// </summary>
    public bool AiCreditGuardEnabled { get; set; } = true;

    /// <summary>
    /// 月度 Credits 额度(对应所购套餐:Lite=41亿、Standard=110亿、Pro=380亿、Max=820亿)。
    /// 默认 41 亿(Lite)。护栏用到该额度的 95% 即停。
    /// </summary>
    public long AiMonthlyCreditBudget { get; set; } = 4_100_000_000;

    /// <summary>当前用户态基础事件源(只读展示:Wmi / Simulated)。</summary>
    public string EventSource { get; set; } = "Wmi";

    /// <summary>内核驱动是否已连接(只读展示)。仅在 <see cref="KernelDriverEnabled"/> 开启且驱动已加载时为 true。</summary>
    public bool KernelConnected { get; set; }

    /// <summary>内核/防护引擎状态的可读描述(只读展示)。</summary>
    public string KernelStatus { get; set; } = string.Empty;

    /// <summary>
    /// 拦截恶意进程时,是否将其主体可执行文件移入隔离区(而非原地删除,可恢复)。
    /// 目的:防止「杀了进程但磁盘上的恶意文件仍在,重启/重新运行后再次作恶」。
    /// 仅对「确定性恶意」处置(命中 Block 规则 / 高危启发式 / 威胁情报确认)生效,
    /// 且严格排除带可信签名的主体与系统目录文件,避免误隔离合法程序。默认关闭(谨慎起见)。
    /// </summary>
    public bool QuarantineOnBlock { get; set; }

    public RuntimeSettings Clone() => (RuntimeSettings)MemberwiseClone();
}
