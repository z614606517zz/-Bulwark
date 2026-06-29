using System;

namespace Bulwark.Core.Models;

/// <summary>
/// 防护事件类型。对应内核/服务监控到的敏感行为维度。
/// </summary>
public enum EventType
{
    ProcessCreate,      // 进程创建
    ProcessTerminate,   // 结束进程
    RemoteThread,       // 远程线程注入
    ImageLoad,          // 模块/驱动加载
    FileWrite,          // 文件写入/修改
    FileDelete,         // 文件删除
    RegistryWrite,      // 注册表写入(启动项/服务等)
    NetworkConnect,     // 网络外联
    SelfProtect,        // 自我保护(自身被操作)
}

/// <summary>
/// 一次需要裁决的安全事件。由监控层(内核驱动/用户态采集器)产生,
/// 经规则引擎处理后得到 <see cref="Verdict"/>。
/// </summary>
public sealed class SecurityEvent
{
    /// <summary>事件唯一 Id,用于异步裁决关联。</summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>事件产生时间(UTC)。</summary>
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;

    public EventType Type { get; set; }

    /// <summary>发起行为的主体进程 Id。</summary>
    public int ActorPid { get; set; }

    /// <summary>发起行为的主体进程映像路径。</summary>
    public string ActorPath { get; set; } = string.Empty;

    /// <summary>主体进程文件 SHA-256(可空,采集失败时为空)。</summary>
    public string? ActorHash { get; set; }

    /// <summary>主体进程是否带可信数字签名。</summary>
    public bool ActorSigned { get; set; }

    /// <summary>主体文件存在签名但校验失败(HashMismatch/篡改/盗用证书)。比"无签名"更可疑。</summary>
    public bool SignatureMismatch { get; set; }

    /// <summary>主体文件大小(字节)。0 表示未知。用于检测"文件膨胀"规避。</summary>
    public long ActorFileSize { get; set; }

    /// <summary>签名发行商名称(如 "Microsoft Corporation"),可空。</summary>
    public string? ActorPublisher { get; set; }

    /// <summary>签名证书指纹(SHA-1 Thumbprint,大写十六进制)。用于指纹白名单/黑名单精确判定,可空。</summary>
    public string? ActorCertThumbprint { get; set; }

    /// <summary>签名证书的有效期截止(NotAfter,UTC)。null 表示无签名或未采集。</summary>
    public DateTime? CertNotAfterUtc { get; set; }

    /// <summary>Authenticode 反签名时间戳(签名时间,UTC)。null 表示无时间戳或未采集。</summary>
    public DateTime? SigningTimeUtc { get; set; }

    /// <summary>签名证书已被吊销(CRL/OCSP 校验)。被盗用证书常已吊销 —— 强可疑。</summary>
    public bool CertRevoked { get; set; }

    /// <summary>
    /// 签名证书在文件落地/签名时已过期(或在证书有效期外签名)。
    /// 合法厂商不会用过期证书签名新文件,常见于盗用旧证书。
    /// </summary>
    public bool SignedAfterCertExpiry { get; set; }

    /// <summary>主体文件在本机首次出现(按哈希判定)。配合"新证书"是抓空壳公司样本的关键信号。</summary>
    public bool IsFirstSeen { get; set; }

    /// <summary>
    /// 外部文件信誉结论(如 VirusTotal 哈希查询命中的缓存结果)。null 表示无信誉数据。
    /// 仅以本地缓存形式参与评分,绝不在裁决同步路径上发起网络调用。
    /// </summary>
    public FileReputation? Reputation { get; set; }

    /// <summary>
    /// RPC 发起者进程 Id(可空,0 表示无/未追溯到)。
    ///
    /// 用于服务创建这类"经 RPC 转交给系统服务执行"的场景:创建服务时,真正写入
    /// <c>HKLM\SYSTEM\CurrentControlSet\Services\&lt;名&gt;</c> 的是 services.exe(SCM),
    /// 内核注册表回调只能看到 services.exe(在其线程上下文触发)。真正发起 RCreateService
    /// RPC 的进程(sc.exe / 恶意样本 / PowerShell 等)由用户态做调用方追溯后填入此处,
    /// 让规则与 UI 能看到"真凶"而非 services.exe。
    /// </summary>
    public int OriginatorPid { get; set; }

    /// <summary>RPC 发起者进程映像路径(可空)。语义见 <see cref="OriginatorPid"/>。</summary>
    public string? OriginatorPath { get; set; }

    /// <summary>父进程 Id(可空)。</summary>
    public int ParentPid { get; set; }

    /// <summary>父进程映像路径(可空,采集失败时为空)。</summary>
    public string ParentPath { get; set; } = string.Empty;

    /// <summary>进程命令行(可空,用于检测 LOLBin 滥用等)。</summary>
    public string? CommandLine { get; set; }

    /// <summary>操作目标:目标进程路径 / 文件路径 / 注册表键 / 远端地址。</summary>
    public string Target { get; set; } = string.Empty;

    /// <summary>补充说明,例如目标 Pid、端口、注册表值名等。</summary>
    public string? Detail { get; set; }

    /// <summary>威胁检测得分(0-100,由 ThreatDetector 计算)。0 表示无可疑信号。</summary>
    public int RiskScore { get; set; }

    /// <summary>命中的风险原因(可读),由 ThreatDetector 填充。</summary>
    public System.Collections.Generic.List<string> RiskReasons { get; set; } = new();

    /// <summary>
    /// 结构化证据链(决策时间线)。与 <see cref="RiskReasons"/> 并存:RiskReasons 是扁平的
    /// 可读字符串(向后兼容旧 UI/日志),EvidenceChain 则附带「来源分析器 / 类别 / 分值贡献」,
    /// 供 UI 做可解释性时间线展示、供 AI 研判做结构化输入。由各分析器与规则引擎填充。
    /// </summary>
    public System.Collections.Generic.List<Evidence> EvidenceChain { get; set; } = new();

    /// <summary>
    /// 本事件命中的 MITRE ATT&CK 技战术(去重,"T1218.010 Regsvr32 代理执行" 形式),
    /// 由 AttackAnnotator 在裁决末尾从证据链汇总。供 UI 标签展示与 AI 研判结构化输入。
    /// </summary>
    public System.Collections.Generic.List<string> Techniques { get; set; } = new();

    /// <summary>
    /// 记录一条结构化证据,并(默认)同步追加到 <see cref="RiskReasons"/> 保持向后兼容。
    /// </summary>
    /// <param name="source">产生证据的分析器/决策点名称。</param>
    /// <param name="kind">证据类别。</param>
    /// <param name="description">人类可读说明。</param>
    /// <param name="scoreDelta">对风险分的贡献(可正可负,0 表示纯说明)。</param>
    /// <param name="alsoReason">是否同时追加到 <see cref="RiskReasons"/>(默认 true)。</param>
    public void AddEvidence(string source, EvidenceKind kind, string description,
        int scoreDelta = 0, bool alsoReason = true)
    {
        EvidenceChain.Add(new Evidence
        {
            Source = source,
            Kind = kind,
            Description = description,
            ScoreDelta = scoreDelta
        });
        if (alsoReason) RiskReasons.Add(description);
    }

    /// <summary>
    /// 是否出现"硬"恶意指标:危险命令行 / 异常进程链 / 进程伪装 / 双扩展名 /
    /// 签名异常(篡改·吊销·过期后签名)/ 文件膨胀等。
    /// 用于区分"真正可疑行为"与"仅低风险软信号(本机首见 / 新证书等)",
    /// 使真正安全的签名进程可默认放行而不打扰用户。
    /// </summary>
    public bool HasThreatIndicator { get; set; }

    /// <summary>命中的规则说明(若由某条规则裁决),用于弹窗展示"规则路径"。可空。</summary>
    public string? MatchedRuleNote { get; set; }

    /// <summary>
    /// 本事件由用户态观测源(WMI 等)产生,内核无法在动作发生前原地拦截。
    /// 此类事件被裁决为 Block 时,由用户态补偿处置(结束发起进程)。
    /// 内核驱动事件源不设置此标记(其 Block 通过回写内核原地执行)。
    /// </summary>
    public bool UserModeObserved { get; set; }

    /// <summary>主体文件的版本信息说明(FileDescription),由 UI 侧读取填充。可空。</summary>
    public string? FileDescription { get; set; }

    /// <summary>
    /// 进程链上下文:本事件所属进程树近期发生的关联事件(按时间升序,含本事件)。
    /// 由 <see cref="Engine.ProcessChainTracker"/> 在服务端填充,供 UI/大模型做
    /// 「整条攻击链」研判。为空表示无关联上下文或未启用关联分析。
    /// </summary>
    public System.Collections.Generic.List<ChainEventInfo> ChainContext { get; set; } = new();

    public override string ToString() =>
        $"[{Type}] {System.IO.Path.GetFileName(ActorPath)}(pid={ActorPid}) -> {Target}";
}
