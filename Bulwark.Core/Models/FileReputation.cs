using System;

namespace Bulwark.Core.Models;

/// <summary>
/// 文件信誉结论(来自外部信誉源,如 VirusTotal 哈希查询)。
/// </summary>
public enum ReputationVerdict
{
    /// <summary>未查询 / 无结论(VT 未收录、查询失败、超配额等)。不影响本地决策。</summary>
    Unknown = 0,

    /// <summary>干净:多引擎一致未检出且信誉良好。可作为白名单减分信号。</summary>
    Clean,

    /// <summary>可疑:少量引擎检出(1~4 个)。</summary>
    Suspicious,

    /// <summary>恶意:较多引擎检出(>=5 个),高可信。</summary>
    Malicious
}

/// <summary>
/// 一次文件信誉查询的结果(按 SHA-256)。由信誉源填充并可持久化缓存。
/// 这是"信誉加分项",绝不进同步裁决路径的网络调用,仅以缓存形式参与本地评分。
/// </summary>
public sealed class FileReputation
{
    /// <summary>查询的文件 SHA-256(小写十六进制)。</summary>
    public string Sha256 { get; set; } = string.Empty;

    /// <summary>信誉结论。</summary>
    public ReputationVerdict Verdict { get; set; } = ReputationVerdict.Unknown;

    /// <summary>判为恶意/可疑的引擎数量(VT last_analysis_stats.malicious)。</summary>
    public int Malicious { get; set; }

    /// <summary>参与分析的引擎总数(用于展示,如 "58/72")。</summary>
    public int TotalEngines { get; set; }

    /// <summary>建议的威胁名称(VT suggested_threat_label),可空。</summary>
    public string? ThreatLabel { get; set; }

    /// <summary>本结果的获取时间(UTC),用于缓存 TTL 判断。</summary>
    public DateTime FetchedUtc { get; set; } = DateTime.UtcNow;

    /// <summary>VT 上该文件最近一次分析时间(UTC),可空,用于判断结果新鲜度。</summary>
    public DateTime? LastAnalysisUtc { get; set; }

    /// <summary>
    /// 本次查询是否"成功完成"(结论是否权威可信)。
    /// true 表示信誉源给出了确定答复——包括"收录并检测(干净/可疑/恶意)"以及
    /// "确实未收录(VT 返回 404)";这两种都是权威结果,可缓存。
    /// false 表示查询本身失败(TLS/网络/超时/鉴权/限流/解析异常),结果不可信,
    /// 不应缓存,下次应重新查询。默认 false(未查/失败保守值)。
    /// </summary>
    public bool QuerySucceeded { get; set; }

    /// <summary>是否为恶意结论。</summary>
    public bool IsMalicious => Verdict == ReputationVerdict.Malicious;
}
