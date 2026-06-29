using System;
using System.Text.Json.Serialization;

namespace Bulwark.Core.Models;

/// <summary>
/// 一条证据的类别。用于 UI 分组着色与「为什么这么判」的可解释性展示,
/// 也让 AI 研判拿到结构化输入而非一串扁平字符串。
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum EvidenceKind
{
    /// <summary>中性上下文(如「无签名」「本机首见」)。单独不构成处置理由。</summary>
    Info,

    /// <summary>软信号:单独不处置,仅累加风险分,需与硬指标互证后才升格。</summary>
    SoftSignal,

    /// <summary>硬恶意指标:危险命令行 / 异常进程链 / 进程伪装 / 勒索确证 / 信誉恶意等。</summary>
    HardIndicator,

    /// <summary>互证升格:多个软信号或软信号与硬指标共现,被升格为硬指标。</summary>
    Corroboration,

    /// <summary>信任/放行依据:强可信签名、健康签名、本软件自身组件、开发工具白名单等。</summary>
    Trust,

    /// <summary>命中显式规则(用户加白/锁定或内置规则)。</summary>
    Rule,

    /// <summary>最终裁决说明(动作 + 来源)。证据链的收尾项。</summary>
    Decision
}

/// <summary>
/// 证据链中的单条记录。把「哪个分析器、出于什么类别、加了多少分、说了什么」
/// 结构化下来,串成一条可解释的决策时间线,附加在 <see cref="SecurityEvent"/> 上。
/// </summary>
public sealed class Evidence
{
    /// <summary>该证据产生的时间(UTC),用于时间线排序。</summary>
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// 产生该证据的分析器/决策点名称。例如:
    /// ThreatDetector / RansomwareBehaviorMonitor / BeaconDetector /
    /// DgaDomainAnalyzer / EgressRateMonitor / CommandObfuscationAnalyzer /
    /// ScriptAnalyzer / KillChainAnalyzer / TrustPolicy / RuleEngine / Reputation。
    /// </summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>证据类别。</summary>
    public EvidenceKind Kind { get; set; }

    /// <summary>人类可读的证据说明。</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// 该证据对 <see cref="SecurityEvent.RiskScore"/> 的贡献(可正可负,0 表示纯说明性条目)。
    /// </summary>
    public int ScoreDelta { get; set; }

    /// <summary>关联的 MITRE ATT&CK 技战术编号(如 "T1218.010"),可空。由 AttackAnnotator 填充。</summary>
    public string? Technique { get; set; }

    /// <summary>技战术中文名称(如 "Regsvr32 代理执行(Squiblydoo)"),可空。</summary>
    public string? TechniqueName { get; set; }

    public override string ToString()
        => $"[{Source}/{Kind}{(ScoreDelta != 0 ? $" {ScoreDelta:+0;-0}" : "")}]{(Technique is null ? "" : $" {Technique}")} {Description}";
}
