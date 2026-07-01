namespace Bulwark.Core.Models;

/// <summary>
/// 单个威胁情报源的实时用量快照(供「情报源连接」页展示今日消耗 / 配额)。
/// 由各 <see cref="Bulwark.Core.Engine.IHashReputationService"/> 实现按本地限流器状态填充,
/// 经 IPC 汇总给 UI。纯展示用,不参与任何裁决。
/// </summary>
public sealed class ReputationUsage
{
    /// <summary>源标识(与 UI 条目 / 服务端 SourceName 对应,如 "VirusTotal")。</summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>该源当前是否可用(已配置 Key / 未被关闭)。</summary>
    public bool Enabled { get; set; }

    /// <summary>今日(UTC)已消耗的查询次数。</summary>
    public int UsedToday { get; set; }

    /// <summary>每日配额上限。</summary>
    public int DailyLimit { get; set; }

    /// <summary>每分钟请求上限(静态,来自配置)。</summary>
    public int PerMinuteLimit { get; set; }
}
