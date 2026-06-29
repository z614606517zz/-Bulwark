using System;

namespace Bulwark.Core.Models;

/// <summary>
/// 进程链关联分析用的「精简事件快照」。仅保留研判所需的关键字段,
/// 体积小、可安全经 IPC 传给 UI 并打包发送给大模型,用于把同一进程树下
/// 的多个孤立事件还原成一条完整的「攻击叙事」。
/// </summary>
public sealed class ChainEventInfo
{
    /// <summary>事件时间(UTC)。</summary>
    public DateTime TimestampUtc { get; set; }

    /// <summary>行为类型。</summary>
    public EventType Type { get; set; }

    /// <summary>发起进程 Id。</summary>
    public int ActorPid { get; set; }

    /// <summary>父进程 Id。</summary>
    public int ParentPid { get; set; }

    /// <summary>发起进程映像路径。</summary>
    public string ActorPath { get; set; } = string.Empty;

    /// <summary>命令行(可空,会在打包时做长度截断,避免提示词膨胀)。</summary>
    public string? CommandLine { get; set; }

    /// <summary>操作目标(进程/文件/注册表键/远端地址)。</summary>
    public string Target { get; set; } = string.Empty;

    /// <summary>该事件单独的启发式评分。</summary>
    public int RiskScore { get; set; }

    /// <summary>从一个完整安全事件提取精简快照。</summary>
    public static ChainEventInfo From(SecurityEvent e) => new()
    {
        TimestampUtc = e.TimestampUtc == default ? DateTime.UtcNow : e.TimestampUtc,
        Type = e.Type,
        ActorPid = e.ActorPid,
        ParentPid = e.ParentPid,
        ActorPath = e.ActorPath,
        CommandLine = Truncate(e.CommandLine, 256),
        Target = e.Target,
        RiskScore = e.RiskScore
    };

    private static string? Truncate(string? s, int max)
    {
        if (string.IsNullOrEmpty(s) || s.Length <= max) return s;
        return s.Substring(0, max) + "…";
    }
}
