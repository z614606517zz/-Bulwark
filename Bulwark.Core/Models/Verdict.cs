using System;

namespace Bulwark.Core.Models;

/// <summary>对一次安全事件的最终处置动作。</summary>
public enum VerdictAction
{
    Allow,   // 放行
    Block,   // 阻止
    Ask      // 需要询问用户(仅规则引擎内部使用,不应作为最终结果返回内核)
}

/// <summary>裁决来源,用于日志与排查。</summary>
public enum VerdictSource
{
    Rule,            // 命中已有规则
    Heuristic,       // 启发式威胁检测(风险评分)
    TrustedSigner,   // 受信任签名自动放行
    UserPrompt,      // 用户弹窗决定
    Timeout,         // 用户未响应,按默认策略处置
    DefaultPolicy    // 无规则且未询问时的兜底策略
}

/// <summary>裁决结果。</summary>
public sealed class Verdict
{
    public Guid EventId { get; set; }
    public VerdictAction Action { get; set; }
    public VerdictSource Source { get; set; }

    /// <summary>用户/规则是否要求记住该决定(生成持久化规则)。</summary>
    public bool Remember { get; set; }

    public static Verdict For(SecurityEvent e, VerdictAction action, VerdictSource source, bool remember = false)
        => new() { EventId = e.Id, Action = action, Source = source, Remember = remember };
}
