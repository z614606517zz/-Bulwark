using System;
using System.Collections.Generic;
using Bulwark.Core.Models;

namespace Bulwark.UI.Scifi.ViewModels;

/// <summary>
/// 规则列表的「展示包装」:把 <see cref="DefenseRule"/> 里偏技术的字段(英文枚举、
/// 多种可选匹配条件、可能为空的主体)翻译成人看得懂的中文展示,供规则页直接绑定。
/// 纯展示,不改变规则语义。
/// </summary>
public sealed class RuleRowViewModel
{
    public DefenseRule Rule { get; }

    public RuleRowViewModel(DefenseRule rule) => Rule = rule;

    public Guid Id => Rule.Id;

    /// <summary>主体(谁触发):路径 → 通配 → 哈希 → 任意,保证永不为空。</summary>
    public string ActorDisplay
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(Rule.ActorPath)) return Rule.ActorPath!;
            if (!string.IsNullOrWhiteSpace(Rule.ActorPattern)) return Rule.ActorPattern!;
            if (Rule.ActorHashes is { Count: > 0 }) return $"按文件哈希匹配({Rule.ActorHashes.Count} 个)";
            return "任意程序";
        }
    }

    /// <summary>规则说明:优先用 Note(规则用途/对应攻击手法),没有则用「处置 + 行为」兜底。</summary>
    public string Description
    {
        get
        {
            var note = Rule.Note?.Trim();
            if (!string.IsNullOrEmpty(note)) return note!;
            return $"{ActionDisplay}此{TypeDisplay}";
        }
    }

    /// <summary>行为类型中文化;null = 所有行为。</summary>
    public string TypeDisplay => Rule.Type switch
    {
        null => "所有行为",
        EventType.ProcessCreate => "进程创建",
        EventType.ProcessTerminate => "结束进程",
        EventType.RemoteThread => "远程线程注入",
        EventType.ImageLoad => "模块/驱动加载",
        EventType.FileWrite => "文件写入/修改",
        EventType.FileDelete => "文件删除",
        EventType.RegistryWrite => "注册表写入",
        EventType.NetworkConnect => "网络外联",
        EventType.SelfProtect => "自我保护",
        _ => Rule.Type.ToString() ?? "—"
    };

    /// <summary>处置动作中文化。</summary>
    public string ActionDisplay => Rule.Action switch
    {
        VerdictAction.Allow => "放行",
        VerdictAction.Block => "拦截",
        VerdictAction.Ask => "询问",
        _ => Rule.Action.ToString()
    };

    public bool ActionIsBlock => Rule.Action == VerdictAction.Block;
    public bool ActionIsAllow => Rule.Action == VerdictAction.Allow;
    /// <summary>非拦截(放行/询问),供 XAML 选择展示颜色用。</summary>
    public bool ActionIsNotBlock => Rule.Action != VerdictAction.Block;

    /// <summary>命中条件摘要(目标 / 命令行 / 父进程 / 仅未签名 等),没有附加条件则为空。</summary>
    public string ConditionSummary
    {
        get
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(Rule.TargetPattern)) parts.Add($"目标 {Rule.TargetPattern}");
            if (!string.IsNullOrWhiteSpace(Rule.CommandLinePattern)) parts.Add($"命令行 {Rule.CommandLinePattern}");
            if (!string.IsNullOrWhiteSpace(Rule.ParentPattern)) parts.Add($"父进程 {Rule.ParentPattern}");
            if (Rule.RequireUnsigned) parts.Add("仅未签名");
            return string.Join("   ·   ", parts);
        }
    }

    public bool HasCondition => !string.IsNullOrEmpty(ConditionSummary);

    /// <summary>状态标签(临时 / 仅本次会话 / 已停用),用于在行内提示。空表示常规永久启用。</summary>
    public string StatusTag
    {
        get
        {
            var tags = new List<string>();
            if (!Rule.Enabled) tags.Add("已停用");
            if (Rule.SessionOnly) tags.Add("仅本次会话");
            if (Rule.ExpiresUtc is { } exp)
                tags.Add("到期 " + exp.ToLocalTime().ToString("MM-dd HH:mm"));
            return string.Join("   ·   ", tags);
        }
    }

    public bool HasStatusTag => !string.IsNullOrEmpty(StatusTag);
}
