using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="DefenseRule.Matches"/> 的条件组合语义:所有已设置条件都需满足;
/// 未设置条件视为「任意」。以及 SpecificityScore / 信任规则构造。
/// </summary>
public class DefenseRuleTests
{
    private static SecurityEvent Evt(
        EventType type = EventType.ProcessCreate,
        string actor = @"C:\Users\Public\x.exe",
        string target = "",
        string? cmd = null,
        string parent = "",
        bool signed = false) => new()
        {
            Type = type,
            ActorPath = actor,
            Target = target,
            CommandLine = cmd,
            ParentPath = parent,
            ActorSigned = signed
        };

    [Fact]
    public void Disabled_Rule_NeverMatches()
    {
        var rule = new DefenseRule { Type = EventType.ProcessCreate, Enabled = false, Action = VerdictAction.Block };
        Assert.False(rule.Matches(Evt()));
    }

    [Fact]
    public void TypeMismatch_DoesNotMatch()
    {
        var rule = new DefenseRule { Type = EventType.RegistryWrite, Action = VerdictAction.Block };
        Assert.False(rule.Matches(Evt(type: EventType.ProcessCreate)));
    }

    [Fact]
    public void NullType_MatchesAnyType()
    {
        var rule = new DefenseRule { Type = null, ActorPath = @"C:\Users\Public\x.exe", Action = VerdictAction.Allow };
        Assert.True(rule.Matches(Evt(type: EventType.NetworkConnect)));
    }

    [Fact]
    public void RequireUnsigned_SkipsSignedActor()
    {
        var rule = new DefenseRule
        {
            Type = EventType.ProcessCreate,
            ActorPattern = @"*\x.exe",
            RequireUnsigned = true,
            Action = VerdictAction.Ask
        };
        Assert.False(rule.Matches(Evt(signed: true)));
        Assert.True(rule.Matches(Evt(signed: false)));
    }

    [Fact]
    public void ActorPath_ExactMatch_CaseInsensitive()
    {
        var rule = new DefenseRule { ActorPath = @"C:\Windows\System32\cmd.exe", Action = VerdictAction.Allow };
        Assert.True(rule.Matches(Evt(actor: @"c:\windows\system32\CMD.EXE")));
        Assert.False(rule.Matches(Evt(actor: @"C:\Windows\System32\cmd2.exe")));
    }

    [Fact]
    public void CommandLinePattern_Matches()
    {
        var rule = new DefenseRule
        {
            Type = EventType.ProcessCreate,
            CommandLinePattern = @"*-enc*",
            Action = VerdictAction.Ask
        };
        Assert.True(rule.Matches(Evt(cmd: "powershell -nop -enc ABC")));
        Assert.False(rule.Matches(Evt(cmd: "powershell -file x.ps1")));
        // 命令行为 null 时不应命中需要命令行的规则
        Assert.False(rule.Matches(Evt(cmd: null)));
    }

    [Fact]
    public void ParentPattern_Matches()
    {
        var rule = new DefenseRule
        {
            ParentPattern = @"*\winword.exe",
            Action = VerdictAction.Block
        };
        Assert.True(rule.Matches(Evt(parent: @"C:\Program Files\Microsoft Office\winword.exe")));
        Assert.False(rule.Matches(Evt(parent: @"C:\Windows\explorer.exe")));
    }

    [Fact]
    public void TargetPattern_MatchesTargetOrActor()
    {
        // TargetPattern 同时尝试匹配 Target 与 ActorPath
        var rule = new DefenseRule { TargetPattern = @"*\evil.dll", Action = VerdictAction.Block };
        Assert.True(rule.Matches(Evt(target: @"C:\x\evil.dll", actor: @"C:\loader.exe")));
        Assert.True(rule.Matches(Evt(target: "", actor: @"C:\x\evil.dll")));
        Assert.False(rule.Matches(Evt(target: @"C:\x\good.dll", actor: @"C:\loader.exe")));
    }

    [Fact]
    public void AllConditions_MustHoldTogether()
    {
        var rule = new DefenseRule
        {
            Type = EventType.ProcessCreate,
            ActorPattern = @"*\x.exe",
            CommandLinePattern = @"*-enc*",
            RequireUnsigned = true,
            Action = VerdictAction.Block
        };
        // 全满足
        Assert.True(rule.Matches(Evt(actor: @"C:\a\x.exe", cmd: "x -enc y", signed: false)));
        // 命令行不满足 -> 不命中
        Assert.False(rule.Matches(Evt(actor: @"C:\a\x.exe", cmd: "x -file y", signed: false)));
        // 已签名 -> 不命中(RequireUnsigned)
        Assert.False(rule.Matches(Evt(actor: @"C:\a\x.exe", cmd: "x -enc y", signed: true)));
    }

    [Fact]
    public void SpecificityScore_MoreConditions_HigherScore()
    {
        var broad = new DefenseRule { Type = EventType.ProcessCreate };
        var specific = new DefenseRule
        {
            ActorPath = @"C:\a\x.exe",
            Type = EventType.ProcessCreate,
            CommandLinePattern = "*-enc*"
        };
        Assert.True(specific.SpecificityScore() > broad.SpecificityScore());
    }

    [Fact]
    public void CreateTrust_ProducesAllowRule_ForAllTypes()
    {
        var trust = DefenseRule.CreateTrust(@"C:\app\my.exe", "我的工具");
        Assert.Equal(VerdictAction.Allow, trust.Action);
        Assert.Null(trust.Type); // 对所有事件类型生效
        Assert.True(trust.IsTrustEntry);
        Assert.Equal(@"C:\app\my.exe", trust.ActorPath);
    }
}
