using System;
using System.Linq;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// 规则有效期与会话作用域:到期规则不再命中、不被引擎列出、可被清理;
/// 未到期规则正常命中。降低「记住」产生永久误放行的风险。
/// </summary>
public class RuleExpiryTests
{
    private static SecurityEvent SampleEvent() => new()
    {
        Type = EventType.ProcessCreate,
        ActorPath = @"C:\app\tool.exe"
    };

    [Fact]
    public void ExpiredRule_DoesNotMatch()
    {
        var rule = new DefenseRule
        {
            ActorPath = @"C:\app\tool.exe",
            Action = VerdictAction.Allow,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(-1)
        };
        Assert.False(rule.Matches(SampleEvent()));
        Assert.True(rule.IsExpired(DateTime.UtcNow));
    }

    [Fact]
    public void FutureExpiryRule_StillMatches()
    {
        var rule = new DefenseRule
        {
            ActorPath = @"C:\app\tool.exe",
            Action = VerdictAction.Allow,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(30)
        };
        Assert.True(rule.Matches(SampleEvent()));
        Assert.False(rule.IsExpired(DateTime.UtcNow));
    }

    [Fact]
    public void Engine_DoesNotListOrApplyExpiredRule_ButPrunesIt()
    {
        var engine = new RuleEngine();
        engine.AddRule(new DefenseRule
        {
            ActorPath = @"C:\app\tool.exe",
            Action = VerdictAction.Block,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(-5)
        });

        // 到期规则不出现在列表
        Assert.Empty(engine.GetRules());

        // 到期的 Block 规则不应生效(事件无硬指标 -> 默认放行)
        var e = SampleEvent();
        var verdict = engine.Evaluate(e);
        Assert.Equal(VerdictAction.Allow, verdict.Action);

        // 可被清理
        Assert.Equal(1, engine.PruneExpired());
        Assert.Equal(0, engine.PruneExpired());
    }

    [Fact]
    public void SessionOnlyRule_MatchesButIsMarkedNonPersistent()
    {
        var rule = new DefenseRule
        {
            ActorPath = @"C:\app\tool.exe",
            Action = VerdictAction.Allow,
            SessionOnly = true
        };
        Assert.True(rule.Matches(SampleEvent())); // 会话内有效
        Assert.True(rule.SessionOnly);            // 标记为不持久化(由 RuleStore 在保存时排除)
    }
}
