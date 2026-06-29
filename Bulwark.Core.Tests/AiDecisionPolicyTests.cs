using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="AiDecisionPolicy"/>:AI 灰区研判折叠规则。
/// 仅灰区(Ask)咨询;AI 恶意->升格拦截;AI 干净+无硬指标->降级放行;
/// AI 干净+有硬指标->维持询问;AI 不可用->fail-open 维持原裁决。
/// </summary>
public class AiDecisionPolicyTests
{
    private static SecurityEvent Ev(bool hardIndicator) => new()
    {
        Type = EventType.ProcessCreate,
        ActorPath = @"C:\Temp\x.exe",
        HasThreatIndicator = hardIndicator
    };

    [Fact]
    public void OnlyConsultsInGrayZone()
    {
        Assert.True(AiDecisionPolicy.ShouldConsultGrayZone(VerdictAction.Ask));
        Assert.False(AiDecisionPolicy.ShouldConsultGrayZone(VerdictAction.Block));
        Assert.False(AiDecisionPolicy.ShouldConsultGrayZone(VerdictAction.Allow));
    }

    [Fact]
    public void AiUnavailable_KeepsOriginal_FailOpen()
    {
        var o = AiDecisionPolicy.Apply(Ev(true), VerdictAction.Ask,
            aiAvailable: false, aiRecommendation: VerdictAction.Allow);
        Assert.Equal(VerdictAction.Ask, o.Action);
        Assert.False(o.Changed);
        Assert.False(o.RememberMalicious);
    }

    [Fact]
    public void AiMalicious_EscalatesToBlock()
    {
        var o = AiDecisionPolicy.Apply(Ev(true), VerdictAction.Ask,
            aiAvailable: true, aiRecommendation: VerdictAction.Block, aiSummary: "下载执行远控");
        Assert.Equal(VerdictAction.Block, o.Action);
        Assert.True(o.Changed);
        Assert.True(o.RememberMalicious);
        Assert.Contains("恶意", o.Note);
    }

    [Fact]
    public void AiClean_NoHardIndicator_DowngradesToAllow()
    {
        var o = AiDecisionPolicy.Apply(Ev(hardIndicator: false), VerdictAction.Ask,
            aiAvailable: true, aiRecommendation: VerdictAction.Allow);
        Assert.Equal(VerdictAction.Allow, o.Action);
        Assert.True(o.Changed);
        Assert.False(o.RememberMalicious);
    }

    [Fact]
    public void AiClean_WithHardIndicator_KeepsAsk()
    {
        // AI 单独不得压制硬恶意指标,仍交用户裁决。
        var o = AiDecisionPolicy.Apply(Ev(hardIndicator: true), VerdictAction.Ask,
            aiAvailable: true, aiRecommendation: VerdictAction.Allow);
        Assert.Equal(VerdictAction.Ask, o.Action);
        Assert.False(o.Changed);
    }
}
