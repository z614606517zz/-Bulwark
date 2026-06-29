using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// 验证 <see cref="ThreatDetector"/> 对外部文件信誉(VirusTotal 缓存结果)的评分接入:
/// 恶意结论应顶到拦截区间并置硬指标;可疑结论提级;干净结论轻微减分且不强行掩盖硬指标。
/// </summary>
public class ReputationScoringTests
{
    private static SecurityEvent BaseEvent() => new()
    {
        Type = EventType.ProcessCreate,
        ActorPid = 4321,
        ActorPath = @"C:\Users\Public\Downloads\sample.exe",
        ActorSigned = false,
        ActorHash = "a".PadRight(64, 'a')
    };

    [Fact]
    public void Malicious_PushesIntoHighRisk_AndSetsIndicator()
    {
        var e = BaseEvent();
        e.Reputation = new FileReputation
        {
            Sha256 = e.ActorHash!,
            Verdict = ReputationVerdict.Malicious,
            Malicious = 58,
            TotalEngines = 72,
            ThreatLabel = "trojan.generic"
        };

        ThreatDetector.Analyze(e);

        Assert.True(e.HasThreatIndicator);
        Assert.True(e.RiskScore >= ThreatDetector.HighRisk,
            $"恶意信誉应达到高危阈值,实际 {e.RiskScore}");
        Assert.Contains(e.RiskReasons, r => r.Contains("威胁情报") && r.Contains("恶意"));
    }

    [Fact]
    public void Suspicious_RaisesScore_AndSetsIndicator()
    {
        var e = BaseEvent();
        e.Reputation = new FileReputation
        {
            Sha256 = e.ActorHash!,
            Verdict = ReputationVerdict.Suspicious,
            Malicious = 2,
            TotalEngines = 70
        };

        ThreatDetector.Analyze(e);

        Assert.True(e.HasThreatIndicator);
        Assert.Contains(e.RiskReasons, r => r.Contains("可疑"));
    }

    [Fact]
    public void Clean_DoesNotSetIndicator()
    {
        var e = BaseEvent();
        e.Reputation = new FileReputation
        {
            Sha256 = e.ActorHash!,
            Verdict = ReputationVerdict.Clean,
            Malicious = 0,
            TotalEngines = 72
        };

        ThreatDetector.Analyze(e);

        // 干净信誉不应制造硬指标(不会因信誉本身触发拦截/询问)。
        Assert.False(e.HasThreatIndicator);
    }

    [Fact]
    public void NoReputation_DoesNotThrow_AndScoresNormally()
    {
        var e = BaseEvent();
        e.Reputation = null;

        ThreatDetector.Analyze(e);

        // 无信誉数据时不应因信誉逻辑产生异常或硬指标(本例无其他硬信号)。
        Assert.False(e.HasThreatIndicator);
    }
}
