using System.Linq;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// 证据链(可解释性决策时间线)填充验证:每个分析器与决策点都应留下结构化证据,
/// 且最终裁决项收尾。证据链与既有 <see cref="SecurityEvent.RiskReasons"/> 保持一致(向后兼容)。
/// </summary>
public class EvidenceChainTests
{
    [Fact]
    public void ThreatDetector_RecordsAttributedEvidenceWithScoreDelta()
    {
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Users\me\AppData\Local\Temp\x.exe",
            ActorSigned = false,
            CommandLine = "powershell -enc ZQBjAGgA"
        };
        ThreatDetector.Analyze(e);

        // 至少应有「无签名」与「编码命令」两条来自 ThreatDetector 的证据
        Assert.All(e.EvidenceChain, ev => Assert.False(string.IsNullOrWhiteSpace(ev.Source)));
        Assert.Contains(e.EvidenceChain, ev => ev.Source == "ThreatDetector");

        // 编码命令应被标记为硬指标且带正分值
        var encoded = e.EvidenceChain.FirstOrDefault(ev => ev.Description.Contains("编码命令"));
        Assert.NotNull(encoded);
        Assert.Equal(EvidenceKind.HardIndicator, encoded!.Kind);
        Assert.True(encoded.ScoreDelta > 0);

        // 证据链里的硬指标加分总和应等于最终 RiskScore(无负向减分场景下)
        var positiveSum = e.EvidenceChain.Where(ev => ev.Source == "ThreatDetector").Sum(ev => ev.ScoreDelta);
        Assert.Equal(e.RiskScore, System.Math.Min(100, positiveSum));

        // 与扁平 RiskReasons 一致(每条带原因的证据都进了 RiskReasons)
        foreach (var ev in e.EvidenceChain.Where(ev => ev.Kind != EvidenceKind.Decision))
            Assert.Contains(ev.Description, e.RiskReasons);
    }

    [Fact]
    public void RuleEngine_AppendsFinalDecisionEvidence()
    {
        var engine = new RuleEngine();
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Users\me\AppData\Local\Temp\evil.exe",
            ActorSigned = false,
            CommandLine = "powershell -nop -w hidden -enc AAAA -executionpolicy bypass"
        };

        var verdict = engine.Evaluate(e);

        // 证据链最后一条必为「最终裁决」收尾
        var last = e.EvidenceChain.Last();
        Assert.Equal(EvidenceKind.Decision, last.Kind);
        Assert.Equal("RuleEngine", last.Source);
        Assert.Contains("最终裁决", last.Description);

        // 高危危险命令行应被拦截,且证据链含 ThreatDetector 硬指标
        Assert.Equal(VerdictAction.Block, verdict.Action);
        Assert.Contains(e.EvidenceChain, ev => ev.Kind == EvidenceKind.HardIndicator);
    }

    [Fact]
    public void TrustedSystemBinary_RecordsTrustEvidence()
    {
        var engine = new RuleEngine { TrustSignedActors = true };
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\notepad.exe",
            ActorSigned = true,
            ActorPublisher = "Microsoft Corporation"
        };

        var verdict = engine.Evaluate(e);

        Assert.Equal(VerdictAction.Allow, verdict.Action);
        // 收尾的 Decision 之外,应有一条信任类证据
        Assert.Contains(e.EvidenceChain, ev => ev.Kind == EvidenceKind.Trust);
        Assert.Equal(EvidenceKind.Decision, e.EvidenceChain.Last().Kind);
    }
}
