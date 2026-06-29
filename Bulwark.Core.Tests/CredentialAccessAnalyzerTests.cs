using System.Linq;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// 凭据访问 / LSASS 保护分析器:对 LSASS 转储/注入、SAM/NTDS 导出等高置信凭据攻击给出硬信号,
/// 对正常行为不误报;并验证签名系统工具(reg.exe / ntdsutil)做凭据导出时失去信任放行豁免。
/// </summary>
public class CredentialAccessAnalyzerTests
{
    [Fact]
    public void LsassRemoteThread_IsHardSignal()
    {
        var e = new SecurityEvent
        {
            Type = EventType.RemoteThread,
            ActorPath = @"C:\Users\me\AppData\Local\Temp\x.exe",
            Target = @"C:\Windows\System32\lsass.exe"
        };
        var (score, reasons, hard) = CredentialAccessAnalyzer.Analyze(e);
        Assert.True(hard);
        Assert.True(score >= 50);
        Assert.Contains(reasons, r => r.Contains("T1003.001"));
    }

    [Theory]
    [InlineData("reg save hklm\\sam C:\\temp\\sam.hiv", "T1003.002")]
    [InlineData("ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\"", "T1003.003")]
    public void HiveAndNtdsDump_AreHardSignals(string cmd, string technique)
    {
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\reg.exe",
            CommandLine = cmd
        };
        var (_, reasons, hard) = CredentialAccessAnalyzer.Analyze(e);
        Assert.True(hard);
        Assert.Contains(reasons, r => r.Contains(technique));
    }

    [Fact]
    public void BrowserReadingOwnCredentials_NotHard()
    {
        // 浏览器自身访问自己的凭据库 —— 正常,不应硬拦
        var e = new SecurityEvent
        {
            Type = EventType.FileWrite,
            ActorPath = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
            Target = @"C:\Users\me\AppData\Local\Google\Chrome\User Data\Default\Login Data"
        };
        var (_, _, hard) = CredentialAccessAnalyzer.Analyze(e);
        Assert.False(hard);
    }

    [Fact]
    public void NonBrowserReadingCredentialStore_IsSoftSignal()
    {
        var e = new SecurityEvent
        {
            Type = EventType.FileWrite,
            ActorPath = @"C:\Users\me\AppData\Local\Temp\stealer.exe",
            Target = @"C:\Users\me\AppData\Local\Google\Chrome\User Data\Default\Login Data"
        };
        var (score, _, hard) = CredentialAccessAnalyzer.Analyze(e);
        Assert.False(hard);       // 软信号,不单独硬拦
        Assert.True(score > 0);   // 但累加风险分,交互证升格
    }

    [Fact]
    public void SignedRegExe_DumpingSam_LosesTrustAndIsBlocked()
    {
        // 微软签名的 reg.exe 导出 SAM 蜂巢 —— 正常会命中强可信放行,这里应失去豁免并被处置。
        var engine = new RuleEngine { TrustSignedActors = true };
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\reg.exe",
            ActorSigned = true,
            ActorPublisher = "Microsoft Corporation",
            CommandLine = "reg save hklm\\sam C:\\temp\\sam.hiv"
        };

        engine.Evaluate(e);

        Assert.True(e.HasThreatIndicator);
        Assert.Contains(e.Techniques, s => s.StartsWith("T1003.002"));
        Assert.Contains(e.EvidenceChain, ev => ev.Source == "CredentialAccessAnalyzer" && ev.Kind == EvidenceKind.HardIndicator);
    }
}
