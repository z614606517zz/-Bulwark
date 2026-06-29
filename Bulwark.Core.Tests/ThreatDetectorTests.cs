using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="ThreatDetector.Analyze"/> 启发式评分:对真实恶意行为高分,
/// 对合法软件尽量 0 分(降误报)。
/// </summary>
public class ThreatDetectorTests
{
    [Fact]
    public void SignedSystemBinary_ScoresZero()
    {
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\notepad.exe",
            ActorSigned = true,
            ActorPublisher = "Microsoft Corporation"
        };
        ThreatDetector.Analyze(e);
        Assert.Equal(0, e.RiskScore);
    }

    [Fact]
    public void OfficeSpawningPowerShell_IsHighRisk()
    {
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ParentPath = @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            ActorSigned = true,
            CommandLine = "powershell -nop -w hidden -enc ZQBjAGgA"
        };
        ThreatDetector.Analyze(e);
        // 异常链(45) + 隐藏窗口(30) + 编码命令(35) 已远超高危阈值
        Assert.True(e.RiskScore >= ThreatDetector.HighRisk,
            $"期望高危,实际 {e.RiskScore}");
    }

    [Fact]
    public void EncodedPowerShell_AccumulatesRisk()
    {
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ActorSigned = true,
            CommandLine = "powershell -nop -enc ZQBjAGgAbwAg"
        };
        ThreatDetector.Analyze(e);
        Assert.True(e.RiskScore > 0);
        Assert.Contains(e.RiskReasons, r => r.Contains("编码命令"));
    }

    [Fact]
    public void UnsignedFromTemp_IsSuspicious()
    {
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Users\me\AppData\Local\Temp\dropper.exe",
            ActorSigned = false
        };
        ThreatDetector.Analyze(e);
        // 无签名(15) + 未签名从可疑目录(25) = 40
        Assert.True(e.RiskScore >= 40, $"实际 {e.RiskScore}");
        Assert.Contains(e.RiskReasons, r => r.Contains("可疑目录"));
    }

    [Fact]
    public void DoubleExtension_IsFlagged()
    {
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Users\me\Downloads\invoice.pdf.exe",
            ActorSigned = false
        };
        ThreatDetector.Analyze(e);
        Assert.Contains(e.RiskReasons, r => r.Contains("双重扩展名"));
    }

    [Fact]
    public void ProcessMasquerade_SvchostOutsideSystem32_IsFlagged()
    {
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Users\me\AppData\Roaming\svchost.exe",
            ActorSigned = false
        };
        ThreatDetector.Analyze(e);
        Assert.Contains(e.RiskReasons, r => r.Contains("进程伪装"));
    }

    [Fact]
    public void BareFileName_NotTreatedAsMasquerade()
    {
        // 裸文件名(无目录)路径未知,不应误判为伪装
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = "svchost.exe",
            ActorSigned = false
        };
        ThreatDetector.Analyze(e);
        Assert.DoesNotContain(e.RiskReasons, r => r.Contains("进程伪装"));
    }

    [Fact]
    public void Score_IsCappedAt100()
    {
        var e = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = @"C:\Users\Public\svchost.exe", // 伪装 + 可疑目录
            ParentPath = @"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
            ActorSigned = false,
            CommandLine = "powershell -enc x -w hidden downloadstring iex( frombase64string -executionpolicy bypass"
        };
        ThreatDetector.Analyze(e);
        Assert.True(e.RiskScore <= 100);
    }
}
