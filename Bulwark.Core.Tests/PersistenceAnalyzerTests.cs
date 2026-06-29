using System.Linq;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// 持久化项分析器:复用 ThreatDetector 启发式 + 叠加自启动点 ATT&CK 标注。
/// 验证恶意自启动高分、合法签名自启动低分、各类别技战术标注正确。
/// </summary>
public class PersistenceAnalyzerTests
{
    [Fact]
    public void RunKey_WithEncodedPowerShell_IsHighRisk()
    {
        var entry = new PersistenceEntry
        {
            Category = PersistenceCategory.RegistryRun,
            Name = "Updater",
            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            Command = "powershell -nop -w hidden -enc ZQBjAGgA",
            ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            Signed = true
        };
        PersistenceAnalyzer.Analyze(entry);

        Assert.True(entry.RiskScore >= ThreatDetector.Suspicious, $"实际 {entry.RiskScore}");
        // 既有命令行技战术(T1027)也有自启动位置技战术(T1547.001)
        Assert.Contains(entry.Techniques, t => t.StartsWith("T1547.001"));
        Assert.Contains(entry.Techniques, t => t.StartsWith("T1027"));
    }

    [Fact]
    public void SignedServiceFromProgramFiles_IsLowRisk()
    {
        var entry = new PersistenceEntry
        {
            Category = PersistenceCategory.Service,
            Name = "AppSvc",
            Location = @"HKLM\SYSTEM\CurrentControlSet\Services\AppSvc",
            Command = @"C:\Program Files\App\app.exe --service",
            ImagePath = @"C:\Program Files\App\app.exe",
            Signed = true,
            Publisher = "Contoso Ltd"
        };
        PersistenceAnalyzer.Analyze(entry);

        // 合法签名服务从 Program Files 自启 —— 不应被判高危
        Assert.True(entry.RiskScore < ThreatDetector.Suspicious, $"实际 {entry.RiskScore}");
        // 仍应标注服务持久化技战术
        Assert.Contains(entry.Techniques, t => t.StartsWith("T1543.003"));
    }

    [Fact]
    public void IfeoDebugger_GetsHighRiskWeightAndTechnique()
    {
        var entry = new PersistenceEntry
        {
            Category = PersistenceCategory.IfeoDebugger,
            Name = "sethc.exe",
            Location = @"HKLM\...\Image File Execution Options\sethc.exe",
            Command = @"C:\Windows\System32\cmd.exe",
            ImagePath = @"C:\Windows\System32\cmd.exe",
            Signed = true
        };
        PersistenceAnalyzer.Analyze(entry);

        Assert.Contains(entry.Techniques, t => t.StartsWith("T1546.012"));
        Assert.Contains(entry.RiskReasons, r => r.Contains("映像劫持"));
    }

    [Fact]
    public void StartupFolder_UnsignedFromTemp_IsFlagged()
    {
        var entry = new PersistenceEntry
        {
            Category = PersistenceCategory.StartupFolder,
            Name = "x.exe",
            Location = @"C:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            Command = @"C:\Users\me\AppData\Local\Temp\x.exe",
            ImagePath = @"C:\Users\me\AppData\Local\Temp\x.exe",
            Signed = false
        };
        PersistenceAnalyzer.Analyze(entry);

        Assert.True(entry.RiskScore > 0);
        Assert.Contains(entry.Techniques, t => t.StartsWith("T1547.001"));
    }
}
