using System;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="BeaconDetector"/>:用外联时间间隔的规律性识别 C2 信标回连。
/// 规律间隔 => 高分;不规律(突发)网络行为 => 0 分。
/// </summary>
public class BeaconDetectorTests
{
    private static SecurityEvent Conn(int pid, string remote, DateTime at, bool signed = false, string actor = @"C:\Temp\rat.exe")
        => new()
        {
            Type = EventType.NetworkConnect,
            ActorPid = pid,
            ActorPath = actor,
            ActorSigned = signed,
            Target = remote,
            TimestampUtc = at
        };

    [Fact]
    public void RegularInterval_IsFlaggedAsBeacon()
    {
        var det = new BeaconDetector(minSamples: 4);
        var t0 = DateTime.UtcNow;
        (int Score, System.Collections.Generic.List<string> Reasons) last = default;
        // 每 60 秒精确回连
        for (int i = 0; i < 6; i++)
            last = det.Observe(Conn(100, "evil.example:443", t0.AddSeconds(i * 60)));

        Assert.True(last.Score >= 55, $"规律信标应高分,实际 {last.Score}");
        Assert.NotEmpty(last.Reasons!);
    }

    [Fact]
    public void IrregularTraffic_NotFlagged()
    {
        var det = new BeaconDetector(minSamples: 4);
        var t0 = DateTime.UtcNow;
        // 间隔杂乱:正常突发网络行为
        var offsets = new[] { 0, 2, 47, 51, 300, 305, 1200 };
        int lastScore = 0;
        foreach (var off in offsets)
            lastScore = det.Observe(Conn(200, "cdn.example:443", t0.AddSeconds(off), signed: true)).Score;

        Assert.Equal(0, lastScore);
    }

    [Fact]
    public void InsufficientSamples_ReturnsZero()
    {
        var det = new BeaconDetector(minSamples: 4);
        var t0 = DateTime.UtcNow;
        var r1 = det.Observe(Conn(300, "a.example:80", t0));
        var r2 = det.Observe(Conn(300, "a.example:80", t0.AddSeconds(60)));
        Assert.Equal(0, r1.Score);
        Assert.Equal(0, r2.Score);
    }

    [Fact]
    public void ScriptHostBeacon_GetsExtraScore()
    {
        var det = new BeaconDetector(minSamples: 4);
        var t0 = DateTime.UtcNow;
        int lastScore = 0;
        for (int i = 0; i < 6; i++)
            lastScore = det.Observe(Conn(400, "c2.example:8080",
                t0.AddSeconds(i * 30), actor: @"C:\Windows\System32\powershell.exe")).Score;

        Assert.True(lastScore >= 75, $"脚本解释器规律外联应更高分,实际 {lastScore}");
    }

    [Fact]
    public void SlowBeacon_LongerThanLegacyRetention_IsStillDetected()
    {
        // 回归:旧实现 retention 固定 30min,间隔 > 30min 的慢信标序列会在两次回连之间被淘汰,
        // 永远攒不够样本而漏报。修复后 retention 下限随 MaxPeriodSec 抬高,慢信标应能检出。
        var det = new BeaconDetector(minSamples: 4);
        var t0 = DateTime.UtcNow;
        (int Score, System.Collections.Generic.List<string> Reasons) last = default;
        // 每 40 分钟(2400s)精确回连,超过旧的 30min 保留期。
        for (int i = 0; i < 6; i++)
            last = det.Observe(Conn(500, "slow-c2.example:443", t0.AddSeconds(i * 2400)));

        Assert.True(last.Score >= 55, $"慢信标(40min 间隔)应被检出,实际 {last.Score}");
    }

    [Fact]
    public void MeanAndCv_ComputesCorrectly()
    {
        var (mean, cv) = BeaconDetector.MeanAndCv(new double[] { 60, 60, 60, 60 });
        Assert.Equal(60, mean, 3);
        Assert.True(cv < 0.001, "恒定间隔 CV 应接近 0");
    }
}
