using System;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="EgressRateMonitor"/>:有状态外联速率/扇出检测。验证速率突发、目标扇出
/// 被识别,以及对零散/少量外联的低误报。
/// </summary>
public class EgressRateMonitorTests
{
    private static SecurityEvent Conn(int pid, string target, DateTime at, bool signed = false)
        => new()
        {
            Type = EventType.NetworkConnect,
            ActorPid = pid,
            ActorPath = @"C:\x.exe",
            ActorSigned = signed,
            Target = target,
            TimestampUtc = at
        };

    [Fact]
    public void NonNetworkEvent_ReturnsZero()
    {
        var mon = new EgressRateMonitor();
        var e = new SecurityEvent { Type = EventType.FileWrite, ActorPid = 1, Target = "x" };
        var (score, _) = mon.Observe(e);
        Assert.Equal(0, score);
    }

    [Fact]
    public void FewConnections_ScoreZero()
    {
        var mon = new EgressRateMonitor();
        var t0 = DateTime.UtcNow;
        (int Score, System.Collections.Generic.List<string> Reasons) last = default;
        for (int i = 0; i < 5; i++)
            last = mon.Observe(Conn(100, "1.2.3.4:443", t0.AddSeconds(i)));
        Assert.Equal(0, last.Score);
    }

    [Fact]
    public void HighFanout_ManyDistinctTargets_Detected()
    {
        var mon = new EgressRateMonitor();
        var t0 = DateTime.UtcNow;
        (int Score, System.Collections.Generic.List<string> Reasons) last = default;
        // 25 个不同目标,极短时间内 —— 扇出异常(横移/扫描)
        for (int i = 0; i < 25; i++)
            last = mon.Observe(Conn(200, $"10.0.0.{i}:445", t0.AddMilliseconds(i * 20)));

        Assert.True(last.Score > 0, "高扇出应被识别");
        Assert.Contains(last.Reasons!, r => r.Contains("不同目标"));
    }

    [Fact]
    public void HighRate_SameTarget_Detected()
    {
        var mon = new EgressRateMonitor();
        var t0 = DateTime.UtcNow;
        (int Score, System.Collections.Generic.List<string> Reasons) last = default;
        // 50 次外联同一目标 —— 速率突发(C2 轮询/外传分块)
        for (int i = 0; i < 50; i++)
            last = mon.Observe(Conn(300, "203.0.113.9:443", t0.AddMilliseconds(i * 10)));

        Assert.True(last.Score > 0, "速率突发应被识别");
        Assert.Contains(last.Reasons!, r => r.Contains("高速外联"));
    }

    [Fact]
    public void OldEvents_OutsideWindow_DoNotCount()
    {
        var mon = new EgressRateMonitor(window: TimeSpan.FromSeconds(10));
        var t0 = DateTime.UtcNow;
        // 旧的一批在窗口外
        for (int i = 0; i < 30; i++)
            mon.Observe(Conn(400, $"10.1.0.{i}:443", t0.AddSeconds(i)));
        // 远晚于窗口的一次零散外联
        var (score, _) = mon.Observe(Conn(400, "10.1.0.99:443", t0.AddSeconds(120)));
        Assert.Equal(0, score);
    }
}
