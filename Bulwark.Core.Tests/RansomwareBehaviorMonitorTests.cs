using System;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="RansomwareBehaviorMonitor"/>:有状态时序检测。验证批量改写、
/// 扩展名同化、蜜罐触碰、勒索信等勒索特征,以及对零散写入的低误报。
/// </summary>
public class RansomwareBehaviorMonitorTests
{
    private static SecurityEvent Write(int pid, string target, DateTime at)
        => new()
        {
            Type = EventType.FileWrite,
            ActorPid = pid,
            ActorPath = @"C:\Temp\enc.exe",
            Target = target,
            TimestampUtc = at
        };

    [Fact]
    public void CanaryFile_Touch_TriggersImmediateBlock()
    {
        var mon = new RansomwareBehaviorMonitor();
        mon.AddCanaryFile(@"C:\Users\me\Documents\~canary_donottouch.docx");

        var (score, reasons, canary, hard) = mon.Observe(
            Write(100, @"C:\Users\me\Documents\~canary_donottouch.docx", DateTime.UtcNow));

        Assert.True(canary);
        Assert.True(hard);
        Assert.Equal(100, score);
        Assert.NotEmpty(reasons);
    }

    [Fact]
    public void BurstRewrite_IsFlagged()
    {
        var mon = new RansomwareBehaviorMonitor(window: TimeSpan.FromSeconds(10), burstThreshold: 12);
        var t0 = DateTime.UtcNow;
        int lastScore = 0;
        for (int i = 0; i < 20; i++)
            lastScore = mon.Observe(Write(200, $@"C:\Users\me\Docs\file{i}.txt", t0.AddMilliseconds(i * 100))).Score;

        Assert.True(lastScore > 0, "批量改写应被打分");
    }

    [Fact]
    public void ExtensionAssimilation_KnownRansomExt_IsFlagged()
    {
        var mon = new RansomwareBehaviorMonitor();
        var t0 = DateTime.UtcNow;
        (int Score, System.Collections.Generic.List<string> Reasons, bool Canary, bool Hard) last = default;
        for (int i = 0; i < 6; i++)
            last = mon.Observe(Write(300, $@"C:\Users\me\Docs\file{i}.locked", t0.AddMilliseconds(i * 50)));

        Assert.True(last.Score > 0);
        Assert.True(last.Hard, "已知勒索扩展名批量产生应为加密确证(硬)信号");
        Assert.Contains(last.Reasons!, r => r.Contains(".locked"));
    }

    [Fact]
    public void SporadicWrites_DoNotTrigger()
    {
        var mon = new RansomwareBehaviorMonitor(window: TimeSpan.FromSeconds(10), burstThreshold: 12);
        var t0 = DateTime.UtcNow;
        // 每次写入间隔很长,且文件少,不构成批量
        var r1 = mon.Observe(Write(400, @"C:\Users\me\a.txt", t0));
        var r2 = mon.Observe(Write(400, @"C:\Users\me\b.txt", t0.AddSeconds(30)));

        Assert.Equal(0, r1.Score);
        Assert.Equal(0, r2.Score);
    }

    [Fact]
    public void WindowEviction_ResetsDistinctCount_NoFalsePositive()
    {
        // 守护增量计数器的窗口淘汰逻辑:在窗口内分散改写少量文件,
        // 旧条目随时间滑出窗口后计数应回退,不应累积成"批量改写"误报。
        var mon = new RansomwareBehaviorMonitor(window: TimeSpan.FromSeconds(10), burstThreshold: 12);
        var t0 = DateTime.UtcNow;
        int lastScore = 0;
        // 每 2 秒改写 1 个不同文件,持续 60 秒:任一 10s 窗口内最多 ~5 个文件,远低于阈值 12。
        for (int i = 0; i < 30; i++)
            lastScore = mon.Observe(Write(700, $@"C:\Users\me\Docs\f{i}.txt", t0.AddSeconds(i * 2))).Score;

        Assert.Equal(0, lastScore);
    }

    [Fact]
    public void IncrementalCounters_StillDetectBurst_AfterWindowChurn()
    {
        // 在长时间零散写入后,再来一波真正的批量改写,增量计数器应正确反映窗口内突增并打分。
        var mon = new RansomwareBehaviorMonitor(window: TimeSpan.FromSeconds(10), burstThreshold: 12);
        var t0 = DateTime.UtcNow;
        // 先零散写入(会触发多次窗口淘汰)
        for (int i = 0; i < 20; i++)
            mon.Observe(Write(800, $@"C:\Users\me\old{i}.txt", t0.AddSeconds(i * 3)));

        // 再在 1 秒内集中改写 20 个新文件
        var burstStart = t0.AddSeconds(80);
        int lastScore = 0;
        for (int i = 0; i < 20; i++)
            lastScore = mon.Observe(Write(800, $@"C:\Users\me\burst{i}.txt", burstStart.AddMilliseconds(i * 50))).Score;

        Assert.True(lastScore > 0, "窗口轮换后仍应正确检出批量改写");
    }

    [Fact]
    public void NonFileEvent_ReturnsZero()
    {
        var mon = new RansomwareBehaviorMonitor();
        var e = new SecurityEvent { Type = EventType.NetworkConnect, ActorPid = 1, Target = "1.2.3.4" };
        var (score, _, _, _) = mon.Observe(e);
        Assert.Equal(0, score);
    }
}
