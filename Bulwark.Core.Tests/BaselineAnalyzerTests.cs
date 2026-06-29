using System;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="BaselineAnalyzer"/>:为每个程序建立正常行为画像,偏离自身历史时升分。
/// 核心约束:学习期不评分;偏离恒为软信号;高基数程序豁免;已知行为不评分。
/// </summary>
public class BaselineAnalyzerTests
{
    private static SecurityEvent Spawn(string parent, string child, DateTime at)
        => new()
        {
            Type = EventType.ProcessCreate,
            ParentPath = parent,
            ActorPath = child,
            ActorPid = 1000,
            TimestampUtc = at
        };

    private static SecurityEvent Net(string actor, string remote, DateTime at)
        => new()
        {
            Type = EventType.NetworkConnect,
            ActorPath = actor,
            ActorPid = 1000,
            Target = remote,
            TimestampUtc = at
        };

    private static SecurityEvent Write(string actor, string targetFile, DateTime at)
        => new()
        {
            Type = EventType.FileWrite,
            ActorPath = actor,
            ActorPid = 1000,
            Target = targetFile,
            TimestampUtc = at
        };

    [Fact]
    public void DuringLearningPeriod_NoScore()
    {
        var bl = new BaselineAnalyzer(minObservationsToEstablish: 5);
        var t0 = DateTime.UtcNow;

        // 学习期内即使每次都是不同主机,也不评分。
        for (int i = 0; i < 4; i++)
        {
            var (score, _, dev) = bl.Observe(Net(@"C:\app\updater.exe", $"host{i}.example:443", t0.AddSeconds(i)));
            Assert.Equal(0, score);
            Assert.False(dev);
        }
    }

    [Fact]
    public void KnownBehavior_AfterEstablished_NoScore()
    {
        var bl = new BaselineAnalyzer(minObservationsToEstablish: 5);
        var t0 = DateTime.UtcNow;

        // 反复连同一个主机:建立基线后再次出现该主机不应升分。
        int last = -1;
        for (int i = 0; i < 10; i++)
            last = bl.Observe(Net(@"C:\app\updater.exe", "update.vendor.com:443", t0.AddSeconds(i))).Score;

        Assert.Equal(0, last);
    }

    [Fact]
    public void NovelHost_AfterEstablished_IsDeviation()
    {
        var bl = new BaselineAnalyzer(minObservationsToEstablish: 5);
        var t0 = DateTime.UtcNow;

        // 先用固定主机把基线建立起来(>= minObs 次观测)。
        for (int i = 0; i < 8; i++)
            bl.Observe(Net(@"C:\app\updater.exe", "update.vendor.com:443", t0.AddSeconds(i)));

        // 然后突然连向陌生主机 —— 偏离基线,应产出软信号分。
        var (score, reasons, dev) = bl.Observe(Net(@"C:\app\updater.exe", "evil-c2.example:8080", t0.AddSeconds(100)));
        Assert.True(dev, "首次连陌生主机应判为偏离");
        Assert.True(score > 0, $"偏离应升分,实际 {score}");
        Assert.NotEmpty(reasons);
    }

    [Fact]
    public void NovelChildProcess_AfterEstablished_IsDeviation()
    {
        var bl = new BaselineAnalyzer(minObservationsToEstablish: 5);
        var t0 = DateTime.UtcNow;

        // updater 一直只派生 helper.exe,建立基线。
        for (int i = 0; i < 8; i++)
            bl.Observe(Spawn(@"C:\app\updater.exe", @"C:\app\helper.exe", t0.AddSeconds(i)));

        // 突然派生 powershell.exe —— 偏离基线。
        var (score, _, dev) = bl.Observe(Spawn(@"C:\app\updater.exe",
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", t0.AddSeconds(100)));
        Assert.True(dev);
        Assert.True(score > 0);
    }

    [Fact]
    public void PromiscuousProgram_NotScored()
    {
        // 浏览器类:连大量不同主机,基数超过 promiscuous 阈值后不再评分。
        var bl = new BaselineAnalyzer(minObservationsToEstablish: 5, promiscuousThreshold: 20);
        var t0 = DateTime.UtcNow;

        for (int i = 0; i < 40; i++)
            bl.Observe(Net(@"C:\browser\chrome.exe", $"site{i}.example:443", t0.AddSeconds(i)));

        // 第 41 个全新主机:已是高基数程序,不应再升分。
        var (score, _, dev) = bl.Observe(Net(@"C:\browser\chrome.exe", "brand-new.example:443", t0.AddSeconds(200)));
        Assert.Equal(0, score);
        Assert.False(dev);
    }

    [Fact]
    public void NovelWriteDir_AfterEstablished_IsDeviation()
    {
        var bl = new BaselineAnalyzer(minObservationsToEstablish: 5);
        var t0 = DateTime.UtcNow;

        for (int i = 0; i < 8; i++)
            bl.Observe(Write(@"C:\app\app.exe", $@"C:\app\data\file{i}.dat", t0.AddSeconds(i)));

        var (score, _, dev) = bl.Observe(Write(@"C:\app\app.exe",
            @"C:\Users\u\AppData\Roaming\Startup\evil.lnk", t0.AddSeconds(100)));
        Assert.True(dev);
        Assert.True(score > 0);
    }

    [Fact]
    public void ExportImport_RoundTrips_PreservesBaseline()
    {
        var bl = new BaselineAnalyzer(minObservationsToEstablish: 5);
        var t0 = DateTime.UtcNow;
        for (int i = 0; i < 8; i++)
            bl.Observe(Net(@"C:\app\updater.exe", "update.vendor.com:443", t0.AddSeconds(i)));

        var snap = bl.Export();

        // 导入到新实例:已知主机不应被判为偏离(说明基线与观测计数都被保留)。
        var bl2 = new BaselineAnalyzer(minObservationsToEstablish: 5);
        bl2.Import(snap);

        var known = bl2.Observe(Net(@"C:\app\updater.exe", "update.vendor.com:443", t0.AddSeconds(200)));
        Assert.Equal(0, known.Score);

        // 新主机仍应被判为偏离。
        var novel = bl2.Observe(Net(@"C:\app\updater.exe", "stranger.example:443", t0.AddSeconds(201)));
        Assert.True(novel.IsDeviation);
        Assert.True(novel.Score > 0);
    }

    [Fact]
    public void EmptyPaths_AreIgnored()
    {
        var bl = new BaselineAnalyzer(minObservationsToEstablish: 2);
        var t0 = DateTime.UtcNow;
        var (score, _, dev) = bl.Observe(Net("", "host.example:443", t0));
        Assert.Equal(0, score);
        Assert.False(dev);
    }
}
