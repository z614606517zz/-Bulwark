using System;
using System.Linq;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="ProcessChainTracker"/>:把孤立事件按进程树聚合,
/// 还原「祖先→自身→子进程」的攻击链上下文。
/// </summary>
public class ProcessChainTrackerTests
{
    private static SecurityEvent Evt(
        EventType type, int actorPid, int parentPid,
        string actorPath, string target = "", DateTime? ts = null) => new()
    {
        Type = type,
        ActorPid = actorPid,
        ParentPid = parentPid,
        ActorPath = actorPath,
        Target = target,
        TimestampUtc = ts ?? DateTime.UtcNow
    };

    [Fact]
    public void BuildContext_IncludesAncestorChain()
    {
        var tracker = new ProcessChainTracker();
        var t0 = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);

        // winword(100) → powershell(200) → dropper(300)
        tracker.Record(Evt(EventType.ProcessCreate, 200, 100, @"C:\powershell.exe", ts: t0));
        tracker.Record(Evt(EventType.NetworkConnect, 200, 100, @"C:\powershell.exe", "1.2.3.4:443", t0.AddSeconds(1)));
        tracker.Record(Evt(EventType.ProcessCreate, 300, 200, @"C:\Temp\dropper.exe", ts: t0.AddSeconds(2)));

        // 现在 dropper(300) 要改注册表 —— 构建上下文应能回溯到 powershell(200)
        var current = Evt(EventType.RegistryWrite, 300, 200, @"C:\Temp\dropper.exe",
            @"HKCU\...\Run", t0.AddSeconds(3));

        var ctx = tracker.BuildContext(current);

        // 应同时包含 powershell 与 dropper 的事件
        Assert.Contains(ctx, c => c.ActorPid == 200);
        Assert.Contains(ctx, c => c.ActorPid == 300 && c.Type == EventType.RegistryWrite);
        // 时间升序
        Assert.True(ctx.SequenceEqual(ctx.OrderBy(c => c.TimestampUtc)));
    }

    [Fact]
    public void BuildContext_IncludesChildProcesses()
    {
        var tracker = new ProcessChainTracker();
        var t0 = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);

        // 父 500 派生子 600
        tracker.Record(Evt(EventType.ProcessCreate, 500, 1, @"C:\parent.exe", ts: t0));
        tracker.Record(Evt(EventType.ProcessCreate, 600, 500, @"C:\child.exe", ts: t0.AddSeconds(1)));
        tracker.Record(Evt(EventType.FileWrite, 600, 500, @"C:\child.exe", @"C:\evil.dll", t0.AddSeconds(2)));

        // 对父进程构建上下文,应纳入子进程 600 的行为
        var current = Evt(EventType.NetworkConnect, 500, 1, @"C:\parent.exe", "9.9.9.9:80", t0.AddSeconds(3));
        var ctx = tracker.BuildContext(current);

        Assert.Contains(ctx, c => c.ActorPid == 600 && c.Type == EventType.FileWrite);
    }

    [Fact]
    public void BuildContext_IncludesCurrentEvent_EvenIfNotRecorded()
    {
        var tracker = new ProcessChainTracker();
        var current = Evt(EventType.ProcessCreate, 700, 1, @"C:\x.exe");
        var ctx = tracker.BuildContext(current);
        Assert.Single(ctx);
        Assert.Equal(700, ctx[0].ActorPid);
    }

    [Fact]
    public void BuildContext_RespectsMaxEvents()
    {
        var tracker = new ProcessChainTracker();
        var t0 = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        for (int i = 0; i < 30; i++)
            tracker.Record(Evt(EventType.FileWrite, 800, 1, @"C:\a.exe", $"f{i}", t0.AddSeconds(i)));

        var current = Evt(EventType.FileWrite, 800, 1, @"C:\a.exe", "final", t0.AddSeconds(100));
        var ctx = tracker.BuildContext(current, maxEvents: 5);

        Assert.Equal(5, ctx.Count);
        // 保留最近的:最后一条应为 current
        Assert.Equal("final", ctx.Last().Target);
    }

    [Fact]
    public void Record_IgnoresInvalidPid()
    {
        var tracker = new ProcessChainTracker();
        tracker.Record(Evt(EventType.ProcessCreate, 0, 0, @"C:\x.exe"));
        Assert.Equal(0, tracker.TrackedProcessCount);
    }

    [Fact]
    public void Retention_EvictsExpiredEntries()
    {
        // 保留期极短,记录后立即过期
        var tracker = new ProcessChainTracker(retention: TimeSpan.FromMilliseconds(1));
        tracker.Record(Evt(EventType.ProcessCreate, 900, 1, @"C:\old.exe",
            ts: DateTime.UtcNow.AddMinutes(-10)));
        System.Threading.Thread.Sleep(5);
        // 再记录一个新事件触发清理
        tracker.Record(Evt(EventType.ProcessCreate, 901, 1, @"C:\new.exe"));

        Assert.Equal(1, tracker.TrackedProcessCount);
    }

    [Fact]
    public void AncestorCycle_DoesNotHang()
    {
        var tracker = new ProcessChainTracker();
        // 构造父子环:1000←1001, 1001←1000
        tracker.Record(Evt(EventType.ProcessCreate, 1000, 1001, @"C:\a.exe"));
        tracker.Record(Evt(EventType.ProcessCreate, 1001, 1000, @"C:\b.exe"));

        var current = Evt(EventType.FileWrite, 1000, 1001, @"C:\a.exe", "f");
        var ctx = tracker.BuildContext(current);
        Assert.NotEmpty(ctx); // 不应死循环
    }
}
