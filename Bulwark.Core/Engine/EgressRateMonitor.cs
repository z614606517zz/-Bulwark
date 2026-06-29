using System;
using System.Collections.Generic;
using System.Linq;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// 外联速率/扇出监视器(独创·有状态时序检测)。
///
/// 补全网络防护的第三条腿(前两条:<see cref="BeaconDetector"/> 时序节律、
/// <see cref="DgaDomainAnalyzer"/> 域名随机度)。本监视器关注**外联的"量"与"面"**:
///   · 速率突发(rate burst):单进程在极短时间内发起远超常态的外联次数;
///   · 目标扇出(fan-out):单进程在短时间内连向大量【不同】远端目标。
///
/// 这两类是端口扫描 / 内网横移 / 蠕虫传播 / C2 多节点轮询 / 数据外传分块上传的共同特征。
/// 正常程序的外联通常集中在少数几个固定服务端(浏览器除外),很少在数秒内打向几十个不同 IP。
///
/// 关键约束(遵循全局低误报原则):速率/扇出是**软信号**,
/// <b>单独不得</b>置位 <see cref="SecurityEvent.HasThreatIndicator"/> 或直接处置 ——
/// 浏览器、下载器、P2P、爬虫、更新检查都可能高速多目标外联。
/// 它只贡献 RiskScore / RiskReasons,由调用方在与另一硬指标(信标 / DGA 升格 /
/// 未签名可疑目录主体)共现时才升格(互证机制)。
///
/// 线程安全:单锁串行化,带容量/过期治理。
/// </summary>
public sealed class EgressRateMonitor
{
    private readonly object _gate = new();
    private readonly Dictionary<int, ProcState> _byPid = new();
    private readonly TimeSpan _window;
    private readonly int _maxPids;

    /// <summary>窗口内"外联次数"达到此值视为速率突发。</summary>
    private readonly int _rateThreshold;

    /// <summary>窗口内"不同远端目标数"达到此值视为高扇出。</summary>
    private readonly int _fanoutThreshold;

    public EgressRateMonitor(
        TimeSpan? window = null,
        int rateThreshold = 40,
        int fanoutThreshold = 20,
        int maxPids = 4096)
    {
        _window = window ?? TimeSpan.FromSeconds(10);
        _rateThreshold = Math.Max(10, rateThreshold);
        _fanoutThreshold = Math.Max(8, fanoutThreshold);
        _maxPids = Math.Max(64, maxPids);
    }

    /// <summary>
    /// 观测一次网络外联事件,更新进程状态并研判速率/扇出异常。
    /// 仅对 <see cref="EventType.NetworkConnect"/> 有意义,其它类型返回 0 分。
    /// </summary>
    public (int Score, List<string> Reasons) Observe(SecurityEvent e)
    {
        var reasons = new List<string>();
        if (e is null || e.Type != EventType.NetworkConnect || e.ActorPid <= 0)
            return (0, reasons);

        string remote = NormalizeRemote(e.Target);
        var now = e.TimestampUtc == default ? DateTime.UtcNow : e.TimestampUtc;
        int score = 0;

        lock (_gate)
        {
            if (!_byPid.TryGetValue(e.ActorPid, out var st))
            {
                st = new ProcState();
                _byPid[e.ActorPid] = st;
            }
            st.Add(remote, now, _window);

            int count = st.CountInWindow(now, _window);
            int distinct = st.DistinctTargetsInWindow(now, _window);

            // 1) 速率突发
            if (count >= _rateThreshold)
            {
                int over = count - _rateThreshold;
                score += 25 + Math.Min(over, 40);
                reasons.Add($"{_window.TotalSeconds:0}秒内高速外联 {count} 次(疑似扫描/外传/C2 轮询)");
            }

            // 2) 目标扇出(更强信号:连大量不同目标)
            if (distinct >= _fanoutThreshold)
            {
                int over = distinct - _fanoutThreshold;
                score += 30 + Math.Min(over * 2, 40);
                reasons.Add($"{_window.TotalSeconds:0}秒内连向 {distinct} 个不同目标(疑似横移/扫描/蠕虫传播)");
            }

            EvictIfNeeded(now);
        }

        return (Math.Min(score, 100), reasons);
    }

    /// <summary>进程退出时清理其状态(可选)。</summary>
    public void Forget(int pid)
    {
        lock (_gate) _byPid.Remove(pid);
    }

    /// <summary>当前跟踪进程数(诊断/测试用)。</summary>
    public int TrackedProcessCount
    {
        get { lock (_gate) return _byPid.Count; }
    }

    private void EvictIfNeeded(DateTime now)
    {
        var stale = now - TimeSpan.FromTicks(_window.Ticks * 4);
        List<int>? dead = null;
        foreach (var kv in _byPid)
            if (kv.Value.LastUtc < stale)
                (dead ??= new List<int>()).Add(kv.Key);
        if (dead is not null)
            foreach (var pid in dead) _byPid.Remove(pid);

        if (_byPid.Count > _maxPids)
        {
            var oldest = _byPid.OrderBy(kv => kv.Value.LastUtc)
                .Take(_byPid.Count - _maxPids)
                .Select(kv => kv.Key).ToList();
            foreach (var pid in oldest) _byPid.Remove(pid);
        }
    }

    private static string NormalizeRemote(string? target)
    {
        if (string.IsNullOrEmpty(target)) return "?";
        var t = target.Trim().ToLowerInvariant();
        int colon = t.LastIndexOf(':');
        if (colon > 0 && colon < t.Length - 1 && t.Skip(colon + 1).All(char.IsDigit))
            t = t.Substring(0, colon);
        return t;
    }

    /// <summary>单进程的外联滑动窗口状态。</summary>
    private sealed class ProcState
    {
        public DateTime LastUtc;
        private readonly List<(string Remote, DateTime At)> _events = new();
        private const int HardCap = 4096;

        public void Add(string remote, DateTime at, TimeSpan window)
        {
            _events.Add((remote, at));
            LastUtc = at;
            var cutoff = at - window;
            int i = 0;
            while (i < _events.Count && _events[i].At < cutoff) i++;
            if (i > 0) _events.RemoveRange(0, i);
            if (_events.Count > HardCap)
                _events.RemoveRange(0, _events.Count - HardCap);
        }

        public int CountInWindow(DateTime now, TimeSpan window)
        {
            var cutoff = now - window;
            int n = 0;
            foreach (var ev in _events) if (ev.At >= cutoff) n++;
            return n;
        }

        public int DistinctTargetsInWindow(DateTime now, TimeSpan window)
        {
            var cutoff = now - window;
            return _events.Where(ev => ev.At >= cutoff)
                          .Select(ev => ev.Remote)
                          .Distinct()
                          .Count();
        }
    }
}
