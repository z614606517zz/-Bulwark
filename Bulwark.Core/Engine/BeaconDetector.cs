using System;
using System.Collections.Generic;
using System.Linq;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// C2 心跳信标探测器(独创·时序节律分析)。
///
/// 远控木马(Cobalt Strike / ValleyRAT / Gh0st 等)植入后会周期性"回连"C2 拿指令,
/// 即 beaconing。其标志是**外联时间间隔高度规律**(固定 60s,或带少量抖动 jitter),
/// 这一点正常软件的网络行为很难复现(浏览器/更新器的外联是突发且不规则的)。
///
/// 传统检测靠 IP/域名黑名单,对全新 C2 失效。本探测器不看"连到哪",只看"怎么连":
/// 为每个 (进程, 远端目标) 维护外联时间序列,当样本足够时计算间隔的
///   · 均值 μ 与标准差 σ;
///   · 变异系数 CV = σ/μ(越小越规律);
/// CV 很小(间隔近乎恒定)且周期落在常见信标区间(数秒~数十分钟)即判为信标回连。
///
/// 命中返回 (score, reasons)。这是纯行为侧、对未知 C2 同样有效的能力。
/// 线程安全:单锁串行化,带容量/过期治理。
/// </summary>
public sealed class BeaconDetector
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Series> _series = new(StringComparer.OrdinalIgnoreCase);
    private readonly int _minSamples;
    private readonly int _maxSeries;
    private readonly TimeSpan _retention;

    /// <summary>变异系数阈值:CV <= 此值视为"高度规律"。0.15 ≈ 间隔抖动 < 15%。</summary>
    private const double CvRegular = 0.15;
    private const double CvSemiRegular = 0.28;

    /// <summary>合理的信标周期区间(秒)。太短=正常突发,太长=噪声。</summary>
    private const double MinPeriodSec = 2.0;
    private const double MaxPeriodSec = 3600.0;

    public BeaconDetector(int minSamples = 4, int maxSeries = 4096, TimeSpan? retention = null)
    {
        _minSamples = Math.Max(3, minSamples);
        _maxSeries = Math.Max(64, maxSeries);

        // 保留期必须显著大于可检测的最大信标周期(MaxPeriodSec)。
        // 关键:序列按 LastUtc 过期(每次外联刷新),故只需跨越「单次回连间隔」即可存活并持续累积样本。
        // 若 retention <= MaxPeriodSec,慢信标(如间隔 1h)的序列会在两次回连之间被 EvictIfNeeded 清掉,
        // 永远攒不够 _minSamples,导致慢信标完全检测不到。这里强制下限为 MaxPeriodSec 的 1.5 倍。
        var floor = TimeSpan.FromSeconds(MaxPeriodSec * 1.5);
        _retention = retention ?? TimeSpan.FromSeconds(MaxPeriodSec * 2);
        if (_retention < floor) _retention = floor;
    }

    /// <summary>
    /// 观测一次网络外联事件,更新时序并研判是否为周期性信标。
    /// 仅对 <see cref="EventType.NetworkConnect"/> 有意义。
    /// </summary>
    public (int Score, List<string> Reasons) Observe(SecurityEvent e)
    {
        var reasons = new List<string>();
        if (e is null || e.Type != EventType.NetworkConnect || e.ActorPid <= 0)
            return (0, reasons);

        // 以 (PID + 远端目标主机) 为序列键。去掉端口后缀差异,聚焦"连同一个家"。
        string remote = NormalizeRemote(e.Target);
        string key = $"{e.ActorPid}|{remote}";
        var now = e.TimestampUtc == default ? DateTime.UtcNow : e.TimestampUtc;

        lock (_gate)
        {
            if (!_series.TryGetValue(key, out var s))
            {
                s = new Series { ActorPath = e.ActorPath, Remote = remote };
                _series[key] = s;
            }
            s.Add(now);

            EvictIfNeeded(now);

            var intervals = s.IntervalsSeconds();
            if (intervals.Count < _minSamples - 1)
                return (0, reasons); // 样本不足,继续累积

            var (mean, cv) = MeanAndCv(intervals);
            if (mean < MinPeriodSec || mean > MaxPeriodSec)
                return (0, reasons); // 周期不在信标区间

            int score = 0;
            if (cv <= CvRegular)
            {
                score = 55;
                reasons.Add($"周期性外联信标:间隔≈{mean:0.#}s 抖动极低(CV={cv:0.00},疑似 C2 回连)");
            }
            else if (cv <= CvSemiRegular)
            {
                score = 35;
                reasons.Add($"近周期性外联:间隔≈{mean:0.#}s(CV={cv:0.00},疑似带抖动的 C2 信标)");
            }
            else
            {
                return (0, reasons); // 间隔不规律,正常网络行为
            }

            // 未签名主体的规律回连更可疑
            if (!e.ActorSigned)
            {
                score += 15;
                reasons.Add("信标主体无可信签名");
            }
            // 脚本解释器做规律回连几乎必为恶意
            string actor = SafeName(e.ActorPath);
            if (ScriptHosts.Contains(actor))
            {
                score += 20;
                reasons.Add($"脚本解释器({actor})周期性外联(强 C2 特征)");
            }

            reasons.Add($"目标 {remote},已累计 {s.Count} 次外联");
            return (Math.Min(score, 100), reasons);
        }
    }

    public void Forget(int pid)
    {
        lock (_gate)
        {
            var keys = _series.Keys.Where(k => k.StartsWith($"{pid}|", StringComparison.Ordinal)).ToList();
            foreach (var k in keys) _series.Remove(k);
        }
    }

    public int TrackedSeriesCount
    {
        get { lock (_gate) return _series.Count; }
    }

    private void EvictIfNeeded(DateTime now)
    {
        var cutoff = now - _retention;
        List<string>? dead = null;
        foreach (var kv in _series)
            if (kv.Value.LastUtc < cutoff)
                (dead ??= new List<string>()).Add(kv.Key);
        if (dead is not null)
            foreach (var k in dead) _series.Remove(k);

        if (_series.Count > _maxSeries)
        {
            var oldest = _series.OrderBy(kv => kv.Value.LastUtc)
                .Take(_series.Count - _maxSeries)
                .Select(kv => kv.Key).ToList();
            foreach (var k in oldest) _series.Remove(k);
        }
    }

    /// <summary>计算间隔序列的均值与变异系数 CV=σ/μ。</summary>
    public static (double Mean, double Cv) MeanAndCv(IReadOnlyList<double> intervals)
    {
        if (intervals.Count == 0) return (0, double.MaxValue);
        double mean = intervals.Average();
        if (mean <= 0) return (0, double.MaxValue);
        double variance = intervals.Sum(x => (x - mean) * (x - mean)) / intervals.Count;
        double std = Math.Sqrt(variance);
        return (mean, std / mean);
    }

    private static string NormalizeRemote(string? target)
    {
        if (string.IsNullOrEmpty(target)) return "?";
        var t = target.Trim().ToLowerInvariant();
        // 去掉 "host:port" 的端口部分(只在最后一个冒号且其后全是数字时)
        int colon = t.LastIndexOf(':');
        if (colon > 0 && colon < t.Length - 1 && t.Skip(colon + 1).All(char.IsDigit))
            t = t.Substring(0, colon);
        return t;
    }

    private static readonly string[] ScriptHosts =
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe"
    };

    private static string SafeName(string? path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        try { return System.IO.Path.GetFileName(path).ToLowerInvariant(); }
        catch { return path.ToLowerInvariant(); }
    }

    /// <summary>单个 (进程, 目标) 的外联时间序列。</summary>
    private sealed class Series
    {
        public string ActorPath = string.Empty;
        public string Remote = string.Empty;
        public DateTime LastUtc;
        public int Count;

        private readonly List<DateTime> _times = new();
        private const int MaxKeep = 64;

        public void Add(DateTime at)
        {
            _times.Add(at);
            LastUtc = at;
            Count++;
            if (_times.Count > MaxKeep)
                _times.RemoveRange(0, _times.Count - MaxKeep);
        }

        public List<double> IntervalsSeconds()
        {
            var result = new List<double>();
            for (int i = 1; i < _times.Count; i++)
            {
                double sec = (_times[i] - _times[i - 1]).TotalSeconds;
                if (sec >= 0) result.Add(sec);
            }
            return result;
        }
    }
}
