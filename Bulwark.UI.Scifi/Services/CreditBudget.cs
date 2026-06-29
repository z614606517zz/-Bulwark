using System;
using System.IO;
using System.Text.Json;

namespace Bulwark.UI.Services;

/// <summary>
/// 大模型 Credits 月度预算护栏(本地估算·硬性防爆额度)。
///
/// 按 mimo-v2.5-pro 官方计费(未命中缓存输入 300 Credits/token、输出 600 Credits/token)
/// 在本地累计估算每月已消耗的 Credits。每次调用大模型前先估算本次开销:若「已用 + 本次预估」
/// 会超过 (月额度 × 软停比例),则拒绝本次调用 —— 各调用方据此 fail-open(只走本地引擎,不调模型),
/// 从而保证绝不会因 AI 调用把套餐额度刷爆。
///
/// 用量按自然月(yyyy-MM)统计,跨月自动归零。状态持久化于
/// %LocalAppData%\Bulwark\ai_credit_usage.json。线程安全(单锁)。
/// </summary>
public sealed class CreditBudget
{
    /// <summary>未命中缓存输入的单价(Credits/token),mimo-v2.5-pro。</summary>
    public const int InputCreditsPerToken = 300;

    /// <summary>输出的单价(Credits/token),mimo-v2.5-pro。</summary>
    public const int OutputCreditsPerToken = 600;

    private readonly object _gate = new();
    private readonly string _path;

    private string _period = CurrentPeriod();
    private long _used;

    /// <summary>按功能类别统计的本月用量(类别名 -> 次数/Credits)。</summary>
    private readonly Dictionary<string, CatStat> _byCat = new(StringComparer.Ordinal);

    private bool _enabled = true;
    private long _monthlyLimit = 4_100_000_000; // 默认 41 亿(Lite 套餐)
    private double _softStopRatio = 0.95;        // 用到 95% 即停,留 5% 安全垫

    public CreditBudget()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Bulwark");
        try { Directory.CreateDirectory(dir); } catch { /* 忽略 */ }
        _path = Path.Combine(dir, "ai_credit_usage.json");
        Load();
    }

    /// <summary>用运行时设置更新护栏参数(开关 / 月额度)。</summary>
    public void Configure(bool enabled, long monthlyLimit, double softStopRatio = 0.95)
    {
        lock (_gate)
        {
            _enabled = enabled;
            if (monthlyLimit > 0) _monthlyLimit = monthlyLimit;
            if (softStopRatio is > 0 and <= 1) _softStopRatio = softStopRatio;
        }
    }

    /// <summary>估算一次调用的 Credits 开销(输入按未命中缓存价,输出按上限保守计)。</summary>
    public static long EstimateCredits(string? inputText, int maxOutputTokens)
    {
        long inTokens = EstimateTokens(inputText);
        return inTokens * InputCreditsPerToken + (long)maxOutputTokens * OutputCreditsPerToken;
    }

    /// <summary>
    /// 估算文本 token 数。无本地分词器,按字符数 ×0.5 粗估(对中英文/代码混合偏保守,
    /// 用于"防爆"门禁更安全)。
    /// </summary>
    public static long EstimateTokens(string? text)
    {
        if (string.IsNullOrEmpty(text)) return 0;
        return (long)Math.Ceiling(text.Length * 0.5);
    }

    /// <summary>
    /// 在调用大模型【之前】检查预算:返回 true 表示可调用;false 表示本月额度将耗尽,应跳过(fail-open)。
    /// 关闭护栏时恒为 true。
    /// </summary>
    public bool CanAfford(long estimatedCredits)
    {
        lock (_gate)
        {
            RollPeriodIfNeeded();
            if (!_enabled) return true;
            long cap = (long)(_monthlyLimit * _softStopRatio);
            return _used + Math.Max(0, estimatedCredits) <= cap;
        }
    }

    /// <summary>记录一次调用的实际(或估算)开销。优先用接口返回的真实 usage。</summary>
    public void Record(long credits) => Record(null, credits);

    /// <summary>记录一次调用的开销并归入指定功能类别(用于分项统计)。</summary>
    public void Record(string? category, long credits)
    {
        if (credits <= 0) return;
        lock (_gate)
        {
            RollPeriodIfNeeded();
            _used += credits;
            if (!string.IsNullOrEmpty(category))
            {
                if (!_byCat.TryGetValue(category!, out var st)) st = new CatStat();
                st.Count += 1;
                st.Credits += credits;
                _byCat[category!] = st;
            }
            Save();
        }
    }

    /// <summary>本月各功能类别的用量快照(类别名, 次数, Credits),按 Credits 降序。</summary>
    public (string Category, long Count, long Credits)[] PerCategory()
    {
        lock (_gate)
        {
            RollPeriodIfNeeded();
            var list = new List<(string, long, long)>(_byCat.Count);
            foreach (var kv in _byCat) list.Add((kv.Key, kv.Value.Count, kv.Value.Credits));
            list.Sort((a, b) => b.Item3.CompareTo(a.Item3));
            return list.ToArray();
        }
    }

    /// <summary>当前用量快照(已用 Credits / 月额度 / 是否启用)。</summary>
    public (long Used, long Limit, bool Enabled) Snapshot()
    {
        lock (_gate)
        {
            RollPeriodIfNeeded();
            return (_used, _monthlyLimit, _enabled);
        }
    }

    private void RollPeriodIfNeeded()
    {
        var now = CurrentPeriod();
        if (_period != now)
        {
            _period = now;
            _used = 0;
            _byCat.Clear();
            Save();
        }
    }

    private static string CurrentPeriod() => DateTime.Now.ToString("yyyy-MM");

    private void Load()
    {
        try
        {
            if (!File.Exists(_path)) return;
            using var fs = File.OpenRead(_path);
            var snap = JsonSerializer.Deserialize<Persisted>(fs);
            if (snap is null) return;
            // 跨月则不沿用旧用量。
            if (string.Equals(snap.Period, CurrentPeriod(), StringComparison.Ordinal))
            {
                _period = snap.Period;
                _used = Math.Max(0, snap.Used);
                _byCat.Clear();
                if (snap.Categories is not null)
                    foreach (var kv in snap.Categories)
                        _byCat[kv.Key] = new CatStat { Count = kv.Value.Count, Credits = kv.Value.Credits };
            }
        }
        catch { /* 读取失败视为零用量 */ }
    }

    private void Save()
    {
        try
        {
            using var fs = File.Create(_path);
            var cats = new Dictionary<string, CatStat>(_byCat, StringComparer.Ordinal);
            JsonSerializer.Serialize(fs, new Persisted { Period = _period, Used = _used, Categories = cats });
        }
        catch { /* 落盘失败不影响计量(内存仍准确) */ }
    }

    private struct CatStat
    {
        public long Count { get; set; }
        public long Credits { get; set; }
    }

    private sealed class Persisted
    {
        public string Period { get; set; } = string.Empty;
        public long Used { get; set; }
        public Dictionary<string, CatStat>? Categories { get; set; }
    }
}
