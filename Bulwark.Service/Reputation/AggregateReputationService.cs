using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Microsoft.Extensions.Logging;

namespace Bulwark.Service.Reputation;

/// <summary>
/// 多源信誉聚合器。对上层(ReputationManager / Worker)实现统一的
/// <see cref="IHashReputationService"/>,内部并发查询所有已启用的下游信誉源
/// (VirusTotal / MalwareBazaar / OTX …),再按策略合并为单一结论。
///
/// 合并策略(取最强可信结论):
///  - 只要任一源判 Malicious => 结果 Malicious(任一权威源命中即拦截);
///  - 否则任一源判 Suspicious => 结果 Suspicious;
///  - 否则若有源判 Clean => 结果 Clean;
///  - 否则 Unknown。
///  - QuerySucceeded:只要任一源成功完成即为 true(可缓存);全失败则 false(下次重查)。
///  - Malicious/TotalEngines/ThreatLabel 取贡献最终结论的那个源(展示用)。
///
/// 单个源失败/超时/降级都不影响其他源,整体仍然是"锦上添花"。
/// </summary>
public sealed class AggregateReputationService : IHashReputationService
{
    private readonly ILogger<AggregateReputationService> _logger;
    private readonly IReadOnlyList<IHashReputationService> _sources;

    /// <summary>
    /// 各源的运行时开关(按源名)。由 Worker 依 RuntimeSettings 更新。
    /// 源最终是否参与查询 = 配置可用(IsEnabled,含 Key/开关)且 运行时开关为 true。
    /// 未在表中的源默认放行(由其自身 IsEnabled 决定),保证向后兼容。
    /// </summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> _runtimeEnabled =
        new(StringComparer.OrdinalIgnoreCase);

    public bool IsEnabled => _sources.Any(IsActive);

    /// <summary>聚合器自身的用量无实际意义(占位实现,满足接口)。真实用量见 <see cref="GetUsages"/>。</summary>
    public ReputationUsage GetUsage() => new() { Source = "Aggregate", Enabled = IsEnabled };

    /// <summary>逐源收集实时用量快照。Enabled 以「配置可用 且 运行时开关未关」为准。</summary>
    public IReadOnlyList<ReputationUsage> GetUsages()
    {
        var list = new List<ReputationUsage>();
        foreach (var s in _sources)
        {
            var u = s.GetUsage();
            u.Enabled = IsActive(s);
            list.Add(u);
        }
        return list;
    }

    public AggregateReputationService(
        ILogger<AggregateReputationService> logger,
        IEnumerable<IHashReputationService> sources)
    {
        _logger = logger;
        // 排除聚合器自身,避免递归。
        _sources = sources.Where(s => s is not AggregateReputationService).ToList();

        var enabled = _sources.Where(s => s.IsEnabled).Select(s => s.GetType().Name);
        _logger.LogInformation("信誉聚合器就绪,已启用源:{sources}",
            string.Join(", ", enabled.DefaultIfEmpty("(无)")));
    }

    /// <summary>
    /// 按运行时设置更新各源开关。Worker 在设置变更时调用。
    /// </summary>
    public void SetRuntimeEnabled(bool virusTotal, bool malwareBazaar, bool otx, bool threatBook, bool metaDefender, bool hybridAnalysis)
    {
        _runtimeEnabled[SourceName(typeof(VirusTotalClient))] = virusTotal;
        _runtimeEnabled[SourceName(typeof(MalwareBazaarClient))] = malwareBazaar;
        _runtimeEnabled[SourceName(typeof(OtxClient))] = otx;
        _runtimeEnabled[SourceName(typeof(ThreatBookClient))] = threatBook;
        _runtimeEnabled[SourceName(typeof(MetaDefenderClient))] = metaDefender;
        _runtimeEnabled[SourceName(typeof(HybridAnalysisClient))] = hybridAnalysis;
    }

    /// <summary>某源当前是否真正参与查询:配置可用 且 运行时开关未关闭。</summary>
    private bool IsActive(IHashReputationService s)
    {
        if (!s.IsEnabled) return false;
        return !_runtimeEnabled.TryGetValue(SourceName(s.GetType()), out var on) || on;
    }

    public async Task<FileReputation> QueryAsync(string sha256, CancellationToken token = default)
    {
        var unknown = new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };
        if (string.IsNullOrEmpty(sha256)) return unknown;

        var active = _sources.Where(IsActive).ToList();
        if (active.Count == 0) return unknown;

        FileReputation[] results;
        try
        {
            results = await Task.WhenAll(active.Select(s => QuerySafe(s, sha256, token)));
        }
        catch (OperationCanceledException) { return unknown; }

        return Merge(sha256, results);
    }

    /// <summary>
    /// 仅查询 VirusTotal 之外的其他已启用源(MalwareBazaar / OTX / ThreatBook / MetaDefender)。
    /// 供「双击病毒扫描」在 VT 不可用 / 无明确结论时回退使用 —— 优先 VT,VT 缺位才动用其他源,
    /// 既保证 VT 的权威性,又能在 VT 失效时不留盲区。合并策略与 <see cref="QueryAsync"/> 一致。
    /// </summary>
    public async Task<FileReputation> QueryExcludingVirusTotalAsync(string sha256, CancellationToken token = default)
    {
        var unknown = new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };
        if (string.IsNullOrEmpty(sha256)) return unknown;

        var active = _sources.Where(s => IsActive(s) && s is not VirusTotalClient).ToList();
        if (active.Count == 0) return unknown;

        FileReputation[] results;
        try
        {
            results = await Task.WhenAll(active.Select(s => QuerySafe(s, sha256, token)));
        }
        catch (OperationCanceledException) { return unknown; }

        return Merge(sha256, results);
    }

    private async Task<FileReputation> QuerySafe(IHashReputationService source, string sha256, CancellationToken token)
    {
        try { return await source.QueryAsync(sha256, token); }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "信誉源 {src} 查询异常,降级为 Unknown。", source.GetType().Name);
            return new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };
        }
    }

    /// <summary>按"取最强可信结论"策略合并多源结果。</summary>
    private static FileReputation Merge(string sha256, IReadOnlyList<FileReputation> results)
    {
        bool anySucceeded = results.Any(r => r.QuerySucceeded);

        // 优先级:Malicious > Suspicious > Clean > Unknown。
        FileReputation? best = null;
        foreach (var r in results)
        {
            if (best is null || Rank(r.Verdict) > Rank(best.Verdict))
                best = r;
        }

        var merged = new FileReputation
        {
            Sha256 = sha256,
            Verdict = best?.Verdict ?? ReputationVerdict.Unknown,
            Malicious = best?.Malicious ?? 0,
            TotalEngines = best?.TotalEngines ?? 0,
            ThreatLabel = best?.ThreatLabel,
            LastAnalysisUtc = best?.LastAnalysisUtc,
            FetchedUtc = DateTime.UtcNow,
            QuerySucceeded = anySucceeded,
        };
        return merged;
    }

    private static int Rank(ReputationVerdict v) => v switch
    {
        ReputationVerdict.Malicious => 3,
        ReputationVerdict.Suspicious => 2,
        ReputationVerdict.Clean => 1,
        _ => 0,
    };

    /// <summary>测试连接:汇总所有已启用源的测试结果。任一成功即视为整体可用。</summary>
    public async Task<(bool Ok, string Message)> TestConnectionAsync(CancellationToken token = default)
    {
        var active = _sources.Where(IsActive).ToList();
        if (active.Count == 0) return (false, "未启用任何信誉源");

        var tests = await Task.WhenAll(active.Select(async s =>
        {
            try { var (ok, msg) = await s.TestConnectionAsync(token); return (Name: SourceName(s), ok, msg); }
            catch (Exception ex) { return (Name: SourceName(s), ok: false, msg: ex.Message); }
        }));

        bool anyOk = tests.Any(t => t.ok);
        var summary = string.Join(" | ", tests.Select(t => $"{t.Name}: {(t.ok ? "✓" : "✗")} {t.msg}"));
        return (anyOk, summary);
    }

    /// <summary>测试指定源(按名称:VirusTotal / MalwareBazaar / OTX)的连接。</summary>
    public async Task<(bool Ok, string Message)> TestConnectionAsync(string source, CancellationToken token = default)
    {
        var target = _sources.FirstOrDefault(s =>
            string.Equals(SourceName(s), source, StringComparison.OrdinalIgnoreCase));
        if (target is null)
            return (false, $"未找到信誉源:{source}");
        if (!target.IsEnabled)
            return (false, $"{source} 未配置或不可用(检查开关与 API Key)");
        try { return await target.TestConnectionAsync(token); }
        catch (Exception ex) { return (false, "连接失败:" + ex.Message); }
    }

    private static string SourceName(IHashReputationService s) => SourceName(s.GetType());

    private static string SourceName(Type t) => t.Name switch
    {
        nameof(VirusTotalClient) => "VirusTotal",
        nameof(MalwareBazaarClient) => "MalwareBazaar",
        nameof(OtxClient) => "OTX",
        nameof(ThreatBookClient) => "ThreatBook",
        nameof(MetaDefenderClient) => "MetaDefender",
        nameof(HybridAnalysisClient) => "HybridAnalysis",
        _ => t.Name,
    };
}
