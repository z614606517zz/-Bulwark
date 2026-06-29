using System.Threading.Channels;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Microsoft.Extensions.Logging;

namespace Bulwark.Service.Reputation;

/// <summary>
/// 信誉查询协调器。把"本地缓存(同步路径用)"与"后台异步 VT 查询(限流)"解耦:
///
///  - <see cref="TryGetCached"/>:裁决同步路径调用,只读内存缓存,微秒级,绝不碰网络。
///  - <see cref="Enqueue"/>:对"值得查"的样本入队,后台 worker 限流查询并写缓存。
///  - 后台查到恶意结论且进程仍在运行时,通过 <see cref="MaliciousConfirmed"/> 回调
///    交由宿主做补偿处置(告警 + 结束进程)。
///
/// 这样 VirusTotal 永远是"锦上添花":挂了/超配额/断网都不影响内核实时防护与本地启发式。
/// </summary>
public sealed class ReputationManager : IDisposable
{
    private readonly ILogger<ReputationManager> _logger;
    private readonly IHashReputationService _client;
    private readonly ReputationCache _cache;

    /// <summary>有界去重队列:容量满或重复哈希在途时丢弃(本地启发式已兜底,丢弃安全)。</summary>
    private readonly Channel<SecurityEvent> _queue =
        Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(256)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.DropWrite
        });

    /// <summary>在途/已入队哈希,避免对同一文件重复排队。</summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> _inflight =
        new(StringComparer.OrdinalIgnoreCase);

    private CancellationTokenSource? _cts;
    private Task? _loop;

    /// <summary>
    /// 后台确认某文件为恶意时触发(参数:触发事件 + 信誉结论)。
    /// 宿主据此做补偿处置:推送告警、结束仍在运行的进程、可选固化拦截规则。
    /// </summary>
    public event Action<SecurityEvent, FileReputation>? MaliciousConfirmed;

    public bool IsEnabled => _client.IsEnabled;

    /// <summary>
    /// 按运行时设置更新各信誉源开关(仅当底层为聚合器时生效)。
    /// </summary>
    public void SetRuntimeEnabled(bool virusTotal, bool malwareBazaar, bool otx, bool threatBook, bool metaDefender)
    {
        if (_client is AggregateReputationService agg)
            agg.SetRuntimeEnabled(virusTotal, malwareBazaar, otx, threatBook, metaDefender);
    }

    /// <summary>测试指定源的连接;source 为空则测试全部已启用源(透传客户端)。</summary>
    public Task<(bool Ok, string Message)> TestConnectionAsync(string? source, CancellationToken token = default)
    {
        if (!string.IsNullOrWhiteSpace(source) && _client is AggregateReputationService agg)
            return agg.TestConnectionAsync(source, token);
        return _client.TestConnectionAsync(token);
    }

    public ReputationManager(
        ILogger<ReputationManager> logger,
        IHashReputationService client,
        ReputationCache cache)
    {
        _logger = logger;
        _client = client;
        _cache = cache;
    }

    /// <summary>
    /// 同步路径:读已缓存的信誉用于富化。返回最近一次已知结论(恶意/干净/可疑),
    /// 即便已过 TTL 也照用(离线兜底);Unknown 视为无信息返回 null。绝不发起网络调用。
    /// </summary>
    public FileReputation? TryGetCached(string? sha256) => _cache.TryGetForEnrichment(sha256);

    /// <summary>
    /// 手动查询(用户在 UI 主动触发)。先查缓存,命中任何已保存结论(含 Unknown 负缓存)
    /// 都直接返回,不重复查 VT;仅当缓存未命中或已过期时才真正发起一次网络查询并写缓存。
    /// </summary>
    public async Task<FileReputation> QueryNowAsync(string sha256, CancellationToken token = default)
    {
        if (string.IsNullOrEmpty(sha256))
            return new FileReputation { Verdict = ReputationVerdict.Unknown };

        // 命中缓存(含未收录的负缓存)直接复用,避免重复查询。
        var cached = _cache.TryGet(sha256);
        if (cached is not null) return cached;

        var rep = await _client.QueryAsync(sha256, token);
        rep.Sha256 = sha256;
        // 仅缓存查询成功的权威结果(Store 内部按 QuerySucceeded 过滤);
        // 查询失败的不缓存,下次重查。
        _cache.Store(rep);
        return rep;
    }

    /// <summary>
    /// 双击病毒扫描回退:当 VirusTotal 不可用 / 无明确结论时,按哈希查询其他已启用情报源
    /// (MalwareBazaar / OTX / ThreatBook / MetaDefender,不含 VT)。先读缓存避免重复查询;
    /// 仅在底层为聚合器时生效,否则返回 Unknown。查询成功的权威结果会写入缓存以便去重。
    /// </summary>
    public async Task<FileReputation> QueryFallbackExcludingVtAsync(string sha256, CancellationToken token = default)
    {
        if (string.IsNullOrEmpty(sha256))
            return new FileReputation { Verdict = ReputationVerdict.Unknown };

        if (_client is not AggregateReputationService agg)
            return new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };

        // 命中缓存(含未收录的负缓存)直接复用。
        var cached = _cache.TryGet(sha256);
        if (cached is not null) return cached;

        var rep = await agg.QueryExcludingVirusTotalAsync(sha256, token);
        rep.Sha256 = sha256;
        _cache.Store(rep); // 仅缓存查询成功的权威结果(Store 内部按 QuerySucceeded 过滤)
        return rep;
    }

    /// <summary>测试连接 / API Key 有效性(透传客户端)。</summary>
    public Task<(bool Ok, string Message)> TestConnectionAsync(CancellationToken token = default)
        => _client.TestConnectionAsync(token);

    /// <summary>
    /// 判断某事件是否"值得"查 VT,并在值得时入队后台查询。
    /// 过滤条件(省配额核心):未签名 + 本机首见 + 启发式已达可疑(>=50),
    /// 且缓存未命中、不在途。带可信签名/低风险/已缓存的样本一律跳过。
    /// </summary>
    public void MaybeEnqueue(SecurityEvent e)
    {
        if (!_client.IsEnabled) return;
        var hash = e.ActorHash;
        if (string.IsNullOrEmpty(hash)) return;

        // 已有缓存结论 -> 不必再查。
        if (_cache.TryGet(hash) is not null) return;

        // 只查高价值样本。
        bool worth = !e.ActorSigned
                     && e.IsFirstSeen
                     && e.RiskScore >= ThreatDetector.Suspicious;
        if (!worth) return;

        if (!_inflight.TryAdd(hash, 0)) return; // 同一文件已在途

        if (!_queue.Writer.TryWrite(e))
            _inflight.TryRemove(hash, out _); // 队列满,放弃(本地启发式兜底)
    }

    public void Start(CancellationToken token)
    {
        if (!_client.IsEnabled) return;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        _loop = Task.Run(() => ConsumeLoopAsync(_cts.Token));
        _logger.LogInformation("信誉查询后台 worker 已启动。");
    }

    private async Task ConsumeLoopAsync(CancellationToken token)
    {
        try
        {
            await foreach (var e in _queue.Reader.ReadAllAsync(token))
            {
                var hash = e.ActorHash;
                try
                {
                    if (string.IsNullOrEmpty(hash)) continue;

                    var rep = await _client.QueryAsync(hash, token);
                    rep.Sha256 = hash;
                    // 仅缓存查询成功的权威结果(Store 内部按 QuerySucceeded 过滤);
                    // 查询失败(TLS/网络/超时等)不缓存,下次重查。
                    _cache.Store(rep);
                    if (rep.Verdict == ReputationVerdict.Unknown) continue;

                    _logger.LogInformation("信誉查询完成:{file} => {verdict}({m}/{t})",
                        System.IO.Path.GetFileName(e.ActorPath), rep.Verdict, rep.Malicious, rep.TotalEngines);

                    // 命中恶意:把结论挂回事件,交宿主补偿处置(告警 + 结束进程)。
                    if (rep.IsMalicious)
                    {
                        e.Reputation = rep;
                        try { MaliciousConfirmed?.Invoke(e, rep); }
                        catch (Exception cbEx) { _logger.LogError(cbEx, "恶意确认回调异常。"); }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogError(ex, "后台信誉查询处理失败。"); }
                finally
                {
                    if (!string.IsNullOrEmpty(hash)) _inflight.TryRemove(hash, out _);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _logger.LogError(ex, "信誉查询 worker 异常退出。"); }
    }

    public void Dispose()
    {
        try { _cts?.Cancel(); } catch { }
        _queue.Writer.TryComplete();
    }
}
