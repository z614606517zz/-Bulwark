using System.Net;
using System.Text.Json;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Microsoft.Extensions.Logging;

namespace Bulwark.Service.Reputation;

/// <summary>
/// MetaDefender Cloud(OPSWAT)多引擎哈希信誉客户端。GET https://api.metadefender.com/v4/hash/{sha256}
/// 读取该文件经多款引擎扫描后的结果,作为第 5 个 <see cref="IHashReputationService"/> 源。
///
/// 设计与 VirusTotal 客户端一致:自带令牌桶 + 日配额限流、超时、任何失败降级 Unknown、
/// 只读哈希、仅后台异步调用。404=未收录(权威负结果,可缓存)。
///
/// API Key:环境变量 BULWARK_MDC_APIKEY 优先,其次配置 ApiKey。
/// </summary>
public sealed class MetaDefenderClient : IHashReputationService
{
    private const string BaseUrl = "https://api.metadefender.com/v4/hash/";

    private readonly ILogger<MetaDefenderClient> _logger;
    private readonly MetaDefenderOptions _opt;
    private readonly string? _apiKey;
    private readonly TokenBucket _bucket;
    private readonly DailyQuota _daily;

    public bool IsEnabled { get; }

    public ReputationUsage GetUsage()
    {
        var (used, limit) = _daily.Snapshot();
        return new ReputationUsage
        {
            Source = "MetaDefender", Enabled = IsEnabled,
            UsedToday = used, DailyLimit = limit, PerMinuteLimit = _opt.RequestsPerMinute
        };
    }

    public MetaDefenderClient(ILogger<MetaDefenderClient> logger, BulwarkOptions options)
    {
        _logger = logger;
        _opt = options.MetaDefender;

        var envKey = Environment.GetEnvironmentVariable(MetaDefenderOptions.ApiKeyEnvVar);
        _apiKey = !string.IsNullOrWhiteSpace(envKey) ? envKey.Trim()
                : !string.IsNullOrWhiteSpace(_opt.ApiKey) ? _opt.ApiKey!.Trim()
                : null;

        IsEnabled = !string.IsNullOrEmpty(_apiKey);

        _bucket = new TokenBucket(Math.Max(1, _opt.RequestsPerMinute), TimeSpan.FromMinutes(1));
        _daily = new DailyQuota(Math.Max(1, _opt.RequestsPerDay));

        if (_apiKey is null)
            _logger.LogInformation("MetaDefender 未提供 API Key(环境变量 {env} 或配置 ApiKey),信誉查询不可用。",
                MetaDefenderOptions.ApiKeyEnvVar);
        else
            _logger.LogInformation("MetaDefender Cloud 信誉查询能力就绪(限流 {rpm}/min, {rpd}/day);是否实际启用由运行时设置控制。",
                _opt.RequestsPerMinute, _opt.RequestsPerDay);
    }

    public async Task<FileReputation> QueryAsync(string sha256, CancellationToken token = default)
    {
        var unknown = new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };
        if (!IsEnabled || string.IsNullOrEmpty(sha256)) return unknown;

        if (!_daily.TryConsume())
        {
            _logger.LogDebug("MetaDefender 日配额已用尽,跳过查询 {hash}。", sha256);
            return unknown;
        }

        try { await _bucket.WaitAsync(token); }
        catch (OperationCanceledException) { return unknown; }

        try
        {
            var (code, body) = await ReputationCurl.GetAsync(
                BaseUrl + sha256, new[] { "apikey: " + _apiKey }, _opt.QueryTimeoutSeconds, token);

            if (code == 404)
            {
                // 未收录:权威负结果,可缓存,避免反复查同一未收录文件。
                return new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown, QuerySucceeded = true };
            }
            if (code is 401 or 403)
            {
                _logger.LogWarning("MetaDefender 鉴权失败({code}),请检查 API Key。", code);
                return unknown;
            }
            if (code == 429)
            {
                _logger.LogWarning("MetaDefender 触发限流(429),本次跳过。");
                return unknown;
            }
            if (code != 200) return unknown;

            return Parse(sha256, body);
        }
        catch (OperationCanceledException) { return unknown; }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "MetaDefender 查询异常,降级为 Unknown。");
            return unknown;
        }
    }

    /// <summary>解析 MetaDefender v4/hash 响应:scan_results.total_detected_avs / total_avs。</summary>
    private FileReputation Parse(string sha256, string body)
    {
        var rep = new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            // 未收录的另一种返回:含 error.code(如 404003)。
            if (root.TryGetProperty("error", out _))
            {
                rep.QuerySucceeded = true; // 权威"未收录"
                return rep;
            }

            int detected = 0, total = 0;
            if (root.TryGetProperty("scan_results", out var sr))
            {
                detected = GetInt(sr, "total_detected_avs");
                total = GetInt(sr, "total_avs");
            }
            rep.Malicious = detected;
            rep.TotalEngines = total;

            if (root.TryGetProperty("threat_name", out var tn) && tn.ValueKind == JsonValueKind.String)
                rep.ThreatLabel = tn.GetString();
            else if (root.TryGetProperty("scan_results", out var sr2)
                     && sr2.TryGetProperty("scan_all_result_a", out var ra) && ra.ValueKind == JsonValueKind.String)
                rep.ThreatLabel = ra.GetString();

            if (detected >= _opt.MaliciousThreshold)
                rep.Verdict = ReputationVerdict.Malicious;
            else if (detected >= 1)
                rep.Verdict = ReputationVerdict.Suspicious;
            else
                rep.Verdict = ReputationVerdict.Clean;

            rep.QuerySucceeded = true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "解析 MetaDefender 响应失败。");
        }
        return rep;
    }

    private static int GetInt(JsonElement obj, string name)
        => obj.TryGetProperty(name, out var v) && v.TryGetInt32(out var n) ? n : 0;

    public async Task<(bool Ok, string Message)> TestConnectionAsync(CancellationToken token = default)
    {
        if (string.IsNullOrEmpty(_apiKey))
            return (false, "服务端未配置 MetaDefender API 密钥(环境变量 BULWARK_MDC_APIKEY)");

        const string eicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        try { await _bucket.WaitAsync(token); }
        catch (OperationCanceledException) { return (false, "已取消"); }

        try
        {
            var (code, _) = await ReputationCurl.GetAsync(
                BaseUrl + eicarSha256, new[] { "apikey: " + _apiKey }, _opt.QueryTimeoutSeconds, token);
            return code switch
            {
                200 => (true, "连接成功,API 密钥有效"),
                404 => (true, "连接成功(测试样本未收录,密钥有效)"),
                401 => (false, "API 密钥无效(401)"),
                403 => (false, "API 密钥无权限(403)"),
                429 => (true, "密钥有效,但当前已触发限流(429)"),
                0 => (false, "连接失败(curl 不可用或网络不通)"),
                _ => (false, $"返回异常状态:{code}")
            };
        }
        catch (OperationCanceledException) { return (false, "请求超时或已取消"); }
        catch (Exception ex) { return (false, "连接失败:" + ex.Message); }
    }
}
