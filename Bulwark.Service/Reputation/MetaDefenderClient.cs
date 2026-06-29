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
    private readonly HttpClient _http;

    public bool IsEnabled { get; }

    public MetaDefenderClient(ILogger<MetaDefenderClient> logger, BulwarkOptions options)
    {
        _logger = logger;
        _opt = options.MetaDefender;

        var envKey = Environment.GetEnvironmentVariable(MetaDefenderOptions.ApiKeyEnvVar);
        _apiKey = !string.IsNullOrWhiteSpace(envKey) ? envKey.Trim()
                : !string.IsNullOrWhiteSpace(_opt.ApiKey) ? _opt.ApiKey!.Trim()
                : null;

        IsEnabled = !string.IsNullOrEmpty(_apiKey);

        _http = ReputationHttp.Create(
            TimeSpan.FromSeconds(Math.Max(3, _opt.QueryTimeoutSeconds)), "MetaDefender");
        if (_apiKey is not null)
            _http.DefaultRequestHeaders.Add("apikey", _apiKey);

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
            using var resp = await _http.GetAsync(BaseUrl + sha256, token);

            if (resp.StatusCode == HttpStatusCode.NotFound)
            {
                // 未收录:权威负结果,可缓存,避免反复查同一未收录文件。
                return new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown, QuerySucceeded = true };
            }
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                _logger.LogWarning("MetaDefender 鉴权失败({code}),请检查 API Key。", (int)resp.StatusCode);
                return unknown;
            }
            if (resp.StatusCode == (HttpStatusCode)429)
            {
                _logger.LogWarning("MetaDefender 触发限流(429),本次跳过。");
                return unknown;
            }
            if (!resp.IsSuccessStatusCode) return unknown;

            var body = await resp.Content.ReadAsStringAsync(token);
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
            using var resp = await _http.GetAsync(BaseUrl + eicarSha256, token);
            return resp.StatusCode switch
            {
                HttpStatusCode.OK => (true, "连接成功,API 密钥有效"),
                HttpStatusCode.NotFound => (true, "连接成功(测试样本未收录,密钥有效)"),
                HttpStatusCode.Unauthorized => (false, "API 密钥无效(401)"),
                HttpStatusCode.Forbidden => (false, "API 密钥无权限(403)"),
                (HttpStatusCode)429 => (true, "密钥有效,但当前已触发限流(429)"),
                _ => (false, $"返回异常状态:{(int)resp.StatusCode}")
            };
        }
        catch (OperationCanceledException) { return (false, "请求超时或已取消"); }
        catch (Exception ex) { return (false, "连接失败:" + ex.Message); }
    }
}
