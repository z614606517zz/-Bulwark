using System.Net;
using System.Text.Json;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Microsoft.Extensions.Logging;

namespace Bulwark.Service.Reputation;

/// <summary>
/// Hybrid Analysis(Falcon Sandbox)哈希信誉客户端。
/// GET https://www.hybrid-analysis.com/api/v2/overview/{sha256}
///
/// 读取样本概览中的 verdict / threat_score / vx_family / multiscan_result,作为与 VirusTotal
/// 互证的第二权威源(双证据原则):两个独立权威源同时报恶意时可作为高可信硬指标。
///
/// 设计与其它 <see cref="IHashReputationService"/> 源一致:自带令牌桶 + 日配额限流、超时、
/// 任何失败(网络/超时/404 未收录/401 鉴权/429 限流/解析异常)都降级为 Unknown、只读哈希、
/// 仅供后台异步调用。404 = 未收录(权威负结果,可缓存)。
///
/// 鉴权:HA 要求请求头携带 <c>api-key</c> 与固定 <c>User-Agent: Falcon Sandbox</c>,否则 403。
/// API Key:环境变量 BULWARK_HA_APIKEY 优先,其次配置 ApiKey。
/// </summary>
public sealed class HybridAnalysisClient : IHashReputationService
{
    private const string BaseUrl = "https://www.hybrid-analysis.com/api/v2/overview/";

    /// <summary>HA 强制要求的固定 User-Agent,缺失会被服务端以 403 拒绝。</summary>
    private const string RequiredUserAgent = "Falcon Sandbox";

    private readonly ILogger<HybridAnalysisClient> _logger;
    private readonly HybridAnalysisOptions _opt;
    private readonly string? _apiKey;
    private readonly TokenBucket _bucket;
    private readonly DailyQuota _daily;

    public bool IsEnabled { get; }

    public ReputationUsage GetUsage()
    {
        var (used, limit) = _daily.Snapshot();
        return new ReputationUsage
        {
            Source = "HybridAnalysis", Enabled = IsEnabled,
            UsedToday = used, DailyLimit = limit, PerMinuteLimit = _opt.RequestsPerMinute
        };
    }

    public HybridAnalysisClient(ILogger<HybridAnalysisClient> logger, BulwarkOptions options)
    {
        _logger = logger;
        _opt = options.HybridAnalysis;

        var envKey = Environment.GetEnvironmentVariable(HybridAnalysisOptions.ApiKeyEnvVar);
        _apiKey = !string.IsNullOrWhiteSpace(envKey) ? envKey.Trim()
                : !string.IsNullOrWhiteSpace(_opt.ApiKey) ? _opt.ApiKey!.Trim()
                : null;

        IsEnabled = !string.IsNullOrEmpty(_apiKey);

        _bucket = new TokenBucket(Math.Max(1, _opt.RequestsPerMinute), TimeSpan.FromMinutes(1));
        _daily = new DailyQuota(Math.Max(1, _opt.RequestsPerDay));

        if (_apiKey is null)
            _logger.LogInformation("Hybrid Analysis 未提供 API Key(环境变量 {env} 或配置 ApiKey),信誉查询不可用。",
                HybridAnalysisOptions.ApiKeyEnvVar);
        else
            _logger.LogInformation("Hybrid Analysis 信誉查询能力就绪(限流 {rpm}/min, {rpd}/day);是否实际启用由运行时设置控制。",
                _opt.RequestsPerMinute, _opt.RequestsPerDay);
    }

    public async Task<FileReputation> QueryAsync(string sha256, CancellationToken token = default)
    {
        var unknown = new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };
        if (!IsEnabled || string.IsNullOrEmpty(sha256)) return unknown;

        if (!_daily.TryConsume())
        {
            _logger.LogDebug("Hybrid Analysis 日配额已用尽,跳过查询 {hash}。", sha256);
            return unknown;
        }

        try { await _bucket.WaitAsync(token); }
        catch (OperationCanceledException) { return unknown; }

        try
        {
            var (code, body) = await ReputationCurl.GetAsync(
                BaseUrl + sha256,
                new[] { "User-Agent: " + RequiredUserAgent, "api-key: " + _apiKey },
                _opt.QueryTimeoutSeconds, token);

            if (code == 404)
            {
                // 未收录:权威负结果,可缓存,避免反复查同一未收录文件。
                return new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown, QuerySucceeded = true };
            }
            if (code is 401 or 403)
            {
                _logger.LogWarning("Hybrid Analysis 鉴权失败({code}),请检查 API Key。", code);
                return unknown;
            }
            if (code == 429)
            {
                _logger.LogWarning("Hybrid Analysis 触发限流(429),本次跳过。");
                return unknown;
            }
            if (code != 200) return unknown;

            return Parse(sha256, body);
        }
        catch (OperationCanceledException) { return unknown; }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Hybrid Analysis 查询异常,降级为 Unknown。");
            return unknown;
        }
    }

    /// <summary>
    /// 解析 HA overview 响应:verdict / threat_score / vx_family / multiscan_result。
    /// 判定以 verdict 字符串为主,缺失时回退到 threat_score 阈值。
    /// </summary>
    private FileReputation Parse(string sha256, string body)
    {
        var rep = new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            int threatScore = GetInt(root, "threat_score");
            int multiscan = GetInt(root, "multiscan_result");
            string? verdict = GetString(root, "verdict");
            string? vxFamily = GetString(root, "vx_family");

            // multiscan_result 近似为被多引擎检出的比例/计数,作为展示用检出数。
            rep.Malicious = multiscan;
            rep.TotalEngines = 0; // HA overview 不直接给引擎总数,展示以 verdict / threat_score 为主。
            if (!string.IsNullOrWhiteSpace(vxFamily))
                rep.ThreatLabel = vxFamily;

            // 优先按 verdict 文本判定。
            switch (verdict?.Trim().ToLowerInvariant())
            {
                case "malicious":
                    rep.Verdict = ReputationVerdict.Malicious;
                    break;
                case "suspicious":
                    rep.Verdict = ReputationVerdict.Suspicious;
                    break;
                case "whitelisted":
                case "no specific threat":
                    rep.Verdict = ReputationVerdict.Clean;
                    break;
                default:
                    // verdict 缺失/未知:回退到 threat_score 阈值。
                    if (threatScore >= _opt.MaliciousThreatScore)
                        rep.Verdict = ReputationVerdict.Malicious;
                    else if (threatScore > 0)
                        rep.Verdict = ReputationVerdict.Suspicious;
                    else
                        rep.Verdict = ReputationVerdict.Clean;
                    break;
            }

            rep.QuerySucceeded = true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "解析 Hybrid Analysis 响应失败。");
        }
        return rep;
    }

    private static int GetInt(JsonElement obj, string name)
        => obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n) ? n : 0;

    private static string? GetString(JsonElement obj, string name)
        => obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public async Task<(bool Ok, string Message)> TestConnectionAsync(CancellationToken token = default)
    {
        if (string.IsNullOrEmpty(_apiKey))
            return (false, "服务端未配置 Hybrid Analysis API 密钥(环境变量 BULWARK_HA_APIKEY)");

        const string eicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        try { await _bucket.WaitAsync(token); }
        catch (OperationCanceledException) { return (false, "已取消"); }

        try
        {
            var (code, _) = await ReputationCurl.GetAsync(
                BaseUrl + eicarSha256,
                new[] { "User-Agent: " + RequiredUserAgent, "api-key: " + _apiKey },
                _opt.QueryTimeoutSeconds, token);
            return code switch
            {
                200 => (true, "连接成功,API 密钥有效"),
                404 => (true, "连接成功(测试样本未收录,密钥有效)"),
                401 => (false, "API 密钥无效(401)"),
                403 => (false, "API 密钥无权限或缺少 User-Agent(403)"),
                429 => (true, "密钥有效,但当前已触发限流(429)"),
                0 => (false, "连接失败(curl 不可用或网络不通)"),
                _ => (false, $"返回异常状态:{code}")
            };
        }
        catch (OperationCanceledException) { return (false, "请求超时或已取消"); }
        catch (Exception ex) { return (false, "连接失败:" + ex.Message); }
    }
}
