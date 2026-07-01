using System.Net;
using System.Text.Json;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Microsoft.Extensions.Logging;

namespace Bulwark.Service.Reputation;

/// <summary>
/// AlienVault OTX 哈希信誉客户端。
/// GET https://otx.alienvault.com/api/v1/indicators/file/{hash}/general
/// 读取该文件关联的 pulse(威胁情报报告)数量与标签。
///
/// 设计要点(与 VirusTotalClient 对齐):
///  - 自带限流(令牌桶 + 每日配额);
///  - 任何失败(网络/超时/404/鉴权/限流)都返回 Unknown,绝不抛断主流程;
///  - 只查哈希,不上传文件;仅供后台异步调用。
///
/// 语义:OTX 不是多引擎杀软扫描,而是社区威胁情报。pulse 数越多代表被越多情报
/// 报告关联。pulse_count >= 阈值 判 Malicious;1~阈值-1 判 Suspicious;0 判 Clean。
/// API Key 优先从环境变量 BULWARK_OTX_APIKEY 读取。
/// </summary>
public sealed class OtxClient : IHashReputationService
{
    private const string BaseUrl = "https://otx.alienvault.com/api/v1/indicators/file/";

    private readonly ILogger<OtxClient> _logger;
    private readonly OtxOptions _opt;
    private readonly string? _apiKey;
    private readonly TokenBucket _bucket;
    private readonly DailyQuota _daily;

    public bool IsEnabled { get; }

    public ReputationUsage GetUsage()
    {
        var (used, limit) = _daily.Snapshot();
        return new ReputationUsage
        {
            Source = "OTX", Enabled = IsEnabled,
            UsedToday = used, DailyLimit = limit, PerMinuteLimit = _opt.RequestsPerMinute
        };
    }

    public OtxClient(ILogger<OtxClient> logger, BulwarkOptions options)
    {
        _logger = logger;
        _opt = options.Otx;

        var envKey = Environment.GetEnvironmentVariable(OtxOptions.ApiKeyEnvVar);
        _apiKey = !string.IsNullOrWhiteSpace(envKey) ? envKey.Trim()
                : !string.IsNullOrWhiteSpace(_opt.ApiKey) ? _opt.ApiKey!.Trim()
                : null;

        IsEnabled = _opt.Enabled && !string.IsNullOrEmpty(_apiKey);

        _bucket = new TokenBucket(Math.Max(1, _opt.RequestsPerMinute), TimeSpan.FromMinutes(1));
        _daily = new DailyQuota(Math.Max(1, _opt.RequestsPerDay));

        if (_opt.Enabled && _apiKey is null)
            _logger.LogInformation("OTX 已启用但未提供 API Key(环境变量 {env} 或配置 ApiKey),信誉查询不可用。",
                OtxOptions.ApiKeyEnvVar);
        else if (IsEnabled)
            _logger.LogInformation("OTX 信誉查询能力就绪(限流 {rpm}/min, {rpd}/day)。",
                _opt.RequestsPerMinute, _opt.RequestsPerDay);
    }

    public async Task<FileReputation> QueryAsync(string sha256, CancellationToken token = default)
    {
        var unknown = new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };
        if (!IsEnabled || string.IsNullOrEmpty(sha256)) return unknown;

        if (!_daily.TryConsume())
        {
            _logger.LogDebug("OTX 日配额已用尽,跳过查询 {hash}。", sha256);
            return unknown;
        }

        try { await _bucket.WaitAsync(token); }
        catch (OperationCanceledException) { return unknown; }

        try
        {
            var (code, body) = await ReputationCurl.GetAsync(
                $"{BaseUrl}{sha256}/general", new[] { "X-OTX-API-KEY: " + _apiKey }, _opt.QueryTimeoutSeconds, token);

            if (code == 404)
            {
                // OTX 无该指标记录:权威负结果,可缓存,但不等于"干净"。保持 Unknown。
                ReputationHttp.DiagLog($"OTX query {sha256[..12]} => 404 NotFound");
                return new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown, QuerySucceeded = true };
            }
            if (code is 401 or 403)
            {
                _logger.LogWarning("OTX 鉴权失败({code}),请检查 API Key。", code);
                ReputationHttp.DiagLog($"OTX query {sha256[..12]} => AUTH FAIL {code}");
                return unknown;
            }
            if (code == 429)
            {
                _logger.LogWarning("OTX 触发限流(429),本次跳过。");
                return unknown;
            }
            if (code != 200)
            {
                ReputationHttp.DiagLog($"OTX query {sha256[..12]} => HTTP {code}");
                return unknown;
            }

            var parsed = Parse(sha256, body);
            ReputationHttp.DiagLog($"OTX query {sha256[..12]} => {parsed.Verdict} pulses={parsed.Malicious}");
            return parsed;
        }
        catch (OperationCanceledException) { return unknown; }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "OTX 查询异常,降级为 Unknown。");
            ReputationHttp.DiagLog($"OTX query {sha256[..12]} => EX {ex.Message}");
            return unknown;
        }
    }

    /// <summary>解析 OTX general 响应,提取 pulse_info.count 与标签。</summary>
    private FileReputation Parse(string sha256, string json)
    {
        var rep = new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            int pulseCount = 0;
            if (root.TryGetProperty("pulse_info", out var pi))
            {
                if (pi.TryGetProperty("count", out var c) && c.TryGetInt32(out var n))
                    pulseCount = n;

                // 从第一个 pulse 抓一个可读标签做威胁名称富化。
                if (pi.TryGetProperty("pulses", out var pulses) &&
                    pulses.ValueKind == JsonValueKind.Array && pulses.GetArrayLength() > 0)
                {
                    var first = pulses[0];
                    if (first.TryGetProperty("name", out var nameEl) &&
                        nameEl.ValueKind == JsonValueKind.String)
                        rep.ThreatLabel = nameEl.GetString();
                }
            }

            // pulse 数映射到展示字段(复用 Malicious/TotalEngines 表示情报命中强度)。
            rep.Malicious = pulseCount;
            rep.TotalEngines = pulseCount;

            if (pulseCount >= _opt.MaliciousPulseThreshold)
                rep.Verdict = ReputationVerdict.Malicious;
            else if (pulseCount >= 1)
                rep.Verdict = ReputationVerdict.Suspicious;
            else
                rep.Verdict = ReputationVerdict.Clean;

            rep.QuerySucceeded = true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "解析 OTX 响应失败。");
        }
        return rep;
    }

    public async Task<(bool Ok, string Message)> TestConnectionAsync(CancellationToken token = default)
    {
        if (string.IsNullOrEmpty(_apiKey))
            return (false, "未配置 OTX API 密钥(环境变量 BULWARK_OTX_APIKEY)");

        const string eicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        try { await _bucket.WaitAsync(token); }
        catch (OperationCanceledException) { return (false, "已取消"); }

        try
        {
            var (code, _) = await ReputationCurl.GetAsync(
                $"{BaseUrl}{eicarSha256}/general", new[] { "X-OTX-API-KEY: " + _apiKey }, _opt.QueryTimeoutSeconds, token);
            return code switch
            {
                200 => (true, "连接成功,API 密钥有效"),
                404 => (true, "连接成功(测试样本无记录,密钥有效)"),
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
