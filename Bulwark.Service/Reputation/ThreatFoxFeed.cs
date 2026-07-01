using System.Text;
using System.Text.Json;
using Bulwark.Core.Models;
using Microsoft.Extensions.Logging;

namespace Bulwark.Service.Reputation;

/// <summary>ThreatFox 返回的一条 IOC 记录(仅取生成规则需要的字段)。</summary>
public sealed record ThreatFoxIoc(
    string Ioc,          // IOC 值(如 "1.2.3.4:443"、"evil.com"、sha256)
    string IocType,      // ip:port / domain / url / md5_hash / sha256_hash
    string? Malware,     // 恶意家族可读名
    string? ThreatType,  // 威胁类型(如 botnet_cc、payload)
    int Confidence);     // 置信度 0-100

/// <summary>
/// ThreatFox(abuse.ch)情报 feed 客户端 + 规则生成器。
///
/// 定期批量拉取最近已知恶意 IOC(get_iocs),转换成一批 <see cref="DefenseRule"/>:
///  · sha256_hash → 按哈希 Block(整文件禁跑,改名无效);
///  · ip:port     → NetworkConnect Block(拦截外联到该 IP);
///  · domain      → NetworkConnect Block(可选)。
///
/// 网络经系统 curl.exe 发起(与其它信誉源一致,规避本环境 .NET TLS 握手问题)。
/// 任何失败都返回空列表/不抛断,绝不影响主防护流程。
/// </summary>
public sealed class ThreatFoxFeedClient
{
    private const string ApiUrl = "https://threatfox-api.abuse.ch/api/v1/";

    private readonly ILogger _logger;
    private readonly ThreatFoxFeedOptions _opt;
    private readonly string _authKey;

    public bool IsEnabled => _opt.Enabled && !string.IsNullOrWhiteSpace(_authKey);

    public ThreatFoxFeedClient(ILogger logger, ThreatFoxFeedOptions opt, string? malwareBazaarKey)
    {
        _logger = logger;
        _opt = opt;
        _authKey = opt.ResolveAuthKey(malwareBazaarKey);
    }

    /// <summary>拉取最近 <see cref="ThreatFoxFeedOptions.Days"/> 天、置信度达标的 IOC。失败返回空列表。</summary>
    public async Task<IReadOnlyList<ThreatFoxIoc>> FetchRecentAsync(CancellationToken token = default)
    {
        if (!IsEnabled) return Array.Empty<ThreatFoxIoc>();

        int days = Math.Clamp(_opt.Days, 1, 7);
        string body = JsonSerializer.Serialize(new { query = "get_iocs", days });

        try
        {
            var (code, resp) = await RunCurlAsync(body, token);
            if (code != 200)
            {
                _logger.LogWarning("ThreatFox feed 拉取失败,HTTP {code}。", code);
                return Array.Empty<ThreatFoxIoc>();
            }
            return Parse(resp);
        }
        catch (OperationCanceledException) { return Array.Empty<ThreatFoxIoc>(); }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ThreatFox feed 拉取异常。");
            return Array.Empty<ThreatFoxIoc>();
        }
    }

    private List<ThreatFoxIoc> Parse(string json)
    {
        var list = new List<ThreatFoxIoc>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (!root.TryGetProperty("query_status", out var qs)
                || !string.Equals(qs.GetString(), "ok", StringComparison.OrdinalIgnoreCase))
                return list;
            if (!root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
                return list;

            foreach (var it in data.EnumerateArray())
            {
                string ioc = GetStr(it, "ioc");
                string iocType = GetStr(it, "ioc_type");
                if (string.IsNullOrWhiteSpace(ioc) || string.IsNullOrWhiteSpace(iocType)) continue;

                int conf = it.TryGetProperty("confidence_level", out var c) && c.TryGetInt32(out var n) ? n : 0;
                if (conf < _opt.MinConfidence) continue;

                string? malware = GetStrOrNull(it, "malware_printable") ?? GetStrOrNull(it, "malware");
                string? threat = GetStrOrNull(it, "threat_type");
                list.Add(new ThreatFoxIoc(ioc.Trim(), iocType.Trim().ToLowerInvariant(), malware, threat, conf));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "解析 ThreatFox feed 响应失败。");
        }
        return list;
    }

    private static string GetStr(JsonElement e, string name)
        => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static string? GetStrOrNull(JsonElement e, string name)
        => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>经 curl.exe POST(带 Auth-Key + application/json),返回 (状态码, 响应体)。</summary>
    private async Task<(int Code, string Body)> RunCurlAsync(string jsonBody, CancellationToken token)
    {
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "curl.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("-sS");
        psi.ArgumentList.Add("-k");
        psi.ArgumentList.Add("--max-time");
        psi.ArgumentList.Add(Math.Max(10, _opt.QueryTimeoutSeconds).ToString());
        psi.ArgumentList.Add("-H");
        psi.ArgumentList.Add("Auth-Key: " + _authKey);
        psi.ArgumentList.Add("-H");
        psi.ArgumentList.Add("Content-Type: application/json");
        psi.ArgumentList.Add("--data-raw");
        psi.ArgumentList.Add(jsonBody);
        psi.ArgumentList.Add("-w");
        psi.ArgumentList.Add("\nHTTPSTATUS:%{http_code}");
        psi.ArgumentList.Add(ApiUrl);

        using var proc = new System.Diagnostics.Process { StartInfo = psi };
        if (!proc.Start()) return (0, string.Empty);

        var outTask = proc.StandardOutput.ReadToEndAsync(token);
        var errTask = proc.StandardError.ReadToEndAsync(token);
        await proc.WaitForExitAsync(token);
        var stdout = await outTask;
        _ = await errTask;

        int code = 0;
        string bodyText = stdout;
        const string marker = "\nHTTPSTATUS:";
        int idx = stdout.LastIndexOf(marker, StringComparison.Ordinal);
        if (idx >= 0)
        {
            bodyText = stdout[..idx];
            int.TryParse(stdout[(idx + marker.Length)..].Trim(), out code);
        }
        return (code, bodyText);
    }
}

/// <summary>
/// 把 ThreatFox 拉到的 IOC 批量转换成防护规则(<see cref="DefenseRule"/>)。
/// 纯函数、无副作用;去重、上限、过期时间、来源标记都在此处理。
/// </summary>
public static class IntelRuleGenerator
{
    /// <summary>
    /// 生成规则列表。规则统一带来源标记(便于刷新时先清旧再灌新)与过期时间。
    /// </summary>
    public static List<DefenseRule> Generate(IReadOnlyList<ThreatFoxIoc> iocs, ThreatFoxFeedOptions opt)
    {
        var rules = new List<DefenseRule>();
        if (iocs is null || iocs.Count == 0) return rules;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        DateTime expires = DateTime.UtcNow.AddDays(Math.Max(1, opt.RuleTtlDays));
        int max = Math.Max(1, opt.MaxRules);

        foreach (var ioc in iocs)
        {
            if (rules.Count >= max) break;
            if (!seen.Add(ioc.IocType + "|" + ioc.Ioc)) continue;

            var rule = ioc.IocType switch
            {
                "sha256_hash" when opt.GenerateHashRules => BuildHashRule(ioc, expires),
                "ip:port" when opt.GenerateIpRules       => BuildIpRule(ioc, expires),
                "domain" when opt.GenerateDomainRules    => BuildDomainRule(ioc, expires),
                _ => null,
            };
            if (rule is not null) rules.Add(rule);
        }
        return rules;
    }

    private static string Label(ThreatFoxIoc ioc)
    {
        string fam = !string.IsNullOrWhiteSpace(ioc.Malware) ? ioc.Malware!
                   : !string.IsNullOrWhiteSpace(ioc.ThreatType) ? ioc.ThreatType!
                   : "malicious";
        return $"{ThreatFoxFeedOptions.RuleNoteTag} {fam} ({ioc.Confidence}%)";
    }

    /// <summary>SHA-256 → 按哈希 Block:Type=null 表示该文件的任何行为都拦截,改名无效。</summary>
    private static DefenseRule BuildHashRule(ThreatFoxIoc ioc, DateTime expires) => new()
    {
        ActorHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ioc.Ioc.ToUpperInvariant() },
        Type = null,
        Action = VerdictAction.Block,
        HardOverride = true,
        ExpiresUtc = expires,
        Note = Label(ioc),
    };

    /// <summary>ip:port → NetworkConnect Block:拦截外联到该 IP(任意端口)。</summary>
    private static DefenseRule BuildIpRule(ThreatFoxIoc ioc, DateTime expires)
    {
        string ip = ioc.Ioc;
        int colon = ip.LastIndexOf(':');
        if (colon > 0) ip = ip[..colon];   // 去掉 :port,拦该 IP 的任意端口
        return new DefenseRule
        {
            Type = EventType.NetworkConnect,
            TargetPattern = ip.Trim() + "*",
            Action = VerdictAction.Block,
            ExpiresUtc = expires,
            Note = Label(ioc),
        };
    }

    /// <summary>domain → NetworkConnect Block:目标中包含该域名即拦。</summary>
    private static DefenseRule BuildDomainRule(ThreatFoxIoc ioc, DateTime expires) => new()
    {
        Type = EventType.NetworkConnect,
        TargetPattern = "*" + ioc.Ioc.Trim() + "*",
        Action = VerdictAction.Block,
        ExpiresUtc = expires,
        Note = Label(ioc),
    };
}
