using System.Text;
using System.Text.Json;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Microsoft.Extensions.Logging;

namespace Bulwark.Service.Reputation;

/// <summary>
/// 微步在线 ThreatBook 云 API 哈希信誉客户端。POST https://api.threatbook.cn/v3/file/report
/// 按 SHA-256 查询文件信誉(恶意/可疑/正常),作为第 4 个 <see cref="IHashReputationService"/> 源。
///
/// 设计要点(与 VirusTotal 客户端一致):
///  - 自带限流:令牌桶(每分钟 N)+ 每日计数器,尊重免费档 300/天、30 分钟 100 次配额;
///  - 任何失败(网络/超时/鉴权/未收录/配额)都返回 Unknown,绝不抛断主流程;
///  - 只读哈希、仅后台异步调用、不阻塞裁决同步路径。
///
/// API Key:优先环境变量 BULWARK_THREATBOOK_APIKEY,其次配置 ApiKey。
/// 微步返回字段无完整公开 schema,故解析采用防御式(递归找 threat_level/judgments/is_whitelist),
/// 并把原始响应落盘 tb_diag.log 便于按真实返回校准映射。
/// </summary>
public sealed class ThreatBookClient : IHashReputationService
{
    private const string ReportUrl = "https://api.threatbook.cn/v3/file/report";
    private const string IpReputationUrl = "https://api.threatbook.cn/v3/scene/ip_reputation";

    private readonly ILogger<ThreatBookClient> _logger;
    private readonly ThreatBookOptions _opt;
    private readonly string? _apiKey;
    private readonly TokenBucket _bucket;
    private readonly DailyQuota _daily;

    // ===== 场景 API(IP 信誉 / 失陷检测)月度配额守护 =====
    // 免费档场景接口配额极低(常见「每月 20 次」),必须与文件信誉(300/天)分开计数,
    // 否则一次性打爆。这里用一个进程内月度计数器兜底,叠加上层「仅可疑外联才查 + 缓存」。
    private readonly object _sceneLock = new();
    private int _sceneMonth = -1;
    private int _sceneUsed;

    /// <summary>本月场景接口(IP 信誉)是否还有额度。到月自动归零。</summary>
    private bool TrySceneQuota()
    {
        lock (_sceneLock)
        {
            int m = DateTime.UtcNow.Year * 100 + DateTime.UtcNow.Month;
            if (m != _sceneMonth) { _sceneMonth = m; _sceneUsed = 0; }
            if (_sceneUsed >= Math.Max(1, _opt.SceneRequestsPerMonth)) return false;
            _sceneUsed++;
            return true;
        }
    }

    public bool IsEnabled { get; }

    public ReputationUsage GetUsage()
    {
        var (used, limit) = _daily.Snapshot();
        return new ReputationUsage
        {
            Source = "ThreatBook", Enabled = IsEnabled,
            UsedToday = used, DailyLimit = limit, PerMinuteLimit = _opt.RequestsPerMinute
        };
    }

    public ThreatBookClient(ILogger<ThreatBookClient> logger, BulwarkOptions options)
    {
        _logger = logger;
        _opt = options.ThreatBook;

        var envKey = Environment.GetEnvironmentVariable(ThreatBookOptions.ApiKeyEnvVar);
        _apiKey = !string.IsNullOrWhiteSpace(envKey) ? envKey.Trim()
                : !string.IsNullOrWhiteSpace(_opt.ApiKey) ? _opt.ApiKey!.Trim()
                : null;

        IsEnabled = !string.IsNullOrEmpty(_apiKey);

        _bucket = new TokenBucket(Math.Max(1, _opt.RequestsPerMinute), TimeSpan.FromMinutes(1));
        _daily = new DailyQuota(Math.Max(1, _opt.RequestsPerDay));

        if (_apiKey is null)
            _logger.LogInformation("ThreatBook 未提供 API Key(环境变量 {env} 或配置 ApiKey),信誉查询不可用。",
                ThreatBookOptions.ApiKeyEnvVar);
        else
            _logger.LogInformation("ThreatBook 信誉查询能力就绪(限流 {rpm}/min, {rpd}/day);是否实际启用由运行时设置控制。",
                _opt.RequestsPerMinute, _opt.RequestsPerDay);
    }

    /// <summary>
    /// 查询某公网 IP 的信誉(微步场景 API v3/scene/ip_reputation)。
    /// 供网络防护对「已可疑的外联」做情报互证使用 —— 严禁对每个外联都调用(月配额极低)。
    /// 任何失败/超配额都返回 QuerySucceeded=false 的 Unknown,绝不抛断实时防护(fail-open)。
    /// </summary>
    public async Task<IpReputation> QueryIpAsync(string ip, CancellationToken token = default)
    {
        var unknown = new IpReputation { Resource = ip, Verdict = ReputationVerdict.Unknown };
        if (!IsEnabled || string.IsNullOrWhiteSpace(ip)) return unknown;

        if (!TrySceneQuota())
        {
            _logger.LogDebug("ThreatBook 场景接口月配额已用尽,跳过 IP 查询 {ip}。", ip);
            return unknown;
        }

        try { await _bucket.WaitAsync(token); }
        catch (OperationCanceledException) { return unknown; }

        try
        {
            var (code, body) = await RunCurlPostAsync(IpReputationUrl, new[]
            {
                new KeyValuePair<string, string>("apikey", _apiKey!),
                new KeyValuePair<string, string>("resource", ip),
            }, token);

            if (code != 200)
            {
                DiagLog($"ip {ip} => HTTP {code}");
                return unknown;
            }

            var parsed = ParseIp(ip, body);
            DiagLog($"ip {ip} => {parsed.Verdict} ({parsed.ThreatLabel}) raw={Clip(body)}");
            return parsed;
        }
        catch (OperationCanceledException) { return unknown; }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ThreatBook IP 查询异常,降级为 Unknown。");
            DiagLog($"ip {ip} => EX {ex.Message}");
            return unknown;
        }
    }

    /// <summary>
    /// 防御式解析微步 IP 信誉返回:response_code==0 视为成功;
    /// 递归找 judgments / severity / confidence_level / is_malicious 映射结论。
    /// </summary>
    private IpReputation ParseIp(string ip, string body)
    {
        var rep = new IpReputation { Resource = ip, Verdict = ReputationVerdict.Unknown };
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            int code = root.TryGetProperty("response_code", out var rc) && rc.TryGetInt32(out var c) ? c : -1;
            if (code != 0)
            {
                rep.QuerySucceeded = false;
                return rep;
            }
            rep.QuerySucceeded = true;

            JsonElement data = root.TryGetProperty("data", out var d) ? d : root;

            // 明确恶意标记优先。
            bool? isMalicious = FindBool(data, "is_malicious");
            string? judgments = FindFirstString(data, "judgments");
            string? severity = FindFirstString(data, "severity");
            string? confidence = FindFirstString(data, "confidence_level");

            var verdict = MapVerdict(severity) ?? MapJudgments(judgments);
            if (isMalicious == true && verdict is null or ReputationVerdict.Clean)
                verdict = ReputationVerdict.Malicious;

            // 低置信度的恶意判定降级为可疑(降误报,交由双证据互证)。
            if (verdict == ReputationVerdict.Malicious
                && !string.IsNullOrWhiteSpace(confidence)
                && confidence.Trim().ToLowerInvariant() is "low")
                verdict = ReputationVerdict.Suspicious;

            rep.Verdict = verdict ?? ReputationVerdict.Clean; // 收录但无威胁信号 -> 视为干净
            rep.ThreatLabel = !string.IsNullOrWhiteSpace(judgments) ? judgments
                            : !string.IsNullOrWhiteSpace(severity) ? "ThreatBook:" + severity
                            : null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "解析 ThreatBook IP 响应失败。");
        }
        return rep;
    }

    public async Task<FileReputation> QueryAsync(string sha256, CancellationToken token = default)
    {
        var unknown = new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };
        if (!IsEnabled || string.IsNullOrEmpty(sha256)) return unknown;

        if (!_daily.TryConsume())
        {
            _logger.LogDebug("ThreatBook 日配额已用尽,跳过查询 {hash}。", sha256);
            return unknown;
        }

        try { await _bucket.WaitAsync(token); }
        catch (OperationCanceledException) { return unknown; }

        try
        {
            var (code, body) = await RunCurlPostAsync(ReportUrl, new[]
            {
                new KeyValuePair<string, string>("apikey", _apiKey!),
                new KeyValuePair<string, string>("sha256", sha256),
            }, token);

            if (code != 200)
            {
                DiagLog($"query {sha256[..12]} => HTTP {code}");
                return unknown;
            }

            var parsed = Parse(sha256, body);
            DiagLog($"query {sha256[..12]} => {parsed.Verdict} ({parsed.ThreatLabel}) raw={Clip(body)}");
            return parsed;
        }
        catch (OperationCanceledException) { return unknown; }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ThreatBook 查询异常,降级为 Unknown。");
            DiagLog($"query {sha256[..12]} => EX {ex.Message}");
            return unknown;
        }
    }

    /// <summary>
    /// 防御式解析微步返回:response_code==0 视为查询成功;递归在 data 内找
    /// threat_level / judgments / is_whitelist / malware_family 映射结论。
    /// </summary>
    private FileReputation Parse(string sha256, string body)
    {
        var rep = new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            int code = root.TryGetProperty("response_code", out var rc) && rc.TryGetInt32(out var c) ? c : 0;
            // response_code != 0:鉴权/参数/未收录等。不缓存(下次可重试),除非确实是"未收录"语义。
            if (code != 0)
            {
                rep.QuerySucceeded = false;
                return rep;
            }

            // 查询成功(权威结果,可缓存,含"收录但未判恶意"的负结果)。
            rep.QuerySucceeded = true;

            JsonElement data = root.TryGetProperty("data", out var d) ? d : root;

            // 白名单 -> 干净。
            if (FindBool(data, "is_whitelist") == true)
            {
                rep.Verdict = ReputationVerdict.Clean;
                rep.ThreatLabel = "ThreatBook 白名单";
                return rep;
            }

            // 威胁等级:threat_level / judgments / severity。
            string? level = FindFirstString(data, "threat_level");
            string? judgments = FindFirstString(data, "judgments");
            string? severity = FindFirstString(data, "severity");
            string? family = FindFirstString(data, "malware_family") ?? FindFirstString(data, "malware_type");

            var verdict = MapVerdict(level) ?? MapVerdict(severity) ?? MapJudgments(judgments);

            rep.Verdict = verdict ?? ReputationVerdict.Clean; // 收录但无威胁信号 -> 视为干净
            rep.ThreatLabel = !string.IsNullOrWhiteSpace(family) ? family
                            : !string.IsNullOrWhiteSpace(judgments) ? judgments
                            : !string.IsNullOrWhiteSpace(level) ? "ThreatBook:" + level
                            : null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "解析 ThreatBook 响应失败。");
        }
        return rep;
    }

    private static ReputationVerdict? MapVerdict(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var v = s.Trim().ToLowerInvariant();
        if (v is "malicious" or "high" or "critical" or "severe" || v.Contains("恶意") || v.Contains("高危"))
            return ReputationVerdict.Malicious;
        if (v is "suspicious" or "mid" or "medium" or "moderate" || v.Contains("可疑") || v.Contains("中危"))
            return ReputationVerdict.Suspicious;
        if (v is "clean" or "safe" or "white" or "info" or "low" || v.Contains("正常") || v.Contains("无威胁") || v.Contains("低危"))
            return ReputationVerdict.Clean;
        return null;
    }

    /// <summary>judgments(标签数组里出现 C2/Trojan/Ransom 等)视为恶意。</summary>
    private static ReputationVerdict? MapJudgments(string? j)
    {
        if (string.IsNullOrWhiteSpace(j)) return null;
        var v = j.ToLowerInvariant();
        string[] bad = { "c2", "trojan", "ransom", "backdoor", "miner", "worm", "botnet", "malware", "apt", "exploit", "spyware", "rat" };
        return Array.Exists(bad, k => v.Contains(k)) ? ReputationVerdict.Malicious : null;
    }

    // ===== 递归查找辅助(微步字段层级不固定,防御式提取) =====

    private static string? FindFirstString(JsonElement el, string name)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in el.EnumerateObject())
                {
                    if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
                    {
                        if (p.Value.ValueKind == JsonValueKind.String) return p.Value.GetString();
                        if (p.Value.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var it in p.Value.EnumerateArray())
                                if (it.ValueKind == JsonValueKind.String) return it.GetString();
                        }
                    }
                    var r = FindFirstString(p.Value, name);
                    if (r is not null) return r;
                }
                break;
            case JsonValueKind.Array:
                foreach (var it in el.EnumerateArray())
                {
                    var r = FindFirstString(it, name);
                    if (r is not null) return r;
                }
                break;
        }
        return null;
    }

    private static bool? FindBool(JsonElement el, string name)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in el.EnumerateObject())
                {
                    if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)
                        && (p.Value.ValueKind == JsonValueKind.True || p.Value.ValueKind == JsonValueKind.False))
                        return p.Value.GetBoolean();
                    var r = FindBool(p.Value, name);
                    if (r is not null) return r;
                }
                break;
            case JsonValueKind.Array:
                foreach (var it in el.EnumerateArray())
                {
                    var r = FindBool(it, name);
                    if (r is not null) return r;
                }
                break;
        }
        return null;
    }

    public async Task<(bool Ok, string Message)> TestConnectionAsync(CancellationToken token = default)
    {
        if (string.IsNullOrEmpty(_apiKey))
            return (false, "服务端未配置 ThreatBook API 密钥(环境变量 BULWARK_THREATBOOK_APIKEY)");

        // 用 EICAR 测试样本哈希探测鉴权与连通。
        const string eicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        try { await _bucket.WaitAsync(token); }
        catch (OperationCanceledException) { return (false, "已取消"); }

        try
        {
            var (code, body) = await RunCurlPostAsync(ReportUrl, new[]
            {
                new KeyValuePair<string, string>("apikey", _apiKey!),
                new KeyValuePair<string, string>("sha256", eicarSha256),
            }, token);
            if (code != 200)
                return (false, $"返回异常状态:{code}");

            using var doc = JsonDocument.Parse(body);
            int rcode = doc.RootElement.TryGetProperty("response_code", out var rc) && rc.TryGetInt32(out var c) ? c : -999;
            string? msg = doc.RootElement.TryGetProperty("verbose_msg", out var vm) ? vm.GetString() : null;

            // response_code==0 表示 Key 有效(即便样本未收录);非 0 多为鉴权/配额问题。
            return rcode == 0
                ? (true, "连接成功,API 密钥有效")
                : (false, $"密钥或配额异常(response_code={rcode}{(string.IsNullOrEmpty(msg) ? "" : ", " + msg)})");
        }
        catch (OperationCanceledException) { return (false, "请求超时或已取消"); }
        catch (Exception ex) { return (false, "连接失败:" + ex.Message); }
    }

    private static string Clip(string s) => s.Length > 400 ? s[..400] + "…" : s;

    /// <summary>
    /// 经系统 curl.exe 发起一次 POST(application/x-www-form-urlencoded),返回 (HTTP 状态码, 响应体)。
    /// 与 VirusTotalClient 一致:规避本环境下 .NET HttpClient 的 TLS 握手失败
    /// (SChannel/SSPI「要求的安全包不存在」),curl 走系统网络栈稳定可靠。失败返回 (0, "")。
    /// </summary>
    private async Task<(int Code, string Body)> RunCurlPostAsync(
        string url, IReadOnlyList<KeyValuePair<string, string>> form, CancellationToken token)
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
        psi.ArgumentList.Add(Math.Max(5, _opt.QueryTimeoutSeconds).ToString());
        foreach (var kv in form)
        {
            psi.ArgumentList.Add("--data-urlencode");
            psi.ArgumentList.Add($"{kv.Key}={kv.Value}");
        }
        psi.ArgumentList.Add("-w");
        psi.ArgumentList.Add("\nHTTPSTATUS:%{http_code}");
        psi.ArgumentList.Add(url);

        try
        {
            using var proc = new System.Diagnostics.Process { StartInfo = psi };
            if (!proc.Start()) return (0, string.Empty);

            var outTask = proc.StandardOutput.ReadToEndAsync(token);
            var errTask = proc.StandardError.ReadToEndAsync(token);
            await proc.WaitForExitAsync(token);
            var stdout = await outTask;
            _ = await errTask;

            int code = 0;
            string body = stdout;
            const string marker = "\nHTTPSTATUS:";
            int idx = stdout.LastIndexOf(marker, StringComparison.Ordinal);
            if (idx >= 0)
            {
                body = stdout[..idx];
                int.TryParse(stdout[(idx + marker.Length)..].Trim(), out code);
            }
            return (code, body);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { return (0, string.Empty); }
    }

    /// <summary>把原始响应落盘 %ProgramData%\Bulwark\tb_diag.log,便于按真实字段校准映射。</summary>
    private static void DiagLog(string line)
    {
        try
        {
            var dir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bulwark");
            System.IO.Directory.CreateDirectory(dir);
            System.IO.File.AppendAllText(System.IO.Path.Combine(dir, "tb_diag.log"),
                $"{DateTime.Now:HH:mm:ss} {line}{Environment.NewLine}");
        }
        catch { }
    }
}
