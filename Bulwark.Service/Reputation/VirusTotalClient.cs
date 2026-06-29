using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Microsoft.Extensions.Logging;

namespace Bulwark.Service.Reputation;

/// <summary>
/// VirusTotal v3 哈希信誉 / 文件上传扫描客户端。
///
/// 网络一律经系统 <c>curl.exe</c> 子进程发起(与 <see cref="Bulwark.UI"/> 侧 AiClient/MimoUsageClient
/// 一致),规避部分环境下 .NET 进程 SChannel/SSPI「要求的安全包不存在(SEC_E_SECPKG_NOT_FOUND)」
/// 导致 HttpClient TLS 握手始终失败的问题。curl 走系统自带网络栈,稳定可靠。
///
/// 设计要点:
///  - 自带限流(令牌桶 N/min + 每日计数);
///  - 任何失败(网络/超时/404 未收录/401 鉴权/429 限流)都返回 Unknown,绝不抛断主流程;
///  - 查询只读哈希;上传扫描会上传文件完整内容(仅用于双击/释放载荷这类高价值新样本)。
///
/// API Key 优先级:环境变量 BULWARK_VT_APIKEY > 配置文件 ApiKey > 内置默认 Key(开箱即用)。
/// </summary>
public sealed class VirusTotalClient : IHashReputationService
{
    private const string BaseUrl = "https://www.virustotal.com/api/v3/files/";
    private const string UploadUrl = "https://www.virustotal.com/api/v3/files";
    private const string BigUploadUrlEndpoint = "https://www.virustotal.com/api/v3/files/upload_url";
    private const string AnalysesUrl = "https://www.virustotal.com/api/v3/analyses/";

    /// <summary>直传上限:>32MB 需先取专用上传 URL。</summary>
    private const long DirectUploadMaxBytes = 32L * 1024 * 1024;

    /// <summary>上传扫描可处理的最大文件大小(保守取 200MB)。</summary>
    private const long MaxUploadBytes = 200L * 1024 * 1024;

    /// <summary>
    /// 内置默认 API Key —— 开箱即用,无需用户配置。免费层配额很低(4/min、500/day),
    /// 多用户共用易触发 429;高频使用建议在设置页填入自己的 Key。
    /// </summary>
    private const string BuiltInDefaultApiKey = "f760f5be4fe2cd00b73fe989e51e450321263f879dae9d404a8a035c3e3d0778";

    /// <summary>内置默认 API Key(供 UI 设置页展示/回退)。</summary>
    public static string BuiltInApiKey => BuiltInDefaultApiKey;

    private readonly ILogger<VirusTotalClient> _logger;
    private readonly VirusTotalOptions _opt;
    private readonly string? _apiKey;
    private readonly TokenBucket _bucket;
    private readonly DailyQuota _daily;

    public bool IsEnabled { get; }

    public VirusTotalClient(ILogger<VirusTotalClient> logger, BulwarkOptions options)
    {
        _logger = logger;
        _opt = options.VirusTotal;

        var envKey = Environment.GetEnvironmentVariable(VirusTotalOptions.ApiKeyEnvVar);
        _apiKey = !string.IsNullOrWhiteSpace(envKey) ? envKey.Trim()
                : !string.IsNullOrWhiteSpace(_opt.ApiKey) ? _opt.ApiKey!.Trim()
                : BuiltInDefaultApiKey;

        IsEnabled = !string.IsNullOrEmpty(_apiKey);

        _bucket = new TokenBucket(Math.Max(1, _opt.RequestsPerMinute), TimeSpan.FromMinutes(1));
        _daily = new DailyQuota(Math.Max(1, _opt.RequestsPerDay));

        bool builtIn = string.Equals(_apiKey, BuiltInDefaultApiKey, StringComparison.Ordinal);
        _logger.LogInformation("VirusTotal 信誉查询能力就绪(经 curl,限流 {rpm}/min, {rpd}/day,{key});是否启用由运行时设置控制。",
            _opt.RequestsPerMinute, _opt.RequestsPerDay, builtIn ? "内置默认 Key" : "用户配置 Key");
    }

    /// <summary>经 curl.exe 发起一次请求,返回 (HTTP 状态码, 响应体)。失败抛异常由上层降级。</summary>
    private async Task<(int Code, string Body)> RunCurlAsync(IReadOnlyList<string> args, CancellationToken token)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "curl.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var proc = new Process { StartInfo = psi };
        if (!proc.Start()) throw new InvalidOperationException("无法启动 curl.exe");

        var outTask = proc.StandardOutput.ReadToEndAsync(token);
        var errTask = proc.StandardError.ReadToEndAsync(token);
        await proc.WaitForExitAsync(token);
        var stdout = await outTask;
        var stderr = await errTask;

        if (proc.ExitCode != 0)
            throw new InvalidOperationException($"curl 退出码 {proc.ExitCode}: {stderr.Trim()}");

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

    /// <summary>组装一次 GET 的 curl 参数(带 x-apikey 与状态码回写)。</summary>
    private List<string> BuildGetArgs(string url, int timeoutSeconds) => new()
    {
        "-sS", "-k",
        "--max-time", Math.Max(5, timeoutSeconds).ToString(),
        "-H", "x-apikey: " + _apiKey,
        "-w", "\nHTTPSTATUS:%{http_code}",
        url
    };

    /// <summary>把一行诊断追加到 %ProgramData%\Bulwark\vt_diag.log。</summary>
    private static void DiagLog(string line)
    {
        try
        {
            var dir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bulwark");
            System.IO.Directory.CreateDirectory(dir);
            System.IO.File.AppendAllText(System.IO.Path.Combine(dir, "vt_diag.log"),
                $"{DateTime.Now:HH:mm:ss} {line}{Environment.NewLine}");
        }
        catch { }
    }

    public async Task<FileReputation> QueryAsync(string sha256, CancellationToken token = default)
    {
        var unknown = new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };
        if (!IsEnabled || string.IsNullOrEmpty(sha256)) return unknown;

        if (!_daily.TryConsume())
        {
            _logger.LogDebug("VirusTotal 日配额已用尽,跳过查询 {hash}。", sha256);
            return unknown;
        }

        try { await _bucket.WaitAsync(token); }
        catch (OperationCanceledException) { return unknown; }

        try
        {
            var (code, body) = await RunCurlAsync(BuildGetArgs(BaseUrl + sha256, _opt.QueryTimeoutSeconds), token);

            if (code == 404)
            {
                // 未收录:正常情况,也是「查询成功」的权威负结果(可缓存,避免反复查)。
                DiagLog($"query {sha256[..12]} => 404 NotFound");
                return new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown, QuerySucceeded = true };
            }
            if (code == 401 || code == 403)
            {
                _logger.LogWarning("VirusTotal 鉴权失败({code}),请检查 API Key。", code);
                DiagLog($"query {sha256[..12]} => AUTH FAIL {code}");
                return unknown;
            }
            if (code == 429)
            {
                _logger.LogWarning("VirusTotal 触发限流(429),本次跳过。");
                DiagLog($"query {sha256[..12]} => 429 RateLimit");
                return unknown;
            }
            if (code != 200)
            {
                DiagLog($"query {sha256[..12]} => HTTP {code}");
                return unknown;
            }

            var parsed = Parse(sha256, body);
            DiagLog($"query {sha256[..12]} => OK {parsed.Verdict} {parsed.Malicious}/{parsed.TotalEngines}");
            return parsed;
        }
        catch (OperationCanceledException) { DiagLog($"query {sha256[..12]} => canceled/timeout"); return unknown; }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "VirusTotal 查询异常,降级为 Unknown。");
            DiagLog($"query {sha256[..12]} => EX {ex.Message}");
            return unknown;
        }
    }

    /// <summary>解析 VT v3 文件报告 JSON,提取 last_analysis_stats 等关键字段。</summary>
    private FileReputation Parse(string sha256, string json)
    {
        var rep = new FileReputation { Sha256 = sha256, Verdict = ReputationVerdict.Unknown };
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("data", out var data) ||
                !data.TryGetProperty("attributes", out var attr))
                return rep;

            int malicious = 0, suspicious = 0, total = 0;
            if (attr.TryGetProperty("last_analysis_stats", out var stats))
            {
                malicious = GetInt(stats, "malicious");
                suspicious = GetInt(stats, "suspicious");
                total = malicious + suspicious
                      + GetInt(stats, "undetected") + GetInt(stats, "harmless")
                      + GetInt(stats, "timeout") + GetInt(stats, "failure")
                      + GetInt(stats, "type-unsupported");
            }

            rep.Malicious = malicious;
            rep.TotalEngines = total;

            if (attr.TryGetProperty("suggested_threat_label", out var label) &&
                label.ValueKind == JsonValueKind.String)
                rep.ThreatLabel = label.GetString();
            else if (attr.TryGetProperty("popular_threat_classification", out var ptc) &&
                     ptc.TryGetProperty("suggested_threat_label", out var label2) &&
                     label2.ValueKind == JsonValueKind.String)
                rep.ThreatLabel = label2.GetString();

            if (attr.TryGetProperty("last_analysis_date", out var lad) &&
                lad.TryGetInt64(out var epoch))
                rep.LastAnalysisUtc = DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime;

            if (malicious >= _opt.MaliciousThreshold)
                rep.Verdict = ReputationVerdict.Malicious;
            else if (malicious + suspicious >= 1)
                rep.Verdict = ReputationVerdict.Suspicious;
            else
                rep.Verdict = ReputationVerdict.Clean;

            rep.QuerySucceeded = true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "解析 VirusTotal 响应失败。");
        }
        return rep;
    }

    private static int GetInt(JsonElement obj, string name)
        => obj.TryGetProperty(name, out var v) && v.TryGetInt32(out var n) ? n : 0;

    /// <summary>
    /// 上传文件到 VirusTotal 多引擎扫描,轮询至完成后按 SHA-256 拉取完整报告。
    /// 经 curl 上传(-F file=@path);任何失败都返回 QuerySucceeded=false 的 Unknown,绝不抛断。
    /// </summary>
    public async Task<FileReputation> UploadAndScanAsync(
        string filePath, string? sha256,
        IProgress<(VtScanStage stage, int percent)>? progress,
        CancellationToken token = default)
    {
        var unknown = new FileReputation { Sha256 = sha256 ?? string.Empty, Verdict = ReputationVerdict.Unknown };
        if (!IsEnabled) return unknown;

        System.IO.FileInfo fi;
        try { fi = new System.IO.FileInfo(filePath); }
        catch { return unknown; }
        if (!fi.Exists) { DiagLog($"upload skip: file not found {filePath}"); return unknown; }
        if (fi.Length > MaxUploadBytes) { DiagLog($"upload skip: file too large {fi.Length} bytes"); return unknown; }

        if (!_daily.TryConsume()) { DiagLog("upload skip: daily quota exhausted"); return unknown; }

        try
        {
            await _bucket.WaitAsync(token);
            progress?.Report((VtScanStage.Uploading, 0));

            // 大文件:先取一次性上传 URL。
            string target = UploadUrl;
            if (fi.Length > DirectUploadMaxBytes)
            {
                var (uc, ub) = await RunCurlAsync(BuildGetArgs(BigUploadUrlEndpoint, _opt.QueryTimeoutSeconds), token);
                if (uc == 200)
                {
                    try
                    {
                        using var ud = JsonDocument.Parse(ub);
                        if (ud.RootElement.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.String)
                            target = d.GetString() ?? UploadUrl;
                    }
                    catch { }
                }
            }

            // 上传(curl -F),给较长超时(含上传 + 服务端入队)。
            var upArgs = new List<string>
            {
                "-sS", "-k",
                "--max-time", "300",
                "-H", "x-apikey: " + _apiKey,
                "-F", $"file=@{fi.FullName};type=application/octet-stream",
                "-w", "\nHTTPSTATUS:%{http_code}",
                target
            };
            var (code, body) = await RunCurlAsync(upArgs, token);
            if (code != 200)
            {
                DiagLog($"upload {fi.Name} => HTTP {code}");
                return unknown;
            }

            string analysisId = string.Empty;
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("data", out var data)
                    && data.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String)
                    analysisId = id.GetString() ?? string.Empty;
            }
            catch { }

            if (string.IsNullOrEmpty(analysisId))
            {
                DiagLog($"upload {fi.Name}: no analysis id");
                return unknown;
            }
            DiagLog($"upload {fi.Name} => analysis {analysisId}");

            // 轮询分析结果(最长约 4 分钟)。
            progress?.Report((VtScanStage.Analyzing, 100));
            string? resolvedSha = sha256;
            var deadline = DateTime.UtcNow + TimeSpan.FromMinutes(4);
            while (DateTime.UtcNow < deadline)
            {
                await Task.Delay(TimeSpan.FromSeconds(15), token);
                await _bucket.WaitAsync(token);

                var (pc, pb) = await RunCurlAsync(BuildGetArgs(AnalysesUrl + analysisId, _opt.QueryTimeoutSeconds), token);
                if (pc != 200) { DiagLog($"poll {analysisId} => HTTP {pc}"); continue; }

                try
                {
                    using var doc = JsonDocument.Parse(pb);
                    var root = doc.RootElement;
                    if (root.TryGetProperty("meta", out var meta)
                        && meta.TryGetProperty("file_info", out var finfo)
                        && finfo.TryGetProperty("sha256", out var sh)
                        && sh.ValueKind == JsonValueKind.String)
                        resolvedSha = sh.GetString();

                    string status = root.TryGetProperty("data", out var data)
                                    && data.TryGetProperty("attributes", out var attr)
                                    && attr.TryGetProperty("status", out var st)
                                    && st.ValueKind == JsonValueKind.String
                        ? st.GetString() ?? "" : "";

                    if (string.Equals(status, "completed", StringComparison.OrdinalIgnoreCase))
                    {
                        DiagLog($"poll {analysisId} => completed");
                        break;
                    }
                }
                catch { /* 单次轮询解析失败,继续 */ }
            }

            if (!string.IsNullOrEmpty(resolvedSha))
            {
                var rep = await QueryAsync(resolvedSha!, token);
                rep.Sha256 = resolvedSha!;
                progress?.Report((VtScanStage.Completed, 100));
                return rep;
            }
            return unknown;
        }
        catch (OperationCanceledException) { DiagLog($"upload {filePath} => canceled/timeout"); return unknown; }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "VirusTotal 上传扫描异常,降级为 Unknown。");
            DiagLog($"upload {filePath} => EX {ex.Message}");
            return unknown;
        }
    }

    /// <summary>测试连接 / API Key 有效性(用 EICAR 哈希探测,经 curl)。</summary>
    public async Task<(bool Ok, string Message)> TestConnectionAsync(CancellationToken token = default)
    {
        if (string.IsNullOrEmpty(_apiKey))
            return (false, "未配置 API 密钥");

        const string eicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

        try { await _bucket.WaitAsync(token); }
        catch (OperationCanceledException) { return (false, "已取消"); }

        try
        {
            var (code, _) = await RunCurlAsync(BuildGetArgs(BaseUrl + eicarSha256, _opt.QueryTimeoutSeconds), token);
            return code switch
            {
                200 => (true, "连接成功,API 密钥有效"),
                401 => (false, "API 密钥无效(401)"),
                403 => (false, "API 密钥无权限(403)"),
                429 => (true, "密钥有效,但当前已触发限流(429)"),
                404 => (true, "连接成功(测试样本未收录,密钥有效)"),
                _ => (false, $"返回异常状态:{code}")
            };
        }
        catch (OperationCanceledException) { return (false, "请求超时或已取消"); }
        catch (Exception ex) { return (false, "连接失败:" + ex.Message); }
    }
}
