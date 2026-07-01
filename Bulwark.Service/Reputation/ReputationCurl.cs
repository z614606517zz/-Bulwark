using System.Diagnostics;
using System.Text;

namespace Bulwark.Service.Reputation;

/// <summary>
/// 信誉客户端共用的「经系统 curl.exe 发起 HTTPS 请求」助手。
///
/// 背景:本项目在部分 Windows 服务/SYSTEM 上下文下,.NET 的 HttpClient(无论 Schannel
/// 还是托管 TLS)都可能出现 "The SSL connection could not be established"(SChannel/SSPI
/// 「要求的安全包不存在」等)。curl.exe 走系统自带网络栈,稳定可靠 —— 与
/// <see cref="VirusTotalClient"/> / <see cref="ThreatBookClient"/> 的做法一致。
///
/// 约定:返回 (HTTP 状态码, 响应体)。任何失败返回 (0, "")(由各源自行降级 Unknown)。
/// </summary>
internal static class ReputationCurl
{
    /// <summary>GET 请求。headers 形如 "apikey: xxx"、"X-OTX-API-KEY: xxx"。</summary>
    public static Task<(int Code, string Body)> GetAsync(
        string url, IEnumerable<string>? headers, int timeoutSeconds, CancellationToken token)
        => RunAsync(BuildArgs("GET", url, headers, null, timeoutSeconds), token);

    /// <summary>POST(application/x-www-form-urlencoded)。form 为键值对,自动 url-encode。</summary>
    public static Task<(int Code, string Body)> PostFormAsync(
        string url, IReadOnlyList<KeyValuePair<string, string>> form,
        IEnumerable<string>? headers, int timeoutSeconds, CancellationToken token)
        => RunAsync(BuildArgs("POST", url, headers, form, timeoutSeconds), token);

    private static List<string> BuildArgs(
        string method, string url, IEnumerable<string>? headers,
        IReadOnlyList<KeyValuePair<string, string>>? form, int timeoutSeconds)
    {
        var args = new List<string>
        {
            "-sS", "-k", "-L", "--max-redirs", "5",
            "--max-time", Math.Max(5, timeoutSeconds).ToString(),
            "-X", method,
        };
        if (headers is not null)
            foreach (var h in headers)
            {
                args.Add("-H");
                args.Add(h);
            }
        if (form is not null)
            foreach (var kv in form)
            {
                args.Add("--data-urlencode");
                args.Add($"{kv.Key}={kv.Value}");
            }
        args.Add("-w");
        args.Add("\nHTTPSTATUS:%{http_code}");
        args.Add(url);
        return args;
    }

    private static async Task<(int Code, string Body)> RunAsync(
        IReadOnlyList<string> args, CancellationToken token)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "curl.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        try
        {
            using var proc = new Process { StartInfo = psi };
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
}
