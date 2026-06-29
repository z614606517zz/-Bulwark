using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Bulwark.UI.Services;

/// <summary>
/// 小米 MiMo 平台「官方用量」查询客户端(可选·纯展示)。
///
/// 调用控制台用量接口 GET https://platform.xiaomimimo.com/api/v1/tokenPlan/usage,
/// 返回本月已用 / 总额度 Credits(即控制台「当前套餐用量 X / Y」那条数据)。
///
/// 注意:该接口由【网页登录态 Cookie】鉴权(api-platform_serviceToken 等),
/// 不是 tp- 开头的模型 API Key —— 故需用户从控制台粘贴 Cookie。Cookie 会过期,
/// 过期后查询失败,调用方应自动降级回本地估算。
///
/// 这是控制台内部接口(非文档公开 API),仅用于展示用户自己账号的用量,绝不影响防护。
/// 用系统 curl.exe 发起(与 AiClient 一致,规避部分环境 .NET SChannel 问题)。
/// </summary>
public sealed class MimoUsageClient
{
    private const string UsageUrl = "https://platform.xiaomimimo.com/api/v1/tokenPlan/usage";

    /// <summary>官方用量查询结果。</summary>
    public readonly struct Result
    {
        public bool Ok { get; init; }
        public long Used { get; init; }
        public long Total { get; init; }
        public string Message { get; init; }
        /// <summary>原始响应(解析失败时供排查/映射字段)。</summary>
        public string Raw { get; init; }
    }

    /// <summary>用粘贴的控制台 Cookie 查询官方用量。失败(网络/过期/解析)返回 Ok=false。</summary>
    public async Task<Result> FetchAsync(string? cookie, CancellationToken token = default)
    {
        // 容错:用户可能直接粘贴整段 cURL(右键请求 → Copy as cURL)或带 "Cookie:" 前缀的请求头行,
        // 统一规整为纯 Cookie 串。
        cookie = NormalizeCookieInput(cookie);

        if (string.IsNullOrWhiteSpace(cookie))
            return new Result { Ok = false, Message = "未配置 Cookie" };

        string? raw;
        try
        {
            raw = await GetViaCurlAsync(cookie!.Trim(), token);
        }
        catch (Exception ex)
        {
            return new Result { Ok = false, Message = "请求失败:" + ex.Message };
        }

        if (string.IsNullOrWhiteSpace(raw))
            return new Result { Ok = false, Message = "无响应(Cookie 可能已过期,请重新粘贴)" };

        // 鉴权失败常返回登录页 HTML 或 401 JSON。
        var head = raw.TrimStart();
        if (head.StartsWith("<"))
            return new Result { Ok = false, Message = "返回非 JSON(Cookie 已过期或无效,请重新登录控制台复制)", Raw = Trim(raw) };

        try
        {
            using var doc = JsonDocument.Parse(raw);
            var (used, total, found) = ExtractUsage(doc.RootElement);
            if (found && total > 0)
                return new Result { Ok = true, Used = used, Total = total, Message = "官方用量", Raw = Trim(raw) };

            return new Result { Ok = false, Message = "已连通但未能解析用量字段(请把原始响应发我以精确映射)", Raw = Trim(raw) };
        }
        catch
        {
            return new Result { Ok = false, Message = "响应解析失败(Cookie 可能过期)", Raw = Trim(raw) };
        }
    }

    /// <summary>
    /// 把用户粘贴的内容规整为纯 Cookie 串。支持:
    ///  1) 纯 Cookie 串;2) "Cookie:" 请求头行;3) 整段 cURL(bash '…' 或 cmd ^"…")。
    /// 关键:Cookie 值本身可能带引号(name="value"),不能在第一个引号处截断;
    /// 故先还原 cmd 的 ^ 转义,再按 -H 参数的外层引号、识别 \" 转义来正确截取。
    /// </summary>
    public static string NormalizeCookieInput(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        var s = raw.Trim();

        // 1) 还原 cmd「Copy as cURL (cmd)」的 ^ 转义:^" -> " , ^\ -> \ , ^^ -> ^ , 行尾 ^ 续行去除。
        if (s.Contains("^\"") || s.Contains("^^") || s.Contains("^\\"))
            s = DecodeCmdCarets(s);

        // 2) 定位 "cookie:"(在 -H 参数里或裸请求头行里)。
        int idx = s.IndexOf("cookie:", StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
        {
            // 尝试 -b / --cookie。
            foreach (var flag in new[] { "--cookie ", "-b " })
            {
                int f = s.IndexOf(flag, StringComparison.Ordinal);
                if (f >= 0)
                {
                    var v = s[(f + flag.Length)..].TrimStart();
                    return ExtractQuotedOrLine(v);
                }
            }
            return s; // 认为本身就是 Cookie 串
        }

        // 3) 判断 -H 参数的外层引号:从 "cookie:" 往前找最近的非空白字符。
        char wrap = '\0';
        for (int i = idx - 1; i >= 0; i--)
        {
            char c = s[i];
            if (c == ' ') continue;
            if (c is '"' or '\'') wrap = c;
            break;
        }

        string rest = s[(idx + "cookie:".Length)..].TrimStart();
        if (wrap == '\0') return CutToLineEnd(rest);           // 裸请求头行
        return ExtractUntilUnescaped(rest, wrap);              // -H 包裹的参数
    }

    /// <summary>还原 cmd cURL 的脱字符转义。</summary>
    private static string DecodeCmdCarets(string s)
    {
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '^' && i + 1 < s.Length)
            {
                char next = s[i + 1];
                if (next is '\r' or '\n')
                {
                    // 行尾续行:跳过脱字符与随后的换行。
                    i++;
                    while (i + 1 < s.Length && (s[i + 1] is '\r' or '\n')) i++;
                    continue;
                }
                sb.Append(next); // ^X -> X
                i++;
                continue;
            }
            sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>从值起点截到与外层引号匹配的收尾引号(识别 \" 转义),并还原 \" -> " 。</summary>
    private static string ExtractUntilUnescaped(string rest, char wrap)
    {
        var sb = new StringBuilder(rest.Length);
        for (int i = 0; i < rest.Length; i++)
        {
            char c = rest[i];
            if (c == '\\' && i + 1 < rest.Length)
            {
                char n = rest[i + 1];
                if (n == wrap || n == '\\') { sb.Append(n); i++; continue; } // \" 或 \\ -> 字面量
                sb.Append(c);
                continue;
            }
            if (c == wrap) break; // 未转义的外层引号 = 参数结束
            sb.Append(c);
        }
        return sb.ToString().Trim().TrimEnd(';', ' ');
    }

    /// <summary>裸请求头行:截到行尾。</summary>
    private static string CutToLineEnd(string rest)
    {
        int end = rest.IndexOfAny(new[] { '\r', '\n' });
        var v = end >= 0 ? rest[..end] : rest;
        return v.Trim().TrimEnd(';', ' ');
    }

    /// <summary>-b/--cookie 后:若有引号取引号内,否则取到行尾。</summary>
    private static string ExtractQuotedOrLine(string v)
    {
        if (v.Length > 0 && (v[0] == '"' || v[0] == '\''))
            return ExtractUntilUnescaped(v[1..], v[0]);
        return CutToLineEnd(v);
    }

    private static string Trim(string s) => s.Length > 600 ? s[..600] + "…" : s;

    /// <summary>
    /// 解析 used / total。优先按小米平台真实结构精确取:
    ///   data.monthUsage.items[name=month_total_token].{used,limit} —— 即控制台「当前套餐用量」;
    ///   退而取 data.usage.items[name=plan_total_token]。取不到再回退通用启发式扫描。
    /// </summary>
    private static (long Used, long Total, bool Found) ExtractUsage(JsonElement root)
    {
        if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object)
        {
            if (TryFromItems(data, "monthUsage", "month_total_token", out var u1, out var t1)) return (u1, t1, true);
            if (TryFromItems(data, "usage", "plan_total_token", out var u2, out var t2)) return (u2, t2, true);
        }

        // 通用启发式兜底(结构变化时仍尽力解析)。
        var nums = new List<(string Name, long Value)>();
        Collect(root, nums);
        long used = PickBest(nums, new[] { "used", "consume" });
        long total = PickBest(nums, new[] { "total", "quota", "limit" });
        if (total > 0 && used < 0)
        {
            long remain = PickBest(nums, new[] { "remain", "left", "balance", "available" });
            if (remain >= 0) used = Math.Max(0, total - remain);
        }
        return (Math.Max(0, used), total, total > 0 && used >= 0);
    }

    /// <summary>从 data.&lt;section&gt;.items 中取指定 name 的 used/limit;找不到该 name 则取第一项。</summary>
    private static bool TryFromItems(JsonElement data, string section, string itemName, out long used, out long limit)
    {
        used = 0; limit = 0;
        if (!data.TryGetProperty(section, out var sec) || sec.ValueKind != JsonValueKind.Object) return false;
        if (!sec.TryGetProperty("items", out var items) || items.ValueKind != JsonValueKind.Array) return false;

        JsonElement? first = null;
        foreach (var it in items.EnumerateArray())
        {
            if (first is null) first = it;
            if (it.TryGetProperty("name", out var nm)
                && string.Equals(nm.GetString(), itemName, StringComparison.OrdinalIgnoreCase))
            {
                used = GetLong(it, "used");
                limit = GetLong(it, "limit");
                return limit > 0;
            }
        }
        if (first is { } f)
        {
            used = GetLong(f, "used");
            limit = GetLong(f, "limit");
            return limit > 0;
        }
        return false;
    }

    private static long GetLong(JsonElement el, string prop)
    {
        if (!el.TryGetProperty(prop, out var p)) return 0;
        if (p.ValueKind == JsonValueKind.Number && p.TryGetInt64(out var v)) return v;
        if (p.ValueKind == JsonValueKind.String && long.TryParse(p.GetString(), out var sv)) return sv;
        return 0;
    }

    private static long PickBest(List<(string Name, long Value)> nums, string[] keys)
    {
        // 优先名字「以关键字开头/完全匹配」的,其次「包含」的。
        foreach (var prefer in new Func<string, string, bool>[]
        {
            (n, k) => n == k,
            (n, k) => n.StartsWith(k, StringComparison.Ordinal) || n.EndsWith(k, StringComparison.Ordinal),
            (n, k) => n.Contains(k, StringComparison.Ordinal),
        })
        {
            foreach (var (name, val) in nums)
                foreach (var k in keys)
                    if (prefer(name, k)) return val;
        }
        return -1;
    }

    private static void Collect(JsonElement el, List<(string, long)> sink, string name = "")
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in el.EnumerateObject())
                    Collect(p.Value, sink, p.Name.ToLowerInvariant());
                break;
            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray())
                    Collect(item, sink, name);
                break;
            case JsonValueKind.Number:
                if (el.TryGetInt64(out var n)) sink.Add((name, n));
                break;
            case JsonValueKind.String:
                // 数字以字符串形式返回(大额度常见)。
                var s = el.GetString();
                if (!string.IsNullOrEmpty(s) && long.TryParse(s, out var sv)) sink.Add((name, sv));
                break;
        }
    }

    /// <summary>用 curl.exe 发起带 Cookie 的 GET(返回响应体)。</summary>
    private static async Task<string?> GetViaCurlAsync(string cookie, CancellationToken token)
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
        psi.ArgumentList.Add("-s");
        psi.ArgumentList.Add("-k");
        psi.ArgumentList.Add("--max-time");
        psi.ArgumentList.Add("20");
        psi.ArgumentList.Add("-H");
        psi.ArgumentList.Add("accept: */*");
        psi.ArgumentList.Add("-H");
        psi.ArgumentList.Add("x-timezone: Asia/Shanghai");
        psi.ArgumentList.Add("-H");
        psi.ArgumentList.Add("referer: https://platform.xiaomimimo.com/console/plan-manage");
        psi.ArgumentList.Add("-H");
        psi.ArgumentList.Add("Cookie: " + cookie);
        psi.ArgumentList.Add(UsageUrl);

        using var proc = new Process { StartInfo = psi };
        if (!proc.Start()) throw new InvalidOperationException("无法启动 curl.exe");

        var stdoutTask = proc.StandardOutput.ReadToEndAsync(token);
        await proc.WaitForExitAsync(token);
        var stdout = await stdoutTask;
        if (proc.ExitCode != 0) throw new InvalidOperationException($"curl 退出码 {proc.ExitCode}");
        return stdout;
    }
}
