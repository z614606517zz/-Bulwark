using System;
using System.Collections.Generic;
using System.Linq;

namespace Bulwark.Core.Engine;

/// <summary>
/// DGA(域名生成算法)随机度分析器(独创·无黑名单)。
///
/// 现代僵尸网络 / C2(Conficker、Necurs、Emotet、各类 RAT)用 DGA 周期性生成
/// 大量伪随机域名(如 <c>kq3v9zxl2p.com</c>、<c>xn7gqweuio.net</c>)轮询回连,
/// 使域名黑名单永远滞后失效。这类域名的共同特征是**像随机字母堆而非可读单词**:
///   · 香农熵偏高(字符分布接近均匀);
///   · 元音比例异常低(可读英文单词元音约 38%,DGA 常 &lt;25%);
///   · 长连续辅音串(正常域名极少出现 6+ 连续辅音);
///   · 数字与字母交错、整体长度偏长。
///
/// 本分析器**只看域名字符串的统计特征**,不依赖任何黑名单,因此对全新 DGA 同样有效。
///
/// 关键约束(遵循全局低误报原则):DGA 随机度是**软信号**,
/// <b>单独不得</b>置位 <see cref="Models.SecurityEvent.HasThreatIndicator"/> 或直接处置 ——
/// 正常 CDN / 哈希化子域(如 <c>a1b2c3.cloudfront.net</c>)也可能高随机度。
/// 它只贡献 RiskScore / RiskReasons,只有与另一硬指标(如 <see cref="BeaconDetector"/>
/// 周期信标命中、未签名脚本解释器外联)<b>共现</b>时才由调用方升格为硬指标(互证机制)。
///
/// 输出 (score, reasons)。无域名 / 是 IP / 是常见可信域名后缀时返回 0。
/// 纯函数,无状态,线程安全。
/// </summary>
public static class DgaDomainAnalyzer
{
    /// <summary>低于此长度的标签不评估(短域名随机度统计不可靠,易误报)。</summary>
    private const int MinLabelLength = 8;

    /// <summary>香农熵阈值:可读域名标签通常 &lt; 3.2,随机串常 &gt; 3.6。</summary>
    private const double EntropyHigh = 3.6;
    private const double EntropyVeryHigh = 4.0;

    /// <summary>元音比例下限:英文可读串元音约 38%,DGA 常低于此。</summary>
    private const double VowelRatioLow = 0.26;
    private const double VowelRatioVeryLow = 0.18;

    /// <summary>判定为"异常长辅音串"的连续辅音数。</summary>
    private const int LongConsonantRun = 6;

    /// <summary>常见可信顶级/二级后缀,这些下面的随机子域多为 CDN/哈希化资源,不评估随机度。</summary>
    private static readonly string[] BenignSuffixes =
    {
        ".cloudfront.net", ".akamai.net", ".akamaihd.net", ".azureedge.net",
        ".windows.net", ".windowsupdate.com", ".cloudflare.net", ".fastly.net",
        ".amazonaws.com", ".googleusercontent.com", ".gvt1.com", ".azure.com",
        ".edgekey.net", ".edgesuite.net", ".llnwd.net", ".cdn.cloudflare.net",
        ".1e100.net", ".gstatic.com", ".office.com", ".office365.com",
        ".sharepoint.com", ".live.com", ".microsoft.com", ".apple.com",
        ".icloud.com", ".github.io", ".githubusercontent.com",
    };

    private const string Vowels = "aeiouy";

    /// <summary>
    /// 评估网络外联目标域名的 DGA 随机度。返回累加分与原因。
    /// 传入值可为 "host" 或 "host:port";IP 地址、空值、可信后缀返回 0 分。
    /// </summary>
    public static (int Score, List<string> Reasons) Analyze(string? target)
    {
        var reasons = new List<string>();
        if (string.IsNullOrWhiteSpace(target))
            return (0, reasons);

        string host = ExtractHost(target);
        if (string.IsNullOrEmpty(host) || IsIpAddress(host))
            return (0, reasons);

        string lower = host.ToLowerInvariant();

        // 可信 CDN / 大厂后缀:其随机子域为正常哈希资源,跳过。
        if (BenignSuffixes.Any(s => lower.EndsWith(s, StringComparison.Ordinal)))
            return (0, reasons);

        // 取"可注册标签"(去掉公共后缀部分,取倒数第二段作为主标签)做随机度分析。
        string label = RegistrableLabel(lower);
        if (label.Length < MinLabelLength)
            return (0, reasons);

        // 只保留字母数字用于统计(去掉连字符等)
        string core = new string(label.Where(char.IsLetterOrDigit).ToArray());
        if (core.Length < MinLabelLength)
            return (0, reasons);

        int score = 0;

        // 1) 香农熵(复用 CommandObfuscationAnalyzer 的实现)
        double entropy = CommandObfuscationAnalyzer.ShannonEntropy(core);
        if (entropy >= EntropyVeryHigh)
        {
            score += 30;
            reasons.Add($"域名标签熵极高({entropy:0.0},疑似 DGA 随机域名)");
        }
        else if (entropy >= EntropyHigh)
        {
            score += 18;
            reasons.Add($"域名标签熵偏高({entropy:0.0},疑似算法生成)");
        }

        // 2) 元音比例(可读单词元音约 38%,随机串显著偏低)
        double vowelRatio = VowelRatio(core);
        if (vowelRatio <= VowelRatioVeryLow)
        {
            score += 24;
            reasons.Add($"域名元音比例极低({vowelRatio:P0},非可读单词)");
        }
        else if (vowelRatio <= VowelRatioLow)
        {
            score += 12;
            reasons.Add($"域名元音比例偏低({vowelRatio:P0})");
        }

        // 3) 异常长连续辅音串
        int maxConsonant = LongestConsonantRun(core);
        if (maxConsonant >= LongConsonantRun)
        {
            score += 16;
            reasons.Add($"含 {maxConsonant} 个连续辅音(非自然拼写)");
        }

        // 4) 数字字母交错(DGA 常混入数字;正常品牌域名很少)
        double digitRatio = core.Count(char.IsDigit) / (double)core.Length;
        int alternations = DigitLetterAlternations(core);
        if (digitRatio > 0.2 && alternations >= 3)
        {
            score += 12;
            reasons.Add($"数字字母高频交错({alternations} 次,疑似算法生成)");
        }

        // 5) 标签很长又高熵的叠加(典型 DGA 形态)
        if (core.Length >= 14 && entropy >= EntropyHigh)
        {
            score += 8;
            reasons.Add($"超长高熵标签({core.Length} 字符)");
        }

        return (Math.Min(score, 100), reasons);
    }

    /// <summary>从 "host" 或 "host:port" 中提取主机名(去端口)。</summary>
    private static string ExtractHost(string target)
    {
        var t = target.Trim();
        // 去掉可能的 scheme
        int scheme = t.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) t = t.Substring(scheme + 3);
        // 去掉路径
        int slash = t.IndexOf('/');
        if (slash >= 0) t = t.Substring(0, slash);
        // 去掉端口(仅当最后一个冒号后全是数字)
        int colon = t.LastIndexOf(':');
        if (colon > 0 && colon < t.Length - 1 && t.Skip(colon + 1).All(char.IsDigit))
            t = t.Substring(0, colon);
        return t;
    }

    /// <summary>是否为 IPv4/IPv6 字面地址(IP 无 DGA 语义)。</summary>
    private static bool IsIpAddress(string host)
        => System.Net.IPAddress.TryParse(host, out _);

    /// <summary>取"主标签":去掉顶级后缀,取剩余的最后一段(example.co.uk -> example)。</summary>
    private static string RegistrableLabel(string host)
    {
        var parts = host.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length <= 1) return host;
        // 简化处理:对 a.b.co.uk 取倒数第三段,否则取倒数第二段。
        // 仅用于随机度统计,不需要精确的公共后缀列表。
        int idx = parts.Length - 2;
        if (parts.Length >= 3 && parts[^1].Length == 2 && parts[^2].Length <= 3)
            idx = parts.Length - 3; // 双段国家后缀(co.uk / com.cn)
        return idx >= 0 ? parts[idx] : parts[^1];
    }

    private static double VowelRatio(string s)
    {
        if (s.Length == 0) return 0;
        int letters = 0, vowels = 0;
        foreach (char c in s)
        {
            if (!char.IsLetter(c)) continue;
            letters++;
            if (Vowels.IndexOf(c) >= 0) vowels++;
        }
        return letters == 0 ? 0 : (double)vowels / letters;
    }

    private static int LongestConsonantRun(string s)
    {
        int longest = 0, cur = 0;
        foreach (char c in s)
        {
            bool isConsonant = char.IsLetter(c) && Vowels.IndexOf(c) < 0;
            if (isConsonant)
            {
                cur++;
                if (cur > longest) longest = cur;
            }
            else cur = 0;
        }
        return longest;
    }

    private static int DigitLetterAlternations(string s)
    {
        int count = 0;
        for (int i = 1; i < s.Length; i++)
        {
            bool prevDigit = char.IsDigit(s[i - 1]);
            bool curDigit = char.IsDigit(s[i]);
            if (prevDigit != curDigit) count++;
        }
        return count;
    }
}
