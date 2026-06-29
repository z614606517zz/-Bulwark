using System;
using System.Collections.Generic;
using System.Linq;

namespace Bulwark.Core.Engine;

/// <summary>
/// 命令行混淆分析器(独创·无特征码)。
///
/// 无文件攻击 / LOLBin 滥用为绕过基于关键字的规则,普遍对命令行做"混淆":
/// 海量 Base64、字符拼接(`'i'+'e'+'x'`)、转义插入(cmd 的 `^`、PowerShell 的反引号 `` ` ``)、
/// 字符串反转、`[char]0x65` 强转、`-join`、环境变量子串截取(`%comspec:~0,1%`)等。
///
/// 传统规则只能匹配"明文 token",混淆后即失效。本分析器不依赖具体 token,而是从
/// **统计与结构特征**判定"这条命令行是否被刻意混淆":
///   · 香农熵(信息密度)—— 混淆/编码串熵显著偏高;
///   · 非字母数字符号占比 —— 拼接/转义会塞入大量 + ^ ` { } ( ) ' 等;
///   · 已知混淆构造的结构计数 —— 越多越可疑。
///
/// 输出 (score, reasons),由 <see cref="ThreatDetector"/> 汇入总分;命中即视为硬恶意指标。
/// 设计目标:对正常长命令行(含路径/参数)保持低分,对刻意混淆载荷高分。
/// </summary>
public static class CommandObfuscationAnalyzer
{
    /// <summary>结构化混淆信号:正则/子串特征 + 单项分值 + 原因。</summary>
    private static readonly (string Token, int Score, string Reason)[] StructuralSignals =
    {
        // PowerShell 反引号转义(g`et-i`tem)——正常命令几乎不用反引号
        ("`", 12, "命令行含反引号转义(PowerShell 混淆)"),
        // 字符强转 / 拼接执行
        ("[char]", 20, "字符码强转拼接([char],混淆)"),
        ("[convert]::", 18, "Convert 解码调用(混淆/解码执行)"),
        ("-join", 14, "字符数组拼接(-join,混淆)"),
        ("[string]::join", 16, "字符串拼接(String.Join,混淆)"),
        (".invoke(", 16, "反射式调用(.Invoke,混淆执行)"),
        ("[scriptblock]", 20, "动态脚本块(ScriptBlock,混淆执行)"),
        ("-replace", 10, "运行时字符替换(-replace,混淆)"),
        ("-f ", 8, "格式化拼接(-f 运算符,混淆)"),
        ("[reflection.assembly]", 22, "反射加载程序集(内存执行)"),
        ("frombase64string", 18, "Base64 解码(混淆载荷)"),
        // cmd 转义与变量子串截取
        ("^", 8, "命令行含 ^ 转义(cmd 混淆)"),
        (":~", 16, "环境变量子串截取(%var:~%,混淆)"),
        ("set /a", 8, "算术求值拼接(set /a,混淆)"),
        // 字符串反转技巧
        ("[array]::reverse", 18, "字符串反转(Array.Reverse,混淆)"),
        ("::new(", 10, "反射式构造(::new,混淆执行)"),
    };

    /// <summary>香农熵阈值:正常含路径/参数命令行通常 < 4.0,混淆 Base64 常 > 4.5。</summary>
    private const double EntropyHigh = 4.5;
    private const double EntropyVeryHigh = 5.2;

    /// <summary>非字母数字符号占比阈值(拼接/转义会显著抬高)。</summary>
    private const double SymbolRatioHigh = 0.28;

    /// <summary>命令行过短不评估(避免误报)。</summary>
    private const int MinLength = 24;

    /// <summary>
    /// 评估命令行的混淆程度。返回累加分与原因列表。无命令行或过短返回 0。
    /// </summary>
    public static (int Score, List<string> Reasons) Analyze(string? commandLine)
    {
        var reasons = new List<string>();
        if (string.IsNullOrWhiteSpace(commandLine) || commandLine.Length < MinLength)
            return (0, reasons);

        string cmd = commandLine;
        string lower = cmd.ToLowerInvariant();
        int score = 0;

        // 1) 结构化混淆构造计数
        int structuralHits = 0;
        foreach (var sig in StructuralSignals)
        {
            int occurrences = CountOccurrences(lower, sig.Token);
            if (occurrences > 0)
            {
                structuralHits++;
                // 同一构造重复出现额外加权(但设上限,防单条命令分数爆炸)
                int add = sig.Score + Math.Min(occurrences - 1, 3) * (sig.Score / 4);
                score += add;
                reasons.Add(sig.Reason);
            }
        }

        // 2) 香农熵(对"去掉空格后的主体"计算,空格会拉低熵)
        string compact = new string(cmd.Where(c => !char.IsWhiteSpace(c)).ToArray());
        double entropy = ShannonEntropy(compact);
        if (entropy >= EntropyVeryHigh)
        {
            score += 28;
            reasons.Add($"命令行信息熵极高({entropy:0.0},疑似编码/加密载荷)");
        }
        else if (entropy >= EntropyHigh)
        {
            score += 16;
            reasons.Add($"命令行信息熵偏高({entropy:0.0},疑似混淆)");
        }

        // 3) 非字母数字符号占比
        double symbolRatio = SymbolRatio(compact);
        if (symbolRatio >= SymbolRatioHigh)
        {
            score += 14;
            reasons.Add($"命令行符号占比异常({symbolRatio:P0},疑似拼接/转义混淆)");
        }

        // 4) 超长 Base64 连续块(>=120 个 Base64 字符且无空格)——编码载荷标志
        int longestB64 = LongestBase64Run(cmd);
        if (longestB64 >= 220)
        {
            score += 26;
            reasons.Add($"含超长 Base64 块({longestB64} 字符,疑似编码载荷)");
        }
        else if (longestB64 >= 120)
        {
            score += 14;
            reasons.Add($"含较长 Base64 块({longestB64} 字符)");
        }

        // 5) 多种混淆手法叠加 —— 组合拳几乎必为恶意
        if (structuralHits >= 3)
        {
            score += 18;
            reasons.Add($"叠加 {structuralHits} 种混淆手法(高度可疑)");
        }

        return (score, reasons);
    }

    /// <summary>香农熵 H = -Σ p·log2(p)。值越大信息越"随机"(编码/加密特征)。</summary>
    public static double ShannonEntropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;
        var freq = new Dictionary<char, int>();
        foreach (char c in s)
            freq[c] = freq.TryGetValue(c, out var n) ? n + 1 : 1;

        double len = s.Length;
        double entropy = 0;
        foreach (var kv in freq)
        {
            double p = kv.Value / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    /// <summary>非字母数字、非常见路径符的符号占比。</summary>
    private static double SymbolRatio(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;
        int symbols = 0;
        foreach (char c in s)
        {
            if (char.IsLetterOrDigit(c)) continue;
            // 常见正常路径/参数符号不计入(避免误伤普通命令行)
            if (c is '\\' or '/' or ':' or '.' or '-' or '_' or '"') continue;
            symbols++;
        }
        return (double)symbols / s.Length;
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        if (string.IsNullOrEmpty(needle)) return 0;
        int count = 0, idx = 0;
        while ((idx = haystack.IndexOf(needle, idx, StringComparison.Ordinal)) >= 0)
        {
            count++;
            idx += needle.Length;
        }
        return count;
    }

    /// <summary>找出最长的"连续 Base64 字符串"长度(A-Za-z0-9+/=)。</summary>
    private static int LongestBase64Run(string s)
    {
        int longest = 0, cur = 0;
        foreach (char c in s)
        {
            bool isB64 = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                       || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
            if (isB64)
            {
                cur++;
                if (cur > longest) longest = cur;
            }
            else cur = 0;
        }
        return longest;
    }
}
