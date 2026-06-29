using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Bulwark.UI.Services;

/// <summary>
/// UI 侧轻量文件检查器:计算 SHA-256、读取签名/版本信息,
/// 用于 AI 病毒扫描组装研判上下文。仅做静态信息提取,不执行任何样本。
/// </summary>
public static class FileInspector
{
    /// <summary>
    /// AI 扫描内容提取上限(可配置)。控制喂给大模型的体积:
    /// 脚本源码字节数、二进制采样字节数、提取字符串条数。
    /// </summary>
    public sealed class ScanOptions
    {
        /// <summary>脚本/文本读取上限(字节)。1M token 窗口下默认放大到 2MB,基本可整份送审。</summary>
        public int ScriptTextLimit { get; init; } = 2 * 1024 * 1024;
        /// <summary>二进制采样读取上限(字节)。整文件流式扫描下保留作兼容,实际已全文件遍历。</summary>
        public long BinarySampleLimit { get; init; } = 64L * 1024 * 1024;
        /// <summary>提取的可打印字符串最大条数。1M token 窗口下默认放大。</summary>
        public int MaxStrings { get; init; } = 50000;

        public static ScanOptions Default { get; } = new();

        /// <summary>
        /// 从运行时设置构造。旧版本的小阈值会被上调到适配 1M 上下文窗口的充裕下限
        /// (用户主动调更大则尊重),从而真正"读整个文件内容"送审。
        /// </summary>
        public static ScanOptions FromSettings(int scriptKb, int binaryMb, int maxStrings) => new()
        {
            ScriptTextLimit = Math.Clamp(Math.Max(scriptKb, 2048), 1, 8192) * 1024,
            BinarySampleLimit = (long)Math.Clamp(Math.Max(binaryMb, 256), 1, 1024) * 1024 * 1024,
            MaxStrings = Math.Clamp(Math.Max(maxStrings, 100_000), 50, 300_000)
        };
    }

    /// <summary>单文件信息快照。</summary>
    public sealed class FileSnapshot
    {
        public string Path { get; init; } = string.Empty;
        public long Size { get; init; }
        public string? Sha256 { get; init; }
        public bool Signed { get; init; }
        public string? Publisher { get; init; }
        public string? FileDescription { get; init; }
        public string? CompanyName { get; init; }
        public string? ProductName { get; init; }
        public string? OriginalFileName { get; init; }
        public string? FileVersion { get; init; }
        public string? Extension { get; init; }
        public DateTime CreatedUtc { get; init; }
        public DateTime ModifiedUtc { get; init; }
        public string? Error { get; init; }

        // ===== 内容/静态特征(供大模型真正"看文件"研判) =====
        /// <summary>文件起始字节的十六进制(用于识别真实文件类型/魔数)。</summary>
        public string? MagicHex { get; init; }
        /// <summary>是否为 PE 可执行(MZ 头)。</summary>
        public bool IsPe { get; init; }
        /// <summary>是否被识别为文本/脚本(可读源码)。</summary>
        public bool IsTextScript { get; init; }
        /// <summary>脚本/文本源码内容(已截断,仅文本类文件)。</summary>
        public string? ScriptText { get; init; }
        /// <summary>从二进制中提取的可打印字符串(已过滤、截断)。</summary>
        public System.Collections.Generic.List<string> Strings { get; init; } = new();
        /// <summary>命中的可疑 API / 关键词(基于字符串扫描)。</summary>
        public System.Collections.Generic.List<string> SuspiciousIndicators { get; init; } = new();
        /// <summary>文件整体香农熵(0~8,越高越像加壳/加密)。</summary>
        public double Entropy { get; init; }
    }

    /// <summary>读取文件全部静态信息(尽力,失败字段留空)。</summary>
    public static FileSnapshot Inspect(string path, ScanOptions? options = null)
    {
        options ??= ScanOptions.Default;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists)
                return new FileSnapshot { Path = path, Error = "文件不存在" };

            string? sha = TryComputeSha256(path, fi.Length);
            bool signed = false;
            string? publisher = null;
            try
            {
                using var cert = new X509Certificate2(path);
                signed = true;
                publisher = cert.GetNameInfo(X509NameType.SimpleName, false);
                if (string.IsNullOrEmpty(publisher))
                    publisher = cert.Subject;
            }
            catch { /* 无签名 / 读取失败 */ }

            string? desc = null, company = null, product = null, original = null, version = null;
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(path);
                desc = vi.FileDescription;
                company = vi.CompanyName;
                product = vi.ProductName;
                original = vi.OriginalFilename;
                version = vi.FileVersion;
            }
            catch { /* 非 PE / 读取失败 */ }

            // 真正"读文件内容"提取静态特征,供大模型研判。
            var content = ExtractContent(path, fi.Length, fi.Extension?.ToLowerInvariant(), options);

            return new FileSnapshot
            {
                Path = path,
                Size = fi.Length,
                Sha256 = sha,
                Signed = signed,
                Publisher = publisher,
                FileDescription = desc,
                CompanyName = company,
                ProductName = product,
                OriginalFileName = original,
                FileVersion = version,
                Extension = fi.Extension?.ToLowerInvariant(),
                CreatedUtc = fi.CreationTimeUtc,
                ModifiedUtc = fi.LastWriteTimeUtc,
                MagicHex = content.MagicHex,
                IsPe = content.IsPe,
                IsTextScript = content.IsTextScript,
                ScriptText = content.ScriptText,
                Strings = content.Strings,
                SuspiciousIndicators = content.Indicators,
                Entropy = content.Entropy
            };
        }
        catch (Exception ex)
        {
            return new FileSnapshot { Path = path, Error = ex.Message };
        }
    }

    // ===================== 文件内容/静态特征提取 =====================

    /// <summary>内容提取结果(内部用)。</summary>
    private sealed class ContentResult
    {
        public string? MagicHex;
        public bool IsPe;
        public bool IsTextScript;
        public string? ScriptText;
        public System.Collections.Generic.List<string> Strings = new();
        public System.Collections.Generic.List<string> Indicators = new();
        public double Entropy;
    }

    // 读取上限默认值见 ScanOptions;此处仅保留扩展名/关键词字典等常量。

    // 脚本/文本类扩展名 —— 这类直接把源码喂给模型。
    private static readonly string[] TextScriptExt =
    {
        ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".hta", ".py", ".pl", ".rb", ".sh", ".php",
        ".reg", ".inf", ".xml", ".html", ".htm", ".txt"
    };

    // 恶意软件常见的可疑 API / 关键词(命中即作为线索提示给模型)。
    private static readonly string[] SuspiciousKeywords =
    {
        // 进程注入 / 内存
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "QueueUserAPC", "SetWindowsHookEx", "ResumeThread",
        "RtlCreateUserThread", "MapViewOfFile", "LoadLibrary", "GetProcAddress",
        // 反调试 / 反分析
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "FindWindow", "GetTickCount", "Sleep",
        // 持久化 / 注册表
        "RegSetValue", "RegCreateKey", "CurrentVersion\\Run", "schtasks", "sc create",
        "Userinit", "Winlogon", "Image File Execution Options",
        // 凭据 / 信息窃取
        "CredEnumerate", "lsass", "SamConnect", "GetAsyncKeyState", "GetForegroundWindow",
        "wallet", "password", "cookies", "Login Data",
        // 网络 / C2
        "WinHttp", "InternetOpen", "URLDownloadToFile", "WSASocket", "socket",
        "powershell -enc", "powershell -e ", "-EncodedCommand", "DownloadString",
        "Invoke-Expression", "IEX", "FromBase64String", "bitsadmin", "certutil -decode",
        // 破坏 / 勒索
        "vssadmin delete", "wbadmin delete", "bcdedit", "cipher /w",
        "CryptEncrypt", "CryptAcquireContext", "RANSOM", "bitcoin", "decrypt",
        // 自启 / 提权 / 横移
        "AdjustTokenPrivileges", "SeDebugPrivilege", "psexec", "wmic", "rundll32",
        "regsvr32", "mshta", "wscript", "cscript", "net user", "net localgroup",
        // 防御规避
        "Set-MpPreference", "DisableRealtimeMonitoring", "netsh advfirewall", "taskkill",
        "amsi", "AmsiScanBuffer", "ETW", "wevtutil cl"
    };

    /// <summary>真正读取文件内容,提取魔数/脚本源码/可打印字符串/可疑线索/熵。</summary>
    private static ContentResult ExtractContent(string path, long size, string? ext, ScanOptions options)
    {
        var r = new ContentResult();
        try
        {
            // 1) 读取头部用于判类型与魔数。
            byte[] head;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
            {
                int headLen = (int)Math.Min(size, 64);
                head = new byte[headLen];
                int read = fs.Read(head, 0, headLen);
                if (read < headLen) Array.Resize(ref head, read);
            }
            r.MagicHex = Convert.ToHexString(head, 0, Math.Min(head.Length, 16));
            r.IsPe = head.Length >= 2 && head[0] == 0x4D && head[1] == 0x5A; // 'MZ'

            bool textByExt = ext is not null && Array.IndexOf(TextScriptExt, ext) >= 0;
            bool textByContent = !r.IsPe && LooksLikeText(head);
            r.IsTextScript = textByExt || textByContent;

            if (r.IsTextScript)
            {
                // 2a) 文本/脚本:直接读源码(截断)。
                r.ScriptText = ReadTextTruncated(path, options.ScriptTextLimit);
                ScanIndicators(r.ScriptText, r.Indicators);
            }
            else
            {
                // 二进制:流式读取【整个文件】→ 全文件熵 + 全文件可打印字符串 + 全文件可疑线索。
                ScanWholeBinary(path, options, r);
            }
        }
        catch { /* 提取失败,字段留空,模型退化为按元数据研判 */ }
        return r;
    }

    /// <summary>头部是否像文本(无 NUL,绝大多数为可打印/常见空白)。</summary>
    private static bool LooksLikeText(byte[] head)
    {
        if (head.Length == 0) return false;
        int printable = 0;
        foreach (var b in head)
        {
            if (b == 0) return false; // 含 NUL 视为二进制
            if (b >= 0x20 && b < 0x7F) printable++;
            else if (b is 0x09 or 0x0A or 0x0D) printable++;
            else if (b >= 0x80) printable++; // UTF-8 多字节,宽容处理
        }
        return printable >= head.Length * 0.85;
    }

    /// <summary>读取文本文件前 limit 字节,自动按 UTF-8 解码(BOM 友好)。</summary>
    private static string ReadTextTruncated(string path, int limit)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        int len = (int)Math.Min(fs.Length, limit);
        var buf = new byte[len];
        int read = fs.Read(buf, 0, len);
        var text = new System.Text.UTF8Encoding(false, false).GetString(buf, 0, read);
        if (fs.Length > limit) text += $"\n\n...(已截断,仅显示前 {limit / 1024}KB)...";
        return text;
    }

    /// <summary>
    /// 流式遍历【整个文件】:计算全文件香农熵、提取全文件可打印字符串(ASCII + UTF-16LE,
    /// 跨缓冲区边界连续),并在全文件范围扫描可疑 API/关键词。
    /// 内存恒定(分块读取),可处理大文件;字符串保留条数受 MaxStrings 限制(满额时优先保留高价值串)。
    /// </summary>
    private static void ScanWholeBinary(string path, ScanOptions options, ContentResult r)
    {
        const int MinLen = 5;
        var counts = new long[256];
        long totalBytes = 0;

        var kept = new System.Collections.Generic.List<string>();
        var keptSet = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var ascii = new System.Text.StringBuilder(256);
        var wide = new System.Text.StringBuilder(256);
        byte widePrev = 0; bool widePending = false; // 简易 UTF-16LE: 可打印字节 + 0x00

        void Consider(string raw)
        {
            var s = raw.Trim();
            if (s.Length < MinLen) return;

            // 全文件线索扫描(不受保留条数限制,确保末尾命中也能发现)。
            ScanIndicators(s, r.Indicators);

            if (keptSet.Contains(s)) return;
            if (kept.Count < options.MaxStrings)
            {
                keptSet.Add(s); kept.Add(s);
            }
            else if (IsInterestingString(s))
            {
                // 已满:用高价值串替换一个普通串,保证关键证据不被截断丢弃。
                int idx = kept.FindIndex(x => !IsInterestingString(x));
                if (idx >= 0) { keptSet.Remove(kept[idx]); kept[idx] = s; keptSet.Add(s); }
            }
        }

        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
            var buf = new byte[1 << 20]; // 1MB 分块
            int n;
            while ((n = fs.Read(buf, 0, buf.Length)) > 0)
            {
                for (int i = 0; i < n; i++)
                {
                    byte b = buf[i];
                    counts[b]++; totalBytes++;

                    // ASCII 可打印连续串
                    if (b >= 0x20 && b < 0x7F) ascii.Append((char)b);
                    else { if (ascii.Length >= MinLen) Consider(ascii.ToString()); ascii.Clear(); }

                    // UTF-16LE: 形如 [可打印][00]
                    if (widePending)
                    {
                        if (b == 0x00) wide.Append((char)widePrev);
                        else { if (wide.Length >= MinLen) Consider(wide.ToString()); wide.Clear(); }
                        widePending = false;
                    }
                    else if (b >= 0x20 && b < 0x7F) { widePrev = b; widePending = true; }
                    else { if (wide.Length >= MinLen) Consider(wide.ToString()); wide.Clear(); widePending = false; }
                }
                // 安全上限:超大文件只扫描前 N 字节,避免长时间卡顿(默认 256MB,覆盖绝大多数程序)。
                if (totalBytes >= options.BinarySampleLimit) break;
            }
            if (ascii.Length >= MinLen) Consider(ascii.ToString());
            if (wide.Length >= MinLen) Consider(wide.ToString());
        }
        catch { /* 读取中断:用已扫描部分 */ }

        if (totalBytes > 0)
        {
            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                double p = counts[i] / (double)totalBytes;
                entropy -= p * Math.Log2(p);
            }
            r.Entropy = Math.Round(entropy, 2);
        }

        r.Strings = kept;
    }

    /// <summary>是否为"高价值"字符串(含可疑关键词 / URL / IP / 路径 / 模块名),满额时优先保留。</summary>
    private static bool IsInterestingString(string s)
    {
        foreach (var kw in SuspiciousKeywords)
            if (s.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0) return true;
        if (s.IndexOf("http", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        if (s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase) >= 0
            || s.IndexOf(".dll", StringComparison.OrdinalIgnoreCase) >= 0
            || s.IndexOf('\\') >= 0) return true;
        if (System.Text.RegularExpressions.Regex.IsMatch(s, @"\b\d{1,3}(\.\d{1,3}){3}\b")) return true;
        return false;
    }

    /// <summary>在文本中扫描可疑 API/关键词,命中的收集为线索。</summary>
    private static void ScanIndicators(string? text, System.Collections.Generic.List<string> into)
    {
        if (string.IsNullOrEmpty(text)) return;
        foreach (var kw in SuspiciousKeywords)
        {
            if (text.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0 && !into.Contains(kw))
                into.Add(kw);
        }
        // URL / IP 粗略线索
        if (System.Text.RegularExpressions.Regex.IsMatch(text, @"https?://", System.Text.RegularExpressions.RegexOptions.IgnoreCase)
            && !into.Contains("含 URL")) into.Add("含 URL");
        if (System.Text.RegularExpressions.Regex.IsMatch(text, @"\b\d{1,3}(\.\d{1,3}){3}\b")
            && !into.Contains("含 IP 地址")) into.Add("含 IP 地址");
    }

    /// <summary>计算文件 SHA-256(大文件分块流读),失败返回 null。超过 200MB 跳过。</summary>
    public static string? TryComputeSha256(string path, long? sizeHint = null)
    {
        try
        {
            long size = sizeHint ?? new FileInfo(path).Length;
            if (size > 200L * 1024 * 1024) return null; // 200MB 上限避免卡死
            using var sha = SHA256.Create();
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            var hash = sha.ComputeHash(fs);
            return Convert.ToHexString(hash);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>常见的可执行/脚本类型,AI 扫描默认只扫这些。</summary>
    public static readonly string[] ExecutableExtensions = new[]
    {
        ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv",
        ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf",
        ".jar", ".lnk", ".hta", ".chm"
    };

    public static bool LooksExecutable(string path)
    {
        var ext = System.IO.Path.GetExtension(path)?.ToLowerInvariant();
        if (string.IsNullOrEmpty(ext)) return false;
        return Array.IndexOf(ExecutableExtensions, ext) >= 0;
    }
}
