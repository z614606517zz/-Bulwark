using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Bulwark.Core.Engine;

/// <summary>
/// 脚本内容静态分析器(独创·无特征码)。
///
/// 分析 PowerShell/VBS/JS 脚本内容，检测恶意特征：
/// 1. 危险命令/函数调用
/// 2. 混淆技术特征
/// 3. 可疑编码/加密操作
/// 4. 绕过安全策略的技术
/// 5. 文件系统/注册表操作
/// 6. 网络通信操作
///
/// 设计目标：对正常脚本保持低误报，对恶意脚本高检出。
/// </summary>
public static class ScriptAnalyzer
{
    /// <summary>PowerShell 危险命令特征</summary>
    private static readonly (string Pattern, int Score, string Reason)[] PowerShellDangerousCommands =
    {
        // 执行与调用
        ("invoke-expression", 35, "PowerShell 动态执行(Invoke-Expression)"),
        ("iex ", 35, "PowerShell 动态执行(IEX 别名)"),
        ("iex(", 35, "PowerShell 动态执行(IEX 别名)"),
        ("invoke-command", 25, "PowerShell 远程命令执行(Invoke-Command)"),
        ("invoke-item", 15, "PowerShell 执行文件(Invoke-Item)"),
        ("start-process", 20, "PowerShell 启动进程(Start-Process)"),
        
        // 下载与网络
        ("downloadstring", 40, "PowerShell 内存下载执行(DownloadString)"),
        ("downloadfile", 35, "PowerShell 远程下载文件"),
        ("invoke-webrequest", 30, "PowerShell HTTP 请求(Invoke-WebRequest)"),
        ("iwr ", 25, "PowerShell HTTP 请求(IWR 别名)"),
        ("net.webclient", 35, "PowerShell 网络下载(Net.WebClient)"),
        ("system.net.webclient", 35, "PowerShell 网络下载(System.Net.WebClient)"),
        ("bitsadmin", 30, "BITS 后台下载"),
        ("start-bitstransfer", 30, "BITS 后台传输"),
        
        // 编码与混淆
        ("frombase64string", 30, "Base64 解码"),
        ("tobase64string", 20, "Base64 编码"),
        ("-encodedcommand", 35, "PowerShell 编码命令"),
        ("-enc ", 35, "PowerShell 编码命令(缩写)"),
        ("[convert]::", 25, "类型转换(常用于解码)"),
        ("[system.convert]", 25, "系统转换类"),
        
        // 反射与内存操作
        ("[reflection.assembly]", 30, "反射加载程序集(内存执行)"),
        ("reflection.assembly]::load", 30, "反射加载程序集"),
        ("[system.reflection]", 25, "反射操作"),
        ("assembly]::load(", 30, "动态加载程序集"),
        ("add-type", 25, "动态添加类型(可能加载恶意代码)"),
        
        // 绕过技术
        ("-executionpolicy bypass", 35, "绕过执行策略"),
        ("-ep bypass", 35, "绕过执行策略(缩写)"),
        ("-windowstyle hidden", 30, "隐藏窗口运行"),
        ("-w hidden", 30, "隐藏窗口运行(缩写)"),
        ("-noprofile", 20, "跳过配置文件"),
        ("-noninteractive", 15, "非交互模式"),
        
        // 进程与系统操作
        ("process]::start(", 25, "启动进程"),
        ("diagnostics.process", 25, "进程诊断操作"),
        ("get-process", 10, "获取进程信息"),
        ("stop-process", 20, "停止进程"),
        ("remove-item", 15, "删除文件/目录"),
        ("del ", 15, "删除命令"),
        ("rmdir", 15, "删除目录"),
        
        // 注册表操作
        ("set-itemproperty", 20, "设置注册表/环境变量"),
        ("new-itemproperty", 20, "新建注册表属性"),
        ("remove-itemproperty", 20, "删除注册表属性"),
        ("hklm:\\", 25, "操作本地机器注册表"),
        ("hkcu:\\", 20, "操作当前用户注册表"),
        
        // 凭据与安全
        ("get-credential", 25, "获取凭据"),
        ("convertto-securestring", 25, "转换为安全字符串"),
        ("convertfrom-securestring", 25, "从安全字符串转换"),
        ("system.security.cryptography", 25, "加密操作"),
        
        // 持久化
        ("new-scheduledtask", 30, "创建计划任务"),
        ("register-scheduledtask", 30, "注册计划任务"),
        ("new-service", 25, "创建服务"),
        
        // 混淆技术
        ("-join", 15, "字符串拼接(-join)"),
        ("-replace", 10, "字符串替换(-replace)"),
        ("-split", 10, "字符串分割(-split)"),
        ("-f ", 10, "格式化字符串(-f)"),
        ("[char]", 20, "字符码转换([char])"),
        ("[string]", 15, "字符串类型转换"),
        ("[array]", 10, "数组操作"),
    };

    /// <summary>VBS/JS 危险特征</summary>
    private static readonly (string Pattern, int Score, string Reason)[] VbsJsDangerousPatterns =
    {
        // Shell 执行
        ("wscript.shell", 35, "WScript.Shell 对象(命令执行)"),
        ("shell.application", 35, "Shell.Application 对象"),
        ("cmd.exe", 30, "调用命令行"),
        ("cmd /c", 30, "执行命令"),
        ("powershell", 35, "调用 PowerShell"),
        
        // 文件系统操作
        ("scripting.filesystemobject", 25, "文件系统对象"),
        ("filesystemobject", 25, "文件系统对象"),
        ("createobject", 20, "创建 COM 对象"),
        ("getobject", 20, "获取 COM 对象"),
        
        // 网络操作
        ("msxml2.xmlhttp", 35, "XMLHTTP 网络请求"),
        ("microsoft.xmlhttp", 35, "XMLHTTP 网络请求"),
        ("winhttp.winhttprequest", 35, "WinHTTP 网络请求"),
        ("serverxmlhttp", 30, "服务器 XMLHTTP"),
        
        // 注册表操作
        ("regread", 25, "读取注册表"),
        ("regwrite", 30, "写入注册表"),
        ("regdelete", 30, "删除注册表"),
        
        // 进程操作
        ("wscript.sleep", 10, "脚本延迟执行"),
        ("run ", 20, "执行命令"),
        ("exec ", 25, "执行命令"),
        
        // 混淆技术
        ("chr(", 15, "字符码转换(chr)"),
        ("asc(", 10, "字符转 ASCII 码"),
        ("eval(", 30, "动态执行(eval)"),
        ("execute(", 30, "动态执行(execute)"),
        ("executeglobal", 35, "全局执行(executeGlobal)"),
        
        // 下载执行
        ("urlmon.dll", 35, "URL 监视器库(下载)"),
        ("urldownloadtofile", 35, "下载文件到本地"),
        ("wininet.dll", 30, "Windows Internet 库"),
        
        // 脚本宿主
        ("cscript.exe", 25, "CScript 脚本宿主"),
        ("wscript.exe", 25, "WScript 脚本宿主"),
        ("mshta.exe", 35, "MSHTA 执行(常用于绕过)"),
        
        // 可疑操作
        ("environment", 15, "环境变量操作"),
        ("specialfolders", 15, "特殊文件夹访问"),
        ("currentdirectory", 15, "当前目录操作"),
    };

    /// <summary>PowerShell 混淆结构特征</summary>
    private static readonly (string Pattern, int Score, string Reason)[] PowerShellObfuscation =
    {
        // 字符串拼接
        ("'+'", 15, "字符串拼接('+')"),
        ("\"+\"", 15, "字符串拼接(\"+\")"),
        ("' & '", 15, "字符串连接(' & ')"),
        
        // 字符码转换
        ("[char]0x", 25, "十六进制字符码([char]0x)"),
        ("[char]([int]", 25, "整数字符转换"),
        
        // 反引号转义
        ("`", 12, "反引号转义(混淆)"),
        
        // 变量扩展
        ("${", 10, "变量扩展(${})"),
        
        // 类型转换
        ("[int]", 10, "整数类型转换"),
        ("[byte]", 10, "字节类型转换"),
        
        // 数组操作
        ("@(", 10, "数组表达式"),
        
        // 哈希表
        ("@{", 10, "哈希表表达式"),
        
        // 子表达式
        ("$(", 10, "子表达式$()"),
        
        // 脚本块
        ("{", 5, "脚本块{}"),
    };

    /// <summary>Base64 正则表达式</summary>
    private static readonly Regex Base64Regex = new(
        @"[A-Za-z0-9+/]{50,}={0,2}",
        RegexOptions.Compiled);

    /// <summary>十六进制字符串正则</summary>
    private static readonly Regex HexStringRegex = new(
        @"0x[A-Fa-f0-9]{8,}|\\x[A-Fa-f0-9]{2,}",
        RegexOptions.Compiled);

    /// <summary>IP 地址正则</summary>
    private static readonly Regex IpAddressRegex = new(
        @"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        RegexOptions.Compiled);

    /// <summary>URL 正则</summary>
    private static readonly Regex UrlRegex = new(
        @"https?://[^\s]+",
        RegexOptions.Compiled);

    /// <summary>脚本内容最小分析长度</summary>
    private const int MinContentLength = 50;

    /// <summary>分析脚本内容，返回风险评分和原因</summary>
    public static (int Score, List<string> Reasons) AnalyzeScript(string? scriptContent, ScriptType scriptType)
    {
        var reasons = new List<string>();
        if (string.IsNullOrWhiteSpace(scriptContent) || scriptContent.Length < MinContentLength)
            return (0, reasons);

        string content = scriptContent;
        string lowerContent = content.ToLowerInvariant();
        int score = 0;

        // 根据脚本类型选择分析策略
        switch (scriptType)
        {
            case ScriptType.PowerShell:
                var psResult = AnalyzePowerShell(content, lowerContent);
                score += psResult.Score;
                reasons.AddRange(psResult.Reasons);
                break;
                
            case ScriptType.Vbscript:
            case ScriptType.Javascript:
                var vbsResult = AnalyzeVbsJs(content, lowerContent, scriptType);
                score += vbsResult.Score;
                reasons.AddRange(vbsResult.Reasons);
                break;
                
            case ScriptType.Batch:
                var batchResult = AnalyzeBatch(content, lowerContent);
                score += batchResult.Score;
                reasons.AddRange(batchResult.Reasons);
                break;
        }

        // 通用分析：编码、网络、文件操作
        var commonResult = AnalyzeCommon(content, lowerContent);
        score += commonResult.Score;
        reasons.AddRange(commonResult.Reasons);

        return (score, reasons);
    }

    /// <summary>
    /// 从命令行中提取**真正可分析的脚本内容**。
    ///
    /// 关键设计(降误报):**只在能拿到脚本体本身**(如 -EncodedCommand 解码后的真实代码)
    /// 时才返回脚本类型;**只看到 "powershell" / ".ps1" 等关键字而无脚本体内容时返回 Unknown**,
    /// 让 <see cref="CommandObfuscationAnalyzer"/> 与 ThreatDetector 的命令行特征
    /// (`CommandLineSignals`)负责检测——那边对 token 加分稳健,有 ATT&CK 标注,
    /// 不会因 `{`、`@(`、`Start-Process` 等正常 PowerShell 命令的常见结构而误把
    /// 纯命令行误分类为「混淆脚本内容」。
    /// </summary>
    public static (string? Content, ScriptType Type) ExtractScriptFromCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
            return (null, ScriptType.Unknown);

        string cmd = commandLine.Trim();
        string lower = cmd.ToLowerInvariant();

        // 仅 -EncodedCommand 能拿到真正的「脚本内容」(Base64 解码后即为代码体)。
        // 其它情形(命令行里只有 .ps1 路径、或裸 powershell.exe 调用)拿不到内容,
        // 不送 ScriptAnalyzer —— 否则会把命令行参数本身当成脚本误分析。
        if (lower.Contains("-encodedcommand") || lower.Contains("-enc "))
        {
            string? encoded = ExtractEncodedCommand(cmd);
            if (!string.IsNullOrEmpty(encoded))
            {
                try
                {
                    byte[] bytes = Convert.FromBase64String(encoded);
                    string decoded = System.Text.Encoding.Unicode.GetString(bytes);
                    return (decoded, ScriptType.PowerShell);
                }
                catch { /* 解码失败,不分析(避免把无效编码当脚本) */ }
            }
        }

        // mshta 内联脚本(javascript:/vbscript:):内联代码紧跟在 scheme 后,可分析。
        if (lower.Contains("mshta") && (lower.Contains("javascript:") || lower.Contains("vbscript:")))
            return (cmd, ScriptType.Javascript);

        // 其它仅看到「调用脚本宿主 + 文件路径」的情形:返回 Unknown,
        // 交由命令行特征/混淆分析器负责,避免脚本分析器误判纯命令行。
        return (null, ScriptType.Unknown);
    }

    /// <summary>分析 PowerShell 脚本</summary>
    private static (int Score, List<string> Reasons) AnalyzePowerShell(string content, string lowerContent)
    {
        var reasons = new List<string>();
        int score = 0;

        // 检查危险命令
        foreach (var (pattern, cmdScore, reason) in PowerShellDangerousCommands)
        {
            if (lowerContent.Contains(pattern))
            {
                score += cmdScore;
                reasons.Add(reason);
            }
        }

        // 检查混淆特征
        foreach (var (pattern, obfScore, reason) in PowerShellObfuscation)
        {
            if (content.Contains(pattern))
            {
                score += obfScore;
                reasons.Add(reason);
            }
        }

        // 检查 Base64 编码内容
        var base64Matches = Base64Regex.Matches(content);
        foreach (Match match in base64Matches)
        {
            if (match.Length >= 100)
            {
                score += 20;
                reasons.Add($"发现长 Base64 字符串({match.Length} 字符)");
            }
        }

        // 检查十六进制编码
        var hexMatches = HexStringRegex.Matches(content);
        if (hexMatches.Count > 3)
        {
            score += 15;
            reasons.Add($"发现多个十六进制字符串({hexMatches.Count} 个)");
        }

        return (score, reasons);
    }

    /// <summary>分析 VBS/JS 脚本</summary>
    private static (int Score, List<string> Reasons) AnalyzeVbsJs(string content, string lowerContent, ScriptType type)
    {
        var reasons = new List<string>();
        int score = 0;

        foreach (var (pattern, cmdScore, reason) in VbsJsDangerousPatterns)
        {
            if (lowerContent.Contains(pattern))
            {
                score += cmdScore;
                reasons.Add(reason);
            }
        }

        // 检查混淆技术
        if (lowerContent.Contains("chr(") && lowerContent.Contains("&"))
        {
            score += 20;
            reasons.Add("字符拼接混淆(chr + &)");
        }

        // 检查长字符串拼接
        if (Regex.Matches(content, @"&\s*""").Count > 5)
        {
            score += 15;
            reasons.Add("频繁字符串拼接(混淆)");
        }

        return (score, reasons);
    }

    /// <summary>分析批处理脚本</summary>
    private static (int Score, List<string> Reasons) AnalyzeBatch(string content, string lowerContent)
    {
        var reasons = new List<string>();
        int score = 0;

        // 批处理危险命令
        var batchDangerous = new (string Pattern, int Score, string Reason)[]
        {
            ("powershell", 35, "调用 PowerShell"),
            ("cmd.exe /c", 25, "执行命令"),
            ("certutil", 30, "证书工具(常用于下载)"),
            ("bitsadmin", 30, "BITS 后台下载"),
            ("reg add", 25, "修改注册表"),
            ("reg delete", 25, "删除注册表"),
            ("schtasks", 25, "计划任务操作"),
            ("net user", 20, "用户管理"),
            ("net localgroup", 20, "用户组管理"),
            ("attrib", 15, "文件属性修改"),
            ("icacls", 20, "权限修改"),
            ("takeown", 20, "获取所有权"),
        };

        foreach (var (pattern, cmdScore, reason) in batchDangerous)
        {
            if (lowerContent.Contains(pattern))
            {
                score += cmdScore;
                reasons.Add(reason);
            }
        }

        // 检查环境变量混淆
        if (lowerContent.Contains("%comspec%") || lowerContent.Contains("%windir%"))
        {
            score += 10;
            reasons.Add("环境变量引用(可能用于混淆)");
        }

        return (score, reasons);
    }

    /// <summary>通用脚本分析</summary>
    private static (int Score, List<string> Reasons) AnalyzeCommon(string content, string lowerContent)
    {
        var reasons = new List<string>();
        int score = 0;

        // 检查网络操作
        var urlMatches = UrlRegex.Matches(content);
        if (urlMatches.Count > 0)
        {
            score += 15;
            reasons.Add($"发现 URL 引用({urlMatches.Count} 个)");
        }

        var ipMatches = IpAddressRegex.Matches(content);
        if (ipMatches.Count > 0)
        {
            score += 10;
            reasons.Add($"发现 IP 地址({ipMatches.Count} 个)");
        }

        // 检查文件系统操作
        var fileOps = new[]
        {
            ("filesystemobject", 15, "文件系统操作"),
            ("createobject", 10, "创建 COM 对象"),
            ("shell.application", 25, "Shell 应用程序"),
            ("wscript.shell", 25, "WScript.Shell"),
        };

        foreach (var (pattern, opScore, reason) in fileOps)
        {
            if (lowerContent.Contains(pattern))
            {
                score += opScore;
                reasons.Add(reason);
            }
        }

        // 检查编码/加密操作
        if (lowerContent.Contains("base64") || lowerContent.Contains("frombase64string"))
        {
            score += 15;
            reasons.Add("Base64 编码/解码操作");
        }

        // 检查长字符串（可能是编码载荷）
        if (content.Length > 1000)
        {
            // 计算可打印字符密度
            int printableCount = content.Count(c => c >= 32 && c <= 126);
            double density = (double)printableCount / content.Length;
            if (density > 0.9)
            {
                score += 10;
                reasons.Add("高密度可打印字符(可能包含编码内容)");
            }
        }

        return (score, reasons);
    }

    /// <summary>提取 PowerShell 编码命令</summary>
    private static string? ExtractEncodedCommand(string commandLine)
    {
        // 尝试多种格式
        string[] patterns = new[]
        {
            @"-EncodedCommand\s+([A-Za-z0-9+/=]+)",
            @"-enc\s+([A-Za-z0-9+/=]+)",
            @"-e\s+([A-Za-z0-9+/=]+)",
        };

        foreach (var pattern in patterns)
        {
            var match = Regex.Match(commandLine, pattern, RegexOptions.IgnoreCase);
            if (match.Success)
                return match.Groups[1].Value;
        }

        return null;
    }
}

/// <summary>脚本类型枚举</summary>
public enum ScriptType
{
    Unknown,
    PowerShell,
    Vbscript,
    Javascript,
    Batch,
    Shell
}
