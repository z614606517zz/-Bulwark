using System;
using System.Collections.Generic;
using System.Linq;

namespace Bulwark.Core.Engine;

/// <summary>
/// LOLBins(Living-off-the-Land Binaries,白利用)滥用分析器(独创·签名无关)。
///
/// 攻击者绕过「签名可信」的首选路径:不带自己的恶意 EXE,而是驱动系统自带、
/// 微软签名的合法程序(rundll32 / regsvr32 / mshta / certutil / bitsadmin /
/// msbuild / installutil / msiexec / wmic …)去下载、解码、执行载荷。
/// 这些二进制本身签名健康,会命中「强可信 / 健康签名放行」通道 —— 因此**只看签名
/// 永远抓不到**,必须看「这个二进制 + 这串参数」的组合是否构成已知滥用技战术。
///
/// 本分析器对每个已知 LOLBin 检查其**特征性滥用参数**(而非泛化 token 匹配),
/// 命中即给出分值、可读原因与对应 ATT&CK 技战术编号(如 T1218.010 Squiblydoo)。
///
/// 设计原则(遵循全局低误报):
///   · <b>HardSignal</b>:二进制 + 参数构成「远程载荷 / 无文件执行 / 凭据转储」等
///     高置信滥用(如 regsvr32 /i:http scrobj.dll、mshta http://…、certutil -urlcache http)。
///     这类几乎只有攻击者会做,直接作为硬恶意指标,使其失去签名放行豁免。
///   · 软信号:LOLBin 出现了「可疑但未必恶意」的参数形态(如 rundll32 调用非常规导出),
///     仅累加分,交由互证机制升格,避免误伤合法的系统/厂商调用。
///
/// 纯函数,无状态,线程安全。输出 (Score, Reasons, HardSignal)。
/// </summary>
public static class LolbinAnalyzer
{
    /// <summary>
    /// 分析一次进程创建的 LOLBin 滥用嫌疑。
    /// </summary>
    /// <param name="actorPath">主体进程映像路径(用于识别是哪个 LOLBin)。</param>
    /// <param name="commandLine">主体进程命令行。</param>
    /// <returns>累加分、可读原因(含 ATT&CK 编号)、是否构成高置信硬滥用信号。</returns>
    public static (int Score, List<string> Reasons, bool HardSignal) Analyze(
        string? actorPath, string? commandLine)
    {
        var reasons = new List<string>();
        if (string.IsNullOrEmpty(commandLine))
            return (0, reasons, false);

        string name = SafeName(actorPath);
        if (string.IsNullOrEmpty(name) || !KnownLolbins.Contains(name))
            return (0, reasons, false);

        string cmd = commandLine.ToLowerInvariant();
        bool hasRemote = ContainsAny(cmd, "http://", "https://", "ftp://", @"\\");

        int score = 0;
        bool hard = false;

        void Hit(int delta, string reason, bool isHard = false)
        {
            score += delta;
            reasons.Add(reason);
            if (isHard) hard = true;
        }

        switch (name)
        {
            // ── regsvr32:Squiblydoo —— /i:http 远程 scrobj.dll 执行 COM scriptlet ──
            case "regsvr32.exe":
                if (cmd.Contains("scrobj.dll") || cmd.Contains("/i:"))
                {
                    if (hasRemote && (cmd.Contains("scrobj") || cmd.Contains("/i:http")))
                        Hit(55, "regsvr32 远程加载 scriptlet(Squiblydoo 无文件执行,T1218.010)", isHard: true);
                    else if (cmd.Contains("/i:") && cmd.Contains("scrobj"))
                        Hit(35, "regsvr32 经 scrobj.dll 执行 scriptlet(T1218.010)", isHard: true);
                }
                if (ContainsAny(cmd, "/s ", "/u") && hasRemote)
                    Hit(30, "regsvr32 静默注册远程组件(T1218.010)", isHard: true);
                break;

            // ── rundll32:多种代理执行 ──
            case "rundll32.exe":
                if (ContainsAny(cmd, "javascript:", "vbscript:", "mshtml", "runhtmlapplication"))
                    Hit(50, "rundll32 执行内联脚本(mshtml/RunHTMLApplication,T1218.011)", isHard: true);
                else if (cmd.Contains("comsvcs.dll") && cmd.Contains("minidump"))
                    Hit(55, "rundll32 经 comsvcs 转储 LSASS 内存(凭据窃取,T1003.001)", isHard: true);
                else if (cmd.Contains("url.dll") && ContainsAny(cmd, "openurl", "fileprotocolhandler"))
                    Hit(30, "rundll32 经 url.dll 打开远程资源(T1218.011)", isHard: hasRemote);
                else if (cmd.Contains("shell32.dll") && cmd.Contains("control_rundll") && hasRemote)
                    Hit(28, "rundll32 经 shell32 加载远程 .cpl(T1218.011)", isHard: true);
                else if (hasRemote)
                    Hit(20, "rundll32 命令行含远程地址(疑似代理执行,T1218.011)");
                break;

            // ── mshta:执行 HTA / 内联脚本,常远程 ──
            case "mshta.exe":
                if (hasRemote)
                    Hit(50, "mshta 执行远程 HTA/脚本(T1218.005)", isHard: true);
                else if (ContainsAny(cmd, "javascript:", "vbscript:"))
                    Hit(45, "mshta 执行内联脚本(T1218.005)", isHard: true);
                else if (cmd.Contains(".hta"))
                    Hit(18, "mshta 运行 HTA 文件(T1218.005)");
                break;

            // ── certutil:下载 / 解码载荷 ──
            case "certutil.exe":
                if (ContainsAny(cmd, "-urlcache", "-verifyctl", "-f ") && hasRemote)
                    Hit(50, "certutil 远程下载文件(伪装证书工具,T1105/T1140)", isHard: true);
                else if (ContainsAny(cmd, "-decode", "-decodehex"))
                    Hit(30, "certutil 解码载荷(还原隐藏可执行体,T1140)", isHard: true);
                else if (cmd.Contains("-encode"))
                    Hit(15, "certutil 编码数据(可能用于外传/隐藏)");
                break;

            // ── bitsadmin:后台传输下载 ──
            case "bitsadmin.exe":
                if (cmd.Contains("/transfer") && hasRemote)
                    Hit(45, "bitsadmin 后台下载文件(T1197/T1105)", isHard: true);
                else if (ContainsAny(cmd, "/addfile", "/setnotifycmdline"))
                    Hit(30, "bitsadmin 配置传输任务/回调命令(T1197)", isHard: cmd.Contains("/setnotifycmdline"));
                break;

            // ── msbuild / installutil / regasm / regsvcs:编译/反射加载内联代码 ──
            case "msbuild.exe":
                if (ContainsAny(cmd, ".csproj", ".xml", ".targets", ".proj") || hasRemote)
                    Hit(40, "msbuild 执行内联任务工程(无文件 C# 执行,T1127.001)", isHard: true);
                break;
            case "installutil.exe":
                if (ContainsAny(cmd, "/logfile=", "/u", "/logtoconsole=false"))
                    Hit(38, "installutil 经卸载钩子执行程序集(T1218.004)", isHard: true);
                break;
            case "regasm.exe":
            case "regsvcs.exe":
                if (ContainsAny(cmd, "/u", ".dll"))
                    Hit(35, $"{name} 注册/卸载钩子执行程序集(T1218.009)", isHard: true);
                break;

            // ── msiexec:安装远程 MSI ──
            case "msiexec.exe":
                if (hasRemote && ContainsAny(cmd, "/i", "/package", "/q"))
                    Hit(42, "msiexec 安装远程 MSI 包(T1218.007)", isHard: true);
                break;

            // ── wmic:进程创建 / 远程节点执行 ──
            case "wmic.exe":
                if (cmd.Contains("process") && cmd.Contains("call") && cmd.Contains("create"))
                    Hit(35, "wmic 创建进程(代理执行,T1047)", isHard: true);
                else if (cmd.Contains("/node:"))
                    Hit(40, "wmic 远程节点执行(横向移动,T1047)", isHard: true);
                else if (ContainsAny(cmd, "os get", "/format:http"))
                    Hit(25, "wmic 经远程 XSL 执行(T1220)", isHard: hasRemote);
                break;

            // ── mavinject:向远程进程注入 DLL ──
            case "mavinject.exe":
                if (cmd.Contains("/injectrunning"))
                    Hit(48, "mavinject 向运行中进程注入 DLL(T1218.013)", isHard: true);
                break;

            // ── 其他代理执行 LOLBins ──
            case "forfiles.exe":
                if (cmd.Contains("/c") && ContainsAny(cmd, "cmd", "powershell"))
                    Hit(28, "forfiles 代理执行命令(T1202)", isHard: true);
                break;
            case "pcalua.exe":
                if (cmd.Contains("-a"))
                    Hit(28, "pcalua(程序兼容助手)代理执行(T1202)", isHard: true);
                break;
            case "scriptrunner.exe":
                if (cmd.Contains("-appvscript"))
                    Hit(30, "scriptrunner 代理执行(T1218)", isHard: true);
                break;
        }

        return (Math.Min(score, 100), reasons, hard);
    }

    /// <summary>命令行是否构成「让签名 LOLBin 失去信任豁免」的高置信滥用(供 TrustPolicy 门禁复用)。</summary>
    public static bool IsAbusedLolbin(string? actorPath, string? commandLine)
    {
        var (_, _, hard) = Analyze(actorPath, commandLine);
        return hard;
    }

    /// <summary>已知会被白利用的系统/框架二进制(小写映像名)。</summary>
    private static readonly HashSet<string> KnownLolbins = new(StringComparer.OrdinalIgnoreCase)
    {
        "regsvr32.exe", "rundll32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
        "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "msiexec.exe",
        "wmic.exe", "mavinject.exe", "forfiles.exe", "pcalua.exe", "scriptrunner.exe",
    };

    private static bool ContainsAny(string s, params string[] tokens)
        => !string.IsNullOrEmpty(s) && tokens.Any(t => s.Contains(t));

    private static string SafeName(string? path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        try { return System.IO.Path.GetFileName(path).ToLowerInvariant(); }
        catch { return path.ToLowerInvariant(); }
    }
}
