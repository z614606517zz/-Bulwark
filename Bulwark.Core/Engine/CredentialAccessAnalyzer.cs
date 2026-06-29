using System;
using System.Collections.Generic;
using System.Linq;

namespace Bulwark.Core.Engine;

/// <summary>
/// 凭据访问 / LSASS 保护分析器(ATT&CK TA0006)。
///
/// 凭据窃取是入侵后横向移动与提权的关键一环,且常借合法签名工具完成
/// (reg.exe 导出 SAM、ntdsutil/esentutl 提取 ntds.dit、rundll32+comsvcs 转储 LSASS),
/// 仅看签名永远抓不到。本分析器从「目标/路径 + 命令行 + 行为类型」语义识别凭据访问:
///
///   · LSASS 内存转储 / 向 lsass 注入远程线程(T1003.001);
///   · 导出 SAM/SECURITY/SYSTEM 蜂巢(reg save、直接访问 \config\SAM,T1003.002);
///   · 提取域控 NTDS.dit(ntdsutil ifm / esentutl / 卷影副本,T1003.003);
///   · 读取浏览器凭据库 / Cookie / DPAPI 主密钥(T1555.003 / T1003);
///
/// 设计原则(低误报):
///   · <b>HardSignal</b>:高置信凭据攻击(reg save sam、ntdsutil、lsass 转储/注入)——
///     置硬指标,并经 TrustPolicy 复用使签名工具失去放行豁免。
///   · 软信号:非属主进程触碰浏览器凭据库等,仅累加分,交互证升格,避免误伤浏览器自身/同步盘。
///
/// 纯函数,无状态,线程安全。输出 (Score, Reasons, HardSignal)。
/// </summary>
public static class CredentialAccessAnalyzer
{
    /// <summary>分析事件的凭据访问嫌疑。</summary>
    public static (int Score, List<string> Reasons, bool HardSignal) Analyze(Models.SecurityEvent e)
    {
        var reasons = new List<string>();
        int score = 0;
        bool hard = false;

        void Hit(int delta, string reason, bool isHard)
        {
            score += delta;
            reasons.Add(reason);
            if (isHard) hard = true;
        }

        string cmd = (e.CommandLine ?? string.Empty).ToLowerInvariant();
        string target = (e.Target ?? string.Empty).ToLowerInvariant();
        string actorName = SafeName(e.ActorPath);

        // ── 1) LSASS:向 lsass 注入远程线程,或转储其内存 ──
        bool targetIsLsass = target.Contains("lsass.exe") || target.EndsWith("\\lsass") || target == "lsass";
        if (e.Type == Models.EventType.RemoteThread && targetIsLsass)
            Hit(55, "向 LSASS 注入远程线程(凭据窃取,T1003.001)", true);

        if ((cmd.Contains("comsvcs.dll") && cmd.Contains("minidump")) ||
            cmd.Contains("sekurlsa") || cmd.Contains("lsadump") ||
            cmd.Contains("mimikatz") || cmd.Contains("invoke-mimikatz"))
            Hit(55, "LSASS 内存转储 / Mimikatz 凭据抓取(T1003.001)", true);

        // LSASS 转储落地文件(.dmp 且上下文提及 lsass)
        if (e.Type is Models.EventType.FileWrite &&
            (target.EndsWith(".dmp") || target.Contains("lsass")) &&
            (target.Contains("lsass") || cmd.Contains("lsass")))
            Hit(45, "疑似 LSASS 内存转储文件落地(T1003.001)", true);

        // ── 2) SAM/SECURITY/SYSTEM 蜂巢导出(本地账户哈希)──
        bool hiveCmd = (cmd.Contains("reg save") || cmd.Contains("reg.exe save") || cmd.Contains("regedit")) &&
                       (cmd.Contains(@"hklm\sam") || cmd.Contains(@"hklm\security") ||
                        cmd.Contains(@"hklm\system") || cmd.Contains("\\sam ") || cmd.Contains(" sam.hiv"));
        if (hiveCmd)
            Hit(50, "导出 SAM/SECURITY/SYSTEM 注册表蜂巢(本地哈希窃取,T1003.002)", true);

        // 直接触碰蜂巢文件(\Windows\System32\config\SAM 等)
        if ((target.Contains(@"\config\sam") || target.Contains(@"\config\security") ||
             target.EndsWith(@"\system32\config\system")) &&
            e.Type is Models.EventType.FileWrite or Models.EventType.FileDelete)
            Hit(40, "直接访问 SAM/SECURITY 注册表蜂巢文件(T1003.002)", true);

        // ── 3) 域控 NTDS.dit 提取 ──
        if (cmd.Contains("ntdsutil") || cmd.Contains("ntds.dit") ||
            (cmd.Contains("esentutl") && cmd.Contains("ntds")) ||
            (cmd.Contains("ifm") && cmd.Contains("create")))
            Hit(50, "提取域控 NTDS.dit 凭据库(T1003.003)", true);
        if (target.Contains("ntds.dit"))
            Hit(45, "访问 NTDS.dit 数据库文件(T1003.003)", true);

        // ── 4) 浏览器凭据库 / Cookie / DPAPI(软信号:仅非属主进程触碰才记) ──
        bool isBrowser = BrowserProcesses.Contains(actorName);
        bool credStoreTarget = ContainsAny(target,
            @"\login data", "logins.json", "key4.db", "signons.sqlite",
            @"\cookies", "cookies.sqlite", @"\web data");
        if (credStoreTarget && !isBrowser)
            Hit(28, "非浏览器进程读取浏览器凭据库/Cookie(T1555.003)", false);

        // DPAPI 主密钥(解密保存的凭据)
        if (target.Contains(@"\microsoft\protect\") && !IsSystemActor(actorName))
            Hit(24, "访问 DPAPI 主密钥目录(凭据解密,T1003)", false);

        // vaultcmd / 凭据管理器枚举
        if (cmd.Contains("vaultcmd") && cmd.Contains("/list"))
            Hit(20, "枚举 Windows 凭据保管库(T1555.004)", false);

        return (Math.Min(score, 100), reasons, hard);
    }

    /// <summary>是否构成「让签名工具失去信任豁免」的高置信凭据攻击(供 TrustPolicy 门禁复用)。</summary>
    public static bool IsHardCredentialAccess(Models.SecurityEvent e)
    {
        var (_, _, hard) = Analyze(e);
        return hard;
    }

    private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe",
        "brave.exe", "360se.exe", "360chrome.exe", "qqbrowser.exe", "vivaldi.exe",
    };

    private static bool IsSystemActor(string name)
        => name is "lsass.exe" or "services.exe" or "svchost.exe" or "winlogon.exe" or "system";

    private static bool ContainsAny(string s, params string[] tokens)
        => !string.IsNullOrEmpty(s) && tokens.Any(t => s.Contains(t));

    private static string SafeName(string? path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        try { return System.IO.Path.GetFileName(path).ToLowerInvariant(); }
        catch { return path.ToLowerInvariant(); }
    }
}
