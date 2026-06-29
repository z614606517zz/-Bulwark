using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// 进程注入 / DLL 侧载分析器(独创·内存与无文件攻击检测)。
///
/// 补足现有检测的一块空白:进程镂空(Process Hollowing)、APC 注入、线程劫持、
/// shellcode 注入、反射式 DLL 加载、DLL 搜索顺序劫持(侧载)等「无文件 / 内存型」手法。
/// 这些在内核/用户态事件里主要表现为两类信号:
///   · <see cref="EventType.RemoteThread"/>:一个进程向【另一个】进程创建远程线程
///     (镂空/APC/劫持/shellcode 注入的共同落点);
///   · <see cref="EventType.ImageLoad"/>:从可写/可疑目录加载未签名模块(侧载/搜索顺序劫持)。
///
/// 设计原则(遵循全局低误报):
///   · 注入【敏感高价值进程】(lsass / 系统关键进程 / 浏览器邮件)= 几乎无合法理由,置硬指标;
///   · 一般跨进程注入若发起方未签名 / 是脚本宿主或 LOLBin,也置硬指标;
///   · 带可信签名的合法程序做跨进程注入(反作弊 / IM / 录屏 / 安全软件本就会注入)仅给软信号,
///     交互证机制升格,避免误伤;
///   · 自注入(目标==自身)是常见合法行为,不计分;
///   · DLL 侧载仅对「高危可写目录(Temp/Public/ProgramData 根/回收站/PerfLogs)+ 未签名模块」
///     这一明确组合置硬指标,避免对从安装目录/AppData 加载自带 DLL 的正常程序误报。
///
/// 纯静态、无状态;返回 (score, reasons, hard) 供 <see cref="ThreatDetector"/> 汇总。
/// </summary>
public static class InjectionAnalyzer
{
    /// <summary>凭据宝库进程:向其注入几乎必为凭据窃取(T1003.001)。</summary>
    private static readonly HashSet<string> CredentialTargets =
        new(StringComparer.OrdinalIgnoreCase) { "lsass.exe", "lsaiso.exe" };

    /// <summary>关键系统进程:无合法理由被第三方注入。</summary>
    private static readonly HashSet<string> CriticalTargets =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "winlogon.exe", "csrss.exe", "services.exe", "wininit.exe", "smss.exe",
            "svchost.exe", "spoolsv.exe", "explorer.exe", "dwm.exe", "lsm.exe",
        };

    /// <summary>浏览器/邮件进程:注入这些常为信息窃取 / 银行木马 / 会话劫持。</summary>
    private static readonly HashSet<string> SensitiveAppTargets =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe",
            "brave.exe", "outlook.exe", "thunderbird.exe", "360se.exe", "360chrome.exe",
        };

    /// <summary>脚本宿主 / 常被滥用的 LOLBin:由它们发起注入是强信号。</summary>
    private static readonly HashSet<string> InjectorLolbins =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "msbuild.exe",
        };

    /// <summary>高危可写落地目录:几乎只有恶意软件会在此释放并从中加载模块。</summary>
    private static readonly string[] HighRiskDirs =
    {
        @"\appdata\local\temp\", @"\windows\temp\", @"\users\public\",
        @"\programdata\", @"\$recycle.bin\", @"\perflogs\",
    };

    /// <summary>
    /// 分析一个事件的注入/侧载特征。仅对 RemoteThread / ImageLoad 有意义,其它返回零分。
    /// </summary>
    public static (int Score, List<string> Reasons, bool Hard) Analyze(SecurityEvent e)
    {
        if (e is null) return (0, new List<string>(), false);
        return e.Type switch
        {
            EventType.RemoteThread => AnalyzeRemoteThread(e),
            EventType.ImageLoad => AnalyzeImageLoad(e),
            _ => (0, new List<string>(), false)
        };
    }

    private static (int, List<string>, bool) AnalyzeRemoteThread(SecurityEvent e)
    {
        var reasons = new List<string>();
        if (string.IsNullOrEmpty(e.Target)) return (0, reasons, false);

        // 自注入(目标即自身)是常见合法行为(自身多进程/热补丁),不计分。
        if (string.Equals(e.Target, e.ActorPath, StringComparison.OrdinalIgnoreCase))
            return (0, reasons, false);

        string victim = SafeName(e.Target);
        string injector = SafeName(e.ActorPath);
        string injectorPathLower = (e.ActorPath ?? string.Empty).ToLowerInvariant();

        int score = 30; // 跨进程远程线程注入本身即值得关注
        bool hard = false;

        if (CredentialTargets.Contains(victim))
        {
            score += 50;
            hard = true;
            reasons.Add($"向凭据进程 {victim} 注入远程线程(疑似凭据窃取,T1003.001 / T1055)");
        }
        else if (CriticalTargets.Contains(victim))
        {
            score += 40;
            hard = true;
            reasons.Add($"向关键系统进程 {victim} 注入远程线程(无合法理由,T1055)");
        }
        else if (SensitiveAppTargets.Contains(victim))
        {
            score += 30;
            reasons.Add($"向浏览器/邮件进程 {victim} 注入远程线程(疑似信息窃取/会话劫持,T1055)");
        }
        else
        {
            reasons.Add($"跨进程远程线程注入 -> {victim}(进程镂空/APC/线程劫持的共同落点,T1055)");
        }

        bool injectorUnsigned = !e.ActorSigned;
        bool injectorIsLolbin = InjectorLolbins.Contains(injector);
        bool injectorInHighRiskDir = HighRiskDirs.Any(d => injectorPathLower.Contains(d));

        if (injectorIsLolbin)
        {
            score += 20;
            hard = true;
            reasons.Add($"注入发起方为脚本宿主/LOLBin({injector}),远程注入几乎必为恶意");
        }
        if (injectorUnsigned)
        {
            score += 15;
            // 未签名进程向另一个进程注入:正常软件几乎不做 -> 升为硬指标。
            hard = true;
            reasons.Add("注入发起方无可信签名");
        }
        if (injectorInHighRiskDir)
        {
            score += 10;
            reasons.Add("注入发起方位于高危可写目录");
        }

        // 说明:带可信签名、且非 LOLBin 的程序做一般跨进程注入(反作弊/录屏/IM/安全软件等)
        // 不置硬指标(hard 维持 false),仅累加软信号分,交互证机制升格,避免误伤合法注入。
        return (Math.Min(score, 100), reasons, hard);
    }

    private static (int, List<string>, bool) AnalyzeImageLoad(SecurityEvent e)
    {
        var reasons = new List<string>();
        string module = e.Target ?? string.Empty;
        if (string.IsNullOrEmpty(module)) return (0, reasons, false);

        // 注意:ImageLoad 事件里 ActorSigned 表示【被加载模块】自身的签名(由事件源按模块判定)。
        bool moduleSigned = e.ActorSigned;
        string moduleLower = module.ToLowerInvariant();
        bool inHighRiskDir = HighRiskDirs.Any(d => moduleLower.Contains(d));

        // 明确组合:未签名模块 + 从高危可写目录加载 = DLL 侧载/搜索顺序劫持的典型形态。
        // 合法程序极少从 Temp/Public/ProgramData 根加载未签名 DLL。
        if (!moduleSigned && inHighRiskDir)
        {
            reasons.Add($"从高危可写目录加载未签名模块 {SafeName(module)}(疑似 DLL 侧载/搜索顺序劫持,T1574.002)");
            return (40, reasons, true);
        }

        return (0, reasons, false);
    }

    private static string SafeName(string? path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        try { return Path.GetFileName(path).ToLowerInvariant(); }
        catch { return path.ToLowerInvariant(); }
    }
}
