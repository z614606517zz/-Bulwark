using System;
using System.Collections.Generic;
using System.Linq;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// 杀伤链阶段分析器(独创·基于进程树叙事)。
///
/// 传统检测对单个事件孤立打分,容易漏掉"每步都不够格、串起来却是完整入侵"的攻击。
/// 本分析器接收 <see cref="ProcessChainTracker"/> 还原的进程链上下文
/// (<see cref="SecurityEvent.ChainContext"/>),把每个事件归类到 ATT&CK 风格的
/// **战术阶段**(初始执行 / 防御规避 / 持久化 / 凭据访问 / 横向移动 / 影响破坏 等),
/// 然后按"同一进程树覆盖了多少个不同阶段"来研判:
///
///   · 覆盖阶段越多 => 越像一次有组织的完整攻击(而非单一可疑动作);
///   · 命中"高危阶段顺序"(如 执行→防御规避→持久化)额外加权;
///   · 单纯一个阶段(哪怕分高)不在此加分,交由其它检测器处理,避免误报。
///
/// 输出 (score, reasons, stageSummary),由 <see cref="ThreatDetector"/> 汇入。
/// 这是"看整条攻击叙事"的能力,正常软件极少在短时间内横跨多个攻击阶段。
/// </summary>
public static class KillChainAnalyzer
{
    /// <summary>ATT&CK 风格战术阶段(精简版,聚焦终端可观测维度)。</summary>
    [Flags]
    public enum Stage
    {
        None = 0,
        Execution = 1 << 0,        // 执行(脚本解释器/LOLBin 落地运行)
        DefenseEvasion = 1 << 1,   // 防御规避(关杀软/改策略/混淆/BYOVD)
        Persistence = 1 << 2,      // 持久化(启动项/服务/计划任务/WMI 订阅)
        CredentialAccess = 1 << 3, // 凭据访问(LSASS/SAM/浏览器密码库)
        LateralMovement = 1 << 4,  // 横向移动(远程进程/服务/共享)
        Impact = 1 << 5,           // 影响破坏(删卷影/勒索信/改引导)
        CommandControl = 1 << 6,   // 命令控制(可疑外联/下载执行)
        Discovery = 1 << 7,        // 侦察(系统/账户/网络信息收集)
    }

    /// <summary>三阶段及以上判定为"多阶段攻击链"。</summary>
    private const int MultiStageThreshold = 3;

    /// <summary>
    /// 分析进程链上下文,识别多阶段攻击。返回累加分、原因、命中的阶段集合。
    /// <paramref name="context"/> 通常为 <see cref="SecurityEvent.ChainContext"/>。
    /// </summary>
    public static (int Score, List<string> Reasons, Stage Stages) Analyze(
        IReadOnlyList<ChainEventInfo>? context)
    {
        var reasons = new List<string>();
        if (context is null || context.Count == 0)
            return (0, reasons, Stage.None);

        Stage stages = Stage.None;
        var perStageEvidence = new Dictionary<Stage, string>();

        foreach (var ev in context)
        {
            var s = Classify(ev);
            if (s == Stage.None) continue;
            // 记录每个阶段第一条证据(用于可读输出)
            foreach (Stage flag in Enum.GetValues(typeof(Stage)))
            {
                if (flag == Stage.None) continue;
                if ((s & flag) == flag && !perStageEvidence.ContainsKey(flag))
                    perStageEvidence[flag] = DescribeEvidence(ev, flag);
            }
            stages |= s;
        }

        int stageCount = CountStages(stages);
        if (stageCount < MultiStageThreshold)
            return (0, reasons, stages); // 阶段不足,不在此加分(降误报)

        int score = 0;

        // 1) 多阶段覆盖度基础分:阶段越多越像完整攻击
        score += (stageCount - MultiStageThreshold + 1) * 20;
        reasons.Add($"进程链横跨 {stageCount} 个攻击阶段({DescribeStages(stages)},疑似完整攻击链)");

        // 2) 高危阶段组合额外加权
        if (Has(stages, Stage.Execution) && Has(stages, Stage.Persistence))
        {
            score += 12;
            reasons.Add("执行 + 持久化组合(驻留意图明确)");
        }
        if (Has(stages, Stage.DefenseEvasion) &&
            (Has(stages, Stage.Persistence) || Has(stages, Stage.CredentialAccess)))
        {
            score += 14;
            reasons.Add("防御规避 + 持久化/凭据访问组合(高危)");
        }
        if (Has(stages, Stage.CredentialAccess) && Has(stages, Stage.LateralMovement))
        {
            score += 18;
            reasons.Add("凭据访问 + 横向移动组合(疑似定向入侵)");
        }
        if (Has(stages, Stage.Impact) &&
            (Has(stages, Stage.Execution) || Has(stages, Stage.DefenseEvasion)))
        {
            score += 20;
            reasons.Add("破坏性影响 + 执行/规避组合(疑似勒索/擦除)");
        }

        // 3) 附上每阶段的代表性证据(便于用户/大模型理解叙事)
        foreach (var kv in perStageEvidence.OrderBy(k => (int)k.Key))
            reasons.Add($"· [{StageName(kv.Key)}] {kv.Value}");

        return (Math.Min(score, 100), reasons, stages);
    }

    /// <summary>把单个链事件归类到一个或多个战术阶段。</summary>
    private static Stage Classify(ChainEventInfo ev)
    {
        Stage s = Stage.None;
        string actor = SafeName(ev.ActorPath);
        string target = (ev.Target ?? string.Empty).ToLowerInvariant();
        string cmd = (ev.CommandLine ?? string.Empty).ToLowerInvariant();

        // --- 执行:脚本解释器 / LOLBin 进程创建 ---
        if (ev.Type == EventType.ProcessCreate && IsScriptHost(actor))
            s |= Stage.Execution;

        // --- 命令控制 / 下载执行 ---
        if (ev.Type == EventType.NetworkConnect && IsScriptHost(actor))
            s |= Stage.CommandControl;
        if (ContainsAny(cmd, "downloadstring", "downloadfile", "invoke-webrequest",
                "certutil", "bitsadmin", "http://", "https://"))
            s |= Stage.CommandControl;

        // --- 防御规避 ---
        if (ContainsAny(cmd, "bypass", "-enc", "-w hidden", "-windowstyle hidden",
                "disableantispyware", "disablerealtimemonitoring", "set-mppreference",
                "testsigning", "nointegritychecks"))
            s |= Stage.DefenseEvasion;
        if (ev.Type == EventType.ProcessTerminate && IsSecurityProcess(target))
            s |= Stage.DefenseEvasion;
        if (ev.Type == EventType.ImageLoad && target.EndsWith(".sys"))
            s |= Stage.DefenseEvasion; // 可疑驱动加载(BYOVD)

        // --- 持久化 ---
        if (ev.Type == EventType.RegistryWrite &&
            ContainsAny(target, @"\run\", @"\runonce\", "winlogon", "userinit",
                "image file execution options", @"\services\", "appinit_dlls"))
            s |= Stage.Persistence;
        if (ev.Type == EventType.FileWrite &&
            ContainsAny(target, @"\startup\", @"\tasks\", "normal.dotm", @"\xlstart\"))
            s |= Stage.Persistence;
        if (ContainsAny(cmd, "schtasks", "__eventfilter", "commandlineeventconsumer",
                "new-scheduledtask"))
            s |= Stage.Persistence;

        // --- 凭据访问 ---
        if (ContainsAny(target, "lsass.exe", @"\config\sam", "ntds.dit",
                "login data", "logins.json", @"\credentials\", @"\protect\"))
            s |= Stage.CredentialAccess;
        if (ContainsAny(cmd, "mimikatz", "sekurlsa", "lsadump", "comsvcs.dll, minidump"))
            s |= Stage.CredentialAccess;

        // --- 横向移动 ---
        if (ContainsAny(cmd, "psexec", "/node:", "-computername", "enter-pssession",
                "winrs", @"\admin$", @"\c$", "wmic /node"))
            s |= Stage.LateralMovement;

        // --- 影响破坏 ---
        if (ContainsAny(cmd, "vssadmin", "shadowcopy", "wbadmin", "delete catalog",
                "recoveryenabled no", "bcdedit"))
            s |= Stage.Impact;
        if (ContainsAny(target, "_readme.txt", "how_to_decrypt", "recover", @"\boot\bcd"))
            s |= Stage.Impact;

        // --- 侦察 ---
        if (ContainsAny(cmd, "whoami", "ipconfig", "net view", "net group",
                "nltest", "systeminfo", "tasklist", "arp -a", "query user"))
            s |= Stage.Discovery;

        return s;
    }

    private static string DescribeEvidence(ChainEventInfo ev, Stage stage)
    {
        string actor = SafeName(ev.ActorPath);
        string detail = !string.IsNullOrEmpty(ev.CommandLine)
            ? Trim(ev.CommandLine, 80)
            : (!string.IsNullOrEmpty(ev.Target) ? Trim(ev.Target, 80) : ev.Type.ToString());
        return $"{actor}(pid={ev.ActorPid}): {detail}";
    }

    // ---- 辅助 ----

    private static readonly string[] ScriptHosts =
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "msbuild.exe",
        "installutil.exe", "wmic.exe"
    };

    private static readonly string[] SecurityProcessHints =
    {
        "msmpeng.exe", "mpdefendercoreservice.exe", "360tray.exe", "360sd.exe",
        "zhudongfangyu.exe", "hipstray.exe", "usysdiag.exe", "qqpcrtp.exe",
        "kxetray.exe", "avp.exe", "ekrn.exe", "mcshield.exe"
    };

    private static bool IsScriptHost(string name) => ScriptHosts.Contains(name);
    private static bool IsSecurityProcess(string target)
        => SecurityProcessHints.Any(p => target.Contains(p));

    private static bool ContainsAny(string s, params string[] tokens)
        => !string.IsNullOrEmpty(s) && tokens.Any(t => s.Contains(t));

    private static bool Has(Stage stages, Stage flag) => (stages & flag) == flag;

    private static int CountStages(Stage stages)
    {
        int count = 0;
        foreach (Stage flag in Enum.GetValues(typeof(Stage)))
            if (flag != Stage.None && (stages & flag) == flag) count++;
        return count;
    }

    private static string DescribeStages(Stage stages)
        => string.Join("→", EnumerateStages(stages).Select(StageName));

    private static IEnumerable<Stage> EnumerateStages(Stage stages)
    {
        foreach (Stage flag in Enum.GetValues(typeof(Stage)))
            if (flag != Stage.None && (stages & flag) == flag) yield return flag;
    }

    private static string StageName(Stage s) => s switch
    {
        Stage.Execution => "执行",
        Stage.DefenseEvasion => "防御规避",
        Stage.Persistence => "持久化",
        Stage.CredentialAccess => "凭据访问",
        Stage.LateralMovement => "横向移动",
        Stage.Impact => "破坏影响",
        Stage.CommandControl => "命令控制",
        Stage.Discovery => "侦察",
        _ => s.ToString()
    };

    private static string SafeName(string? path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        try { return System.IO.Path.GetFileName(path).ToLowerInvariant(); }
        catch { return path.ToLowerInvariant(); }
    }

    private static string Trim(string s, int max)
        => s.Length <= max ? s : s.Substring(0, max) + "…";
}
