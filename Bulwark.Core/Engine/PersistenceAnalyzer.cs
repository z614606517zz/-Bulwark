using System;
using System.Collections.Generic;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// 持久化项风险分析器。对每个自启动持久化项(<see cref="PersistenceEntry"/>)研判风险。
///
/// 复用策略:把持久化项的「可执行路径 + 命令行」构造成一个合成的进程创建事件,
/// 交给 <see cref="ThreatDetector"/> 跑完整启发式(LOLBin 滥用 / 凭据访问 / 命令混淆 /
/// 进程伪装 / 可疑目录 / 无签名 等),从而无需重复实现检测逻辑;再叠加「该自启动点本身
/// 对应的 ATT&CK 持久化技战术」标注,并经 <see cref="AttackAnnotator"/> 统一汇总。
///
/// 设计原则:持久化「位置」本身是中性的(大量合法软件用 Run 键/服务/计划任务自启),
/// 因此位置只贡献技战术标注与少量基础分,真正的风险来自「自启动的是什么、怎么跑的」。
/// 纯函数,无状态,线程安全。
/// </summary>
public static class PersistenceAnalyzer
{
    /// <summary>分析并就地填充 <paramref name="entry"/> 的 RiskScore / RiskReasons / Techniques。</summary>
    public static void Analyze(PersistenceEntry entry)
    {
        // 1) 构造合成事件,复用 ThreatDetector 的全部启发式(其证据链已含 LOLBin/凭据等带 T 编号的项)
        var synthetic = new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            ActorPath = entry.ImagePath ?? entry.Command,
            CommandLine = entry.Command,
            ActorSigned = entry.Signed ?? false,
            ActorPublisher = entry.Publisher,
            Target = entry.Location
        };
        ThreatDetector.Analyze(synthetic);

        int score = synthetic.RiskScore;
        var reasons = new List<string>(synthetic.RiskReasons);

        // 2) 叠加该自启动点本身的 ATT&CK 技战术标注(作为独立证据,供注解器提取)
        string tech = TechniqueFor(entry.Category);
        if (!string.IsNullOrEmpty(tech))
        {
            string posReason = $"{CategoryLabel(entry.Category)}自启动持久化({tech})";
            reasons.Add(posReason);
            synthetic.AddEvidence("PersistenceAnalyzer", EvidenceKind.Info, posReason, alsoReason: false);
        }

        // 3) 高危持久化点轻微加权(映像劫持 / WMI 订阅 / AppInit 几乎只被恶意使用)
        switch (entry.Category)
        {
            case PersistenceCategory.IfeoDebugger:
                score += 25;
                reasons.Add("映像劫持(IFEO Debugger):劫持目标程序启动,极少合法用途");
                break;
            case PersistenceCategory.WmiSubscription:
                score += 20;
                reasons.Add("WMI 事件订阅:无文件持久化,常用于隐蔽驻留");
                break;
            case PersistenceCategory.AppInitDll:
                score += 20;
                reasons.Add("AppInit_DLLs:注入所有 GUI 进程,高危持久化");
                break;
        }

        entry.RiskScore = Math.Min(100, score);
        entry.RiskReasons = reasons;

        // 4) 汇总技战术(含 ThreatDetector 证据里的 LOLBin/凭据编号 + 上面的位置技战术)
        AttackAnnotator.Annotate(synthetic);
        entry.Techniques = synthetic.Techniques;
    }

    /// <summary>该持久化类别对应的主 ATT&CK 技战术编号。</summary>
    public static string TechniqueFor(PersistenceCategory c) => c switch
    {
        PersistenceCategory.RegistryRun => "T1547.001",
        PersistenceCategory.RegistryRunOnce => "T1547.001",
        PersistenceCategory.StartupFolder => "T1547.001",
        PersistenceCategory.ScheduledTask => "T1053.005",
        PersistenceCategory.Service => "T1543.003",
        PersistenceCategory.WmiSubscription => "T1546.003",
        PersistenceCategory.IfeoDebugger => "T1546.012",
        PersistenceCategory.Winlogon => "T1547.004",
        PersistenceCategory.AppInitDll => "T1546.010",
        _ => string.Empty
    };

    private static string CategoryLabel(PersistenceCategory c) => c switch
    {
        PersistenceCategory.RegistryRun => "注册表 Run 键",
        PersistenceCategory.RegistryRunOnce => "注册表 RunOnce 键",
        PersistenceCategory.StartupFolder => "启动文件夹",
        PersistenceCategory.ScheduledTask => "计划任务",
        PersistenceCategory.Service => "Windows 服务",
        PersistenceCategory.WmiSubscription => "WMI 事件订阅",
        PersistenceCategory.IfeoDebugger => "映像劫持",
        PersistenceCategory.Winlogon => "Winlogon",
        PersistenceCategory.AppInitDll => "AppInit_DLLs",
        _ => "其它"
    };
}
