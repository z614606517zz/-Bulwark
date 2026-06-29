using System;

namespace Bulwark.Core.Models;

/// <summary>自启动持久化点的类别。对应不同的 ATT&CK 持久化技战术。</summary>
public enum PersistenceCategory
{
    RegistryRun,        // HKLM/HKCU ...\CurrentVersion\Run(T1547.001)
    RegistryRunOnce,    // ...\RunOnce(T1547.001)
    StartupFolder,      // 启动文件夹(T1547.001)
    ScheduledTask,      // 计划任务(T1053.005)
    Service,            // Windows 服务(T1543.003)
    WmiSubscription,    // WMI 事件订阅(T1546.003)
    IfeoDebugger,       // 映像劫持 Image File Execution Options Debugger(T1546.012)
    Winlogon,           // Winlogon Userinit/Shell(T1547.004)
    AppInitDll,         // AppInit_DLLs(T1546.010)
    Other
}

/// <summary>
/// 一条自启动持久化项的快照(供持久化审计视图展示)。由服务端枚举各自启动点产生,
/// 经 <see cref="Engine"/> 的分析器打分后,经 IPC 传给 UI 列表展示与新增项告警。
/// </summary>
public sealed class PersistenceEntry
{
    /// <summary>稳定标识(类别+位置+名称的哈希),用于「新增项」对比。</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>持久化类别。</summary>
    public PersistenceCategory Category { get; set; }

    /// <summary>条目名称(注册表值名 / 任务名 / 服务名 / 文件名)。</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>所在位置(注册表键路径 / 文件夹路径 / 任务路径)。</summary>
    public string Location { get; set; } = string.Empty;

    /// <summary>原始命令(可执行命令行,可能含参数)。</summary>
    public string Command { get; set; } = string.Empty;

    /// <summary>从命令解析出的可执行文件完整路径(可空)。</summary>
    public string? ImagePath { get; set; }

    /// <summary>该可执行文件是否带可信签名(服务端填充;未采集时为 null)。</summary>
    public bool? Signed { get; set; }

    /// <summary>签名发行商(可空)。</summary>
    public string? Publisher { get; set; }

    /// <summary>风险评分(0-100,由 PersistenceAnalyzer 计算)。</summary>
    public int RiskScore { get; set; }

    /// <summary>风险原因(可读)。</summary>
    public System.Collections.Generic.List<string> RiskReasons { get; set; } = new();

    /// <summary>命中的 ATT&CK 技战术(去重,"T1547.001 注册表 Run 键" 形式)。</summary>
    public System.Collections.Generic.List<string> Techniques { get; set; } = new();

    public override string ToString() => $"[{Category}] {Name} -> {Command}";
}
