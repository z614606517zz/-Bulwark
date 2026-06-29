using System;
using System.Collections.Generic;

namespace Bulwark.Core.Engine;

/// <summary>
/// MITRE ATT&CK 技战术精简目录(终端可观测子集)。
///
/// 把分析器命中的技战术编号(如 T1218.010)映射到「中文名称 + 所属战术阶段」,
/// 让告警与 AI 研判从"一句话原因"升级为"标准化技战术标签",显著提升专业度与可读性。
/// 这是查表,几乎零运行时成本。仅收录本项目各分析器实际会产出的编号。
/// </summary>
public static class AttackCatalog
{
    /// <summary>一条 ATT&CK 技战术条目。</summary>
    public sealed record Technique(string Id, string Name, string Tactic);

    private static readonly Dictionary<string, Technique> Map = Build();

    private static Dictionary<string, Technique> Build()
    {
        var t = new Dictionary<string, Technique>(StringComparer.OrdinalIgnoreCase);
        void A(string id, string name, string tactic) => t[id] = new Technique(id, name, tactic);

        // 执行 Execution
        A("T1059.001", "PowerShell", "执行");
        A("T1047", "WMI", "执行");
        A("T1202", "间接命令执行", "执行");
        A("T1204", "用户执行", "执行");

        // 防御规避 Defense Evasion
        A("T1027", "混淆文件或信息", "防御规避");
        A("T1140", "去混淆/解码文件", "防御规避");
        A("T1197", "BITS 任务", "防御规避");
        A("T1220", "XSL 脚本处理", "防御规避");
        A("T1036.005", "伪装为合法名称/位置", "防御规避");
        A("T1036.007", "双重文件扩展名", "防御规避");
        A("T1564.004", "NTFS 备用数据流", "防御规避");
        A("T1218", "系统二进制代理执行", "防御规避");
        A("T1218.004", "InstallUtil 代理执行", "防御规避");
        A("T1218.005", "Mshta 代理执行", "防御规避");
        A("T1218.007", "Msiexec 代理执行", "防御规避");
        A("T1218.009", "Regsvcs/Regasm 代理执行", "防御规避");
        A("T1218.010", "Regsvr32 代理执行(Squiblydoo)", "防御规避");
        A("T1218.011", "Rundll32 代理执行", "防御规避");
        A("T1218.013", "Mavinject 代理执行", "防御规避");
        A("T1127.001", "MSBuild 可信工具代理执行", "防御规避");

        // 凭据访问 Credential Access
        A("T1003", "操作系统凭据转储", "凭据访问");
        A("T1003.001", "LSASS 内存转储", "凭据访问");
        A("T1003.002", "SAM 数据库(本地账户哈希)", "凭据访问");
        A("T1003.003", "NTDS 域控凭据库", "凭据访问");
        A("T1555.003", "浏览器存储凭据", "凭据访问");
        A("T1555.004", "Windows 凭据保管库", "凭据访问");

        // 命令与控制 Command and Control
        A("T1105", "工具传输/下载执行", "命令控制");
        A("T1071", "应用层协议外联", "命令控制");

        // 影响 Impact
        A("T1490", "抑制系统恢复(删卷影/备份)", "破坏影响");
        A("T1486", "数据加密勒索", "破坏影响");

        // 持久化 Persistence
        A("T1547.001", "注册表 Run 键/启动文件夹", "持久化");
        A("T1547.004", "Winlogon 助手 DLL/Shell", "持久化");
        A("T1546.003", "WMI 事件订阅", "持久化");
        A("T1546.010", "AppInit_DLLs", "持久化");
        A("T1546.012", "映像劫持(IFEO Debugger)", "持久化");
        A("T1543.003", "Windows 服务", "持久化");
        A("T1053", "计划任务", "持久化");
        A("T1053.005", "计划任务(schtasks)", "持久化");

        // 进程注入 Privilege Escalation / Defense Evasion
        A("T1055", "进程注入", "进程注入");

        return t;
    }

    /// <summary>查找技战术编号。支持「父技战术兜底」:子编号未收录时回退到父编号(T1218.999 → T1218)。</summary>
    public static Technique? Lookup(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return null;
        if (Map.TryGetValue(id, out var t)) return t;

        int dot = id.IndexOf('.');
        if (dot > 0 && Map.TryGetValue(id.Substring(0, dot), out var parent))
            return parent;

        return null;
    }

    /// <summary>"T1218.010 Regsvr32 代理执行(Squiblydoo)" 形式的可读标签;未收录则回退为裸编号。</summary>
    public static string Describe(string id)
    {
        var t = Lookup(id);
        return t is null ? id : $"{id} {t.Name}";
    }
}
