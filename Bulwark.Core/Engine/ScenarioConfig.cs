using System;
using System.Collections.Generic;

namespace Bulwark.Core.Engine;

/// <summary>
/// 场景化规则配置。允许用户根据使用场景自定义规则行为。
/// </summary>
public class ScenarioConfig
{
    /// <summary>场景类型</summary>
    public enum ScenarioType
    {
        /// <summary>默认场景(平衡安全与易用性)</summary>
        Default,
        
        /// <summary>开发环境(减少开发工具误报)</summary>
        Development,
        
        /// <summary>企业环境(严格安全策略)</summary>
        Enterprise,
        
        /// <summary>个人用户(宽松策略)</summary>
        Personal,
        
        /// <summary>服务器环境(最小化干扰)</summary>
        Server,
        
        /// <summary>测试环境(允许更多操作)</summary>
        Testing
    }

    /// <summary>当前场景</summary>
    public ScenarioType CurrentScenario { get; set; } = ScenarioType.Default;

    /// <summary>是否启用开发工具白名单</summary>
    public bool EnableDevToolWhitelist { get; set; } = true;

    /// <summary>是否启用CI/CD环境检测</summary>
    public bool EnableCiCdDetection { get; set; } = true;

    /// <summary>PowerShell编码命令阈值(字符数)</summary>
    public int PowerShellEncodedCommandThreshold { get; set; } = 100;

    /// <summary>是否自动放行开发工具的Ask规则</summary>
    public bool AutoAllowDevToolAskRules { get; set; } = true;

    /// <summary>是否启用Office开发者模式</summary>
    public bool EnableOfficeDeveloperMode { get; set; } = false;

    /// <summary>是否启用COM注册白名单</summary>
    public bool EnableComRegistrationWhitelist { get; set; } = true;

    /// <summary>是否启用explorer注入白名单</summary>
    public bool EnableExplorerInjectionWhitelist { get; set; } = true;

    /// <summary>是否启用网络外联白名单</summary>
    public bool EnableNetworkWhitelist { get; set; } = true;

    /// <summary>自定义开发工具进程名列表</summary>
    public HashSet<string> CustomDevToolProcessNames { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>自定义开发工具路径模式列表</summary>
    public List<string> CustomDevToolPathPatterns { get; set; } = new();

    /// <summary>自定义可信安装器进程名列表</summary>
    public HashSet<string> CustomTrustedInstallerNames { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// 根据场景类型获取默认配置
    /// </summary>
    public static ScenarioConfig GetDefaultConfig(ScenarioType scenario)
    {
        return scenario switch
        {
            ScenarioType.Development => new ScenarioConfig
            {
                CurrentScenario = ScenarioType.Development,
                EnableDevToolWhitelist = true,
                EnableCiCdDetection = true,
                PowerShellEncodedCommandThreshold = 200, // 开发环境允许更长的编码命令
                AutoAllowDevToolAskRules = true,
                EnableOfficeDeveloperMode = true, // 开发者可能需要修改Office设置
                EnableComRegistrationWhitelist = true,
                EnableExplorerInjectionWhitelist = true,
                EnableNetworkWhitelist = true
            },
            ScenarioType.Enterprise => new ScenarioConfig
            {
                CurrentScenario = ScenarioType.Enterprise,
                EnableDevToolWhitelist = false, // 企业环境不自动放行开发工具
                EnableCiCdDetection = false,
                PowerShellEncodedCommandThreshold = 50, // 企业环境更严格
                AutoAllowDevToolAskRules = false,
                EnableOfficeDeveloperMode = false,
                EnableComRegistrationWhitelist = false,
                EnableExplorerInjectionWhitelist = false,
                EnableNetworkWhitelist = false
            },
            ScenarioType.Personal => new ScenarioConfig
            {
                CurrentScenario = ScenarioType.Personal,
                EnableDevToolWhitelist = true,
                EnableCiCdDetection = false,
                PowerShellEncodedCommandThreshold = 150,
                AutoAllowDevToolAskRules = true,
                EnableOfficeDeveloperMode = false,
                EnableComRegistrationWhitelist = true,
                EnableExplorerInjectionWhitelist = true,
                EnableNetworkWhitelist = true
            },
            ScenarioType.Server => new ScenarioConfig
            {
                CurrentScenario = ScenarioType.Server,
                EnableDevToolWhitelist = false, // 服务器环境不自动放行开发工具
                EnableCiCdDetection = false,
                PowerShellEncodedCommandThreshold = 100,
                AutoAllowDevToolAskRules = false,
                EnableOfficeDeveloperMode = false,
                EnableComRegistrationWhitelist = false,
                EnableExplorerInjectionWhitelist = false,
                EnableNetworkWhitelist = false
            },
            ScenarioType.Testing => new ScenarioConfig
            {
                CurrentScenario = ScenarioType.Testing,
                EnableDevToolWhitelist = true,
                EnableCiCdDetection = true,
                PowerShellEncodedCommandThreshold = 500, // 测试环境允许很长的编码命令
                AutoAllowDevToolAskRules = true,
                EnableOfficeDeveloperMode = true,
                EnableComRegistrationWhitelist = true,
                EnableExplorerInjectionWhitelist = true,
                EnableNetworkWhitelist = true
            },
            _ => new ScenarioConfig // Default
            {
                CurrentScenario = ScenarioType.Default,
                EnableDevToolWhitelist = true,
                EnableCiCdDetection = true,
                PowerShellEncodedCommandThreshold = 100,
                AutoAllowDevToolAskRules = true,
                EnableOfficeDeveloperMode = false,
                EnableComRegistrationWhitelist = true,
                EnableExplorerInjectionWhitelist = true,
                EnableNetworkWhitelist = true
            }
        };
    }

    /// <summary>
    /// 检查进程是否在白名单中
    /// </summary>
    public bool IsProcessWhitelisted(string? processPath)
    {
        if (string.IsNullOrEmpty(processPath))
            return false;

        // 检查自定义开发工具进程名
        string fileName = System.IO.Path.GetFileName(processPath);
        if (CustomDevToolProcessNames.Contains(fileName))
            return true;

        // 检查自定义开发工具路径模式
        string lower = processPath.ToLowerInvariant();
        foreach (var pattern in CustomDevToolPathPatterns)
        {
            if (lower.Contains(pattern.ToLowerInvariant()))
                return true;
        }

        // 检查自定义可信安装器
        if (CustomTrustedInstallerNames.Contains(fileName))
            return true;

        return false;
    }

    /// <summary>
    /// 检查编码命令长度是否超过阈值
    /// </summary>
    public bool IsEncodedCommandTooLong(string? commandLine)
    {
        if (string.IsNullOrEmpty(commandLine))
            return false;

        // 查找Base64编码内容
        var match = System.Text.RegularExpressions.Regex.Match(
            commandLine,
            @"[A-Za-z0-9+/]{100,}={0,2}");

        return match.Success && match.Length > PowerShellEncodedCommandThreshold;
    }

    /// <summary>
    /// 合并两个配置（用于用户自定义覆盖默认配置）
    /// </summary>
    public void MergeWith(ScenarioConfig other)
    {
        EnableDevToolWhitelist = other.EnableDevToolWhitelist;
        EnableCiCdDetection = other.EnableCiCdDetection;
        PowerShellEncodedCommandThreshold = other.PowerShellEncodedCommandThreshold;
        AutoAllowDevToolAskRules = other.AutoAllowDevToolAskRules;
        EnableOfficeDeveloperMode = other.EnableOfficeDeveloperMode;
        EnableComRegistrationWhitelist = other.EnableComRegistrationWhitelist;
        EnableExplorerInjectionWhitelist = other.EnableExplorerInjectionWhitelist;
        EnableNetworkWhitelist = other.EnableNetworkWhitelist;

        // 合并自定义列表
        foreach (var name in other.CustomDevToolProcessNames)
            CustomDevToolProcessNames.Add(name);
        foreach (var pattern in other.CustomDevToolPathPatterns)
            CustomDevToolPathPatterns.Add(pattern);
        foreach (var name in other.CustomTrustedInstallerNames)
            CustomTrustedInstallerNames.Add(name);
    }
}
