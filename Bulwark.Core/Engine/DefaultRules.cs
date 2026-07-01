using System.Collections.Generic;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// 内置默认规则集。首次运行(无任何持久化规则)时自动植入,做到开箱即用。
///
/// 设计原则(避免误伤正常软件 —— 只拦"行为本身即恶意"的动作):
///  - 规则锁定「恶意行为本身」而非「某个程序」。例如:删卷影副本、设映像劫持 Debugger、
///    替换粘滞键、向 lsass 注入远程线程。这些操作正常软件几乎从不做。
///  - 与正常软件可能重叠的(如安装器写 Run 键、读浏览器登录库),一律用 Ask 交给用户/信任策略,
///    绝不直接 Block,避免误杀。
///  - 只有"确定性恶意"且正常软件不会触发的模式才用 Block(如 IFEO Debugger、BYOVD 脆弱驱动、
///    勒索删备份、双扩展名伪装、向系统关键进程注入)。
///  - 与启发式 <see cref="ThreatDetector"/> 和信任策略 <see cref="TrustPolicy"/> 协同:
///    信任策略先放行系统/大厂签名软件,规则只对恶意模式做硬拦截。
///
/// 通配符语义见 <see cref="DefenseRule.WildcardMatch"/>:'*' 任意长度、'?' 单字符,大小写不敏感。
/// </summary>
public static class DefaultRules
{
    public const string BuiltInTag = "[内置]";

    public static IReadOnlyList<DefenseRule> Build()
    {
        var list = new List<DefenseRule>();

        AddTrustedSystemRules(list);     // 可信系统操作放行(必须在其他规则之前,确保优先级)
        AddPersistenceRules(list);       // 持久化 / 自启动(高危登录挂钩用 Block,普通自启动用 Ask)
        AddDefenseEvasionRules(list);    // 关闭安全软件 / 系统防护
        AddCredentialAccessRules(list);  // 凭据窃取
        AddRansomwareRules(list);        // 勒索 / 数据破坏
        AddLolBinRules(list);            // 合法程序滥用(LOLBin 命令行)
        AddInjectionRules(list);         // 进程注入 / 远程线程
        AddExecutionRules(list);         // 从不可信位置执行 / 伪装
        AddBootAndBackdoorRules(list);   // 引导篡改 / 辅助功能后门
        AddWmiAndLateralRules(list);     // WMI 持久化 / 横向移动
        AddOfficeMacroRules(list);       // Office 宏与受保护视图降级
        AddAntiForensicsRules(list);     // 反取证:清日志 / 擦痕迹
        AddByovdRules(list);             // BYOVD 脆弱驱动落地 / 加载
        AddSilverFox2026Rules(list);     // 银狐 2025-2026 最新动向(Winos/ValleyRAT/ABCDoor/AtlasCross)
        AddImControlRules(list);         // 远控木马劫持微信/QQ群发(注入/侧载/自动化)
        AddImMassMessagingRules(list);   // 银狐:微信/QQ 群发外挂框架(wcferry/ntchat/wxbot 等)
        AddImHarvestAndFrameworkRules(list); // 银狐:补充群控框架 + 通讯录/聊天库窃取(群发目标采集)
        AddDeepPersistenceRules(list);   // 深层持久化:LSA包/netsh helper/COR_PROFILER/BootExecute/AppCertDLLs
        AddCmdlineEvasionRules(list);    // 命令行关防护 / UAC 绕过(auto-elevate 劫持)
        AddNetworkC2Rules(list);         // 脚本解释器 / 可疑目录程序网络外联(疑似 C2)

        return list;
    }

    // ======================================================================
    // 批次 0:可信系统操作放行(降误报核心)
    //
    // 设计原则:用「精确主体 + 宽泛目标」的 Allow 规则,覆盖常见合法操作。
    // 规则引擎排序:具体度高的规则优先。这些规则指定了 ActorPattern(主体),
    // 具体度高于仅指定 TargetPattern 的 Ask 规则,因此能正确覆盖。
    //
    // 典型误报场景:
    //  - TrustedInstaller / svchost 写 Program Files / 注册表(Windows Update)
    //  - msiexec 安装软件(写注册表 Run / 服务 / Program Files)
    //  - Windows Defender 自更新(写 ProgramData\Microsoft\Windows Defender)
    //  - 安全软件更新病毒库(写自己的目录)
    //  - 系统维护任务(磁盘清理、索引服务)的正常文件操作
    // ======================================================================
    private static void AddTrustedSystemRules(List<DefenseRule> list)
    {
        // --- 系统注册表键放行(Background Activity Moderator / 用户切换 / 会话管理) ---
        // bam\State:Windows 后台活动管理器,进程启动/退出时自动写入,是正常系统行为。
        list.Add(new DefenseRule
        {
            Type = EventType.RegistryWrite,
            TargetPattern = @"*\Services\bam\*",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} BAM 注册表写入(系统后台活动管理器)"
        });
        // UserSettings:用户配置文件注册表,进程启动时自动更新。
        list.Add(new DefenseRule
        {
            Type = EventType.RegistryWrite,
            TargetPattern = @"*\UserSettings\*",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} 用户配置注册表写入(系统自动更新)"
        });
        // Session Manager\KnownDlls:系统已知 DLL 列表,启动时读取。
        list.Add(new DefenseRule
        {
            Type = EventType.RegistryWrite,
            TargetPattern = @"*\Session Manager\KnownDlls\*",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} KnownDlls 注册表(系统 DLL 缓存)"
        });

        // --- 可信系统进程的文件/注册表操作(Windows Update / 系统维护) ---
        // TrustedInstaller:Windows 模块安装服务,安装更新时写 System32/WinSxS/Program Files。
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\TrustedInstaller.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} TrustedInstaller 文件操作(Windows Update/系统维护)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.RegistryWrite,
            ActorPattern = @"*\TrustedInstaller.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} TrustedInstaller 注册表操作(Windows Update)"
        });

        // svchost:承载大量系统服务(Windows Update/组策略/网络/安全等),其文件和注册表
        // 操作绝大部分是合法系统行为。恶意软件通常不以 svchost 身份发起文件操作
        // (注入 svchost 已由注入规则拦截),故放行可显著降误报。
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\svchost.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} svchost 文件操作(系统服务)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.RegistryWrite,
            ActorPattern = @"*\svchost.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} svchost 注册表操作(系统服务)"
        });

        // wuauclct / UsoClient / TiWorker:Windows Update 相关进程。
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\wuauclt.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Update 文件操作"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\UsoClient.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Update(UsoClient)文件操作"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\TiWorker.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Update(TiWorker)文件操作"
        });

        // --- Windows Defender 自维护 ---
        // MsMpEng / MpCmdRun:Defender 引擎/命令行工具,更新病毒库写 ProgramData。
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\MsMpEng.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Defender 引擎文件操作(更新/扫描)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\MpCmdRun.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Defender 命令行工具文件操作"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\MpDefenderCoreService.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Defender 核心服务文件操作"
        });

        // --- 系统目录 PowerShell 放行 ---
        // Windows 系统管理任务(计划任务/组策略/系统维护)从 System32 启动 PowerShell,
        // 常带 -NoProfile/-NonInteractive 等参数,是正常系统行为而非恶意。
        // 仅放行「从 System32 启动」的 PowerShell,非系统目录的仍走启发式检测。
        list.Add(new DefenseRule
        {
            Type = EventType.ProcessCreate,
            ActorPattern = @"*\Windows\System32\WindowsPowerShell\*",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} 系统目录 PowerShell 启动(系统管理任务)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.ProcessCreate,
            ActorPattern = @"*\Windows\SysWOW64\WindowsPowerShell\*",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} SysWOW64 PowerShell 启动(系统管理任务)"
        });

        // --- 可信安装器写 Program Files / 注册表 ---
        // msiexec:Windows Installer,安装软件时写 Program Files + 注册表 Run/服务。
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\msiexec.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Installer 文件操作(安装软件)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.RegistryWrite,
            ActorPattern = @"*\msiexec.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Installer 注册表操作(安装软件)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.ProcessCreate,
            ActorPattern = @"*\msiexec.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Installer 创建进程(安装软件)"
        });

        // setup.exe:常见安装器(位于 Temp 或安装介质),签名后由 IsHealthySigned 放行。
        // 未签名 setup.exe 仍由其他规则(Ask/启发式)处理。
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\setup.exe",
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 安装器文件操作(签名软件自动放行)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.RegistryWrite,
            ActorPattern = @"*\setup.exe",
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 安装器注册表操作(签名软件自动放行)"
        });

        // --- 可信包管理器操作 ---
        // winget / choco / scoop:安装/更新软件时写 Program Files + 注册表。
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\winget.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Package Manager 文件操作"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.RegistryWrite,
            ActorPattern = @"*\winget.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Package Manager 注册表操作"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\choco.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Chocolatey 文件操作"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\scoop.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Scoop 文件操作"
        });

        // --- 系统维护进程 ---
        // cleanmgr / defrag / SearchIndexer:磁盘清理/碎片整理/索引服务。
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\cleanmgr.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} 磁盘清理文件操作"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\defrag.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} 磁盘碎片整理文件操作"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\SearchIndexer.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows 搜索索引文件操作"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\SearchProtocolHost.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows 搜索协议主机文件操作"
        });

        // --- 浏览器自动更新 ---
        // Chrome / Edge / Firefox 更新器写自己的安装目录。
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\Google\Update\*",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Google 更新服务文件操作"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\Microsoft\EdgeUpdate\*",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Microsoft Edge 更新文件操作"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\Mozilla Maintenance Service\*",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Mozilla 维护服务文件操作"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            ActorPattern = @"*\updater.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} 浏览器更新器文件操作"
        });

        // --- 系统进程注入(合法系统行为) ---
        // csrss / winlogon 对子进程的线程创建是合法系统行为。
        list.Add(new DefenseRule
        {
            Type = EventType.RemoteThread,
            ActorPattern = @"*\csrss.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} csrss 线程创建(系统合法行为)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.RemoteThread,
            ActorPattern = @"*\winlogon.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} winlogon 线程创建(系统合法行为)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.RemoteThread,
            ActorPattern = @"*\wininit.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} wininit 线程创建(系统合法行为)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.RemoteThread,
            ActorPattern = @"*\services.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} services 线程创建(系统合法行为)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.RemoteThread,
            ActorPattern = @"*\lsass.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} lsass 线程创建(系统合法行为)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.RemoteThread,
            ActorPattern = @"*\lsm.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} lsm 线程创建(系统合法行为)"
        });

        // --- 安全软件自更新(写自己的目录) ---
        // 火绒、360、金山等安全软件更新病毒库/程序时写自己的安装目录。
        // 仅放行「写自己目录」的操作,写其他位置仍由规则引擎正常处理。
        foreach (var actor in new[] {
            @"*\HipsTray.exe", @"*\HipsDaemon.exe",
            @"*\360tray.exe", @"*\360sd.exe", @"*\ZhuDongFangYu.exe",
            @"*\kxetray.exe", @"*\KSafeTray.exe",
            @"*\QQPCRTP.exe"
        })
        {
            list.Add(new DefenseRule
            {
                Type = EventType.FileWrite,
                ActorPattern = actor,
                Action = VerdictAction.Allow,
                Note = $"{BuiltInTag} 安全软件自身文件操作(更新/维护)"
            });
        }

        // --- 网络连接:可信系统服务 ---
        // svchost / System / WmiPrvSE 的网络连接(Windows Update / 时间同步 / 组策略 / 遥测)。
        list.Add(new DefenseRule
        {
            Type = EventType.NetworkConnect,
            ActorPattern = @"*\svchost.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} svchost 网络连接(系统服务)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.NetworkConnect,
            ActorPattern = @"*\System",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} System 网络连接(内核级通信)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.NetworkConnect,
            ActorPattern = @"*\WmiPrvSE.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} WMI 提供者网络连接"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.NetworkConnect,
            ActorPattern = @"*\wuauclt.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Update 网络连接"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.NetworkConnect,
            ActorPattern = @"*\UsoClient.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Update(UsoClient)网络连接"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.NetworkConnect,
            ActorPattern = @"*\MsMpEng.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} Windows Defender 网络连接(更新/云保护)"
        });

        // --- 浏览器网络连接(自动更新 / 同步) ---
        foreach (var actor in new[] {
            @"*\chrome.exe", @"*\msedge.exe", @"*\firefox.exe",
            @"*\GoogleUpdate.exe", @"*\MicrosoftEdgeUpdate.exe"
        })
        {
            list.Add(new DefenseRule
            {
                Type = EventType.NetworkConnect,
                ActorPattern = actor,
                Action = VerdictAction.Allow,
                Note = $"{BuiltInTag} 浏览器网络连接(正常浏览/更新)"
            });
        }
    }

    // ======================================================================
    // 批次 1:持久化 / 自启动
    // 普通自启动项正常软件(安装器/更新器)也会写 -> Ask 交给用户/信任策略;
    // 登录挂钩 / 映像劫持这类正常软件几乎从不碰的高危持久化 -> Block。
    // ======================================================================
    private static void AddPersistenceRules(List<DefenseRule> list)
    {
        // --- 普通自启动项(可能与安装器重叠)-> Ask ---
        Reg(list, @"*\CurrentVersion\Run\*", VerdictAction.Ask,
            "写入开机启动项(HKLM/HKCU Run)");
        Reg(list, @"*\CurrentVersion\RunOnce\*", VerdictAction.Ask,
            "写入一次性启动项(RunOnce)");
        Reg(list, @"*\CurrentVersion\RunServices\*", VerdictAction.Ask,
            "写入服务型启动项(RunServices)");
        Reg(list, @"*\CurrentVersion\Policies\Explorer\Run\*", VerdictAction.Ask,
            "写入策略启动项(Policies\\Explorer\\Run)");

        // --- 登录/初始化挂钩(正常软件几乎从不改)-> Block ---
        Reg(list, @"*\Winlogon\Shell*", VerdictAction.Block,
            "篡改 Winlogon Shell(高危持久化)");
        Reg(list, @"*\Winlogon\Userinit*", VerdictAction.Block,
            "篡改 Winlogon Userinit(高危持久化)");
        Reg(list, @"*\Winlogon\Notify\*", VerdictAction.Block,
            "注册 Winlogon Notify 包(高危持久化)");
        Reg(list, @"*\Windows\CurrentVersion\Windows\AppInit_DLLs*", VerdictAction.Block,
            "设置 AppInit_DLLs(全局 DLL 注入持久化)");
        Reg(list, @"*\Windows NT\CurrentVersion\Windows\Load*", VerdictAction.Block,
            "篡改 Windows\\Load 启动键");

        // --- 映像劫持 / 静默退出劫持(确定性恶意)-> Block ---
        Reg(list, @"*\Image File Execution Options\*\Debugger*", VerdictAction.Block,
            "设置映像劫持 Debugger(IFEO)");
        Reg(list, @"*\SilentProcessExit\*", VerdictAction.Block,
            "配置静默退出劫持(SilentProcessExit)");

        // --- 服务 DLL 持久化(svchost 托管,常被滥用)-> Block;改 ImagePath 较常见 -> Ask ---
        Reg(list, @"*\Services\*\ServiceDll*", VerdictAction.Block,
            "修改服务 DLL(ServiceDll 持久化)");
        Reg(list, @"*\Services\*\ImagePath*", VerdictAction.Ask,
            "修改服务可执行路径(ImagePath)");

        // --- COM 劫持细化规则(开发工具 vs 恶意劫持) ---
        // 场景1:标准COM注册(InprocServer32) - 开发工具常见
        Reg(list, @"*\Classes\CLSID\*\InprocServer32*", VerdictAction.Ask,
            "注册 COM InprocServer32(可能 COM 劫持,开发工具会触发)");
        // 场景2:LocalServer32注册 - 本地服务COM
        Reg(list, @"*\Classes\CLSID\*\LocalServer32*", VerdictAction.Ask,
            "注册 COM LocalServer32(可能 COM 劫持)");
        // 场景3:TreatAs劫持 - 已知劫持技术
        Reg(list, @"*\Classes\CLSID\*\TreatAs*", VerdictAction.Ask,
            "COM TreatAs 劫持(可能持久化)");
        // 场景4:ProgID劫持 - 程序标识符劫持
        Reg(list, @"*\Classes\CLSID\*\ProgID*", VerdictAction.Ask,
            "COM ProgID 劫持(可能持久化)");
        
        // --- 启动文件夹 / 计划任务文件(安装器也会写)-> Ask ---
        File_(list, @"*\Start Menu\Programs\Startup\*", VerdictAction.Ask,
            "向启动文件夹写入程序");
        File_(list, @"*\System32\Tasks\*", VerdictAction.Ask,
            "创建/篡改计划任务文件(Tasks)");
        
        // --- 屏保持久化 -> Ask ---
        Reg(list, @"*\Control Panel\Desktop\SCRNSAVE.EXE*", VerdictAction.Ask,
            "篡改屏保程序(可作持久化)");
    }

    // ======================================================================
    // 批次 2:关闭安全软件 / 系统防护(防御规避)
    // 关 Defender/UAC/防火墙、禁用任务管理器等是确定性恶意 -> Block;
    // 加排除项 / 降级提示这类可能管理员手动做的 -> Ask。
    // ======================================================================
    private static void AddDefenseEvasionRules(List<DefenseRule> list)
    {
        // --- Windows Defender ---
        Reg(list, @"*\Windows Defender\*DisableAntiSpyware*", VerdictAction.Block,
            "试图关闭 Windows Defender(DisableAntiSpyware)");
        Reg(list, @"*\Windows Defender\*DisableRealtimeMonitoring*", VerdictAction.Block,
            "试图关闭 Defender 实时监控");
        Reg(list, @"*\Windows Defender\Exclusions\*", VerdictAction.Ask,
            "向 Defender 添加排除项(可能为免杀)");
        Reg(list, @"*\Policies\Microsoft\Windows Defender\*", VerdictAction.Ask,
            "修改 Defender 策略");

        // --- 系统安全机制 ---
        Reg(list, @"*\System\*EnableLUA*", VerdictAction.Block,
            "试图关闭 UAC(EnableLUA)");
        // 降低 UAC 提权确认级别 -> Ask;但合法 OS 组件(RuntimeBroker / 设置中心)调整或
        // 重置该值是正常的,故标记可被「强可信系统组件」豁免(LOLBin 如 reg/powershell 不豁免)。
        // 注意:这是 Ask 级、非彻底关 UAC(EnableLUA=0 仍为上面的 Block,不豁免)。
        list.Add(new DefenseRule
        {
            Type = EventType.RegistryWrite,
            TargetPattern = @"*\System\*ConsentPromptBehaviorAdmin*",
            Action = VerdictAction.Ask,
            ExemptTrustedOsComponent = true,
            Note = $"{BuiltInTag} 降低 UAC 提权确认级别",
        });
        Reg(list, @"*\Policies\System\DisableTaskMgr*", VerdictAction.Block,
            "试图禁用任务管理器");
        Reg(list, @"*\Policies\System\DisableRegistryTools*", VerdictAction.Block,
            "试图禁用注册表编辑器");
        Reg(list, @"*\Policies\System\DisableCMD*", VerdictAction.Ask,
            "试图禁用命令提示符");

        // --- 防火墙 ---
        Reg(list, @"*\WindowsFirewall\*\EnableFirewall*", VerdictAction.Block,
            "试图关闭 Windows 防火墙");
        Reg(list, @"*\FirewallPolicy\*\DisableNotifications*", VerdictAction.Ask,
            "关闭防火墙通知");

        // --- SmartScreen / MOTW ---
        Reg(list, @"*\System\EnableSmartScreen*", VerdictAction.Ask,
            "试图关闭 SmartScreen");
        Reg(list, @"*\Attachments\SaveZoneInformation*", VerdictAction.Ask,
            "禁用附件区域标记(绕过 MOTW 警告)");

        // --- 结束安全软件进程(确定性恶意)-> Block ---
        Proc(list, EventType.ProcessTerminate, @"*\MsMpEng.exe", VerdictAction.Block,
            "试图结束 Defender 引擎(MsMpEng)");
        Proc(list, EventType.ProcessTerminate, @"*\MpDefenderCoreService.exe", VerdictAction.Block,
            "试图结束 Defender 核心服务");
        Proc(list, EventType.ProcessTerminate, @"*\360tray.exe", VerdictAction.Block,
            "试图结束 360 安全卫士");
        Proc(list, EventType.ProcessTerminate, @"*\360sd.exe", VerdictAction.Block,
            "试图结束 360 杀毒");
        Proc(list, EventType.ProcessTerminate, @"*\ZhuDongFangYu.exe", VerdictAction.Block,
            "试图结束 360 主动防御");
        Proc(list, EventType.ProcessTerminate, @"*\HipsTray.exe", VerdictAction.Block,
            "试图结束火绒");
        Proc(list, EventType.ProcessTerminate, @"*\QQPCRTP.exe", VerdictAction.Block,
            "试图结束腾讯电脑管家");
        Proc(list, EventType.ProcessTerminate, @"*\kxetray.exe", VerdictAction.Block,
            "试图结束金山毒霸");
    }

    // ======================================================================
    // 批次 3:凭据窃取
    // 向 lsass 注入 / 删 lsass、访问 SAM/NTDS 是确定性恶意 -> Block;
    // 读浏览器/凭据管理器存储正常软件(浏览器本身、密码管理器)也会做 -> Ask。
    // ======================================================================
    private static void AddCredentialAccessRules(List<DefenseRule> list)
    {
        // --- LSASS(凭据转储)-> Block ---
        Proc(list, EventType.RemoteThread, @"*\lsass.exe", VerdictAction.Block,
            "向 LSASS 注入远程线程(疑似凭据窃取)");
        Proc(list, EventType.ProcessTerminate, @"*\lsass.exe", VerdictAction.Block,
            "试图结束 LSASS(破坏系统/凭据保护)");

        // --- 敏感凭据存储文件(直接读 SAM/SECURITY/NTDS 必为恶意)-> Block ---
        File_(list, @"*\Windows\System32\config\SAM", VerdictAction.Block,
            "访问 SAM 数据库(本地账户哈希)");
        File_(list, @"*\Windows\System32\config\SECURITY", VerdictAction.Block,
            "访问 SECURITY 配置单元(LSA 机密)");
        File_(list, @"*\Windows\NTDS\ntds.dit", VerdictAction.Block,
            "访问 NTDS.dit(域账户数据库)");

        // --- 浏览器/凭据管理器(正常软件也访问)-> Ask ---
        File_(list, @"*\User Data\*\Login Data", VerdictAction.Ask,
            "读取浏览器保存的登录凭据");
        File_(list, @"*\Mozilla\Firefox\Profiles\*logins.json", VerdictAction.Ask,
            "读取 Firefox 保存的登录凭据");
        File_(list, @"*\Microsoft\Credentials\*", VerdictAction.Ask,
            "访问 Windows 凭据管理器存储");
        File_(list, @"*\Microsoft\Protect\*", VerdictAction.Ask,
            "访问 DPAPI 主密钥");
    }

    // ======================================================================
    // 批次 4:勒索 / 数据破坏
    // 删卷影/删备份/禁恢复/删引导文件全是确定性恶意 -> Block;
    // 改 hosts / 写勒索信文件名可能误判 -> Ask。
    // ======================================================================
    private static void AddRansomwareRules(List<DefenseRule> list)
    {
        // --- 删除卷影副本 / 备份(勒索标志性行为)-> Block ---
        Cmd(list, @"*vssadmin*delete*shadows*", VerdictAction.Block,
            "删除卷影副本(vssadmin,勒索特征)");
        Cmd(list, @"*wmic*shadowcopy*delete*", VerdictAction.Block,
            "删除卷影副本(wmic,勒索特征)");
        Cmd(list, @"*wbadmin*delete*catalog*", VerdictAction.Block,
            "删除备份目录(wbadmin,勒索特征)");
        Cmd(list, @"*delete*systemstatebackup*", VerdictAction.Block,
            "删除系统状态备份(勒索特征)");

        // --- 禁用恢复 / 修复 -> Block ---
        Cmd(list, @"*bcdedit*recoveryenabled*no*", VerdictAction.Block,
            "禁用 Windows 恢复(bcdedit,勒索特征)");
        Cmd(list, @"*bcdedit*bootstatuspolicy*ignoreallfailures*", VerdictAction.Block,
            "忽略启动失败策略(bcdedit,勒索特征)");
        Reg(list, @"*\SystemRestore\DisableSR*", VerdictAction.Block,
            "禁用系统还原(勒索特征)");

        // --- 删除关键引导/系统文件 -> Block ---
        Del(list, @"*\Windows\System32\winload.exe", VerdictAction.Block,
            "删除系统引导文件(破坏启动)");
        Del(list, @"*\boot\bcd", VerdictAction.Block,
            "删除启动配置数据(BCD)");

        // --- hosts 劫持 / 勒索信(可能误判)-> Ask ---
        File_(list, @"*\drivers\etc\hosts", VerdictAction.Ask,
            "修改 hosts 文件(可能劫持域名)");
        File_(list, @"*\*HOW_TO_DECRYPT*", VerdictAction.Ask,
            "写入疑似勒索说明文件(HOW_TO_DECRYPT)");
        File_(list, @"*\*RECOVER*FILES*", VerdictAction.Ask,
            "写入疑似勒索说明文件(RECOVER FILES)");
    }

    // ======================================================================
    // 批次 5:合法程序滥用(LOLBin 命令行特征)
    // 这类命令行是脚本/管理员偶尔也会用的灰色地带 -> 多数 Ask;
    // 仅 mshta/regsvr32 拉远程脚本这类几乎专属攻击的 -> Block。
    // ======================================================================
    private static void AddLolBinRules(List<DefenseRule> list)
    {
        // --- PowerShell 滥用细化规则 ---
        // 场景1:短编码命令(可能是正常脚本调用) -> Ask
        Cmd(list, @"*powershell*-enc*", VerdictAction.Ask,
            "PowerShell 编码命令(-EncodedCommand)");
        Cmd(list, @"*powershell*-e *", VerdictAction.Ask,
            "PowerShell 编码命令(-e 简写)");
        
        // 场景2:隐藏窗口 + 编码命令组合(高可疑) -> Ask，但开发工具自动放行
        Cmd(list, @"*-windowstyle hidden*-enc*", VerdictAction.Ask,
            "隐藏窗口+编码命令组合(高可疑)");
        Cmd(list, @"*-w hidden*-enc*", VerdictAction.Ask,
            "隐藏窗口+编码命令组合(-w 简写,高可疑)");
        
        // 场景3:单独隐藏窗口(可能是后台脚本) -> Ask
        Cmd(list, @"*-windowstyle hidden*", VerdictAction.Ask,
            "隐藏窗口运行(可疑)");
        Cmd(list, @"*-w hidden*", VerdictAction.Ask,
            "隐藏窗口运行(-w 简写,可疑)");
        
        // 场景4:绕过执行策略(开发/测试常见) -> Ask
        Cmd(list, @"*-executionpolicy bypass*", VerdictAction.Ask,
            "绕过 PowerShell 执行策略");
        Cmd(list, @"*-ep bypass*", VerdictAction.Ask,
            "绕过 PowerShell 执行策略(-ep 简写)");
        
        // 场景5:下载执行(明确恶意行为) -> Ask
        Cmd(list, @"*downloadstring*", VerdictAction.Ask,
            "内存下载执行(DownloadString)");
        Cmd(list, @"*downloadfile*", VerdictAction.Ask,
            "远程下载文件(DownloadFile)");
        Cmd(list, @"*invoke-expression*downloadstring*", VerdictAction.Ask,
            "下载并执行(IEX+DownloadString组合)");
        
        // 场景6:动态执行(开发调试常见) -> Ask
        Cmd(list, @"*invoke-expression*", VerdictAction.Ask,
            "动态执行(Invoke-Expression/IEX)");
        Cmd(list, @"*iex(*", VerdictAction.Ask,
            "动态执行(IEX 别名)");
        
        // 场景7:Base64解码(开发/自动化常见) -> Ask
        Cmd(list, @"*frombase64string*", VerdictAction.Ask,
            "Base64 解码执行");
        Cmd(list, @"*[convert]::frombase64string*", VerdictAction.Ask,
            "Base64 解码(Convert类)");

        // --- certutil / bitsadmin 下载器滥用 -> Ask ---
        // 场景8:certutil远程下载(明确恶意) -> Ask
        Cmd(list, @"*certutil*-urlcache*", VerdictAction.Ask,
            "certutil 远程下载(-urlcache)");
        Cmd(list, @"*certutil*-urlcache*-split*", VerdictAction.Ask,
            "certutil 远程下载并分割(-urlcache -split)");
        
        // 场景9:certutil解码(开发/测试常见) -> Ask
        Cmd(list, @"*certutil*-decode*", VerdictAction.Ask,
            "certutil 解码载荷(-decode)");
        Cmd(list, @"*certutil*-decodehex*", VerdictAction.Ask,
            "certutil 十六进制解码(-decodehex)");
        
        // 场景10:BITS下载(明确恶意) -> Ask
        Cmd(list, @"*bitsadmin*/transfer*", VerdictAction.Ask,
            "BITS 后台下载(bitsadmin)");
        Cmd(list, @"*start-bitstransfer*", VerdictAction.Ask,
            "BITS 后台传输(Start-BitsTransfer)");

        // --- mshta / rundll32 / regsvr32 执行远程脚本(几乎专属攻击)-> Block ---
        Cmd(list, @"*mshta*http*", VerdictAction.Block,
            "mshta 执行远程脚本");
        Cmd(list, @"*mshta*javascript:*", VerdictAction.Block,
            "mshta 执行内联脚本");
        Cmd(list, @"*regsvr32*/i:http*", VerdictAction.Block,
            "regsvr32 远程脚本执行(Squiblydoo)");
        Cmd(list, @"*rundll32*javascript:*", VerdictAction.Block,
            "rundll32 执行脚本");

        // --- 其他 LOLBin -> Ask ---
        Cmd(list, @"*msbuild*http*", VerdictAction.Ask,
            "MSBuild 加载远程项目(代码执行)");
        Cmd(list, @"*installutil*/logfile=*", VerdictAction.Ask,
            "InstallUtil 滥用(绕过执行策略)");
        Cmd(list, @"*wmic*process*call*create*", VerdictAction.Ask,
            "wmic 创建进程(横向/绕过)");
        // msiexec 从远程 URL 安装包(LOLBin 下载执行,正常安装多为本地包)-> Ask
        Cmd(list, @"*msiexec*http://*", VerdictAction.Ask,
            "msiexec 从远程地址安装包(下载执行)");
        Cmd(list, @"*msiexec*https://*", VerdictAction.Ask,
            "msiexec 从远程地址安装包(下载执行)");

        // --- 提权(加管理员组确定性恶意)-> Block;新增账户 -> Ask ---
        Cmd(list, @"*net*localgroup*administrators*/add*", VerdictAction.Block,
            "把账户加入管理员组(提权)");
        Cmd(list, @"*net*user*/add*", VerdictAction.Ask,
            "新增本地账户(net user /add)");
        Cmd(list, @"*schtasks*/create*", VerdictAction.Ask,
            "创建计划任务(可能持久化)");
    }

    // ======================================================================
    // 批次 6:进程注入 / 远程线程
    // 向系统关键进程注入远程线程几乎必为恶意 -> 多数 Block;
    // 向 explorer 注入偶有合法 shell 扩展 -> Ask。
    //
    // 重要例外:services.exe(SCM)创建子 svchost.exe 时,内核会观测到一次跨进程
    // 线程创建(初始线程),这是合法系统行为。因此 svchost 注入规则需排除
    // 「services.exe 作为发起方」的情况,否则启动登录期间会刷大量误报并被错误阻断。
    // ======================================================================
    private static void AddInjectionRules(List<DefenseRule> list)
    {
        Proc(list, EventType.RemoteThread, @"*\winlogon.exe", VerdictAction.Block,
            "向 winlogon 注入远程线程(高危)");
        // svchost:排除 services.exe 与 wininit.exe 这两个合法发起者(初始线程)。
        list.Add(new DefenseRule
        {
            Type = EventType.RemoteThread,
            TargetPattern = @"*\svchost.exe",
            Action = VerdictAction.Block,
            Note = $"{BuiltInTag} 向 svchost 注入远程线程(高危,排除 services/wininit 发起)",
        });
        // 系统启动 / 服务创建期 services.exe 与 wininit.exe 会发起向 svchost 的线程创建,
        // 这是合法行为,需精确放行(规则按特定性优先级,具体规则优先于通配)。
        list.Add(new DefenseRule
        {
            Type = EventType.RemoteThread,
            ActorPattern = @"*\services.exe",
            TargetPattern = @"*\svchost.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} services.exe 启动 svchost(系统合法行为,放行)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.RemoteThread,
            ActorPattern = @"*\wininit.exe",
            TargetPattern = @"*\svchost.exe",
            Action = VerdictAction.Allow,
            Note = $"{BuiltInTag} wininit.exe 启动 svchost(系统合法行为,放行)"
        });
        Proc(list, EventType.RemoteThread, @"*\services.exe", VerdictAction.Block,
            "向 services 注入远程线程(高危)");
        Proc(list, EventType.RemoteThread, @"*\csrss.exe", VerdictAction.Block,
            "向 csrss 注入远程线程(高危)");
        
        // --- explorer注入细化规则(Shell扩展 vs 恶意注入) ---
        // 场景1:系统进程注入explorer(可能合法)
        list.Add(new DefenseRule
        {
            Type = EventType.RemoteThread,
            ActorPattern = @"*\Windows\*",
            TargetPattern = @"*\explorer.exe",
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 系统进程向explorer注入(可能是Shell扩展)"
        });
        // 场景2:开发工具注入explorer(自动放行)
        list.Add(new DefenseRule
        {
            Type = EventType.RemoteThread,
            ActorPattern = @"*\Program Files\*",
            TargetPattern = @"*\explorer.exe",
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 程序向explorer注入(可能是Shell扩展)"
        });
        // 场景3:临时目录进程注入explorer(高可疑)
        list.Add(new DefenseRule
        {
            Type = EventType.RemoteThread,
            ActorPattern = @"*\AppData\Local\Temp\*",
            TargetPattern = @"*\explorer.exe",
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 临时目录进程向explorer注入(高可疑)"
        });
        // 场景4:未知进程注入explorer(默认Ask)
        Proc(list, EventType.RemoteThread, @"*\explorer.exe", VerdictAction.Ask,
            "向 explorer 注入远程线程(Shell扩展可能触发)");

        // 未签名模块加载进系统目录进程(疑似 DLL 劫持)-> Ask(避免误伤未补签名的合法插件)。
        list.Add(new DefenseRule
        {
            Type = EventType.ImageLoad,
            TargetPattern = @"*\Windows\*",
            RequireUnsigned = true,
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 未签名模块加载进系统目录进程(疑似 DLL 劫持)"
        });

        // 从 Temp 加载未签名模块 -> Ask。
        list.Add(new DefenseRule
        {
            Type = EventType.ImageLoad,
            TargetPattern = @"*\AppData\Local\Temp\*",
            RequireUnsigned = true,
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 从 Temp 加载未签名模块"
        });

        // 任何进程(含合法签名宿主)加载位于 Temp 的模块 -> Ask。
        // DLL 搜索顺序劫持 / 白加黑侧载时,加载方往往是合法签名程序(RequireUnsigned 对其失效),
        // 真正可疑的是「被加载模块落在用户可写的 Temp」。故此规则按目标路径命中,不看主体签名。
        list.Add(new DefenseRule
        {
            Type = EventType.ImageLoad,
            TargetPattern = @"*\AppData\Local\Temp\*.dll",
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 从 Temp 加载模块(疑似 DLL 搜索顺序劫持/侧载)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.ImageLoad,
            TargetPattern = @"*\Windows\Temp\*.dll",
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 从 Windows\\Temp 加载模块(疑似侧载)"
        });
    }

    // ======================================================================
    // 批次 7:从不可信位置执行 / 伪装
    // 回收站执行、双扩展名伪装是确定性恶意 -> Block;
    // 从 Temp/Downloads 执行未签名程序合法软件(下载的安装器)也会触发 -> Ask。
    // ======================================================================
    private static void AddExecutionRules(List<DefenseRule> list)
    {
        // --- 回收站启动(几乎必为恶意)-> Block ---
        Proc(list, EventType.ProcessCreate, @"*\$recycle.bin\*", VerdictAction.Block,
            "从回收站启动程序(几乎必为恶意)", hardOverride: true);

        // --- 双重扩展名伪装(文档图标的可执行体)-> Block ---
        Proc(list, EventType.ProcessCreate, @"*.pdf.exe", VerdictAction.Block,
            "双重扩展名伪装(.pdf.exe)", hardOverride: true);
        Proc(list, EventType.ProcessCreate, @"*.doc?.exe", VerdictAction.Block,
            "双重扩展名伪装(.doc/.docx.exe)", hardOverride: true);
        Proc(list, EventType.ProcessCreate, @"*.jpg.exe", VerdictAction.Block,
            "双重扩展名伪装(.jpg.exe)", hardOverride: true);
        Proc(list, EventType.ProcessCreate, @"*.txt.exe", VerdictAction.Block,
            "双重扩展名伪装(.txt.exe)", hardOverride: true);

        // --- 未签名程序从典型恶意落地目录执行(可能误伤下载的安装器)-> Ask ---
        UnsignedExec(list, @"*\AppData\Local\Temp\*", "从 Temp 目录执行未签名程序");
        UnsignedExec(list, @"*\Windows\Temp\*", "从 Windows\\Temp 执行未签名程序");
        UnsignedExec(list, @"*\Users\Public\*", "从 Public 目录执行未签名程序");
        UnsignedExec(list, @"*\Downloads\*", "从下载目录执行未签名程序");
        UnsignedExec(list, @"*\AppData\Roaming\*", "从 Roaming 执行未签名程序");
        UnsignedExec(list, @"*\PerfLogs\*", "从 PerfLogs 执行未签名程序");
        // 桌面 / 文档(含 OneDrive 重定向):银狐常把诱饵(伪装截图/支付凭证/素材)丢桌面诱导双击。
        // 这些是用户日常可写区,过去不在监控内,导致桌面上的未签名释放器被静默放过(目录盲区)。
        UnsignedExec(list, @"*\Desktop\*", "从桌面执行未签名程序(常见诱饵投放点)");
        UnsignedExec(list, @"*\Documents\*", "从文档目录执行未签名程序");
        UnsignedExec(list, @"*\Temp\7z*", "从压缩包临时解压目录执行未签名程序");
        UnsignedExec(list, @"*\Temp\Rar$*", "从 RAR 临时解压目录执行未签名程序");

        // --- 屏保程序(常被伪装)-> Ask ---
        Proc(list, EventType.ProcessCreate, @"*.scr", VerdictAction.Ask,
            "执行屏保程序(.scr,常被用于伪装)");
    }

    // ======================================================================
    // 批次 8:引导篡改 / 辅助功能后门
    // 全部是正常软件绝不触碰的高危操作 -> 一律 Block(安全模式启动除外 -> Ask)。
    // ======================================================================
    private static void AddBootAndBackdoorRules(List<DefenseRule> list)
    {
        // --- 辅助功能"映像劫持"后门(登录界面即可拿 SYSTEM shell)-> Block ---
        File_(list, @"*\System32\sethc.exe", VerdictAction.Block,
            "篡改粘滞键程序(sethc.exe,登录后门)", hardOverride: true);
        File_(list, @"*\System32\utilman.exe", VerdictAction.Block,
            "篡改辅助工具管理器(utilman.exe,登录后门)", hardOverride: true);
        File_(list, @"*\System32\osk.exe", VerdictAction.Block,
            "篡改屏幕键盘(osk.exe,登录后门)", hardOverride: true);
        File_(list, @"*\System32\Magnify.exe", VerdictAction.Block,
            "篡改放大镜(Magnify.exe,登录后门)", hardOverride: true);
        File_(list, @"*\System32\Narrator.exe", VerdictAction.Block,
            "篡改讲述人(Narrator.exe,登录后门)", hardOverride: true);
        Reg(list, @"*\Image File Execution Options\sethc.exe\*", VerdictAction.Block,
            "为粘滞键设置调试器劫持(IFEO 登录后门)");
        Reg(list, @"*\Image File Execution Options\utilman.exe\*", VerdictAction.Block,
            "为辅助工具设置调试器劫持(IFEO 登录后门)");
        Reg(list, @"*\Image File Execution Options\osk.exe\*", VerdictAction.Block,
            "为屏幕键盘设置调试器劫持(IFEO 登录后门)");

        // --- 引导配置篡改(为加载未签名驱动/Rootkit 铺路)-> Block ---
        Cmd(list, @"*bcdedit*testsigning*on*", VerdictAction.Block,
            "启用测试签名模式(bcdedit,可加载未签名驱动)");
        Cmd(list, @"*bcdedit*nointegritychecks*on*", VerdictAction.Block,
            "禁用驱动完整性检查(bcdedit)");
        Cmd(list, @"*bcdedit*loadoptions*DISABLE_INTEGRITY_CHECKS*", VerdictAction.Block,
            "禁用内核完整性检查(bcdedit loadoptions)");
        Reg(list, @"*\CI\Policy\*", VerdictAction.Block,
            "篡改代码完整性策略(CI)");

        // --- 安全模式启动(可能正常排障)-> Ask ---
        Cmd(list, @"*bcdedit*set*{*}*safeboot*", VerdictAction.Ask,
            "配置安全模式启动(可能用于绕过防护)");
    }

    // ======================================================================
    // 批次 9:WMI 持久化 / 横向移动
    // WMI 事件订阅持久化是确定性恶意 -> Block;
    // 远程执行/PsExec 管理员运维也用 -> Ask。
    // ======================================================================
    private static void AddWmiAndLateralRules(List<DefenseRule> list)
    {
        // --- WMI 事件订阅持久化(无文件持久化经典手法)-> Block ---
        Cmd(list, @"*__EventFilter*", VerdictAction.Block,
            "创建 WMI 事件过滤器(无文件持久化)");
        Cmd(list, @"*CommandLineEventConsumer*", VerdictAction.Block,
            "创建 WMI 命令行消费者(无文件持久化)");
        Cmd(list, @"*ActiveScriptEventConsumer*", VerdictAction.Block,
            "创建 WMI 脚本消费者(无文件持久化)");
        Cmd(list, @"*__FilterToConsumerBinding*", VerdictAction.Block,
            "绑定 WMI 事件过滤器与消费者(无文件持久化)");

        // --- 横向移动(运维也可能用)-> Ask ---
        Cmd(list, @"*wmic*/node:*process*call*create*", VerdictAction.Ask,
            "wmic 远程创建进程(横向移动)");
        Cmd(list, @"*Invoke-WmiMethod*-ComputerName*Create*", VerdictAction.Ask,
            "WMI 远程执行(横向移动)");
        Cmd(list, @"*Invoke-Command*-ComputerName*", VerdictAction.Ask,
            "远程执行命令(WinRM,可能横向)");
        Cmd(list, @"*psexec*-s*", VerdictAction.Ask,
            "PsExec 以 SYSTEM 远程执行(横向移动)");
        Cmd(list, @"*psexec*\\*", VerdictAction.Ask,
            "PsExec 远程执行(横向移动)");
        Cmd(list, @"*sc*\\*create*", VerdictAction.Ask,
            "在远程主机创建服务(横向移动)");
        Cmd(list, @"*net*use*\\*admin$*", VerdictAction.Ask,
            "连接 ADMIN$ 管理共享(横向移动)");
        Cmd(list, @"*net*use*\\*c$*", VerdictAction.Ask,
            "连接 C$ 管理共享(横向移动)");
    }

    // ======================================================================
    // 批次 10:Office 宏与受保护视图降级
    // 优化:Office开发者/VBA开发者需要修改这些设置,将Block改为Ask
    // 写 Office 启动目录(加载项)正常插件也会做 -> Ask。
    // ======================================================================
    private static void AddOfficeMacroRules(List<DefenseRule> list)
    {
        // --- 场景1:宏安全级别(开发者 vs 普通用户) ---
        // 启用所有宏(VBAWarnings=1) - 开发者调试需要，普通用户不应设置
        Reg(list, @"*\Office\*\*\Security\VBAWarnings*", VerdictAction.Ask,
            "降低 Office 宏安全级别(启用所有宏,开发者可能需要)");
        // 禁用宏通知(VBAWarnings=2) - 可能是恶意配置
        Reg(list, @"*\Office\*\*\Security\VBAWarnings*2*", VerdictAction.Ask,
            "禁用 Office 宏通知(可疑配置)");
        // 允许VBA对象模型访问 - 宏自我复制需要
        Reg(list, @"*\Office\*\*\Security\AccessVBOM*", VerdictAction.Ask,
            "允许程序化访问 VBA 工程对象模型(宏自我复制)");
        
        // --- 场景2:受保护视图(开发者调试 vs 恶意规避) ---
        // 关闭网络文件受保护视图 - 开发者调试需要
        Reg(list, @"*\Office\*\*\Security\ProtectedView\DisableInternetFilesInPV*", VerdictAction.Ask,
            "关闭网络文件受保护视图(Office,开发者调试)");
        // 关闭附件受保护视图 - 可能是恶意规避
        Reg(list, @"*\Office\*\*\Security\ProtectedView\DisableAttachmentsInPV*", VerdictAction.Ask,
            "关闭附件受保护视图(Office,开发者调试)");
        // 关闭不安全位置受保护视图 - 可能是恶意规避
        Reg(list, @"*\Office\*\*\Security\ProtectedView\DisableUnsafeLocationsInPV*", VerdictAction.Ask,
            "关闭不安全位置受保护视图(Office,开发者调试)");
        // 禁用所有受保护视图 - 高可疑配置
        Reg(list, @"*\Office\*\*\Security\ProtectedView\DisableAllProtectedView*", VerdictAction.Ask,
            "禁用所有受保护视图(高可疑配置)");
        
        // --- 场景3:Office启动目录(插件安装 vs 恶意持久化) ---
        // Word启动目录 - 合法插件会写入
        File_(list, @"*\Microsoft\Word\STARTUP\*", VerdictAction.Ask,
            "向 Word 启动目录写入模板/加载项(持久化)");
        // Excel启动目录 - 合法插件会写入
        File_(list, @"*\Microsoft\Excel\XLSTART\*", VerdictAction.Ask,
            "向 Excel 启动目录写入工作簿(持久化)");
        // PowerPoint启动目录 - 合法插件会写入
        File_(list, @"*\Microsoft\PowerPoint\STARTUP\*", VerdictAction.Ask,
            "向 PowerPoint 启动目录写入演示文稿(持久化)");
        // Outlook启动目录 - 合法插件会写入
        File_(list, @"*\Microsoft\Outlook\STARTUP\*", VerdictAction.Ask,
            "向 Outlook 启动目录写入脚本(持久化)");
        
        // --- 场景4:Office全局模板(宏持久化) ---
        // Normal.dotm - Word全局模板，恶意宏会修改
        File_(list, @"*\Microsoft\Templates\Normal.dotm", VerdictAction.Ask,
            "篡改 Word 全局模板 Normal.dotm(宏持久化)");
        // Personal.xlsb - Excel个人宏工作簿
        File_(list, @"*\Microsoft\Excel\XLSTART\Personal.xlsb", VerdictAction.Ask,
            "篡改 Excel 个人宏工作簿(宏持久化)");
        
        // --- 场景5:Office加载项注册(合法插件 vs 恶意加载) ---
        // COM加载项注册
        Reg(list, @"*\Office\*\*\Addins\*", VerdictAction.Ask,
            "注册 Office COM 加载项(可能持久化)");
        // VBA加载项注册
        Reg(list, @"*\Office\*\*\WLL\*", VerdictAction.Ask,
            "注册 Office VBA 加载项(可能持久化)");
    }

    // ======================================================================
    // 批次 11:反取证(清日志 / 擦痕迹)
    // 清空事件日志、删卷影日志、wevtutil cl 是攻击者收尾动作,正常运维极少这么做 -> Block;
    // 改事件日志服务启动配置 -> Ask。
    // ======================================================================
    private static void AddAntiForensicsRules(List<DefenseRule> list)
    {
        Cmd(list, @"*wevtutil*cl*", VerdictAction.Block,
            "清空事件日志(wevtutil cl,反取证)");
        Cmd(list, @"*Clear-EventLog*", VerdictAction.Block,
            "清空事件日志(PowerShell,反取证)");
        Cmd(list, @"*wevtutil*sl*/e:false*", VerdictAction.Block,
            "禁用事件日志通道(wevtutil sl,反取证)");
        Cmd(list, @"*fsutil*usn*deletejournal*", VerdictAction.Block,
            "删除 USN 变更日志(fsutil,反取证)");
        Reg(list, @"*\Services\eventlog\*\Start*", VerdictAction.Ask,
            "篡改事件日志服务启动配置");
    }

    // ======================================================================
    // 批次 12:BYOVD 脆弱驱动(Bring Your Own Vulnerable Driver)
    // 已知脆弱驱动文件落地 / 注册为内核服务是确定性恶意(用于关杀软)-> Block。
    // ======================================================================
    private static void AddByovdRules(List<DefenseRule> list)
    {
        // --- 已知脆弱驱动文件落地 -> Block ---
        File_(list, @"*\amsdk.sys", VerdictAction.Block,
            "BYOVD:投放脆弱驱动 amsdk.sys(WatchDog,用于关杀软)", hardOverride: true);
        File_(list, @"*\Truesight.sys", VerdictAction.Block,
            "BYOVD:投放脆弱驱动 Truesight.sys(用于关杀软)", hardOverride: true);
        File_(list, @"*\zam64.sys", VerdictAction.Block,
            "BYOVD:投放 Zemana 脆弱驱动 zam64.sys", hardOverride: true);
        File_(list, @"*\zamguard64.sys", VerdictAction.Block,
            "BYOVD:投放 Zemana 脆弱驱动 zamguard64.sys", hardOverride: true);

        // --- 把脆弱驱动注册为内核服务 -> Block ---
        Reg(list, @"*\Services\amsdk*", VerdictAction.Block,
            "BYOVD:注册 amsdk 驱动服务");
        Reg(list, @"*\Services\Truesight*", VerdictAction.Block,
            "BYOVD:注册 Truesight 驱动服务");
        Reg(list, @"*\Services\zam*", VerdictAction.Block,
            "BYOVD:注册 Zemana(zam)驱动服务");

        // --- 从用户可写目录加载内核驱动(.sys)-> Block ---
        list.Add(new DefenseRule
        {
            Type = EventType.ImageLoad,
            TargetPattern = @"*.sys",
            ActorPattern = @"*\AppData\*",
            Action = VerdictAction.Block,
            Note = $"{BuiltInTag} BYOVD:从 AppData 加载内核驱动(.sys)"
        });
    }

    // ======================================================================
    // 批次 13:银狐(Silver Fox / SwimSnake / UTG-Q-1000 / Void Arachne)2025-2026 最新动向
    //
    // 依据 2025 下半年至 2026 年公开威胁情报(Check Point / Kaspersky / Hexastrike /
    // Sekoia / ESET / The Hacker News 等)归纳的当前在用 TTP:
    //  - 载荷家族:Winos 4.0 / ValleyRAT(核心 login-module.dll)、HoldingHands(Gh0stBins)、
    //    AtlasCross RAT(AtlasAgent)、ABCDoor(Python 后门)、Blackmoon。
    //  - 加载器:RustSL(Rust 免杀加载器,exe 伪装成 PDF)、JavaScript/SFX 释放器。
    //  - 投递:钓鱼邮件(税务主题/工资调整/审计通知)、仿冒安装包(Surfshark/Signal/
    //    Telegram/Zoom/Teams/QuickQ/UltraViewer 等域名仿冒,盗用 EV 证书签名)。
    //  - BYOVD:微软签名脆弱驱动 WatchDog(amsdk.sys)+ Zemana 双驱动策略关杀软,
    //    投放内核 rootkit("Driver Plugin",部分有效签名可在 Win11 加载)。
    //  - 持久化:Phantom Persistence(拦截关机信号伪装更新触发重启重运行)、
    //    AppShellElevationService 服务、持久化计划任务、.pwn 关联劫持。
    //  - 防御规避:PowerChell(原生 C/C++ PowerShell 引擎,禁用 AMSI/ETW/CLM/ScriptBlock 日志)、
    //    TCP 级强杀国产安全软件连接、APC 用户态 shellcode 注入、强删 AV/EDR 驱动。
    //  - 重点滥用:DLL 侧载(签名合法程序 + 同目录恶意 DLL)、注入微信(WeChat)、RDP 会话劫持。
    //
    // 仅对正常软件几乎不触发的确定性恶意特征用 Block;可能与正常软件重叠的用 Ask。
    // ======================================================================
    private static void AddSilverFox2026Rules(List<DefenseRule> list)
    {
        // --- BYOVD:已知脆弱/恶意驱动文件落地(2025-2026 仍在用)-> Block ---
        File_(list, @"*\amsdk.sys", VerdictAction.Block,
            "银狐 BYOVD:投放脆弱驱动 amsdk.sys(WatchDog,用于关杀软)", hardOverride: true);
        File_(list, @"*\wamsdk.sys", VerdictAction.Block,
            "银狐 BYOVD:投放 WatchDog 驱动变体(关杀软)", hardOverride: true);
        File_(list, @"*\ZAM.exe", VerdictAction.Block,
            "银狐 BYOVD:投放 Zemana 释放器(关杀软)", hardOverride: true);

        // --- 内核 rootkit「Driver Plugin」从用户可写目录加载 -> Block ---
        list.Add(new DefenseRule
        {
            Type = EventType.ImageLoad,
            TargetPattern = @"*.sys",
            ActorPattern = @"*\AppData\*",
            Action = VerdictAction.Block,
            Note = $"{BuiltInTag} 银狐:从 AppData 加载内核驱动(疑似 ValleyRAT Driver Plugin rootkit)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.ImageLoad,
            TargetPattern = @"*.sys",
            ActorPattern = @"*\Users\Public\*",
            Action = VerdictAction.Block,
            Note = $"{BuiltInTag} 银狐:从 Public 目录加载内核驱动(疑似内核 rootkit)"
        });

        // --- ValleyRAT / Winos:.pwn 文件关联劫持(标志性持久化)-> Block ---
        Reg(list, @"*\Classes\.pwn\*", VerdictAction.Block,
            "银狐 ValleyRAT:劫持 .pwn 文件关联(持久化)");
        Reg(list, @"*\Classes\pwnfile\*", VerdictAction.Block,
            "银狐 ValleyRAT:注册 .pwn 文件类型处理器");

        // --- AppShellElevationService 持久化服务(2026 税务钓鱼链 IOC)-> Block ---
        Reg(list, @"*\Services\AppShellElevationService*", VerdictAction.Block,
            "银狐:创建 AppShellElevationService 持久化服务");

        // --- ValleyRAT 核心模块 / 加载器投放 -> Ask(签名合法程序侧载,避免误伤需用户确认)---
        File_(list, @"*\login-module.dll*", VerdictAction.Ask,
            "银狐 ValleyRAT:疑似核心模块 login-module.dll 落地");

        // --- Phantom Persistence:拦截关机伪装更新触发重启重运行 -> Block ---
        // 该手法滥用 RegisterApplicationRestart / 关机阻断,常落在 RunOnce 的更新型键。
        Reg(list, @"*\RunOnce\*Update*", VerdictAction.Block,
            "银狐 ABCDoor:疑似 Phantom Persistence(伪装更新的重启自运行)");

        // --- PowerChell / AMSI·ETW 绕过(命令行特征)-> Block(正常软件不会这么做)---
        Cmd(list, @"*amsiInitFailed*", VerdictAction.Block,
            "银狐 PowerChell:AMSI 绕过(amsiInitFailed)");
        Cmd(list, @"*System.Management.Automation.AmsiUtils*", VerdictAction.Block,
            "银狐 PowerChell:反射篡改 AmsiUtils(AMSI 绕过)");
        Cmd(list, @"*EtwEventWrite*", VerdictAction.Block,
            "银狐 PowerChell:ETW 致盲(EtwEventWrite 补丁)");

        // --- 注入微信(WeChat)/ 企业微信 -> Ask(微信本体行为多,交用户确认避免误伤)---
        Proc(list, EventType.RemoteThread, @"*\WeChat.exe", VerdictAction.Ask,
            "银狐 AtlasCross:向微信(WeChat)注入远程线程");
        Proc(list, EventType.RemoteThread, @"*\WXWork.exe", VerdictAction.Ask,
            "银狐:向企业微信(WXWork)注入远程线程");

        // --- 伪装常见软件的安装包/进程(2026 typosquat 投递,未签名时极可能仿冒)-> Ask ---
        FakeInstaller(list, @"*\Surfshark*Setup*.exe", "银狐:仿冒 Surfshark VPN 安装包");
        FakeInstaller(list, @"*\Signal*Setup*.exe", "银狐:仿冒 Signal 安装包");
        FakeInstaller(list, @"*\Telegram*Setup*.exe", "银狐:仿冒 Telegram 安装包");
        FakeInstaller(list, @"*\ZoomInstaller*.exe", "银狐:仿冒 Zoom 安装包");
        FakeInstaller(list, @"*\Teams*Setup*.exe", "银狐:仿冒 Microsoft Teams 安装包");
        FakeInstaller(list, @"*\QuickQ*.exe", "银狐:仿冒 QuickQ VPN 安装包");
        FakeInstaller(list, @"*\UltraViewer*.exe", "银狐:仿冒 UltraViewer 安装包");
        FakeInstaller(list, @"*\LetsVPN*.exe", "银狐:仿冒 LetsVPN 安装包");

        // --- RustSL 加载器:exe 伪装成 PDF(双扩展名已在批次 7 覆盖,这里补 .pdf.scr 等)-> Block ---
        Proc(list, EventType.ProcessCreate, @"*.pdf.scr", VerdictAction.Block,
            "银狐 RustSL:伪装 PDF 的可执行体(.pdf.scr)");
        Proc(list, EventType.ProcessCreate, @"*.pdf.com", VerdictAction.Block,
            "银狐 RustSL:伪装 PDF 的可执行体(.pdf.com)");

        // --- zpaqfranz 滥用(2026 链中用于解包/释放)-> Ask(合法备份工具,可能误伤)---
        Cmd(list, @"*zpaqfranz*", VerdictAction.Ask,
            "银狐:zpaqfranz 解包(疑似释放载荷)");

        // --- 持久化计划任务(伪装为 Update)-> Ask ---
        File_(list, @"*\System32\Tasks\*Update*", VerdictAction.Ask,
            "银狐:创建伪装为 Update 的计划任务(持久化)");

        // --- DLL 侧载:签名合法程序从用户目录加载未签名 DLL -> Ask ---
        list.Add(new DefenseRule
        {
            Type = EventType.ImageLoad,
            TargetPattern = @"*\AppData\*.dll",
            RequireUnsigned = true,
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 银狐:疑似 DLL 侧载(合法程序从 AppData 加载未签名 DLL)"
        });

        // --- 结束/TCP 强杀国产安全软件(AtlasCross 不走 BYOVD 改用 TCP 级断连)补充进程 -> Block ---
        Proc(list, EventType.ProcessTerminate, @"*\usysdiag.exe", VerdictAction.Block,
            "银狐:试图结束安全分析工具(usysdiag)");
        Proc(list, EventType.ProcessTerminate, @"*\KSafeTray.exe", VerdictAction.Block,
            "银狐:试图结束金山安全");

        // ========== 2026 年新增 IOC / TTP ==========

        // --- 新增 BYOVD 脆弱驱动(2026 新变种仍在用) ---
        File_(list, @"*\ntfs.sys.bak", VerdictAction.Block,
            "银狐 BYOVD:投放 NTFS 驱动备份(用于替换系统驱动)", hardOverride: true);
        File_(list, @"*\WinRing0x64.sys", VerdictAction.Block,
            "银狐 BYOVD:投放 WinRing0 脆弱驱动(用于关杀软)", hardOverride: true);
        File_(list, @"*\lha.sys", VerdictAction.Block,
            "银狐 BYOVD:投放 lha 脆弱驱动(用于关杀软)", hardOverride: true);
        File_(list, @"*\procexp.sys", VerdictAction.Block,
            "银狐 BYOVD:投放 Process Explorer 驱动(滥用用于提权/关杀软)", hardOverride: true);

        // --- 新增仿冒安装包(2026 新增投递域名) ---
        FakeInstaller(list, @"*\WhatsApp*Setup*.exe", "银狐:仿冒 WhatsApp 安装包");
        FakeInstaller(list, @"*\WeChat*Setup*.exe", "银狐:仿冒微信安装包");
        FakeInstaller(list, @"*\QQ*Setup*.exe", "银狐:仿冒 QQ 安装包");
        FakeInstaller(list, @"*\DingTalk*Setup*.exe", "银狐:仿冒钉钉安装包");
        FakeInstaller(list, @"*\Feishu*Setup*.exe", "银狐:仿冒飞书安装包");
        FakeInstaller(list, @"*\WPS*Setup*.exe", "银狐:仿冒 WPS 安装包");
        FakeInstaller(list, @"*\Todesk*Setup*.exe", "银狐:仿冒 ToDesk 安装包");
        FakeInstaller(list, @"*\Sunlogin*Setup*.exe", "银狐:仿冒向日葵安装包");
        FakeInstaller(list, @"*\RustDesk*Setup*.exe", "银狐:仿冒 RustDesk 安装包");
        FakeInstaller(list, @"*\AnyDesk*Setup*.exe", "银狐:仿冒 AnyDesk 安装包");
        FakeInstaller(list, @"*\7z*Setup*.exe", "银狐:仿冒 7-Zip 安装包");
        FakeInstaller(list, @"*\WinRAR*Setup*.exe", "银狐:仿冒 WinRAR 安装包");

        // --- 新增持久化服务名(2026 新变种) ---
        Reg(list, @"*\Services\WindowsDefenderService*", VerdictAction.Block,
            "银狐:创建仿冒 Defender 的持久化服务");
        Reg(list, @"*\Services\MicrosoftTelemetry*", VerdictAction.Block,
            "银狐:创建仿冒微软遥测的持久化服务");
        Reg(list, @"*\Services\SystemHelpService*", VerdictAction.Block,
            "银狐:创建 SystemHelpService 持久化服务");
        Reg(list, @"*\Services\NetworkConnectionService*", VerdictAction.Block,
            "银狐:创建 NetworkConnectionService 持久化服务");
        Reg(list, @"*\Services\RuntimeBroker*", VerdictAction.Block,
            "银狐:创建仿冒 RuntimeBroker 的持久化服务(注意:真正的 RuntimeBroker 不是服务)");

        // --- 新增计划任务持久化(伪装为系统/更新任务) ---
        File_(list, @"*\System32\Tasks\*MicrosoftEdge*", VerdictAction.Ask,
            "银狐:创建仿冒 Edge 更新的计划任务(持久化)");
        File_(list, @"*\System32\Tasks\*WindowsDefender*", VerdictAction.Ask,
            "银狐:创建仿冒 Defender 的计划任务(持久化)");
        File_(list, @"*\System32\Tasks\*GoogleUpdate*", VerdictAction.Ask,
            "银狐:创建仿冒 Google 更新的计划任务(持久化)");
        File_(list, @"*\System32\Tasks\*AdobeARM*", VerdictAction.Ask,
            "银狐:创建仿冒 Adobe 更新的计划任务(持久化)");

        // --- 新增 Gh0st / ValleyRAT 变种 DLL 名 ---
        File_(list, @"*\gh0st.dll", VerdictAction.Block,
            "银狐 Gh0st:恶意模块 gh0st.dll 落地");
        File_(list, @"*\gh0st.dat", VerdictAction.Block,
            "银狐 Gh0st:恶意载荷 gh0st.dat 落地");
        File_(list, @"*\svchost.dll", VerdictAction.Block,
            "银狐:仿冒 svchost 的恶意 DLL(侧载用)");
        File_(list, @"*\winlogon.dll", VerdictAction.Block,
            "银狐:仿冒 winlogon 的恶意 DLL(侧载用)");
        File_(list, @"*\explorer.dll", VerdictAction.Block,
            "银狐:仿冒 explorer 的恶意 DLL(侧载用)");
        File_(list, @"*\RuntimeBroker.dll", VerdictAction.Block,
            "银狐:仿冒 RuntimeBroker 的恶意 DLL(侧载用)");
        File_(list, @"*\Windows.Media.dll", VerdictAction.Block,
            "银狐:仿冒 Windows.Media 的恶意 DLL(侧载用)");

        // --- 新增 ValleyRAT / Winos 变种 C2 通信特征 ---
        // ValleyRAT 使用自定义协议,通常在特定端口通信
        // 这里通过命令行特征检测 C2 配置注入
        Cmd(list, @"*-enc*JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA*", VerdictAction.Block,
            "银狐:PowerShell 编码载荷(ValleyRAT C2 配置注入)");
        Cmd(list, @"*-enc*SUVYIChOAGUAdwAtAE8AYgBqAGUAYwB0*", VerdictAction.Block,
            "银狐:PowerShell 编码载荷(IEX 下载执行)");

        // --- 新增 DLL 侧载特征(合法签名程序 + 同目录恶意 DLL) ---
        // 银狐常把合法签名程序(如 wps.exe)和恶意 DLL(wps.dll)放在同一目录
        list.Add(new DefenseRule
        {
            Type = EventType.ImageLoad,
            TargetPattern = @"*\wps.dll",
            ActorPattern = @"*\AppData\*",
            RequireUnsigned = true,
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 银狐:从 AppData 加载 wps.dll(疑似 WPS 侧载)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.ImageLoad,
            TargetPattern = @"*\qq.exe",
            ActorPattern = @"*\AppData\*",
            RequireUnsigned = true,
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 银狐:从 AppData 加载 qq.exe(疑似 QQ 侧载)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.ImageLoad,
            TargetPattern = @"*\wechat.dll",
            ActorPattern = @"*\AppData\*",
            RequireUnsigned = true,
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 银狐:从 AppData 加载 wechat.dll(疑似微信侧载)"
        });

        // --- 新增注册表持久化(IFEO 新变种) ---
        // 银狐新变种使用 IFEO 劫持常见系统工具
        Reg(list, @"*\Image File Execution Options\cmd.exe\*", VerdictAction.Block,
            "银狐:劫持 cmd.exe 的 IFEO(持久化/提权)");
        Reg(list, @"*\Image File Execution Options\powershell.exe\*", VerdictAction.Block,
            "银狐:劫持 powershell.exe 的 IFEO(持久化/提权)");
        Reg(list, @"*\Image File Execution Options\conhost.exe\*", VerdictAction.Block,
            "银狐:劫持 conhost.exe 的 IFEO(持久化/提权)");

        // --- 新增 AMSI/ETW 绕过变种 ---
        Cmd(list, @"*Set-MpPreference*DisableIOAVProtection*$true*", VerdictAction.Block,
            "银狐:禁用 Defender IOAV 保护(AMSI 绕过变种)");
        Cmd(list, @"*Set-MpPreference*SubmitSamplesConsent*2*", VerdictAction.Block,
            "银狐:禁用 Defender 样本提交(规避云检测)");
        Cmd(list, @"*Set-MpPreference*MAPSReporting*0*", VerdictAction.Block,
            "银狐:禁用 Defender MAPS 报告(规避云检测)");
        Cmd(list, @"*Add-MpPreference*ExclusionProcess*", VerdictAction.Block,
            "银狐:添加 Defender 进程排除(免杀)");

        // --- 新增网络 C2 通信特征 ---
        // ValleyRAT 常用的 C2 端口(非标准端口的 HTTP/HTTPS)
        // 这些通过网络事件检测,但当前引擎仅按进程匹配,故用进程+命令行组合
        Cmd(list, @"*powershell*Net.Sockets.TCPClient*", VerdictAction.Ask,
            "银狐:PowerShell TCP 反向连接(疑似 C2)");
        Cmd(list, @"*powershell*Net.Sockets.Socket*", VerdictAction.Ask,
            "银狐:PowerShell Socket 通信(疑似 C2)");

        // --- 新增文件膨胀规避(2026 新变种用更大体积) ---
        // 银狐新变种把文件撑到 200MB+ 以超过沙箱扫描上限
        // 这由 ThreatDetector 的文件膨胀检测覆盖,这里补充特定文件名
        File_(list, @"*\Windows\Temp\*.exe", VerdictAction.Ask,
            "银狐:从 Windows Temp 释放可执行体(疑似载荷落地)");

        // --- 新增 RDP 劫持特征 ---
        // 银狐新变种通过修改 RDP 注册表实现远程控制
        Reg(list, @"*\Terminal Server\*fSingleSessionPerUser*", VerdictAction.Ask,
            "银狐:修改 RDP 单会话限制(疑似 RDP 劫持)");
        Reg(list, @"*\Terminal Server\*fDenyTSConnections*", VerdictAction.Block,
            "银狐:修改 RDP 连接策略(疑似开启远程桌面)");

        // --- 新增 UAC 绕过变种 ---
        // 银狐新变种使用 fodhelper/eventvwr/sdclt 等 auto-elevate 程序绕过 UAC
        // 这些已在批次 16 覆盖,这里补充新的注册表劫持路径
        Reg(list, @"*\Classes\ms-settings\shell\open\command\DelegateExecute*", VerdictAction.Block,
            "银狐:劫持 ms-settings DelegateExecute(UAC 绕过变种)");
    }

    // ======================================================================
    // 批次 14:远控木马劫持微信 / QQ 进行群发(IM 控制类滥用)
    //
    // 背景:银狐及各类远控(ValleyRAT / AtlasCross / Gh0stRAT 衍生)常见变现手法是
    // 把恶意模块注入微信(WeChat/Weixin)、企业微信(WXWork)、QQ/TIM 进程,
    // 调用其内部接口进行「自动群发广告/诈骗链接」「自动加好友」「窃取聊天记录」。
    //
    // 可观测的恶意信号(本引擎可见):
    //  1) 外部进程向 IM 进程注入远程线程(RemoteThread);
    //  2) IM 进程从用户可写目录(AppData/Temp/Public)加载未签名 DLL(白加黑侧载,
    //     群发模块常以此形式挂进微信);
    //  3) 非官方进程释放/写入到 IM 安装目录下的 DLL(替换/植入群控模块)。
    //
    // 防误伤原则:
    //  - 注入 IM 用 Ask(微信自身多进程 + 合法插件生态,直接 Block 易误杀)交用户确认;
    //  - IM 从用户目录加载「未签名」DLL 才命中(RequireUnsigned),官方签名模块不误伤;
    //  - 仅对「确定性群控特征」(如已知群发模块 DLL 名、注入系统级 IM 进程)用 Block。
    // ======================================================================
    private static void AddImControlRules(List<DefenseRule> list)
    {
        // --- 向 IM 进程注入远程线程(群控/盗号的常见入口)-> Ask ---
        // 仅当「注入方未签名」才命中:IM 本体多为多进程架构(如 QQNT 自身进程间注入线程),
        // 且官方进程带腾讯有效签名;若不加此约束,QQ/微信自注入这类正常行为会被反复误报。
        // 真正的群控木马其注入模块/宿主通常未签名(白加黑侧载),RequireUnsigned 精准锁定它们。
        ImInjectRemoteThread(list, @"*\Weixin.exe",
            "向微信(Weixin)注入远程线程(疑似群发/盗号控制)");
        ImInjectRemoteThread(list, @"*\WeChatApp.exe",
            "向微信小程序宿主注入远程线程(疑似控制)");
        ImInjectRemoteThread(list, @"*\QQ.exe",
            "向 QQ 注入远程线程(疑似群发/盗号控制)");
        ImInjectRemoteThread(list, @"*\TIM.exe",
            "向 TIM 注入远程线程(疑似群发/盗号控制)");
        ImInjectRemoteThread(list, @"*\QQExternal.exe",
            "向 QQ 外部模块注入远程线程(疑似控制)");

        // --- IM 进程从用户可写目录加载未签名 DLL(白加黑:群控模块挂进微信/QQ)-> Ask ---
        ImUnsignedModuleFromUserDir(list);

        // --- 非 IM 官方进程向 IM 安装目录写入/植入 DLL(替换群控模块)-> Ask ---
        File_(list, @"*\Tencent\WeChat\*.dll", VerdictAction.Ask,
            "向微信安装目录写入 DLL(疑似植入群控/外挂模块)");
        File_(list, @"*\Tencent\Weixin\*.dll", VerdictAction.Ask,
            "向微信(Weixin)安装目录写入 DLL(疑似植入群控模块)");
        File_(list, @"*\Tencent\WXWork\*.dll", VerdictAction.Ask,
            "向企业微信安装目录写入 DLL(疑似植入群控模块)");
        File_(list, @"*\Tencent\*\QQ\*.dll", VerdictAction.Ask,
            "向 QQ 安装目录写入 DLL(疑似植入群控模块)");

        // --- 已知群控/外挂模块常用 DLL 名(确定性恶意特征)-> Block ---
        // 这些模块名是第三方"微信群发/营销外挂"和远控群控插件的典型命名,正常软件不会出现。
        File_(list, @"*\wxhelper.dll", VerdictAction.Block,
            "微信群控外挂模块 wxhelper.dll 落地");
        File_(list, @"*\WeChatHelper*.dll", VerdictAction.Block,
            "微信群控外挂模块 WeChatHelper 落地");
        File_(list, @"*\wxauto*.dll", VerdictAction.Block,
            "微信自动化群发模块 wxauto 落地");
        File_(list, @"*\ComWeChatRobot*.dll", VerdictAction.Block,
            "微信机器人群控模块 ComWeChatRobot 落地");
        File_(list, @"*\wxrobot*.dll", VerdictAction.Block,
            "微信群发机器人模块 wxrobot 落地");
        File_(list, @"*\qqhelper*.dll", VerdictAction.Block,
            "QQ 群控外挂模块 qqhelper 落地");

        // --- 已知群控模块被加载进 IM 进程(运行期拦截,改名规避由侧载规则兜底)-> Block ---
        list.Add(new DefenseRule
        {
            Type = EventType.ImageLoad,
            TargetPattern = @"*\wxhelper.dll",
            Action = VerdictAction.Block,
            Note = $"{BuiltInTag} 加载微信群控外挂模块 wxhelper.dll(群发/自动化)"
        });
        list.Add(new DefenseRule
        {
            Type = EventType.ImageLoad,
            TargetPattern = @"*\wxauto*.dll",
            Action = VerdictAction.Block,
            Note = $"{BuiltInTag} 加载微信自动化群发模块 wxauto(群发)"
        });

        // --- 命令行驱动的微信自动化群发框架(Python/PyWeChatSpy/itchat 等)-> Ask ---
        Cmd(list, @"*wxauto*", VerdictAction.Ask,
            "命令行调用微信自动化框架 wxauto(疑似群发)");
        Cmd(list, @"*itchat*", VerdictAction.Ask,
            "命令行调用微信网页协议库 itchat(疑似群发)");
        Cmd(list, @"*PyWeChatSpy*", VerdictAction.Ask,
            "命令行调用微信控制框架 PyWeChatSpy(疑似群发)");
    }

    // ======================================================================
    // 批次 14b:银狐 —— 微信 / QQ「群发外挂框架」专项(一键群发广告/诈骗链接)
    //
    // 背景:银狐(ValleyRAT/Winos 系)与灰产「营销外挂」落地后,普遍不是自己实现协议,
    // 而是复用成熟的第三方「PC 微信/QQ 群控框架」挂进 IM 进程,调用其内部接口做:
    //   自动群发消息/朋友圈、批量加好友、拉群、导出通讯录与聊天记录。
    // 这些框架各自有非常具名的注入模块 DLL 与命令行/包名特征,正常用户环境几乎不出现。
    //
    // 覆盖的已知框架(按注入模块/CLI 命名)——
    //   WeChatFerry(wcf/wcferry/spy.dll)、ntchat(wcprobe.dll)、
    //   WeChatPCAPI、wxbot / wxbotpp、CWeChatRobot、微信 hook「sidecar」等;
    //   QQ 侧:qqbot / QQRobot / TIMHook 等群发模块。
    //
    // 防误伤原则(与批次 14 一致):
    //   - 「具名群控/群发模块 DLL 落地或被加载」= 确定性外挂特征 -> Block
    //     (这些名字正常软件不会出现,改名规避由批次 14 的未签名侧载 Ask 兜底);
    //   - 「命令行调用群发框架 / 包」可能是安全研究或自动化办公 -> Ask,交用户确认;
    //   - 「向企业微信 / QQ 附属进程注入远程线程」-> 仅未签名注入方才命中(Ask)。
    // ======================================================================
    private static void AddImMassMessagingRules(List<DefenseRule> list)
    {
        // --- 已知群发/群控框架的注入模块 DLL 落地(确定性外挂特征)-> Block ---
        // WeChatFerry:开源 PC 微信 RPC 框架,常被灰产用于自动群发/机器人。
        File_(list, @"*\wcf.dll", VerdictAction.Block,
            "微信群发框架 WeChatFerry 模块 wcf.dll 落地(自动群发/机器人)");
        File_(list, @"*\wcferry*.dll", VerdictAction.Block,
            "微信群发框架 WeChatFerry 模块落地(自动群发/机器人)");
        File_(list, @"*\WeChatFerry*.dll", VerdictAction.Block,
            "微信群发框架 WeChatFerry 模块落地(自动群发/机器人)");
        File_(list, @"*\spy.dll", VerdictAction.Block,
            "微信群发框架注入模块 spy.dll 落地(WeChatFerry/hook 群发)");
        // ntchat:另一常见 PC 微信 hook 框架,注入模块名 wcprobe.dll。
        File_(list, @"*\wcprobe.dll", VerdictAction.Block,
            "微信群控框架 ntchat 模块 wcprobe.dll 落地(群发/hook)");
        // WeChatPCAPI / CWeChatRobot / wxbot 系列群控 SDK。
        File_(list, @"*\WeChatPCAPI*.dll", VerdictAction.Block,
            "微信群控 SDK WeChatPCAPI 落地(群发/自动化)");
        File_(list, @"*\CWeChatRobot*.dll", VerdictAction.Block,
            "微信机器人群控模块 CWeChatRobot 落地(群发)");
        File_(list, @"*\wxbot*.dll", VerdictAction.Block,
            "微信群发机器人模块 wxbot 落地(群发)");
        File_(list, @"*\WeChatSpy*.dll", VerdictAction.Block,
            "微信监听/群控模块 WeChatSpy 落地(群发/聊天记录窃取)");
        File_(list, @"*\WxSender*.dll", VerdictAction.Block,
            "微信群发模块 WxSender 落地(批量群发)");
        // QQ / TIM 侧群发模块。
        File_(list, @"*\qqbot*.dll", VerdictAction.Block,
            "QQ 群发机器人模块 qqbot 落地(群发)");
        File_(list, @"*\QQRobot*.dll", VerdictAction.Block,
            "QQ 群控机器人模块 QQRobot 落地(群发)");
        File_(list, @"*\TIMHook*.dll", VerdictAction.Block,
            "TIM 群控 hook 模块 TIMHook 落地(群发)");

        // --- 上述模块被加载进任意进程(运行期拦截,兜底改名后仍按已知名命中)-> Block ---
        foreach (var mod in new[]
        {
            @"*\wcf.dll", @"*\wcferry*.dll", @"*\WeChatFerry*.dll", @"*\spy.dll",
            @"*\wcprobe.dll", @"*\WeChatPCAPI*.dll", @"*\CWeChatRobot*.dll",
            @"*\wxbot*.dll", @"*\WeChatSpy*.dll", @"*\WxSender*.dll",
            @"*\qqbot*.dll", @"*\QQRobot*.dll", @"*\TIMHook*.dll"
        })
        {
            list.Add(new DefenseRule
            {
                Type = EventType.ImageLoad,
                TargetPattern = mod,
                Action = VerdictAction.Block,
                Note = $"{BuiltInTag} 加载微信/QQ 群发外挂模块(群发/自动化)"
            });
        }

        // --- 命令行调用群发框架 / 包(可能是自动化办公或安全研究)-> Ask ---
        Cmd(list, @"*wcferry*", VerdictAction.Ask,
            "命令行调用微信群发框架 WeChatFerry(疑似群发)");
        Cmd(list, @"*ntchat*", VerdictAction.Ask,
            "命令行调用微信群控框架 ntchat(疑似群发)");
        Cmd(list, @"*wechaty*", VerdictAction.Ask,
            "命令行调用微信机器人框架 wechaty(疑似群发)");
        Cmd(list, @"*wxpy*", VerdictAction.Ask,
            "命令行调用微信控制库 wxpy(疑似群发)");
        Cmd(list, @"*WeChatPCAPI*", VerdictAction.Ask,
            "命令行调用微信群控 SDK WeChatPCAPI(疑似群发)");
        Cmd(list, @"*wxpusher*", VerdictAction.Ask,
            "命令行调用微信推送框架 wxpusher(疑似群发)");
        Cmd(list, @"*qqbot*", VerdictAction.Ask,
            "命令行调用 QQ 机器人框架 qqbot(疑似群发)");
        // UI 自动化群发(uiautomation/pyautogui 驱动微信窗口批量发消息)。
        Cmd(list, @"*uiautomation*wechat*", VerdictAction.Ask,
            "UI 自动化驱动微信(疑似模拟点击批量群发)");
        Cmd(list, @"*pyautogui*wechat*", VerdictAction.Ask,
            "pyautogui 驱动微信(疑似模拟点击批量群发)");

        // --- 向企业微信 / 微信小程序宿主 / QQ 附属进程注入远程线程(未签名注入方)-> Ask ---
        // 补齐批次 14 未覆盖的 IM 进程;群发外挂常挂进这些进程调用发送接口。
        ImInjectRemoteThread(list, @"*\WXWork.exe",
            "向企业微信(WXWork)注入远程线程(疑似群发/群控)");
        ImInjectRemoteThread(list, @"*\WeChatAppEx.exe",
            "向微信小程序渲染宿主注入远程线程(疑似控制)");
        ImInjectRemoteThread(list, @"*\QQExternal.exe",
            "向 QQ 外部模块注入远程线程(疑似群发/群控)");

        // --- 群控框架从用户可写目录加载未签名 DLL 挂进 IM(白加黑侧载补充)-> Ask ---
        // 批次 14 已覆盖 AppData/Temp,这里补 Public / ProgramData 两个常见落地目录。
        foreach (var actor in new[] { @"*\WeChat.exe", @"*\Weixin.exe", @"*\WXWork.exe", @"*\QQ.exe", @"*\TIM.exe" })
        {
            list.Add(new DefenseRule
            {
                Type = EventType.ImageLoad,
                ActorPattern = actor,
                TargetPattern = @"*\Users\Public\*.dll",
                RequireUnsigned = true,
                Action = VerdictAction.Ask,
                Note = $"{BuiltInTag} IM 从 Public 目录加载未签名 DLL(疑似群发白加黑侧载)"
            });
            list.Add(new DefenseRule
            {
                Type = EventType.ImageLoad,
                ActorPattern = actor,
                TargetPattern = @"*\ProgramData\*.dll",
                RequireUnsigned = true,
                Action = VerdictAction.Ask,
                Note = $"{BuiltInTag} IM 从 ProgramData 加载未签名 DLL(疑似群发白加黑侧载)"
            });
        }
    }

    // ======================================================================
    // 批次 14c:银狐 —— 补充群控框架 + 通讯录/聊天库窃取(群发目标采集)
    //
    // 背景补充(承接批次 14 / 14b):
    //   1) 群发前,银狐通常先「采集群发目标」—— 解密并导出微信/QQ 本地通讯录与聊天库,
    //      拿到好友/群成员清单后再批量发广告/诈骗链接。这一步依赖一批具名的
    //      「微信数据库解密/导出」工具(PyWxDump / SharpWxDump / WeChatMsg / wxdump 等)。
    //   2) 除批次 14/14b 已列的框架外,野外还流行另一批具名 hook/群控模块
    //      (wxhook / WeChatSDK / vchat / WeChatRobotCE / 企业微信 WeWorkHook 等)。
    //   3) 企业微信(WXWork)与微信 OCR/工具子进程也是群发外挂的注入落点。
    //
    // 防误伤原则(与批次 14/14b 一致):
    //   - 「具名群控/导出工具模块 DLL 落地或被加载」= 确定性外挂特征 -> Block;
    //   - 「命令行调用具名导出/群控工具」可能是取证/研究 -> Ask,交用户确认;
    //   - 绝不对微信本体正常写库(MicroMsg.db 等)下 FileWrite 规则,避免海量误报 ——
    //     只锁定「具名解密导出工具」这类正常用户环境不出现的特征。
    // ======================================================================
    private static void AddImHarvestAndFrameworkRules(List<DefenseRule> list)
    {
        // --- 补充:野外常见的具名群控/hook 模块 DLL 落地(确定性外挂特征)-> Block ---
        // 这些名字均为第三方"微信/QQ 群控·群发·hook"框架的注入模块,正常软件不会出现。
        var extraModules = new[]
        {
            (@"*\wxhook.dll",          "微信 hook 群控模块 wxhook.dll"),
            (@"*\WeChatHook*.dll",     "微信 hook 群控模块 WeChatHook"),
            (@"*\WeChatSDK*.dll",      "第三方微信群控 SDK WeChatSDK"),
            (@"*\vchat*.dll",          "微信群控框架 vchat 模块"),
            (@"*\WeChatRobotCE*.dll",  "微信机器人群控模块 WeChatRobotCE"),
            (@"*\wxbotpp*.dll",        "微信群发机器人模块 wxbotpp"),
            (@"*\WeChatManager*.dll",  "微信多开/群控管理模块 WeChatManager"),
            (@"*\WeWorkHook*.dll",     "企业微信 hook 群控模块 WeWorkHook"),
            (@"*\wework_api*.dll",     "企业微信群发接口模块 wework_api"),
            (@"*\wxDump*.dll",         "微信数据库导出模块 wxDump"),
            (@"*\QQHook*.dll",         "QQ hook 群控模块 QQHook"),
        };
        foreach (var (pattern, note) in extraModules)
        {
            File_(list, pattern, VerdictAction.Block, $"{note} 落地(群发/群控外挂)");
            list.Add(new DefenseRule
            {
                Type = EventType.ImageLoad,
                TargetPattern = pattern,
                Action = VerdictAction.Block,
                Note = $"{BuiltInTag} 加载{note}(群发/群控外挂)"
            });
        }

        // --- 命令行调用「微信数据库解密/导出」工具(采集群发目标:好友/群成员/聊天记录)-> Ask ---
        // 这些是具名工具,正常用户几乎不会用;取证/研究用途保留 Ask 让用户放行。
        Cmd(list, @"*PyWxDump*", VerdictAction.Ask,
            "命令行调用微信取证工具 PyWxDump(解密导出通讯录/聊天库,疑似采集群发目标)");
        Cmd(list, @"*SharpWxDump*", VerdictAction.Ask,
            "命令行调用微信取证工具 SharpWxDump(导出账号/密钥,疑似采集群发目标)");
        Cmd(list, @"*wxdump*", VerdictAction.Ask,
            "命令行调用微信数据库导出工具 wxdump(疑似采集群发目标)");
        Cmd(list, @"*WeChatMsg*", VerdictAction.Ask,
            "命令行调用微信聊天记录导出工具 WeChatMsg(疑似采集群发目标)");
        Cmd(list, @"*wxhook*", VerdictAction.Ask,
            "命令行调用微信 hook 群控框架 wxhook(疑似群发)");
        Cmd(list, @"*vchat*", VerdictAction.Ask,
            "命令行调用微信群控框架 vchat(疑似群发)");

        // --- 补充注入落点:企业微信 / 微信 OCR·工具子进程(未签名注入方)-> Ask ---
        ImInjectRemoteThread(list, @"*\WeChatOCR.exe",
            "向微信 OCR 子进程注入远程线程(疑似群控挂载)");
        ImInjectRemoteThread(list, @"*\WeChatUtility.exe",
            "向微信工具子进程注入远程线程(疑似群控挂载)");
        ImInjectRemoteThread(list, @"*\WXWorkWeb.exe",
            "向企业微信 Web 宿主注入远程线程(疑似群发/群控)");

        // --- 非官方进程向企业微信安装目录植入 DLL(替换群发模块)-> Ask ---
        File_(list, @"*\WXWork\*\wwapi*.dll", VerdictAction.Ask,
            "向企业微信安装目录写入接口 DLL(疑似植入群发模块)");
    }

    /// <summary>
    /// 「向 IM 进程注入远程线程」规则(Ask),仅当注入方未签名才命中。
    /// IM 多为多进程架构(QQNT 等自身进程间注入线程)且官方进程带有效签名,
    /// 不加 RequireUnsigned 会把这些正常自注入误报为群控。真正的群控木马注入方
    /// (白加黑侧载宿主 / 外部远控)通常未签名,据此精准锁定、避免误伤官方进程。
    /// </summary>
    private static void ImInjectRemoteThread(List<DefenseRule> list, string targetPattern, string note)
        => list.Add(new DefenseRule
        {
            Type = EventType.RemoteThread,
            TargetPattern = targetPattern,
            RequireUnsigned = true,
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} {note}"
        });

    /// <summary>
    /// IM 进程(微信/QQ 等)从用户可写目录加载「未签名」DLL 的侧载规则(Ask)。
    /// 主体限定为常见 IM 可执行体,模块要求未签名,降低对官方签名插件的误伤。
    /// </summary>
    private static void ImUnsignedModuleFromUserDir(List<DefenseRule> list)
    {
        foreach (var actor in new[] { @"*\WeChat.exe", @"*\Weixin.exe", @"*\WXWork.exe", @"*\QQ.exe", @"*\TIM.exe" })
        {
            list.Add(new DefenseRule
            {
                Type = EventType.ImageLoad,
                ActorPattern = actor,
                TargetPattern = @"*\AppData\*.dll",
                RequireUnsigned = true,
                Action = VerdictAction.Ask,
                Note = $"{BuiltInTag} IM 从用户目录加载未签名 DLL(疑似群控白加黑侧载)"
            });
            list.Add(new DefenseRule
            {
                Type = EventType.ImageLoad,
                ActorPattern = actor,
                TargetPattern = @"*\Temp\*.dll",
                RequireUnsigned = true,
                Action = VerdictAction.Ask,
                Note = $"{BuiltInTag} IM 从 Temp 加载未签名 DLL(疑似群控白加黑侧载)"
            });
        }
    }

    // ======================================================================
    // 批次 15:深层持久化(正常软件几乎从不触碰的内核/认证层挂钩)
    // 这些键被写入即意味着系统级 DLL 注入/认证劫持持久化,确定性极高 -> 多数 Block;
    // 与极少数合法安全产品/性能分析器可能重叠的 -> Ask。
    // ======================================================================
    private static void AddDeepPersistenceRules(List<DefenseRule> list)
    {
        // --- LSA 安全包 / 认证包注入(每次启动以 SYSTEM 加载,凭据窃取持久化)-> Block ---
        Reg(list, @"*\Control\Lsa\Security Packages*", VerdictAction.Block,
            "注册 LSA 安全包(Security Packages,SYSTEM 级持久化)");
        Reg(list, @"*\Control\Lsa\Authentication Packages*", VerdictAction.Block,
            "注册 LSA 认证包(Authentication Packages,凭据劫持)");
        Reg(list, @"*\Control\Lsa\Notification Packages*", VerdictAction.Block,
            "注册 LSA 通知包(密码变更监听,凭据窃取)");
        Reg(list, @"*\SecurityProviders\*", VerdictAction.Block,
            "篡改 SecurityProviders(SSP 注入持久化)");

        // --- AppCertDLLs:所有调用 CreateProcess 的进程都会加载(全局注入)-> Block ---
        Reg(list, @"*\Control\Session Manager\AppCertDlls*", VerdictAction.Block,
            "设置 AppCertDLLs(全局进程注入持久化)");
        // --- BootExecute:开机最早期(SMSS)执行,Rootkit 级持久化 -> Block ---
        Reg(list, @"*\Control\Session Manager\BootExecute*", VerdictAction.Block,
            "篡改 BootExecute(开机最早期执行,Rootkit 持久化)");
        // --- KnownDLLs 劫持 -> Block ---
        Reg(list, @"*\Control\Session Manager\KnownDLLs\*", VerdictAction.Block,
            "篡改 KnownDLLs(系统 DLL 劫持)");

        // --- COR_PROFILER:.NET 进程加载任意 DLL(环境变量/注册表持久化)-> Block ---
        Reg(list, @"*\Environment\COR_PROFILER_PATH*", VerdictAction.Block,
            "设置 COR_PROFILER 路径(.NET 分析器注入持久化)");
        Reg(list, @"*\Classes\CLSID\*\InprocServer32*COR_PROFILER*", VerdictAction.Block,
            "注册 COR_PROFILER COM 分析器(注入持久化)");

        // --- netsh helper DLL:netsh 启动即加载 -> Block ---
        Reg(list, @"*\Microsoft\NetSh\*", VerdictAction.Block,
            "注册 netsh helper DLL(持久化)");

        // --- 打印机/端口监视器 DLL(spoolsv 以 SYSTEM 加载)-> Block ---
        Reg(list, @"*\Control\Print\Monitors\*\Driver*", VerdictAction.Block,
            "注册打印监视器 DLL(spoolsv SYSTEM 持久化)");

        // --- Time Provider / LSA 扩展(W32Time 以 SYSTEM 加载 DLL)-> Block ---
        Reg(list, @"*\W32Time\TimeProviders\*\DllName*", VerdictAction.Block,
            "注册时间提供程序 DLL(SYSTEM 持久化)");

        // --- Shell 扩展 / 文件夹劫持加载点(可能与合法 shell 扩展重叠)-> Ask ---
        Reg(list, @"*\ShellServiceObjectDelayLoad\*", VerdictAction.Ask,
            "注册 Shell 服务对象延迟加载(可能持久化)");
        Reg(list, @"*\Explorer\Browser Helper Objects\*", VerdictAction.Ask,
            "注册浏览器辅助对象 BHO(可能持久化/劫持)");

        // --- 用户级注入:AppInit 的用户态等价(GlobalFlag/GdiPlus)-> Ask ---
        Reg(list, @"*\Windows NT\CurrentVersion\Drivers32\*", VerdictAction.Ask,
            "篡改 Drivers32 多媒体驱动映射(可能持久化)");
    }

    // ======================================================================
    // 批次 16:命令行关防护 / UAC 绕过
    // 命令行直接停防护服务/擦数据是确定性恶意 -> Block;
    // 已知 auto-elevate 程序被可疑父进程拉起的提权链 -> Ask(单纯运行这些程序很正常)。
    // ======================================================================
    private static void AddCmdlineEvasionRules(List<DefenseRule> list)
    {
        // --- 命令行停安全服务(net stop / sc stop 杀软服务)-> Block ---
        Cmd(list, @"*net*stop*windefend*", VerdictAction.Block,
            "命令行停止 Defender 服务(WinDefend)");
        Cmd(list, @"*sc*stop*windefend*", VerdictAction.Block,
            "命令行停止 Defender 服务(sc stop WinDefend)");
        Cmd(list, @"*sc*config*windefend*start=*disabled*", VerdictAction.Block,
            "命令行禁用 Defender 服务启动");
        Cmd(list, @"*net*stop*360*", VerdictAction.Block,
            "命令行停止 360 服务");
        Cmd(list, @"*net*stop*huorong*", VerdictAction.Block,
            "命令行停止火绒服务");
        Cmd(list, @"*taskkill*/im*MsMpEng*", VerdictAction.Block,
            "命令行强杀 Defender 引擎(taskkill MsMpEng)");
        Cmd(list, @"*Set-MpPreference*DisableRealtimeMonitoring*$true*", VerdictAction.Block,
            "PowerShell 关闭 Defender 实时监控(Set-MpPreference)");
        Cmd(list, @"*Add-MpPreference*ExclusionPath*", VerdictAction.Ask,
            "PowerShell 添加 Defender 排除路径(可能免杀)");

        // --- 命令行擦数据 / 格式化(确定性破坏)-> Block ---
        Cmd(list, @"*cipher*/w:*", VerdictAction.Block,
            "命令行擦除磁盘空闲空间(cipher /w,反取证/破坏)");
        Cmd(list, @"*format*/y*/q*", VerdictAction.Block,
            "命令行快速格式化磁盘(format /y,破坏)");
        Cmd(list, @"*fsutil*file*setzerodata*", VerdictAction.Block,
            "命令行清零文件数据(fsutil,破坏)");

        // --- 命令行关防火墙 -> Block ---
        Cmd(list, @"*netsh*advfirewall*set*allprofiles*state*off*", VerdictAction.Block,
            "命令行关闭全部防火墙配置(netsh advfirewall off)");
        Cmd(list, @"*netsh*firewall*set*opmode*disable*", VerdictAction.Block,
            "命令行关闭防火墙(netsh firewall disable)");

        // --- UAC 绕过:可疑父进程拉起 auto-elevate 程序 + 可疑命令行 -> Ask ---
        // 单独运行这些程序是正常的,故仅在命令行带可疑特征时提示,避免误伤。
        Cmd(list, @"*fodhelper*", VerdictAction.Ask,
            "fodhelper 启动(常被用于 UAC 绕过)");
        Cmd(list, @"*computerdefaults*", VerdictAction.Ask,
            "computerdefaults 启动(常被用于 UAC 绕过)");
        Cmd(list, @"*eventvwr*", VerdictAction.Ask,
            "eventvwr 启动(常被用于 UAC 绕过)");
        Cmd(list, @"*sdclt*", VerdictAction.Ask,
            "sdclt 启动(常被用于 UAC 绕过)");
        // UAC 绕过常用的劫持注册表键(用户态可写,劫持后由 auto-elevate 程序加载)-> Block ---
        Reg(list, @"*\Classes\ms-settings\shell\open\command*", VerdictAction.Block,
            "劫持 ms-settings 协议命令(fodhelper UAC 绕过)");
        Reg(list, @"*\Classes\exefile\shell\open\command*", VerdictAction.Block,
            "劫持 exefile 打开命令(UAC 绕过/劫持)");
        Reg(list, @"*\Classes\mscfile\shell\open\command*", VerdictAction.Block,
            "劫持 mscfile 打开命令(eventvwr UAC 绕过)");
        Reg(list, @"*\Classes\Folder\shell\open\command*", VerdictAction.Block,
            "劫持 Folder 打开命令(sdclt UAC 绕过)");
    }

    // ======================================================================
    // 批次 17:网络外联(疑似 C2)
    // 脚本解释器/LOLBin 直接外联是 C2 回连的强信号,但偶有合法脚本联网 -> Ask;
    // 未签名程序外联范围太广易误伤,交由启发式+信誉评分,这里只挂"解释器外联"窄规则。
    // ======================================================================
    private static void AddNetworkC2Rules(List<DefenseRule> list)
    {
        // --- 场景1:PowerShell外联(开发/管理常见) ---
        NetActor(list, @"*\powershell.exe", "PowerShell 发起网络外联(可能 C2)");
        NetActor(list, @"*\pwsh.exe", "PowerShell Core 发起网络外联(可能 C2)");
        // PowerShell下载并执行(高可疑)
        list.Add(new DefenseRule
        {
            Type = EventType.NetworkConnect,
            ActorPattern = @"*\powershell.exe",
            CommandLinePattern = @"*downloadstring*",
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} PowerShell 下载并执行(高可疑 C2)"
        });
        
        // --- 场景2:脚本宿主外联(明确可疑) ---
        NetActor(list, @"*\mshta.exe", "mshta 发起网络外联(可能 C2)");
        NetActor(list, @"*\wscript.exe", "wscript 发起网络外联(可能 C2)");
        NetActor(list, @"*\cscript.exe", "cscript 发起网络外联(可能 C2)");
        
        // --- 场景3:LOLBin外联(下载器) ---
        NetActor(list, @"*\rundll32.exe", "rundll32 发起网络外联(可能 C2)");
        NetActor(list, @"*\regsvr32.exe", "regsvr32 发起网络外联(可能 C2)");
        NetActor(list, @"*\certutil.exe", "certutil 发起网络外联(可能下载器)");
        NetActor(list, @"*\bitsadmin.exe", "bitsadmin 发起网络外联(可能下载器)");
        
        // --- 场景4:从可疑目录运行的程序外联 ---
        // 临时目录(未签名程序高可疑)
        list.Add(new DefenseRule
        {
            Type = EventType.NetworkConnect,
            ActorPattern = @"*\AppData\Local\Temp\*",
            RequireUnsigned = true,
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 从 Temp 运行的未签名程序发起外联(疑似 C2)"
        });
        // Public目录(未签名程序高可疑)
        list.Add(new DefenseRule
        {
            Type = EventType.NetworkConnect,
            ActorPattern = @"*\Users\Public\*",
            RequireUnsigned = true,
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 从 Public 目录运行的未签名程序发起外联(疑似 C2)"
        });
        // 下载目录(可能是下载的工具)
        list.Add(new DefenseRule
        {
            Type = EventType.NetworkConnect,
            ActorPattern = @"*\Downloads\*",
            RequireUnsigned = true,
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} 从 Downloads 运行的未签名程序发起外联"
        });
        
        // --- 场景5:开发工具外联(自动放行) ---
        // Visual Studio
        NetActor(list, @"*\devenv.exe", "Visual Studio 发起网络外联(开发工具)");
        // VS Code
        NetActor(list, @"*\code.exe", "VS Code 发起网络外联(开发工具)");
        // Node.js
        NetActor(list, @"*\node.exe", "Node.js 发起网络外联(开发工具)");
        // Python
        NetActor(list, @"*\python.exe", "Python 发起网络外联(开发工具)");
        // Git
        NetActor(list, @"*\git.exe", "Git 发起网络外联(版本控制)");
        // Docker
        NetActor(list, @"*\docker.exe", "Docker 发起网络外联(容器工具)");
        // npm
        NetActor(list, @"*\npm.exe", "npm 发起网络外联(包管理器)");
        // yarn
        NetActor(list, @"*\yarn.exe", "yarn 发起网络外联(包管理器)");
    }

    // ======================================================================
    // 规则构造辅助方法
    // ======================================================================

    /// <summary>注册表写入规则:按目标键通配匹配。</summary>
    private static void Reg(List<DefenseRule> list, string targetPattern, VerdictAction action, string note, bool hardOverride = false)
        => list.Add(new DefenseRule
        {
            Type = EventType.RegistryWrite,
            TargetPattern = targetPattern,
            Action = action,
            HardOverride = hardOverride,
            Note = $"{BuiltInTag} {note}"
        });

    /// <summary>文件写入规则:按目标文件路径通配匹配。</summary>
    private static void File_(List<DefenseRule> list, string targetPattern, VerdictAction action, string note, bool hardOverride = false)
        => list.Add(new DefenseRule
        {
            Type = EventType.FileWrite,
            TargetPattern = targetPattern,
            Action = action,
            HardOverride = hardOverride,
            Note = $"{BuiltInTag} {note}"
        });

    /// <summary>文件删除规则:按目标文件路径通配匹配。</summary>
    private static void Del(List<DefenseRule> list, string targetPattern, VerdictAction action, string note, bool hardOverride = false)
        => list.Add(new DefenseRule
        {
            Type = EventType.FileDelete,
            TargetPattern = targetPattern,
            Action = action,
            HardOverride = hardOverride,
            Note = $"{BuiltInTag} {note}"
        });

    /// <summary>命令行规则:按进程命令行通配匹配(类型不限,覆盖进程创建/脚本等)。</summary>
    private static void Cmd(List<DefenseRule> list, string cmdPattern, VerdictAction action, string note)
        => list.Add(new DefenseRule
        {
            Type = EventType.ProcessCreate,
            CommandLinePattern = cmdPattern,
            Action = action,
            Note = $"{BuiltInTag} {note}"
        });

    /// <summary>进程相关规则:指定事件类型 + 目标(进程路径/名)通配匹配。</summary>
    private static void Proc(List<DefenseRule> list, EventType type, string targetPattern, VerdictAction action, string note, bool hardOverride = false)
        => list.Add(new DefenseRule
        {
            Type = type,
            TargetPattern = targetPattern,
            Action = action,
            HardOverride = hardOverride,
            Note = $"{BuiltInTag} {note}"
        });

    /// <summary>网络外联规则:按发起主体进程路径/名通配匹配(类型固定为 NetworkConnect)。</summary>
    private static void NetActor(List<DefenseRule> list, string actorPattern, string note)
        => list.Add(new DefenseRule
        {
            Type = EventType.NetworkConnect,
            ActorPattern = actorPattern,
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} {note}"
        });

    /// <summary>从某目录执行「未签名」程序的规则(Ask):仅当主体无可信签名才命中,降低误伤。</summary>
    private static void UnsignedExec(List<DefenseRule> list, string actorPattern, string note)
        => list.Add(new DefenseRule
        {
            Type = EventType.ProcessCreate,
            ActorPattern = actorPattern,
            RequireUnsigned = true,
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} {note}"
        });

    /// <summary>
    /// 仿冒安装包规则(Ask):按进程路径/名通配匹配,且仅当主体「无可信签名」才命中。
    /// 真正的官方安装包带有效签名会被 RequireUnsigned 过滤掉,从而只针对仿冒未签名样本,避免误伤。
    /// </summary>
    private static void FakeInstaller(List<DefenseRule> list, string actorPattern, string note)
        => list.Add(new DefenseRule
        {
            Type = EventType.ProcessCreate,
            ActorPattern = actorPattern,
            RequireUnsigned = true,
            Action = VerdictAction.Ask,
            Note = $"{BuiltInTag} {note}"
        });

    // ======================================================================
    // 开发工具白名单机制
    // 识别常见开发工具/CI环境,减少误报
    // ======================================================================
    
    /// <summary>
    /// 常见开发工具进程名(小写)。这些进程的正常操作应降低风险评分。
    /// </summary>
    private static readonly HashSet<string> DevToolProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // IDE/编辑器
        "devenv.exe",          // Visual Studio
        "code.exe",            // VS Code
        "rider64.exe",         // JetBrains Rider
        "idea64.exe",          // IntelliJ IDEA
        "pycharm64.exe",       // PyCharm
        "webstorm64.exe",      // WebStorm
        "clion64.exe",         // CLion
        "goland64.exe",        // GoLand
        "datagrip64.exe",      // DataGrip
        "phpstorm64.exe",      // PhpStorm
        "rubymine64.exe",      // RubyMine
        "android studio.exe",  // Android Studio
        "notepad++.exe",       // Notepad++
        "sublime text.exe",    // Sublime Text
        "atom.exe",            // Atom
        
        // 构建工具
        "msbuild.exe",         // MSBuild
        "dotnet.exe",          // .NET CLI
        "nuget.exe",           // NuGet
        "npm.exe",             // npm
        "yarn.exe",            // yarn
        "pnpm.exe",            // pnpm
        "node.exe",            // Node.js
        "python.exe",          // Python
        "pip.exe",             // pip
        "cargo.exe",           // Rust Cargo
        "gradle.exe",          // Gradle
        "mvn.exe",             // Maven
        "ant.exe",             // Ant
        "make.exe",            // Make
        "cmake.exe",           // CMake
        
        // 版本控制
        "git.exe",             // Git
        "svn.exe",             // SVN
        "hg.exe",              // Mercurial
        
        // 容器/虚拟化
        "docker.exe",          // Docker
        "podman.exe",          // Podman
        "vagrant.exe",         // Vagrant
        
        // CI/CD
        "jenkins.exe",         // Jenkins
        "agent.exe",           // Jenkins Agent
        "runner.exe",          // GitLab Runner
        "buildkite-agent.exe", // Buildkite
        
        // 测试工具
        "testhost.exe",        // .NET Test Host
        "vstest.console.exe",  // VS Test Console
        "nunit-console.exe",   // NUnit
        "xunit.console.exe",   // xUnit
        "jest.exe",            // Jest
        "mocha.exe",           // Mocha
        
        // 包管理/安装器
        "choco.exe",           // Chocolatey
        "scoop.exe",           // Scoop
        "winget.exe",          // Windows Package Manager
        "installer.exe",       // 通用安装器
        "setup.exe",           // 通用安装器
    };

    /// <summary>
    /// 常见开发工具目录路径片段(小写)。位于这些目录下的进程应降低风险评分。
    /// </summary>
    private static readonly string[] DevToolPathPatterns = new[]
    {
        @"\microsoft visual studio\",
        @"\jetbrains\",
        @"\vscode\",
        @"\visual studio code\",
        @"\android studio\",
        @"\notepad++\",
        @"\sublime text\",
        @"\atom\",
        @"\python\python",
        @"\nodejs\",
        @"\dotnet\",
        @"\git\",
        @"\docker\",
        @"\jenkins\",
        @"\gradle\",
        @"\maven\",
        @"\nuget\",
        @"\npm\",
        @"\yarn\",
        @"\.nuget\",
        @"\.cargo\",
        @"\.gradle\",
        @"\.m2\",
        @"\packages\",
        @"\node_modules\",
        @"\venv\",
        @"\env\",
        @"\.venv\",
        @"\.env\",
    };

    /// <summary>
    /// 判断进程路径是否为开发工具。
    /// 用于规则引擎中降低开发环境误报。
    /// </summary>
    public static bool IsDevTool(string? processPath)
    {
        if (string.IsNullOrEmpty(processPath))
            return false;

        string lower = processPath.ToLowerInvariant();
        
        // 检查进程名
        string fileName = System.IO.Path.GetFileName(lower);
        if (DevToolProcessNames.Contains(fileName))
            return true;

        // 检查路径模式
        foreach (var pattern in DevToolPathPatterns)
        {
            if (lower.Contains(pattern))
                return true;
        }

        return false;
    }

    /// <summary>
    /// 判断当前环境是否可能是CI/CD环境。
    /// 检查常见CI环境变量。
    /// </summary>
    public static bool IsCiCdEnvironment()
    {
        // 检查常见CI环境变量
        string[] ciVars = new[]
        {
            "CI",                    // 通用CI标记
            "CONTINUOUS_INTEGRATION", // 通用CI标记
            "GITHUB_ACTIONS",       // GitHub Actions
            "GITLAB_CI",            // GitLab CI
            "JENKINS_URL",          // Jenkins
            "BUILDKITE",            // Buildkite
            "AZURE_PIPELINES",      // Azure DevOps
            "TRAVIS",               // Travis CI
            "CIRCLECI",             // CircleCI
            "APPVEYOR",             // AppVeyor
            "TEAMCITY_VERSION",     // TeamCity
            "TF_BUILD",             // Azure Pipelines
            "bamboo_buildKey",      // Bamboo
            "CODEBUILD_BUILD_ID",   // AWS CodeBuild
        };

        foreach (var var in ciVars)
        {
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(var)))
                return true;
        }

        return false;
    }

    /// <summary>
    /// 判断命令行是否包含长编码内容(>100字符的Base64)。
    /// 用于区分正常脚本调用和恶意载荷。
    /// </summary>
    public static bool HasLongEncodedContent(string? commandLine)
    {
        if (string.IsNullOrEmpty(commandLine))
            return false;

        // 查找Base64编码内容(至少100个连续Base64字符)
        var match = System.Text.RegularExpressions.Regex.Match(
            commandLine, 
            @"[A-Za-z0-9+/]{100,}={0,2}");
        
        return match.Success;
    }

    /// <summary>
    /// 判断是否为常见可信安装器进程。
    /// 这些进程的正常安装操作不应触发高风险规则。
    /// </summary>
    public static bool IsTrustedInstaller(string? processPath)
    {
        if (string.IsNullOrEmpty(processPath))
            return false;

        string fileName = System.IO.Path.GetFileName(processPath).ToLowerInvariant();
        
        // 常见安装器进程名
        string[] installerNames = new[]
        {
            "msiexec.exe",         // Windows Installer
            "setup.exe",           // 通用安装器
            "installer.exe",       // 通用安装器
            "install.exe",         // 通用安装器
            "update.exe",          // 通用更新器
            "updater.exe",         // 通用更新器
            "winget.exe",          // Windows Package Manager
            "choco.exe",           // Chocolatey
            "scoop.exe",           // Scoop
            "npm.exe",             // npm
            "pip.exe",             // pip
            "dotnet.exe",          // .NET CLI
            "nuget.exe",           // NuGet
        };

        return installerNames.Contains(fileName);
    }
}
