using System;
using System.Collections.Generic;
using System.Linq;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// 信任策略(降误报核心,同时防"合法签名"被滥用)。
///
/// 关键原则:**签名"合法"不等于"可信"**。银狐等家族会盗用/滥用合法证书、
/// 用空壳公司骗取证书、或用微软签名的脆弱驱动(BYOVD)。因此本策略区分两档:
///
///  1) <see cref="IsStronglyTrusted"/> —— 仅极少数"强可信"主体可被直接放行,
///     跳过行为检测。条件极严:证书指纹在内置白名单,或(微软签名 + 系统目录),
///     且签名未吊销、未过期后签名。这是唯一的"免死金牌",名单极小。
///
///  2) <see cref="IsBenignSigner"/> —— 一般合法签名(大厂发行商等)。仅用于
///     **给风险分打折**,绝不跳过行为规则。勒索/改启动项/关杀软等行为,
///     无论签名多正规都要照常拦截。
///
/// 任一档下,只要出现危险命令行 / 异常进程链 / 签名异常(吊销/过期签名),
/// 一律不放行。
/// </summary>
public static class TrustPolicy
{
    /// <summary>
    /// 强可信证书指纹白名单(SHA-1 Thumbprint,大写无分隔)。
    /// 只有指纹精确匹配才享受"跳过行为检测"待遇,杜绝"发行商名字被冒用"。
    /// 默认放入微软主流代码签名证书指纹;可按需扩充/由配置注入。
    /// </summary>
    private static readonly HashSet<string> StrongTrustThumbprints = new(StringComparer.OrdinalIgnoreCase)
    {
        // Microsoft Code Signing PCA / Windows Production PCA 等(示例,部署时按实际环境校正)
        "8FBE4D070EF8AB1BCCAF2A9D5CCAE7282A2C66B3",
        "A4341B9FD50FB9964283220A36A1EF6F6FAA7840",
        "3B1EFD3A66EA28B16697394703A72CA340A05BD5",
    };

    /// <summary>强可信发行商(仅微软,且必须配合系统目录 + 有效签名)。</summary>
    private static readonly string[] StrongPublishers =
    {
        "Microsoft Corporation", "Microsoft Windows", "Microsoft Windows Publisher",
    };

    /// <summary>
    /// 已知安全软件(杀软/EDR)的进程映像名(小写)。这些是与本软件同类的合法终端安全产品,
    /// 为实现「共存、互不误踩」,当它们位于受保护的安装目录(非用户可写)时直接放行 ——
    /// 避免「对方自我保护导致我方读不到其签名 → 误判篡改/勒索」这类典型 AV 互踩误报
    /// (如 Kaspersky avp.exe 自保护使 WinVerifyTrust 失败、清理自身 Temp 被当勒索批量改写)。
    /// </summary>
    private static readonly HashSet<string> KnownSecurityProcessNames =
        new(StringComparer.OrdinalIgnoreCase)
    {
        // Windows Defender
        "msmpeng.exe", "mpcmdrun.exe", "nissrv.exe", "mpdefendercoreservice.exe", "securityhealthservice.exe",
        // Kaspersky(含无缝更新工具 avpsus.exe / 网络代理 klnagent.exe:它们会在
        // 自身 ProgramData\Kaspersky Lab 目录内批量删改文件做更新,极易被误判勒索)
        "avp.exe", "avpui.exe", "kavfs.exe", "kavfswp.exe", "ksde.exe", "ksdeui.exe",
        "avpsus.exe", "klnagent.exe", "ksn.exe",
        // ESET
        "ekrn.exe", "egui.exe",
        // McAfee
        "mcshield.exe", "masvc.exe", "macmnsvc.exe", "mfemms.exe",
        // Symantec / Norton
        "ccsvchst.exe", "symcorpui.exe", "nortonsecurity.exe", "rtvscan.exe",
        // Avast / AVG
        "avastsvc.exe", "avastui.exe", "afwserv.exe", "avgsvc.exe", "avgui.exe",
        // Avira
        "avguard.exe", "avgnt.exe", "sched.exe",
        // Bitdefender
        "bdagent.exe", "vsserv.exe", "bdservicehost.exe",
        // Trend Micro
        "ntrtscan.exe", "pccntmon.exe", "tmbmsrv.exe",
        // Sophos
        "savservice.exe", "sophosfs.exe", "sophosfilescanner.exe",
        // 国产:360 / 火绒 / 腾讯 / 金山
        "360tray.exe", "360sd.exe", "360rp.exe", "zhudongfangyu.exe", "360safe.exe",
        "hipstray.exe", "hipsdaemon.exe", "usysdiag.exe", "wsctrl.exe",
        "qqpcrtp.exe", "qqpctray.exe", "qqpcmgr.exe",
        "kxetray.exe", "kxescore.exe", "kscan.exe", "ksafetray.exe", "kwsprotect64.exe",
    };

    /// <summary>受保护(非用户可写)的安装目录片段:知名安全产品只可能装在这些位置。</summary>
    private static readonly string[] ProtectedInstallDirs =
    {
        @"\program files\", @"\program files (x86)\", @"\programdata\",
        @"\windows\system32\", @"\windows\syswow64\", @"\windows\defender\",
    };

    /// <summary>
    /// 是否为「已安装的知名安全软件」:进程映像名在 <see cref="KnownSecurityProcessNames"/>,
    /// 且位于受保护安装目录(<see cref="ProtectedInstallDirs"/>)。两者皆需满足,
    /// 防止恶意软件在 Temp/AppData 下伪造同名 exe 冒充而被放行。
    /// </summary>
    public static bool IsTrustedSecurityProduct(SecurityEvent e, out string reason)
    {
        reason = string.Empty;
        var path = e.ActorPath;
        if (string.IsNullOrEmpty(path)) return false;

        string name;
        try { name = System.IO.Path.GetFileName(path); }
        catch { return false; }
        if (string.IsNullOrEmpty(name) || !KnownSecurityProcessNames.Contains(name)) return false;

        string lower = path.ToLowerInvariant().Replace('/', '\\');
        if (!ProtectedInstallDirs.Any(d => lower.Contains(d))) return false;

        reason = $"已安装的知名安全软件({name}),共存放行";
        return true;
    }

    /// <summary>
    /// 一般受信任发行商关键字(出现在签名 CN 视为"较可信大厂")。
    /// 注意:这些只用于"风险打折",不再用于"直接放行"。
    /// </summary>
    private static readonly string[] BenignPublishers =
    {
        "Microsoft Corporation", "Microsoft Windows",
        "Google LLC", "Google Inc",
        "Mozilla Corporation",
        "Apple Inc",
        "Adobe Inc", "Adobe Systems",
        "Intel Corporation", "NVIDIA Corporation", "Advanced Micro Devices",
        "Realtek", "Lenovo", "Dell", "HP Inc", "Hewlett",
        "Valve", "Tencent", "Alibaba", "Bytedance",
        "Oracle", "VMware", "Citrix",
        "JetBrains", "GitHub", "Docker",
        "Igor Pavlov",          // 7-Zip
        "Notepad++",
        // ---- 常用软件厂商(补充)----
        "Kaspersky",                         // 卡巴斯基
        "Beijing Qihu", "Qizhi", "360",      // 360
        "Huorong", "Beijing Huorong",        // 火绒
        "Kingsoft", "WPS",                   // 金山 / WPS
        "Baidu",                             // 百度
        "NetEase",                           // 网易(含网易云音乐/有道)
        "Sogou",                             // 搜狗
        "Bilibili", "Shanghai Hode",         // B 站
        "Beijing Sankuai", "Meituan",        // 美团
        "Spotify",
        "Discord",
        "Telegram", "Telegram FZ",
        "Zoom",
        "Slack Technologies",
        "Dropbox",
        "Logitech", "Logi",
        "ASUS", "ASUSTeK",
        "Razer",
        "Qualcomm", "MediaTek",
        "Western Digital", "Seagate", "Samsung",
        "WinRAR", "win.rar",                 // WinRAR
        "TeamViewer",
        "Cisco",
        "Postman",
        "Python Software Foundation",
        "The Git", "Git for Windows",
        "Canonical",                         // WSL/Ubuntu
        "Epic Games",
        "Blizzard", "Riot Games",
        "Electronic Arts",
        "Ubisoft",
        "miHoYo", "Cognosphere",             // 米哈游
        "OBS",
        "VideoLAN",                          // VLC
        "Audacity",
        "GIMP",
        "Doc-Cmd", "Foxit",                  // 福昕 PDF
        "Tencent Technology", "Shenzhen Tencent", // 微信/QQ 更全的 CN 主体名
    };

    /// <summary>受保护的系统目录(配合微软签名才作"强可信")。</summary>
    private static readonly string[] SystemDirs =
    {
        @"\windows\system32\",
        @"\windows\syswow64\",
        @"\windows\winsxs\",
    };

    /// <summary>一般标准安装目录(用于风险打折)。</summary>
    private static readonly string[] TrustedDirs =
    {
        @"\windows\system32\",
        @"\windows\syswow64\",
        @"\windows\winsxs\",
        @"\program files\",
        @"\program files (x86)\",
    };

    /// <summary>
    /// 兼容旧调用:等价于"是否强可信"。新代码应改用 <see cref="IsStronglyTrusted"/>。
    /// </summary>
    public static bool IsTrusted(SecurityEvent e, out string reason)
        => IsStronglyTrusted(e, out reason);

    /// <summary>
    /// 是否"强可信"——可跳过行为检测直接放行。条件极严且要求签名健康。
    /// </summary>
    public static bool IsStronglyTrusted(SecurityEvent e, out string reason)
    {
        reason = string.Empty;

        // 任何危险命令行 / 异常进程链 —— 绝不放行(防"白加黑"/LOLBin)
        if (HasDangerousCommandLineOrLolbinAbuse(e)) return false;
        if (IsAbnormalChain(e)) return false;

        // 签名必须健康:有可信签名,且未吊销、未"过期后签名"
        if (!e.ActorSigned) return false;
        if (e.CertRevoked || e.SignedAfterCertExpiry) return false;

        // 1) 证书指纹白名单(最强凭据,杜绝发行商名冒用)
        if (!string.IsNullOrEmpty(e.ActorCertThumbprint) &&
            StrongTrustThumbprints.Contains(e.ActorCertThumbprint))
        {
            reason = "证书指纹在强可信白名单";
            return true;
        }

        // 2) 微软签名 + 系统目录(系统组件)
        string pathLower = (e.ActorPath ?? string.Empty).ToLowerInvariant();
        if (!string.IsNullOrEmpty(e.ActorPublisher) &&
            StrongPublishers.Any(p => e.ActorPublisher.Contains(p, StringComparison.OrdinalIgnoreCase)) &&
            SystemDirs.Any(d => pathLower.Contains(d)))
        {
            reason = "微软签名且位于系统目录";
            return true;
        }

        return false;
    }

    /// <summary>
    /// 是否为"健康签名、可直接放行"的主体——用于"有合法证书即免打扰"。
    ///
    /// 放行条件(全部满足):
    ///   1) 带可信数字签名(WinVerifyTrust 通过);
    ///   2) 无任何硬恶意指标(<see cref="SecurityEvent.HasThreatIndicator"/> 为 false)——
    ///      该标志已涵盖银狐核心画像:签名失配/吊销/过期后签名、文件膨胀、危险命令行、
    ///      异常进程链(白加黑)、命令行混淆、多阶段杀伤链、勒索诱饵触碰等;
    ///   3) 排除"空壳公司新证书木马"画像:本机首见 + 证书很新(有效期临近,疑似新签发)。
    ///
    /// 即:证书合法且没有任何盗用/滥用/银狐迹象 → 直接放行,不弹窗。
    /// 一旦命中上述任一恶意画像,即便有正规签名也不走此放行通道(交回行为研判)。
    /// 必须在 <see cref="ThreatDetector.Analyze"/> 之后调用(依赖其填充的指标)。
    /// </summary>
    public static bool IsHealthySigned(SecurityEvent e, out string reason)
    {
        reason = string.Empty;

        // 1) 必须有可信签名
        if (!e.ActorSigned) return false;

        // 2) 显式排除盗用/滥用证书的银狐画像(冗余兜底,即使 HasThreatIndicator 漏置也拦住)
        if (e.SignatureMismatch || e.CertRevoked || e.SignedAfterCertExpiry) return false;

        // 3) 任何硬恶意指标 —— 不放行(白加黑、危险命令行、文件膨胀、攻击链等)
        if (e.HasThreatIndicator) return false;

        // 4) 危险命令行 / 异常进程链(再次兜底,防止指标未及时置位)
        if (HasDangerousCommandLineOrLolbinAbuse(e)) return false;
        if (IsAbnormalChain(e)) return false;

        // 5) 空壳公司新证书木马画像:本机首次出现 + 证书"年轻"(有效期截止距今 <= 6 个月)
        if (e.IsFirstSeen && e.CertNotAfterUtc is { } notAfter)
        {
            var remaining = notAfter - DateTime.UtcNow;
            if (remaining > TimeSpan.Zero && remaining <= TimeSpan.FromDays(186))
                return false; // 疑似新签发证书 + 首见,交回研判,不直接放行
        }

        reason = string.IsNullOrEmpty(e.ActorPublisher)
            ? "有效数字签名(健康),直接放行"
            : $"有效数字签名:{e.ActorPublisher}(健康),直接放行";
        return true;
    }

    /// <summary>
    /// 是否为「有证书且明确安全」的主体——仅用于判断"是否还需要上传 VirusTotal 云查"。
    ///
    /// 与 <see cref="IsHealthySigned"/> 的区别:本判定**不**附加"本机首见 + 新证书(≤6 个月)"
    /// 这条收紧规则。理由:那条规则是为"空壳公司新证书木马"画像服务、用于决定是否【直接放行/弹窗】;
    /// 但对"要不要把文件上传第三方(VT)扫"而言,只要签名健康且无任何硬恶意指标,就属于
    /// "有证书的明确安全",没有必要再把正规签名安装包整文件上传 VT(省配额、免冻结、护隐私)。
    ///
    /// 安全性说明:本判定**只**用于跳过 VT 上传,绝不跳过行为检测 —— 一旦该程序运行中出现
    /// 任何硬恶意指标(签名失配/吊销/过期后签名、危险命令行、白加黑链、攻击链、勒索等),
    /// <see cref="SecurityEvent.HasThreatIndicator"/> 即为真,本判定立即返回 false,照常研判拦截。
    ///
    /// 放行(跳过 VT)条件(全部满足):
    ///   1) 带可信数字签名(WinVerifyTrust 通过);
    ///   2) 签名健康:无失配 / 未吊销 / 非"过期后签名";
    ///   3) 无任何硬恶意指标(HasThreatIndicator=false);
    ///   4) 无危险命令行 / LOLBin 滥用 / 高置信凭据访问,且无异常进程链(白加黑)。
    /// 必须在 <see cref="ThreatDetector.Analyze"/> 之后调用(依赖其填充的指标)。
    /// </summary>
    public static bool IsCleanSigned(SecurityEvent e, out string reason)
    {
        reason = string.Empty;

        if (!e.ActorSigned) return false;
        if (e.SignatureMismatch || e.CertRevoked || e.SignedAfterCertExpiry) return false;
        if (e.HasThreatIndicator) return false;
        if (HasDangerousCommandLineOrLolbinAbuse(e)) return false;
        if (IsAbnormalChain(e)) return false;

        reason = string.IsNullOrEmpty(e.ActorPublisher)
            ? "有合法且健康的数字签名,明确安全,跳过 VT 上传"
            : $"有合法且健康的数字签名:{e.ActorPublisher},明确安全,跳过 VT 上传";
        return true;
    }

    /// <summary>
    /// 是否为"较可信的合法签名主体"。仅用于风险打折,不可跳过行为规则。
    /// 同样要求签名健康(吊销/过期签名直接判否)。
    /// </summary>
    public static bool IsBenignSigner(SecurityEvent e, out string reason)
    {
        reason = string.Empty;
        if (!e.ActorSigned) return false;
        if (e.CertRevoked || e.SignedAfterCertExpiry) return false;

        if (!string.IsNullOrEmpty(e.ActorPublisher))
        {
            foreach (var pub in BenignPublishers)
            {
                if (e.ActorPublisher.Contains(pub, StringComparison.OrdinalIgnoreCase))
                {
                    reason = $"合法签名发行商:{pub}";
                    return true;
                }
            }
        }

        string pathLower = (e.ActorPath ?? string.Empty).ToLowerInvariant();
        if (TrustedDirs.Any(d => pathLower.Contains(d)))
        {
            reason = "合法签名且位于标准安装目录";
            return true;
        }

        return false;
    }

    /// <summary>
    /// 是否为「可豁免敏感 Ask 规则的强可信操作系统组件」。
    ///
    /// 用于消除「合法 OS 组件(如 RuntimeBroker / 设置中心)调整或重置 UAC 提权确认级别」
    /// 这类误报,同时绝不给「恶意脚本借 reg.exe / powershell 改 UAC」开口子:
    ///   1) 必须是强可信(微软签名 + 系统目录,签名健康)——复用 <see cref="IsStronglyTrusted"/>;
    ///   2) 必须无任何硬恶意指标(HasThreatIndicator=false);
    ///   3) 必须不是脚本宿主 / LOLBin(reg.exe/powershell/cmd/rundll32/regsvr32 等)——
    ///      这些即便微软签名也常被滥用来改 UAC,绝不豁免。
    /// 必须在 <see cref="ThreatDetector.Analyze"/> 之后调用(依赖其填充的硬指标)。
    /// </summary>
    public static bool IsTrustedOsComponent(SecurityEvent e, out string reason)
    {
        reason = string.Empty;

        // 1) 出现任何硬恶意指标 —— 不豁免
        if (e.HasThreatIndicator) return false;

        // 2) 脚本宿主 / LOLBin —— 即便微软签名也不豁免(防"白加黑"借系统工具改 UAC)
        if (IsLolBinOrScriptHost(e.ActorPath)) return false;

        // 3) 必须满足"强可信 OS 组件"(微软签名 + 系统目录,签名健康,无危险命令行/异常链)
        if (!IsStronglyTrusted(e, out var t)) return false;

        reason = "强可信系统组件(" + t + "),敏感操作豁免";
        return true;
    }

    /// <summary>常被滥用来改 UAC/关防护的微软签名系统工具(LOLBin)与脚本宿主。</summary>
    private static readonly string[] LolBinsAndHosts =
    {
        "reg.exe", "regedit.exe", "regini.exe",
        "powershell.exe", "pwsh.exe", "cmd.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "sc.exe",
        "wmic.exe", "cmstp.exe", "fodhelper.exe",
    };

    private static bool IsLolBinOrScriptHost(string? path)
    {
        var name = SafeName(path);
        return !string.IsNullOrEmpty(name) && LolBinsAndHosts.Contains(name);
    }

    private static readonly string[] DangerTokens =
    {
        "-enc", "-encodedcommand", "downloadstring", "downloadfile",
        "invoke-expression", "iex(", "frombase64string", "urlcache",
        "-w hidden", "-windowstyle hidden", "bypass", "javascript:", "vbscript:",
        "bitsadmin /transfer", "-decode",
        // 凭据转储(LSASS):微软签名的 rundll32/comsvcs 被滥用,必须纳入"危险命令行"门禁,
        // 否则强可信放行通道(IsStronglyTrusted/IsHealthySigned)会直接放过它(典型 T1003.001)。
        "comsvcs.dll", "minidump", "sekurlsa", "lsadump", "mimikatz", "invoke-mimikatz",
        // 勒索前置 / 无文件加载
        "vssadmin delete", "wmic shadowcopy delete", "wbadmin delete",
        "invoke-webrequest", "start-bitstransfer", "reflection.assembly",
    };

    private static bool HasDangerousCommandLine(string? cmd)
    {
        if (string.IsNullOrEmpty(cmd)) return false;
        var c = cmd.ToLowerInvariant();
        return DangerTokens.Any(t => c.Contains(t));
    }

    /// <summary>
    /// 是否为「危险命令行」或「被滥用的签名 LOLBin」或「高置信凭据访问」。后两者覆盖那些
    /// 不含上面泛化 token、但「二进制/工具 + 参数/目标」语义已构成高置信攻击的情形
    /// (如 regsvr32 Squiblydoo、reg save SAM、ntdsutil 提取 NTDS、向 LSASS 注入)。
    /// 供强可信/健康签名门禁复用,确保微软签名的系统工具被滥用时失去信任豁免。
    /// </summary>
    private static bool HasDangerousCommandLineOrLolbinAbuse(SecurityEvent e)
        => HasDangerousCommandLine(e.CommandLine)
           || LolbinAnalyzer.IsAbusedLolbin(e.ActorPath, e.CommandLine)
           || CredentialAccessAnalyzer.IsHardCredentialAccess(e);

    private static readonly string[] OfficeAndBrowsers =
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "acrord32.exe"
    };

    private static readonly string[] ScriptHosts =
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe"
    };

    private static bool IsAbnormalChain(SecurityEvent e)
    {
        string actor = SafeName(e.ActorPath);
        string parent = SafeName(e.ParentPath);
        return OfficeAndBrowsers.Contains(parent) && ScriptHosts.Contains(actor);
    }

    private static string SafeName(string? path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        try { return System.IO.Path.GetFileName(path).ToLowerInvariant(); }
        catch { return path.ToLowerInvariant(); }
    }
}
