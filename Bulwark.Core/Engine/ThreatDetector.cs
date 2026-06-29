using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// 威胁检测器(启发式)。对一个安全事件计算风险评分(0-100)并给出原因。
/// 不依赖病毒库,而是基于行为特征:可疑路径、缺失签名、异常父子进程链、
/// LOLBin(合法程序被滥用)命令行模式、进程伪装等。
///
/// 评分阈值(供规则引擎参考):
///   >= 80 高危,建议阻止
///   >= 50 可疑,建议询问
///   <  50 低风险
/// </summary>
public static class ThreatDetector
{
    public const int HighRisk = 80;
    public const int Suspicious = 50;

    // 常被攻击者滥用的「合法系统程序」(LOLBins)
    private static readonly string[] LolBins =
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
        "msbuild.exe", "installutil.exe", "wmic.exe", "schtasks.exe", "at.exe"
    };

    // 常见办公/浏览器类进程,若它们派生脚本解释器,高度可疑(宏病毒/钓鱼)
    private static readonly string[] OfficeAndBrowsers =
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "acrord32.exe"
    };

    // 命令行中的高危片段(编码执行、下载执行、绕过策略等)
    private static readonly (string Token, int Score, string Reason)[] CommandLineSignals =
    {
        ("-enc", 35, "PowerShell 编码命令(-EncodedCommand,T1027)"),
        ("-encodedcommand", 35, "PowerShell 编码命令(T1027)"),
        ("-nop", 8, "PowerShell 跳过配置文件(-NoProfile)"),
        ("-noprofile", 8, "PowerShell 跳过配置文件"),
        ("-windowstyle hidden", 30, "隐藏窗口运行"),
        ("-w hidden", 30, "隐藏窗口运行"),
        ("-executionpolicy bypass", 30, "绕过执行策略"),
        ("-ep bypass", 30, "绕过执行策略"),
        ("downloadstring", 40, "内存下载执行(DownloadString,T1105)"),
        ("downloadfile", 35, "远程下载文件(T1105)"),
        ("invoke-expression", 35, "动态执行(IEX,T1059.001)"),
        ("iex(", 35, "动态执行(IEX,T1059.001)"),
        ("frombase64string", 30, "Base64 解码执行(T1140)"),
        ("urlcache", 40, "certutil 远程下载(-urlcache,T1105)"),
        ("-decode", 25, "certutil 解码(可能还原载荷,T1140)"),
        ("http://", 20, "命令行内含明文 URL"),
        ("https://", 15, "命令行内含 URL"),
        ("javascript:", 35, "mshta 执行脚本"),
        ("vbscript:", 35, "mshta 执行脚本"),
        ("bitsadmin /transfer", 35, "BITS 后台下载(T1197)"),
        ("-noninteractive", 5, "非交互运行"),
        // —— 凭据转储(LSASS)特征:微软签名的 rundll32/comsvcs 也常被滥用,必须按命令行抓 ——
        ("comsvcs.dll", 40, "comsvcs 转储 LSASS 内存(凭据窃取,T1003.001)"),
        ("minidump", 35, "进程内存转储(疑似凭据窃取,T1003.001)"),
        ("sekurlsa", 50, "Mimikatz 凭据抓取(sekurlsa,T1003.001)"),
        ("lsadump", 50, "Mimikatz 凭据转储(lsadump,T1003.001)"),
        ("mimikatz", 55, "Mimikatz 凭据攻击工具(T1003.001)"),
        ("invoke-mimikatz", 55, "PowerShell 版 Mimikatz(T1003.001)"),
        ("procdump", 25, "ProcDump 转储进程内存(可能针对 LSASS,T1003.001)"),
        // —— 其他高危执行/规避 token ——
        ("-windowstyle h", 30, "隐藏窗口运行"),
        ("invoke-webrequest", 30, "远程下载(Invoke-WebRequest,T1105)"),
        ("iwr ", 25, "远程下载(iwr 别名,T1105)"),
        ("start-bitstransfer", 30, "BITS 后台下载(PowerShell,T1197)"),
        ("reflection.assembly", 30, "内存加载程序集(无文件,T1027)"),
        ("[reflection.assembly]", 30, "内存加载程序集(无文件,T1027)"),
        ("vssadmin delete", 45, "删除卷影副本(勒索前置,T1490)"),
        ("wmic shadowcopy delete", 45, "删除卷影副本(勒索前置,T1490)"),
        ("wbadmin delete", 40, "删除系统备份(勒索前置,T1490)"),
        ("bcdedit", 25, "修改引导配置(勒索常用,T1490)"),
        ("-noprofile -e", 25, "PowerShell 跳过配置 + 编码执行组合(T1027)"),
    };

    // 可疑落地目录分两级(降误报核心):
    //  高可疑 —— Temp / Public / PerfLogs / RecycleBin 等几乎只有恶意软件会在此释放/驻留;
    //  中可疑 —— Desktop / Documents / Downloads / Roaming 等用户日常可写区,
    //           银狐会在此投放诱饵,但用户也常在此放合法工具(绿色软件/脚本)。
    // 分级后未签名程序从桌面/文档运行的加分从 25 降至 10,显著降误报。
    private static readonly string[] HighSuspiciousDirs =
    {
        @"\appdata\local\temp\", @"\windows\temp\",
        @"\users\public\", @"\programdata\", @"\$recycle.bin\",
        @"\perflogs\",
    };
    private static readonly string[] MediumSuspiciousDirs =
    {
        @"\downloads\", @"\appdata\roaming\",
        @"\desktop\", @"\documents\", @"\onedrive\desktop\", @"\onedrive\documents\",
    };

    /// <summary>
    /// 评估事件,填充 <see cref="SecurityEvent.RiskScore"/> 与 <see cref="SecurityEvent.RiskReasons"/>。
    /// 设计目标:对真实恶意行为高分,对合法软件尽量 0 分(降误报)。
    /// </summary>
    public static void Analyze(SecurityEvent e)
    {
        int score = 0;
        e.HasThreatIndicator = false;

        // 本地助手:同步累加风险分、记录结构化证据(来源=ThreatDetector)并追加可读原因。
        // hard=true 时该信号视为「硬恶意指标」,置位 HasThreatIndicator。
        void Add(int delta, string reason, bool hard = false, EvidenceKind kind = EvidenceKind.SoftSignal)
        {
            score += delta;
            e.AddEvidence("ThreatDetector", hard ? EvidenceKind.HardIndicator : kind, reason, delta);
            if (hard) e.HasThreatIndicator = true;
        }

        string actorName = SafeFileName(e.ActorPath);
        string parentName = SafeFileName(e.ParentPath);
        string cmd = (e.CommandLine ?? string.Empty).ToLowerInvariant();
        string pathLower = (e.ActorPath ?? string.Empty).ToLowerInvariant();

        // 白名单:PowerShell 临时策略测试文件(__PSScriptPolicyTest)是正常系统行为,
        // 不应触发任何威胁检测。PowerShell 执行策略测试时会自动创建/删除这些临时文件。
        string targetLower = (e.Target ?? string.Empty).ToLowerInvariant();
        if (targetLower.Contains("__psscriptpolicytest"))
        {
            return; // 直接跳过分析,不计分
        }

        bool inHighSuspiciousDir = HighSuspiciousDirs.Any(d => pathLower.Contains(d));
        bool inMediumSuspiciousDir = MediumSuspiciousDirs.Any(d => pathLower.Contains(d));
        bool inSuspiciousDir = inHighSuspiciousDir || inMediumSuspiciousDir;

        // 1) 无可信签名 —— 基础风险
        if (!e.ActorSigned)
        {
            Add(15, "无可信数字签名", kind: EvidenceKind.Info);
        }

        // 1b) 签名失配(有签名但校验失败:篡改/盗用第三方证书)—— 比无签名更可疑。
        //     银狐常滥用合法厂商证书(如 BELLSOFT)签名后篡改。
        if (e.SignatureMismatch)
        {
            Add(45, "数字签名校验失败(疑似篡改或盗用证书)", hard: true);
        }

        // 1b-2) 签名"合法但异常"——专门针对"有正规签名的恶意软件":
        //   · 证书被吊销:被盗用证书常已被 CA 吊销,合法软件不会命中。
        //   · 过期后签名:合法厂商不会用过期证书签新文件,常见于盗用旧证书。
        //   这两类即使发行商是大厂也应高分。
        if (e.CertRevoked)
        {
            Add(60, "签名证书已被吊销(疑似盗用证书)", hard: true);
        }
        if (e.SignedAfterCertExpiry)
        {
            Add(45, "使用过期证书签名(疑似盗用旧证书)", hard: true);
        }

        // 1b-3) 首见 + 新证书:抓"空壳公司骗取新证书"的签名样本。
        //   合法签名 + 本机首次出现 + 证书有效期开始很近(用 NotAfter 推断新证书),
        //   单独看每项都正常,组合起来是空壳证书木马的典型画像 —— 提级到"询问"区间附近。
        if (e.ActorSigned && e.IsFirstSeen)
        {
            Add(15, "带签名但本机首次出现(低流行度)", kind: EvidenceKind.Info);

            // 证书"年轻":有效期截止距今较近(<= 6 个月)往往是新签发证书。
            if (e.CertNotAfterUtc is { } notAfter)
            {
                var remaining = notAfter - DateTime.UtcNow;
                if (remaining > TimeSpan.Zero && remaining <= TimeSpan.FromDays(186))
                {
                    Add(15, "签名证书较新(疑似空壳公司新证书)");
                }
            }
        }

        // 1c) 文件膨胀(file bloating)规避:用海量无效数据把文件撑到极大,
        //     以超过杀软/沙箱扫描体积上限。银狐/游蛇标志性手法。
        const long BloatThreshold = 60L * 1024 * 1024;   // > 60MB 强烈可疑
        const long BloatThresholdHi = 90L * 1024 * 1024; // > 90MB 几乎必为膨胀
        if (e.ActorFileSize >= BloatThresholdHi && !e.ActorSigned)
        {
            // 未签名 + 超大体积(>90MB)几乎必为「文件膨胀规避扫描」——银狐/游蛇标志手法。
            // 正常的大型合法程序(安装包/游戏客户端)绝大多数带数字签名,未签名却如此巨大
            // 极不合常理。此处直接给到高危分(>=HighRisk),确保运行时被【拦截】而非仅询问,
            // 堵住「170MB 未签名释放器只弹询问」的漏网。
            Add(65, $"超大未签名可执行文件({e.ActorFileSize / (1024 * 1024)}MB,几乎必为文件膨胀规避扫描)", hard: true);
        }
        else if (e.ActorFileSize >= BloatThreshold && !e.ActorSigned)
        {
            Add(30, $"异常大的可执行文件({e.ActorFileSize / (1024 * 1024)}MB,疑似文件膨胀)", hard: true);
        }

        // 2) 从可疑目录运行 —— 仅当「未签名」时才显著加分;
        //    已签名程序从 Temp 运行多为合法安装器/更新器,降低误报。
        if (inSuspiciousDir)
        {
            if (!e.ActorSigned)
            {
                Add(25, "未签名程序从可疑目录运行");
            }
            else
            {
                Add(5, "已签名程序从可疑目录运行", kind: EvidenceKind.Info); // 轻微提示,不足以触发询问
            }
        }

        // 2b) 可执行体位于 C:\Windows\ 下的「非标准子目录」(如 C:\Windows\Sub\)。
        //     合法软件几乎从不在 Windows 根下自建子目录驻留,恶意软件却常借此把自己
        //     伪装成系统组件(常配合冒用系统进程名,如 \Windows\Sub\RuntimeBroker.exe)。
        //     作为软信号加分(未签名加重),交由互证机制升格,避免误伤罕见但合法的系统子目录。
        if (IsNonStandardWindowsSubdir(pathLower))
        {
            Add(e.ActorSigned ? 12 : 30,
                "可执行体位于 Windows 非标准子目录(疑似伪装系统组件,T1036)");
        }

        // 3) 异常父子链:Office/浏览器 派生 脚本解释器/LOLBin
        bool parentIsOfficeOrBrowser = OfficeAndBrowsers.Contains(parentName);
        bool actorIsLolBin = LolBins.Contains(actorName);
        if (parentIsOfficeOrBrowser && actorIsLolBin)
        {
            Add(45, $"异常进程链:{parentName} 派生 {actorName}(疑似宏病毒/钓鱼)", hard: true);
        }

        // 4) 命令行高危特征(主要针对 LOLBin)。带签名也照查,防"白加黑"。
        if (!string.IsNullOrEmpty(cmd))
        {
            foreach (var sig in CommandLineSignals)
            {
                if (cmd.Contains(sig.Token))
                {
                    Add(sig.Score, sig.Reason, hard: true);
                }
            }
        }

        // 4b) LOLBins(白利用)滥用分析:识别「微软签名的系统二进制 + 特征滥用参数」组合
        //     (Squiblydoo / mshta 远程 HTA / certutil 下载 / msbuild 内联任务 / wmic 远程执行 等)。
        //     这类二进制签名健康、会命中信任放行通道,只看签名抓不到 —— 必须看二进制+参数语义。
        //     高置信滥用置硬指标(失去签名豁免);可疑形态仅软信号,交互证升格。
        {
            var (lolScore, lolReasons, lolHard) = LolbinAnalyzer.Analyze(e.ActorPath, e.CommandLine);
            if (lolScore > 0)
            {
                score += lolScore;
                bool firstL = true;
                foreach (var r in lolReasons)
                {
                    e.AddEvidence("LolbinAnalyzer",
                        lolHard ? EvidenceKind.HardIndicator : EvidenceKind.SoftSignal, r, firstL ? lolScore : 0);
                    firstL = false;
                }
                if (lolHard) e.HasThreatIndicator = true;
            }
        }

        // 4c) 凭据访问 / LSASS 保护分析:从「目标/路径 + 命令行 + 行为类型」识别凭据窃取
        //     (LSASS 转储/注入、SAM/NTDS 导出、浏览器凭据库、DPAPI)。覆盖现有命令行特征
        //     未覆盖的目标维度。高置信攻击置硬指标并使签名工具失去放行豁免。
        {
            var (caScore, caReasons, caHard) = CredentialAccessAnalyzer.Analyze(e);
            if (caScore > 0)
            {
                score += caScore;
                bool firstC = true;
                foreach (var r in caReasons)
                {
                    e.AddEvidence("CredentialAccessAnalyzer",
                        caHard ? EvidenceKind.HardIndicator : EvidenceKind.SoftSignal, r, firstC ? caScore : 0);
                    firstC = false;
                }
                if (caHard) e.HasThreatIndicator = true;
            }
        }

        // 5) 进程伪装:系统进程名出现在「自己合法目录之外」。
        //    必须按进程具体白名单判定 —— explorer/dwm 在 \Windows\ 而非 \System32\。
        //    仅当拿到「带目录的完整路径」时才判定 —— 裸文件名(路径未知)不应误判。
        bool hasFullPath = pathLower.Contains('\\') || pathLower.Contains('/');
        if (IsSystemProcessName(actorName) && hasFullPath && !IsInSystemDirFor(actorName, pathLower))
        {
            Add(40, $"疑似进程伪装:{actorName} 不在合法目录(T1036.005)", hard: true);
        }

        // 5b) 形近仿冒系统进程名(typosquatting):进程名【不是】真正的系统进程名,
        //     但与某个系统进程名「形近」(编辑距离=1 / 同形字符替换 / 插入空格等)。
        //     例:svch0st.exe、scvhost.exe、lsass.exe、explore.exe、"svchost .exe"。
        //     合法系统进程要么用准确名字(走上面第5节判路径),要么压根不叫这名;
        //     一个长得像 svchost 却不是 svchost 的可执行文件,几乎必为伪装载荷(T1036.005)。
        if (!IsSystemProcessName(actorName))
        {
            var impersonated = FindImpersonatedSystemName(actorName);
            if (impersonated is not null)
            {
                Add(45, $"疑似仿冒系统进程名:{actorName} 形近 {impersonated}(典型伪装手法,T1036.005)", hard: true);
            }
        }

        // 6) 双重扩展名 / 可执行伪装为文档
        if (HasDoubleExtension(actorName))
        {
            Add(30, "可疑双重扩展名(伪装文档,T1036.007)", hard: true);
        }

        // 6b) NTFS 备用数据流(ADS)执行:路径形如 file.txt:hidden.exe(冒号在盘符之后)。
        //     合法程序几乎从不从 ADS 启动,是经典隐藏载荷手法(T1564.004)。
        if (IsAlternateDataStreamPath(e.ActorPath))
        {
            Add(40, "从 NTFS 备用数据流(ADS)执行(隐藏载荷,T1564.004)", hard: true);
        }

        // 6c) 进程注入 / DLL 侧载分析(独创·内存与无文件攻击):跨进程远程线程注入
        //     (镂空/APC/线程劫持/shellcode)、注入凭据/关键/浏览器进程、未签名模块侧载等。
        //     高置信注入(注 lsass/关键进程、未签名或 LOLBin 发起、可疑目录侧载)置硬指标;
        //     合法签名程序的一般注入仅软信号,交互证升格,避免误伤反作弊/录屏/安全软件。
        {
            var (injScore, injReasons, injHard) = InjectionAnalyzer.Analyze(e);
            if (injScore > 0)
            {
                score += injScore;
                bool firstI = true;
                foreach (var r in injReasons)
                {
                    e.AddEvidence("InjectionAnalyzer",
                        injHard ? EvidenceKind.HardIndicator : EvidenceKind.SoftSignal, r, firstI ? injScore : 0);
                    firstI = false;
                }
                if (injHard) e.HasThreatIndicator = true;
            }
        }

        // 7) 命令行混淆分析(独创·无特征码):熵/符号占比/混淆构造统计。
        //    传统规则只匹配明文 token,混淆后失效;这里从统计结构识别"被刻意混淆"。
        if (!string.IsNullOrEmpty(cmd))
        {
            var (obfScore, obfReasons) = CommandObfuscationAnalyzer.Analyze(e.CommandLine);
            if (obfScore > 0)
            {
                score += obfScore;
                // 混淆达到一定强度才算"硬指标",避免对长路径命令行误判
                bool obfHard = obfScore >= 30;
                bool first = true;
                foreach (var r in obfReasons)
                {
                    e.AddEvidence("CommandObfuscationAnalyzer",
                        obfHard ? EvidenceKind.HardIndicator : EvidenceKind.SoftSignal, r, first ? obfScore : 0);
                    first = false;
                }
                if (obfHard) e.HasThreatIndicator = true;
            }
        }

        // 7b) 脚本内容静态分析:检测 PowerShell/VBS/JS 脚本中的恶意特征。
        //     从命令行中提取脚本内容或文件路径，进行深度分析。
        if (!string.IsNullOrEmpty(e.CommandLine))
        {
            var (scriptContent, scriptType) = ScriptAnalyzer.ExtractScriptFromCommandLine(e.CommandLine);
            if (scriptContent != null && scriptType != ScriptType.Unknown)
            {
                var (scriptScore, scriptReasons) = ScriptAnalyzer.AnalyzeScript(scriptContent, scriptType);
                if (scriptScore > 0)
                {
                    score += scriptScore;
                    // 脚本分析达到一定强度才算"硬指标"。
                    // 阈值 60(高于普通几个 token 累加 30-50),要求多类强信号共现才升格,
                    // 避免对解码后脚本里少量常见 cmdlet(Start-Process 等)误判。
                    bool scriptHard = scriptScore >= 60;
                    bool first = true;
                    foreach (var r in scriptReasons)
                    {
                        e.AddEvidence("ScriptAnalyzer",
                            scriptHard ? EvidenceKind.HardIndicator : EvidenceKind.SoftSignal, r, first ? scriptScore : 0);
                        first = false;
                    }
                    if (scriptHard) e.HasThreatIndicator = true;
                }
            }
        }

        // 8) 杀伤链阶段分析(独创·进程树叙事):把进程链上下文映射到 ATT&CK 阶段,
        //    覆盖多个阶段(执行→规避→持久化…)才加分,识别"单步无害、串起来是入侵"。
        if (e.ChainContext is { Count: > 0 })
        {
            var (chainScore, chainReasons, _) = KillChainAnalyzer.Analyze(e.ChainContext);
            if (chainScore > 0)
            {
                score += chainScore;
                bool first = true;
                foreach (var r in chainReasons)
                {
                    e.AddEvidence("KillChainAnalyzer", EvidenceKind.HardIndicator, r, first ? chainScore : 0);
                    first = false;
                }
                e.HasThreatIndicator = true; // 多阶段攻击链是确定性强信号
            }
        }

        // 9) 外部文件信誉(VirusTotal 哈希查询的缓存结果)。
        //    这是"信誉加分项":恶意结论是确定性强信号,直接顶到拦截区间;
        //    可疑结论提级到询问区间;干净结论作为白名单减分(仅当无其他硬指标时)。
        //    注意:此处只读取已缓存的信誉,不发起任何网络调用。
        if (e.Reputation is { } rep)
        {
            switch (rep.Verdict)
            {
                case ReputationVerdict.Malicious:
                    score += 60;
                    e.AddEvidence("Reputation", EvidenceKind.HardIndicator,
                        $"威胁情报:{rep.Malicious}/{rep.TotalEngines} 个引擎判为恶意"
                        + (string.IsNullOrEmpty(rep.ThreatLabel) ? "" : $"({rep.ThreatLabel})"), 60);
                    e.HasThreatIndicator = true;
                    break;
                case ReputationVerdict.Suspicious:
                    score += 30;
                    e.AddEvidence("Reputation", EvidenceKind.HardIndicator,
                        $"威胁情报:{rep.Malicious}/{rep.TotalEngines} 个引擎判为可疑", 30);
                    e.HasThreatIndicator = true;
                    break;
                case ReputationVerdict.Clean:
                    // 仅作轻微减分提示,不强行拉低(避免掩盖本地行为硬指标)。
                    if (!e.HasThreatIndicator && score > 0)
                    {
                        score = Math.Max(0, score - 10);
                        e.AddEvidence("Reputation", EvidenceKind.Trust,
                            "威胁情报:多引擎未检出(信誉良好)", -10);
                    }
                    break;
            }
        }

        e.RiskScore = Math.Min(100, score);
    }

    private static string SafeFileName(string? path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        try { return Path.GetFileName(path).ToLowerInvariant(); }
        catch { return path.ToLowerInvariant(); }
    }

    /// <summary>
    /// 系统进程的「合法目录」白名单。多数系统进程在 \Windows\System32\,
    /// 但 explorer.exe / dwm.exe / fontdrvhost.exe 等就在 \Windows\ 直接下面;
    /// taskhostw 等可能也走 SysWOW64 路径。判定伪装时必须按进程具体可信目录列表,
    /// 否则 explorer.exe 会被错判为「不在系统目录」(它本来就不在 System32)。
    /// </summary>
    private static readonly Dictionary<string, string[]> SystemProcessDirs =
        new(StringComparer.OrdinalIgnoreCase)
    {
        ["svchost.exe"]    = new[] { @"\windows\system32\", @"\windows\syswow64\", @"\windows\winsxs\" },
        ["lsass.exe"]      = new[] { @"\windows\system32\" },
        ["csrss.exe"]      = new[] { @"\windows\system32\" },
        ["services.exe"]   = new[] { @"\windows\system32\" },
        ["winlogon.exe"]   = new[] { @"\windows\system32\" },
        ["smss.exe"]       = new[] { @"\windows\system32\" },
        ["wininit.exe"]    = new[] { @"\windows\system32\" },
        ["dllhost.exe"]    = new[] { @"\windows\system32\", @"\windows\syswow64\", @"\windows\winsxs\" },
        ["taskhostw.exe"]  = new[] { @"\windows\system32\", @"\windows\winsxs\" },
        ["spoolsv.exe"]    = new[] { @"\windows\system32\" },
        ["conhost.exe"]    = new[] { @"\windows\system32\" },
        // explorer / dwm / fontdrvhost 直接住在 \Windows\,不在 System32
        ["explorer.exe"]   = new[] { @"\windows\explorer.exe", @"\windows\winsxs\" },
        ["dwm.exe"]        = new[] { @"\windows\system32\" },
        ["fontdrvhost.exe"] = new[] { @"\windows\system32\" },
        // 现代 Windows 系统进程:同样只合法驻留于 System32,极常被恶意软件冒名伪装
        // (如 C:\Windows\Sub\RuntimeBroker.exe)。补入后伪装到错误目录即命中 T1036.005。
        ["runtimebroker.exe"]        = new[] { @"\windows\system32\" },
        ["sihost.exe"]               = new[] { @"\windows\system32\" },
        ["ctfmon.exe"]               = new[] { @"\windows\system32\" },
        ["userinit.exe"]             = new[] { @"\windows\system32\" },
        ["audiodg.exe"]              = new[] { @"\windows\system32\" },
        ["wuauclt.exe"]              = new[] { @"\windows\system32\" },
        ["searchindexer.exe"]        = new[] { @"\windows\system32\" },
        ["searchprotocolhost.exe"]   = new[] { @"\windows\system32\" },
        ["searchfilterhost.exe"]     = new[] { @"\windows\system32\" },
        ["taskhost.exe"]             = new[] { @"\windows\system32\" },
        ["smartscreen.exe"]          = new[] { @"\windows\system32\" },
        ["securityhealthservice.exe"] = new[] { @"\windows\system32\" },
    };

    /// <summary>
    /// C:\Windows\ 下「可能合法驻留可执行体」的第一级子目录名(小写,不含斜杠)。
    /// 合法系统/组件 EXE 只出现在这组目录或直接位于 \Windows\ 根下;出现在其它
    /// 自建子目录(如 \Windows\Sub\)的可执行体几乎必为伪装系统目录的恶意载荷。
    /// 取并集偏宽以压低误报(本判定仅作软信号,需互证升格)。
    /// </summary>
    private static readonly HashSet<string> LegitWindowsSubdirNames =
        new(StringComparer.OrdinalIgnoreCase)
    {
        "system32", "syswow64", "winsxs", "servicing", "microsoft.net", "assembly",
        "systemapps", "systemresources", "immersivecontrolpanel", "shellexperiences",
        "shellcomponents", "softwaredistribution", "fonts", "inf", "diagnostics",
        "debug", "security", "setup", "ime", "appcompat", "apppatch", "schemas",
        "globalization", "policydefinitions", "branding", "resources", "web", "media",
        "boot", "help", "cursors", "speech", "speech_onecore", "vss", "twain_32",
        "system", "l2schemas", "addins", "containers", "migration", "plugplay",
        "registration", "rescache", "servicestate", "tasks", "temp", "tracing",
        "waas", "winrm", "performance", "panther", "prefetch", "logs", "pchealth",
        "pla", "sysnative", "wbem", "windowspowershell", "downloaded program files",
        "offline web pages", "fixit", "diagtrack", "waasmedic",
    };

    private static bool IsSystemProcessName(string name) => SystemProcessDirs.ContainsKey(name);

    /// <summary>
    /// 受保护的「敏感系统进程名」集合(用于形近仿冒判定的比对基准)。
    /// 这些名字最常被恶意软件仿冒以混入进程列表骗过肉眼巡检。
    /// </summary>
    private static readonly string[] CriticalImageNames =
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
        "wininit.exe", "smss.exe", "explorer.exe", "spoolsv.exe", "taskhostw.exe",
        "dwm.exe", "conhost.exe", "rundll32.exe", "dllhost.exe", "ctfmon.exe",
        "runtimebroker.exe", "sihost.exe", "searchindexer.exe", "audiodg.exe",
    };

    /// <summary>
    /// 判断给定进程名是否为某个敏感系统进程名的「形近仿冒」。
    /// 命中返回被仿冒的真实系统进程名,否则返回 null。
    ///
    /// 判定维度(任一命中即视为仿冒):
    ///   · 去掉所有空白后与真实名相等(如 "svchost .exe" / "s v c h o s t.exe");
    ///   · 同形字符还原后与真实名相等(0↔o、1↔l/i、5↔s、vv↔w 等),如 svch0st、scvhost;
    ///   · 文件主名与真实主名的编辑距离 == 1(单字符增删改),如 scvhost、svchost→svchost、explore。
    /// 为降误报:仅对「足够长(>=5)」的主名做编辑距离判定,且要求扩展名为可执行类。
    /// </summary>
    private static string? FindImpersonatedSystemName(string actorName)
    {
        if (string.IsNullOrEmpty(actorName)) return null;

        // 仅判定可执行类文件,避免对资源/文档名误判。
        string[] exeExts = { ".exe", ".scr", ".com", ".pif", ".bat", ".cmd" };
        if (!exeExts.Any(x => actorName.EndsWith(x, StringComparison.OrdinalIgnoreCase)))
            return null;

        // 1) 去空白后与真实名相等 —— 插入空格/不可见空白的仿冒。
        string noSpace = new string(actorName.Where(c => !char.IsWhiteSpace(c)).ToArray());
        foreach (var real in CriticalImageNames)
            if (!string.Equals(actorName, real, StringComparison.OrdinalIgnoreCase)
                && string.Equals(noSpace, real, StringComparison.OrdinalIgnoreCase))
                return real;

        // 2) 同形字符(homoglyph)还原后比对。
        string deHomo = DeHomoglyph(actorName);
        foreach (var real in CriticalImageNames)
            if (!string.Equals(actorName, real, StringComparison.OrdinalIgnoreCase)
                && string.Equals(deHomo, real, StringComparison.OrdinalIgnoreCase))
                return real;

        // 3) 主名编辑距离 == 1(单字符增/删/改),如 scvhost / explore / svchot。
        string stem = StripExe(actorName);
        if (stem.Length >= 5)
        {
            foreach (var real in CriticalImageNames)
            {
                string realStem = StripExe(real);
                // 主名相等的(已是真实名)不算仿冒;只抓"差一个字符"的近似名。
                if (string.Equals(stem, realStem, StringComparison.OrdinalIgnoreCase)) continue;
                if (LevenshteinAtMost1(stem.ToLowerInvariant(), realStem.ToLowerInvariant()))
                    return real;
            }
        }

        return null;
    }

    /// <summary>把常见同形字符还原为对应字母,用于识别 svch0st / 1sass / scvhо st 等仿冒。</summary>
    private static string DeHomoglyph(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (char c in s)
        {
            char lc = char.ToLowerInvariant(c);
            sb.Append(lc switch
            {
                '0' => 'o',
                '1' => 'l',
                '5' => 's',
                '7' => 't',
                '\u0430' => 'a',   // 西里尔 а
                '\u0435' => 'e',   // 西里尔 е
                '\u043e' => 'o',   // 西里尔 о
                '\u0440' => 'p',   // 西里尔 р
                '\u0441' => 'c',   // 西里尔 с
                _ => lc
            });
        }
        return sb.ToString();
    }

    /// <summary>去掉可执行扩展名,返回主名(小写)。</summary>
    private static string StripExe(string name)
    {
        int dot = name.LastIndexOf('.');
        return (dot > 0 ? name[..dot] : name);
    }

    /// <summary>
    /// 判断两个字符串的 Levenshtein 编辑距离是否恰为 1(单次增/删/改)。
    /// 距离 0(相等)返回 false —— 我们只关心"形近但不相同"。
    /// </summary>
    private static bool LevenshteinAtMost1(string a, string b)
    {
        int la = a.Length, lb = b.Length;
        if (System.Math.Abs(la - lb) > 1) return false;
        if (a == b) return false;

        if (la == lb)
        {
            // 等长:恰好一个位置不同(替换)。
            int diff = 0;
            for (int i = 0; i < la; i++)
                if (a[i] != b[i] && ++diff > 1) return false;
            return diff == 1;
        }

        // 长度差 1:较短串是较长串「删一个字符」的子序列。
        string shorter = la < lb ? a : b;
        string longer = la < lb ? b : a;
        int si = 0, li = 0; bool skipped = false;
        while (si < shorter.Length && li < longer.Length)
        {
            if (shorter[si] == longer[li]) { si++; li++; }
            else
            {
                if (skipped) return false;
                skipped = true; li++;   // 跳过较长串中的一个字符
            }
        }
        return true; // 末尾多出的一个字符也算单次插入
    }

    /// <summary>
    /// 判定给定系统进程名是否位于其合法目录。空路径不判伪装(信号不全)。
    /// 对 explorer.exe 这类直接在 \Windows\ 下的进程,精确匹配整路径片段。
    /// </summary>
    private static bool IsInSystemDirFor(string actorName, string pathLower)
    {
        if (string.IsNullOrEmpty(pathLower)) return true;
        if (!SystemProcessDirs.TryGetValue(actorName, out var dirs)) return true;
        foreach (var d in dirs)
        {
            if (pathLower.Contains(d)) return true;
        }
        return false;
    }

    /// <summary>
    /// 路径是否位于「可疑落地目录」(可写、常被恶意软件用于释放/驻留)。
    /// 复用内部高/中可疑目录列表,供 Worker 判定「释放器派生的可疑载荷」
    /// 是否应触发 AI 病毒扫描。
    /// </summary>
    public static bool IsSuspiciousDropDir(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var pathLower = path.ToLowerInvariant();
        return HighSuspiciousDirs.Any(d => pathLower.Contains(d))
            || MediumSuspiciousDirs.Any(d => pathLower.Contains(d))
            || IsNonStandardWindowsSubdir(pathLower);
    }

    /// <summary>
    /// 判断路径是否位于 C:\Windows\ 下的「非标准子目录」。
    /// 合法系统/组件可执行体只出现在固定的一组 Windows 子目录(<see cref="LegitWindowsSubdirNames"/>)
    /// 或直接位于 \Windows\ 根下(explorer.exe 等);出现在 \Windows\&lt;自建目录&gt;\ 下的
    /// 可执行体几乎必为伪装系统目录的恶意载荷(如 C:\Windows\Sub\RuntimeBroker.exe)。
    /// 仅判定系统盘根下的 Windows 目录(x:\windows\...),避免对名为 windows 的普通文件夹误判。
    /// </summary>
    private static bool IsNonStandardWindowsSubdir(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var pathLower = path.ToLowerInvariant().Replace('/', '\\');

        // 必须形如  x:\windows\...
        if (pathLower.Length < 4 || pathLower[1] != ':') return false;
        string rest = pathLower.Substring(2); // 去掉盘符 "x:"
        const string win = @"\windows\";
        if (!rest.StartsWith(win, StringComparison.Ordinal)) return false;

        // \windows\ 之后若没有下一级目录(直接是文件,如 explorer.exe),不算伪装
        int nextSlash = rest.IndexOf('\\', win.Length);
        if (nextSlash < 0) return false;

        string firstSub = rest.Substring(win.Length, nextSlash - win.Length); // 第一级子目录名
        return !LegitWindowsSubdirNames.Contains(firstSub);
    }

    private static bool HasDoubleExtension(string name)
    {
        // 例如 invoice.pdf.exe / photo.jpg.scr
        string[] docExts = { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".rtf" };
        string[] exeExts = { ".exe", ".scr", ".com", ".bat", ".cmd", ".pif", ".vbs", ".js" };
        foreach (var d in docExts)
            foreach (var x in exeExts)
                if (name.EndsWith(d + x, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    /// <summary>
    /// 判断路径是否指向 NTFS 备用数据流(ADS),如 C:\path\file.txt:payload.exe。
    /// 规则:在盘符冒号(位置 1)之后,还出现额外的冒号。合法可执行路径不含此形态。
    /// </summary>
    private static bool IsAlternateDataStreamPath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        int start = (path.Length > 1 && path[1] == ':') ? 2 : 0; // 跳过盘符冒号
        return path.IndexOf(':', start) >= 0;
    }
}