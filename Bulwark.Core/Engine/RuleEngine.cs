using System.Collections.Concurrent;
using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// 规则引擎(决策中心)。对一个事件给出初步裁决:
/// 1) 命中已有规则 -> 直接 Allow/Block
/// 2) 受信任签名 + 默认信任开启 -> Allow
/// 3) 否则 -> Ask(交由 UI 弹窗)
///
/// 线程安全:规则集合用 <see cref="ConcurrentDictionary{TKey,TValue}"/> 持有。
/// </summary>
public sealed class RuleEngine
{
    private readonly ConcurrentDictionary<System.Guid, DefenseRule> _rules = new();

    /// <summary>
    /// 勒索行为监视器(独创·有状态):滑窗内批量改写/扩展名同化/蜜罐触碰/勒索信检测。
    /// 由引擎在评估文件事件时自动喂入,命中即作为硬恶意指标参与决策。
    /// 阈值取 25:编译器 / 安装器 / 测试运行器 / 同步盘在 10 秒内改写十几个文件属常态,
    /// 真实勒索通常瞬时加密成百上千个文件,上调阈值可显著降误报而不漏真勒索。
    /// </summary>
    public RansomwareBehaviorMonitor Ransomware { get; } = new(burstThreshold: 25);

    /// <summary>
    /// C2 心跳信标探测器(独创·有状态):用外联时间间隔规律性识别 Beacon 回连。
    /// 由引擎在评估网络事件时自动喂入。
    /// </summary>
    public BeaconDetector Beacon { get; } = new();

    /// <summary>
    /// 外联速率/扇出监视器(独创·有状态):识别端口扫描 / 横移 / 蠕虫传播 / 数据外传分块上传
    /// 这类"高速、多目标"的外联。由引擎在评估网络事件时自动喂入。
    /// 速率/扇出是软信号,单独不处置,仅在与其它硬指标共现时升格(互证)。
    /// </summary>
    public EgressRateMonitor Egress { get; } = new();

    /// <summary>
    /// 行为基线 / 异常检测器(独创·有状态画像):为每个程序建立"平时怎么做"的画像
    /// (子进程 / 外联目标 / 写入目录),出现显著偏离自身历史的行为时升分。
    /// 偏离基线恒为软信号,单独不处置,仅在与硬指标共现时升格(互证)。
    /// 由引擎在评估时自动喂入。状态可由宿主通过 Export/Import 快照持久化。
    /// </summary>
    public BaselineAnalyzer Baseline { get; } = new();

    /// <summary>是否启用行为基线偏离评分。关闭后仍持续学习画像,但不产出偏离软信号。默认开启。</summary>
    public bool EnableBaseline { get; set; } = true;

    /// <summary>
    /// 本软件(磐垒)自身组件的进程映像名(小写)。这些进程发起的任何事件一律直接放行,
    /// 防御软件绝不应拦截/打扰自己的 UI、服务、驱动与辅助进程。
    /// </summary>
    private static readonly System.Collections.Generic.HashSet<string> SelfImageNames =
        new(System.StringComparer.OrdinalIgnoreCase)
        {
            "bulwark.service.exe",
            "bulwark.ui.exe",
            "bulwark.tray.exe",
            "probe.exe",
        };

    /// <summary>
    /// 本软件自身的目录(小写,以分隔符结尾)。位于这些目录下的主体一律放行。
    /// 由宿主(服务)在启动时通过 <see cref="AddSelfDirectory"/> 注入(如 UI/服务的 bin 目录)。
    /// 配合 <see cref="SelfImageNames"/> 双重兜底:既认进程名,也认安装目录。
    /// </summary>
    private readonly System.Collections.Generic.HashSet<string> _selfDirectories =
        new(System.StringComparer.OrdinalIgnoreCase);

    /// <summary>注册一个"本软件自身目录"。该目录(及其子目录)下的主体进程将被直接放行。</summary>
    public void AddSelfDirectory(string? dir)
    {
        if (string.IsNullOrWhiteSpace(dir)) return;
        var norm = dir.Trim().ToLowerInvariant().Replace('/', '\\');
        if (!norm.EndsWith("\\")) norm += "\\";
        _selfDirectories.Add(norm);
    }

    /// <summary>判断事件主体是否为本软件自身组件(按进程名或自身目录)。</summary>
    private bool IsSelfComponent(SecurityEvent e)
    {
        // 1) 主体进程本身是本软件组件
        if (MatchesSelf(e.ActorPath)) return true;

        // 2) 主体的父进程是本软件组件 —— 即"由本软件启动的子进程"。
        //    典型:UI 通过 AI 客户端(AiClient)调用系统 curl.exe 去请求 AI 接口,
        //    此时主体是 system32\curl.exe(非本软件),但父进程是 Bulwark.UI。
        //    放行这类子进程,避免本软件的正常外部调用被自己拦截/弹窗。
        if (MatchesSelf(e.ParentPath)) return true;

        return false;
    }

    /// <summary>判断给定进程路径是否属于本软件(按映像名或自身目录)。</summary>
    private bool MatchesSelf(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;

        // 进程映像名匹配本软件组件
        try
        {
            var name = System.IO.Path.GetFileName(path);
            if (!string.IsNullOrEmpty(name) && SelfImageNames.Contains(name))
                return true;
        }
        catch { /* 路径异常忽略,继续目录判断 */ }

        // 位于本软件自身目录下
        if (_selfDirectories.Count > 0)
        {
            var pathLower = path.ToLowerInvariant().Replace('/', '\\');
            foreach (var d in _selfDirectories)
                if (pathLower.StartsWith(d, System.StringComparison.OrdinalIgnoreCase))
                    return true;
        }

        return false;
    }

    /// <summary>是否自动放行带可信签名的主体进程。</summary>
    public bool TrustSignedActors { get; set; } = true;

    /// <summary>无规则、未询问时的兜底动作(默认放行以避免误杀;高安全场景可设为 Block)。</summary>
    public VerdictAction DefaultAction { get; set; } = VerdictAction.Allow;

    public void LoadRules(System.Collections.Generic.IEnumerable<DefenseRule> rules)
    {
        _rules.Clear();
        foreach (var r in rules) _rules[r.Id] = r;
    }

    public System.Collections.Generic.IReadOnlyCollection<DefenseRule> GetRules()
        => _rules.Values.Where(r => !r.IsExpired(System.DateTime.UtcNow)).ToArray();

    /// <summary>移除所有已到期规则(从规则集中真正删除)。返回被移除的条数。</summary>
    public int PruneExpired()
    {
        var now = System.DateTime.UtcNow;
        int removed = 0;
        foreach (var kv in _rules)
            if (kv.Value.IsExpired(now) && _rules.TryRemove(kv.Key, out _)) removed++;
        return removed;
    }

    public void AddRule(DefenseRule rule) => _rules[rule.Id] = rule;

    public bool RemoveRule(System.Guid id) => _rules.TryRemove(id, out _);

    /// <summary>规则具体度:越具体越优先。委托给规则自身计算。</summary>
    private static int Specificity(DefenseRule r) => r.SpecificityScore();

    /// <summary>
    /// 规则的「层级」排序键。决定在多条规则同时命中时谁优先,优先级高于具体度:
    ///   2 = 用户精确加白/锁定(指定了 ActorPath 或 ActorHashes)—— 永远最高,保证用户覆盖始终生效;
    ///   1 = 确定性恶意硬拦截(HardOverride)—— 压过宽泛的灰区 Ask 规则,确保 .pdf.exe 等被硬拦;
    ///   0 = 普通内置/灰区规则 —— 按下面的具体度与动作强度竞争。
    /// </summary>
    private static int RuleTier(DefenseRule r)
    {
        bool exactActor = !string.IsNullOrEmpty(r.ActorPath) || (r.ActorHashes is { Count: > 0 });
        if (exactActor) return 2;
        if (r.HardOverride) return 1;
        return 0;
    }

    /// <summary>同等具体度下的动作强度:Block > Ask > Allow。</summary>
    private static int RulePriority(VerdictAction a) => a switch
    {
        VerdictAction.Block => 2,
        VerdictAction.Ask => 1,
        _ => 0
    };

    /// <summary>
    /// 评估事件。返回的 Verdict.Action 可能是 Ask,表示需要用户裁决。
    /// 决策顺序:命中规则 > 威胁评分 > 受信任签名 > 默认。
    ///
    /// 本方法是对 <see cref="EvaluateInternal"/> 的薄包装:在拿到最终裁决后,
    /// 统一在证据链尾部追加一条「最终裁决」说明(动作 + 来源),使时间线自洽完整。
    /// </summary>
    public Verdict Evaluate(SecurityEvent e)
    {
        var verdict = EvaluateInternal(e);
        AppendDecisionEvidence(e, verdict);
        AttackAnnotator.Annotate(e);
        return verdict;
    }

    /// <summary>在证据链尾部补一条最终裁决说明,串起整条决策时间线。</summary>
    private static void AppendDecisionEvidence(SecurityEvent e, Verdict v)
    {
        string action = v.Action switch
        {
            VerdictAction.Block => "阻止",
            VerdictAction.Ask => "询问用户",
            _ => "放行"
        };
        string source = v.Source switch
        {
            VerdictSource.Rule => "命中规则",
            VerdictSource.Heuristic => "行为研判",
            VerdictSource.TrustedSigner => "可信放行",
            VerdictSource.UserPrompt => "用户裁决",
            VerdictSource.Timeout => "超时按默认策略",
            _ => "默认策略"
        };
        e.AddEvidence("RuleEngine", EvidenceKind.Decision,
            $"最终裁决:{action}(依据:{source};风险分 {e.RiskScore})", alsoReason: false);
    }

    private Verdict EvaluateInternal(SecurityEvent e)
    {
        // -1) 本软件自身组件(UI/服务/驱动/探针)无条件放行。
        //     防御软件绝不应拦截或打扰自己,且其行为可信。此判断置于最前,
        //     不跑威胁检测、不弹窗,直接放行,避免自我误伤导致界面/服务异常。
        if (IsSelfComponent(e))
        {
            e.AddEvidence("RuleEngine", EvidenceKind.Trust, "本软件自身组件,无条件放行", alsoReason: false);
            return Verdict.For(e, VerdictAction.Allow, VerdictSource.TrustedSigner);
        }

        // -0.5) 已安装的知名安全软件(杀软/EDR)位于受保护安装目录:共存放行。
        //       这类同类产品有强自我保护,常导致我方读不到其签名(WinVerifyTrust 失败)而误判
        //       「签名失配/篡改」,叠加其清理自身 Temp 的批量删除被勒索监视器计数,造成严重误报
        //       (如 Kaspersky avp.exe)。按「进程名 + 必须位于 Program Files/ProgramData/System32」
        //       双重判定放行,既消除互踩误报,又防恶意软件在用户目录伪造同名 exe 冒充。
        if (TrustPolicy.IsTrustedSecurityProduct(e, out var secReason))
        {
            e.AddEvidence("TrustPolicy", EvidenceKind.Trust, secReason, alsoReason: false);
            return Verdict.For(e, VerdictAction.Allow, VerdictSource.TrustedSigner);
        }

        // 0) 先跑威胁检测,填充 RiskScore / RiskReasons
        ThreatDetector.Analyze(e);

        // 0b) 有状态时序检测器(独创):勒索批量改写 / C2 周期信标。
        //     这两类是"单事件无害、时序聚合才暴露"的攻击,无法用静态规则捕捉。
        if (e.Type is EventType.FileWrite or EventType.FileDelete)
        {
            var (rScore, rReasons, canaryHit, hardSignal) = Ransomware.Observe(e);
            if (rScore > 0)
            {
                e.RiskScore = System.Math.Min(100, e.RiskScore + rScore);
                bool firstR = true;
                foreach (var r in rReasons)
                {
                    e.AddEvidence("RansomwareBehaviorMonitor",
                        (canaryHit || hardSignal) ? EvidenceKind.HardIndicator : EvidenceKind.SoftSignal,
                        r, firstR ? rScore : 0);
                    firstR = false;
                }

                // 触碰蜜罐诱饵 = 几乎可确认勒索,直接硬拦截(任何主体都不豁免,含签名程序)。
                if (canaryHit)
                {
                    e.HasThreatIndicator = true;
                    return Verdict.For(e, VerdictAction.Block, VerdictSource.Heuristic);
                }

                // 主体是否为"健康签名 / 强可信 / 受信任发行商"。
                // 关键事实:真实勒索载荷几乎从不带健康且受信任的数字签名 —— 盗用证书会吊销/失配,
                // 空壳新证书会被首见+新证书画像拦下(这些已使 IsHealthySigned 返回 false)。
                // 因此一个"签名健康"的程序做批量改写,绝大多数是编译器 / dotnet 测试 / 安装器 /
                // 同步盘 / 备份工具的正常行为。除蜜罐诱饵(上面已硬拦)外,不据行为特征拦截它,
                // 消除 "dotnet.exe 清理测试临时文件被当勒索" 这类误报。
                bool trustedActor =
                    TrustPolicy.IsStronglyTrusted(e, out _) ||
                    TrustPolicy.IsHealthySigned(e, out _) ||
                    (e.ActorSigned && TrustPolicy.IsBenignSigner(e, out _));

                // 是否存在"加密确证"信号(已知勒索扩展名批量产生 / 勒索信写入)。
                // 仅有"高速批量改写""未知扩展名同化"等软信号时为 false。
                if (hardSignal)
                {
                    if (trustedActor)
                    {
                        // 健康签名 + 仅行为特征(未触蜜罐):记录原因但不硬拦,交签名放行通道。
                        // 已知勒索扩展名/勒索信由非签名主体产生才是真信号;签名主体多为误判。
                        e.AddEvidence("RansomwareBehaviorMonitor", EvidenceKind.Trust,
                            "主体签名健康,勒索行为特征按误报抑制(未触蜜罐诱饵)", alsoReason: false);
                    }
                    else
                    {
                        // 非可信主体的确证勒索:硬指标,达到可疑分即直接 Block
                        // (高速破坏性,逐文件弹窗无意义)。
                        e.HasThreatIndicator = true;
                        if (rScore >= ThreatDetector.Suspicious)
                            return Verdict.For(e, VerdictAction.Block, VerdictSource.Heuristic);
                    }
                }
                else
                {
                    // 仅软信号(高速批量改写等)。**这不是勒索的充分证据** —— 浏览器缓存、
                    // 同步盘、编译器、安装器、备份工具都会高速改写大量文件。
                    // 若主体是健康签名 / 受信任发行商程序(如签名的浏览器),不据此拦截或弹窗,
                    // 交由下方正常的签名放行通道处理,消除"360浏览器被当勒索"这类误报。
                    if (!trustedActor)
                    {
                        // 非可信主体的高速批量改写仍属可疑,但只"询问"而非直接拦截,
                        // 把最终判断交给用户/AI,而不是仅凭改写速率就处置。
                        e.HasThreatIndicator = true;
                        if (rScore >= ThreatDetector.Suspicious)
                            return Verdict.For(e, VerdictAction.Ask, VerdictSource.Heuristic);
                    }
                    // 可信主体的纯软信号:仅记录原因,不置硬指标,继续走签名放行通道。
                }
            }
        }
        else if (e.Type == EventType.NetworkConnect)
        {
            // 周期性信标(时序节律)—— 强行为指标,命中即置硬指标。
            var (bScore, bReasons) = Beacon.Observe(e);
            bool beaconHit = bScore > 0;
            if (beaconHit)
            {
                e.RiskScore = System.Math.Min(100, e.RiskScore + bScore);
                bool firstB = true;
                foreach (var r in bReasons)
                {
                    e.AddEvidence("BeaconDetector", EvidenceKind.HardIndicator, r, firstB ? bScore : 0);
                    firstB = false;
                }
                e.HasThreatIndicator = true;
            }

            // DGA 域名随机度(无黑名单)—— 纯软信号。正常 CDN/哈希子域也可能高随机度,
            // 故单独【不】置硬指标,仅累加 RiskScore/RiskReasons;只有与另一硬指标
            // (信标命中 / 未签名脚本解释器外联)共现时才"升格"(互证机制),
            // 严守"软信号不单独处置"的低误报原则。
            var (dScore, dReasons) = DgaDomainAnalyzer.Analyze(e.Target);
            bool dgaSuspicious = dScore >= 40;
            if (dScore > 0)
            {
                e.RiskScore = System.Math.Min(100, e.RiskScore + dScore);

                // 升格条件:已命中信标(时序硬证据),或主体是未签名脚本解释器外联到高随机域名
                // (DGA 分达到可疑分,几乎必为 C2 域名生成回连)。
                bool corroborated = beaconHit || (!e.ActorSigned && dgaSuspicious);
                bool firstD = true;
                foreach (var r in dReasons)
                {
                    e.AddEvidence("DgaDomainAnalyzer",
                        corroborated ? EvidenceKind.HardIndicator : EvidenceKind.SoftSignal, r, firstD ? dScore : 0);
                    firstD = false;
                }
                if (corroborated)
                {
                    e.HasThreatIndicator = true;
                    e.AddEvidence("DgaDomainAnalyzer", EvidenceKind.Corroboration,
                        "DGA 随机域名与其它恶意指标互证(升格为硬指标)", alsoReason: false);
                }
            }

            // 外联速率/扇出(高速、多目标)—— 同为软信号。浏览器/下载器/P2P/更新检查
            // 都可能高速多目标外联,故单独【不】置硬指标,仅累加分与原因;
            // 只有与另一硬指标(信标 / DGA 升格)或"未签名主体"共现时才升格(互证)。
            var (eScore, eReasons) = Egress.Observe(e);
            if (eScore > 0)
            {
                e.RiskScore = System.Math.Min(100, e.RiskScore + eScore);

                bool corroborated = beaconHit || dgaSuspicious || !e.ActorSigned;
                bool escalated = corroborated && eScore >= 50;
                bool firstE = true;
                foreach (var r in eReasons)
                {
                    e.AddEvidence("EgressRateMonitor",
                        escalated ? EvidenceKind.HardIndicator : EvidenceKind.SoftSignal, r, firstE ? eScore : 0);
                    firstE = false;
                }
                if (escalated)
                {
                    e.HasThreatIndicator = true;
                    e.AddEvidence("EgressRateMonitor", EvidenceKind.Corroboration,
                        "异常外联速率/扇出与其它恶意指标互证(升格为硬指标)", alsoReason: false);
                }
            }
        }

        // 0c) 行为基线偏离(独创):为每个程序建立"平时怎么做"的画像,出现显著偏离自身历史
        //     (首次派生某子进程 / 首次外联某主机 / 首次写入某目录)时升分。
        //     这是软信号 —— 单独【不】置硬指标、不处置,只累加 RiskScore;
        //     仅当本事件已存在硬指标(被劫持/注入/侧载后行为突变)时,作为互证升格记录。
        //     学习期/高基数程序(浏览器等)不评分,严守低误报原则。
        if (EnableBaseline)
        {
            var (blScore, blReasons, blDeviation) = Baseline.Observe(e);
            if (blScore > 0 && blDeviation)
            {
                e.RiskScore = System.Math.Min(100, e.RiskScore + blScore);
                bool corroborated = e.HasThreatIndicator;
                bool firstBl = true;
                foreach (var r in blReasons)
                {
                    e.AddEvidence("BaselineAnalyzer",
                        corroborated ? EvidenceKind.Corroboration : EvidenceKind.SoftSignal,
                        r, firstBl ? blScore : 0);
                    firstBl = false;
                }
                if (corroborated)
                    e.AddEvidence("BaselineAnalyzer", EvidenceKind.Corroboration,
                        "行为偏离自身历史基线,与其它恶意指标互证", alsoReason: false);
            }
        }

        // 1) 显式规则优先。排序:更具体(指定了主体)的规则 > 动作强度(Block>Ask>Allow)> 最近创建。
        //    这样用户为某程序新增的精确规则(含 ActorPath)可覆盖宽泛的内置规则,
        //    实现"加白";同等宽泛度下,硬拦截优先,保守安全。
        var hit = _rules.Values
            .Where(r => r.Matches(e))
            .OrderByDescending(r => RuleTier(r))
            .ThenByDescending(r => Specificity(r))
            .ThenByDescending(r => RulePriority(r.Action))
            .ThenByDescending(r => r.CreatedUtc)
            .FirstOrDefault();
        if (hit is not null)
        {
            // 敏感但合法 OS 组件也会做的 Ask 级规则(如重置/调整 UAC 提权确认级别):
            // 命中后若主体是强可信系统组件(微软签名+系统目录、签名健康、无硬指标、非 LOLBin),
            // 豁免放行,消除 RuntimeBroker/设置中心这类误报。LOLBin(reg/powershell 等)不豁免。
            if (hit.ExemptTrustedOsComponent
                && hit.Action != VerdictAction.Block
                && TrustPolicy.IsTrustedOsComponent(e, out var osReason))
            {
                e.AddEvidence("TrustPolicy", EvidenceKind.Trust, osReason);
                return Verdict.For(e, VerdictAction.Allow, VerdictSource.TrustedSigner);
            }

            // 优化:开发工具白名单 - 如果是开发工具且规则是Ask级别，自动放行
            // 这减少了开发环境中的弹窗干扰
            if (hit.Action == VerdictAction.Ask && DefaultRules.IsDevTool(e.ActorPath))
            {
                e.AddEvidence("RuleEngine", EvidenceKind.Trust, "开发工具自动放行(白名单)");
                return Verdict.For(e, VerdictAction.Allow, VerdictSource.TrustedSigner);
            }

            e.MatchedRuleNote = hit.Note;
            e.AddEvidence("RuleEngine", EvidenceKind.Rule,
                $"命中规则:{(string.IsNullOrEmpty(hit.Note) ? hit.Action.ToString() : hit.Note)}", alsoReason: false);
            return Verdict.For(e, hit.Action, VerdictSource.Rule);
        }

        // 2) 强可信主体直接放行(降误报)。注意:这是唯一"跳过行为检测"的通道,
        //    条件极严(证书指纹白名单 / 微软签名+系统目录,且签名健康)。
        //    一般合法签名(大厂)不在此放行 —— 它们仍要走下面的行为/评分检测,
        //    以防"合法签名被滥用"(盗证书、空壳公司证书、BYOVD、白加黑)。
        if (TrustSignedActors && TrustPolicy.IsStronglyTrusted(e, out var trustReason))
        {
            e.AddEvidence("TrustPolicy", EvidenceKind.Trust, trustReason);
            return Verdict.For(e, VerdictAction.Allow, VerdictSource.TrustedSigner);
        }

        // 2b) 签名异常(吊销 / 过期后签名)—— 即便发行商是大厂也视为高危,直接阻止。
        //     这是抓"盗用合法证书"样本的关键。(属于硬恶意指标)
        if (e.CertRevoked || e.SignedAfterCertExpiry)
            return Verdict.For(e, VerdictAction.Block, VerdictSource.Heuristic);

        // 2c) 健康签名直接放行(免打扰):有有效数字签名、且无任何盗用/滥用/银狐画像时,
        //     直接放行不弹窗。IsHealthySigned 内部已严格排除签名失配/吊销/过期后签名、
        //     文件膨胀、危险命令行、白加黑链、攻击链、空壳新证书木马等画像 —— 这些场景
        //     不会走此通道,仍交由下方行为研判处置。受 TrustSignedActors 开关控制。
        if (TrustSignedActors && TrustPolicy.IsHealthySigned(e, out var healthyReason))
        {
            e.AddEvidence("TrustPolicy", EvidenceKind.Trust, healthyReason);
            return Verdict.For(e, VerdictAction.Allow, VerdictSource.TrustedSigner);
        }

        // ──────────────────────────────────────────────────────────────
        // 核心原则:**只有真正检测到危险行为才处置**。
        // 危险行为 = 命中上面的规则(确定性恶意操作),或出现「硬恶意指标」
        // (HasThreatIndicator:危险命令行 / 异常进程链 / 进程伪装 / 双扩展名 /
        //  文件膨胀 / 签名篡改 等)。
        //
        // 「软信号」——无签名、在可疑目录运行、本机首见、证书较新——本身不是行为证据,
        // 即便累加出较高 RiskScore 也【不】触发拦截或询问。这避免把正常的绿色软件 /
        // 开源工具 / 自编译程序仅因"没签名/位置/新出现"就拦下来。
        // ──────────────────────────────────────────────────────────────
        if (e.HasThreatIndicator)
        {
            // 真实恶意行为:按风险强度处置。高危直接拦截,其余询问用户。
            return e.RiskScore >= ThreatDetector.HighRisk
                ? Verdict.For(e, VerdictAction.Block, VerdictSource.Heuristic)
                : Verdict.For(e, VerdictAction.Ask, VerdictSource.Heuristic);
        }

        // 无硬恶意指标:无论是否签名、无论软信号评分高低,一律放行(仅记录)。
        if (e.ActorSigned && TrustPolicy.IsBenignSigner(e, out var benignReason))
            e.AddEvidence("TrustPolicy", EvidenceKind.Trust, benignReason);
        else if (e.RiskScore > 0)
            e.AddEvidence("RuleEngine", EvidenceKind.Info, "无恶意行为特征(默认放行)");

        return Verdict.For(e, VerdictAction.Allow, VerdictSource.DefaultPolicy);
    }

    /// <summary>把一条用户/规则裁决固化为持久规则(用于"记住我的选择")。</summary>
    public DefenseRule CreateRuleFrom(SecurityEvent e, VerdictAction action,
        System.DateTime? expiresUtc = null, bool sessionOnly = false)
    {
        var rule = new DefenseRule
        {
            ActorPath = e.ActorPath,
            Type = e.Type,
            TargetPattern = string.IsNullOrEmpty(e.Target) ? null : e.Target,
            Action = action,
            ExpiresUtc = expiresUtc,
            SessionOnly = sessionOnly
        };
        AddRule(rule);
        return rule;
    }
}
