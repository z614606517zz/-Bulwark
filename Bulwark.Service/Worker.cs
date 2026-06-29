using Bulwark.Core.Engine;
using Bulwark.Core.Ipc;
using Bulwark.Core.Models;
using Bulwark.Service.Ipc;
using Bulwark.Service.Monitoring;
using Bulwark.Service.Reputation;
using Bulwark.Service.Storage;

namespace Bulwark.Service;

/// <summary>
/// 主防御循环(决策中心宿主)。
/// 流程:事件源 -> 规则引擎评估 -> (需要时)弹窗询问 UI -> 处置 + 记录 + 可选持久化规则。
/// </summary>
public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly IpcServer _ipc;
    private readonly IEventSource _eventSource;
    private readonly RuleEngine _engine;
    private readonly RuleStore _store;
    private readonly SettingsStore _settingsStore;
    private readonly BaselineStore _baselineStore;
    private readonly AuditLog _audit;
    private readonly AlertExporter _alertExporter;
    private readonly ProcessChainTracker _chain;
    private readonly ReputationManager _reputation;
    private readonly VirusTotalClient _vt;
    private readonly VtScanHistoryStore _vtHistory;
    private readonly QuarantineManager _quarantine;
    private readonly ThreatRemediator? _remediator;

    /// <summary>若事件源支持裁决回写(如内核驱动),则非空。</summary>
    private readonly IVerdictSink? _verdictSink;

    /// <summary>若事件源支持「禁止加载」处置(内核驱动),则非空。</summary>
    private readonly IModuleBlockSink? _moduleBlockSink;

    /// <summary>当前运行时设置(总开关/各维度开关/策略)。</summary>
    private RuntimeSettings _settings;

    /// <summary>用户裁决等待超时。超时后按引擎默认策略处置。</summary>
    private TimeSpan _promptTimeout;

    /// <summary>
    /// 并发处理事件的上限闸门。旧实现对每个事件无条件 fire-and-forget,
    /// 进程风暴(或大量需 AI/弹窗等待 30s 的事件)下会无界堆积任务,耗尽内存/线程。
    /// 这里用信号量对「同时在途的事件处理任务」设上限,超出时消费循环自然背压
    /// (事件仍在事件源的通道里缓冲,不丢),处理完一个再放行下一个。
    /// 取值偏大以容纳大量并发的 I/O 等待(裁决多为快路径,只有少数会真正阻塞)。
    /// </summary>
    private readonly SemaphoreSlim _eventConcurrency =
        new(Math.Max(16, Environment.ProcessorCount * 4));

    public Worker(
        ILogger<Worker> logger,
        IpcServer ipc,
        IEventSource eventSource,
        RuleEngine engine,
        RuleStore store,
        SettingsStore settingsStore,
        AuditLog audit,
        AlertExporter alertExporter,
        BaselineStore baselineStore,
        ProcessChainTracker chain,
        ReputationManager reputation,
        VirusTotalClient vt,
        VtScanHistoryStore vtHistory,
        QuarantineManager quarantine,
        BulwarkOptions options)
    {
        _logger = logger;
        _ipc = ipc;
        _eventSource = eventSource;
        _engine = engine;
        _store = store;
        _settingsStore = settingsStore;
        _audit = audit;
        _alertExporter = alertExporter;
        _baselineStore = baselineStore;
        _chain = chain;
        _reputation = reputation;
        _vt = vt;
        _vtHistory = vtHistory;
        _quarantine = quarantine;
        _remediator = OperatingSystem.IsWindows() ? new ThreatRemediator(quarantine, logger) : null;
        _verdictSink = eventSource as IVerdictSink;
        _moduleBlockSink = eventSource as IModuleBlockSink;

        // 用 appsettings.json 作为默认值初始化设置
#pragma warning disable CA1416 // EventSourceCoordinator 仅在 Windows 创建
        var baseName = (eventSource as EventSourceCoordinator)?.BaseSourceName ?? options.EventSource;
#pragma warning restore CA1416
        _settings = new RuntimeSettings
        {
            TrustSignedActors = options.TrustSignedActors,
            DefaultBlock = options.DefaultAction == VerdictAction.Block,
            PromptTimeoutSeconds = options.PromptTimeoutSeconds,
            EventSource = baseName,
            // 内核驱动事件源默认随配置启用(默认 true)。全维度实时防护(文件/注册表/
            // 网络/反注入/自保 + 内核硬拦截)都来自驱动源;基础 WMI 源只产生「进程创建」,
            // 无法覆盖已运行进程的后续行为。若关闭驱动源,防护就只对新进程生效、对已运行
            // 进程的文件/注册表/网络/注入行为完全无反应。环境未加载驱动时会自动重试并降级。
            KernelDriverEnabled = options.KernelDriverEnabled,
            VirusTotalEnabled = options.VirusTotal.Enabled,
            MalwareBazaarEnabled = options.MalwareBazaar.Enabled,
            OtxEnabled = options.Otx.Enabled,
            ThreatBookEnabled = options.ThreatBook.Enabled,
            MetaDefenderEnabled = options.MetaDefender.Enabled,
            AiBaseUrl = options.Ai.BaseUrl ?? string.Empty,
            AiApiKey = options.Ai.ResolveApiKey(),
            AiModel = options.Ai.Model ?? string.Empty
        };
        _promptTimeout = TimeSpan.FromSeconds(Math.Max(5, options.PromptTimeoutSeconds));

        // 按配置启用/关闭在线证书吊销校验(默认关闭:仅用本机缓存 CRL,不联网不阻塞)。
        Monitoring.ProcessInspector.OnlineRevocationCheck = options.OnlineCertRevocationCheck;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // 启用 SeDebugPrivilege:主动处置(结束恶意进程树)的前提。
        // 没有它,对高完整性 / 跨会话 / 系统自带程序(LOLBin)的 OpenProcess(TERMINATE)
        // 会被拒绝,导致「检测到并判定 Block,但进程结束失败」。服务以 LocalSystem
        // 运行时持有该特权但默认禁用,这里显式启用一次。
        if (OperatingSystem.IsWindows())
        {
            bool seDebug = ProcessInspector.EnsureDebugPrivilege();
            if (seDebug)
                _logger.LogInformation("已启用 SeDebugPrivilege,主动处置可结束高权限/系统自带程序进程。");
            else
                _logger.LogWarning("启用 SeDebugPrivilege 失败:对部分高权限进程的主动处置可能受限" +
                    "(请确认服务以 LocalSystem/管理员身份运行)。");
        }

        // 加载持久化规则
        var rules = await _store.LoadAsync(stoppingToken);
        // 首次运行(无任何持久化规则)时植入内置默认规则,做到开箱即用
        if (rules.Count == 0)
        {
            rules = new List<DefenseRule>(DefaultRules.Build());
            await _store.SaveAsync(rules, stoppingToken);
            _logger.LogInformation("首次运行:已植入 {n} 条内置防护规则。", rules.Count);
        }
        else
        {
            // 已有规则:增量合并新版内置规则(按备注去重),使升级后新增的内置规则能生效,
            // 同时保留用户自定义/信任规则不丢失。
            int added = MergeBuiltInRules(rules);
            if (added > 0)
            {
                await _store.SaveAsync(rules, stoppingToken);
                _logger.LogInformation("已增量合并 {n} 条新增内置防护规则。", added);
            }
        }
        _engine.LoadRules(rules);
        _logger.LogInformation("已加载 {count} 条防护规则。", rules.Count);

        // 注册本软件自身目录到引擎白名单:服务自身目录,以及同级的 UI 目录。
        // 使本软件所有组件(服务/UI/托盘/探针)发起的行为一律放行,绝不自我拦截。
        RegisterSelfDirectories();

        // 部署勒索蜜罐诱饵文件并注册到行为监视器:勒索软件批量加密时极可能触碰这些诱饵,
        // 一旦被改写/重命名/删除即可几乎确认勒索,立即硬拦截 + 结束进程树。
        DeployCanaries();

        // 加载持久化设置(若有),覆盖默认值
        var saved = await _settingsStore.LoadAsync(stoppingToken);
        if (saved is not null)
        {
            saved.EventSource = _settings.EventSource; // 基础事件源以实际运行为准
            // AI 配置:持久化值为空时回退到 appsettings 默认(兼容旧版本无 AI 字段的设置文件)
            if (string.IsNullOrWhiteSpace(saved.AiBaseUrl)) saved.AiBaseUrl = _settings.AiBaseUrl;
            if (string.IsNullOrWhiteSpace(saved.AiApiKey)) saved.AiApiKey = _settings.AiApiKey;
            if (string.IsNullOrWhiteSpace(saved.AiModel)) saved.AiModel = _settings.AiModel;
            // 新增信誉源:旧版持久化设置不含 ThreatBook 字段(反序列化为 false),
            // 用 appsettings 的开关兜底开启,避免被旧设置覆盖关闭。
            saved.ThreatBookEnabled = saved.ThreatBookEnabled || _settings.ThreatBookEnabled;
            saved.MetaDefenderEnabled = saved.MetaDefenderEnabled || _settings.MetaDefenderEnabled;
            _settings = saved;
        }
        ApplySettings();

        // 载入持久化的行为基线画像(跨重启长期积累,提升偏离检测准确度、降低误报)。
        try
        {
            var baselineSnap = await _baselineStore.LoadAsync(stoppingToken);
            if (baselineSnap is not null)
            {
                _engine.Baseline.Import(baselineSnap);
                _logger.LogInformation("已载入行为基线画像:{n} 个程序。",
                    baselineSnap.Programs?.Count ?? 0);
            }
        }
        catch (Exception ex) { _logger.LogDebug(ex, "载入行为基线画像失败(忽略,重新学习)。"); }

        // 周期性落盘行为基线画像(防止异常退出丢失长期积累)。后台进行,失败不影响防护。
        _ = Task.Run(async () =>
        {
            try
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromMinutes(10), stoppingToken);
                    await _baselineStore.SaveAsync(_engine.Baseline.Export(), stoppingToken);
                }
            }
            catch (OperationCanceledException) { /* 正常停止 */ }
            catch (Exception ex) { _logger.LogDebug(ex, "周期保存行为基线画像异常(忽略)。"); }
        }, stoppingToken);


        // 按持久化设置应用内核驱动开关(默认关闭)
        ApplyKernelSwitch(_settings.KernelDriverEnabled);

        // 绑定规则管理回调(UI 通过 IPC 查询/删除/新增规则)
        _ipc.RulesRequested = () => _engine.GetRules();
        _ipc.RuleDeleteRequested = id =>
        {
            if (_engine.RemoveRule(id))
                _ = _store.SaveAsync(_engine.GetRules(), CancellationToken.None);
        };
        _ipc.RuleAddRequested = payload =>
        {
            // 智能解析 UI/AI 传入的主体字符串,避免「只能精确完整路径才命中」导致规则形同虚设:
            //  - 含通配符(* ?)         -> 作为 ActorPattern(通配匹配)
            //  - 带盘符/UNC 的完整路径   -> 作为 ActorPath(精确匹配)
            //  - 裸文件名(如 wscript.exe)-> 归一为 "*\<名>" 通配,匹配任意目录下的同名进程
            var actor = payload.ActorPath?.Trim();
            string? actorPath = null, actorPattern = null;
            if (!string.IsNullOrWhiteSpace(actor))
            {
                bool hasWildcard = actor.Contains('*') || actor.Contains('?');
                bool rootedFullPath = actor.Contains(":\\") || actor.StartsWith("\\\\");
                if (hasWildcard) actorPattern = actor;
                else if (rootedFullPath) actorPath = actor;
                else actorPattern = "*\\" + actor;
            }

            var rule = new DefenseRule
            {
                ActorPath = actorPath,
                ActorPattern = actorPattern,
                Type = payload.Type,
                TargetPattern = string.IsNullOrWhiteSpace(payload.TargetPattern) ? null : payload.TargetPattern.Trim(),
                Action = payload.Action
            };
            _engine.AddRule(rule);
            _ = _store.SaveAsync(_engine.GetRules(), CancellationToken.None);
            _logger.LogInformation("已新增规则:{actor} => {action}",
                actorPath ?? actorPattern ?? "(任意)", rule.Action);
        };

        // 绑定设置读取/更新回调
        _ipc.SettingsRequested = () =>
        {
            var snapshot = _settings.Clone();
            // 填充只读的内核/事件源状态
            if (_eventSource is EventSourceCoordinator coord)
            {
#pragma warning disable CA1416
                snapshot.EventSource = coord.BaseSourceName;
                if (snapshot.KernelDriverEnabled)
                {
                    snapshot.KernelConnected = coord.KernelConnected;
                    if (coord.KernelConnected)
                    {
                        snapshot.KernelStatus = "内核驱动已连接 · 可拦截";
                    }
                    else if (coord.KernelAttachFailed)
                    {
                        // 已尝试连接但失败(驱动未加载 / 被系统代码完整性策略 WDAC 拦截 /
                        // 测试签名缺失等环境限制)。这不是软件故障,继续以用户态观测稳定工作,
                        // 故上报为「降级」而非红色错误,避免一直显示"未连接驱动"误导用户。
                        snapshot.KernelStatus = "内核驱动不可用 · 已自动降级为用户态观测(WMI)";
                    }
                    else
                    {
                        // 尚在连接中(刚开启,还没出结果)
                        snapshot.KernelStatus = "内核驱动启用中 · 正在连接 Bulwark.sys…";
                    }
                }
                else
                {
                    snapshot.KernelConnected = false;
                    snapshot.KernelStatus = string.Equals(coord.BaseSourceName, "Simulated", StringComparison.OrdinalIgnoreCase)
                        ? "内核驱动未启用 · 演示模式(模拟事件)"
                        : "内核驱动未启用 · 用户态监控(WMI)";
                }
#pragma warning restore CA1416
            }
            else
            {
                snapshot.KernelConnected = false;
                snapshot.KernelStatus = "演示模式(模拟事件)";
            }
            return snapshot;
        };
        _ipc.SettingsUpdated = updated =>
        {
            updated.EventSource = _settings.EventSource; // 只读字段保持不变
            bool kernelToggled = updated.KernelDriverEnabled != _settings.KernelDriverEnabled;
            _settings = updated;
            ApplySettings();
            if (kernelToggled)
                ApplyKernelSwitch(_settings.KernelDriverEnabled);
            _ = _settingsStore.SaveAsync(_settings, CancellationToken.None);
            _logger.LogInformation("设置已更新:总开关={on} 默认动作={da} 内核驱动={k}",
                _settings.ProtectionEnabled, _settings.DefaultBlock ? "Block" : "Allow",
                _settings.KernelDriverEnabled ? "开" : "关");
        };

        // 文件信任中心:列表 / 新增 / 移除。信任条目本质是一条精确锁定主体文件的 Allow 规则。
        _ipc.TrustListRequested = () =>
            _engine.GetRules().Where(r => r.IsTrustEntry).ToArray();
        _ipc.TrustAddRequested = payload =>
        {
            var path = payload.ActorPath?.Trim();
            if (string.IsNullOrWhiteSpace(path)) return;

            // 去重:同一文件已信任则不重复添加
            bool exists = _engine.GetRules().Any(r =>
                r.IsTrustEntry &&
                string.Equals(r.ActorPath, path, StringComparison.OrdinalIgnoreCase));
            if (exists)
            {
                _logger.LogInformation("文件已在信任列表中,跳过:{path}", path);
                return;
            }

            var rule = DefenseRule.CreateTrust(path, payload.Note);
            _engine.AddRule(rule);
            _ = _store.SaveAsync(_engine.GetRules(), CancellationToken.None);
            _logger.LogInformation("已加入文件信任:{path}", path);
        };
        _ipc.TrustRemoveRequested = id =>
        {
            if (_engine.RemoveRule(id))
            {
                _ = _store.SaveAsync(_engine.GetRules(), CancellationToken.None);
                _logger.LogInformation("已移除文件信任:{id}", id);
            }
        };

        // VirusTotal 请求处理(测试连接 / 手动查询文件信誉)。
        _ipc.VtRequested = async req =>
        {
            switch (req.Kind)
            {
                case VtRequestKind.TestConnection:
                {
                    var (ok, message) = await _reputation.TestConnectionAsync(req.Source, CancellationToken.None);
                    return new VtResponsePayload { Success = ok, Message = message };
                }
                case VtRequestKind.QueryFile:
                {
                    var path = req.FilePath;
                    if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                        return new VtResponsePayload { Success = false, Message = "文件不存在或路径无效" };

                    string? hash = OperatingSystem.IsWindows()
                        ? ProcessInspector.TryComputeSha256(path)
                        : null;
                    if (string.IsNullOrEmpty(hash))
                        return new VtResponsePayload { Success = false, Message = "无法计算文件哈希" };

                    var rep = await _reputation.QueryNowAsync(hash, CancellationToken.None);
                    if (rep.Verdict == ReputationVerdict.Unknown)
                        return new VtResponsePayload
                        {
                            Success = true,
                            Message = "VirusTotal 未收录该文件(或查询不可用)",
                            Reputation = rep
                        };

                    return new VtResponsePayload
                    {
                        Success = true,
                        Message = $"{rep.Verdict}({rep.Malicious}/{rep.TotalEngines})",
                        Reputation = rep
                    };
                }
                default:
                    return new VtResponsePayload { Success = false, Message = "未知请求类型" };
            }
        };

        // VT 扫描历史:UI 打开「VT 查询记录」视图时请求完整历史。
        _ipc.VtHistoryRequested = () =>
            new VtHistoryResponsePayload { Records = _vtHistory.GetAll() };

        // 自我保护:UI 连接时把其 PID 加入内核受保护进程列表
        _ipc.UiProcessConnected = pid =>
        {
#pragma warning disable CA1416 // EventSourceCoordinator 仅在 Windows 创建,此处安全
            (_eventSource as EventSourceCoordinator)?.AddProtectedUiPid(pid);
#pragma warning restore CA1416
        };

        // 手动强制隔离(清理报告里「重试隔离」):用户明确要求,绕过落地区/签名限制直接隔离。
        _ipc.ManualQuarantineRequested = async path =>
        {
            if (_remediator is null || !OperatingSystem.IsWindows())
                return (false, "当前环境不支持隔离");
            return await _remediator.ForceQuarantineAsync(path, CancellationToken.None);
        };

        // 隔离区管理:列出 / 还原 / 删除。委托给 QuarantineManager(异步)。
        _ipc.QuarantineListRequested = async () =>
        {
            var items = await _quarantine.ListAsync(CancellationToken.None);
            return new QuarantineListResponsePayload
            {
                Items = items.Select(x => new QuarantineItemPayload
                {
                    Id = x.Id,
                    OriginalPath = x.OriginalPath,
                    FileName = x.FileName,
                    QuarantinedUtc = x.QuarantinedUtc,
                    Size = x.Size,
                    Sha256 = x.Sha256,
                    Reason = x.Reason,
                    ActorPid = x.ActorPid
                }).ToList()
            };
        };
        _ipc.QuarantineRestoreRequested = async id =>
        {
            bool ok = await _quarantine.RestoreAsync(id, CancellationToken.None);
            if (ok) _logger.LogWarning("用户从隔离区还原了条目 {id}。", id);
            return new QuarantineActionResultPayload
            {
                Id = id,
                Success = ok,
                Message = ok ? "已还原到原始位置" : "还原失败(条目不存在或文件被占用)"
            };
        };
        _ipc.QuarantineDeleteRequested = async id =>
        {
            bool ok = await _quarantine.DeleteAsync(id, CancellationToken.None);
            if (ok) _logger.LogInformation("用户永久删除了隔离条目 {id}。", id);
            return new QuarantineActionResultPayload
            {
                Id = id,
                Success = ok,
                Message = ok ? "已永久删除" : "删除失败(条目不存在)"
            };
        };

        // 启动 IPC 服务端
        _ipc.Start(stoppingToken);

        // 启动信誉查询后台 worker,并绑定"恶意确认"补偿处置:
        // 后台 VT 查询确认某文件恶意时,推送告警并结束仍在运行的进程,
        // 同时固化一条精确 Block 规则,使该文件后续直接被拦截。
        _reputation.MaliciousConfirmed += OnMaliciousConfirmed;
        _reputation.Start(stoppingToken);

        // 消费事件
        await foreach (var e in _eventSource.ReadEventsAsync(stoppingToken))
        {
            // 背压:在途处理任务达到上限时,等待空出槽位再继续消费(事件在事件源通道里缓冲,不丢)。
            try { await _eventConcurrency.WaitAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }

            // 在独立任务中处理,避免单个慢裁决阻塞事件流;完成后释放并发槽位。
            _ = HandleEventGuardedAsync(e, stoppingToken);
        }
    }

    /// <summary>在并发闸门内处理单个事件,无论成功失败都释放槽位。</summary>
    private async Task HandleEventGuardedAsync(SecurityEvent e, CancellationToken token)
    {
        try
        {
            await HandleEventAsync(e, token);
        }
        finally
        {
            _eventConcurrency.Release();
        }
    }

    /// <summary>
    /// 注册本软件自身目录到引擎白名单。取服务自身所在目录,并推断同级的 UI 目录,
    /// 使本软件所有组件发起的行为被无条件放行(绝不自我拦截/弹窗)。
    /// </summary>
    private void RegisterSelfDirectories()
    {
        try
        {
            // 服务自身目录(...\Bulwark.Service\bin\Debug\net8.0\)
            var svcDir = AppContext.BaseDirectory;
            _engine.AddSelfDirectory(svcDir);
            _logger.LogInformation("自身白名单目录:{dir}", svcDir);

            // 向上回溯到解决方案/安装根,推断同级 UI 目录并加入。
            // 部署形态多样,这里尽量覆盖常见 bin 布局。
            var dir = new System.IO.DirectoryInfo(svcDir);
            for (int i = 0; i < 6 && dir is not null; i++)
            {
                // 同级是否存在 Bulwark.UI 目录
                var uiCandidate = System.IO.Path.Combine(dir.FullName, "Bulwark.UI");
                if (System.IO.Directory.Exists(uiCandidate))
                {
                    _engine.AddSelfDirectory(uiCandidate);
                    _logger.LogInformation("自身白名单目录(UI):{dir}", uiCandidate);
                }
                // 若当前目录本身就是某个 bin 输出,父级根目录也纳入(覆盖并列发布的 exe)
                dir = dir.Parent;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "注册自身白名单目录失败(不影响核心功能)。");
        }
    }

    /// <summary>
    /// 部署勒索蜜罐诱饵文件并注册到勒索行为监视器。
    ///
    /// 思路:勒索软件通常按目录递归枚举并加密所有"文档样"文件。我们在常见目标目录里
    /// 投放一批名字排序靠前(以 '~'/'!' 前缀,使其在枚举时较早被处理)、看起来像普通文档的
    /// 诱饵文件。正常程序不会去改写这些莫名其妙的文件;一旦它们被改写/重命名/删除,
    /// 几乎可确认是无差别批量加密 —— 监视器据此立即判定 canaryHit 并硬拦截。
    ///
    /// 诱饵路径同时注册到内核「受保护路径」与监视器的 canary 列表:
    /// 触碰会被驱动文件遥测捕获,喂给监视器命中 canary -> Block -> 结束进程树。
    /// </summary>
    private void DeployCanaries()
    {
        try
        {
            // 候选投放目录:用户文档/桌面/图片,以及各盘根下的常见数据目录。
            var dirs = new List<string>();
            void AddDir(string? d)
            {
                if (!string.IsNullOrWhiteSpace(d)) dirs.Add(d!);
            }
            AddDir(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            AddDir(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
            AddDir(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures));

            // 诱饵文件名:'~' 前缀使其在多数字母序枚举中靠前(勒索更早碰到),
            // 扩展名取常见文档类型,内容为占位文本。
            string[] names =
            {
                "~$bulwark_canary_donotdelete.docx",
                "~$bulwark_canary_donotdelete.xlsx",
            };

            int deployed = 0;
            foreach (var dir in dirs.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!System.IO.Directory.Exists(dir)) continue;
                foreach (var name in names)
                {
                    var full = System.IO.Path.Combine(dir, name);
                    try
                    {
                        if (!System.IO.File.Exists(full))
                        {
                            System.IO.File.WriteAllText(full,
                                "This file is a security decoy used by Bulwark to detect ransomware. " +
                                "Do not modify or delete.");
                            try
                            {
                                // 隐藏 + 系统属性,降低对用户的可见干扰(不影响检测)。
                                System.IO.File.SetAttributes(full,
                                    System.IO.FileAttributes.Hidden | System.IO.FileAttributes.System);
                            }
                            catch { /* 属性设置失败不致命 */ }
                        }
                        // 注册到监视器:触碰即 canaryHit。
                        _engine.Ransomware.AddCanaryFile(full);
                        deployed++;
                    }
                    catch (Exception exFile)
                    {
                        _logger.LogDebug(exFile, "部署诱饵文件失败:{path}", full);
                    }
                }
            }

            if (deployed > 0)
                _logger.LogInformation("已部署并注册 {n} 个勒索蜜罐诱饵文件。", deployed);
            else
                _logger.LogInformation("未部署诱饵文件(目标目录不可用)。");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "部署勒索蜜罐诱饵失败(不影响核心功能)。");
        }
    }

    /// <summary>把当前设置应用到规则引擎与超时。</summary>
    private void ApplySettings()
    {
        _engine.TrustSignedActors = _settings.TrustSignedActors;
        _engine.DefaultAction = _settings.DefaultBlock ? VerdictAction.Block : VerdictAction.Allow;
        _engine.EnableBaseline = _settings.BehaviorBaselineEnabled;
        _promptTimeout = TimeSpan.FromSeconds(Math.Max(5, _settings.PromptTimeoutSeconds));
        // 把各威胁情报源的运行时开关下发给聚合器。
        _reputation.SetRuntimeEnabled(
            _settings.VirusTotalEnabled, _settings.MalwareBazaarEnabled, _settings.OtxEnabled, _settings.ThreatBookEnabled, _settings.MetaDefenderEnabled);

        // 用户态持续行为监控开关(自启动持久化 + 勒索蜜罐)下发给协调器。
#pragma warning disable CA1416 // EventSourceCoordinator 仅在 Windows 创建
        (_eventSource as EventSourceCoordinator)?.ConfigureBehaviorMonitor(
            _settings.UserModeBehaviorMonitor, _settings.RansomwareCanaryEnabled);
#pragma warning restore CA1416
    }

    /// <summary>服务停止时:卸载内核驱动,实现"软件退出即卸载驱动,不残留常驻"。</summary>
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        // 持久化行为基线画像,使下次启动延续已学习的程序行为(避免重新进入学习期)。
        try
        {
            await _baselineStore.SaveAsync(_engine.Baseline.Export(), cancellationToken);
            _logger.LogInformation("已保存行为基线画像。");
        }
        catch (Exception ex) { _logger.LogDebug(ex, "保存行为基线画像失败(忽略)。"); }

        try
        {
            if (OperatingSystem.IsWindows() && _settings.KernelDriverEnabled)
            {
#pragma warning disable CA1416
                (_eventSource as EventSourceCoordinator)?.SetKernelEnabled(false);
                Monitoring.DriverService.TryStop(_logger);
#pragma warning restore CA1416
                _logger.LogInformation("服务停止,已卸载内核驱动。");
            }
        }
        catch (Exception ex) { _logger.LogDebug(ex, "停止时卸载驱动异常(忽略)。"); }

        await base.StopAsync(cancellationToken);
    }

    /// <summary>按开关启停内核驱动事件源(仅协调器支持)。</summary>
    private void ApplyKernelSwitch(bool enabled)
    {
#pragma warning disable CA1416 // EventSourceCoordinator 仅在 Windows 创建
        if (_eventSource is EventSourceCoordinator coord)
        {
            if (enabled && OperatingSystem.IsWindows())
            {
                // 驱动已设为按需启动:启用内核时由本程序主动加载 Bulwark.sys,
                // 实现"打开软件才加载驱动"。加载失败不致命(协调器会降级为用户态观测)。
                if (Monitoring.DriverService.TryStart(_logger))
                    _logger.LogInformation("内核驱动已按需加载(Bulwark.sys)。");
                else
                    _logger.LogWarning("内核驱动加载失败,将降级为用户态观测(WMI)。");
            }

            coord.SetKernelEnabled(enabled);
            _logger.LogInformation("内核驱动事件源已{state}。", enabled ? "启用" : "停用");

            // 停用内核时卸载驱动,实现"软件退出/关闭内核即卸载驱动"。
            if (!enabled && OperatingSystem.IsWindows())
                Monitoring.DriverService.TryStop(_logger);
        }
        else if (enabled)
        {
            _logger.LogWarning("当前运行环境不支持内核驱动事件源,开关被忽略。");
        }
#pragma warning restore CA1416
    }

    /// <summary>
    /// 增量合并新版内置规则,并就地升级已存在的同名内置规则。
    ///
    /// 历史问题:旧实现仅按 Note 去重「新增」缺失的内置规则,但对「Note 相同、属性已变更」的
    /// 内置规则(如新增豁免标记 ExemptTrustedOsComponent、改用 RequireUnsigned、调整 Action)
    /// 不做更新 —— 导致升级代码后,持久化的旧规则仍生效,新逻辑形同虚设
    /// (典型:RuntimeBroker 改 UAC 的豁免、QQ 自注入的未签名约束)。
    ///
    /// 现策略:
    ///  · 内置规则(Note 以 [内置] 开头)以代码为准:同 Note 的已存内置规则,用新版关键属性覆盖;
    ///  · 用户/信任规则([信任] 或自定义 Note)不动,完全保留;
    ///  · 代码新增、库中缺失的内置规则,追加。
    /// 返回「新增 + 升级」的条数。
    /// </summary>
    private static int MergeBuiltInRules(List<DefenseRule> existing)
    {
        // 按 Note 索引已存规则(仅内置规则参与就地升级)。
        var byNote = new Dictionary<string, DefenseRule>(StringComparer.Ordinal);
        foreach (var r in existing)
            if (!string.IsNullOrEmpty(r.Note))
                byNote[r.Note!] = r;

        int changed = 0;
        foreach (var rule in DefaultRules.Build())
        {
            if (string.IsNullOrEmpty(rule.Note)) continue;

            if (!byNote.TryGetValue(rule.Note!, out var cur))
            {
                // 库中缺失 -> 追加新内置规则
                existing.Add(rule);
                byNote[rule.Note!] = rule;
                changed++;
                continue;
            }

            // 已存在同 Note 的内置规则:若关键属性与新版不一致,就地升级(以代码为准)。
            // 仅升级内置规则,绝不动用户自定义/信任规则(它们的 Note 不会与内置规则撞名)。
            if (!cur.IsTrustEntry && RuleNeedsUpgrade(cur, rule))
            {
                cur.Action = rule.Action;
                cur.Type = rule.Type;
                cur.TargetPattern = rule.TargetPattern;
                cur.ActorPattern = rule.ActorPattern;
                cur.CommandLinePattern = rule.CommandLinePattern;
                cur.ParentPattern = rule.ParentPattern;
                cur.RequireUnsigned = rule.RequireUnsigned;
                cur.ExemptTrustedOsComponent = rule.ExemptTrustedOsComponent;
                cur.HardOverride = rule.HardOverride;
                changed++;
            }
        }
        return changed;
    }

    /// <summary>判断已存内置规则是否需要按新版定义就地升级(关键匹配/动作/豁免属性有差异)。</summary>
    private static bool RuleNeedsUpgrade(DefenseRule cur, DefenseRule latest)
        => cur.Action != latest.Action
        || cur.Type != latest.Type
        || cur.RequireUnsigned != latest.RequireUnsigned
        || cur.ExemptTrustedOsComponent != latest.ExemptTrustedOsComponent
        || cur.HardOverride != latest.HardOverride
        || !string.Equals(cur.TargetPattern, latest.TargetPattern, StringComparison.OrdinalIgnoreCase)
        || !string.Equals(cur.ActorPattern, latest.ActorPattern, StringComparison.OrdinalIgnoreCase)
        || !string.Equals(cur.CommandLinePattern, latest.CommandLinePattern, StringComparison.OrdinalIgnoreCase)
        || !string.Equals(cur.ParentPattern, latest.ParentPattern, StringComparison.OrdinalIgnoreCase);

    /// <summary>判断某事件类型对应的防护维度是否启用。</summary>
    private bool IsDimensionEnabled(EventType type) => type switch
    {
        EventType.ProcessCreate or EventType.ProcessTerminate or EventType.RemoteThread
            or EventType.ImageLoad => _settings.ProcessProtection,
        EventType.FileWrite or EventType.FileDelete => _settings.FileProtection,
        EventType.RegistryWrite => _settings.RegistryProtection,
        EventType.SelfProtect => _settings.SelfProtection,
        EventType.NetworkConnect => _settings.NetworkProtection,
        _ => true
    };

    /// <summary>
    /// 判断事件是否为「用户双击启动的应用」:进程创建事件,且父进程为 explorer.exe。
    /// 这是 Windows 上用户经资源管理器/桌面双击启动程序的标准特征 —— 由 explorer.exe
    /// 作为外壳拉起目标进程。借此把 AI 病毒扫描限定在用户主动启动这一行为上,
    /// 不打扰后台服务/子进程链,避免噪音与无谓的大模型调用。
    /// </summary>
    private static bool IsDoubleClickLaunch(SecurityEvent e)
    {
        if (e.Type != EventType.ProcessCreate) return false;
        if (string.IsNullOrEmpty(e.ParentPath)) return false;
        string parent;
        try { parent = System.IO.Path.GetFileName(e.ParentPath); }
        catch { return false; }
        return string.Equals(parent, "explorer.exe", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 判断事件是否为「释放器(dropper)派生的可疑载荷」:进程创建事件,且主体
    /// 「未签名 + 本机首见 + 从可疑落地目录(Temp/AppData/ProgramData/Downloads/Public 等)运行」。
    ///
    /// 场景:用户双击的安装包 A 看似正常(甚至带签名)被放行,但它在运行中途把真正的
    /// 病毒 B 释放到临时目录再拉起。此时 B 的父进程是 A(而非 explorer.exe),
    /// <see cref="IsDoubleClickLaunch"/> 不会命中,B 便绕过了双击 AI 扫描。
    /// 这里用「未签名 + 首见 + 可疑目录」三重软信号叠加来识别这类新释放的载荷,
    /// 触发对 B 的 AI 病毒研判。注意:这只是触发"分析",并不直接拦截 —— 仍 fail-open,
    /// 只有 AI 明确判定恶意才升级为 Block,符合低误报原则。
    /// </summary>
    private static bool IsDropperSpawnedPayload(SecurityEvent e)
    {
        if (e.Type != EventType.ProcessCreate) return false;
        if (e.ActorSigned) return false;          // 带可信签名的不在此列(降误报)
        if (!e.IsFirstSeen) return false;          // 本机已见过的常规程序不重复打扰
        return ThreatDetector.IsSuspiciousDropDir(e.ActorPath);
    }

    /// <summary>
    /// 是否应对该进程创建事件触发 AI 病毒扫描:
    /// 用户双击启动的程序,或释放器派生的新可疑载荷(堵 dropper 中途释放病毒的盲区)。
    ///
    /// **排除规则(降误报核心)**:
    ///  1) 主体位于 Windows 系统目录(\Windows\System32 等)且带签名 —— 系统组件本身不送 AI;
    ///  2) 主体进程名 = 父进程名(自身派生子进程,如 explorer 拉 explorer 子窗口、
    ///     浏览器多进程架构)—— 这并非用户「双击新程序」,送 AI 易被误判为恶意;
    ///  3) 主体是已知系统/安全软件(由 <see cref="TrustPolicy.IsTrustedSecurityProduct"/>
    ///     和强可信发行商判定)—— 不重复送 AI。
    /// </summary>
    private bool ShouldAiScan(SecurityEvent e)
    {
        // 排除自启子进程(进程名=父进程名),典型如 explorer.exe 由父 explorer 拉起新窗口、
        // chrome/edge/firefox 的多进程架构。这些不是「用户双击新程序」,送 AI 容易被
        // 误判为「系统进程无签名/路径异常」并 Block,导致桌面/浏览器被拖死。
        if (e.Type == EventType.ProcessCreate
            && !string.IsNullOrEmpty(e.ActorPath)
            && !string.IsNullOrEmpty(e.ParentPath))
        {
            try
            {
                var actorName = System.IO.Path.GetFileName(e.ActorPath);
                var parentName = System.IO.Path.GetFileName(e.ParentPath);
                if (!string.IsNullOrEmpty(actorName)
                    && string.Equals(actorName, parentName, StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            catch { /* 路径异常忽略,继续后续判定 */ }
        }

        // 排除 Windows 系统目录里的进程:系统组件本身不送 AI,避免对 explorer/dwm/svchost
        // 这类签名读取偶发失败时被误判为「未签名系统进程=可疑」。
        if (!string.IsNullOrEmpty(e.ActorPath))
        {
            var lower = e.ActorPath.ToLowerInvariant().Replace('/', '\\');
            if (lower.Contains(@"\windows\system32\")
                || lower.Contains(@"\windows\syswow64\")
                || lower.Contains(@"\windows\winsxs\")
                || System.IO.Path.GetDirectoryName(lower)?.EndsWith(@"\windows") == true)
            {
                return false;
            }
        }

        // 排除已知安全软件(双重判定:进程名+受保护安装目录)
        if (TrustPolicy.IsTrustedSecurityProduct(e, out _)) return false;

        // 排除带可信/健康签名的程序:产品原则是"可信签名主体直接放行、不打扰",
        // 对它们再做 AI 深扫既无价值又易误报(典型如酷狗等正规签名安装包被判恶意),
        // 还白白消耗大模型调用与冻结时间。此处仅在裁决已为放行时到达,跳过是安全的。
        if (TrustPolicy.IsStronglyTrusted(e, out _) || TrustPolicy.IsHealthySigned(e, out _))
            return false;

        // "有证书且明确安全"也跳过 VT 上传:只要签名健康且无任何硬恶意指标,即便本机首见 /
        // 证书较新,也无需把正规签名安装包整文件上传第三方(省配额、免冻结、护隐私)。
        // 仅用于跳过 VT —— 若运行中出现任何硬恶意指标,HasThreatIndicator 置真后照常研判拦截。
        if (TrustPolicy.IsCleanSigned(e, out _))
            return false;

        return IsDoubleClickLaunch(e)
            || IsDropperSpawnedPayload(e)
            || IsRecentlyDroppedExecutable(e);
    }

    /// <summary>
    /// 判断主体是否为「刚被释放到磁盘就被执行」的可执行文件:进程创建 + 未签名 +
    /// 该映像在最近时间窗内被(其他进程)写入过(见 <see cref="ProcessChainTracker.WasRecentlyWritten"/>)。
    ///
    /// 这条专门补 <see cref="IsDropperSpawnedPayload"/> 的盲区:释放器若把载荷写到
    /// 非可疑目录(如提权后写入 Program Files),按目录判定会漏过;但"写出来立即执行"
    /// 这一时序本身就是 dropper 的强特征,据此触发 AI 研判(仍 fail-open,只分析不直接拦)。
    /// </summary>
    private bool IsRecentlyDroppedExecutable(SecurityEvent e)
    {
        if (e.Type != EventType.ProcessCreate) return false;
        if (e.ActorSigned) return false; // 带可信签名的更新器/安装器写出并自启属正常,排除以降误报
        return _chain.WasRecentlyWritten(e.ActorPath, RecentDropWindow);
    }

    /// <summary>「写出即执行」关联的时间窗:释放到执行间隔通常很短,5 分钟足够覆盖且不误伤。</summary>
    private static readonly TimeSpan RecentDropWindow = TimeSpan.FromMinutes(5);

    /// <summary>VT 双击上传扫描的整体超时(上传 + 云端分析轮询)。超时按失败策略处理。</summary>
    private static readonly TimeSpan VtScanTimeout = TimeSpan.FromMinutes(5);

    /// <summary>
    /// 「未收录/无明确结论」的去重时间窗:同一文件在此窗口内已扫过(即便 VT 没结论)就不再重复扫/冻结,
    /// 避免反复双击同一未知程序时每次都重新云端查毒。过期后允许重扫(VT 之后可能已收录)。
    /// 恶意/干净等确定性结论不受此限,永久去重。
    /// </summary>
    private static readonly TimeSpan VtUnknownDedupTtl = TimeSpan.FromHours(24);

    /// <summary>
    /// 对双击启动 / 释放载荷的程序做一次 VirusTotal 上传扫描(替换原 AI 双击扫毒)。
    /// 流程:去重(已扫过的哈希复用结论)-> 挂起进程 -> 先查哈希,未收录则上传文件并轮询 ->
    ///      恶意则升级 Block(保持冻结,Enforce 结束进程树并固化哈希规则);干净/可疑放行;
    ///      未知/失败/超时按失败策略(默认 fail-open)。全程经 IPC 推送进度,驱动 UI 进度卡片
    ///      与「VT 查询记录」视图,并把每次扫描持久化以便去重与展示。
    ///
    /// 隐私说明:本路径会把文件【完整内容】上传到 VirusTotal(第三方),仅作用于「用户双击/
    /// 释放载荷」这类高价值新样本,且对已扫过的哈希不重复上传。
    /// </summary>
    private async Task<Verdict> VtScanDoubleClickAsync(SecurityEvent e, Verdict current, CancellationToken token)
    {
        bool vtAvailable = _vt.IsEnabled && _settings.VirusTotalEnabled;

        // VT 与其他情报源都不可用:无从扫描,按失败策略处理。
        if (!vtAvailable && !_settings.AnyReputationEnabled)
            return _settings.AiScanBlockOnFailure
                ? AiFailBlock(e, "病毒扫描不可用(未启用任何威胁情报源)")
                : current;

        var hash = e.ActorHash;

        // 去重:同哈希近期已扫过(确定结论永久去重;未收录/无结论在 TTL 内也去重)-> 不重复扫/不重复上传。
        if (!string.IsNullOrEmpty(hash))
        {
            var prior = _vtHistory.TryGetFinishedByHash(hash, VtUnknownDedupTtl);
            if (prior is not null)
            {
                if (prior.Outcome == VtScanOutcome.Malicious)
                {
                    e.HasThreatIndicator = true;
                    e.RiskReasons.Insert(0, $"VT 扫描:命中历史恶意结论({prior.Malicious}/{prior.TotalEngines})");
                    RememberAiMalicious(e);
                    _logger.LogWarning("VT 双击扫描:命中历史恶意记录,直接拦截:{path}", e.ActorPath);
                    return Verdict.For(e, VerdictAction.Block, VerdictSource.Heuristic);
                }
                e.RiskReasons.Insert(0, prior.Outcome == VtScanOutcome.Unknown
                    ? "VT 扫描:近期已扫描(未收录/无明确结论),按放行处理,不重复扫"
                    : "VT 扫描:近期已判定非恶意(记录命中,不重复扫)");
                return current;
            }
        }

        // 研判期间冻结目标进程(用户开启时)。
        bool suspended = _settings.AiScanSuspendDuringScan
                         && OperatingSystem.IsWindows()
                         && e.ActorPid > 0
                         && Monitoring.ProcessControl.TrySuspend(e.ActorPid);
        if (suspended)
            _logger.LogInformation("VT 扫描期间已挂起进程 pid={pid}:{path}", e.ActorPid, e.ActorPath);

        bool keepFrozen = false;

        // 扫描记录(随阶段更新并推送 UI + 持久化)。
        var record = new VtScanRecord
        {
            Id = e.Id,
            Sha256 = hash ?? string.Empty,
            FilePath = e.ActorPath ?? string.Empty,
            FileName = SafeFileName(e.ActorPath),
            Stage = VtScanStage.Queued,
            Outcome = VtScanOutcome.Pending,
            Source = "双击",
            Message = "排队等待 VirusTotal 扫描…"
        };
        PublishVtRecord(record);

        using var scanCts = CancellationTokenSource.CreateLinkedTokenSource(token);
        scanCts.CancelAfter(VtScanTimeout);

        try
        {
            FileReputation rep = new FileReputation { Sha256 = hash ?? string.Empty, Verdict = ReputationVerdict.Unknown };

            if (vtAvailable)
            {
                // 1) 优先 VirusTotal:先按哈希查询(秒级,省去对已收录文件的重复上传)。
                record.Stage = VtScanStage.Querying;
                record.Message = "正在查询 VirusTotal 是否已收录…";
                PublishVtRecord(record);

                rep = !string.IsNullOrEmpty(hash)
                    ? await _vt.QueryAsync(hash!, scanCts.Token)
                    : new FileReputation { Verdict = ReputationVerdict.Unknown };

                bool foundByHash = rep.QuerySucceeded && rep.Verdict != ReputationVerdict.Unknown;

                // 2) 未收录(404,QuerySucceeded 且 Unknown)-> 上传文件并轮询分析。
                if (!foundByHash
                    && !string.IsNullOrEmpty(e.ActorPath)
                    && System.IO.File.Exists(e.ActorPath))
                {
                    var progress = new Progress<(VtScanStage stage, int percent)>(p =>
                    {
                        record.Stage = p.stage;
                        record.Percent = p.percent;
                        record.Uploaded = true;
                        record.Message = p.stage switch
                        {
                            VtScanStage.Uploading => $"正在上传文件… {p.percent}%",
                            VtScanStage.Analyzing => "已上传,VirusTotal 云端多引擎分析中…",
                            VtScanStage.Completed => "分析完成,正在汇总结论…",
                            _ => record.Message
                        };
                        PublishVtRecord(record);
                    });

                    rep = await _vt.UploadAndScanAsync(e.ActorPath!, hash, progress, scanCts.Token);
                    record.Uploaded = true;
                }
            }

            // 2.5) VT 不可用 / 无明确结论 -> 回退查询其他已启用情报源(仅哈希查询,不上传文件)。
            //      体现"双击扫描优先用 VT,VT 缺位才动用其他源"的策略。
            bool vtConclusive = rep.QuerySucceeded && rep.Verdict != ReputationVerdict.Unknown;
            if (!vtConclusive && !string.IsNullOrEmpty(hash))
            {
                record.Stage = VtScanStage.Querying;
                record.Source = vtAvailable ? "双击·回退" : "双击·其他源";
                record.Message = vtAvailable
                    ? "VT 无明确结论,正在查询其他威胁情报源…"
                    : "VT 未启用,正在查询其他威胁情报源…";
                PublishVtRecord(record);

                var fallback = await _reputation.QueryFallbackExcludingVtAsync(hash!, scanCts.Token);
                if (fallback.QuerySucceeded && fallback.Verdict != ReputationVerdict.Unknown)
                    rep = fallback;
            }

            // 3) 落最终结论。
            FinalizeVtRecord(record, rep);

            if (rep.Verdict == ReputationVerdict.Malicious)
            {
                e.HasThreatIndicator = true;
                e.RiskReasons.Insert(0,
                    $"病毒扫描:判定为恶意({rep.Malicious}/{rep.TotalEngines}"
                    + (string.IsNullOrEmpty(rep.ThreatLabel) ? ")" : $", {rep.ThreatLabel})"));
                _logger.LogWarning("双击病毒扫描判定恶意,阻止并结束:{path}", e.ActorPath);
                RememberAiMalicious(e);
                keepFrozen = true;
                return Verdict.For(e, VerdictAction.Block, VerdictSource.Heuristic);
            }

            if (rep.QuerySucceeded && rep.Verdict != ReputationVerdict.Unknown)
            {
                // 干净 / 可疑(未达恶意阈值)-> 放行。
                e.RiskReasons.Insert(0, $"病毒扫描:未达恶意阈值({rep.Malicious}/{rep.TotalEngines}),放行");
                return current;
            }

            // 未知 / 失败 / 超时 -> 按失败策略。
            if (_settings.AiScanBlockOnFailure)
            {
                keepFrozen = true;
                return AiFailBlock(e, "病毒扫描无明确结论 / 超时(严格模式拦截)");
            }
            return current; // fail-open
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "VT 双击扫描异常:{path}", e.ActorPath);
            record.Stage = VtScanStage.Error;
            record.Outcome = VtScanOutcome.Error;
            record.Message = "扫描异常:" + ex.Message;
            PublishVtRecord(record);
            return _settings.AiScanBlockOnFailure
                ? AiFailBlock(e, "VT 扫描异常(严格模式拦截)")
                : current;
        }
        finally
        {
            if (suspended && !keepFrozen)
                Monitoring.ProcessControl.TryResume(e.ActorPid);
        }
    }

    /// <summary>把 VT 信誉结论落到扫描记录(终态),用于推送与持久化。</summary>
    private void FinalizeVtRecord(VtScanRecord record, FileReputation rep)
    {
        record.Malicious = rep.Malicious;
        record.TotalEngines = rep.TotalEngines;
        record.ThreatLabel = rep.ThreatLabel;
        if (!string.IsNullOrEmpty(rep.Sha256)) record.Sha256 = rep.Sha256;

        if (!rep.QuerySucceeded)
        {
            record.Stage = VtScanStage.Error;
            record.Outcome = VtScanOutcome.Error;
            record.Message = "VT 查询失败 / 超时(已按放行处理)";
        }
        else
        {
            record.Stage = VtScanStage.Completed;
            record.Outcome = rep.Verdict switch
            {
                ReputationVerdict.Malicious => VtScanOutcome.Malicious,
                ReputationVerdict.Suspicious => VtScanOutcome.Suspicious,
                ReputationVerdict.Clean => VtScanOutcome.Clean,
                _ => VtScanOutcome.Unknown
            };
            record.Message = record.Outcome switch
            {
                VtScanOutcome.Malicious => $"恶意 · {rep.Malicious}/{rep.TotalEngines}"
                    + (string.IsNullOrEmpty(rep.ThreatLabel) ? "" : $" · {rep.ThreatLabel}"),
                VtScanOutcome.Suspicious => $"可疑 · {rep.Malicious}/{rep.TotalEngines}",
                VtScanOutcome.Clean => $"干净 · 0/{rep.TotalEngines}",
                _ => "未收录 / 无明确结论"
            };
        }
        PublishVtRecord(record);
    }

    /// <summary>推送一条 VT 扫描记录到 UI 并写入历史存储(去重 + 持久展示)。</summary>
    private void PublishVtRecord(VtScanRecord record)
    {
        record.TimestampUtc = DateTime.UtcNow;
        _vtHistory.Upsert(record);
        _ = _ipc.PushVtScanUpdateAsync(record.Clone(), CancellationToken.None);
    }

    private static string SafeFileName(string? path)
    {
        if (string.IsNullOrEmpty(path)) return "(未知)";
        try { return System.IO.Path.GetFileName(path); }
        catch { return path!; }
    }

    /// <summary>
    /// 灰区 VT 研判:当规则引擎判定为「询问」(Ask)时,先用 VirusTotal(优先)+ 其他情报源(回退)
    /// 对主体文件做一次研判,再决定是否要弹窗。本方法替换原「灰区 AI 研判」,统一走 VT 文件上传
    /// 分析,不再调用大模型、也不再弹出「AI 病毒研判」窗;进度同样经 IPC 推送到「VT 查询记录」视图。
    ///
    /// 折叠规则(与原灰区策略一致,严守低误报 + 不打扰 + 情报源不可用绝不影响实时防护):
    ///   1) VT/情报源 无明确结论 / 失败 / 超时        -> 维持原 Ask(fail-open,退回正常弹窗);
    ///   2) 判定恶意                                  -> 升格为 Block(灰区已隐含可疑,与之互证),并按哈希记忆;
    ///   3) 非恶意 且 本事件【无硬恶意指标】           -> 降级为 Allow(减少打扰);
    ///   4) 非恶意 但 本事件【存在硬恶意指标】         -> 维持 Ask(情报单独不得压制硬指标,仍交用户裁决)。
    /// 不挂起进程(灰区事件多为已运行进程的行为,挂起风险高且无必要)。
    /// </summary>
    private async Task<Verdict> VtGrayZoneConsultAsync(SecurityEvent e, Verdict current, CancellationToken token)
    {
        bool vtAvailable = _vt.IsEnabled && _settings.VirusTotalEnabled;

        // VT 与其他情报源都不可用:无从研判,fail-open 维持原 Ask(退回正常弹窗)。
        if (!vtAvailable && !_settings.AnyReputationEnabled)
            return current;

        // 强可信 / 健康签名主体不打扰也不送扫描(灰区一般不会是这类,双重保险)。
        if (TrustPolicy.IsStronglyTrusted(e, out _) || TrustPolicy.IsHealthySigned(e, out _))
            return current;

        // 有证书且明确安全(签名健康 + 无硬恶意指标)同样不送 VT,维持原裁决。
        if (TrustPolicy.IsCleanSigned(e, out _))
            return current;

        var hash = e.ActorHash;

        // 去重:同哈希近期已扫过(确定结论永久去重;未收录/无结论在 TTL 内也去重)-> 不重复扫 / 不重复上传。
        if (!string.IsNullOrEmpty(hash))
        {
            var prior = _vtHistory.TryGetFinishedByHash(hash, VtUnknownDedupTtl);
            if (prior is not null)
            {
                if (prior.Outcome == VtScanOutcome.Malicious)
                    return GrayZoneBlock(e, $"VT 灰区研判:命中历史恶意结论({prior.Malicious}/{prior.TotalEngines})");
                return GrayZoneAllowIfSoft(e, current, prior.Outcome == VtScanOutcome.Unknown
                    ? "VT 灰区研判:近期已扫描(未收录/无明确结论),不重复扫"
                    : "VT 灰区研判:近期已判定非恶意(记录命中)");
            }
        }

        // 扫描记录(随阶段更新并推送 UI + 持久化)。
        var record = new VtScanRecord
        {
            Id = e.Id,
            Sha256 = hash ?? string.Empty,
            FilePath = e.ActorPath ?? string.Empty,
            FileName = SafeFileName(e.ActorPath),
            Stage = VtScanStage.Queued,
            Outcome = VtScanOutcome.Pending,
            Source = "灰区",
            Message = "排队等待 VirusTotal 研判…"
        };
        PublishVtRecord(record);

        using var scanCts = CancellationTokenSource.CreateLinkedTokenSource(token);
        scanCts.CancelAfter(VtScanTimeout);

        try
        {
            FileReputation rep = new FileReputation { Sha256 = hash ?? string.Empty, Verdict = ReputationVerdict.Unknown };

            if (vtAvailable)
            {
                // 1) 优先 VirusTotal:先按哈希查询(秒级,省去对已收录文件的重复上传)。
                record.Stage = VtScanStage.Querying;
                record.Message = "正在查询 VirusTotal 是否已收录…";
                PublishVtRecord(record);

                rep = !string.IsNullOrEmpty(hash)
                    ? await _vt.QueryAsync(hash!, scanCts.Token)
                    : new FileReputation { Verdict = ReputationVerdict.Unknown };

                bool foundByHash = rep.QuerySucceeded && rep.Verdict != ReputationVerdict.Unknown;

                // 2) 未收录 -> 上传文件并轮询分析。
                if (!foundByHash
                    && !string.IsNullOrEmpty(e.ActorPath)
                    && System.IO.File.Exists(e.ActorPath))
                {
                    var progress = new Progress<(VtScanStage stage, int percent)>(p =>
                    {
                        record.Stage = p.stage;
                        record.Percent = p.percent;
                        record.Uploaded = true;
                        record.Message = p.stage switch
                        {
                            VtScanStage.Uploading => $"正在上传文件… {p.percent}%",
                            VtScanStage.Analyzing => "已上传,VirusTotal 云端多引擎分析中…",
                            VtScanStage.Completed => "分析完成,正在汇总结论…",
                            _ => record.Message
                        };
                        PublishVtRecord(record);
                    });

                    rep = await _vt.UploadAndScanAsync(e.ActorPath!, hash, progress, scanCts.Token);
                    record.Uploaded = true;
                }
            }

            // 2.5) VT 不可用 / 无明确结论 -> 回退查询其他已启用情报源(仅哈希查询,不上传文件)。
            bool vtConclusive = rep.QuerySucceeded && rep.Verdict != ReputationVerdict.Unknown;
            if (!vtConclusive && !string.IsNullOrEmpty(hash))
            {
                record.Stage = VtScanStage.Querying;
                record.Source = vtAvailable ? "灰区·回退" : "灰区·其他源";
                record.Message = vtAvailable
                    ? "VT 无明确结论,正在查询其他威胁情报源…"
                    : "VT 未启用,正在查询其他威胁情报源…";
                PublishVtRecord(record);

                var fallback = await _reputation.QueryFallbackExcludingVtAsync(hash!, scanCts.Token);
                if (fallback.QuerySucceeded && fallback.Verdict != ReputationVerdict.Unknown)
                    rep = fallback;
            }

            // 3) 落最终结论并折叠回灰区裁决。
            FinalizeVtRecord(record, rep);

            if (rep.Verdict == ReputationVerdict.Malicious)
                return GrayZoneBlock(e,
                    $"VT 灰区研判:判定为恶意({rep.Malicious}/{rep.TotalEngines}"
                    + (string.IsNullOrEmpty(rep.ThreatLabel) ? ")" : $", {rep.ThreatLabel})"));

            if (rep.QuerySucceeded && rep.Verdict != ReputationVerdict.Unknown)
                return GrayZoneAllowIfSoft(e, current,
                    $"VT 灰区研判:未达恶意阈值({rep.Malicious}/{rep.TotalEngines})");

            // 未知 / 失败 / 超时 -> fail-open,维持原 Ask(退回正常弹窗)。
            e.AddEvidence("VtGrayZone", EvidenceKind.Info, "VT 灰区研判:无明确结论,维持原裁决(fail-open)", alsoReason: false);
            return current;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "灰区 VT 研判异常:{path}", e.ActorPath);
            record.Stage = VtScanStage.Error;
            record.Outcome = VtScanOutcome.Error;
            record.Message = "研判异常:" + ex.Message;
            PublishVtRecord(record);
            return current; // 异常 -> fail-open,维持原 Ask
        }
    }

    /// <summary>灰区研判升格为 Block(并按哈希记忆恶意),写证据链。</summary>
    private Verdict GrayZoneBlock(SecurityEvent e, string note)
    {
        e.HasThreatIndicator = true;
        e.AddEvidence("VtGrayZone", EvidenceKind.Corroboration, note);
        RememberAiMalicious(e);
        _logger.LogWarning("灰区 VT 研判判定恶意,升格拦截:{path} —— {note}", e.ActorPath, note);
        return Verdict.For(e, VerdictAction.Block, VerdictSource.Heuristic);
    }

    /// <summary>
    /// 灰区研判判定「非恶意」:无硬恶意指标则降级 Allow(减少打扰);
    /// 存在硬指标则维持原 Ask(情报单独不得压制硬指标,仍交用户裁决)。
    /// </summary>
    private Verdict GrayZoneAllowIfSoft(SecurityEvent e, Verdict current, string note)
    {
        if (e.HasThreatIndicator)
        {
            e.AddEvidence("VtGrayZone", EvidenceKind.Info, note + ",但存在硬恶意指标,仍交用户裁决", alsoReason: false);
            return current; // 维持 Ask
        }
        e.AddEvidence("VtGrayZone", EvidenceKind.Trust, note + ",灰区软信号降级放行(减少打扰)");
        return Verdict.For(e, VerdictAction.Allow, VerdictSource.Heuristic);
    }

    /// <summary>AI 研判失败时按 fail-closed 策略构造拦截裁决。</summary>
    private Verdict AiFailBlock(SecurityEvent e, string reason)
    {
        e.HasThreatIndicator = true;
        e.RiskReasons.Insert(0, reason);
        _logger.LogWarning("AI 研判失败且开启严格模式,拦截:{path}({reason})", e.ActorPath, reason);
        return Verdict.For(e, VerdictAction.Block, VerdictSource.Heuristic);
    }

    /// <summary>
    /// 把「AI 已确认恶意」按文件 SHA-256 固化为持久 Block 规则,避免对同一文件重复调用大模型。
    /// 规则用哈希精确匹配(改名无效),标记 HardOverride 享最高优先级;按哈希去重不重复添加。
    /// 下次同哈希文件启动时,规则引擎在规则阶段直接 Block,AI 扫描门禁随即跳过。
    /// </summary>
    private void RememberAiMalicious(SecurityEvent e)
    {
        var hash = e.ActorHash;
        if (string.IsNullOrEmpty(hash)) return; // 无哈希无法可靠记忆

        // 去重:已存在命中该哈希的 Block 规则则不重复添加。
        bool exists = _engine.GetRules().Any(r =>
            r.Action == VerdictAction.Block
            && r.ActorHashes is { Count: > 0 }
            && r.ActorHashes.Contains(hash));
        if (exists) return;

        var rule = new DefenseRule
        {
            ActorHashes = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase) { hash },
            Action = VerdictAction.Block,
            HardOverride = true,
            Note = $"[AI确认] 大模型判定恶意,按哈希记忆(免重复调用):{System.IO.Path.GetFileName(e.ActorPath)}"
        };
        _engine.AddRule(rule);
        _ = _store.SaveAsync(_engine.GetRules(), CancellationToken.None);
        _logger.LogWarning("AI 确认恶意,已固化哈希拦截规则(后续免重复调用大模型):{hash}", hash);
    }

    private async Task HandleEventAsync(SecurityEvent e, CancellationToken token)
    {
        try
        {
            // 总开关关闭 / 该维度关闭 -> 直接放行(并回写内核放行)
            if (!_settings.ProtectionEnabled || !IsDimensionEnabled(e.Type))
            {
                var passVerdict = Verdict.For(e, VerdictAction.Allow, VerdictSource.DefaultPolicy);
                Enforce(e, ref passVerdict);
                var offRecord = new
                {
                    e.Id, e.TimestampUtc, type = e.Type.ToString(),
                    actor = e.ActorPath, target = e.Target,
                    action = "Allow", source = "防护已关闭"
                };
                await _audit.WriteAsync(offRecord, token);
                await _ipc.PushLogAsync(offRecord, token);
                return;
            }

            // 信誉查询(同步路径仅读本地缓存,绝不发起网络调用):
            // 命中缓存则把信誉结论挂到事件上,ThreatDetector 会据此加/减风险分。
            if (_settings.AnyReputationEnabled)
            {
                e.Reputation = _reputation.TryGetCached(e.ActorHash);
            }

            var verdict = _engine.Evaluate(e);

            // 评估后:对"值得查"的高价值新样本(未签名+首见+可疑)入队后台信誉查询。
            // 不阻塞当前裁决;查到恶意后由后台回调做补偿处置。
            if (_settings.AnyReputationEnabled && e.Reputation is null)
            {
                _reputation.MaybeEnqueue(e);
            }

            // 记录到进程链跟踪器(评分已由 Evaluate 填充),供后续关联研判。
            _chain.Record(e);

            // 双击启动应用 / 释放器派生载荷的 AI 病毒扫描:对「用户经资源管理器双击启动」的
            // 程序,以及「未签名+首见+从可疑目录运行」的疑似释放载荷(堵 dropper 中途释放病毒的
            // 盲区),在常规询问/静默处理【之前】先调用大模型做一次病毒研判,确保这类程序一定被
            // 扫到并在 UI 弹出扫描进度窗。模型判定恶意则升级为阻止(随后 Enforce 结束进程树);
            // 否则维持原裁决继续后续流程。已被引擎直接判为 Block 的(高危)无需再扫。
            if (_settings.AiScanDoubleClickEnabled
                && verdict.Action != VerdictAction.Block
                && ShouldAiScan(e))
            {
                verdict = await VtScanDoubleClickAsync(e, verdict, token);
            }

            if (verdict.Action == VerdictAction.Ask)
            {
                // 灰区 VT 研判:在弹窗【之前】先用 VirusTotal/情报源研判(若开启)。避免与上面的双击扫描重复触发。
                // fail-open:情报源不可用时维持 Ask,退回正常弹窗,行为与未启用一致。
                if (_settings.AiGrayZoneConsultEnabled
                    && !(_settings.AiScanDoubleClickEnabled && ShouldAiScan(e)))
                {
                    verdict = await VtGrayZoneConsultAsync(e, verdict, token);
                }
            }

            if (verdict.Action == VerdictAction.Ask)
            {
                // 注意:这里只影响 Ask;规则/启发式已判定为 Block 的高危行为不走这里,仍会拦截。
                if (_settings.SilentMode)
                {
                    var allow = Verdict.For(e, VerdictAction.Allow, VerdictSource.DefaultPolicy);
                    Enforce(e, ref allow);
                    var silentRecord = new
                    {
                        e.Id, e.TimestampUtc, type = e.Type.ToString(),
                        actor = e.ActorPath, target = e.Target,
                        action = "Allow", source = "静默模式",
                        risk = e.RiskScore, reasons = e.RiskReasons
                    };
                    await _audit.WriteAsync(silentRecord, token);
                    await _ipc.PushLogAsync(silentRecord, token);
                    return;
                }

                // 附上进程链上下文,让 UI/大模型能基于整条攻击链(而非孤立动作)研判。
                e.ChainContext = _chain.BuildContext(e);
                var resp = await _ipc.RequestPromptAsync(e, _promptTimeout, token);
                if (resp is null)
                {
                    // 超时 / UI 未连接 的兜底。安全原则:
                    //  - UI 未连接:无人裁决,绝不擅自阻止(尤其进程创建,误杀系统进程会导致系统不稳定),
                    //    一律放行,仅记录。
                    //  - UI 已连接但用户超时未响应:沿用风险感知策略(高危/可疑默认阻止)。
                    VerdictAction fallback;
                    if (!_ipc.IsConnected)
                    {
                        // UI 未连接,无人裁决。
                        // 安全例外:确定性恶意行为即使无人裁决也应阻断,否则攻击者只需令 UI
                        // 崩溃/抢占管道即可让所有"询问"类行为被放行。判据与"用户超时"分支一致:
                        // 高危,或「中等分 + 硬恶意指标」。纯软信号的中低分仍 fail-open,避免误杀系统进程。
                        bool deterministicMalicious =
                            e.RiskScore >= ThreatDetector.HighRisk
                            || (e.HasThreatIndicator && e.RiskScore >= ThreatDetector.Suspicious);
                        if (deterministicMalicious)
                        {
                            fallback = VerdictAction.Block;
                            _logger.LogWarning("事件 {e}(风险 {r},硬指标={ind})无 UI 裁决,但为确定性恶意,阻断(fail-closed)。",
                                e, e.RiskScore, e.HasThreatIndicator);
                        }
                        else
                        {
                            fallback = VerdictAction.Allow;
                            _logger.LogWarning("事件 {e}(风险 {r})无 UI 裁决,放行(fail-open)。", e, e.RiskScore);
                        }
                    }
                    else
                    {
                        // UI 已连接但用户没在超时内响应。这通常发生在事件风暴期间或用户离开座位。
                        // 安全策略(分级 fail-closed,兼顾"防绕过"与"防误杀"):
                        //  1) 确定性高危(HighRisk,大量硬指标)—— 一律阻断;
                        //  2) 中等分(>= Suspicious)且带「硬恶意指标」(HasThreatIndicator:危险命令行 /
                        //     异常进程链 / 进程伪装 / 双扩展名 / 编码混淆 / 攻击链等确定性行为证据)——
                        //     也阻断。这堵住了"未签名样本靠 56 分这类中分、趁用户不在场超时放行"的绕过;
                        //  3) 仅软信号的中分(无硬指标,如"未签名+Temp"这类可能误判合法绿色软件)——
                        //     走默认策略(通常 Allow),避免误杀。
                        // 注:进程伪装等会打断系统组件的极端情况仍由 Enforce 里的关键系统进程白名单兜底。
                        bool deterministicMalicious =
                            e.RiskScore >= ThreatDetector.HighRisk
                            || (e.HasThreatIndicator && e.RiskScore >= ThreatDetector.Suspicious);

                        fallback = deterministicMalicious
                            ? VerdictAction.Block
                            : _engine.DefaultAction;
                        _logger.LogWarning("事件 {e}(风险 {r},硬指标={ind})用户超时未响应,按 {a} 处置。",
                            e, e.RiskScore, e.HasThreatIndicator, fallback);
                    }
                    verdict = Verdict.For(e, fallback, VerdictSource.Timeout);
                }
                else
                {
                    verdict = Verdict.For(e, resp.Action, VerdictSource.UserPrompt, resp.Remember);
                    if (resp.Remember && resp.Action != VerdictAction.Ask)
                    {
                        // 按用户选择的「记住范围」生成规则:永久 / 本次会话 / 限时,降低永久误放行风险。
                        DateTime? expiresUtc = resp.Scope switch
                        {
                            RememberScope.OneHour => DateTime.UtcNow.AddHours(1),
                            RememberScope.OneDay => DateTime.UtcNow.AddDays(1),
                            _ => null
                        };
                        bool sessionOnly = resp.Scope == RememberScope.Session;
                        _engine.CreateRuleFrom(e, resp.Action, expiresUtc, sessionOnly);
                        await _store.SaveAsync(_engine.GetRules(), token);
                        _logger.LogInformation("已记住用户选择(范围 {scope}),生成新规则。", resp.Scope);
                    }
                }
            }

            Enforce(e, ref verdict);

            // 明确恶意行为被"直接拦截"(命中内置规则 / 启发式高危),主动弹通知告知用户。
            // 用户超时/兜底导致的 Block 不在此列(那类已在弹窗里告知过)。
            if (verdict.Action == VerdictAction.Block &&
                (verdict.Source == VerdictSource.Rule || verdict.Source == VerdictSource.Heuristic))
            {
                await _ipc.PushBlockNotificationAsync(e, token);
            }

            var record = new
            {
                e.Id, e.TimestampUtc, type = e.Type.ToString(),
                actor = e.ActorPath, target = e.Target,
                action = verdict.Action.ToString(), source = verdict.Source.ToString(),
                risk = e.RiskScore,
                reasons = e.RiskReasons
            };
            // 先落盘审计(UI 离线也不丢),再推送 UI。
            await _audit.WriteAsync(record, token);
            // 可选:导出 ECS 结构化告警(含证据链 + ATT&CK)供 SIEM 采集。
            await _alertExporter.ExportAsync(e, verdict, token);
            await _ipc.PushLogAsync(record, token);

            // 结构化事件日志(供活动日志视图回溯攻击时间线)。仅推送「值得回溯」的事件:
            // 非放行(询问/拦截)、有风险分、或出现硬指标 —— 避免海量纯净放行(进程创建等)刷屏。
            if (verdict.Action != VerdictAction.Allow || e.RiskScore > 0 || e.HasThreatIndicator)
            {
                await _ipc.PushEventLogAsync(e, verdict, token);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.LogError(ex, "处理事件失败: {e}", e);
        }
    }

    /// <summary>
    /// 关键系统进程文件名(全部小写)。这些进程被拦截/结束会导致系统不稳定甚至蓝屏:
    /// - explorer.exe:被结束 = 桌面消失
    /// - services.exe / wininit.exe / csrss.exe / lsass.exe / smss.exe / winlogon.exe:
    ///   被拦截或结束会触发 CRITICAL_PROCESS_DIED(蓝屏)
    /// - dwm.exe / fontdrvhost.exe:UI 体验依赖
    /// - conhost.exe / taskhostw.exe / runtimebroker.exe / tiworker.exe / searchindexer.exe /
    ///   sihost.exe / usoclient.exe / wuauclt.exe:Windows 后台/任务托管进程,被结束会
    ///   破坏控制台/计划任务/UWP/Windows Update 等基础功能。
    /// - msmpeng.exe / mpdefendercoreservice.exe:Defender 引擎,误结束会破坏系统防护。
    /// 任何启发式/规则误判命中这些主体时,在 Enforce 阶段一律强制改写为 Allow,
    /// 杜绝"软件把桌面/系统拖死"。
    /// </summary>
    private static readonly System.Collections.Generic.HashSet<string> CriticalSystemProcesses =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // R3 关键系统进程(误杀=蓝屏 / 桌面消失)
            "explorer.exe", "dwm.exe", "fontdrvhost.exe",
            "services.exe", "wininit.exe", "csrss.exe", "lsass.exe",
            "smss.exe", "winlogon.exe", "spoolsv.exe",
            // 系统辅助/后台托管(误杀=系统功能异常)
            "conhost.exe", "taskhostw.exe", "runtimebroker.exe",
            "tiworker.exe", "searchindexer.exe", "searchprotocolhost.exe",
            "sihost.exe", "lsm.exe",
            // Windows Update 链
            "wuauclt.exe", "usoclient.exe", "trustedinstaller.exe",
            // Windows Defender
            "msmpeng.exe", "mpdefendercoreservice.exe",
            "securityhealthservice.exe", "securityhealthsystray.exe",
        };

    private static bool IsCriticalSystemActor(SecurityEvent e)
    {
        if (string.IsNullOrEmpty(e.ActorPath)) return false;
        var name = System.IO.Path.GetFileName(e.ActorPath);
        return !string.IsNullOrEmpty(name) && CriticalSystemProcesses.Contains(name);
    }

    /// <summary>
    /// 执行处置。对于内核驱动事件源,通过 IVerdictSink 把裁决回写内核
    /// (内核据此放行或拒绝进程创建);对于纯观测源仅记录日志。
    ///
    /// 对「仅记录型」事件(映像加载 / 远程线程注入)——内核回调无法原地阻断——
    /// 若裁决为 Block,则由用户态主动结束发起进程作为补偿处置。
    ///
    /// <paramref name="verdict"/> 为 ref:关键系统进程被误判 Block 时,本方法将其改写
    /// 为 Allow;调用方需用改写后的裁决记录审计与推送 UI 通知,否则审计/通知会出现
    /// 与实际处置不一致的「假 Block」。
    /// </summary>
    private void Enforce(SecurityEvent e, ref Verdict verdict)
    {
        // 硬底线:关键系统进程作为发起方时,无论规则/启发式怎么判,都不阻止 / 不结束。
        // 这些进程被打断会直接破坏系统(桌面消失 / 蓝屏)。误判要么放行,要么人工介入,
        // 绝不在主路径上把它们 Block 掉。
        if (verdict.Action == VerdictAction.Block && IsCriticalSystemActor(e))
        {
            _logger.LogWarning(
                "覆盖拦截:关键系统进程 {actor} 命中规则/启发式 Block(原因:{src}),改为放行以保护系统稳定。",
                e.ActorPath, verdict.Source);
            verdict = Verdict.For(e, VerdictAction.Allow, VerdictSource.DefaultPolicy);
        }

        // 回写内核(若支持)。Ask 不会到这里,只会是 Allow/Block。
        _verdictSink?.SubmitVerdict(e, verdict.Action);

        // 用户态补偿处置:对内核无法原地拦截的 Block,从用户态结束发起进程。
        //  - 仅记录型内核事件(映像加载 / 远程线程注入):内核回调无法原地阻断;
        //  - 用户态观测事件(WMI 进程创建):进程已启动,只能"启动后立即结束"。
        // 两类都靠结束发起进程兜底,使无内核驱动时"阻止"也能真正生效。
        if (verdict.Action == VerdictAction.Block && (IsReportOnly(e.Type) || e.UserModeObserved))
        {
            // 映像加载事件 ActorPid==0 表示内核驱动加载,无用户态进程可结束,跳过。
            if (e.ActorPid > 4 && OperatingSystem.IsWindows())
            {
                // 结束整棵进程树:不仅杀软件本体,连带清除它已派生/释放的子进程
                // (藏在软件包内、由主程序拉起的载荷 / helper / worker),否则杀了本体
                // 这些后代仍会继续作恶。每个进程仍受关键进程/系统目录白名单保护。
                int killed = ProcessInspector.TerminateProcessTree(e.ActorPid);
                if (killed > 0)
                    _logger.LogWarning("主动处置:已结束进程树 {path} (PID {pid}),共 {n} 个进程,因 {type} 被裁决为阻止。",
                        e.ActorPath, e.ActorPid, killed, e.Type);
                else
                    _logger.LogWarning("主动处置失败:无法结束进程 {path} (PID {pid})(可能已退出或权限不足)。",
                        e.ActorPath, e.ActorPid);
            }
        }

        // 文件隔离:对确定性恶意(命中规则 / 启发式判定)的进程主体,在结束进程后
        // 把其磁盘上的可执行文件本体移入隔离区并失活,杜绝"杀掉进程但文件仍在、下次又被拉起"。
        // 仅对进程类事件的主体文件隔离,且仅在确定性来源(规则/启发式)下进行;
        // 关键系统进程已在 Enforce 开头被改判 Allow,不会走到这里。
        if (verdict.Action == VerdictAction.Block
            && (verdict.Source == VerdictSource.Rule || verdict.Source == VerdictSource.Heuristic)
            && e.Type is EventType.ProcessCreate or EventType.RemoteThread
            && !string.IsNullOrEmpty(e.ActorPath)
            && OperatingSystem.IsWindows())
        {
            _ = QuarantineActorAsync(e, verdict);
        }

        // 白加黑专项处置:被拦截的「模块加载(ImageLoad)」事件——恶意载荷以 DLL 形式
        // 侧载进合法/系统宿主进程,没有自己的进程树节点,杀宿主既不应该也防不住下次再载。
        // 改为把该恶意模块文件下发内核「禁止加载」名单:此后任何进程(含合法签名宿主)
        // 都无法再以执行/映射方式加载它,从根上断掉白加黑。仅对确定性 Block 生效。
        if (verdict.Action == VerdictAction.Block
            && e.Type == EventType.ImageLoad
            && _moduleBlockSink is not null
            && !string.IsNullOrWhiteSpace(e.Target)
            && OperatingSystem.IsWindows())
        {
            if (_moduleBlockSink.BlockModuleLoad(e.Target))
                _logger.LogWarning("白加黑处置:已将恶意模块 {mod} 加入内核禁止加载名单(宿主 {host} PID {pid} 不结束)。",
                    e.Target, e.ActorPath, e.ActorPid);
        }

        _logger.LogInformation("处置 {e} => {action} (来源:{source})",
            e, verdict.Action, verdict.Source);
    }

    /// <summary>
    /// 后台 VT 查询确认某文件为恶意时的补偿处置:
    ///  1) 推送"已拦截"告警通知 UI;
    ///  2) 若进程仍在运行,从用户态结束它(执行前没拦住的事后补刀);
    ///  3) 固化一条精确锁定该文件路径的 Block 规则,使其后续被实时拦截。
    /// 注意:本回调在后台 worker 线程触发,需自行容错,不抛断。
    /// </summary>
    private void OnMaliciousConfirmed(SecurityEvent e, FileReputation rep)
    {
        try
        {
            _logger.LogWarning("威胁情报确认恶意:{file}({m}/{t}{label}),执行补偿处置。",
                e.ActorPath, rep.Malicious, rep.TotalEngines,
                string.IsNullOrEmpty(rep.ThreatLabel) ? "" : $", {rep.ThreatLabel}");

            // 1) 告警通知 UI(尽力而为)。
            _ = _ipc.PushBlockNotificationAsync(e, CancellationToken.None);

            // 2) 结束仍在运行的进程树(进程已退出则忽略)。连带清除其派生的子进程。
            if (e.ActorPid > 4 && OperatingSystem.IsWindows())
            {
                int killed = ProcessInspector.TerminateProcessTree(e.ActorPid);
                if (killed > 0)
                    _logger.LogWarning("补偿处置:已结束恶意进程树 {file} (PID {pid}),共 {n} 个进程。",
                        e.ActorPath, e.ActorPid, killed);
            }

            // 3) 固化精确 Block 规则(按主体路径),后续命中直接拦截。
            if (!string.IsNullOrEmpty(e.ActorPath))
            {
                var rule = new DefenseRule
                {
                    ActorPath = e.ActorPath,
                    Type = e.Type,
                    Action = VerdictAction.Block,
                    Note = $"威胁情报自动拦截({rep.Malicious}/{rep.TotalEngines})"
                };
                _engine.AddRule(rule);
                _ = _store.SaveAsync(_engine.GetRules(), CancellationToken.None);
            }

            // 落审计。
            var record = new
            {
                e.Id, e.TimestampUtc, type = e.Type.ToString(),
                actor = e.ActorPath, target = e.Target,
                action = "Block", source = "威胁情报",
                risk = e.RiskScore,
                reasons = new[] { $"VirusTotal {rep.Malicious}/{rep.TotalEngines} 恶意" }
            };
            _ = _audit.WriteAsync(record, CancellationToken.None);
            _ = _ipc.PushLogAsync(record, CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "恶意确认补偿处置失败。");
        }
    }

    /// <summary>
    /// 把被裁决为恶意的进程主体文件移入隔离区(失活磁盘上的载荷),并把结果推送/落盘。
    /// 在后台任务中执行,绝不抛断主处置流程。隔离成功后会向 UI 推送一条审计日志。
    /// </summary>
    private async Task QuarantineActorAsync(SecurityEvent e, Verdict verdict)
    {
        bool actorQuarantined = false;
        try
        {
            var path = e.ActorPath;

            // 1) 隔离主体载荷(确认恶意的主程序),无论其落地位置。文件不存在则跳过隔离,
            //    但仍继续执行下方的「足迹清理」(进程可能已被结束、主体被改名/移动)。
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
            {
                // 隔离原因:汇总裁决来源与风险原因,便于事后审计与还原判断。
                string reason = verdict.Source == VerdictSource.Rule
                    ? $"命中规则拦截{(string.IsNullOrEmpty(e.MatchedRuleNote) ? "" : ":" + e.MatchedRuleNote)}"
                    : $"启发式判定恶意(风险 {e.RiskScore}):{string.Join("; ", e.RiskReasons.Take(4))}";

                string? hash = e.ActorHash ?? QuarantineManager.TryComputeSha256(path);

                var entry = await _quarantine.QuarantineAsync(path, reason, e.ActorPid, hash, CancellationToken.None);
                if (entry is null)
                {
                    _logger.LogWarning("文件隔离失败(文件可能仍被占用或权限不足):{path}", path);
                }
                else
                {
                    actorQuarantined = true;
                    _logger.LogWarning("已隔离恶意文件:{path} -> 隔离区({size} 字节,原因:{reason})。",
                        path, entry.Size, reason);

                    var record = new
                    {
                        id = entry.Id, timestampUtc = entry.QuarantinedUtc,
                        type = e.Type.ToString(),
                        actor = e.ActorPath, target = "(已移入隔离区)",
                        action = "Quarantine", source = verdict.Source.ToString(),
                        risk = e.RiskScore,
                        reasons = new[] { reason }
                    };
                    await _audit.WriteAsync(record, CancellationToken.None);
                    await _ipc.PushLogAsync(record, CancellationToken.None);
                }
            }

            // 2) 足迹清理:基于进程树记录,清理该恶意进程(及其子孙)释放的文件与
            //    写入的自启动持久化项。内存足迹由「结束整棵进程树」覆盖,无需另行处理。
            await RemediateFootprintAsync(e, verdict, actorQuarantined);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "隔离/清理恶意文件时出错:{path}", e.ActorPath);
        }
    }

    /// <summary>
    /// 对确认恶意的进程执行「完整足迹清理」:收集其进程树记录过的全部事件,
    /// 交 <see cref="ThreatRemediator"/> 清理释放文件与自启动持久化项,把结果记入审计、
    /// 并通过结构化「清理报告」推送 UI —— 既展示清理成功项,也明确告知哪些未能清理(及原因)。
    /// </summary>
    private async Task RemediateFootprintAsync(SecurityEvent e, Verdict verdict, bool actorQuarantined)
    {
        if (_remediator is null || !OperatingSystem.IsWindows()) return;

        try
        {
            var footprint = _chain.CollectTreeEvents(e.ActorPid);
            var report = await _remediator.RemediateAsync(e, footprint, CancellationToken.None);

            // 没有任何成功清理、也没有任何跳过/失败,且主体也未隔离 —— 无需打扰用户。
            if (report.TotalActions == 0 && report.Skipped.Count == 0 && !actorQuarantined)
                return;

            string reason = verdict.Source switch
            {
                VerdictSource.Rule => string.IsNullOrEmpty(e.MatchedRuleNote)
                    ? "命中规则拦截" : "命中规则:" + e.MatchedRuleNote,
                VerdictSource.Heuristic => e.RiskReasons.Count > 0
                    ? "启发式/AI 判定恶意:" + string.Join("; ", e.RiskReasons.Take(3))
                    : "启发式判定恶意",
                _ => verdict.Source.ToString()
            };

            // 审计日志(始终留痕)。
            var details = report.QuarantinedFiles.Select(f => "清理文件:" + f)
                .Concat(report.RemovedRegistryValues.Select(r => "移除自启动:" + r))
                .Concat(report.Skipped.Select(s => $"未清理:{s.Target}({s.Reason})"))
                .Take(30).ToArray();
            var record = new
            {
                id = Guid.NewGuid(),
                timestampUtc = DateTime.UtcNow,
                type = e.Type.ToString(),
                actor = e.ActorPath,
                target = $"足迹清理 · 成功 {report.TotalActions} · 未清理 {report.Skipped.Count}",
                action = "Remediate",
                source = verdict.Source.ToString(),
                risk = e.RiskScore,
                reasons = details
            };
            await _audit.WriteAsync(record, CancellationToken.None);
            await _ipc.PushLogAsync(record, CancellationToken.None);

            // 结构化清理报告 -> UI 弹窗(成功项 + 未清理项及原因)。
            var payload = new RemediationReportPayload
            {
                TimestampUtc = DateTime.UtcNow,
                ActorPath = e.ActorPath,
                ActorPid = e.ActorPid,
                Reason = reason,
                ActorQuarantined = actorQuarantined,
                QuarantinedFiles = report.QuarantinedFiles.ToList(),
                RemovedRegistryValues = report.RemovedRegistryValues.ToList(),
                Skipped = report.Skipped.ToList()
            };
            await _ipc.PushRemediationReportAsync(payload, CancellationToken.None);

            _logger.LogWarning("已完成恶意足迹清理:{actor}(隔离文件 {f} 个,移除自启动 {r} 项,未清理 {s} 项)。",
                e.ActorPath, report.QuarantinedFiles.Count, report.RemovedRegistryValues.Count, report.Skipped.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "执行足迹清理时出错:{actor}", e.ActorPath);
        }
    }

    /// <summary>
    /// 「仅记录型」事件:内核回调不会原地阻断,需要用户态补偿处置(结束发起进程)。
    /// 当前包含:
    ///   - ProcessCreate:架构上改为 fire-and-forget,内核永不挂起进程创建;
    ///     Block 由用户态 TerminateProcess 启动后立即结束(post-launch kill,
    ///     EDR 标准模型)。
    ///   - ImageLoad / RemoteThread:内核回调本身就是「通知型」,无法原地阻断,
    ///     Block 由用户态结束发起进程兜底。
    ///   - RegistryWrite:为彻底消除卡顿,内核注册表回调已改为「放行 + 异步上报」
    ///     (宽子串热键如 \Services 无法在内核同步裁决,否则会卡死整机)。因此注册表
    ///     的 Block 不再由内核原地拒绝,改由用户态结束发起进程兜底。
    ///     局限:键值写入此时已落地,结束进程只能阻断「后续/批量」篡改,无法回滚单次写入;
    ///     这是稳定性与拦截即时性的工程取舍,与 EDR 的 post-write kill 模型一致。
    ///     注:发起者若是 services.exe(SCM 代写服务键),DriverEventSource 已通过
    ///     TraceServiceOriginator 把主体改写为真正的 RPC 发起者,故结束的是真凶而非 SCM;
    ///     且 TryTerminateProcess 内置关键进程白名单,绝不会误杀 services.exe。
    /// 文件事件(FileDelete/FileWrite)不在此列:内核已本地查表原地拒绝(STATUS_ACCESS_DENIED),
    /// 无需用户态补偿。
    /// </summary>
    private static bool IsReportOnly(EventType type) =>
        type is EventType.ImageLoad or EventType.RemoteThread
            or EventType.ProcessCreate or EventType.RegistryWrite;
}
