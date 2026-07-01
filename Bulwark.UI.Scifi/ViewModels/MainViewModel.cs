using System.Collections.ObjectModel;
using Bulwark.UI.Services;

namespace Bulwark.UI.Scifi.ViewModels;

/// <summary>
/// 主窗口 ViewModel — 驱动仪表盘并持有各子页面 ViewModel。
/// </summary>
public sealed class MainViewModel : ObservableObject
{
    public IpcClient Ipc { get; }
    public RulesViewModel RulesVm { get; }
    public TrustViewModel TrustVm { get; }
    public QuarantineViewModel QuarantineVm { get; }
    public InterceptLogViewModel InterceptLogVm { get; }
    public ActivityLogViewModel ActivityLogVm { get; }
    public PersistenceViewModel PersistenceVm { get; }
    public SettingsViewModel SettingsVm { get; }
    public AiScanViewModel AiScanVm { get; }
    public VtHistoryViewModel VtHistoryVm { get; }
    public ReputationSourcesViewModel ApiStatusVm { get; }

    public MainViewModel(IpcClient ipc)
    {
        Ipc = ipc;
        RulesVm = new RulesViewModel(ipc);
        TrustVm = new TrustViewModel(ipc);
        QuarantineVm = new QuarantineViewModel(ipc);
        InterceptLogVm = new InterceptLogViewModel(ipc);
        ActivityLogVm = new ActivityLogViewModel(ipc);
        PersistenceVm = new PersistenceViewModel(ipc);
        SettingsVm = new SettingsViewModel(ipc);
        AiScanVm = new AiScanViewModel();
        VtHistoryVm = new VtHistoryViewModel(ipc);
        ApiStatusVm = new ReputationSourcesViewModel(ipc, SettingsVm);

        // 官方用量配置变化 / Cookie 测试成功 -> 立即重新拉取官方用量刷新仪表盘(不必等 5 分钟定时器)。
        SettingsVm.OfficialUsageConfigChanged += () =>
            Avalonia.Threading.Dispatcher.UIThread.Post(TryFetchOfficial);

        ipc.ConnectionChanged += connected =>
        {
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                IsConnected = connected;
                StatusText = connected ? "链路在线" : "链路离线";
            });
        };
        ipc.LogReceived += msg =>
        {
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                if (Logs.Count > 200) Logs.RemoveAt(0);
                Logs.Add(msg);
                TotalEvents++;
                LogsEmpty = false;
            });
        };
        ipc.SettingsReceived += s =>
        {
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                KernelConnected = s.KernelConnected;
                KernelStatus = string.IsNullOrEmpty(s.KernelStatus) ? "未知" : s.KernelStatus;
            });
        };

        // 周期刷新 AI Credits 月度用量(供仪表盘用量条展示)。
        _creditTimer = new Avalonia.Threading.DispatcherTimer
        {
            Interval = System.TimeSpan.FromSeconds(5)
        };
        _creditTimer.Tick += (_, _) => RefreshCreditUsage();
        _creditTimer.Start();

        // 官方用量(可选)独立较慢刷新:每 5 分钟拉一次,避免频繁网络请求。
        _officialTimer = new Avalonia.Threading.DispatcherTimer
        {
            Interval = System.TimeSpan.FromMinutes(5)
        };
        _officialTimer.Tick += (_, _) => TryFetchOfficial();
        _officialTimer.Start();

        TryFetchOfficial();
        RefreshCreditUsage();
    }

    private readonly Avalonia.Threading.DispatcherTimer _creditTimer;
    private readonly Avalonia.Threading.DispatcherTimer _officialTimer;

    // 官方用量状态
    private bool _officialOk;
    private long _officialUsed;
    private long _officialTotal;
    private string _officialNote = string.Empty;

    /// <summary>读取 UI 本地的官方用量配置;启用且有 Cookie 时发起拉取。</summary>
    private void TryFetchOfficial()
    {
        var local = UiLocalConfig.Load();
        if (local.MimoUsageEnabled && !string.IsNullOrWhiteSpace(local.MimoUsageCookie))
            _ = FetchOfficialUsageAsync(local.MimoUsageCookie);
        else
        {
            _officialOk = false;
            _officialNote = string.Empty;
            RefreshCreditUsage();
        }
    }

    /// <summary>拉取官方用量;成功则用官方数覆盖展示,失败则清标记自动降级回本地估算。</summary>
    private async System.Threading.Tasks.Task FetchOfficialUsageAsync(string cookie)
    {
        try
        {
            var r = await App.MimoUsage.FetchAsync(cookie);
            if (r.Ok)
            {
                _officialOk = true;
                _officialUsed = r.Used;
                _officialTotal = r.Total;
                _officialNote = string.Empty;
            }
            else
            {
                _officialOk = false;
                _officialNote = "官方用量获取失败:" + r.Message + "(已回退本地估算)";
            }
        }
        catch
        {
            _officialOk = false;
            _officialNote = "官方用量获取异常(已回退本地估算)";
        }
        Avalonia.Threading.Dispatcher.UIThread.Post(RefreshCreditUsage);
    }

    /// <summary>从 AI 客户端读取本月 Credits 用量快照,刷新仪表盘用量条。</summary>
    private void RefreshCreditUsage()
    {
        try
        {
            // 优先展示官方用量(若启用且获取成功);否则用本地估算。
            if (_officialOk && _officialTotal > 0)
            {
                double opct = System.Math.Min(100.0, _officialUsed * 100.0 / _officialTotal);
                CreditGuardEnabled = true;
                CreditUsedPercent = opct;
                CreditUsageText = $"[官方] 本月用量 {_officialUsed / 1e8:0.##} / {_officialTotal / 1e8:0.#} 亿 Credits ({opct:0}%)";
            }
            else
            {
                var (used, limit, enabled) = App.Ai.Budget.Snapshot();
                CreditGuardEnabled = enabled;
                if (limit <= 0) limit = 1;
                double pct = System.Math.Min(100.0, used * 100.0 / limit);
                CreditUsedPercent = pct;
                CreditUsageText = $"[本地估算] 本月 AI 用量 {used / 1e8:0.##} / {limit / 1e8:0.#} 亿 Credits ({pct:0}%)";
            }

            var cats = App.Ai.Budget.PerCategory();
            string catText = cats.Length == 0
                ? "本月暂无 AI 调用"
                : string.Join("    ", System.Linq.Enumerable.Select(cats,
                    c => $"{c.Category} ×{c.Count} · {c.Credits / 1e8:0.##}亿"));
            CreditBreakdownText = string.IsNullOrEmpty(_officialNote) ? catText : _officialNote + "    " + catText;
        }
        catch { /* 忽略:用量展示失败不影响功能 */ }
    }

    private bool _creditGuardEnabled = true;
    public bool CreditGuardEnabled { get => _creditGuardEnabled; set => Set(ref _creditGuardEnabled, value); }

    private double _creditUsedPercent;
    public double CreditUsedPercent { get => _creditUsedPercent; set => Set(ref _creditUsedPercent, value); }

    private string _creditUsageText = "本月 AI 用量 —";
    public string CreditUsageText { get => _creditUsageText; set => Set(ref _creditUsageText, value); }

    private string _creditBreakdownText = "本月暂无 AI 调用";
    /// <summary>各 AI 功能的本月调用次数与 Credits 分项(用量条下方展示)。</summary>
    public string CreditBreakdownText { get => _creditBreakdownText; set => Set(ref _creditBreakdownText, value); }

    // ===== 状态 =====
    private bool _isConnected;
    public bool IsConnected
    {
        get => _isConnected;
        set { if (Set(ref _isConnected, value)) OnPropertyChanged(nameof(IsDisconnected)); }
    }

    /// <summary>IsConnected 取反,供 XAML 直接绑定(编译绑定不支持 ! 运算)。</summary>
    public bool IsDisconnected => !_isConnected;

    private string _statusText = "链路离线";
    public string StatusText { get => _statusText; set => Set(ref _statusText, value); }

    private bool _logsEmpty = true;
    public bool LogsEmpty { get => _logsEmpty; set => Set(ref _logsEmpty, value); }

    // ===== 统计 =====
    private int _allowCount;
    public int AllowCount { get => _allowCount; set => Set(ref _allowCount, value); }

    private int _blockCount;
    public int BlockCount { get => _blockCount; set => Set(ref _blockCount, value); }

    private int _totalEvents;
    public int TotalEvents { get => _totalEvents; set => Set(ref _totalEvents, value); }

    private int _aiScanCount;
    public int AiScanCount { get => _aiScanCount; set => Set(ref _aiScanCount, value); }

    // ===== 日志 =====
    public ObservableCollection<string> Logs { get; } = new();

    // ===== 驱动状态(仪表盘展示) =====
    private bool _kernelConnected;
    public bool KernelConnected { get => _kernelConnected; set => Set(ref _kernelConnected, value); }

    private string _kernelStatus = "未知";
    public string KernelStatus { get => _kernelStatus; set => Set(ref _kernelStatus, value); }
}
