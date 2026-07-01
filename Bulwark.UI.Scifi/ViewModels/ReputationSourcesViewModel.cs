using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using Avalonia.Media;
using Avalonia.Threading;
using Bulwark.UI.Services;

namespace Bulwark.UI.Scifi.ViewModels;

/// <summary>
/// 「情报源连接」页 VM:集中展示各威胁情报 API 的连接/可用状态,并支持逐个或一键测试。
/// 服务端持有各源的 API Key,UI 仅经 IPC 转发「测试连接」请求并展示结果。
/// </summary>
public sealed class ReputationSourcesViewModel : ObservableObject
{
    private readonly IpcClient _ipc;

    /// <summary>各情报源条目(顺序即展示顺序,大致按可信度/优先级排列)。</summary>
    public ObservableCollection<ReputationSourceItem> Sources { get; } = new()
    {
        new ReputationSourceItem("VirusTotal",     "VirusTotal",        "T1 权威 · 多引擎聚合 · 4/min · 500/day"),
        new ReputationSourceItem("MalwareBazaar",  "MalwareBazaar",     "T2 高可信 · abuse.ch 已知恶意样本库 · 10/min · 2000/day"),
        new ReputationSourceItem("ThreatBook",     "微步在线 ThreatBook","T2 高可信 · 多引擎(国内) · 3/min · 300/day"),
        new ReputationSourceItem("MetaDefender",   "MetaDefender",      "T3 稀缺 · OPSWAT 多引擎 · 6/min · 100/day"),
        new ReputationSourceItem("OTX",            "AlienVault OTX",    "T3 富化 · 威胁情报报告(pulse) · 10/min · 1000/day"),
        new ReputationSourceItem("HybridAnalysis", "Hybrid Analysis",   "T3 富化 · 沙箱分析报告 · 5/min · 200/day"),
    };

    public ReputationSourcesViewModel(IpcClient ipc, SettingsViewModel settings)
    {
        _ipc = ipc;
        Settings = settings;

        // 初始化各项开关状态,并挂上「用户切换 -> 写回设置」回调。
        foreach (var item in Sources)
        {
            item.SetEnabledSilently(ReadEnabled(item.Name));
            item.EnabledChanged = OnItemEnabledToggled;
        }

        // 设置(经服务端下发)变化时,同步各项开关的展示状态。
        settings.PropertyChanged += (_, e) => SyncItemFromSettings(e.PropertyName);

        // 连接建立时拉取一次实时用量。
        _ipc.ConnectionChanged += connected => { if (connected) RefreshUsage(); };
        if (_ipc.IsConnected) RefreshUsage();
    }

    /// <summary>向服务端拉取各源今日用量并回填到条目(纯展示,失败静默)。</summary>
    public async void RefreshUsage()
    {
        if (!_ipc.IsConnected) return;
        try
        {
            var resp = await _ipc.RequestReputationUsageAsync();
            if (resp?.Usages is null) return;
            foreach (var u in resp.Usages)
                foreach (var item in Sources)
                    if (item.Name == u.Source) { item.SetUsage(u.UsedToday, u.DailyLimit); break; }
        }
        catch { /* 用量展示失败不影响页面 */ }
    }

    /// <summary>共享的设置 VM —— 6 个源的启用开关由它统一持有并持久化。</summary>
    public SettingsViewModel Settings { get; }

    /// <summary>用户在本页切换某源开关 -> 写回共享设置(触发保存下发服务端)。</summary>
    private void OnItemEnabledToggled(ReputationSourceItem item)
    {
        switch (item.Name)
        {
            case "VirusTotal": Settings.VirusTotalEnabled = item.Enabled; break;
            case "MalwareBazaar": Settings.MalwareBazaarEnabled = item.Enabled; break;
            case "ThreatBook": Settings.ThreatBookEnabled = item.Enabled; break;
            case "MetaDefender": Settings.MetaDefenderEnabled = item.Enabled; break;
            case "OTX": Settings.OtxEnabled = item.Enabled; break;
            case "HybridAnalysis": Settings.HybridAnalysisEnabled = item.Enabled; break;
        }
    }

    /// <summary>设置某个开关属性变化时,回填对应源条目的展示开关(静默,避免回环写入)。</summary>
    private void SyncItemFromSettings(string? propName)
    {
        var name = propName switch
        {
            nameof(SettingsViewModel.VirusTotalEnabled) => "VirusTotal",
            nameof(SettingsViewModel.MalwareBazaarEnabled) => "MalwareBazaar",
            nameof(SettingsViewModel.ThreatBookEnabled) => "ThreatBook",
            nameof(SettingsViewModel.MetaDefenderEnabled) => "MetaDefender",
            nameof(SettingsViewModel.OtxEnabled) => "OTX",
            nameof(SettingsViewModel.HybridAnalysisEnabled) => "HybridAnalysis",
            _ => null
        };
        if (name is null) return;
        foreach (var item in Sources)
            if (item.Name == name) { item.SetEnabledSilently(ReadEnabled(name)); break; }
    }

    private bool ReadEnabled(string name) => name switch
    {
        "VirusTotal" => Settings.VirusTotalEnabled,
        "MalwareBazaar" => Settings.MalwareBazaarEnabled,
        "ThreatBook" => Settings.ThreatBookEnabled,
        "MetaDefender" => Settings.MetaDefenderEnabled,
        "OTX" => Settings.OtxEnabled,
        "HybridAnalysis" => Settings.HybridAnalysisEnabled,
        _ => false
    };

    private bool _busy;
    /// <summary>是否有正在进行的批量测试(禁用「全部测试」按钮)。</summary>
    public bool Busy { get => _busy; set { if (Set(ref _busy, value)) OnPropertyChanged(nameof(NotBusy)); } }
    public bool NotBusy => !_busy;

    private string _summary = "点击「全部测试」逐一探测各情报源连接。";
    /// <summary>顶部汇总提示。</summary>
    public string Summary { get => _summary; set => Set(ref _summary, value); }

    /// <summary>测试全部情报源(串行,避免同时打满多个源的限流)。</summary>
    public async void TestAll()
    {
        if (_busy) return;
        if (!_ipc.IsConnected) { Summary = "未连接服务,无法测试。请确认后台服务在运行。"; return; }

        Busy = true;
        Summary = "正在逐一测试各情报源…";
        int ok = 0, fail = 0;
        try
        {
            foreach (var item in Sources)
            {
                await TestItemAsync(item);
                if (item.State == SourceState.Online) ok++;
                else if (item.State == SourceState.Offline) fail++;
            }
            Summary = $"测试完成 · 在线 {ok} · 异常 {fail} · 共 {Sources.Count} 个源。";
        }
        finally { Busy = false; }
        RefreshUsage();
    }

    /// <summary>测试单个情报源。</summary>
    public async void TestOne(ReputationSourceItem item)
    {
        if (item is null || item.Busy) return;
        if (!_ipc.IsConnected) { item.SetResult(SourceState.Offline, "未连接服务"); return; }
        await TestItemAsync(item);
    }

    private async Task TestItemAsync(ReputationSourceItem item)
    {
        item.SetTesting();
        try
        {
            var resp = await _ipc.TestReputationSourceAsync(item.Name);
            item.SetResult(resp.Success ? SourceState.Online : SourceState.Offline, resp.Message);
        }
        catch (Exception ex)
        {
            item.SetResult(SourceState.Offline, "异常:" + ex.Message);
        }
    }
}

/// <summary>情报源连接状态。</summary>
public enum SourceState { Unknown, Testing, Online, Offline }

/// <summary>单个情报源的展示条目(名称 / 描述 / 实时连接状态)。</summary>
public sealed class ReputationSourceItem : ObservableObject
{
    /// <summary>IPC 用的源标识(与服务端 SourceName 对应)。</summary>
    public string Name { get; }

    /// <summary>展示名。</summary>
    public string DisplayName { get; }

    /// <summary>分层/配额说明。</summary>
    public string Note { get; }

    public ReputationSourceItem(string name, string displayName, string note)
    {
        Name = name;
        DisplayName = displayName;
        Note = note;
    }

    private SourceState _state = SourceState.Unknown;
    public SourceState State { get => _state; private set => Set(ref _state, value); }

    private string _statusText = "未测试";
    public string StatusText { get => _statusText; private set => Set(ref _statusText, value); }

    private string _detail = "尚未测试连接。";
    /// <summary>最近一次测试的详细信息(成功提示 / 失败原因)。</summary>
    public string Detail { get => _detail; private set => Set(ref _detail, value); }

    private string _usageText = "";
    /// <summary>今日用量文案,如 "今日 12 / 500"。未取到时为空。</summary>
    public string UsageText { get => _usageText; private set => Set(ref _usageText, value); }

    private bool _hasUsage;
    /// <summary>是否已取到用量(控制用量行/进度条可见性)。</summary>
    public bool HasUsage { get => _hasUsage; private set => Set(ref _hasUsage, value); }

    private double _usagePercent;
    /// <summary>今日已用占日配额的百分比(0-100)。</summary>
    public double UsagePercent { get => _usagePercent; private set => Set(ref _usagePercent, value); }

    private IBrush _usageBrush = MakeBrush("#39FF14");
    /// <summary>用量进度条颜色(绿→黄→红,按接近上限程度)。</summary>
    public IBrush UsageBrush { get => _usageBrush; private set => Set(ref _usageBrush, value); }

    /// <summary>用服务端用量快照更新展示。</summary>
    public void SetUsage(int used, int dailyLimit) => Post(() =>
    {
        int limit = dailyLimit > 0 ? dailyLimit : 1;
        double pct = Math.Min(100.0, used * 100.0 / limit);
        UsagePercent = pct;
        UsageText = $"今日 {used} / {dailyLimit}";
        UsageBrush = MakeBrush(pct >= 90 ? "#FF3B5C" : pct >= 70 ? "#FFB020" : "#39FF14");
        HasUsage = true;
    });

    private IBrush _statusBrush = MakeBrush("#6B7A8F");
    /// <summary>状态指示点颜色。</summary>
    public IBrush StatusBrush { get => _statusBrush; private set => Set(ref _statusBrush, value); }

    private bool _busy;
    /// <summary>该源是否正在测试(禁用其测试按钮)。</summary>
    public bool Busy { get => _busy; private set { if (Set(ref _busy, value)) OnPropertyChanged(nameof(NotBusy)); } }
    public bool NotBusy => !_busy;

    private bool _enabled;
    private bool _suppressEnabled;
    /// <summary>该源是否启用(与设置双向同步)。用户切换时经 <see cref="EnabledChanged"/> 写回设置。</summary>
    public bool Enabled
    {
        get => _enabled;
        set { if (Set(ref _enabled, value) && !_suppressEnabled) EnabledChanged?.Invoke(this); }
    }

    /// <summary>用户切换开关时的回调(由父 VM 挂接,写回共享设置)。</summary>
    internal Action<ReputationSourceItem>? EnabledChanged;

    /// <summary>静默设置开关状态(不触发写回,用于从设置同步展示)。</summary>
    public void SetEnabledSilently(bool value)
    {
        _suppressEnabled = true;
        Enabled = value;
        _suppressEnabled = false;
    }

    public void SetTesting() => Post(() =>
    {
        Busy = true;
        State = SourceState.Testing;
        StatusText = "测试中…";
        StatusBrush = MakeBrush("#22D3EE");
        Detail = "正在探测连接…";
    });

    public void SetResult(SourceState state, string message) => Post(() =>
    {
        Busy = false;
        State = state;
        switch (state)
        {
            case SourceState.Online:
                StatusText = "在线";
                StatusBrush = MakeBrush("#39FF14");
                break;
            case SourceState.Offline:
                StatusText = "异常";
                StatusBrush = MakeBrush("#FF3B5C");
                break;
            default:
                StatusText = "未测试";
                StatusBrush = MakeBrush("#6B7A8F");
                break;
        }
        Detail = string.IsNullOrWhiteSpace(message) ? "(无附加信息)" : message;
    });

    private static void Post(Action action)
    {
        if (Dispatcher.UIThread.CheckAccess()) action();
        else Dispatcher.UIThread.Post(action);
    }

    private static IBrush MakeBrush(string hex) => new SolidColorBrush(Avalonia.Media.Color.Parse(hex));
}
