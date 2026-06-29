using System;
using System.Collections.ObjectModel;
using System.Linq;
using Avalonia;
using Avalonia.Media;
using Avalonia.Threading;
using Bulwark.Core.Ipc;
using Bulwark.Core.Models;
using Bulwark.UI.Services;

namespace Bulwark.UI.Scifi.ViewModels;

/// <summary>
/// 持久化审计页 VM:请求服务枚举系统自启动持久化项,按风险展示并支持刷新。
/// 只读审计 —— 不在此页做任何处置,清理仍走既有规则/隔离流程。
/// </summary>
public sealed class PersistenceViewModel : ObservableObject
{
    private readonly IpcClient _ipc;

    public ObservableCollection<PersistenceRow> Items { get; } = new();

    private bool _isLoading;
    public bool IsLoading { get => _isLoading; set { if (Set(ref _isLoading, value)) OnPropertyChanged(nameof(NotLoading)); } }
    public bool NotLoading => !_isLoading;

    private bool _isEmpty = true;
    public bool IsEmpty { get => _isEmpty; set => Set(ref _isEmpty, value); }

    private string _statusMessage = "尚未扫描";
    public string StatusMessage { get => _statusMessage; set => Set(ref _statusMessage, value); }

    public PersistenceViewModel(IpcClient ipc)
    {
        _ipc = ipc;
        _ipc.PersistenceListReceived += OnReceived;
    }

    /// <summary>请求服务扫描自启动持久化项。</summary>
    public void Refresh()
    {
        if (!_ipc.IsConnected)
        {
            StatusMessage = "未连接服务";
            return;
        }
        IsLoading = true;
        StatusMessage = "正在扫描自启动项…";
        _ = _ipc.RequestPersistenceListAsync();
    }

    private void OnReceived(PersistenceListResponsePayload payload)
    {
        Dispatcher.UIThread.Post(() =>
        {
            Items.Clear();
            foreach (var e in payload.Entries)
                Items.Add(new PersistenceRow(e));
            IsLoading = false;
            IsEmpty = Items.Count == 0;
            int risky = Items.Count(i => i.Entry.RiskScore >= 50);
            StatusMessage = string.IsNullOrEmpty(payload.Message)
                ? $"共 {Items.Count} 项,其中 {risky} 项需关注"
                : $"{payload.Message}({risky} 项需关注)";
        });
    }
}

/// <summary>持久化项的展示包装:把风险分映射为等级标签与色彩,聚合 ATT&CK 与原因文本。</summary>
public sealed class PersistenceRow
{
    public PersistenceEntry Entry { get; }

    public PersistenceRow(PersistenceEntry e)
    {
        Entry = e;
        Category = CategoryLabel(e.Category);
        Name = e.Name;
        Location = e.Location;
        Command = e.Command;
        ScoreText = e.RiskScore.ToString();

        (Level, Accent) = e.RiskScore switch
        {
            >= 80 => ("高危", Brush("StateDangerBrush")),
            >= 50 => ("可疑", Brush("StateWarnBrush")),
            > 0   => ("关注", Brush("NeonCyanBrush")),
            _     => ("正常", Brush("StateOkBrush"))
        };

        TechniquesText = e.Techniques is { Count: > 0 } ? string.Join("  ·  ", e.Techniques) : string.Empty;
        ReasonsText = e.RiskReasons is { Count: > 0 } ? string.Join("; ", e.RiskReasons.Take(4)) : string.Empty;
    }

    public string Category { get; }
    public string Name { get; }
    public string Location { get; }
    public string Command { get; }
    public string ScoreText { get; }
    public string Level { get; }
    public IBrush Accent { get; }
    public string TechniquesText { get; }
    public bool HasTechniques => !string.IsNullOrEmpty(TechniquesText);
    public string ReasonsText { get; }
    public bool HasReasons => !string.IsNullOrEmpty(ReasonsText);

    private static string CategoryLabel(PersistenceCategory c) => c switch
    {
        PersistenceCategory.RegistryRun => "Run 键",
        PersistenceCategory.RegistryRunOnce => "RunOnce",
        PersistenceCategory.StartupFolder => "启动文件夹",
        PersistenceCategory.ScheduledTask => "计划任务",
        PersistenceCategory.Service => "服务",
        PersistenceCategory.WmiSubscription => "WMI 订阅",
        PersistenceCategory.IfeoDebugger => "映像劫持",
        PersistenceCategory.Winlogon => "Winlogon",
        PersistenceCategory.AppInitDll => "AppInit",
        _ => "其它"
    };

    private static IBrush Brush(string key)
        => Application.Current is { } app && app.TryGetResource(key, app.ActualThemeVariant, out var v) && v is IBrush b
            ? b
            : Avalonia.Media.Brushes.Gray;
}
