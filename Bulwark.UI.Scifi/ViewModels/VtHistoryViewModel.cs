using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Avalonia.Media;
using Avalonia.Threading;
using Bulwark.Core.Models;
using Bulwark.UI.Services;
using Color = Avalonia.Media.Color;
using Brushes = Avalonia.Media.Brushes;

namespace Bulwark.UI.Scifi.ViewModels;

/// <summary>
/// 「VT 查询记录」视图 VM:持久展示每一次 VirusTotal 扫描(双击上传扫描 / 手动查询)的
/// 实时进度与最终结论。数据来自服务端:打开时请求历史快照,之后随扫描进度增量更新。
/// </summary>
public sealed class VtHistoryViewModel : ObservableObject
{
    private readonly IpcClient _ipc;

    public ObservableCollection<VtScanItem> Records { get; } = new();

    private bool _isEmpty = true;
    public bool IsEmpty { get => _isEmpty; set => Set(ref _isEmpty, value); }

    public VtHistoryViewModel(IpcClient ipc)
    {
        _ipc = ipc;
        _ipc.VtHistoryReceived += OnHistory;
        _ipc.VtScanUpdateReceived += OnUpdate;
        _ipc.ConnectionChanged += connected => { if (connected) Refresh(); };
    }

    /// <summary>向服务端请求最新历史记录列表。</summary>
    public void Refresh() => _ = _ipc.RequestVtHistoryAsync();

    private void OnHistory(List<VtScanRecord> list)
    {
        Dispatcher.UIThread.Post(() =>
        {
            Records.Clear();
            foreach (var r in list)
                Records.Add(new VtScanItem(r));
            IsEmpty = Records.Count == 0;
        });
    }

    private void OnUpdate(VtScanRecord r)
    {
        Dispatcher.UIThread.Post(() =>
        {
            for (int i = 0; i < Records.Count; i++)
            {
                if (Records[i].Id == r.Id)
                {
                    Records[i].Update(r);
                    // 把最新更新的项移到顶部(最近活动在前)。
                    if (i > 0)
                    {
                        var item = Records[i];
                        Records.RemoveAt(i);
                        Records.Insert(0, item);
                    }
                    IsEmpty = Records.Count == 0;
                    return;
                }
            }
            Records.Insert(0, new VtScanItem(r));
            IsEmpty = Records.Count == 0;
        });
    }
}

/// <summary>「VT 查询记录」列表中的一行(可随进度更新)。</summary>
public sealed class VtScanItem : ObservableObject
{
    public Guid Id { get; }

    public VtScanItem(VtScanRecord r)
    {
        Id = r.Id;
        Update(r);
    }

    private string _fileName = string.Empty;
    public string FileName { get => _fileName; set => Set(ref _fileName, value); }

    private string _filePath = string.Empty;
    public string FilePath { get => _filePath; set => Set(ref _filePath, value); }

    private string _sha256 = string.Empty;
    public string Sha256 { get => _sha256; set => Set(ref _sha256, value); }

    private string _statusText = string.Empty;
    public string StatusText { get => _statusText; set => Set(ref _statusText, value); }

    private IBrush _statusBrush = Brushes.Gray;
    public IBrush StatusBrush { get => _statusBrush; set => Set(ref _statusBrush, value); }

    private string _detail = string.Empty;
    public string Detail { get => _detail; set => Set(ref _detail, value); }

    private string _timeText = string.Empty;
    public string TimeText { get => _timeText; set => Set(ref _timeText, value); }

    private string _source = string.Empty;
    public string Source { get => _source; set => Set(ref _source, value); }

    public void Update(VtScanRecord r)
    {
        FileName = string.IsNullOrEmpty(r.FileName) ? "(未知文件)" : r.FileName;
        FilePath = r.FilePath;
        Sha256 = r.Sha256;
        Source = r.Source;
        Detail = r.Message ?? string.Empty;
        TimeText = r.TimestampUtc.ToLocalTime().ToString("MM-dd HH:mm:ss");

        // 状态文案与颜色:终态按结论上色,进行中按阶段显示。
        if (!r.IsTerminal)
        {
            StatusText = r.Stage switch
            {
                VtScanStage.Queued => "排队中",
                VtScanStage.Querying => "查询中",
                VtScanStage.Uploading => $"上传中 {r.Percent}%",
                VtScanStage.Analyzing => "云端分析中",
                _ => "进行中"
            };
            StatusBrush = new SolidColorBrush(Color.Parse("#3BA0FF"));
            return;
        }

        switch (r.Outcome)
        {
            case VtScanOutcome.Malicious:
                StatusText = $"恶意 {r.Malicious}/{r.TotalEngines}";
                StatusBrush = new SolidColorBrush(Color.Parse("#FF3B5C"));
                break;
            case VtScanOutcome.Suspicious:
                StatusText = $"可疑 {r.Malicious}/{r.TotalEngines}";
                StatusBrush = new SolidColorBrush(Color.Parse("#FFB020"));
                break;
            case VtScanOutcome.Clean:
                StatusText = $"干净 0/{r.TotalEngines}";
                StatusBrush = new SolidColorBrush(Color.Parse("#1BE38B"));
                break;
            case VtScanOutcome.Error:
                StatusText = "失败";
                StatusBrush = new SolidColorBrush(Color.Parse("#FFB020"));
                break;
            default:
                StatusText = "未收录";
                StatusBrush = new SolidColorBrush(Color.Parse("#8A93A6"));
                break;
        }
    }
}
