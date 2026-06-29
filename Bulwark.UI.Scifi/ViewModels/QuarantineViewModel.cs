using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Avalonia.Threading;
using Bulwark.Core.Ipc;
using Bulwark.UI.Services;

namespace Bulwark.UI.Scifi.ViewModels;

/// <summary>隔离区页 VM:请求隔离条目、还原、删除。</summary>
public sealed class QuarantineViewModel : ObservableObject
{
    private readonly IpcClient _ipc;

    public ObservableCollection<QuarantineItemPayload> Items { get; } = new();

    private bool _isEmpty = true;
    public bool IsEmpty { get => _isEmpty; set => Set(ref _isEmpty, value); }

    private string _statusMessage = string.Empty;
    public string StatusMessage { get => _statusMessage; set => Set(ref _statusMessage, value); }

    public QuarantineViewModel(IpcClient ipc)
    {
        _ipc = ipc;
        _ipc.QuarantineListReceived += OnListReceived;
        _ipc.QuarantineActionReceived += OnActionReceived;
        _ipc.ConnectionChanged += connected => { if (connected) Refresh(); };
    }

    public void Refresh() => _ = _ipc.RequestQuarantineListAsync();

    private void OnListReceived(List<QuarantineItemPayload> items)
    {
        Dispatcher.UIThread.Post(() =>
        {
            Items.Clear();
            foreach (var i in items) Items.Add(i);
            IsEmpty = Items.Count == 0;
        });
    }

    private void OnActionReceived(QuarantineActionResultPayload result)
    {
        Dispatcher.UIThread.Post(() =>
        {
            StatusMessage = result.Success ? "操作成功" : $"失败: {result.Message}";
        });
    }

    public void Restore(QuarantineItemPayload item) => _ = _ipc.RestoreQuarantineAsync(item.Id);
    public void Delete(QuarantineItemPayload item) => _ = _ipc.DeleteQuarantineAsync(item.Id);
}
