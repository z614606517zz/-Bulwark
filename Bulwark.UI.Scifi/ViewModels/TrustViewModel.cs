using System.Collections.Generic;
using System.Collections.ObjectModel;
using Avalonia.Threading;
using Bulwark.Core.Models;
using Bulwark.UI.Services;

namespace Bulwark.UI.Scifi.ViewModels;

/// <summary>文件信任页 VM:请求信任列表、添加、移除。</summary>
public sealed class TrustViewModel : ObservableObject
{
    private readonly IpcClient _ipc;

    public ObservableCollection<DefenseRule> Entries { get; } = new();

    private bool _isEmpty = true;
    public bool IsEmpty { get => _isEmpty; set => Set(ref _isEmpty, value); }

    public TrustViewModel(IpcClient ipc)
    {
        _ipc = ipc;
        _ipc.TrustListReceived += OnTrustReceived;
        _ipc.ConnectionChanged += connected => { if (connected) Refresh(); };
    }

    public void Refresh() => _ = _ipc.RequestTrustListAsync();

    private void OnTrustReceived(List<DefenseRule> entries)
    {
        Dispatcher.UIThread.Post(() =>
        {
            Entries.Clear();
            foreach (var e in entries) Entries.Add(e);
            IsEmpty = Entries.Count == 0;
        });
    }

    public void Add(string actorPath, string? note = null) => _ = _ipc.AddTrustAsync(actorPath, note);
    public void Remove(DefenseRule entry) => _ = _ipc.RemoveTrustAsync(entry.Id);
}
