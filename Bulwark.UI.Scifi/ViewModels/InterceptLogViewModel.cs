using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.RegularExpressions;
using Avalonia.Threading;
using Bulwark.Core.Models;
using Bulwark.UI.Services;
using Bulwark.UI.Scifi.Services;

namespace Bulwark.UI.Scifi.ViewModels;

/// <summary>拦截记录页一条记录(结构化,便于清晰展示)。</summary>
public sealed class InterceptLogEntry
{
    public string Time { get; init; } = string.Empty;
    public string ActionText { get; init; } = string.Empty;   // 人话化行为,如"尝试修改注册表"
    public string ActorName { get; init; } = string.Empty;    // 程序名(高亮)
    public string ActorPath { get; init; } = string.Empty;    // 完整路径(次要行)
    public string TargetText { get; init; } = string.Empty;   // 清理后的目标
    public string TypeBadge { get; init; } = string.Empty;    // 类型短标签
    public string Icon { get; init; } = "🚫";
    public bool HasTarget => !string.IsNullOrWhiteSpace(TargetText) && TargetText != "—";

    /// <summary>原始安全事件(含证据链/技战术/进程链),供点开「攻击时间线」回溯。可空(旧记录)。</summary>
    public SecurityEvent? Event { get; init; }
}

/// <summary>拦截记录页 VM:累积「已拦截恶意行为」通知。</summary>
public sealed class InterceptLogViewModel : ObservableObject
{
    public ObservableCollection<InterceptLogEntry> Entries { get; } = new();

    private bool _isEmpty = true;
    public bool IsEmpty { get => _isEmpty; set => Set(ref _isEmpty, value); }

    public InterceptLogViewModel(IpcClient ipc)
    {
        ipc.BlockNotificationReceived += OnBlock;
    }

    private void OnBlock(SecurityEvent e)
    {
        Dispatcher.UIThread.Post(() =>
        {
            Entries.Insert(0, Build(e));
            if (Entries.Count > 300) Entries.RemoveAt(Entries.Count - 1);
            IsEmpty = Entries.Count == 0;
        });
    }

    private static InterceptLogEntry Build(SecurityEvent e)
    {
        var actorName = EventTypeDisplay.ActorName(e);

        return new InterceptLogEntry
        {
            Time = DateTime.Now.ToString("HH:mm:ss"),
            ActionText = EventTypeDisplay.Action(e.Type),
            TypeBadge = EventTypeDisplay.Badge(e.Type),
            Icon = EventTypeDisplay.Icon(e.Type),
            ActorName = actorName,
            ActorPath = e.ActorPath ?? string.Empty,
            TargetText = CleanTarget(e.Target),
            Event = e
        };
    }

    /// <summary>清理目标字符串:把冗长的注册表内核路径转成更易读的 HKxx 形式。</summary>
    private static string CleanTarget(string? target)
    {
        if (string.IsNullOrWhiteSpace(target)) return "—";
        var t = target.Trim();

        // \REGISTRY\USER\S-1-5-21-...\Rest  ->  HKU\...\Rest(去掉冗长 SID)
        var mUser = Regex.Match(t, @"^\\REGISTRY\\USER\\[^\\]+\\(.+)$", RegexOptions.IgnoreCase);
        if (mUser.Success) return "HKCU\\" + mUser.Groups[1].Value;

        var mMachine = Regex.Match(t, @"^\\REGISTRY\\MACHINE\\(.+)$", RegexOptions.IgnoreCase);
        if (mMachine.Success) return "HKLM\\" + mMachine.Groups[1].Value;

        return t;
    }
}
