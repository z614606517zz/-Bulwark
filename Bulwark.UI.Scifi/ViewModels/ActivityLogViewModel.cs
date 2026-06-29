using System;
using System.Collections.ObjectModel;
using System.Text.RegularExpressions;
using Avalonia.Media;
using Avalonia.Threading;
using Bulwark.Core.Ipc;
using Bulwark.Core.Models;
using Bulwark.UI.Services;
using Bulwark.UI.Scifi.Services;

namespace Bulwark.UI.Scifi.ViewModels;

/// <summary>活动日志一条记录(结构化)。保留完整事件以便点开攻击时间线回溯。</summary>
public sealed class ActivityLogEntry
{
    public string Time { get; init; } = string.Empty;
    public string ActionText { get; init; } = string.Empty;
    public string ActorName { get; init; } = string.Empty;
    public string ActorPath { get; init; } = string.Empty;
    public string TargetText { get; init; } = string.Empty;
    public string TypeBadge { get; init; } = string.Empty;
    public string Icon { get; init; } = "•";

    /// <summary>裁决文案(放行 / 询问 / 已拦截)。</summary>
    public string VerdictText { get; init; } = string.Empty;

    /// <summary>裁决徽标着色。</summary>
    public IBrush VerdictBrush { get; init; } = Avalonia.Media.Brushes.Gray;

    /// <summary>风险分(0 时不展示)。</summary>
    public string ScoreText { get; init; } = string.Empty;
    public bool HasScore => !string.IsNullOrEmpty(ScoreText);

    public bool HasTarget => !string.IsNullOrWhiteSpace(TargetText) && TargetText != "—";

    /// <summary>原始安全事件(含证据链/技战术/进程链),供点开「攻击时间线」回溯。</summary>
    public SecurityEvent? Event { get; init; }
}

/// <summary>
/// 活动日志页 VM:累积所有「值得回溯」的事件(放行带风险 / 询问 / 拦截),
/// 每条保留完整事件,双击即可打开攻击时间线。与「拦截记录」(仅拦截)互补。
/// </summary>
public sealed class ActivityLogViewModel : ObservableObject
{
    public ObservableCollection<ActivityLogEntry> Entries { get; } = new();

    private bool _isEmpty = true;
    public bool IsEmpty { get => _isEmpty; set => Set(ref _isEmpty, value); }

    public ActivityLogViewModel(IpcClient ipc)
    {
        ipc.EventLogReceived += OnEventLog;
    }

    private void OnEventLog(EventLogPayload payload)
    {
        if (payload.Event is null) return;
        Dispatcher.UIThread.Post(() =>
        {
            Entries.Insert(0, Build(payload));
            if (Entries.Count > 400) Entries.RemoveAt(Entries.Count - 1);
            IsEmpty = Entries.Count == 0;
        });
    }

    private static ActivityLogEntry Build(EventLogPayload p)
    {
        var e = p.Event;
        var (text, brushKey) = p.Action switch
        {
            VerdictAction.Block => ("已拦截", "StateDangerBrush"),
            VerdictAction.Ask => ("询问", "StateWarnBrush"),
            _ => ("放行", "StateOkBrush")
        };

        return new ActivityLogEntry
        {
            Time = e.TimestampUtc.ToLocalTime().ToString("HH:mm:ss"),
            ActionText = EventTypeDisplay.Action(e.Type),
            TypeBadge = EventTypeDisplay.Badge(e.Type),
            Icon = EventTypeDisplay.Icon(e.Type),
            ActorName = EventTypeDisplay.ActorName(e),
            ActorPath = e.ActorPath ?? string.Empty,
            TargetText = CleanTarget(e.Target),
            VerdictText = text,
            VerdictBrush = Brush(brushKey),
            ScoreText = e.RiskScore > 0 ? e.RiskScore.ToString() : string.Empty,
            Event = e
        };
    }

    private static string CleanTarget(string? target)
    {
        if (string.IsNullOrWhiteSpace(target)) return "—";
        var t = target.Trim();
        var mUser = Regex.Match(t, @"^\\REGISTRY\\USER\\[^\\]+\\(.+)$", RegexOptions.IgnoreCase);
        if (mUser.Success) return "HKCU\\" + mUser.Groups[1].Value;
        var mMachine = Regex.Match(t, @"^\\REGISTRY\\MACHINE\\(.+)$", RegexOptions.IgnoreCase);
        if (mMachine.Success) return "HKLM\\" + mMachine.Groups[1].Value;
        return t;
    }

    private static IBrush Brush(string key)
        => Avalonia.Application.Current is { } app
           && app.TryGetResource(key, app.ActualThemeVariant, out var v) && v is IBrush b
            ? b
            : Avalonia.Media.Brushes.Gray;
}
