using System;
using System.Collections.Generic;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Bulwark.Core.Models;
using Bulwark.UI.Scifi.Services;

namespace Bulwark.UI.Scifi.Views;

/// <summary>
/// 攻击时间线窗口:把一个安全事件的「判定依据(证据链)+ 命中技战术(ATT&amp;CK)+
/// 进程链上下文(攻击叙事)」渲染成一条可读的可解释性时间线。
///
/// 数据全部来自 <see cref="SecurityEvent"/>(由服务端各分析器填充,经 IPC 传到 UI),
/// 本窗口只做展示,不发起任何处置。供拦截记录 / 裁决弹窗等处复用回溯「为什么这么判」。
/// </summary>
public partial class AttackTimelineWindow : Window
{
    private readonly SecurityEvent _event;

    public AttackTimelineWindow() : this(new SecurityEvent()) { }

    public AttackTimelineWindow(SecurityEvent e)
    {
        _event = e ?? new SecurityEvent();
        InitializeComponent();
        Populate();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void Populate()
    {
        SetText("ActorNameText", EventTypeDisplay.ActorNameWithPid(_event));
        SetText("ActorPathText", string.IsNullOrEmpty(_event.ActorPath) ? "—" : _event.ActorPath);
        SetText("BehaviorText", EventTypeDisplay.Action(_event.Type));
        SetText("TargetText", string.IsNullOrWhiteSpace(_event.Target) ? "—" : _event.Target);
        SetText("ScoreText", _event.RiskScore.ToString());
        SetText("TimeText", "· " + _event.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));

        PopulateTechniques();
        PopulateChain();
        PopulateEvidence();
    }

    private void PopulateTechniques()
    {
        var section = this.FindControl<StackPanel>("TechniqueSection");
        var list = this.FindControl<ItemsControl>("TechniqueList");
        var techniques = _event.Techniques;
        if (techniques is { Count: > 0 })
        {
            if (list is not null) list.ItemsSource = techniques;
        }
        else if (section is not null)
        {
            section.IsVisible = false;
        }
    }

    /// <summary>把进程链上下文渲染成按时间排列的攻击叙事步骤。</summary>
    private void PopulateChain()
    {
        var section = this.FindControl<StackPanel>("ChainSection");
        var list = this.FindControl<ItemsControl>("ChainList");
        if (list is null) return;

        var chain = _event.ChainContext;
        if (chain is null || chain.Count == 0)
        {
            if (section is not null) section.IsVisible = false;
            return;
        }

        var rows = new List<ChainRow>(chain.Count);
        foreach (var c in chain)
        {
            string brushKey = c.RiskScore >= 80 ? "StateDangerBrush"
                : c.RiskScore >= 50 ? "StateWarnBrush"
                : "NeonCyanBrush";
            string actorName = string.IsNullOrEmpty(c.ActorPath)
                ? $"PID {c.ActorPid}"
                : $"{System.IO.Path.GetFileName(c.ActorPath)} (PID {c.ActorPid})";
            rows.Add(new ChainRow
            {
                TimeText = c.TimestampUtc.ToLocalTime().ToString("HH:mm:ss"),
                Noun = EventTypeDisplay.Noun(c.Type),
                ActorText = actorName,
                TargetText = c.Target ?? string.Empty,
                ScoreText = c.RiskScore > 0 ? c.RiskScore.ToString() : string.Empty,
                Accent = Brush(brushKey)
            });
        }
        list.ItemsSource = rows;
    }

    /// <summary>把结构化证据链渲染成按类别着色的决策时间线(与裁决弹窗一致)。</summary>
    private void PopulateEvidence()
    {
        var section = this.FindControl<StackPanel>("EvidenceSection");
        var list = this.FindControl<ItemsControl>("EvidenceList");
        if (list is null) return;

        var chain = _event.EvidenceChain;
        if (chain is null || chain.Count == 0)
        {
            // 回退到扁平 RiskReasons,保证旧事件仍有展示。
            if (_event.RiskReasons is { Count: > 0 } reasons)
            {
                list.ItemsSource = reasons.ConvertAll(r => new EvidenceRow
                {
                    KindLabel = "原因",
                    Source = "—",
                    Description = r,
                    Accent = Brush("TextDimBrush")
                });
            }
            else if (section is not null)
            {
                section.IsVisible = false;
            }
            return;
        }

        var rows = new List<EvidenceRow>(chain.Count);
        foreach (var ev in chain)
        {
            var (label, brushKey) = ev.Kind switch
            {
                EvidenceKind.HardIndicator => ("硬指标", "StateDangerBrush"),
                EvidenceKind.Corroboration => ("互证升格", "StateDangerBrush"),
                EvidenceKind.SoftSignal => ("软信号", "StateWarnBrush"),
                EvidenceKind.Trust => ("信任", "StateOkBrush"),
                EvidenceKind.Rule => ("规则", "NeonCyanBrush"),
                EvidenceKind.Decision => ("裁决", "NeonCyanBrush"),
                _ => ("信息", "TextDimBrush")
            };
            rows.Add(new EvidenceRow
            {
                KindLabel = label,
                Source = ev.Source,
                Description = ev.Description,
                ScoreText = ev.ScoreDelta == 0 ? string.Empty
                    : (ev.ScoreDelta > 0 ? $"+{ev.ScoreDelta}" : ev.ScoreDelta.ToString()),
                Accent = Brush(brushKey),
                Technique = ev.Technique ?? string.Empty
            });
        }
        list.ItemsSource = rows;
    }

    private void SetText(string name, string value)
    {
        var tb = this.FindControl<TextBlock>(name);
        if (tb is not null) tb.Text = value;
    }

    private static IBrush Brush(string key)
        => Application.Current is { } app && app.TryGetResource(key, app.ActualThemeVariant, out var v) && v is IBrush b
            ? b
            : Avalonia.Media.Brushes.Gray;

    private void Close_Click(object? sender, RoutedEventArgs e) => Close();

    /// <summary>按住标题栏拖动移动窗口(NoChrome 无原生标题栏,需手动发起拖拽)。</summary>
    private void TitleBar_PointerPressed(object? sender, Avalonia.Input.PointerPressedEventArgs e)
    {
        if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
            BeginMoveDrag(e);
    }
}

/// <summary>进程链单步的展示模型(供 ChainList 的 ItemsControl 绑定)。</summary>
public sealed class ChainRow
{
    public string TimeText { get; init; } = string.Empty;
    public string Noun { get; init; } = string.Empty;
    public string ActorText { get; init; } = string.Empty;
    public string TargetText { get; init; } = string.Empty;
    public string ScoreText { get; init; } = string.Empty;
    public IBrush Accent { get; init; } = Avalonia.Media.Brushes.Gray;
    public bool HasTarget => !string.IsNullOrWhiteSpace(TargetText) && TargetText != "—";
}
