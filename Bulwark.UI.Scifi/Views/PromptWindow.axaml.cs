using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Avalonia.Threading;
using Bulwark.Core.Models;
using Bulwark.UI.Scifi.Services;

namespace Bulwark.UI.Scifi.Views;

public partial class PromptWindow : Window
{
    private readonly SecurityEvent _event;
    private VerdictAction _result = VerdictAction.Block;
    private readonly CancellationTokenSource _cts = new();

    /// <summary>无操作自动关闭倒计时(秒)。到 0 时按默认裁决(拦截)关闭。</summary>
    private const int AutoCloseSeconds = 15;
    private int _remaining = AutoCloseSeconds;
    private Avalonia.Threading.DispatcherTimer? _countdownTimer;
    private bool _aiRequested;

    public VerdictAction ResultAction => _result;
    public bool Remember => this.FindControl<CheckBox>("RememberCheck")?.IsChecked == true;

    public Bulwark.Core.Ipc.RememberScope Scope =>
        this.FindControl<ComboBox>("ScopeCombo")?.SelectedIndex switch
        {
            1 => Bulwark.Core.Ipc.RememberScope.Session,
            2 => Bulwark.Core.Ipc.RememberScope.OneHour,
            3 => Bulwark.Core.Ipc.RememberScope.OneDay,
            _ => Bulwark.Core.Ipc.RememberScope.Permanent
        };

    public PromptWindow() : this(new SecurityEvent()) { }

    public PromptWindow(SecurityEvent e)
    {
        _event = e ?? new SecurityEvent();
        InitializeComponent();
        Populate();
        Closed += (_, _) => { _cts.Cancel(); _countdownTimer?.Stop(); };
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    protected override void OnOpened(System.EventArgs e)
    {
        base.OnOpened(e);
        StartCountdown();
        try
        {
            var screen = Screens.ScreenFromWindow(this) ?? Screens.Primary ?? Screens.All[0];
            if (screen is null) return;

            var wa = screen.WorkingArea;
            double scale = screen.Scaling <= 0 ? 1.0 : screen.Scaling;
            int winW = (int)(Width * scale);
            int winH = (int)(Height * scale);
            int margin = (int)(16 * scale);

            int x = wa.X + wa.Width - winW - margin;
            int y = wa.Y + wa.Height - winH - margin;
            Position = new PixelPoint(System.Math.Max(wa.X, x), System.Math.Max(wa.Y, y));
        }
        catch
        {
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }
    }

    private void Populate()
    {
        SetText("HeaderTitle", EventTypeDisplay.Action(_event.Type));
        SetText("ActorText", string.IsNullOrEmpty(_event.ActorPath) ? "未知" : _event.ActorPath);
        SetText("BehaviorText", EventTypeDisplay.Action(_event.Type));
        SetText("TargetText", string.IsNullOrEmpty(_event.Target) ? "—" : _event.Target);
        SetText("DescText", string.IsNullOrWhiteSpace(_event.FileDescription)
            ? EventTypeDisplay.Badge(_event.Type) + " 行为" : _event.FileDescription!);
        SetText("CommandText", string.IsNullOrWhiteSpace(_event.CommandLine) ? "—" : _event.CommandLine!);
        SetText("Sha256Text", string.IsNullOrWhiteSpace(_event.ActorHash) ? "—" : _event.ActorHash!);
        SetText("ScoreText", _event.RiskScore.ToString());

        PopulateHeader();
        PopulateSignature();
        PopulateReputation();
        PopulateTechniques();
        PopulateChain();
        PopulateEvidence();
    }

    private void PopulateHeader()
    {
        int score = _event.RiskScore;
        var (level, sub, badge, c0, c1, icon) = score >= 80
            ? ("高风险", "检测到危险行为,建议立即拦截", "高危", "#7A1B0E", "#5E1A0A", "⚠")
            : score >= 50
                ? ("中等风险", "请确认是否为预期操作", "可疑", "#7A4A0E", "#5E3A0A", "🛡")
                : ("低风险", "未发现明显危险信号,请自行确认", "提示", "#0E3A52", "#0A2E44", "🛡");

        SetText("HeaderSubtitle", level + " · " + sub);
        SetText("HeaderBadgeText", badge);
        SetText("HeaderIcon", icon);
        SetText("RiskLabelText", level);

        var header = this.FindControl<Border>("HeaderBorder");
        if (header is not null)
        {
            header.Background = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(1, 0, RelativeUnit.Relative),
                GradientStops =
                {
                    new GradientStop(Avalonia.Media.Color.Parse(c0), 0),
                    new GradientStop(Avalonia.Media.Color.Parse(c1), 1)
                }
            };
        }

        var scoreText = this.FindControl<TextBlock>("ScoreText");
        if (scoreText is not null)
            scoreText.Foreground = Brush(score >= 80 ? "StateDangerBrush"
                : score >= 50 ? "StateWarnBrush" : "NeonCyanBrush");
    }

    private void PopulateSignature()
    {
        var icon = this.FindControl<TextBlock>("SignIcon");
        string text;
        string brushKey;
        if (_event.SignatureMismatch || _event.CertRevoked || _event.SignedAfterCertExpiry)
        {
            text = "签名异常(篡改/吊销/过期)";
            brushKey = "StateDangerBrush";
        }
        else if (_event.ActorSigned)
        {
            text = string.IsNullOrWhiteSpace(_event.ActorPublisher)
                ? "已签名" : "已验证:" + _event.ActorPublisher;
            brushKey = "StateOkBrush";
        }
        else
        {
            text = "无数字签名";
            brushKey = "TextDimBrush";
        }
        SetText("SignText", text);
        if (icon is not null) icon.Foreground = Brush(brushKey);
    }

    private void PopulateReputation()
    {
        var icon = this.FindControl<TextBlock>("VtIcon");
        var rep = _event.Reputation;
        string text;
        string brushKey;
        if (rep is null || rep.Verdict == ReputationVerdict.Unknown)
        {
            text = "无情报数据";
            brushKey = "TextDimBrush";
        }
        else
        {
            string head = rep.Verdict switch
            {
                ReputationVerdict.Malicious => "恶意",
                ReputationVerdict.Suspicious => "可疑",
                _ => "未检出"
            };
            string stats = rep.TotalEngines > 0 ? $"{rep.Malicious}/{rep.TotalEngines} 引擎判定恶意" : head;
            text = $"{head} · {stats}";
            brushKey = rep.Verdict switch
            {
                ReputationVerdict.Malicious => "StateDangerBrush",
                ReputationVerdict.Suspicious => "StateWarnBrush",
                _ => "StateOkBrush"
            };
        }
        SetText("VtText", text);
        if (icon is not null) icon.Foreground = Brush(brushKey);
    }

    private void PopulateTechniques()
    {
        var list = this.FindControl<ItemsControl>("TechniqueList");
        var techniques = _event.Techniques;
        if (list is null) return;
        list.IsVisible = techniques is { Count: > 0 };
        if (techniques is { Count: > 0 }) list.ItemsSource = techniques;
    }

    private void PopulateChain()
    {
        var section = this.FindControl<Expander>("ChainSection");
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
                : c.RiskScore >= 50 ? "StateWarnBrush" : "NeonCyanBrush";
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

    private void PopulateEvidence()
    {
        var section = this.FindControl<Expander>("EvidenceSection");
        var list = this.FindControl<ItemsControl>("EvidenceList");
        if (list is null) return;

        var chain = _event.EvidenceChain;
        if (chain is null || chain.Count == 0)
        {
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
                ScoreText = ev.ScoreDelta == 0 ? string.Empty : (ev.ScoreDelta > 0 ? $"+{ev.ScoreDelta}" : ev.ScoreDelta.ToString()),
                Accent = Brush(brushKey),
                Technique = ev.Technique ?? string.Empty
            });
        }
        list.ItemsSource = rows;
    }

    /// <summary>启动 15 秒倒计时:每秒刷新「拦截」按钮文案,归零时按默认裁决(拦截)自动关闭。</summary>
    private void StartCountdown()
    {
        UpdateCountdownText();
        _countdownTimer = new Avalonia.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _countdownTimer.Tick += (_, _) =>
        {
            _remaining--;
            if (_remaining <= 0)
            {
                _countdownTimer?.Stop();
                _result = VerdictAction.Block; // 超时默认拦截(安全优先)
                Close();
                return;
            }
            UpdateCountdownText();
        };
        _countdownTimer.Start();
    }

    private void UpdateCountdownText()
    {
        var btn = this.FindControl<Button>("BlockButton");
        if (btn is not null) btn.Content = $"✕ 拦截 ({_remaining})";
    }

    private void SetText(string name, string value)
    {
        var tb = this.FindControl<TextBlock>(name);
        if (tb is not null) tb.Text = value;
    }

    /// <summary>用户点击「生成攻击叙事」:按需调用大模型解释本行为(默认不自动调,省 Credits)。
    /// 点击即停止自动关闭倒计时,避免分析未完成窗口就被关掉。</summary>
    private void AiExplain_Click(object? sender, RoutedEventArgs e)
    {
        if (_aiRequested) return;
        _aiRequested = true;
        _countdownTimer?.Stop(); // 用户已介入,取消自动关闭
        var btn = this.FindControl<Button>("AiButton");
        if (btn is not null) btn.IsVisible = false;
        var aiText = this.FindControl<TextBlock>("AiText");
        if (aiText is not null) { aiText.IsVisible = true; aiText.Text = "正在分析该行为…"; }
        _ = LoadAiAsync();
    }

    private async System.Threading.Tasks.Task LoadAiAsync()
    {
        var aiText = this.FindControl<TextBlock>("AiText");
        if (aiText is null) return;

        try
        {
            if (!App.Ai.IsConfigured)
            {
                aiText.Text = "未配置 AI · 在「设置 → AI / 大模型研判」中填入 API Key 可解锁本节解读。";
                aiText.Foreground = new SolidColorBrush(Avalonia.Media.Color.Parse("#5C708C"));
                return;
            }

            var explanation = await App.Ai.ExplainEventAsync(_event, _cts.Token);
            if (_cts.IsCancellationRequested) return;
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                aiText.Text = string.IsNullOrWhiteSpace(explanation)
                    ? "AI 暂未给出明确解读。"
                    : explanation!;
            });
        }
        catch
        {
            if (!_cts.IsCancellationRequested)
                await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => aiText.Text = "AI 解读失败,请检查网络或配置。");
        }
    }

    private static IBrush Brush(string key)
        => Application.Current is { } app && app.TryGetResource(key, app.ActualThemeVariant, out var v) && v is IBrush b
            ? b
            : Avalonia.Media.Brushes.Gray;

    private void TitleBar_PointerPressed(object? sender, Avalonia.Input.PointerPressedEventArgs e)
    {
        if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
            BeginMoveDrag(e);
    }

    private void Allow_Click(object? sender, RoutedEventArgs e)
    {
        _countdownTimer?.Stop();
        _result = VerdictAction.Allow;
        Close();
    }

    private void Block_Click(object? sender, RoutedEventArgs e)
    {
        _countdownTimer?.Stop();
        _result = VerdictAction.Block;
        Close();
    }
}

/// <summary>证据链单行的展示模型(供 PromptWindow 的 ItemsControl 绑定)。</summary>
public sealed class EvidenceRow
{
    public string KindLabel { get; init; } = string.Empty;
    public string Source { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string ScoreText { get; init; } = string.Empty;
    public IBrush Accent { get; init; } = Avalonia.Media.Brushes.Gray;
    public string Technique { get; init; } = string.Empty;
    public bool HasTechnique => !string.IsNullOrEmpty(Technique);
}
