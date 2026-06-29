using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Bulwark.Core.Models;
using Bulwark.UI.Scifi.Services;

namespace Bulwark.UI.Scifi.Views;

public partial class BlockNotifyWindow : Window
{
    /// <summary>当前屏幕右下角堆叠的活跃 toast(用于纵向排列)。</summary>
    private static readonly object _sync = new();
    private static readonly List<BlockNotifyWindow> _active = new();
    private static readonly Queue<BlockNotifyWindow> _queue = new();
    private const int MaxVisible = 2;   // 同屏最多显示数(卡片较大,取小值),其余排队
    private const int MaxQueued = 30;   // 排队上限,超出丢弃最旧的
    private const int Gap = 8;          // 相邻 toast 间距
    private const int RightMargin = 16; // 右边距
    private const int BottomMargin = 16;// 任务栏上方留白
    private const int AutoCloseSeconds = 8;
    private const int MaxLifetimeSeconds = 25; // 硬上限:AI 卡住时也最终关闭

    private SecurityEvent _event;
    private readonly CancellationTokenSource _cts = new();
    private readonly string _coalesceKey;
    private int _count = 1;
    private DispatcherTimer? _closeTimer;
    private DispatcherTimer? _maxLifeTimer;
    private bool _readCountdownStarted;

    public BlockNotifyWindow() : this(new SecurityEvent()) { }

    public BlockNotifyWindow(SecurityEvent e)
    {
        _event = e;
        _coalesceKey = MakeKey(e);
        InitializeComponent();
        FillDetails(e);

        Opened += (_, _) =>
        {
            Reflow();
            StartMaxLifetime();          // 硬上限兜底
            StartOrResetAutoClose();     // 立即开始阅读倒计时,不再自动等待 AI(AI 改为按需点击)
        };
        Closed += (_, _) =>
        {
            _cts.Cancel();
            _closeTimer?.Stop();
            _maxLifeTimer?.Stop();
            BlockNotifyWindow? next = null;
            lock (_sync)
            {
                _active.Remove(this);
                if (_queue.Count > 0)
                {
                    next = _queue.Dequeue();
                    _active.Add(next);
                }
            }
            Reflow();
            next?.Show();
        };
    }

    /// <summary>合并键:同一进程(PID + 路径)的多条拦截合并到同一通知里计数。</summary>
    private static string MakeKey(SecurityEvent e)
        => $"{e.ActorPid}|{e.ActorPath}";

    /// <summary>
    /// 创建并按"同进程合并 + 同屏限量 + 排队"策略显示一个拦截通知。必须在 UI 线程调用。
    /// 同一进程已有通知时,只在原通知上累加计数并刷新,不再新开窗口。
    /// </summary>
    public static void Notify(SecurityEvent e)
    {
        var key = MakeKey(e);
        BlockNotifyWindow? existing = null;
        BlockNotifyWindow? toShow = null;

        lock (_sync)
        {
            foreach (var w in _active)
                if (w._coalesceKey == key) { existing = w; break; }
            if (existing is null)
                foreach (var w in _queue)
                    if (w._coalesceKey == key) { existing = w; break; }

            if (existing is null)
            {
                var w = new BlockNotifyWindow(e);
                if (_active.Count < MaxVisible) { _active.Add(w); toShow = w; }
                else
                {
                    if (_queue.Count >= MaxQueued) _queue.Dequeue();
                    _queue.Enqueue(w);
                }
            }
        }

        existing?.Bump(e);
        toShow?.Show();
    }

    /// <summary>同进程又一条拦截:累加计数、刷新为最新一条明细、重置自动关闭倒计时。</summary>
    private void Bump(SecurityEvent e)
    {
        _count++;
        _event = e;
        FillDetails(e);
        var title = this.FindControl<TextBlock>("TitleText");
        if (title is not null) title.Text = $"已拦截 {_count} 项危险行为";
        var lead = this.FindControl<TextBlock>("LeadText");
        if (lead is not null)
            lead.Text = $"已为您拦截该程序的 {_count} 项危险行为(下方为最近一条)。可在主界面 [拦截记录] 中查看。";
        // 同进程又一条拦截:重置自动关闭倒计时,延长停留。
        StartOrResetAutoClose();
    }

    private bool _aiRequested;

    /// <summary>用户点击「让 AI 解释」:按需调用大模型(默认不自动调,省 Credits)。</summary>
    private void AiExplain_Click(object? sender, RoutedEventArgs e)
    {
        if (_aiRequested) return;
        _aiRequested = true;
        var btn = this.FindControl<Button>("AiExplainButton");
        if (btn is not null) btn.IsVisible = false;
        var aiText = this.FindControl<TextBlock>("AiText");
        if (aiText is not null) { aiText.IsVisible = true; aiText.Text = "正在分析该行为…"; }
        _closeTimer?.Stop(); // 加载与阅读期间暂停自动关闭,完成后再重置
        _ = LoadAiAsync();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void FillDetails(SecurityEvent e)
    {
        // 来源 = 真正决定拦截的依据。优先展示硬恶意指标 / 互证升格(如 AI/VT 判定恶意),
        // 而不是最初命中的那条软规则(如「未签名+从桌面运行」),避免让用户误以为
        // 「仅因未签名就被拦」。回退顺序:硬指标/互证 > 命中的规则 > 规则备注 > 风险原因。
        var source = DecisiveReason(e);

        var actorName = EventTypeDisplay.ActorNameWithPid(e);

        var action = EventTypeDisplay.Action(e.Type);

        SetText("SourceText", source);
        SetText("ProcText", actorName);
        SetText("ActionText", action);
        SetText("TargetText", string.IsNullOrEmpty(e.Target) ? "—" : e.Target);
    }

    /// <summary>从证据链推导「真正导致拦截的原因」,而非最初命中的软信号规则。</summary>
    private static string DecisiveReason(SecurityEvent e)
    {
        var chain = e.EvidenceChain;
        if (chain is { Count: > 0 })
        {
            // 1) 硬恶意指标 / 互证升格:取分值贡献最大的一条(分值相同则取靠后的,即更接近最终裁决)。
            Evidence? decisive = null;
            foreach (var ev in chain)
            {
                if (ev.Kind is EvidenceKind.HardIndicator or EvidenceKind.Corroboration
                    && !string.IsNullOrWhiteSpace(ev.Description)
                    && (decisive is null || ev.ScoreDelta >= decisive.ScoreDelta))
                    decisive = ev;
            }
            // 2) 否则用「命中规则」类证据(可能是 Block 规则)。
            if (decisive is null)
                for (int i = chain.Count - 1; i >= 0; i--)
                    if (chain[i].Kind == EvidenceKind.Rule && !string.IsNullOrWhiteSpace(chain[i].Description))
                    { decisive = chain[i]; break; }

            if (decisive is not null) return decisive.Description;
        }

        if (!string.IsNullOrEmpty(e.MatchedRuleNote)) return e.MatchedRuleNote!;
        return e.RiskReasons.Count > 0 ? string.Join(" · ", e.RiskReasons) : "—";
    }

    private void SetText(string name, string value)
    {
        var tb = this.FindControl<TextBlock>(name);
        if (tb is not null) tb.Text = value;
    }

    /// <summary>异步调用 AI 解释该行为,失败/未配置则隐藏 AI 区。完成后才开始正常阅读倒计时。</summary>
    private async Task LoadAiAsync()
    {
        var aiText = this.FindControl<TextBlock>("AiText");
        if (aiText is null) { StartOrResetAutoClose(); return; }

        try
        {
            if (!App.Ai.IsConfigured)
            {
                aiText.Text = "未配置 AI · 在「设置 → AI / 大模型研判」中填入 API Key 可解锁本节解读。";
                aiText.Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#5C708C"));
                return;
            }

            var explanation = await App.Ai.ExplainEventAsync(_event, _cts.Token);
            if (_cts.IsCancellationRequested) return;
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                aiText.Text = string.IsNullOrWhiteSpace(explanation)
                    ? "AI 暂未给出明确解读。"
                    : explanation!;
            });
        }
        catch
        {
            await Dispatcher.UIThread.InvokeAsync(() => aiText.Text = "AI 解读失败,请检查网络或配置。");
        }
        finally
        {
            // AI 解读完成(成功/失败/未配置)后,重置自动关闭倒计时,给用户阅读时间。
            if (!_cts.IsCancellationRequested)
                await Dispatcher.UIThread.InvokeAsync(StartOrResetAutoClose);
        }
    }

    /// <summary>AI 解读就绪后开始正常阅读倒计时(仅触发一次,后续同进程合并会重置)。</summary>
    private void BeginReadCountdown()
    {
        if (_readCountdownStarted) return;
        _readCountdownStarted = true;
        StartOrResetAutoClose();
    }

    /// <summary>硬上限计时:AI 长时间不返回时也最终关闭,避免"正在分析…"永久停留。</summary>
    private void StartMaxLifetime()
    {
        if (_cts.IsCancellationRequested) return;
        _maxLifeTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(MaxLifetimeSeconds) };
        _maxLifeTimer.Tick += (_, _) =>
        {
            _maxLifeTimer?.Stop();
            if (!_cts.IsCancellationRequested) Close();
        };
        _maxLifeTimer.Start();
    }

    /// <summary>把当前所有活跃 toast 在屏幕右下角竖向排列,新的在最下。</summary>
    private void Reflow()
    {
        Dispatcher.UIThread.Post(() =>
        {
            var screen = Screens.Primary ?? (Screens.All.Count > 0 ? Screens.All[0] : null);
            if (screen is null) return;
            var work = screen.WorkingArea;
            var scale = screen.Scaling;

            int x = (int)(work.Right - (Width * scale) - RightMargin * scale);
            int bottom = (int)(work.Bottom - BottomMargin * scale);

            BlockNotifyWindow[] snapshot;
            lock (_sync) snapshot = _active.ToArray();

            // 从下往上堆叠:最旧的在最下
            for (int i = snapshot.Length - 1; i >= 0; i--)
            {
                var w = snapshot[i];
                int y = (int)(bottom - (w.Height * scale));
                w.Position = new Avalonia.PixelPoint(x, y);
                bottom -= (int)((w.Height + Gap) * scale);
            }
        });
    }

    /// <summary>启动或重置自动关闭倒计时(同进程又来一条拦截时延长停留)。</summary>
    private void StartOrResetAutoClose()
    {
        if (_cts.IsCancellationRequested) return;
        if (_closeTimer is null)
        {
            _closeTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(AutoCloseSeconds) };
            _closeTimer.Tick += (_, _) =>
            {
                _closeTimer?.Stop();
                if (!_cts.IsCancellationRequested) Close();
            };
        }
        _closeTimer.Stop();
        _closeTimer.Start();
    }

    private void Close_Click(object? sender, RoutedEventArgs e) => Close();
}
