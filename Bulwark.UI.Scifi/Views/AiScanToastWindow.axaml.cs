using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Avalonia.Threading;
using Bulwark.Core.Ipc;
using Bulwark.Core.Models;

namespace Bulwark.UI.Scifi.Views;

/// <summary>
/// AI 病毒研判进度卡片。服务端对「双击启动 / dropper 释放载荷」请求 UI 做 AI 研判时,
/// 在屏幕中央弹出本卡片(磐垒暗色霓虹风),展示"正在检测 + 预计等待"进度,并在出结果后切换为结论态。
/// 同一时刻只显示一个,其余排队依次显示。
/// </summary>
public partial class AiScanToastWindow : Window
{
    private static readonly object _sync = new();
    private static readonly List<AiScanToastWindow> _active = new();
    private static readonly Queue<AiScanToastWindow> _queue = new();
    private const int MaxVisible = 1;   // 居中卡片,同一时刻只显示一个,其余排队
    private const int MaxQueued = 20;   // 排队上限,超出丢弃最旧的

    // ===== 按目标文件去重(核心)=====
    // 同一文件可能产生多个 SecurityEvent(不同 Id):被拉起多次、或被多个监控点各报一次,
    // 每个事件各自触发一次 VT 扫描 -> 若仅按扫描 Id 去重,会为同一文件弹出多张一模一样的卡片。
    // 这里额外以「规范化文件路径」为键做去重:同一文件已有卡片(显示中或排队中)时复用并更新,
    // 绝不再开第二张。路径为空时回退用事件 Id 作键(不误合并不同来源)。
    private static readonly Dictionary<string, AiScanToastWindow> _byKey = new(StringComparer.OrdinalIgnoreCase);
    private string? _key;

    private static string KeyFor(string? path, Guid fallback)
        => !string.IsNullOrWhiteSpace(path) ? path!.Trim().ToLowerInvariant() : "id:" + fallback;

    private const int EstimateSeconds = 120; // 初始"预计等待"估值

    // 主题色(取自 Themes/Scifi.axaml)
    private static readonly Avalonia.Media.Color StateOk = Avalonia.Media.Color.Parse("#1BE38B");
    private static readonly Avalonia.Media.Color StateDanger = Avalonia.Media.Color.Parse("#FF3B5C");
    private static readonly Avalonia.Media.Color StateWarn = Avalonia.Media.Color.Parse("#FFB020");

    private readonly CancellationTokenSource _cts = new();
    private bool _resultShown;
    private bool _shown;
    private bool _hasPendingResult;
    private AiScanResponsePayload? _pendingResult;

    private DispatcherTimer? _countdownTimer;
    private int _remaining = EstimateSeconds;

    // ===== VT 上传扫描进度(以扫描 Id 关联同一次扫描的多次更新) =====
    private static readonly ConcurrentDictionary<Guid, AiScanToastWindow> _vtToasts = new();
    private Guid _vtId;
    private bool _isVt;
    private VtScanRecord? _pendingVt;

    public AiScanToastWindow() : this(new SecurityEvent()) { }

    public AiScanToastWindow(SecurityEvent e)
    {
        InitializeComponent();
        FillDetails(e);

        Opened += (_, _) =>
        {
            _shown = true;
            CenterOnScreen();
            StartCountdown();
            FallbackClose();
            // 排队期间若已拿到研判结果,显示时立即套用(通常此时已是结论态)。
            if (_hasPendingResult) ApplyResult(_pendingResult);
            // VT 路径:显示时套用最近一次进度/结论。
            if (_pendingVt is not null) ApplyVtRecord(_pendingVt);
        };
        Closed += (_, _) =>
        {
            _cts.Cancel();
            _countdownTimer?.Stop();
            if (_isVt) _vtToasts.TryRemove(_vtId, out _);
            AiScanToastWindow? next = null;
            lock (_sync)
            {
                _active.Remove(this);
                // 仅当映射仍指向本窗口时才移除路径键(避免误删同名后续卡片)。
                if (_key != null && _byKey.TryGetValue(_key, out var owner) && ReferenceEquals(owner, this))
                    _byKey.Remove(_key);
                if (_queue.Count > 0)
                {
                    next = _queue.Dequeue();
                    _active.Add(next);
                }
            }
            next?.Show();
        };
    }

    /// <summary>
    /// 创建并按"单卡片 + 排队"策略显示一个研判卡片。返回窗口句柄,
    /// 供调用方在研判结束后调用 <see cref="ShowResult"/> 更新结论(排队中也可调用)。
    /// 必须在 UI 线程调用。
    /// </summary>
    public static AiScanToastWindow Create(SecurityEvent e)
    {
        var key = KeyFor(e.ActorPath, e.Id);

        // 同一文件已有卡片(显示中或排队中):直接复用,不再新开第二张。
        lock (_sync)
        {
            if (_byKey.TryGetValue(key, out var dup)) return dup;
        }

        var w = new AiScanToastWindow(e) { _key = key };
        bool show;
        lock (_sync)
        {
            // 二次确认(极小并发窗口):期间若已有同键卡片则丢弃本次新建,复用既有。
            if (_byKey.TryGetValue(key, out var dup2)) return dup2;
            _byKey[key] = w;

            show = _active.Count < MaxVisible;
            if (show) _active.Add(w);
            else
            {
                if (_queue.Count >= MaxQueued) _queue.Dequeue(); // 丢弃最旧的待显示项
                _queue.Enqueue(w);
            }
        }
        if (show) w.Show();
        return w;
    }

    /// <summary>
    /// VT 上传扫描进度入口:按扫描 <see cref="VtScanRecord.Id"/> 创建或更新对应进度卡片。
    /// 首次出现某 Id 时按「单卡片 + 排队」策略弹出;后续更新套用到同一卡片;终态后从注册表移除。
    /// 必须在 UI 线程调用。
    /// </summary>
    public static void VtUpdate(VtScanRecord r)
    {
        var key = KeyFor(r.FilePath, r.Id);

        // 1) 先按扫描 Id 找同一次扫描的卡片;找不到再按文件路径复用同一文件的既有卡片。
        AiScanToastWindow? target = null;
        lock (_sync)
        {
            if (_vtToasts.TryGetValue(r.Id, out var byId)) target = byId;
            else if (_byKey.TryGetValue(key, out var byKey))
            {
                target = byKey;
                _vtToasts[r.Id] = byKey;   // 让该扫描 Id 的后续更新继续路由到同一张卡
            }
        }
        if (target is not null)
        {
            target.ApplyVtRecord(r);
            if (r.IsTerminal) _vtToasts.TryRemove(r.Id, out _);
            return;
        }

        // 2) 首次出现该文件/扫描:新建一张卡片(终态也可直接展示结论)。
        var w = new AiScanToastWindow(VtToEvent(r)) { _isVt = true, _vtId = r.Id, _pendingVt = r, _key = key };

        bool show;
        lock (_sync)
        {
            _vtToasts[r.Id] = w;
            _byKey[key] = w;

            show = _active.Count < MaxVisible;
            if (show) _active.Add(w);
            else
            {
                if (_queue.Count >= MaxQueued) _queue.Dequeue();
                _queue.Enqueue(w);
            }
        }
        if (show) w.Show();
        if (r.IsTerminal) _vtToasts.TryRemove(r.Id, out _);
    }

    private static SecurityEvent VtToEvent(VtScanRecord r)
        => new() { Id = r.Id, ActorPath = r.FilePath };

    /// <summary>套用一条 VT 扫描记录到卡片:进行中显示阶段/进度,终态显示结论并自动关闭。</summary>
    private void ApplyVtRecord(VtScanRecord r)
    {
        if (!_shown) { _pendingVt = r; return; }
        if (_resultShown) return;

        // 进行中:更新阶段文案与进度条(上传阶段显示百分比)。
        if (!r.IsTerminal)
        {
            SetText("TitleText", "正在云端查毒…");
            SetText("SubtitleText", r.Message ?? "VirusTotal 扫描进行中");
            var prog = this.FindControl<Avalonia.Controls.ProgressBar>("Progress");
            if (prog is not null)
            {
                if (r.Stage == VtScanStage.Uploading && r.Percent > 0)
                {
                    prog.IsIndeterminate = false;
                    prog.Maximum = 100;
                    prog.Value = r.Percent;
                }
                else
                {
                    prog.IsIndeterminate = true;
                }
            }
            var cd = this.FindControl<TextBlock>("CountdownText");
            if (cd is not null && r.Stage == VtScanStage.Uploading)
                cd.Text = $"上传中 {r.Percent}%";
            return;
        }

        // 终态:映射为结论展示。
        _resultShown = true;
        _countdownTimer?.Stop();

        bool malicious = r.Outcome == VtScanOutcome.Malicious;
        bool conclusive = r.Outcome is VtScanOutcome.Clean or VtScanOutcome.Suspicious or VtScanOutcome.Malicious;
        var accent = malicious ? StateDanger : conclusive ? StateOk : StateWarn;

        SetText("TitleText", malicious ? "检测到威胁,已处置"
                           : conclusive ? "未发现风险,文件安全"
                           : "检测未完成");
        SetText("SubtitleText", malicious ? "磐垒已结束其进程树并固化拦截规则,无需手动操作"
                              : conclusive ? "VirusTotal 多引擎未判定为恶意,该文件可放心使用"
                              : "VT 未收录 / 未获明确结论,已按放行处理(fail-open)");

        var progress = this.FindControl<Avalonia.Controls.ProgressBar>("Progress");
        if (progress is not null)
        {
            progress.IsIndeterminate = false;
            progress.Value = 100;
            progress.Maximum = 100;
            progress.Foreground = new SolidColorBrush(accent);
        }

        var countdown = this.FindControl<TextBlock>("CountdownText");
        if (countdown is not null)
        {
            countdown.Text = string.IsNullOrWhiteSpace(r.Message)
                ? (malicious ? "VirusTotal 判定该文件为恶意。" : "未发现明显恶意特征。")
                : r.Message!;
            countdown.Foreground = new SolidColorBrush(accent);
        }

        var icon = this.FindControl<Border>("IconBorder");
        if (icon is not null) icon.BorderBrush = new SolidColorBrush(accent);
        var iconAccent = this.FindControl<Border>("IconAccent");
        if (iconAccent is not null) iconAccent.Background = new SolidColorBrush(accent);

        AutoClose(malicious ? 10 : 6);
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void FillDetails(SecurityEvent e)
    {
        SetText("FileText", Services.EventTypeDisplay.ActorName(e));
    }

    private void SetText(string name, string value)
    {
        var tb = this.FindControl<TextBlock>(name);
        if (tb is not null) tb.Text = value;
    }

    // ===== 倒计时 =====
    private void StartCountdown()
    {
        _remaining = EstimateSeconds;
        UpdateCountdownText();
        _countdownTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _countdownTimer.Tick += (_, _) =>
        {
            if (_resultShown) { _countdownTimer?.Stop(); return; }
            _remaining = Math.Max(0, _remaining - 1);
            UpdateCountdownText();
        };
        _countdownTimer.Start();
    }

    private void UpdateCountdownText()
    {
        SetText("CountdownText", _remaining > 0 ? $"预计等待 {_remaining} 秒" : "即将完成…");
    }

    /// <summary>研判结束后更新结论并自动关闭。排队未显示时,先缓存结果,待显示时套用。</summary>
    public void ShowResult(AiScanResponsePayload? result)
    {
        if (_resultShown) return;
        if (!_shown)
        {
            _pendingResult = result;
            _hasPendingResult = true;
            return;
        }
        ApplyResult(result);
    }

    private void ApplyResult(AiScanResponsePayload? result)
    {
        if (_resultShown) return;
        _resultShown = true;
        _countdownTimer?.Stop();

        bool malicious = result is { Available: true, Recommendation: VerdictAction.Block };
        bool available = result is { Available: true };
        var accent = malicious ? StateDanger : available ? StateOk : StateWarn;

        SetText("TitleText", !available ? "检测未完成"
                           : malicious ? "检测到威胁,已处置"
                           : "未发现风险,文件安全");

        SetText("SubtitleText", !available ? "AI 引擎不可用 / 超时,已按放行处理(fail-open)"
                              : malicious ? "磐垒已结束其进程树并固化拦截规则,无需手动操作"
                              : "基于文件内容与行为的综合研判,该文件可放心使用");

        // 进度条收尾
        var progress = this.FindControl<Avalonia.Controls.ProgressBar>("Progress");
        if (progress is not null)
        {
            progress.IsIndeterminate = false;
            progress.Value = 100;
            progress.Maximum = 100;
            progress.Foreground = new SolidColorBrush(accent);
        }

        // 结论文字(用 summary 优先)
        var summary = result?.Summary;
        var conclusion = string.IsNullOrWhiteSpace(summary)
            ? (malicious ? "AI 判定该文件具有恶意特征。"
               : available ? "未发现明显恶意特征。" : "未获得明确结论,已放行。")
            : summary!;
        var countdown = this.FindControl<TextBlock>("CountdownText");
        if (countdown is not null)
        {
            countdown.Text = conclusion;
            countdown.Foreground = new SolidColorBrush(accent);
        }

        // 图标改色呼应结论
        var icon = this.FindControl<Border>("IconBorder");
        if (icon is not null) icon.BorderBrush = new SolidColorBrush(accent);
        var iconAccent = this.FindControl<Border>("IconAccent");
        if (iconAccent is not null) iconAccent.Background = new SolidColorBrush(accent);

        AutoClose(malicious ? 10 : 6);
    }

    /// <summary>居中显示在主屏工作区。</summary>
    private void CenterOnScreen()
    {
        Dispatcher.UIThread.Post(() =>
        {
            var screen = Screens.Primary ?? (Screens.All.Count > 0 ? Screens.All[0] : null);
            if (screen is null) return;
            var work = screen.WorkingArea;
            var scale = screen.Scaling;
            int x = (int)(work.X + (work.Width - Width * scale) / 2);
            int y = (int)(work.Y + (work.Height - Height * scale) / 2);
            Position = new Avalonia.PixelPoint(x, y);
        });
    }

    private async void AutoClose(int seconds)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(seconds), _cts.Token);
            if (!_cts.IsCancellationRequested) Close();
        }
        catch (TaskCanceledException) { }
    }

    /// <summary>
    /// 兜底关闭:卡片弹出后若长时间仍未收到结果(服务异常 / UI 断链未回调),
    /// 自动关闭,避免长期滞留。收到结果后改走 <see cref="AutoClose"/>。
    /// </summary>
    private async void FallbackClose()
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(310), _cts.Token);
            if (!_cts.IsCancellationRequested && !_resultShown) Close();
        }
        catch (TaskCanceledException) { }
    }

    private void Close_Click(object? sender, RoutedEventArgs e) => Close();
}
