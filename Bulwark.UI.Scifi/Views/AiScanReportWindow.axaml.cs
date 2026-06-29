using System;
using System.Collections.Generic;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Bulwark.Core.Ipc;
using Bulwark.UI.Services;

namespace Bulwark.UI.Scifi.Views;

/// <summary>
/// AI 病毒扫描 + 溯源清理报告弹窗。
/// 
/// 有两种使用模式:
/// 1. 手动触发 AI 扫描(传入 AiFileVerdict + 可选 remediation 结果)
/// 2. 自动扫描后展示完整报告(传入 RemediationReportPayload)
/// 
/// 设计参考 RemediationReportWindow,呈现:
/// - 恶意主体路径 + PID
/// - AI 判定结果(判定来源 / 理由 / 置信度)
/// - 已隔离的主体载荷
/// - 已隔离的释放/关联文件
/// - 已移除的自启动项
/// - 未能清理的残留(可重试)
/// </summary>
public partial class AiScanReportWindow : Window
{
    private readonly RemediationReportPayload _report;
    private readonly IpcClient? _ipc;

    public AiScanReportWindow() : this(new RemediationReportPayload(), null) { }

    /// <summary>
    /// 完整清理报告模式:服务端完成 AI 扫描 + 溯源清理后推送。
    /// </summary>
    public AiScanReportWindow(RemediationReportPayload report, IpcClient? ipc)
    {
        _report = report;
        _ipc = ipc;
        InitializeComponent();
        Populate();
    }

    /// <summary>
    /// 手动扫描模式:用户在 AI 扫描页手动扫描单个文件后,展示扫描结果 + 可选处置建议。
    /// </summary>
    public AiScanReportWindow(AiFileVerdict verdict, IpcClient? ipc)
    {
        _report = VerdictToReport(verdict);
        _ipc = ipc;
        InitializeComponent();
        Populate();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void Populate()
    {
        // 主体信息
        var actorText = this.FindControl<TextBlock>("ActorText")!;
        actorText.Text = _report.ActorPid > 0
            ? $"主体:{_report.ActorPath}  (PID {_report.ActorPid})"
            : $"主体:{_report.ActorPath}";

        // 判定信息
        var verdictText = this.FindControl<TextBlock>("VerdictText")!;
        verdictText.Text = $"判定:{_report.Reason}";

        // 统计
        var summaryText = this.FindControl<TextBlock>("SummaryText")!;
        summaryText.Text = $"成功清理 {_report.SuccessCount} 项 · 未能清理 {_report.Skipped.Count} 项 · {_report.TimestampUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}";

        // 时间戳
        var timestampText = this.FindControl<TextBlock>("TimestampText")!;
        timestampText.Text = $"报告时间: {_report.TimestampUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}";

        // 主体载荷隔离
        var actorSection = this.FindControl<StackPanel>("ActorQuarantinedSection")!;
        var actorFileList = this.FindControl<StackPanel>("ActorFileList")!;
        if (_report.ActorQuarantined && !string.IsNullOrWhiteSpace(_report.ActorPath))
        {
            actorSection.IsVisible = true;
            var tb = new TextBlock
            {
                Text = $"• {_report.ActorPath}",
                Foreground = Avalonia.Media.Brushes.LightGray,
                FontSize = 11,
                TextWrapping = Avalonia.Media.TextWrapping.Wrap
            };
            actorFileList.Children.Add(tb);
        }
        else
        {
            actorSection.IsVisible = false;
        }

        // 已隔离释放/关联文件
        var quarantinedSection = this.FindControl<StackPanel>("QuarantinedSection")!;
        var quarantinedTitle = this.FindControl<TextBlock>("QuarantinedTitle")!;
        var quarantinedList = this.FindControl<ItemsControl>("QuarantinedList")!;
        if (_report.QuarantinedFiles.Count > 0)
        {
            quarantinedSection.IsVisible = true;
            quarantinedTitle.Text = $"已隔离释放/关联文件  ({_report.QuarantinedFiles.Count})";
            quarantinedList.ItemsSource = _report.QuarantinedFiles;
        }
        else
        {
            quarantinedSection.IsVisible = false;
        }

        // 已移除注册表自启动
        var registrySection = this.FindControl<StackPanel>("RegistrySection")!;
        var registryTitle = this.FindControl<TextBlock>("RegistryTitle")!;
        var registryList = this.FindControl<ItemsControl>("RegistryList")!;
        if (_report.RemovedRegistryValues.Count > 0)
        {
            registrySection.IsVisible = true;
            registryTitle.Text = $"已移除自启动项  ({_report.RemovedRegistryValues.Count})";
            registryList.ItemsSource = _report.RemovedRegistryValues;
        }
        else
        {
            registrySection.IsVisible = false;
        }

        // 未能清理
        var skippedSection = this.FindControl<StackPanel>("SkippedSection")!;
        var skippedTitle = this.FindControl<TextBlock>("SkippedTitle")!;
        var skippedList = this.FindControl<ItemsControl>("SkippedList")!;
        if (_report.Skipped.Count > 0)
        {
            skippedSection.IsVisible = true;
            skippedTitle.Text = $"未能清理  ({_report.Skipped.Count})";
            skippedList.ItemsSource = _report.Skipped;
        }
        else
        {
            skippedSection.IsVisible = false;
        }
    }

    /// <summary>将 AI 文件扫描裁决转为 RemediationReportPayload 格式以复用展示逻辑。</summary>
    private static RemediationReportPayload VerdictToReport(AiFileVerdict verdict)
    {
        var reasonParts = new List<string>();
        reasonParts.Add(verdict.Available
            ? $"AI 判定{verdict.Verdict switch { AiVerdict.Malicious => "恶意", AiVerdict.Suspicious => "可疑", _ => "安全" }}"
            : "AI 不可用");

        if (!string.IsNullOrEmpty(verdict.Summary))
            reasonParts.Add(verdict.Summary);
        if (!string.IsNullOrEmpty(verdict.Confidence))
            reasonParts.Add($"置信度: {verdict.Confidence}");

        return new RemediationReportPayload
        {
            TimestampUtc = verdict.ScannedAtUtc,
            ActorPath = verdict.Path,
            ActorPid = 0,
            Reason = string.Join(" · ", reasonParts),
            ActorQuarantined = false, // 手动扫描模式下尚未执行隔离
            QuarantinedFiles = new(),
            RemovedRegistryValues = new(),
            Skipped = new()
        };
    }

    private async void Retry_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string path || _ipc is null) return;

        btn.IsEnabled = false;
        btn.Content = "隔离中…";
        var result = await _ipc.RequestManualQuarantineAsync(path);
        btn.Content = result.Success ? "✓ 已隔离" : "✕ 失败";
        if (!result.Success)
        {
            btn.IsEnabled = true;
            btn.Content = "重试隔离";
        }
    }

    private void Title_PointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
            BeginMoveDrag(e);
    }

    private void Close_Click(object? sender, RoutedEventArgs e) => Close();
}
