using System;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Bulwark.Core.Ipc;
using Bulwark.UI.Services;

namespace Bulwark.UI.Scifi.Views;

public partial class RemediationReportWindow : Window
{
    private readonly RemediationReportPayload _report;
    private readonly IpcClient? _ipc;

    public RemediationReportWindow() : this(new RemediationReportPayload(), null) { }

    public RemediationReportWindow(RemediationReportPayload report, IpcClient? ipc)
    {
        _report = report;
        _ipc = ipc;
        InitializeComponent();
        Populate();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void Populate()
    {
        this.FindControl<TextBlock>("ActorText")!.Text =
            $"{_report.ActorPath}  (PID {_report.ActorPid})";
        this.FindControl<TextBlock>("ReasonText")!.Text =
            $"判定原因:{_report.Reason}" + (_report.ActorQuarantined ? "  ·  主体已隔离" : "  ·  主体未隔离");

        this.FindControl<TextBlock>("SummaryText")!.Text =
            $"成功清理 {_report.SuccessCount} 项 · 未清理 {_report.Skipped.Count} 项";

        BindSection("QuarantinedSection", "QuarantinedList", _report.QuarantinedFiles);
        BindSection("RegistrySection", "RegistryList", _report.RemovedRegistryValues);

        var skippedSection = this.FindControl<StackPanel>("SkippedSection")!;
        var skippedList = this.FindControl<ItemsControl>("SkippedList")!;
        if (_report.Skipped.Count == 0)
            skippedSection.IsVisible = false;
        else
            skippedList.ItemsSource = _report.Skipped;
    }

    private void BindSection(string sectionName, string listName, System.Collections.Generic.IList<string> items)
    {
        var section = this.FindControl<StackPanel>(sectionName)!;
        var list = this.FindControl<ItemsControl>(listName)!;
        if (items.Count == 0)
            section.IsVisible = false;
        else
            list.ItemsSource = items;
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
