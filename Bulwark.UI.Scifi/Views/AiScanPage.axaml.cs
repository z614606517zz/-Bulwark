using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using Bulwark.UI.Services;
using Bulwark.UI.Scifi.ViewModels;

namespace Bulwark.UI.Scifi.Views;

public partial class AiScanPage : UserControl
{
    private AiScanViewModel? Vm => DataContext as AiScanViewModel;

    public AiScanPage()
    {
        InitializeComponent();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private async void ScanFile_Click(object? sender, RoutedEventArgs e)
    {
        var top = TopLevel.GetTopLevel(this);
        if (top is null || Vm is null) return;

        var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "选择要扫描的文件",
            AllowMultiple = false
        });

        if (files.Count > 0)
        {
            var path = files[0].TryGetLocalPath();
            if (!string.IsNullOrWhiteSpace(path))
                Vm.ScanFile(path);
        }
    }

    private async void ScanFolder_Click(object? sender, RoutedEventArgs e)
    {
        var top = TopLevel.GetTopLevel(this);
        if (top is null || Vm is null) return;

        var folders = await top.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "选择要扫描的文件夹",
            AllowMultiple = false
        });

        if (folders.Count > 0)
        {
            var path = folders[0].TryGetLocalPath();
            if (!string.IsNullOrWhiteSpace(path))
                Vm.ScanFolder(path);
        }
    }

    private void Cancel_Click(object? sender, RoutedEventArgs e) => Vm?.Cancel();

    /// <summary>
    /// 扫描溯源:选择单个文件 → AI 研判 → 弹出详细报告弹窗(手动触发的完整 AI 扫描流程)。
    /// </summary>
    private async void ScanAndTrace_Click(object? sender, RoutedEventArgs e)
    {
        var top = TopLevel.GetTopLevel(this);
        if (top is null) return;

        var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "选择要 AI 扫描并溯源的文件",
            AllowMultiple = false
        });

        if (files.Count == 0) return;
        var path = files[0].TryGetLocalPath();
        if (string.IsNullOrWhiteSpace(path)) return;

        // 提取文件特征
        var snapshot = await System.Threading.Tasks.Task.Run(() => FileInspector.Inspect(path));
        if (snapshot.Error != null)
        {
            var errorVerdict = new AiFileVerdict
            {
                Path = path,
                Available = false,
                Error = snapshot.Error
            };
            var errWin = new AiScanReportWindow(errorVerdict, App.Ipc);
            errWin.Show();
            return;
        }

        // AI 研判
        var verdict = await App.Ai.ScanFileAsync(snapshot, System.Threading.CancellationToken.None, "手动扫描");

        // 弹出报告窗口
        var win = new AiScanReportWindow(verdict, App.Ipc);
        win.Show();
    }

    /// <summary>溯源按钮:打开 AI 扫描报告弹窗,展示详细判定 + 可手动触发隔离。</summary>
    private void Trace_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not AiFileVerdict verdict) return;

        var win = new AiScanReportWindow(verdict, App.Ipc);
        win.Show();
    }
}
