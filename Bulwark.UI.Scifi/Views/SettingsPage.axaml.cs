using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using Bulwark.UI.Scifi.ViewModels;

namespace Bulwark.UI.Scifi.Views;

public partial class SettingsPage : UserControl
{
    private SettingsViewModel? Vm => DataContext as SettingsViewModel;

    public SettingsPage()
    {
        InitializeComponent();
        Loaded += (_, _) => Vm?.Refresh();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void Refresh_Click(object? sender, RoutedEventArgs e) => Vm?.Refresh();

    private void QueryVt_Click(object? sender, RoutedEventArgs e) => Vm?.QueryFile();

    private void TestAi_Click(object? sender, RoutedEventArgs e) => Vm?.TestAiConnection();

    private async void TestMimoUsage_Click(object? sender, RoutedEventArgs e)
    {
        if (Vm is not null) await Vm.TestMimoUsageAsync();
    }

    private async void BrowseVt_Click(object? sender, RoutedEventArgs e)
    {
        var top = TopLevel.GetTopLevel(this);
        if (top is null || Vm is null) return;

        var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "选择要查询信誉的文件",
            AllowMultiple = false
        });

        if (files.Count > 0)
        {
            var path = files[0].TryGetLocalPath();
            if (!string.IsNullOrWhiteSpace(path))
                Vm.VtFilePath = path;
        }
    }
}
