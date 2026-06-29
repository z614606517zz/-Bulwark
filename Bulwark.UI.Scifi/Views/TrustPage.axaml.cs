using System;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using Bulwark.UI.Scifi.ViewModels;

namespace Bulwark.UI.Scifi.Views;

public partial class TrustPage : UserControl
{
    private TrustViewModel? Vm => DataContext as TrustViewModel;

    public TrustPage()
    {
        InitializeComponent();
        Loaded += (_, _) => Vm?.Refresh();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void Refresh_Click(object? sender, RoutedEventArgs e) => Vm?.Refresh();

    private async void Add_Click(object? sender, RoutedEventArgs e)
    {
        var top = TopLevel.GetTopLevel(this);
        if (top is null) return;

        var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "选择要信任的可执行文件",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("可执行文件") { Patterns = new[] { "*.exe", "*.dll", "*.sys" } },
                new FilePickerFileType("所有文件") { Patterns = new[] { "*" } }
            }
        });

        if (files.Count > 0 && Vm is not null)
        {
            var path = files[0].TryGetLocalPath();
            if (!string.IsNullOrWhiteSpace(path))
                Vm.Add(path);
        }
    }

    private void Remove_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is Guid id && Vm is not null)
        {
            foreach (var entry in Vm.Entries)
            {
                if (entry.Id == id) { Vm.Remove(entry); break; }
            }
        }
    }
}
