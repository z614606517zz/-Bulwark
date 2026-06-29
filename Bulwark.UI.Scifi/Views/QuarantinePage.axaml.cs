using System;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Bulwark.UI.Scifi.ViewModels;

namespace Bulwark.UI.Scifi.Views;

public partial class QuarantinePage : UserControl
{
    private QuarantineViewModel? Vm => DataContext as QuarantineViewModel;

    public QuarantinePage()
    {
        InitializeComponent();
        Loaded += (_, _) => Vm?.Refresh();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void Refresh_Click(object? sender, RoutedEventArgs e) => Vm?.Refresh();

    private void Restore_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is Guid id && Vm is not null)
        {
            foreach (var item in Vm.Items)
            {
                if (item.Id == id) { Vm.Restore(item); break; }
            }
        }
    }

    private void Delete_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is Guid id && Vm is not null)
        {
            foreach (var item in Vm.Items)
            {
                if (item.Id == id) { Vm.Delete(item); break; }
            }
        }
    }
}
