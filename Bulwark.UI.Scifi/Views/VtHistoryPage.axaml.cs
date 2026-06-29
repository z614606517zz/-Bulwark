using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Bulwark.UI.Scifi.ViewModels;

namespace Bulwark.UI.Scifi.Views;

public partial class VtHistoryPage : UserControl
{
    private VtHistoryViewModel? Vm => DataContext as VtHistoryViewModel;

    public VtHistoryPage()
    {
        InitializeComponent();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void Refresh_Click(object? sender, RoutedEventArgs e) => Vm?.Refresh();
}
