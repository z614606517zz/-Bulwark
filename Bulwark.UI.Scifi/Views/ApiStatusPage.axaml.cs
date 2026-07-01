using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Bulwark.UI.Scifi.ViewModels;

namespace Bulwark.UI.Scifi.Views;

public partial class ApiStatusPage : UserControl
{
    private ReputationSourcesViewModel? Vm => DataContext as ReputationSourcesViewModel;

    public ApiStatusPage()
    {
        InitializeComponent();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void TestAll_Click(object? sender, RoutedEventArgs e) => Vm?.TestAll();

    private void TestOne_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: ReputationSourceItem item })
            Vm?.TestOne(item);
    }
}
