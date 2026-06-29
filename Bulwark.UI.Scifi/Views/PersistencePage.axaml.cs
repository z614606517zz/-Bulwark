using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Bulwark.UI.Scifi.ViewModels;

namespace Bulwark.UI.Scifi.Views;

public partial class PersistencePage : UserControl
{
    public PersistencePage()
    {
        InitializeComponent();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void Refresh_Click(object? sender, RoutedEventArgs e)
        => (DataContext as PersistenceViewModel)?.Refresh();
}
