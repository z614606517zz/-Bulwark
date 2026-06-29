using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace Bulwark.UI.Scifi.Views;

public partial class DashboardPage : UserControl
{
    public DashboardPage()
    {
        InitializeComponent();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);
}
