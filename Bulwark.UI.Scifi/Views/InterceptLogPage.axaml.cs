using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Bulwark.UI.Scifi.ViewModels;

namespace Bulwark.UI.Scifi.Views;

public partial class InterceptLogPage : UserControl
{
    public InterceptLogPage()
    {
        InitializeComponent();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    /// <summary>双击一条拦截记录:打开其「攻击时间线」窗口回溯判定依据 / 技战术 / 进程链。</summary>
    private void OnEntryDoubleTapped(object? sender, TappedEventArgs e)
    {
        var list = this.FindControl<ListBox>("EntriesList");
        if (list?.SelectedItem is not InterceptLogEntry entry || entry.Event is null) return;

        var window = new AttackTimelineWindow(entry.Event);
        var owner = TopLevel.GetTopLevel(this) as Window;
        if (owner is not null) window.Show(owner);
        else window.Show();
    }
}
