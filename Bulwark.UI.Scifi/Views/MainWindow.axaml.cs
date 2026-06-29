using System.Collections.Generic;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;

namespace Bulwark.UI.Scifi.Views;

public partial class MainWindow : Window
{
    private readonly Dictionary<string, Control> _pages = new();
    private Button? _activeNavBtn;
    private ContentControl _pageHost = null!;

    /// <summary>true 时允许真正关闭(由托盘"退出"触发);否则关闭按钮仅隐藏到托盘。</summary>
    public bool ForceClose { get; set; }

    public MainWindow()
    {
        InitializeComponent();

        // 手动查找控件（AvaloniaXamlLoader 模式下 generated fields 不可用）
        _pageHost = this.FindControl<ContentControl>("PageHost")!;
        _activeNavBtn = this.FindControl<Button>("NavDashboard");

        // 关闭主窗口时:若托盘可用且非显式退出 -> 取消关闭、隐藏到托盘(后台继续防护);
        // 托盘不可用时 -> 关闭即退出应用,避免无窗口无托盘的"幽灵进程"。
        Closing += (_, e) =>
        {
            if (!ForceClose && App.TrayActive)
            {
                e.Cancel = true;
                Hide();
            }
            else if (Avalonia.Application.Current?.ApplicationLifetime
                     is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.Shutdown();
            }
        };

        // DataContext 由 App 在构造后通过对象初始化器设置,此处尚为 null;
        // 推迟到 Loaded 再做首次导航,确保各页能拿到对应的子 ViewModel。
        Loaded += (_, _) =>
        {
            HookStatusDot();
            NavigateTo("Dashboard");
        };
    }

    /// <summary>把侧栏状态点颜色与连接状态绑定(绿=在线 / 红=离线)。</summary>
    private void HookStatusDot()
    {
        var dot = this.FindControl<Avalonia.Controls.Shapes.Ellipse>("StatusDot");
        if (dot is null || DataContext is not ViewModels.MainViewModel vm) return;

        void Apply() => dot.Fill = vm.IsConnected
            ? new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#39FF14"))
            : new Avalonia.Media.SolidColorBrush(Avalonia.Media.Color.Parse("#FF3B5C"));

        Apply();
        vm.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(ViewModels.MainViewModel.IsConnected))
                Avalonia.Threading.Dispatcher.UIThread.Post(Apply);
        };
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    // ===== 导航 =====
    private void Nav_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string tag)
        {
            if (_activeNavBtn is not null)
                _activeNavBtn.Classes.Remove("active");

            btn.Classes.Add("active");
            _activeNavBtn = btn;

            NavigateTo(tag);
        }
    }

    private void NavigateTo(string pageName)
    {
        if (!_pages.TryGetValue(pageName, out var page))
        {
            var main = DataContext as ViewModels.MainViewModel;
            page = pageName switch
            {
                "Dashboard" => new DashboardPage { DataContext = main },
                "Rules" => new RulesPage { DataContext = main?.RulesVm },
                "Trust" => new TrustPage { DataContext = main?.TrustVm },
                "Quarantine" => new QuarantinePage { DataContext = main?.QuarantineVm },
                "Persistence" => new PersistencePage { DataContext = main?.PersistenceVm },
                "InterceptLog" => new InterceptLogPage { DataContext = main?.InterceptLogVm },
                "ActivityLog" => new ActivityLogPage { DataContext = main?.ActivityLogVm },
                "AiScan" => new AiScanPage { DataContext = main?.AiScanVm },
                "VtHistory" => new VtHistoryPage { DataContext = main?.VtHistoryVm },
                "Settings" => new SettingsPage { DataContext = main?.SettingsVm },
                _ => new DashboardPage { DataContext = main }
            };
            _pages[pageName] = page;
        }
        _pageHost.Content = page;
    }

    // ===== 标题栏按钮 =====
    private void Minimize_Click(object? sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void MaxRestore_Click(object? sender, RoutedEventArgs e)
        => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void Close_Click(object? sender, RoutedEventArgs e) => Close();

    // ===== 标题栏拖动 / 双击最大化 =====
    private void TitleBar_PointerPressed(object? sender, Avalonia.Input.PointerPressedEventArgs e)
    {
        if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
            BeginMoveDrag(e);
    }

    private void TitleBar_DoubleTapped(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
}
