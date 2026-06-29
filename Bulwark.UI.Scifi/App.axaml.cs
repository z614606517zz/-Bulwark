using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Bulwark.Core.Ipc;
using Bulwark.Core.Models;
using Bulwark.UI.Services;
using Bulwark.UI.Scifi.Services;
using Bulwark.UI.Scifi.ViewModels;
using Bulwark.UI.Scifi.Views;

namespace Bulwark.UI.Scifi;

public partial class App : Application
{
    public static IpcClient Ipc { get; } = new();
    public static AiClient Ai { get; } = new();
    public static MimoUsageClient MimoUsage { get; } = new();

    /// <summary>托盘是否可用。可用时关闭主窗口将隐藏到托盘而非退出。</summary>
    public static bool TrayActive { get; private set; }

    private MainViewModel? _vm;
    private TrayManager? _tray;
    private RuntimeSettings? _lastSettings;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // 仅在托盘菜单"退出"时显式退出;关闭主窗口/关闭末个窗口都不退出应用,
            // 以实现"关窗最小化到托盘、后台继续防护"。
            desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;

            _vm = new MainViewModel(Ipc);
            var mainWin = new MainWindow { DataContext = _vm };
            desktop.MainWindow = mainWin;

            // 托盘（窗口加载后再初始化，避免 WinForms 句柄时机问题）
            mainWin.Loaded += (_, _) =>
            {
                try { _tray ??= new TrayManager(mainWin); TrayActive = true; }
                catch { TrayActive = false; /* 托盘不可用不影响主程序 */ }
            };

            desktop.ShutdownRequested += (_, _) =>
            {
                _tray?.Dispose();
                Ipc.DisposeAsync().AsTask().Wait(500);
            };

            // 挂载 IPC 事件
            Ipc.PromptReceived += OnPromptReceived;
            Ipc.BlockNotificationReceived += OnBlockNotification;
            Ipc.RemediationReportReceived += OnRemediationReport;
            Ipc.ConnectionChanged += OnConnectionChanged;

            // 挂载 AI 病毒扫描处理器：服务请求 -> UI 调大模型 -> 回传结果。
            // 同时弹出研判进度 Toast（双击启动 / dropper 释放载荷），出结果后更新结论。
            Ipc.AiScanHandler = async e =>
            {
                AiScanToastWindow? toast = null;
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    if (_vm is not null) _vm.AiScanCount++;
                    try { toast = AiScanToastWindow.Create(e); }
                    catch { toast = null; /* Toast 失败不影响研判 */ }
                });

                var result = await Ai.ScanAsync(e);

                if (toast is not null)
                    await Dispatcher.UIThread.InvokeAsync(() => toast.ShowResult(result));

                return result;
            };

            // 设置到达时同步更新 AI 配置(并缓存,供自愈清除坏 Key 使用)
            Ipc.SettingsReceived += s => { _lastSettings = s; Ai.Configure(s); };

            // VT 上传扫描进度:服务端推送 -> 居中进度卡片(复用扫描卡片,显示上传/分析进度与结论)。
            Ipc.VtScanUpdateReceived += rec =>
            {
                Dispatcher.UIThread.Post(() =>
                {
                    if (rec.Stage == Bulwark.Core.Models.VtScanStage.Queued && _vm is not null)
                        _vm.AiScanCount++;
                    try { AiScanToastWindow.VtUpdate(rec); }
                    catch { /* 卡片失败不影响扫描 */ }
                });
            };

            // AI 自愈:检测到持久化的自定义 Key 无效(已回退内置 Key)时,
            // 通过正常 IPC 把该 Key 清空并持久化,使内置 Key 成为永久主路径。
            Ai.BadUserKeyDetected += () =>
            {
                var s = _lastSettings;
                if (s is null || string.IsNullOrWhiteSpace(s.AiApiKey)) return;
                s.AiApiKey = string.Empty; // 留空 -> 回退到内置默认 Key
                _ = Ipc.UpdateSettingsAsync(s);
            };

            Ipc.Start();
        }

        base.OnFrameworkInitializationCompleted();
    }

    // ===== 行为裁决弹窗 =====
    private void OnPromptReceived(SecurityEvent e)
    {
        Dispatcher.UIThread.Post(() =>
        {
            var prompt = new PromptWindow(e);

            // 非模态显示:裁决弹窗不应锁死主窗口,用户在裁决期间仍可操作主程序
            //(查看规则/记录等)。结果在弹窗关闭时回传,而非阻塞等待。
            // 弹窗自身 Topmost,保证可见且不被主窗口遮挡。
            bool sent = false;
            prompt.Closed += async (_, _) =>
            {
                if (sent) return;
                sent = true;

                // 把裁决结果回传服务
                await Ipc.SendVerdictAsync(e.Id, prompt.ResultAction, prompt.Remember, prompt.Scope);

                // 更新统计
                if (_vm is not null)
                {
                    if (prompt.ResultAction == VerdictAction.Allow)
                        _vm.AllowCount++;
                    else
                        _vm.BlockCount++;
                }
            };

            prompt.Show();
        });
    }

    // ===== 拦截通知 Toast =====
    private void OnBlockNotification(SecurityEvent e)
    {
        Dispatcher.UIThread.Post(() =>
        {
            BlockNotifyWindow.Notify(e);

            // 更新统计
            if (_vm is not null)
                _vm.BlockCount++;
        });
    }

    // ===== 足迹清理报告:服务清理恶意后弹窗告知用户清理了什么、还剩什么 =====
    private void OnRemediationReport(RemediationReportPayload report)
    {
        Dispatcher.UIThread.Post(() =>
        {
            // 若判定来源含 AI 标记,使用新的 AI 扫描报告弹窗(更丰富的展示);否则用传统报告。
            if (report.Reason.Contains("AI", StringComparison.OrdinalIgnoreCase))
            {
                var win = new AiScanReportWindow(report, Ipc);
                win.Show();
            }
            else
            {
                var win = new RemediationReportWindow(report, Ipc);
                win.Show();
            }
        });
    }

    // ===== 连接状态变化:更新侧栏状态点颜色 =====
    private void OnConnectionChanged(bool connected)
    {
        Dispatcher.UIThread.Post(() =>
        {
            if (_vm is not null)
            {
                _vm.IsConnected = connected;
                _vm.StatusText = connected ? "链路在线" : "链路离线";
            }
        });
    }

    private Window? GetMainWindow()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            return desktop.MainWindow;
        return null;
    }
}
