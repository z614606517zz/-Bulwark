using System.Threading;
using Avalonia;

namespace Bulwark.UI.Scifi;

internal static class Program
{
    /// <summary>
    /// 单实例互斥量。守护整个进程生命周期(静态字段,避免被 GC 回收)。
    /// 防止 UI 被重复拉起导致同一告警/研判卡片弹出多个(每个实例各弹各的)。
    /// </summary>
    private static Mutex? _singleInstance;

    // Avalonia 要求 STA 线程作为入口。
    [STAThread]
    public static void Main(string[] args)
    {
        // 单实例保护:已有实例在运行时,本次启动直接退出,不再重复弹窗。
        // 使用当前用户会话内的命名互斥量,避免跨会话的权限问题。
        _singleInstance = new Mutex(initiallyOwned: true, name: "Bulwark.UI.Scifi.SingleInstance", out bool createdNew);
        if (!createdNew)
            return;

        // 捕获未处理异常写入日志
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            var ex = e.ExceptionObject as Exception;
            File.WriteAllText(
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crash.log"),
                $"{DateTime.Now}\n{ex}");
        };

        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            File.WriteAllText(
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crash.log"),
                $"{DateTime.Now}\n{ex}");
        }
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
