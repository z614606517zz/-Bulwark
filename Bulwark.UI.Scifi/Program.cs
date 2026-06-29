using Avalonia;

namespace Bulwark.UI.Scifi;

internal static class Program
{
    // Avalonia 要求 STA 线程作为入口。
    [STAThread]
    public static void Main(string[] args)
    {
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
