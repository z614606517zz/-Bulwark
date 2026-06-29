using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Bulwark.Service.Monitoring;

/// <summary>
/// 内核驱动(Bulwark.sys,minifilter,服务名 "Bulwark")按需注册/加载/卸载。
/// 驱动为 minifilter(type=filesys,依赖 FltMgr),demand 启动:开机不常驻,
/// 由本程序在"启用内核驱动"时主动加载、退出/停用时卸载。
///
/// 若内核服务尚未注册(sc query 返回 1060),会自动:
///   sc create + 写 Instances/Altitude 注册表 → 再加载。
/// 通过 sc.exe / fltmc.exe 控制,失败不抛出(降级为用户态观测)。
/// 注意:注册/加载内核驱动需要管理员权限 + 测试签名模式;失败时静默降级。
/// </summary>
[SupportedOSPlatform("windows")]
public static class DriverService
{
    public const string DriverServiceName = "Bulwark";
    private const string Altitude     = "385201";
    private const string InstanceName = "Bulwark Instance";

    /// <summary>加载(必要时先注册)内核驱动。已在运行则直接成功。</summary>
    public static bool TryStart(ILogger? logger = null)
    {
        if (IsRunning()) return true;

        // 确保 minifilter 服务已注册(首次或被清理后自动 sc create + 写实例注册表)
        EnsureRegistered(logger);

        // 优先 fltmc load(minifilter 的规范加载方式),失败再退回 sc start
        if (RunFltmc("load", logger) || RunSc("start", logger))
            return true;

        return IsRunning();
    }

    /// <summary>卸载(停止)内核驱动。</summary>
    public static bool TryStop(ILogger? logger = null)
        => RunFltmc("unload", logger) || RunSc("stop", logger);

    public static bool IsRunning()
    {
        try
        {
            var (_, output) = Exec("sc.exe", $"query {DriverServiceName}");
            return output.IndexOf("RUNNING", StringComparison.OrdinalIgnoreCase) >= 0;
        }
        catch { return false; }
    }

    /// <summary>服务是否已在 SCM 注册(sc query 不返回 1060)。</summary>
    private static bool IsRegistered()
    {
        try
        {
            var (_, output) = Exec("sc.exe", $"query {DriverServiceName}");
            return output.IndexOf("1060", StringComparison.Ordinal) < 0
                && output.IndexOf("does not exist", StringComparison.OrdinalIgnoreCase) < 0
                && output.IndexOf("未安装", StringComparison.Ordinal) < 0;
        }
        catch { return false; }
    }

    /// <summary>若未注册则自动注册 minifilter 服务(sc create + Instances/Altitude 注册表)。</summary>
    private static void EnsureRegistered(ILogger? logger)
    {
        try
        {
            if (IsRegistered()) return;

            var sys = LocateSys();
            if (sys is null)
            {
                logger?.LogWarning("未找到 Bulwark.sys,无法注册内核驱动(将降级为用户态观测)。");
                return;
            }

            // 1) 创建 minifilter 服务(type=filesys, 依赖 FltMgr, demand 启动)
            var (code, output) = Exec("sc.exe",
                $"create {DriverServiceName} type= filesys binPath= \"{sys}\" start= demand depend= FltMgr group= \"FSFilter Activity Monitor\"");
            if (code != 0 && output.IndexOf("1073", StringComparison.Ordinal) < 0) // 1073=已存在
            {
                logger?.LogWarning("注册内核驱动失败(sc create code={code}):{out}", code, output.Trim());
                return;
            }

            // 2) 写 Minifilter 实例配置:Instances\DefaultInstance + <实例>\Altitude/Flags
            string baseKey = $@"SYSTEM\CurrentControlSet\Services\{DriverServiceName}\Instances";
            using (var inst = Registry.LocalMachine.CreateSubKey(baseKey))
            {
                inst?.SetValue("DefaultInstance", InstanceName, RegistryValueKind.String);
            }
            using (var one = Registry.LocalMachine.CreateSubKey($@"{baseKey}\{InstanceName}"))
            {
                one?.SetValue("Altitude", Altitude, RegistryValueKind.String);
                one?.SetValue("Flags", 0, RegistryValueKind.DWord);
            }

            logger?.LogInformation("内核驱动已自动注册(minifilter,Altitude={alt},binPath={sys})。", Altitude, sys);
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "自动注册内核驱动异常(需管理员权限)。");
        }
    }

    /// <summary>定位 Bulwark.sys:System32\drivers 优先,其次 C:\BulwarkDrv,再次仓库构建产物。</summary>
    private static string? LocateSys()
    {
        string sysDrivers = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "Bulwark.sys");
        string[] candidates =
        {
            sysDrivers,
            @"C:\BulwarkDrv\Bulwark.sys",
            Path.Combine(AppContext.BaseDirectory, "Bulwark.sys"),
        };
        foreach (var c in candidates)
        {
            try { if (File.Exists(c)) return c; } catch { }
        }
        return null;
    }

    private static bool RunSc(string verb, ILogger? logger)
    {
        try
        {
            var (code, output) = Exec("sc.exe", $"{verb} {DriverServiceName}");
            bool ok = code == 0
                || output.Contains("1056")  // already running
                || (verb == "stop" && output.Contains("1062")); // not started
            if (ok) logger?.LogInformation("内核驱动 sc {verb} 成功。", verb);
            else    logger?.LogWarning("内核驱动 sc {verb} 失败(code={code}):{out}", verb, code, output.Trim());
            return ok;
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "调用 sc {verb} {svc} 异常。", verb, DriverServiceName);
            return false;
        }
    }

    private static bool RunFltmc(string verb, ILogger? logger)
    {
        try
        {
            var (code, output) = Exec("fltmc.exe", $"{verb} {DriverServiceName}");
            bool ok = code == 0;
            if (ok) logger?.LogInformation("内核驱动 fltmc {verb} 成功。", verb);
            else    logger?.LogInformation("fltmc {verb} 返回 code={code}(将尝试 sc 回退):{out}", verb, code, output.Trim());
            return ok;
        }
        catch (Exception ex)
        {
            logger?.LogInformation(ex, "调用 fltmc {verb} 异常(将尝试 sc 回退)。", verb);
            return false;
        }
    }

    private static (int code, string output) Exec(string exe, string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi)!;
        string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(15000);
        return (p.HasExited ? p.ExitCode : -1, o);
    }
}
