using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Bulwark.Core.Engine;
using Bulwark.Core.Ipc;
using Bulwark.Core.Models;
using Microsoft.Win32;

namespace Bulwark.Service.Monitoring;

/// <summary>
/// 自启动持久化点枚举器(只读审计)。枚举系统常见自启动位置,逐项交
/// <see cref="PersistenceAnalyzer"/> 打分与 ATT&CK 标注,产出供 UI 展示的清单。
///
/// 覆盖:注册表 Run/RunOnce(HKLM+HKCU,32/64 视图)、启动文件夹、Windows 服务、
/// 映像劫持(IFEO Debugger)、Winlogon(Userinit/Shell)、AppInit_DLLs、计划任务(读 Tasks XML)。
///
/// 纯只读:绝不修改任何自启动项;失败的源静默跳过并在 Message 里汇总,做到透明而非假装完整。
/// </summary>
[SupportedOSPlatform("windows")]
internal static class PersistenceScanner
{
    public static PersistenceListResponsePayload Scan()
    {
        var entries = new List<PersistenceEntry>();
        var notes = new List<string>();

        Safe(notes, "注册表 Run/RunOnce", () => ScanRunKeys(entries));
        Safe(notes, "启动文件夹", () => ScanStartupFolders(entries));
        Safe(notes, "Windows 服务", () => ScanServices(entries));
        Safe(notes, "映像劫持(IFEO)", () => ScanIfeo(entries));
        Safe(notes, "Winlogon", () => ScanWinlogon(entries));
        Safe(notes, "AppInit_DLLs", () => ScanAppInit(entries));
        Safe(notes, "计划任务", () => ScanScheduledTasks(entries));

        // 逐项分析(签名解析 + 启发式 + ATT&CK)
        foreach (var e in entries)
        {
            try
            {
                if (!string.IsNullOrEmpty(e.ImagePath) && File.Exists(e.ImagePath))
                {
                    e.Signed = ProcessInspector.IsSigned(e.ImagePath);
                    e.Publisher = ProcessInspector.TryGetPublisher(e.ImagePath);
                }
                PersistenceAnalyzer.Analyze(e);
            }
            catch { /* 单项失败不影响整体 */ }
            e.Id = MakeId(e);
        }

        return new PersistenceListResponsePayload
        {
            ScannedUtc = DateTime.UtcNow,
            Entries = entries.OrderByDescending(x => x.RiskScore).ThenBy(x => x.Category).ToList(),
            Message = notes.Count == 0 ? $"共 {entries.Count} 项" : string.Join("; ", notes)
        };
    }

    private static void Safe(List<string> notes, string source, Action act)
    {
        try { act(); }
        catch (Exception ex) { notes.Add($"{source} 枚举受限:{ex.Message}"); }
    }

    // ── 注册表 Run / RunOnce ──────────────────────────────────────
    private static readonly (RegistryHive Hive, string Sub, PersistenceCategory Cat)[] RunKeys =
    {
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", PersistenceCategory.RegistryRun),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceCategory.RegistryRunOnce),
        (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", PersistenceCategory.RegistryRun),
        (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceCategory.RegistryRunOnce),
    };

    private static void ScanRunKeys(List<PersistenceEntry> entries)
    {
        foreach (var (hive, sub, cat) in RunKeys)
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var key = baseKey.OpenSubKey(sub);
            if (key is null) continue;
            foreach (var name in key.GetValueNames())
            {
                var cmd = key.GetValue(name)?.ToString() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(cmd)) continue;
                entries.Add(new PersistenceEntry
                {
                    Category = cat,
                    Name = name,
                    Location = $"{HiveName(hive)}\\{sub}",
                    Command = cmd,
                    ImagePath = ExtractImagePath(cmd)
                });
            }
        }
    }

    // ── 启动文件夹 ────────────────────────────────────────────────
    private static void ScanStartupFolders(List<PersistenceEntry> entries)
    {
        var folders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        };
        foreach (var folder in folders.Where(f => !string.IsNullOrEmpty(f) && Directory.Exists(f)))
        foreach (var file in Directory.EnumerateFiles(folder))
        {
            string target = file;
            // .lnk 解析较重,这里以快捷方式文件本身为目标(命令=路径),由分析器看路径/扩展名
            entries.Add(new PersistenceEntry
            {
                Category = PersistenceCategory.StartupFolder,
                Name = Path.GetFileName(file),
                Location = folder,
                Command = target,
                ImagePath = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? null : file
            });
        }
    }

    // ── Windows 服务(自动启动且有镜像路径)─────────────────────────
    private static void ScanServices(List<PersistenceEntry> entries)
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var svcRoot = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (svcRoot is null) return;
        foreach (var svc in svcRoot.GetSubKeyNames())
        {
            using var k = svcRoot.OpenSubKey(svc);
            if (k is null) continue;
            var imagePath = k.GetValue("ImagePath")?.ToString();
            if (string.IsNullOrWhiteSpace(imagePath)) continue;

            // 仅关注自动/按需启动的服务(Start=2 自动 / 3 手动),跳过禁用(4)
            int start = (k.GetValue("Start") as int?) ?? 3;
            if (start == 4) continue;

            entries.Add(new PersistenceEntry
            {
                Category = PersistenceCategory.Service,
                Name = svc,
                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svc}",
                Command = imagePath,
                ImagePath = ExtractImagePath(imagePath)
            });
        }
    }

    // ── 映像劫持 IFEO Debugger ────────────────────────────────────
    private static void ScanIfeo(List<PersistenceEntry> entries)
    {
        const string ifeo = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var root = baseKey.OpenSubKey(ifeo);
        if (root is null) return;
        foreach (var img in root.GetSubKeyNames())
        {
            using var k = root.OpenSubKey(img);
            var debugger = k?.GetValue("Debugger")?.ToString();
            if (string.IsNullOrWhiteSpace(debugger)) continue; // 仅 Debugger 值才是劫持
            entries.Add(new PersistenceEntry
            {
                Category = PersistenceCategory.IfeoDebugger,
                Name = img,
                Location = $@"HKLM\{ifeo}\{img}",
                Command = debugger,
                ImagePath = ExtractImagePath(debugger)
            });
        }
    }

    // ── Winlogon Userinit / Shell ─────────────────────────────────
    private static void ScanWinlogon(List<PersistenceEntry> entries)
    {
        const string sub = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var k = baseKey.OpenSubKey(sub);
        if (k is null) return;
        foreach (var val in new[] { "Userinit", "Shell" })
        {
            var cmd = k.GetValue(val)?.ToString();
            if (string.IsNullOrWhiteSpace(cmd)) continue;
            entries.Add(new PersistenceEntry
            {
                Category = PersistenceCategory.Winlogon,
                Name = val,
                Location = $@"HKLM\{sub}",
                Command = cmd,
                ImagePath = ExtractImagePath(cmd)
            });
        }
    }

    // ── AppInit_DLLs ──────────────────────────────────────────────
    private static void ScanAppInit(List<PersistenceEntry> entries)
    {
        const string sub = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var k = baseKey.OpenSubKey(sub);
            var dlls = k?.GetValue("AppInit_DLLs")?.ToString();
            if (string.IsNullOrWhiteSpace(dlls)) continue;
            entries.Add(new PersistenceEntry
            {
                Category = PersistenceCategory.AppInitDll,
                Name = "AppInit_DLLs",
                Location = $@"HKLM\{sub}",
                Command = dlls,
                ImagePath = ExtractImagePath(dlls)
            });
        }
    }

    // ── 计划任务(读取 Tasks 文件夹的 XML,提取 Exec/Command)─────────
    private static void ScanScheduledTasks(List<PersistenceEntry> entries)
    {
        string tasksRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        if (!Directory.Exists(tasksRoot)) return;

        foreach (var file in Directory.EnumerateFiles(tasksRoot, "*", SearchOption.AllDirectories))
        {
            string xml;
            try { xml = File.ReadAllText(file); }
            catch { continue; }
            if (string.IsNullOrEmpty(xml) || !xml.Contains("<Exec")) continue;

            var cmd = Between(xml, "<Command>", "</Command>");
            if (string.IsNullOrWhiteSpace(cmd)) continue;
            var args = Between(xml, "<Arguments>", "</Arguments>");
            string full = string.IsNullOrEmpty(args) ? cmd! : $"{cmd} {args}";
            string image = ExpandEnv(cmd!.Trim().Trim('"'));

            // 任务名 = 相对 Tasks 根的路径
            string taskName = file.Substring(tasksRoot.Length).Replace('\\', '/').TrimStart('/');
            entries.Add(new PersistenceEntry
            {
                Category = PersistenceCategory.ScheduledTask,
                Name = taskName,
                Location = $@"\{taskName}",
                Command = full,
                ImagePath = File.Exists(image) ? image : ExtractImagePath(full)
            });
        }
    }

    // ── 辅助 ──────────────────────────────────────────────────────

    private static string? Between(string s, string a, string b)
    {
        int i = s.IndexOf(a, StringComparison.OrdinalIgnoreCase);
        if (i < 0) return null;
        i += a.Length;
        int j = s.IndexOf(b, i, StringComparison.OrdinalIgnoreCase);
        return j < 0 ? null : s.Substring(i, j - i).Trim();
    }

    /// <summary>从命令行提取可执行文件路径(处理带引号与含空格路径、环境变量)。</summary>
    private static string? ExtractImagePath(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        var c = command.Trim();
        string path;
        if (c.StartsWith("\""))
        {
            int end = c.IndexOf('"', 1);
            path = end > 1 ? c.Substring(1, end - 1) : c.Trim('"');
        }
        else
        {
            // 服务镜像可能形如 \??\C:\... 或带参数;取第一个 .exe 结束处
            var m = Regex.Match(c, @"^(.*?\.(?:exe|dll|sys|com|bat|cmd|scr))(?:\s|$)",
                RegexOptions.IgnoreCase);
            path = m.Success ? m.Groups[1].Value : c.Split(' ')[0];
        }
        path = path.Replace(@"\??\", "").Trim();
        return ExpandEnv(path);
    }

    private static string ExpandEnv(string p)
    {
        try { return Environment.ExpandEnvironmentVariables(p); }
        catch { return p; }
    }

    private static string HiveName(RegistryHive hive) => hive switch
    {
        RegistryHive.LocalMachine => "HKLM",
        RegistryHive.CurrentUser => "HKCU",
        _ => hive.ToString()
    };

    private static string MakeId(PersistenceEntry e)
    {
        using var sha = SHA256.Create();
        var raw = $"{e.Category}|{e.Location}|{e.Name}|{e.Command}";
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash, 0, 8);
    }
}
