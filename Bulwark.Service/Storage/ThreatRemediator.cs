using System.Runtime.Versioning;
using Bulwark.Core.Models;
using Bulwark.Service.Monitoring;
using Microsoft.Win32;

namespace Bulwark.Service.Storage;

/// <summary>
/// 一次「确定恶意」处置的足迹清理报告。供日志/审计/UI 展示「清理了哪些痕迹」。
/// </summary>
public sealed class RemediationReport
{
    /// <summary>被清理(隔离)的释放文件原始路径。</summary>
    public List<string> QuarantinedFiles { get; } = new();

    /// <summary>被删除的注册表持久化项(键路径\值名)。</summary>
    public List<string> RemovedRegistryValues { get; } = new();

    /// <summary>未能清理的项(连同原因 + 是否文件),供 UI 透明呈现并支持重试隔离。</summary>
    public List<Bulwark.Core.Ipc.RemediationSkippedItem> Skipped { get; } = new();

    public int TotalActions => QuarantinedFiles.Count + RemovedRegistryValues.Count;
}

/// <summary>
/// 威胁足迹清理器(remediation / rollback)。
///
/// 当某进程被「确定为恶意」(命中规则 / 高危启发式 / 威胁情报确认)并结束进程树后,
/// 单纯隔离主体 exe 往往不够 —— 恶意软件通常已经:
///   · 在用户可写目录(Temp/AppData/桌面/下载/ProgramData 等)释放了载荷/副本;
///   · 写入自启动注册表项(Run/RunOnce)指向这些载荷以实现持久化。
/// 本类基于 <see cref="Engine.ProcessChainTracker"/> 还原出的「整棵进程树足迹」,
/// 把这些痕迹一并清理:释放文件移入隔离区、自启动项删除。
///
/// 安全原则(贯彻本项目低误伤理念):
///   · 文件只清理「位于用户可写落地区、且无可信签名」的目标 —— 绝不动系统目录 /
///     Program Files / 带可信签名的文件,避免误删合法文件;
///   · 注册表只删「自启动键(Run/RunOnce)里、值数据指向上述已确认恶意文件」的值 ——
///     精准移除持久化,绝不泛删无关键值;
///   · 内存足迹由「结束整棵进程树」覆盖(调用方已处置),本类不再处理。
/// 全程尽力而为、绝不抛断主防御流程。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ThreatRemediator
{
    private readonly QuarantineManager _quarantine;
    private readonly Microsoft.Extensions.Logging.ILogger _logger;

    public ThreatRemediator(
        QuarantineManager quarantine,
        Microsoft.Extensions.Logging.ILogger logger)
    {
        _quarantine = quarantine;
        _logger = logger;
    }

    /// <summary>用户可写「落地区」目录特征(小写)。仅清理位于这些区域的释放文件。</summary>
    private static readonly string[] DropZones =
    {
        @"\appdata\local\temp\", @"\windows\temp\", @"\appdata\roaming\",
        @"\appdata\local\", @"\downloads\", @"\desktop\", @"\documents\",
        @"\users\public\", @"\programdata\", @"\$recycle.bin\", @"\perflogs\",
    };

    /// <summary>受保护(绝不清理)目录特征 —— 系统与正规安装目录。</summary>
    private static readonly string[] ProtectedZones =
    {
        @"\windows\system32\", @"\windows\syswow64\", @"\windows\winsxs\",
        @"\program files\", @"\program files (x86)\",
    };

    /// <summary>自启动注册表键(枚举其值,删除指向恶意文件的持久化项)。</summary>
    private static readonly (RegistryHive Hive, string SubKey)[] AutostartKeys =
    {
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        // Winlogon 登录挂钩(仅当值数据被追加了恶意文件路径时清理)
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    };

    /// <summary>映像劫持(IFEO)根键:其子键下的 Debugger 值指向恶意文件即为劫持。</summary>
    private static readonly (RegistryHive Hive, string SubKey)[] IfeoRoots =
    {
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
        (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
    };

    /// <summary>
    /// 对一次确认恶意的处置执行足迹清理。<paramref name="footprint"/> 为进程树记录的全部事件。
    /// 返回清理报告(尽力而为,绝不抛出)。
    /// </summary>
    public async Task<RemediationReport> RemediateAsync(
        SecurityEvent malicious,
        IReadOnlyList<ChainEventInfo> footprint,
        CancellationToken token)
    {
        var report = new RemediationReport();
        if (!OperatingSystem.IsWindows()) return report;

        // 1) 汇总「恶意文件集」:进程树释放/写入/创建过的文件 + 主体自身。
        //    用于:① 清理这些落地文件;② 删除指向它们的自启动项。
        var maliciousFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Consider(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            if (path.StartsWith("PID ", StringComparison.Ordinal)) return;
            if (!LooksLikeFilePath(path)) return;
            maliciousFiles.Add(path.Trim());
        }

        Consider(malicious.ActorPath);
        foreach (var ev in footprint)
        {
            if (ev.Type is EventType.FileWrite or EventType.FileDelete)
            {
                Consider(ev.Target);
            }
        }

        // 2) 文件清理:仅清理位于落地区、无可信签名的文件,隔离而非直接删除(可还原+留证)。
        foreach (var path in maliciousFiles)
        {
            try
            {
                if (!File.Exists(path)) continue;
                if (!IsSafeToRemove(path, out var why))
                {
                    report.Skipped.Add(SkipFile(path, why));
                    continue;
                }

                string? hash = QuarantineManager.TryComputeSha256(path);
                var entry = await _quarantine.QuarantineAsync(
                    path, $"恶意进程释放/关联文件的足迹清理(主体 PID {malicious.ActorPid})",
                    malicious.ActorPid, hash, token).ConfigureAwait(false);

                if (entry is not null)
                {
                    report.QuarantinedFiles.Add(path);
                    _logger.LogWarning("足迹清理:已隔离恶意释放文件 {path}", path);
                }
                else
                {
                    report.Skipped.Add(SkipFile(path, "隔离失败,可能被占用"));
                }
            }
            catch (Exception ex)
            {
                report.Skipped.Add(SkipFile(path, ex.GetType().Name));
            }
        }

        // 3) 注册表持久化清理:删除指向恶意文件的「自启动值 / 映像劫持 / 恶意服务」。
        try
        {
            RemoveAutostartPersistence(maliciousFiles, report);   // Run/RunOnce/策略等值型自启动
            RemoveIfeoPersistence(maliciousFiles, report);        // 映像劫持 IFEO Debugger
            RemoveServicePersistence(maliciousFiles, report);     // 指向恶意文件的服务
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "注册表持久化清理出错(忽略)。");
        }

        if (report.TotalActions > 0)
            _logger.LogWarning("足迹清理完成:隔离文件 {f} 个,移除自启动项 {r} 个。",
                report.QuarantinedFiles.Count, report.RemovedRegistryValues.Count);

        return report;
    }

    /// <summary>删除指向恶意文件集的自启动注册表值(精准持久化清理)。</summary>
    private void RemoveAutostartPersistence(HashSet<string> maliciousFiles, RemediationReport report)
    {
        foreach (var (hive, subKey) in AutostartKeys)
        {
            RegistryKey? baseKey = null;
            RegistryKey? key = null;
            try
            {
                baseKey = RegistryKey.OpenBaseKey(hive,
                    subKey.Contains("WOW6432Node", StringComparison.OrdinalIgnoreCase)
                        ? RegistryView.Registry64 : RegistryView.Default);
                key = baseKey.OpenSubKey(subKey, writable: true);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var data = key.GetValue(valueName) as string;
                    if (string.IsNullOrEmpty(data)) continue;

                    // 值数据(命令行)中若引用了任一恶意文件路径,则该自启动项是持久化痕迹。
                    bool pointsToMalware = maliciousFiles.Any(mf =>
                        data.Contains(mf, StringComparison.OrdinalIgnoreCase));
                    if (!pointsToMalware) continue;

                    try
                    {
                        key.DeleteValue(valueName, throwOnMissingValue: false);
                        var full = $"{HiveName(hive)}\\{subKey}\\{valueName}";
                        report.RemovedRegistryValues.Add(full);
                        _logger.LogWarning("足迹清理:已删除自启动持久化项 {item}", full);
                    }
                    catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
                    {
                        var full = $"{HiveName(hive)}\\{subKey}\\{valueName}";
                        var view = subKey.Contains("WOW6432Node", StringComparison.OrdinalIgnoreCase)
                            ? RegistryView.Registry64 : RegistryView.Default;
                        if (RegSurgery.ForceDeleteValue(hive, subKey, valueName, view))
                        {
                            report.RemovedRegistryValues.Add(full + "(夺取所有权后删除)");
                            _logger.LogWarning("足迹清理:夺取所有权后删除自启动项 {item}", full);
                        }
                        else
                        {
                            report.Skipped.Add(new Bulwark.Core.Ipc.RemediationSkippedItem
                            { Target = full, Reason = "受 ACL 保护,夺取所有权仍失败(建议手动删除)", IsFile = false });
                        }
                    }
                    catch (Exception ex)
                    {
                        report.Skipped.Add(new Bulwark.Core.Ipc.RemediationSkippedItem
                        {
                            Target = $"{subKey}\\{valueName}",
                            Reason = ex.GetType().Name,
                            IsFile = false
                        });
                    }
                }
            }
            catch { /* 单个键失败不影响其它键 */ }
            finally
            {
                key?.Dispose();
                baseKey?.Dispose();
            }
        }
    }

    /// <summary>构造一条「文件」类未清理项。</summary>
    private static Bulwark.Core.Ipc.RemediationSkippedItem SkipFile(string path, string reason)
        => new() { Target = path, Reason = reason, IsFile = true };

    /// <summary>值数据是否引用了任一恶意文件(全路径子串匹配,大小写不敏感)。</summary>
    private static bool ReferencesMalware(string? data, HashSet<string> maliciousFiles)
        => !string.IsNullOrEmpty(data)
           && maliciousFiles.Any(mf => data!.Contains(mf, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// 清理映像劫持(IFEO):遍历 IFEO 子键,若其 Debugger / GlobalFlag 调试器值指向恶意文件,删除该值。
    /// 仅删值不删子键(子键本身可能是系统正常存在的应用调优项)。
    /// </summary>
    private void RemoveIfeoPersistence(HashSet<string> maliciousFiles, RemediationReport report)
    {
        foreach (var (hive, root) in IfeoRoots)
        {
            RegistryKey? baseKey = null, rootKey = null;
            try
            {
                baseKey = RegistryKey.OpenBaseKey(hive,
                    root.Contains("WOW6432Node", StringComparison.OrdinalIgnoreCase)
                        ? RegistryView.Registry64 : RegistryView.Default);
                rootKey = baseKey.OpenSubKey(root, writable: false);
                if (rootKey is null) continue;

                foreach (var sub in rootKey.GetSubKeyNames())
                {
                    RegistryKey? child = null;
                    try
                    {
                        // 先只读打开读取 Debugger 值(读取通常被允许,即使写入被 ACL 拒绝)。
                        child = rootKey.OpenSubKey(sub, writable: false);
                        var dbg = child?.GetValue("Debugger") as string;
                        if (child is null || !ReferencesMalware(dbg, maliciousFiles)) continue;
                        child.Dispose(); child = null; // 释放只读句柄,后续走写入/强删

                        var full = $"{HiveName(hive)}\\{root}\\{sub}\\Debugger";
                        var view = root.Contains("WOW6432Node", StringComparison.OrdinalIgnoreCase)
                            ? RegistryView.Registry64 : RegistryView.Default;
                        try
                        {
                            // 尝试常规可写打开并删除。受保护键在以写入方式打开时即抛异常,
                            // 由下方 catch 统一走"夺取所有权强删"。
                            using var wk = rootKey.OpenSubKey(sub, writable: true)
                                ?? throw new UnauthorizedAccessException("无法以写入方式打开 IFEO 子键");
                            wk.DeleteValue("Debugger", throwOnMissingValue: false);
                            report.RemovedRegistryValues.Add(full);
                            _logger.LogWarning("足迹清理:已删除映像劫持(IFEO)项 {item}", full);
                        }
                        catch (Exception delEx) when (delEx is System.Security.SecurityException or UnauthorizedAccessException)
                        {
                            // ACL 保护(TrustedInstaller/Defender 篡改保护)——夺取所有权后强删。
                            if (RegSurgery.ForceDeleteValue(hive, $"{root}\\{sub}", "Debugger", view))
                            {
                                report.RemovedRegistryValues.Add(full + "(夺取所有权后删除)");
                                _logger.LogWarning("足迹清理:夺取所有权后删除映像劫持项 {item}", full);
                            }
                            else
                            {
                                report.Skipped.Add(new Bulwark.Core.Ipc.RemediationSkippedItem
                                { Target = full, Reason = "受 ACL 保护,夺取所有权仍失败(建议关闭 Defender 篡改保护后手动删除)", IsFile = false });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        report.Skipped.Add(new Bulwark.Core.Ipc.RemediationSkippedItem
                        { Target = $"{root}\\{sub}\\Debugger", Reason = ex.GetType().Name, IsFile = false });
                    }
                    finally { child?.Dispose(); }
                }
            }
            catch { /* 单根失败不影响其它 */ }
            finally { rootKey?.Dispose(); baseKey?.Dispose(); }
        }
    }

    /// <summary>
    /// 清理指向恶意文件的服务:遍历 HKLM\SYSTEM\CurrentControlSet\Services,
    /// 若某服务的 ImagePath / ServiceDll 指向恶意文件,删除该服务子键(连同持久化点)。
    /// 仅删命中恶意文件的服务,绝不动其它系统服务。
    /// </summary>
    private void RemoveServicePersistence(HashSet<string> maliciousFiles, RemediationReport report)
    {
        RegistryKey? servicesKey = null;
        try
        {
            servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: true);
            if (servicesKey is null) return;

            foreach (var svc in servicesKey.GetSubKeyNames())
            {
                RegistryKey? sk = null;
                try
                {
                    sk = servicesKey.OpenSubKey(svc, writable: false);
                    if (sk is null) continue;
                    var imagePath = sk.GetValue("ImagePath") as string;
                    string? serviceDll = null;
                    using (var param = sk.OpenSubKey("Parameters"))
                        serviceDll = param?.GetValue("ServiceDll") as string;

                    bool hit = ReferencesMalware(imagePath, maliciousFiles)
                               || ReferencesMalware(serviceDll, maliciousFiles);
                    sk.Dispose(); sk = null;
                    if (!hit) continue;

                    var full = $"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc}";
                    try
                    {
                        servicesKey.DeleteSubKeyTree(svc, throwOnMissingSubKey: false);
                        report.RemovedRegistryValues.Add(full);
                        _logger.LogWarning("足迹清理:已删除指向恶意文件的服务 {item}", full);
                    }
                    catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
                    {
                        if (RegSurgery.ForceDeleteSubKeyTree(RegistryHive.LocalMachine,
                                @"SYSTEM\CurrentControlSet\Services", svc, RegistryView.Default))
                        {
                            report.RemovedRegistryValues.Add(full + "(夺取所有权后删除)");
                            _logger.LogWarning("足迹清理:夺取所有权后删除恶意服务 {item}", full);
                        }
                        else
                        {
                            report.Skipped.Add(new Bulwark.Core.Ipc.RemediationSkippedItem
                            { Target = full, Reason = "受 ACL 保护,夺取所有权仍失败(建议手动删除该服务)", IsFile = false });
                        }
                    }
                }
                catch (Exception ex)
                {
                    report.Skipped.Add(new Bulwark.Core.Ipc.RemediationSkippedItem
                    { Target = $"Services\\{svc}", Reason = ex.GetType().Name, IsFile = false });
                }
                finally { sk?.Dispose(); }
            }
        }
        catch { /* 服务根不可写/不可读时忽略 */ }
        finally { servicesKey?.Dispose(); }
    }

    /// <summary>
    /// 用户手动请求的「强制隔离」:不受落地区/签名限制(用户已明确要求),直接尝试隔离指定文件。
    /// 成功返回 (true, 提示);失败返回 (false, 原因)。
    /// </summary>
    public async Task<(bool ok, string message)> ForceQuarantineAsync(string path, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(path))
            return (false, "路径为空");
        if (!File.Exists(path))
            return (false, "文件不存在(可能已被移动或删除)");

        try
        {
            string? hash = QuarantineManager.TryComputeSha256(path);
            var entry = await _quarantine.QuarantineAsync(
                path, "用户手动强制隔离(清理报告重试)", 0, hash, token).ConfigureAwait(false);
            if (entry is not null)
            {
                _logger.LogWarning("手动强制隔离成功:{path}", path);
                return (true, "已移入隔离区");
            }
            return (false, "隔离失败(文件可能被占用或权限不足)");
        }
        catch (Exception ex)
        {
            return (false, ex.GetType().Name + ":" + ex.Message);
        }
    }

    /// <summary>是否可安全清理:位于用户可写落地区、不在系统/安装目录、且无可信签名。</summary>
    private static bool IsSafeToRemove(string path, out string reason)
    {
        reason = string.Empty;
        var lower = path.ToLowerInvariant().Replace('/', '\\');

        if (ProtectedZones.Any(z => lower.Contains(z)))
        {
            reason = "位于系统/安装目录,保护不动";
            return false;
        }
        if (!DropZones.Any(z => lower.Contains(z)))
        {
            reason = "不在用户可写落地区,谨慎起见不清理";
            return false;
        }
        // 带可信签名的文件几乎不可能是恶意释放物,绝不清理(防误删合法组件)。
        try
        {
            if (ProcessInspector.IsSigned(path))
            {
                reason = "带可信数字签名,保护不动";
                return false;
            }
        }
        catch { /* 签名校验失败时按未签名处理,继续清理 */ }

        return true;
    }

    /// <summary>粗判一个字符串是否像本地文件路径(含盘符或 UNC,且有扩展名)。</summary>
    private static bool LooksLikeFilePath(string s)
    {
        if (s.Length < 4) return false;
        bool hasRoot = (s.Length > 2 && s[1] == ':' && (s[2] == '\\' || s[2] == '/'))
                       || s.StartsWith(@"\\", StringComparison.Ordinal);
        if (!hasRoot) return false;
        // 注册表内核路径(\REGISTRY\...)不是文件路径,排除。
        if (s.StartsWith(@"\REGISTRY", StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private static string HiveName(RegistryHive hive) => hive switch
    {
        RegistryHive.LocalMachine => "HKLM",
        RegistryHive.CurrentUser => "HKCU",
        RegistryHive.Users => "HKU",
        _ => hive.ToString()
    };
}
