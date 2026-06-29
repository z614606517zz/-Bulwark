using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Threading.Channels;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Bulwark.Service.Monitoring;

/// <summary>
/// 用户态「持续行为监控」事件源(无需内核驱动)。
///
/// 背景:WMI 基础源只能观测「进程创建」(Win32_ProcessStartTrace),对程序运行【之后】的
/// 危险行为(自启动持久化、勒索批量加密)完全失明 —— 这正是「只防双击、事后无感」的盲区。
/// 本源在纯用户态补上两类高价值、低误报的事后监控:
///
///   1) 自启动持久化(Persistence):
///      · 监视「启动」文件夹(当前用户 + 所有用户)的新增/改名文件;
///      · 轮询 Run / RunOnce / Policies\Explorer\Run 注册表(HKLM + HKCU,含 Wow6432Node),
///        以基线增量方式只上报【新增/变更】的自启动项,避免开机把存量项全报一遍。
///      上报为 FileWrite / RegistryWrite 事件,交规则引擎按持久化规则裁决(多为询问,
///      被自启动的程序若是受信任签名则由信任策略自动放行,不打扰用户)。
///
///   2) 勒索蜜罐诱饵(Canary):
///      · 在文档/桌面/图片目录投放隐藏诱饵文件,并登记到 <see cref="RansomwareBehaviorMonitor"/>;
///      · 任何进程改写/删除这些诱饵几乎可确认为勒索,触发即上报 -> 规则引擎硬拦并告警。
///      这是误报极低的勒索早期发现手段。
///
/// 诚实的局限:用户态拿不到「是谁(哪个 PID)写的文件/注册表」,故:
///   · 自启动事件不归因发起进程(ActorPid=0),以「被持久化的目标程序」作为可信度评估对象;
///   · 勒索诱饵命中只能告警 + 记录,无法精确结束元凶进程。
/// 真正的「写入前原地拦截 + 精确归因」需连接同源编译的内核驱动(Bulwark.sys)。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class UserModeBehaviorSource : IEventSource, IDisposable
{
    private readonly ILogger<UserModeBehaviorSource> _logger;
    private readonly RuleEngine _engine;

    /// <summary>主开关。由 Worker 按 RuntimeSettings.UserModeBehaviorMonitor 实时设置。</summary>
    public volatile bool Enabled = true;

    /// <summary>勒索诱饵开关。由 Worker 按 RuntimeSettings.RansomwareCanaryEnabled 实时设置。</summary>
    public volatile bool CanaryEnabled = true;

    /// <summary>
    /// 诱饵命中事件使用的合成 PID(>4)。用户态无真实 PID,但 <see cref="RansomwareBehaviorMonitor"/>
    /// 要求 ActorPid&gt;0 才会评估;同时这些事件 UserModeObserved=false 且不会触发进程结束,
    /// 不存在误杀真实进程的风险。
    /// </summary>
    private const int SyntheticActorPid = 0x0B0_0000; // 任意稳定的非常规值

    private readonly Channel<SecurityEvent> _channel =
        Channel.CreateUnbounded<SecurityEvent>(new UnboundedChannelOptions { SingleReader = true });

    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly List<string> _canaryFiles = new();
    private CancellationTokenSource? _cts;
    private Task? _regPoller;

    /// <summary>注册表自启动基线快照:keyPath -> (valueName -> valueData)。用于只报增量。</summary>
    private readonly Dictionary<string, Dictionary<string, string>> _regBaseline =
        new(StringComparer.OrdinalIgnoreCase);

    public UserModeBehaviorSource(ILogger<UserModeBehaviorSource> logger, RuleEngine engine)
    {
        _logger = logger;
        _engine = engine;
    }

    public async IAsyncEnumerable<SecurityEvent> ReadEventsAsync(
        [EnumeratorCancellation] CancellationToken token)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        try
        {
            StartStartupFolderWatchers();
            DeployCanaries();
            SnapshotRegistryBaseline();
            _regPoller = Task.Run(() => RegistryPollLoopAsync(_cts.Token), _cts.Token);
            _logger.LogInformation("用户态持续行为监控已启动(自启动持久化 + 勒索诱饵)。");

            await foreach (var e in _channel.Reader.ReadAllAsync(token))
                yield return e;
        }
        finally
        {
            Dispose();
        }
    }

    // ==================================================================
    // 1) 自启动文件夹监控
    // ==================================================================
    private void StartStartupFolderWatchers()
    {
        foreach (var dir in EnumStartupFolders())
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                var w = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                    EnableRaisingEvents = true
                };
                w.Created += (_, ev) => OnStartupItem(ev.FullPath);
                w.Changed += (_, ev) => OnStartupItem(ev.FullPath);
                w.Renamed += (_, ev) => OnStartupItem(ev.FullPath);
                _watchers.Add(w);
                _logger.LogInformation("监视启动文件夹:{dir}", dir);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "无法监视启动文件夹 {dir}", dir);
            }
        }
    }

    private static IEnumerable<string> EnumStartupFolders()
    {
        string?[] dirs =
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        };
        foreach (var d in dirs)
            if (!string.IsNullOrEmpty(d)) yield return d!;
    }

    private void OnStartupItem(string fullPath)
    {
        if (!Enabled) return;
        try
        {
            // 忽略我方诱饵文件(诱饵不放在启动目录,这里仅作保险)。
            if (_canaryFiles.Contains(fullPath, StringComparer.OrdinalIgnoreCase)) return;
            if (Directory.Exists(fullPath)) return; // 目录变更忽略

            // 以「被持久化的程序」作为可信度评估对象:.lnk 解析目标,否则用文件本身。
            string target = ResolveAutorunTarget(fullPath) ?? fullPath;
            var ev = BuildAutorunFileEvent(fullPath, target);
            _channel.Writer.TryWrite(ev);
            _logger.LogInformation("检测到启动文件夹新增/变更:{f}(目标 {t})", fullPath, target);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "处理启动文件夹项失败:{f}", fullPath);
        }
    }

    // ==================================================================
    // 2) 勒索蜜罐诱饵
    // ==================================================================
    private void DeployCanaries()
    {
        if (!CanaryEnabled) return;

        // 诱饵命名以 "~$" 前缀 + "aaa" 排序靠前,尽量让勒索"按字母序加密"时优先触碰。
        const string canaryName = "~$Bulwark_请勿删除_DoNotDelete.docx";
        foreach (var dir in EnumCanaryFolders())
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                string path = Path.Combine(dir, canaryName);
                if (!File.Exists(path))
                {
                    File.WriteAllText(path,
                        "此文件为磐垒主动防御的勒索诱饵(蜜罐),用于尽早发现勒索加密行为。请勿删除或修改。\r\n" +
                        "This is a Bulwark ransomware canary (honeypot) file. Do not delete or modify.\r\n");
                    try { File.SetAttributes(path, FileAttributes.Hidden); } catch { }
                }
                _canaryFiles.Add(path);
                _engine.Ransomware.AddCanaryFile(path);
                WatchCanary(path);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "投放勒索诱饵失败:{dir}", dir);
            }
        }
        if (_canaryFiles.Count > 0)
            _logger.LogInformation("已投放 {n} 个勒索诱饵文件并登记蜜罐。", _canaryFiles.Count);
    }

    private static IEnumerable<string> EnumCanaryFolders()
    {
        string?[] dirs =
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)
        };
        foreach (var d in dirs)
            if (!string.IsNullOrEmpty(d)) yield return d!;
    }

    private void WatchCanary(string path)
    {
        try
        {
            string? dir = Path.GetDirectoryName(path);
            string name = Path.GetFileName(path);
            if (string.IsNullOrEmpty(dir)) return;
            var w = new FileSystemWatcher(dir, name)
            {
                IncludeSubdirectories = false,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                EnableRaisingEvents = true
            };
            w.Changed += (_, ev) => OnCanaryTampered(ev.FullPath, EventType.FileWrite);
            w.Deleted += (_, ev) => OnCanaryTampered(ev.FullPath, EventType.FileDelete);
            w.Renamed += (_, ev) => OnCanaryTampered(ev.FullPath, EventType.FileWrite);
            _watchers.Add(w);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "监视诱饵失败:{p}", path);
        }
    }

    private void OnCanaryTampered(string fullPath, EventType type)
    {
        if (!Enabled || !CanaryEnabled) return;
        try
        {
            // 命中诱饵 = 强勒索信号。交规则引擎(Ransomware.Observe 命中 canary 即硬拦)。
            var ev = new SecurityEvent
            {
                Type = type,
                TimestampUtc = DateTime.UtcNow,
                ActorPid = SyntheticActorPid,
                ActorPath = "(用户态行为监控·勒索诱饵)",
                Target = fullPath,
                UserModeObserved = false,
                Detail = "勒索诱饵文件被改写/删除(疑似勒索批量加密)"
            };
            _channel.Writer.TryWrite(ev);
            _logger.LogWarning("勒索诱饵被触碰:{p}({t}) —— 疑似勒索行为!", fullPath, type);

            // 诱饵可能被加密删除,尽力重建以便持续监视后续目录。
            TryRecreateCanary(fullPath);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "处理诱饵触碰失败:{p}", fullPath);
        }
    }

    private void TryRecreateCanary(string path)
    {
        try
        {
            if (File.Exists(path)) return;
            File.WriteAllText(path, "Bulwark canary\r\n");
            try { File.SetAttributes(path, FileAttributes.Hidden); } catch { }
        }
        catch { /* 勒索仍在进行时重建可能失败,忽略 */ }
    }

    // ==================================================================
    // 3) 注册表自启动项轮询(基线增量)
    // ==================================================================
    private async Task RegistryPollLoopAsync(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(4), token);
                if (!Enabled) continue;
                ScanRegistryDelta(emit: true);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "注册表自启动轮询结束。");
        }
    }

    private void SnapshotRegistryBaseline() => ScanRegistryDelta(emit: false);

    /// <summary>(基线键, 子键路径, 根名)三元组。</summary>
    private static IEnumerable<(RegistryKey Root, string SubKey, string RootName)> AutorunRegLocations()
    {
        string[] hklmSubs =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        };
        string[] hkcuSubs =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        };
        foreach (var s in hklmSubs) yield return (Registry.LocalMachine, s, "HKLM");
        foreach (var s in hkcuSubs) yield return (Registry.CurrentUser, s, "HKCU");
    }

    private void ScanRegistryDelta(bool emit)
    {
        foreach (var (root, subKey, rootName) in AutorunRegLocations())
        {
            try
            {
                using var key = root.OpenSubKey(subKey, writable: false);
                string keyId = rootName + "\\" + subKey;
                var current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                if (key is not null)
                {
                    foreach (var name in key.GetValueNames())
                    {
                        if (string.IsNullOrEmpty(name)) continue;
                        object? v = key.GetValue(name);
                        current[name] = v?.ToString() ?? string.Empty;
                    }
                }

                if (!_regBaseline.TryGetValue(keyId, out var baseline))
                {
                    _regBaseline[keyId] = current;
                    continue; // 首次:仅建立基线,不报
                }

                if (emit)
                {
                    foreach (var kv in current)
                    {
                        bool isNew = !baseline.TryGetValue(kv.Key, out var old);
                        bool changed = !isNew && !string.Equals(old, kv.Value, StringComparison.OrdinalIgnoreCase);
                        if (isNew || changed)
                        {
                            string regPath = keyId + "\\" + kv.Key;
                            string target = ResolveAutorunTarget(kv.Value) ?? kv.Value;
                            var ev = BuildAutorunRegEvent(regPath, kv.Key, kv.Value, target);
                            _channel.Writer.TryWrite(ev);
                            _logger.LogInformation("检测到自启动注册表{act}:{p} = {d}",
                                isNew ? "新增" : "变更", regPath, kv.Value);
                        }
                    }
                }

                _regBaseline[keyId] = current; // 更新基线
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "扫描自启动注册表失败:{root}\\{sub}", rootName, subKey);
            }
        }
    }

    // ==================================================================
    // 事件构造 + 目标解析
    // ==================================================================
    private static SecurityEvent BuildAutorunFileEvent(string filePath, string targetExe)
    {
        bool signed = ProcessInspector.IsSigned(targetExe);
        return new SecurityEvent
        {
            Type = EventType.FileWrite,
            TimestampUtc = DateTime.UtcNow,
            ActorPid = 0, // 用户态无法归因发起进程
            ActorPath = targetExe,
            ActorSigned = signed,
            ActorHash = ProcessInspector.TryComputeSha256(targetExe),
            ActorPublisher = signed ? ProcessInspector.TryGetPublisher(targetExe) : null,
            Target = filePath,
            UserModeObserved = false,
            Detail = "向启动文件夹写入自启动程序(持久化)"
        };
    }

    private static SecurityEvent BuildAutorunRegEvent(string regPath, string valueName, string valueData, string targetExe)
    {
        bool signed = ProcessInspector.IsSigned(targetExe);
        return new SecurityEvent
        {
            Type = EventType.RegistryWrite,
            TimestampUtc = DateTime.UtcNow,
            ActorPid = 0,
            ActorPath = targetExe,
            ActorSigned = signed,
            ActorHash = ProcessInspector.TryComputeSha256(targetExe),
            ActorPublisher = signed ? ProcessInspector.TryGetPublisher(targetExe) : null,
            Target = regPath,
            UserModeObserved = false,
            Detail = $"新增/变更自启动项:{valueName} = {valueData}"
        };
    }

    /// <summary>
    /// 从自启动项数据解析出被持久化的可执行文件路径。
    /// 支持:带引号的路径、命令行首个 token、.lnk 快捷方式目标、环境变量展开。
    /// 解析失败返回 null。
    /// </summary>
    private static string? ResolveAutorunTarget(string? data)
    {
        if (string.IsNullOrWhiteSpace(data)) return null;
        try
        {
            string s = Environment.ExpandEnvironmentVariables(data.Trim());

            // 带引号:取第一段引号内内容
            if (s.StartsWith("\""))
            {
                int end = s.IndexOf('"', 1);
                if (end > 1) return s.Substring(1, end - 1);
            }

            // 无引号:取首个 token(到第一个空格);若该 token 本身存在则用之,
            // 否则尝试逐步扩展(处理 "C:\Program Files\..." 含空格但未加引号的情况)。
            if (File.Exists(s)) return s;
            int sp = s.IndexOf(' ');
            if (sp > 0)
            {
                string first = s.Substring(0, sp);
                if (File.Exists(first)) return first;
            }
            return s;
        }
        catch
        {
            return data;
        }
    }

    public void Dispose()
    {
        try { _cts?.Cancel(); } catch { }
        foreach (var w in _watchers)
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
        }
        _watchers.Clear();
        _channel.Writer.TryComplete();
    }
}
