using System.Management;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Threading.Channels;
using Bulwark.Core.Models;
using Microsoft.Extensions.Logging;

namespace Bulwark.Service.Monitoring;

/// <summary>
/// 真实进程创建事件源(用户态)。通过 WMI 订阅 Win32_ProcessStartTrace,
/// 监控本机所有进程的启动,并补充签名/哈希信息。
///
/// 说明:这是用户态监控,只能"观测"进程启动(无法在内核层"阻止"启动)。
/// 真正的拦截需要 M2 的内核驱动(PsSetCreateProcessNotifyRoutineEx)。
/// 这里先提供真实事件流,把 UI/规则引擎链路从"模拟"升级为"真实可用"。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WmiProcessEventSource : IEventSource, IDisposable
{
    private readonly ILogger<WmiProcessEventSource> _logger;

    /// <summary>已富化、可供消费的事件输出通道。</summary>
    private readonly Channel<SecurityEvent> _channel =
        Channel.CreateUnbounded<SecurityEvent>(new UnboundedChannelOptions { SingleReader = true });

    /// <summary>
    /// 原始事件中转通道。WMI 回调只把「廉价可得的原始字段」(pid/name/父pid)快速入队即返回,
    /// 绝不在回调线程上做签名校验/整文件哈希/命令行 WMI 查询等重 I/O ——
    /// 否则 Win32_ProcessStartTrace 消费过慢会【丢事件】。富化由独立后台 worker 完成。
    /// </summary>
    private readonly Channel<RawProc> _raw =
        Channel.CreateUnbounded<RawProc>(new UnboundedChannelOptions { SingleReader = false });

    private ManagementEventWatcher? _watcher;
    private CancellationTokenSource? _cts;
    private Task[]? _enrichWorkers;

    /// <summary>富化并发度:签名/哈希多为 I/O 等待,适度并行以跟上进程风暴。</summary>
    private static readonly int EnrichWorkerCount = Math.Max(2, Environment.ProcessorCount / 2);

    /// <summary>WMI 回调里廉价捕获的进程原始信息(不含任何重 I/O 结果)。</summary>
    private readonly record struct RawProc(int Pid, string Name, int ParentPid, DateTime AtUtc);

    public WmiProcessEventSource(ILogger<WmiProcessEventSource> logger) => _logger = logger;

    public async IAsyncEnumerable<SecurityEvent> ReadEventsAsync(
        [EnumeratorCancellation] CancellationToken token)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        StartWatcher();
        StartEnrichWorkers(_cts.Token);
        try
        {
            await foreach (var e in _channel.Reader.ReadAllAsync(token))
                yield return e;
        }
        finally
        {
            Dispose();
        }
    }

    /// <summary>启动富化后台 worker:从原始通道取廉价记录,做重 I/O 富化后写入输出通道。</summary>
    private void StartEnrichWorkers(CancellationToken token)
    {
        _enrichWorkers = new Task[EnrichWorkerCount];
        for (int i = 0; i < EnrichWorkerCount; i++)
            _enrichWorkers[i] = Task.Run(() => EnrichLoopAsync(token), token);
    }

    private async Task EnrichLoopAsync(CancellationToken token)
    {
        try
        {
            await foreach (var raw in _raw.Reader.ReadAllAsync(token))
            {
                try
                {
                    var ev = Enrich(raw);
                    _channel.Writer.TryWrite(ev);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "富化进程事件失败(PID {pid})。", raw.Pid);
                }
            }
        }
        catch (OperationCanceledException) { /* 正常停止 */ }
    }

    /// <summary>对一条原始记录做完整富化(签名/哈希/发行商/命令行/父路径)。在后台 worker 上执行。</summary>
    private static SecurityEvent Enrich(RawProc raw)
    {
        string path = TryResolvePath(raw.Pid) ?? raw.Name;
        bool signed = ProcessInspector.IsSigned(path);
        string? hash = ProcessInspector.TryComputeSha256(path);
        string? publisher = signed ? ProcessInspector.TryGetPublisher(path) : null;
        string? cmdLine = TryGetCommandLine(raw.Pid);
        string parentPath = TryResolvePath(raw.ParentPid) ?? string.Empty;

        return new SecurityEvent
        {
            Type = EventType.ProcessCreate,
            // 时间戳在 WMI 投递时刻捕获(而非富化时刻),保证并行富化下进程链的因果顺序不被打乱。
            TimestampUtc = raw.AtUtc,
            ActorPid = raw.Pid,
            ActorPath = path,
            ActorSigned = signed,
            ActorHash = hash,
            ActorPublisher = publisher,
            ParentPid = raw.ParentPid,
            ParentPath = parentPath,
            CommandLine = cmdLine,
            Target = raw.Name,
            UserModeObserved = true,
            Detail = $"进程启动 (PID {raw.Pid}" +
                     (raw.ParentPid > 0 ? $",父 {System.IO.Path.GetFileName(parentPath)}" : "") + ")"
        };
    }

    private void StartWatcher()
    {
        try
        {
            // Win32_ProcessStartTrace 需要管理员权限
            var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
            _watcher = new ManagementEventWatcher(query);
            _watcher.EventArrived += OnProcessStarted;
            _watcher.Start();
            _logger.LogInformation("WMI 进程监控已启动(Win32_ProcessStartTrace)。");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "无法启动 WMI 进程监控(需要管理员权限)。将不会有真实事件。");
        }
    }

    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        // 关键:本方法运行在 WMI 投递线程上,必须尽快返回。只读取廉价的事件属性并入队,
        // 重 I/O(路径解析/签名/哈希/命令行查询)一律交给富化 worker,避免拖慢/丢失事件。
        try
        {
            var props = e.NewEvent.Properties;
            int pid = Convert.ToInt32(props["ProcessID"].Value);
            string name = props["ProcessName"].Value?.ToString() ?? "unknown";
            int parentPid = TryGetInt(props, "ParentProcessID");

            _raw.Writer.TryWrite(new RawProc(pid, name, parentPid, DateTime.UtcNow));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "捕获进程启动事件失败。");
        }
    }

    private static int TryGetInt(PropertyDataCollection props, string name)
    {
        try { return Convert.ToInt32(props[name].Value); }
        catch { return 0; }
    }

    /// <summary>通过 WMI 查询指定进程的命令行。</summary>
    private static string? TryGetCommandLine(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject mo in searcher.Get())
            {
                return mo["CommandLine"]?.ToString();
            }
        }
        catch { /* 进程可能已退出 / 无权限 */ }
        return null;
    }

    /// <summary>尝试解析进程的可执行文件完整路径。</summary>
    private static string? TryResolvePath(int pid)
    {
        // 优先用 QueryFullProcessImageName(对系统/跨位数进程更可靠);失败再回退 MainModule。
        var path = ProcessInspector.TryGetProcessImagePath(pid);
        if (!string.IsNullOrEmpty(path)) return path;
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            return p.MainModule?.FileName;
        }
        catch
        {
            return null; // 进程已退出 / 无权限(系统进程)
        }
    }

    public void Dispose()
    {
        try
        {
            if (_watcher is not null)
            {
                _watcher.EventArrived -= OnProcessStarted;
                _watcher.Stop();
                _watcher.Dispose();
                _watcher = null;
            }
        }
        catch { /* ignore */ }

        // 停止富化:完成原始通道使 worker 自然退出,再取消并完成输出通道。
        _raw.Writer.TryComplete();
        try { _cts?.Cancel(); } catch { /* ignore */ }
        _channel.Writer.TryComplete();
    }
}
