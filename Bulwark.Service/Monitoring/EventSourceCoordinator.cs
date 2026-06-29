using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Threading.Channels;
using Bulwark.Core.Models;
using Microsoft.Extensions.Logging;

namespace Bulwark.Service.Monitoring;

/// <summary>
/// 事件源协调器。始终运行一个用户态基础事件源(WMI / 模拟)用于观测;
/// 并可在运行时按用户开关动态启动/停止内核驱动事件源(Bulwark.sys),
/// 实现"内核驱动开关"。两路事件流合并后对外提供统一的事件序列。
///
/// 设计要点:
/// - 内核源默认不连接(安全),仅当用户开启开关后才尝试连接已加载的驱动。
/// - 裁决回写(IVerdictSink)会路由到产生该事件的源(只有内核源支持回写)。
/// - 内核源的启停不影响基础源,UI/规则引擎链路始终可用。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EventSourceCoordinator : IEventSource, IVerdictSink, IDisposable
{
    private readonly ILogger<EventSourceCoordinator> _logger;
    private readonly IEventSource _baseSource;
    private readonly Func<DriverEventSource> _driverFactory;

    /// <summary>用户态持续行为监控源(自启动持久化 + 勒索诱饵)。始终在线,与内核连接无关。</summary>
    private readonly UserModeBehaviorSource? _behaviorSource;

    private readonly Channel<SecurityEvent> _merged =
        Channel.CreateUnbounded<SecurityEvent>(new UnboundedChannelOptions { SingleReader = true });

    // 记录每个事件来自哪个支持回写的源(用于裁决回写路由)
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, IVerdictSink> _eventOrigin = new();

    private readonly object _gate = new();
    private DriverEventSource? _driver;
    private Task? _driverPump;
    private CancellationTokenSource? _driverCts;
    private CancellationToken _hostToken;

    /// <summary>已连接 UI 的 PID 集合,内核源(重新)启动时需要补发以维持自我保护。</summary>
    private readonly System.Collections.Generic.HashSet<int> _protectedUiPids = new();

    public EventSourceCoordinator(
        ILogger<EventSourceCoordinator> logger,
        IEventSource baseSource,
        Func<DriverEventSource> driverFactory,
        UserModeBehaviorSource? behaviorSource = null)
    {
        _logger = logger;
        _baseSource = baseSource;
        _driverFactory = driverFactory;
        _behaviorSource = behaviorSource;
    }

    /// <summary>用户态持续行为监控开关(自启动持久化 + 勒索蜜罐)。由设置驱动。</summary>
    public void ConfigureBehaviorMonitor(bool enabled, bool canaryEnabled)
    {
        if (_behaviorSource is null) return;
        _behaviorSource.Enabled = enabled;
        _behaviorSource.CanaryEnabled = canaryEnabled;
    }

    /// <summary>基础(用户态)事件源名称,用于状态展示。</summary>
    public string BaseSourceName =>
        _baseSource is WmiProcessEventSource ? "Wmi" : "Simulated";

    /// <summary>内核驱动是否已连接。</summary>
    public bool KernelConnected
    {
        get { lock (_gate) return _driver?.IsConnected == true; }
    }

    /// <summary>
    /// 是否尝试过启用内核驱动但连接失败(驱动未加载 / 被 WDAC 等代码完整性策略拦截 /
    /// 测试签名缺失等环境限制)。用于把"未连接驱动"如实呈现为「环境不支持·已降级」,
    /// 而非一直显示红色错误。开关关闭或成功连接时为 false。
    /// </summary>
    public bool KernelAttachFailed
    {
        get { lock (_gate) return _kernelAttachFailed; }
    }
    private bool _kernelAttachFailed;

    public async IAsyncEnumerable<SecurityEvent> ReadEventsAsync(
        [EnumeratorCancellation] CancellationToken token)
    {
        _hostToken = token;

        // 主机已启动:若启动早期(ApplyKernelSwitch 在 ReadEventsAsync 之前调用)
        // 已经启动了内核监督循环,把它绑到主机停止令牌上,确保服务停止时能干净退出。
        RebindKernelTokenIfNeeded();

        // 持续把基础源事件泵入合并通道
        var basePump = Task.Run(() => PumpAsync(_baseSource, sink: null, token, isBase: true), token);

        // 用户态持续行为源(若启用):始终泵送,内核连接也不抑制(文件/注册表类事件)。
        Task? behaviorPump = _behaviorSource is not null
            ? Task.Run(() => PumpAsync(_behaviorSource, sink: null, token, isBase: false), token)
            : null;

        try
        {
            await foreach (var e in _merged.Reader.ReadAllAsync(token))
                yield return e;
        }
        finally
        {
            StopKernel();
            try { await basePump.ConfigureAwait(false); } catch { /* ignore */ }
            if (behaviorPump is not null)
                try { await behaviorPump.ConfigureAwait(false); } catch { /* ignore */ }
        }
    }

    /// <summary>
    /// 早期(ReadEventsAsync 调用前)由 SetKernelEnabled 启动的监督循环,使用的是
    /// default(CancellationToken),无法响应主机停止。这里在 ReadEventsAsync 拿到
    /// 真正的主机令牌后,如果监督循环已经在跑,把它停掉再以新的令牌重启,
    /// 保证服务下线时能干净收敛。
    /// </summary>
    private void RebindKernelTokenIfNeeded()
    {
        bool needRestart = false;
        lock (_gate)
        {
            if (_driverCts is not null) needRestart = true;
        }
        if (!needRestart) return;

        _logger.LogDebug("ReadEventsAsync 已就绪,把内核监督循环重新绑定到主机停止令牌。");
        StopKernel();
        StartKernel();
    }

    /// <summary>把一个事件源的事件泵入合并通道;若源支持回写则记录来源。</summary>
    /// <param name="isBase">是否为用户态基础源(WMI/模拟)。内核连接时,基础源的
    /// 进程创建/退出事件会被抑制,避免与内核源重复上报(内核数据更全且可拦截)。</param>
    private async Task PumpAsync(IEventSource source, IVerdictSink? sink, CancellationToken token, bool isBase = false)
    {
        try
        {
            await foreach (var e in source.ReadEventsAsync(token).WithCancellation(token))
            {
                // 内核已接管进程事件时,丢弃基础源的进程创建/退出,避免重复
                if (isBase && KernelConnected &&
                    (e.Type == EventType.ProcessCreate || e.Type == EventType.ProcessTerminate))
                {
                    continue;
                }

                if (sink is not null)
                    _eventOrigin[e.Id] = sink;
                _merged.Writer.TryWrite(e);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "事件源 {src} 泵送结束。", source.GetType().Name);
        }
    }

    /// <summary>
    /// 启用或停用内核驱动事件源(由"内核驱动开关"调用)。
    /// 启用:创建并连接 DriverEventSource;失败则保持停用,不影响基础源。
    /// </summary>
    public void SetKernelEnabled(bool enabled)
    {
        if (enabled) StartKernel();
        else StopKernel();
    }

    private void StartKernel()
    {
        lock (_gate)
        {
            if (_driverCts is not null) return; // 已在运行(监督循环已启动)

            _logger.LogInformation("正在启用内核驱动事件源,尝试连接 Bulwark.sys ...");
            _kernelAttachFailed = false; // 新一轮尝试,清除上次失败标记
            _driverCts = CancellationTokenSource.CreateLinkedTokenSource(_hostToken);
            var cts = _driverCts;

            // 启动重连监督循环:连接断开后自动重试,实现驱动重启后的自愈,
            // 避免服务卡在"内核不可用"状态需要手动重启。
            _driverPump = Task.Run(() => KernelSuperviseAsync(cts));
        }
    }

    /// <summary>
    /// 内核驱动连接监督循环。在内核开关开启期间持续维持与驱动的连接:
    ///  - 成功连接后泵送事件,直到连接断开(驱动卸载/重启,或读取出错);
    ///  - 断开后按退避策略自动重连,无需用户干预;
    ///  - 用户关闭开关(取消令牌)或服务停止时退出。
    /// 退避:连接成功后掉线 -> 短延迟(3s)快速重连;始终连不上(环境不支持)->
    /// 渐进延迟(最多 30s),并在首次确认连不上时标记降级状态供 UI 展示。
    /// 日志策略:连接失败的底层错误只在第一次以错误级别打印一次;此后每次重试
    /// 把驱动侧失败日志降为 Debug,避免长时间无驱动环境刷屏。
    /// </summary>
    private async Task KernelSuperviseAsync(CancellationTokenSource cts)
    {
        int consecutiveFailures = 0;
        var token = cts.Token;

        while (!token.IsCancellationRequested)
        {
            // 自愈:每次尝试连接前,先确保驱动已按需启动(幂等:已在运行则直接成功)。
            // 这弥补了「ApplyKernelSwitch 仅启动一次,若那次失败则驱动永不加载」的缺陷——
            // 现在只要驱动可加载(测试签名/正式签名就绪),后台循环会自动把它拉起并连接,
            // 无需用户手动 sc start 或重启服务。驱动确实无法加载时,此调用快速失败、继续走连接重试退避。
            try { DriverService.TryStart(consecutiveFailures == 0 ? _logger : null); }
            catch { /* sc 调用异常不致命,继续尝试连接 */ }

            var driver = _driverFactory();
            // 第二次起的连接失败由协调器统一汇总为 Debug,驱动侧不再刷屏
            driver.QuietConnectFailures = consecutiveFailures > 0;

            lock (_gate)
            {
                if (token.IsCancellationRequested) { try { driver.Dispose(); } catch { } break; }
                _driver = driver;
                // (重新)连接时把已记录的受保护 UI PID 暂存到驱动实例,
                // 端口连接成功后由 DriverEventSource 一并下发,维持 UI 自我保护。
                foreach (var pid in _protectedUiPids)
                    driver.AddProtectedPid(pid);
            }

            var startedUtc = DateTime.UtcNow;
            try
            {
                await PumpAsync(driver, sink: driver, token);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { _logger.LogWarning(ex, "内核事件泵送异常。"); }

            // 判断本次连接是否真正建立过(运行时长 + 是否曾连接)。
            // Dispose 已把 IsConnected 置为 false,这里靠运行时长兜底。
            // 协议握手失败属于持久性环境问题(加载了不匹配的驱动),按"连不上"处理:
            // 走长退避 + 降级,而非 3 秒快速重连,避免空转刷屏。
            bool protocolMismatch = driver.ProtocolMismatch;
            bool everConnected = !protocolMismatch &&
                (driver.IsConnected || (DateTime.UtcNow - startedUtc) > TimeSpan.FromSeconds(3));

            lock (_gate)
            {
                if (ReferenceEquals(_driver, driver)) _driver = null;
            }
            try { driver.Dispose(); } catch { }

            if (token.IsCancellationRequested) break; // 用户主动停用

            if (everConnected)
            {
                // 之前已连接,现在掉线(驱动重启等)-> 快速重连,清除失败标记。
                consecutiveFailures = 0;
                lock (_gate) _kernelAttachFailed = false;
                _logger.LogWarning("内核驱动连接已断开(驱动可能卸载/重启),3 秒后自动重连…");
                await DelaySafe(TimeSpan.FromSeconds(3), token);
            }
            else
            {
                // 始终连不上 / 协议不一致 -> 环境不支持。标记降级,渐进退避重试。
                consecutiveFailures++;
                lock (_gate) _kernelAttachFailed = true;
                if (consecutiveFailures == 1)
                {
                    if (protocolMismatch)
                        _logger.LogWarning(
                            "内核驱动协议不一致,已降级为用户态观测(WMI),且绝不进行内核拦截以防误判。" +
                            "请加载与本服务同源编译的 Bulwark.sys。");
                    else
                        _logger.LogWarning(
                            "内核驱动连接失败,已自动降级为用户态观测(WMI)。将持续后台重试;" +
                            "常见原因:驱动未加载,或被系统代码完整性策略(WDAC)/测试签名限制拦截。");
                }
                else if (consecutiveFailures % 12 == 0)
                {
                    // 长时间连不上时,每 12 次(≈每 6 分钟)记一行进度,便于排障
                    _logger.LogInformation(
                        "内核驱动仍不可用(已尝试 {n} 次),后台继续重试。", consecutiveFailures);
                }
                // 协议不一致时用更长的固定退避(30s),反正重连也没用,只为感知驱动被换成正确版本。
                var backoff = protocolMismatch
                    ? TimeSpan.FromSeconds(30)
                    : TimeSpan.FromSeconds(Math.Min(30, 5 * consecutiveFailures));
                await DelaySafe(backoff, token);
            }
        }
    }

    /// <summary>可取消的延迟,取消时静默返回(不抛)。</summary>
    private static async Task DelaySafe(TimeSpan delay, CancellationToken token)
    {
        try { await Task.Delay(delay, token); }
        catch (OperationCanceledException) { }
    }

    private void StopKernel()
    {
        DriverEventSource? toDispose = null;
        CancellationTokenSource? toCancel = null;
        lock (_gate)
        {
            if (_driverCts is null) return;
            _logger.LogInformation("正在停用内核驱动事件源。");
            _kernelAttachFailed = false; // 用户主动停用,清除降级标记
            toCancel = _driverCts;
            toDispose = _driver;
            _driver = null;
            _driverCts = null;
        }
        try { toCancel?.Cancel(); } catch { }
        // 立即释放当前驱动句柄,确保通信端口释放(便于驱动卸载/重启)。
        try { toDispose?.Dispose(); } catch { }
    }

    /// <summary>把裁决回写到产生该事件的源(仅内核源需要)。</summary>
    public void SubmitVerdict(SecurityEvent e, VerdictAction action)
    {
        if (_eventOrigin.TryRemove(e.Id, out var sink))
            sink.SubmitVerdict(e, action);
    }

    /// <summary>把 UI 进程 PID 加入自我保护(若内核源在运行则下发,并记录以便重启后补发)。</summary>
    public void AddProtectedUiPid(int pid)
    {
        if (pid <= 0) return;
        lock (_gate)
        {
            _protectedUiPids.Add(pid);
            _driver?.AddProtectedPid(pid);
        }
    }

    public void Dispose() => StopKernel();
}
