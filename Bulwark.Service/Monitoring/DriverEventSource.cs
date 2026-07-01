using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading.Channels;
using Bulwark.Core.Models;
using Bulwark.Service.Driver;
using Microsoft.Extensions.Logging;

namespace Bulwark.Service.Monitoring;

/// <summary>
/// 内核驱动事件源。通过 fltlib 连接 Bulwark 驱动的通信端口,
/// 接收进程创建事件(内核侧此刻正阻塞等待裁决),把它转成 SecurityEvent
/// 交给规则引擎/UI;拿到裁决后通过 FilterReplyMessage 回写内核,
/// 决定放行或阻止该进程。
///
/// 这是真正的"驱动级主动防御":可在进程启动前拦截。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DriverEventSource : IEventSource, IVerdictSink, IModuleBlockSink, IDisposable
{
    private readonly ILogger<DriverEventSource> _logger;
    private readonly BulwarkOptions _options;
    private readonly Channel<SecurityEvent> _channel =
        Channel.CreateUnbounded<SecurityEvent>(new UnboundedChannelOptions { SingleReader = true });

    /// <summary>
    /// 原始内核消息富化队列。读取线程只负责"快进快出"地接收并入队;
    /// 由固定数量的后台 worker 做昂贵的签名/哈希富化。
    /// 有界容量:队列满表示事件风暴。对"需裁决"事件不能简单丢弃后让内核超时放行
    /// (那等于静默漏拦),而是立即对溢出事件按 fail-closed 直接回复内核(默认阻止);
    /// 仅记录类事件(自保/网络已阻断)可安全丢弃。
    /// </summary>
    private readonly Channel<BlwGetMessage> _enrichQueue =
        Channel.CreateBounded<BlwGetMessage>(new BoundedChannelOptions(EnrichCapacity)
        {
            SingleReader = false,
            FullMode = BoundedChannelFullMode.Wait
        });

    /// <summary>富化 worker 数量(限制并发的重型 P/Invoke,防止资源爆炸)。</summary>
    private static readonly int EnrichWorkers = Math.Min(4, Environment.ProcessorCount);

    /// <summary>富化队列容量。超出即视为事件风暴。</summary>
    private const int EnrichCapacity = 4096;

    /// <summary>保护 _port 上的 P/Invoke 与 Dispose 不并发(避免句柄释放竞态导致 AV)。</summary>
    private readonly object _portLock = new();

    // EventId -> 内核 MessageId(用于回复时匹配)
    private readonly ConcurrentDictionary<ulong, ulong> _eventToMessageId = new();

    private SafeFilterPortHandle? _port;
    private CancellationTokenSource? _cts;
    private Task? _readLoop;
    private volatile bool _connected;
    private uint _driverProtocolVersion;  // 驱动协议版本(用于判断是否支持沙盒功能)

    /// <summary>
    /// 在连接前由协调器调用 <see cref="AddProtectedPid"/> 排队的 UI 进程 PID。
    /// 端口连接成功后会与服务自身 PID 一起下发,避免重连后 UI 自我保护丢失。
    /// </summary>
    private readonly System.Collections.Generic.HashSet<int> _pendingPids = new();

    /// <summary>
    /// 由调用方(协调器/Worker)设置的"连接失败仅记录为 Debug"的标志。
    /// 持续无法连接时(驱动未加载/被 WDAC 拦截),协调器会按退避不断重试,
    /// 此时若每次都把 ERROR 级别日志打到控制台/事件,会形成噪音。开启后,
    /// 失败仅记 Debug,只有调用方负责输出"已降级"之类的人类可读告警。
    /// </summary>
    public bool QuietConnectFailures { get; set; }

    /// <summary>内核驱动通信端口是否已连接。</summary>
    public bool IsConnected => _connected;

    /// <summary>
    /// 是否因协议握手不一致而拒绝拦截(加载了不匹配的驱动)。这是持久性环境问题,
    /// 协调器据此走"长退避 + 降级"分支,而非 3 秒快速重连,避免刷屏与空转。
    /// </summary>
    public bool ProtocolMismatch => _protocolMismatch;
    private volatile bool _protocolMismatch;

    public DriverEventSource(ILogger<DriverEventSource> logger, BulwarkOptions options)
    {
        _logger = logger;
        _options = options;
    }

    public async IAsyncEnumerable<SecurityEvent> ReadEventsAsync(
        [EnumeratorCancellation] CancellationToken token)
    {
        if (!TryConnect())
        {
            if (QuietConnectFailures)
                _logger.LogDebug("无法连接内核驱动端口 {port}(将由协调器后台重试)。",
                    FilterApi.PortName);
            else
                _logger.LogError("无法连接内核驱动端口 {port}。请确认驱动已加载(sc start Bulwark)。",
                    FilterApi.PortName);
            yield break;
        }

        // 连接成功后立即做协议握手:校验内核与用户态的结构体布局完全一致。
        // 不一致(如加载了旧版/不匹配的驱动)时,绝不拦截 —— 结构体错位会导致
        // 裁决/PID 错乱,可能误杀关键系统进程而蓝屏(0xEF)。此时清理连接并降级。
        if (!TryHandshake())
        {
            _protocolMismatch = true;
            _logger.LogError(
                "内核驱动协议握手失败:驱动与服务的协议版本/结构体不一致,已拒绝启用内核拦截以防误判。" +
                "请用与本服务同源编译的 Bulwark.sys 重新加载驱动。");
            Dispose();
            yield break;
        }

        // 连接后立即下发受保护路径/注册表键配置
        SetProtectedPaths(_options.ProtectedPaths);
        SetFileHardBlocks(_options.FileHardBlocks);
        SetProtectedRegKeys(_options.ProtectedRegistryKeys);
        SetRegHardBlocks(_options.RegistryHardBlocks);
        SetBlockedIps(_options.BlockedRemoteEndpoints);
        // 自我保护:服务自身 + 连接前排队的 UI 进程一并下发,
        // 避免重连后只剩本服务受保护、UI 失去自保。
        int[] initialPids;
        lock (_protectedPids)
        {
            _protectedPids.Clear();
            _protectedPids.Add(Environment.ProcessId);
            foreach (var pid in _pendingPids)
                _protectedPids.Add(pid);
            _pendingPids.Clear();
            initialPids = _protectedPids.ToArray();
        }
        SetProtectedPids(initialPids);

        // 内存防护(反注入):清空并按名登记当前命中进程的 PID。
        InitMemoryProtection();

        // 文件行为遥测:开启内核对删除/重命名的观测上报,作为勒索时序聚合的数据源。
        // 这是「允许进程启动后,其后续批量加密/删原文件行为仍能被检测拦截」的关键。
        SetFileTelemetry(true);

        _cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        _readLoop = Task.Run(() => ReadLoop(_cts.Token));

        // 启动固定数量的富化 worker(并发受限的重型 P/Invoke)
        for (int i = 0; i < EnrichWorkers; i++)
            _ = Task.Run(() => EnrichWorkerAsync(_cts.Token));

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

    private bool TryConnect()
    {
        int hr = FilterApi.FilterConnectCommunicationPort(
            FilterApi.PortName, 0, IntPtr.Zero, 0, IntPtr.Zero, out var port);

        if (hr != 0)
        {
            // 持续重连场景下不刷屏:协调器在重试时把 QuietConnectFailures 置为 true,
            // 由协调器统一打印"已降级·后台重试"即可,这里降级为 Debug。
            if (QuietConnectFailures)
                _logger.LogDebug("FilterConnectCommunicationPort 失败 HRESULT=0x{hr:X8}", hr);
            else
                _logger.LogError("FilterConnectCommunicationPort 失败 HRESULT=0x{hr:X8}", hr);
            return false;
        }
        _port = port;
        _connected = true;
        _logger.LogInformation("已连接内核驱动通信端口。");
        return true;
    }

    /// <summary>
    /// 协议握手:向内核发送 BLW_CMD_HANDSHAKE,校验返回的协议版本与三个关键结构体大小
    /// 是否与用户态完全一致。一致返回 true;任何不一致或失败返回 false(调用方据此降级,
    /// 绝不拦截)。这是防止"结构体错位 -> 裁决/PID 错乱 -> 误杀关键进程蓝屏"的根因防线。
    /// </summary>
    private bool TryHandshake()
    {
        if (_port is null || _port.IsInvalid) return false;

        // 入参:一条 Command=Handshake 的 config 消息(大小必须 >= 内核 sizeof(BLW_CONFIG_MESSAGE))
        int inSize = Marshal.SizeOf<BlwConfigMessage>();
        int outSize = Marshal.SizeOf<BlwHandshakeReply>();
        IntPtr inBuf = Marshal.AllocHGlobal(inSize);
        IntPtr outBuf = Marshal.AllocHGlobal(outSize);
        try
        {
            var cfg = new BlwConfigMessage
            {
                Command = DriverConst.BlwCmdHandshake,
                Path = string.Empty
            };
            Marshal.StructureToPtr(cfg, inBuf, false);

            int hr;
            int returned;
            lock (_portLock)
            {
                if (_port is null || _port.IsInvalid || _port.IsClosed) return false;
                hr = FilterApi.FilterSendMessage(_port, inBuf, inSize, outBuf, outSize, out returned);
            }

            if (hr != 0)
            {
                _logger.LogWarning("协议握手发送失败 0x{hr:X8}(驱动可能为旧版,不支持握手命令)。", hr);
                return false;
            }
            if (returned < outSize)
            {
                _logger.LogWarning("协议握手应答长度异常:{got}/{want}。", returned, outSize);
                return false;
            }

            var reply = Marshal.PtrToStructure<BlwHandshakeReply>(outBuf);

            int expectEvent = Marshal.SizeOf<BlwEventMessage>();
            int expectConfig = Marshal.SizeOf<BlwConfigMessage>();
            int expectVerdict = Marshal.SizeOf<BlwVerdictReply>();

            bool ok =
                (reply.ProtocolVersion == DriverConst.BlwProtocolVersion ||
                 reply.ProtocolVersion == 3) &&  // 兼容旧版驱动(v3)
                reply.EventMessageSize == (uint)expectEvent &&
                reply.ConfigMessageSize == (uint)expectConfig &&
                reply.VerdictReplySize == (uint)expectVerdict;

            // 记录驱动协议版本(用于判断是否支持沙盒功能)
            _driverProtocolVersion = reply.ProtocolVersion;

            if (!ok)
            {
                _logger.LogError(
                    "协议不一致:内核(ver={kver}, event={ke}, config={kc}, verdict={kv}) " +
                    "vs 服务(ver={uver}, event={ue}, config={uc}, verdict={uv})。",
                    reply.ProtocolVersion, reply.EventMessageSize, reply.ConfigMessageSize, reply.VerdictReplySize,
                    DriverConst.BlwProtocolVersion, expectEvent, expectConfig, expectVerdict);
                return false;
            }

            bool isLegacy = reply.ProtocolVersion < DriverConst.BlwProtocolVersion;
            _logger.LogInformation("协议握手通过(ver={v}, event={e}, config={c}, verdict={vr}{legacy})。",
                reply.ProtocolVersion, reply.EventMessageSize, reply.ConfigMessageSize, reply.VerdictReplySize,
                isLegacy ? ", 旧版驱动-沙盒功能不可用" : "");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "协议握手异常。");
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(inBuf);
            Marshal.FreeHGlobal(outBuf);
        }
    }

    private void ReadLoop(CancellationToken token)
    {
        int msgSize = Marshal.SizeOf<BlwGetMessage>();
        IntPtr buffer = Marshal.AllocHGlobal(msgSize);

        try
        {
            while (!token.IsCancellationRequested && _port is not null && !_port.IsInvalid)
            {
                // 同步阻塞读取。务必保持本循环"快进快出":只读消息并复制结构体,
                // 把昂贵的签名/目录校验/哈希等富化工作交给后台任务,避免阻塞读取导致
                // 内核侧大量事件排队、裁决迟于内核超时(从而回复失败 0x801F0020 并重复投递)。
                int hr = FilterApi.FilterGetMessage(_port, buffer, msgSize, IntPtr.Zero);
                if (hr != 0)
                {
                    if (token.IsCancellationRequested) break;
                    // 0x80070103(ERROR_NO_MORE_ITEMS)/0x800704CD(ERROR_CONNECTION_INVALID)
                    // /0x800703E3(ERROR_OPERATION_ABORTED) 等通常代表驱动卸载、端口被关
                    // 或服务正在停用。把它们当作"正常断开",由协调器自愈;其他错误依旧告警。
                    bool benignDisconnect =
                        (uint)hr == 0x80070103u || (uint)hr == 0x800704CDu ||
                        (uint)hr == 0x800703E3u || (uint)hr == 0x80070006u;
                    if (benignDisconnect)
                        _logger.LogInformation("FilterGetMessage 返回 0x{hr:X8}(连接已断开),退出读取循环。", hr);
                    else
                        _logger.LogWarning("FilterGetMessage 返回 0x{hr:X8},退出读取循环(将由协调器重连)。", hr);
                    break;
                }

                var msg = Marshal.PtrToStructure<BlwGetMessage>(buffer);

                // 入队到有界富化队列,读取线程立即继续接收下一条。
                // 队列满(事件风暴)时直接丢弃 —— 当前架构下进程创建 / 映像加载 /
                // 线程创建 / 网络拦截全是「fire-and-forget 遥测」,内核侧不等待回复,
                // 因此队列满时丢弃只损失一条遥测,不会造成漏拦或挂起。
                // 仅 文件 / 注册表 仍是同步等待的拦截操作,但这两类事件量很低
                // (受保护路径列表通常很短),实际不会触发溢出。
                if (!_enrichQueue.Writer.TryWrite(msg))
                {
                    HandleOverflow(msg);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "驱动读取循环异常。");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
            _enrichQueue.Writer.TryComplete();
            _channel.Writer.TryComplete();
        }
    }

    /// <summary>富化 worker:从有界队列取原始消息,做签名/哈希富化后写入事件通道。</summary>
    private async Task EnrichWorkerAsync(CancellationToken token)
    {
        try
        {
            await foreach (var msg in _enrichQueue.Reader.ReadAllAsync(token))
            {
                try { BuildAndQueueEvent(msg); }
                catch (Exception ex) { _logger.LogError(ex, "富化 worker 处理消息失败。"); }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _logger.LogError(ex, "富化 worker 异常退出。"); }
    }

    /// <summary>对一条内核消息做富化(签名/发行商/哈希),并写入事件通道。</summary>
    private void BuildAndQueueEvent(BlwGetMessage msg)
    {
        try
        {
            var e = new SecurityEvent
            {
                Type = MapType(msg.Event.Type),
                ActorPid = (int)msg.Event.ActorPid,
            };

            if (msg.Event.Type is DriverConst.BlwEventFileDelete or DriverConst.BlwEventFileRename)
            {
                var filePath = NormalizePath(msg.Event.TargetPath);
                e.ActorPath = TryResolveProcessPath(e.ActorPid) ?? $"PID {e.ActorPid}";
                e.Target = filePath;
                e.Detail = msg.Event.Type == DriverConst.BlwEventFileDelete
                    ? "内核拦截 · 删除受保护文件"
                    : "内核拦截 · 重命名/移动受保护文件";
                EnrichActor(e);
            }
            else if (msg.Event.Type == DriverConst.BlwEventFileModify)
            {
                // 文件行为遥测(未命中名单的正常删/改名,内核未拦截)。
                // 仅用于勒索时序聚合:批量改写 / 扩展名同化 / 蜜罐触碰。
                // 原始操作类型由内核打包在 ParentPid 字段(2=删除标记,3=重命名)。
                var filePath = NormalizePath(msg.Event.TargetPath);
                // 映射到引擎能聚合的事件类型:删除标记 -> FileDelete,重命名 -> FileWrite。
                e.Type = msg.Event.ParentPid == DriverConst.BlwEventFileDelete
                    ? EventType.FileDelete
                    : EventType.FileWrite;
                e.ActorPath = TryResolveProcessPath(e.ActorPid) ?? $"PID {e.ActorPid}";
                e.Target = filePath;
                // 关键:标记为用户态观测,使 Worker 在聚合判定为 Block 时走
                // TerminateProcess 补偿处置(内核此事件未阻断、也不等待回写)。
                e.UserModeObserved = true;
                e.Detail = "文件行为遥测 · " +
                    (e.Type == EventType.FileDelete ? "删除" : "重命名/移动");
                EnrichActor(e);
            }
            else if (msg.Event.Type is DriverConst.BlwEventRegistrySetValue
                     or DriverConst.BlwEventRegistryDeleteValue
                     or DriverConst.BlwEventRegistryDeleteKey)
            {
                e.ActorPath = TryResolveProcessPath(e.ActorPid) ?? $"PID {e.ActorPid}";
                e.Target = msg.Event.TargetPath ?? string.Empty;
                e.Detail = msg.Event.Type switch
                {
                    DriverConst.BlwEventRegistrySetValue => "内核拦截 · 写入受保护注册表键",
                    DriverConst.BlwEventRegistryDeleteValue => "内核拦截 · 删除受保护注册表值",
                    _ => "内核拦截 · 删除受保护注册表键"
                };
                // 服务数据库写入(...\CurrentControlSet\Services\<名>)由 services.exe(SCM)
                // 代为执行,内核注册表回调只能归因到 SCM。此处趁内核仍同步阻塞(SCM 与
                // RPC 发起者两端线程都还卡着),追溯真正发起 RCreateService 的进程。
                TraceServiceOriginator(e);
                EnrichActor(e);
            }
            else if (msg.Event.Type == DriverConst.BlwEventSelfProtect)
            {
                e.ActorPath = TryResolveProcessPath(e.ActorPid) ?? $"PID {e.ActorPid}";
                e.Target = $"受保护进程 PID {msg.Event.ParentPid}";
                e.Detail = "内核自保 · 已剥离对本软件的危险访问权限";
                EnrichActor(e);
            }
            else if (msg.Event.Type == DriverConst.BlwEventMemoryProtect)
            {
                // 内存防护(反注入):已剥离 actor 对高价值进程(ParentPid)的写内存/远程线程权限。
                // 仅记录型:内核已原地剥权(注入已写不进去),无需用户态再处置。
                int victimPid = (int)msg.Event.ParentPid;
                e.ActorPath = TryResolveProcessPath(e.ActorPid) ?? $"PID {e.ActorPid}";
                var victimPath = TryResolveProcessPath(victimPid);
                e.Target = victimPath ?? $"PID {victimPid}";
                e.Detail = $"内核内存防护 · 已阻止跨进程注入 -> {System.IO.Path.GetFileName(e.Target)} (PID {victimPid})";
                EnrichActor(e);
            }
            else if (msg.Event.Type == DriverConst.BlwEventNetworkConnect)
            {
                e.ActorPath = TryResolveProcessPath(e.ActorPid) ?? $"PID {e.ActorPid}";
                e.Target = $"{FormatIpV4(msg.Event.RemoteIpV4)}:{msg.Event.RemotePort}";
                e.Detail = "内核拦截 · 已阻断对黑名单地址的外联";
                EnrichActor(e);
            }
            else if (msg.Event.Type == DriverConst.BlwEventImageLoad)
            {
                // 映像加载(BYOVD / DLL 侧载)。仅记录型:内核回调无法阻止加载,
                // 由规则引擎据此处置。被加载模块路径在 TargetPath。
                // ActorPid==0 表示内核驱动加载。
                bool kernelModule = e.ActorPid == 0;
                e.ActorPath = kernelModule
                    ? "内核 (驱动加载)"
                    : (TryResolveProcessPath(e.ActorPid) ?? $"PID {e.ActorPid}");
                e.Target = NormalizePath(msg.Event.TargetPath);
                // 这里的"主体签名"应针对被加载的模块本身判定(规则常用 RequireUnsigned)。
                e.ActorSigned = ProcessInspector.IsSigned(e.Target);
                e.ActorPublisher = e.ActorSigned ? ProcessInspector.TryGetPublisher(e.Target) : null;
                e.ActorHash = ProcessInspector.TryComputeSha256(e.Target);
                e.Detail = kernelModule
                    ? $"内核监控 · 加载驱动模块 {System.IO.Path.GetFileName(e.Target)}"
                    : $"内核监控 · 加载模块 {System.IO.Path.GetFileName(e.Target)}";
            }
            else if (msg.Event.Type == DriverConst.BlwEventImageBlocked)
            {
                // 内核已原地阻断「禁止加载」名单中的模块被加载(白加黑 DLL 侧载)。
                // 这是已处置通知:内核已返回 STATUS_ACCESS_DENIED,模块没能载入。
                // 仅用于记录/告警,无需用户态再处置。被拦模块路径在 TargetPath。
                e.ActorPath = e.ActorPid > 0
                    ? (TryResolveProcessPath(e.ActorPid) ?? $"PID {e.ActorPid}")
                    : "(加载方未知)";
                e.Target = NormalizePath(msg.Event.TargetPath);
                e.Detail = $"内核拦截 · 已阻止加载禁用模块 {System.IO.Path.GetFileName(e.Target)}(白加黑防护)";
                EnrichActor(e);
            }
            else if (msg.Event.Type == DriverConst.BlwEventRemoteThread)
            {
                // 远程线程注入(跨进程线程创建)。仅记录型:内核回调无法阻止。
                // Actor = 注入发起进程;目标进程 PID 在 ParentPid 字段,
                // 这里解析为目标进程完整路径供规则 TargetPattern 匹配(如 *\explorer.exe)。
                e.ActorPath = TryResolveProcessPath(e.ActorPid) ?? $"PID {e.ActorPid}";
                int victimPid = (int)msg.Event.ParentPid;
                e.Target = TryResolveProcessPath(victimPid) ?? $"PID {victimPid}";
                e.Detail = $"内核监控 · 跨进程线程注入 -> {System.IO.Path.GetFileName(e.Target)} (PID {victimPid})";
                EnrichActor(e);
            }
            else if (msg.Event.Type == DriverConst.BlwEventProcessTerminate)
            {
                // 结束进程事件:Actor 是发起结束的进程,Target 是被结束的进程。
                // 规则(KillAv / 护 lsass / 护 Defender)以 TargetPattern 匹配被结束进程路径,
                // 因此 Target 必须填「被结束进程」而非发起者。
                e.ActorPath = TryResolveProcessPath(e.ActorPid) ?? $"PID {e.ActorPid}";
                var victim = NormalizePath(msg.Event.TargetPath);
                e.Target = string.IsNullOrEmpty(victim)
                    ? (TryResolveProcessPath((int)msg.Event.ParentPid) ?? string.Empty)
                    : victim;
                e.Detail = $"内核拦截 · 结束进程 {System.IO.Path.GetFileName(e.Target)}";
                EnrichActor(e);
            }
            else
            {
                // 进程创建事件(架构上为 fire-and-forget 遥测,无需内核回复)。
                var path = NormalizePath(msg.Event.ImagePath);
                e.ActorPath = path;
                e.Target = path;
                // 补全命令行:驱动协议不携带命令行,大量规则(LOLBin / 勒索 vssadmin /
                // WMI 持久化 / bcdedit / certutil 等)依赖命令行特征。
                // 此时进程刚启动,通常仍在初始化,可读 PEB 拿命令行。
                e.CommandLine = ProcessInspector.TryGetCommandLine(e.ActorPid);
                // 解析父进程 PID/路径:用于自身白名单判定与 UI 溯源链展示。
                e.ParentPid = (int)msg.Event.ParentPid;
                e.ParentPath = TryResolveProcessPath(e.ParentPid) ?? string.Empty;
                e.Detail = $"内核遥测 · 进程创建 (父PID {msg.Event.ParentPid})";
                // 标记为「用户态观测」:Worker 据此知道 Block 时需 TerminateProcess,
                // 不再尝试通过 IVerdictSink 回写内核(内核已不等待回复)。
                e.UserModeObserved = true;
                EnrichActor(e);

                // 内存防护(反注入)增量登记:新建进程若命中目标名单,把其 PID 下发内核,
                // 使其立即获得反注入保护。
                if (_memProtNames is not null && !string.IsNullOrEmpty(path))
                {
                    var pname = System.IO.Path.GetFileName(path);
                    if (!string.IsNullOrEmpty(pname) && _memProtNames.Contains(pname))
                        AddMemProtPid(e.ActorPid);
                }
            }

            // 统一补全溯源上下文:无论事件类型,都解析「直接操作进程」的父进程链与命令行,
            // 确保每个弹窗都能展示「是哪个程序(及其调用链)触发了本次操作」。
            // 进程创建分支已自行填充父进程/命令行,EnrichOriginContext 内部仅在字段为空时补,
            // 不会覆盖已有的更权威数据。内核驱动加载(ActorPid==0)等无主体的事件自动跳过。
            EnrichOriginContext(e);

            // 关联内核 MessageId,供裁决回写。
            // 当前架构下,进程创建 / 映像加载 / 线程创建 / 自保 / 网络 全是「fire-and-forget」,
            // 内核不等待回复,因此不必追踪 MessageId。仅文件 / 注册表事件需要回写裁决。
            if (msg.Event.Type is DriverConst.BlwEventFileDelete
                or DriverConst.BlwEventFileRename
                or DriverConst.BlwEventRegistrySetValue
                or DriverConst.BlwEventRegistryDeleteValue
                or DriverConst.BlwEventRegistryDeleteKey
                or DriverConst.BlwEventProcessTerminate)
            {
                _eventToMessageId[msg.Event.EventId] = msg.Header.MessageId;
                _driverEventIds[e.Id] = msg.Event.EventId;
            }

            _channel.Writer.TryWrite(e);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "富化内核事件失败。");
        }
    }

    /// <summary>本机「首见哈希」记录(用于低流行度信号)。懒加载单例。</summary>
    private static readonly Lazy<Storage.FirstSeenStore> _firstSeen =
        new(() => new Storage.FirstSeenStore());

    /// <summary>计算主体的签名/发行商(以及哈希、证书详情、首见)。用于决策与展示。</summary>
    private static void EnrichActor(SecurityEvent e)
    {
        var path = e.ActorPath;
        if (string.IsNullOrEmpty(path) || path.StartsWith("PID ", StringComparison.Ordinal))
        {
            e.ActorSigned = false;
            return;
        }
        e.ActorSigned = ProcessInspector.IsSigned(path);
        e.ActorPublisher = ProcessInspector.TryGetPublisher(path);
        e.ActorHash = ProcessInspector.TryComputeSha256(path);

        // 银狐特征采集:签名失配 + 文件大小(文件膨胀)。
        // 注意:IsSignatureMismatch 内部会再跑一次 WinVerifyTrust(IsSigned)。这里我们
        // 已经知道 e.ActorSigned 的结果——只有"内嵌了签名但校验不通过"才算失配,因此
        // 只需检测是否内嵌签名即可,避免在进程创建同步裁决路径上重复一次签名校验。
        if (!e.ActorSigned)
            e.SignatureMismatch = ProcessInspector.HasEmbeddedSignature(path);

        // 「有正规签名的恶意软件」专项采集:证书指纹 / 有效期 / 吊销 / 过期后签名。
        // 仅对带签名的主体做(无签名无需,且省去开销)。
        if (e.ActorSigned)
        {
            try
            {
                var cert = ProcessInspector.GetCertInfo(path);
                e.ActorCertThumbprint = cert.Thumbprint;
                e.CertNotAfterUtc = cert.NotAfterUtc;
                e.SigningTimeUtc = cert.SigningTimeUtc;
                e.CertRevoked = cert.Revoked;
                e.SignedAfterCertExpiry = cert.SignedAfterCertExpiry;
            }
            catch { /* 证书读取失败不影响其余决策 */ }
        }

        // 首见判定(按哈希):带签名 + 首见 + 新证书是空壳证书木马的关键画像。
        if (!string.IsNullOrEmpty(e.ActorHash))
        {
            try { e.IsFirstSeen = _firstSeen.Value.MarkAndCheckFirstSeen(e.ActorHash); }
            catch { /* 首见库不可用时忽略 */ }
        }

        try
        {
            var fi = new System.IO.FileInfo(path);
            if (fi.Exists) e.ActorFileSize = fi.Length;
        }
        catch { /* 文件可能已被拦截/移除 */ }
    }

    /// <summary>
    /// 补全事件主体的「溯源上下文」:命令行 + 完整父进程祖先链(直接进程 → 父 → 祖父 …→ 顶层)。
    /// 内核注册表/文件/结束进程/注入等事件只携带「直接操作进程」的 PID,本方法用 OS API
    /// 实时回溯整条祖先链,使弹窗能展示「到底是哪个主程序(经由哪些子进程)触发了本次操作」。
    ///
    /// 做法:
    ///  1) 补全命令行(此刻进程多半仍存活,可读 PEB);
    ///  2) 逐级解析 父PID→父路径,把每一级祖先作为一条 <see cref="ChainEventInfo"/> 种入
    ///     <see cref="SecurityEvent.ChainContext"/>。服务端随后的 BuildContext 会与历史事件合并,
    ///     UI 的溯源链(BuildProvenanceChain)据此自上而下展示完整调用链。
    /// 已由进程创建分支单独填充父进程/命令行的事件不会被覆盖(仅在空缺时补)。
    /// </summary>
    private static void EnrichOriginContext(SecurityEvent e)
    {
        if (e.ActorPid <= 0) return; // 内核驱动加载等无主体事件跳过

        try
        {
            // 1) 命令行(大量规则与溯源展示依赖)
            if (string.IsNullOrEmpty(e.CommandLine))
                e.CommandLine = ProcessInspector.TryGetCommandLine(e.ActorPid);

            // 2) 直接父进程(填到事件本体,UI/规则的「父进程」字段)
            if (e.ParentPid <= 0)
                e.ParentPid = ProcessInspector.TryGetParentPid(e.ActorPid);
            if (e.ParentPid > 0 && string.IsNullOrEmpty(e.ParentPath))
                e.ParentPath = TryResolveProcessPath(e.ParentPid) ?? string.Empty;

            // 3) 完整祖先链:从直接进程逐级向上,把每级作为一条链节点种入 ChainContext。
            //    这样即使进程链跟踪器没有历史记录(如刚开机、首个事件),弹窗也有完整溯源。
            SeedAncestryChain(e);
        }
        catch { /* 溯源为尽力而为,失败不影响裁决 */ }
    }

    /// <summary>
    /// 用 OS API 实时回溯主体的完整父进程祖先链,把每一级(含主体自身)作为
    /// <see cref="ChainEventInfo"/> 追加到事件的 <see cref="SecurityEvent.ChainContext"/>。
    /// 防环:限制深度并记录已访问 PID。已存在的同 PID 节点不重复添加。
    /// </summary>
    private static void SeedAncestryChain(SecurityEvent e)
    {
        var existingPids = new HashSet<int>();
        foreach (var c in e.ChainContext)
            if (c.ActorPid > 0) existingPids.Add(c.ActorPid);

        var visited = new HashSet<int>();
        int cur = e.ActorPid;
        int depth = 0;
        var seeded = new List<ChainEventInfo>();

        while (cur > 0 && depth < 16 && visited.Add(cur))
        {
            int parent = (cur == e.ActorPid && e.ParentPid > 0)
                ? e.ParentPid
                : ProcessInspector.TryGetParentPid(cur);

            if (!existingPids.Contains(cur))
            {
                string curPath = (cur == e.ActorPid)
                    ? e.ActorPath
                    : (TryResolveProcessPath(cur) ?? string.Empty);

                // 跳过无法解析路径的中间节点(仅 PID 无名意义不大),但主体始终保留。
                if (cur == e.ActorPid || !string.IsNullOrEmpty(curPath))
                {
                    seeded.Add(new ChainEventInfo
                    {
                        TimestampUtc = e.TimestampUtc == default ? DateTime.UtcNow : e.TimestampUtc,
                        Type = e.Type,
                        ActorPid = cur,
                        ParentPid = parent,
                        ActorPath = curPath,
                        Target = (cur == e.ActorPid) ? e.Target : string.Empty,
                        RiskScore = (cur == e.ActorPid) ? e.RiskScore : 0
                    });
                }
            }

            if (parent <= 0) break;
            cur = parent;
            depth++;
        }

        if (seeded.Count > 0)
            e.ChainContext.AddRange(seeded);
    }

    // SecurityEvent.Id (Guid) -> 内核 EventId
    private readonly ConcurrentDictionary<Guid, ulong> _driverEventIds = new();

    /// <summary>
    /// 事件风暴溢出处置:队列已满时丢弃。
    /// 当前架构下,进程创建 / 映像加载 / 线程创建 / 网络拦截均为「fire-and-forget」,
    /// 内核不等回复,丢弃只损失一条遥测;文件/注册表为同步拦截,但事件量低,
    /// 不会真正触发溢出。一律丢弃即可,绝不阻塞读取线程。
    /// </summary>
    private void HandleOverflow(BlwGetMessage msg)
    {
        _logger.LogDebug("富化队列已满,丢弃事件 {type} id={id}(遥测可丢,稳定性优先)。",
            msg.Event.Type, msg.Event.EventId);
    }

    /// <summary>按内核 MessageId/EventId 直接回复一个裁决。线程安全(在 _portLock 内访问句柄)。</summary>
    private void ReplyToKernel(ulong messageId, ulong eventId, uint verdict)
    {
        var reply = new BlwReplyMessage
        {
            Header = new FilterReplyHeader { Status = 0, MessageId = messageId },
            Reply = new BlwVerdictReply { EventId = eventId, Verdict = verdict }
        };

        int size = Marshal.SizeOf<BlwReplyMessage>();
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(reply, buf, false);
            lock (_portLock)
            {
                if (_port is null || _port.IsInvalid || _port.IsClosed) return;
                int hr = FilterApi.FilterReplyMessage(_port, buf, size);
                if (hr != 0)
                    _logger.LogDebug("FilterReplyMessage 失败 0x{hr:X8}(内核可能已超时)", hr);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>把裁决通过 FilterReplyMessage 回写内核。</summary>
    public void SubmitVerdict(SecurityEvent e, VerdictAction action)
    {
        if (!_driverEventIds.TryRemove(e.Id, out var driverEventId)) return;
        if (!_eventToMessageId.TryRemove(driverEventId, out var messageId)) return;

        ReplyToKernel(messageId, driverEventId,
            action == VerdictAction.Block ? DriverConst.BlwVerdictBlock : DriverConst.BlwVerdictAllow);
    }

    /// <summary>
    /// 把内核传来的设备路径(\??\C:\..., \Device\...)尽量规范化为可读的 Win32 路径。
    /// </summary>
    private string NormalizePath(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return string.Empty;
        if (raw.StartsWith(@"\??\")) return raw[4..];

        // \SystemRoot\... -> C:\Windows\...
        if (raw.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return winDir + raw["\\SystemRoot".Length..];
        }
        // \Windows\... (无盘符)-> 加系统盘符
        if (raw.StartsWith(@"\Windows\", StringComparison.OrdinalIgnoreCase))
        {
            var sysDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? "C:\\";
            return sysDrive.TrimEnd('\\') + raw;
        }

        // \Device\HarddiskVolumeN\... -> 盘符:\...(通过缓存的卷映射转换)
        if (raw.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var (devicePrefix, drive) in GetVolumeMap())
            {
                if (raw.StartsWith(devicePrefix, StringComparison.OrdinalIgnoreCase))
                    return drive + raw[devicePrefix.Length..];
            }
        }
        return raw;
    }

    private List<(string Device, string Drive)>? _volumeMap;
    private DateTime _volumeMapTime;

    /// <summary>获取 \Device\HarddiskVolumeN -> 盘符 的映射(缓存 60 秒)。</summary>
    private List<(string Device, string Drive)> GetVolumeMap()
    {
        if (_volumeMap is not null && (DateTime.UtcNow - _volumeMapTime).TotalSeconds < 60)
            return _volumeMap;

        var map = new List<(string, string)>();
        try
        {
            for (char c = 'A'; c <= 'Z'; c++)
            {
                var drive = c + ":";
                var sb = new System.Text.StringBuilder(260);
                if (QueryDosDevice(drive, sb, sb.Capacity) != 0)
                    map.Add((sb.ToString(), drive));
            }
        }
        catch { /* 忽略,回退为原始路径 */ }

        _volumeMap = map;
        _volumeMapTime = DateTime.UtcNow;
        return map;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);

    private static EventType MapType(uint t) => t switch
    {
        DriverConst.BlwEventProcessTerminate => EventType.ProcessTerminate,
        DriverConst.BlwEventFileDelete => EventType.FileDelete,
        DriverConst.BlwEventFileRename => EventType.FileWrite,
        DriverConst.BlwEventRegistrySetValue => EventType.RegistryWrite,
        DriverConst.BlwEventRegistryDeleteValue => EventType.RegistryWrite,
        DriverConst.BlwEventRegistryDeleteKey => EventType.RegistryWrite,
        DriverConst.BlwEventSelfProtect => EventType.SelfProtect,
        DriverConst.BlwEventMemoryProtect => EventType.SelfProtect,
        DriverConst.BlwEventNetworkConnect => EventType.NetworkConnect,
        DriverConst.BlwEventImageLoad => EventType.ImageLoad,
        DriverConst.BlwEventImageBlocked => EventType.ImageLoad,
        DriverConst.BlwEventRemoteThread => EventType.RemoteThread,
        DriverConst.BlwEventFileModify => EventType.FileWrite,
        _ => EventType.ProcessCreate
    };

    /// <summary>
    /// 服务创建「真凶」追溯:仅当目标是服务数据库键(...\Services\<名>)且内核归因主体
    /// 是 services.exe(SCM)时触发。趁内核同步阻塞期间快照系统线程,定位真正发起
    /// RCreateService RPC 的进程,填入 OriginatorPid/Path,并据置信度提升为事件主体。
    ///
    /// 安全约束:绝不把 services.exe 自身当作可处置主体(结束 SCM 会蓝屏)。
    /// 仅当唯一确定了一个非系统的发起者时,才把主体改写为该发起者;否则保留 SCM 主体,
    /// 仅在 Detail 中列出候选,交由人工/规则判断。
    /// </summary>
    private void TraceServiceOriginator(SecurityEvent e)
    {
        try
        {
            if (!ServiceControlTracer.IsServiceDatabaseKey(e.Target)) return;

            // 仅当主体看起来是 SCM(services.exe)时才追溯,避免对普通注册表写入做无谓快照。
            bool actorIsScm = e.ActorPath.EndsWith(@"\services.exe", StringComparison.OrdinalIgnoreCase);
            if (!actorIsScm) return;

            var trace = ServiceControlTracer.Trace(e.ActorPid);
            if (trace.Candidates.Count == 0) return;

            if (trace.HighConfidence)
            {
                // 记录 SCM 作为中介,主体改写为真正的 RPC 发起者,使规则/处置/UI 看到真凶。
                e.OriginatorPid = trace.OriginatorPid;
                e.OriginatorPath = trace.OriginatorPath;

                int scmPid = e.ActorPid;
                e.ActorPid = trace.OriginatorPid;
                e.ActorPath = trace.OriginatorPath ?? $"PID {trace.OriginatorPid}";
                e.CommandLine ??= ProcessInspector.TryGetCommandLine(trace.OriginatorPid);
                e.Detail += $" · RPC 发起者 {System.IO.Path.GetFileName(e.ActorPath)}" +
                            $"(PID {trace.OriginatorPid},经 services.exe PID {scmPid})";
            }
            else
            {
                // 多个/零候选:不指认,保留 SCM 主体,仅展示候选供研判。
                var cands = string.Join(", ",
                    trace.Candidates.ConvertAll(c => $"{System.IO.Path.GetFileName(c.Path)}(PID {c.Pid})"));
                e.Detail += $" · 经 services.exe 创建,疑似 RPC 发起者:{cands}";
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "服务创建发起者追溯失败(忽略,不影响裁决)。");
        }
    }

    private static string? TryResolveProcessPath(int pid)
    {
        // 优先用 QueryFullProcessImageName(对系统/跨位数进程更可靠);
        // 失败再回退到 Process.MainModule。
        var path = ProcessInspector.TryGetProcessImagePath(pid);
        if (!string.IsNullOrEmpty(path)) return path;
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            return p.MainModule?.FileName;
        }
        catch { return null; }
    }

    /// <summary>
    /// 向内核下发受保护路径列表(先清空再逐条追加)。
    /// 文件防护仅对命中这些路径的删除/重命名进行拦截。
    /// </summary>
    public void SetProtectedPaths(IEnumerable<string> paths)
    {
        if (_port is null || _port.IsInvalid) return;

        SendConfig(DriverConst.BlwCmdClearPaths, string.Empty);
        foreach (var path in paths)
        {
            if (!string.IsNullOrWhiteSpace(path))
                SendConfig(DriverConst.BlwCmdAddPath, path.Trim());
        }
        _logger.LogInformation("已向内核下发受保护路径。");
    }

    /// <summary>
    /// 向内核下发「文件硬拦截」名单(先清空再逐条追加)。
    /// 命中名单的文件,任何【写/删/重命名/覆盖】打开都会被【内核本地直接拒绝】
    /// (STATUS_ACCESS_DENIED),只读打开放行;不发 IPC、不等用户态,原地阻断且零延迟。
    ///
    /// 比 ProtectedPaths 更强:不仅防删除/重命名,还防内容篡改。适用于「绝不允许被改一次」
    /// 的关键文件,典型如 hosts、sethc.exe/utilman.exe(粘滞键)、SAM/SECURITY 配置单元。
    /// 名单为子串匹配,应尽量精确以免误伤正常写入。
    /// </summary>
    public void SetFileHardBlocks(IEnumerable<string> paths)
    {
        if (_port is null || _port.IsInvalid) return;

        SendConfig(DriverConst.BlwCmdClearFileHard, string.Empty);
        foreach (var path in paths)
        {
            if (!string.IsNullOrWhiteSpace(path))
                SendConfig(DriverConst.BlwCmdAddFileHard, path.Trim());
        }
        _logger.LogInformation("已向内核下发文件硬拦截名单。");
    }

    /// <summary>
    /// 向内核下发受保护注册表键列表(先清空再逐条追加)。
    /// 注册表防护仅对命中这些键的写值/删值/删键进行拦截。
    /// </summary>
    public void SetProtectedRegKeys(IEnumerable<string> keys)
    {
        if (_port is null || _port.IsInvalid) return;

        SendConfig(DriverConst.BlwCmdClearRegKeys, string.Empty);
        foreach (var key in keys)
        {
            if (!string.IsNullOrWhiteSpace(key))
                SendConfig(DriverConst.BlwCmdAddRegKey, key.Trim());
        }
        _logger.LogInformation("已向内核下发受保护注册表键。");
    }

    /// <summary>
    /// 向内核下发「注册表硬拦截」名单(先清空再逐条追加)。
    /// 命中名单的注册表写入会被【内核本地直接拒绝】(STATUS_ACCESS_DENIED),
    /// 不发 IPC、不等用户态,真·原地阻断且零延迟。
    ///
    /// 重要约束:名单必须是【精确键值】(如 "\Winlogon\Shell"、"\Image File Execution Options\sethc.exe\Debugger"),
    /// 绝不可放入 "\Services" 这类系统高频写入的宽子串 —— 那会拦死系统组件。
    /// 这是为「绝不允许被改一次」的极少数关键键值准备的(防 RDP 粘滞键后门 / 调试器劫持 / Shell 替换等)。
    /// </summary>
    public void SetRegHardBlocks(IEnumerable<string> keys)
    {
        if (_port is null || _port.IsInvalid) return;

        SendConfig(DriverConst.BlwCmdClearRegHard, string.Empty);
        foreach (var key in keys)
        {
            if (!string.IsNullOrWhiteSpace(key))
                SendConfig(DriverConst.BlwCmdAddRegHard, key.Trim());
        }
        _logger.LogInformation("已向内核下发注册表硬拦截名单。");
    }

    /// <summary>
    /// 向内核下发网络黑名单(先清空再逐条追加)。
    /// 条目格式 "1.2.3.4" 或 "1.2.3.4:443"(端口省略表示任意端口)。
    /// </summary>
    public void SetBlockedIps(IEnumerable<string> entries)
    {
        if (_port is null || _port.IsInvalid) return;

        SendConfig(DriverConst.BlwCmdClearBlockIp, string.Empty);
        foreach (var entry in entries)
        {
            if (TryParseIpEndpoint(entry, out var ip, out var port))
                SendConfig(DriverConst.BlwCmdAddBlockIp, string.Empty, 0, ip, port);
            else
                _logger.LogWarning("忽略无法解析的网络黑名单条目:{entry}", entry);
        }
        _logger.LogInformation("已向内核下发网络黑名单。");
    }

    /// <summary>
    /// 运行时向内核追加单个网络黑名单条目(不清空既有)。供情报判定「某远端 IP 恶意」后
    /// 固化拦截:后续该 IP 的外联在内核层预动作拦截。ip 为点分十进制,port=0 表示任意端口。
    /// </summary>
    public void AddBlockedIp(string ip, ushort port = 0)
    {
        if (_port is null || _port.IsInvalid) return;
        var entry = port > 0 ? $"{ip}:{port}" : ip;
        if (TryParseIpEndpoint(entry, out var ipv4, out var p))
            SendConfig(DriverConst.BlwCmdAddBlockIp, string.Empty, 0, ipv4, p);
    }

    /// <summary>解析 "a.b.c.d" 或 "a.b.c.d:port" 为主机字节序 IPv4 + 端口(0=任意)。</summary>
    private static bool TryParseIpEndpoint(string entry, out uint ipHostOrder, out ushort port)
    {
        ipHostOrder = 0;
        port = 0;
        if (string.IsNullOrWhiteSpace(entry)) return false;

        var parts = entry.Trim().Split(':');
        if (!System.Net.IPAddress.TryParse(parts[0], out var addr)) return false;
        if (addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;

        var bytes = addr.GetAddressBytes(); // 网络字节序(大端)
        ipHostOrder = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) |
                      ((uint)bytes[2] << 8) | bytes[3];

        if (parts.Length > 1 && ushort.TryParse(parts[1], out var p))
            port = p;
        return true;
    }

    /// <summary>把主机字节序 IPv4 格式化为点分十进制。</summary>
    private static string FormatIpV4(uint ipHostOrder)
        => $"{(ipHostOrder >> 24) & 0xFF}.{(ipHostOrder >> 16) & 0xFF}.{(ipHostOrder >> 8) & 0xFF}.{ipHostOrder & 0xFF}";

    /// <summary>
    /// 向内核下发「内存防护(反注入)」目标 PID(单个追加)。
    /// 非可信进程对该 PID 申请写内存/远程线程权限时,内核剥离这些权限。
    /// </summary>
    public void AddMemProtPid(int pid)
    {
        if (pid <= 4) return;
        if (_port is null || _port.IsInvalid) return;
        SendConfig(DriverConst.BlwCmdAddMemProt, string.Empty, (uint)pid);
    }

    /// <summary>
    /// 开/关内核「文件行为遥测」。开启后,内核对未命中任何名单的删除/重命名操作做
    /// fire-and-forget 上报(不阻断),供用户态勒索行为时序聚合。由宿主按文件防护维度
    /// 是否启用动态下发。
    /// </summary>
    public void SetFileTelemetry(bool enabled)
    {
        if (_port is null || _port.IsInvalid) return;
        SendConfig(DriverConst.BlwCmdSetFileTelemetry, string.Empty, enabled ? 1u : 0u);
        _logger.LogInformation("已{state}内核文件行为遥测(勒索时序聚合数据源)。",
            enabled ? "开启" : "关闭");
    }

    /// <summary>
    /// 把一个模块文件路径加入内核「禁止加载」名单(IModuleBlockSink)。
    /// 此后该模块以执行/映射意图打开时被内核直接拒绝,任何进程(含合法签名宿主)
    /// 都无法再加载它 —— 专治白加黑侧载 DLL。仅对已确认恶意的模块调用。
    /// </summary>
    public bool BlockModuleLoad(string modulePath)
    {
        if (string.IsNullOrWhiteSpace(modulePath)) return false;
        if (_port is null || _port.IsInvalid) return false;
        // 下发完整路径作为精确子串;内核按大小写不敏感子串匹配,命中即拒绝执行打开。
        SendConfig(DriverConst.BlwCmdAddNoLoad, modulePath.Trim());
        _logger.LogWarning("已下发内核「禁止加载」名单:{path}", modulePath);
        return true;
    }

    /// <summary>
    /// 连接后初始化内存防护:清空内核目标列表,枚举当前所有进程,
    /// 按名匹配 <see cref="BulwarkOptions.MemoryProtectionTargets"/> 把命中进程 PID 下发内核。
    /// 此后新创建的命中进程由进程创建事件增量登记(见 BuildAndQueueEvent)。
    /// </summary>
    private void InitMemoryProtection()
    {
        if (_port is null || _port.IsInvalid) return;

        var targets = _options.MemoryProtectionTargets;
        SendConfig(DriverConst.BlwCmdClearMemProt, string.Empty);
        if (targets is null || targets.Length == 0)
        {
            _memProtNames = null;
            return;
        }

        // 构造小写文件名集合,供进程创建事件快速匹配。
        _memProtNames = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in targets)
        {
            if (string.IsNullOrWhiteSpace(t)) continue;
            _memProtNames.Add(System.IO.Path.GetFileName(t.Trim()));
        }

        int count = 0;
        try
        {
            foreach (var p in System.Diagnostics.Process.GetProcesses())
            {
                try
                {
                    if (p.Id <= 4) continue;
                    var path = TryResolveProcessPath(p.Id);
                    var name = string.IsNullOrEmpty(path) ? p.ProcessName + ".exe"
                                                          : System.IO.Path.GetFileName(path);
                    if (!string.IsNullOrEmpty(name) && _memProtNames.Contains(name))
                    {
                        AddMemProtPid(p.Id);
                        count++;
                    }
                }
                catch { /* 单个进程访问失败忽略 */ }
                finally { p.Dispose(); }
            }
        }
        catch (Exception ex) { _logger.LogDebug(ex, "枚举进程初始化内存防护失败。"); }

        _logger.LogInformation("内存防护(反注入)已启用,目标进程名 {n} 个,已登记现存进程 {c} 个。",
            _memProtNames.Count, count);
    }

    /// <summary>内存防护目标进程名集合(小写文件名)。null/空 表示未启用。</summary>
    private System.Collections.Generic.HashSet<string>? _memProtNames;

    /// <summary>
    /// 向内核下发受保护进程 PID(自我保护)。先清空再逐个追加。
    /// 默认包含本服务进程自身;可附加 UI 进程 PID。
    /// </summary>
    public void SetProtectedPids(IEnumerable<int> pids)
    {
        if (_port is null || _port.IsInvalid) return;

        SendConfig(DriverConst.BlwCmdClearPids, string.Empty);
        foreach (var pid in pids)
        {
            if (pid > 0)
                SendConfig(DriverConst.BlwCmdAddPid, string.Empty, (uint)pid);
        }
        _logger.LogInformation("已向内核下发受保护进程 PID(自我保护)。");
    }

    private readonly System.Collections.Generic.HashSet<int> _protectedPids = new() { Environment.ProcessId };

    /// <summary>追加一个受保护进程 PID(如 UI 连接时),并下发内核。</summary>
    /// <remarks>
    /// 端口尚未连接时(首次连接前 / 重连窗口中)会暂存到 <see cref="_pendingPids"/>,
    /// 端口连接成功后由 <see cref="ReadEventsAsync"/> 一并下发,确保 UI 自我保护
    /// 不会在驱动重启 / 连接抖动后丢失。
    /// </remarks>
    public void AddProtectedPid(int pid)
    {
        if (pid <= 0) return;
        bool sendNow;
        lock (_protectedPids)
        {
            if (!_protectedPids.Add(pid)) return;
            sendNow = _connected && _port is not null && !_port.IsInvalid;
            if (!sendNow) _pendingPids.Add(pid);
        }
        if (sendNow)
        {
            SendConfig(DriverConst.BlwCmdAddPid, string.Empty, (uint)pid);
            _logger.LogInformation("已将 UI 进程 PID {pid} 加入自我保护。", pid);
        }
        else
        {
            _logger.LogDebug("UI 进程 PID {pid} 已暂存,端口连接后下发。", pid);
        }
    }

    private void SendConfig(uint command, string path, uint pid = 0, uint blockIp = 0, ushort blockPort = 0)
    {
        var cfg = new BlwConfigMessage
        {
            Command = command,
            Pid = pid,
            BlockIpV4 = blockIp,
            BlockPort = blockPort,
            PathLength = (ushort)Math.Min(path.Length, DriverConst.BlwMaxPath - 1),
            Path = path.Length >= DriverConst.BlwMaxPath
                ? path[..(DriverConst.BlwMaxPath - 1)] : path
        };

        int size = Marshal.SizeOf<BlwConfigMessage>();
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(cfg, buf, false);
            // 在锁内访问句柄,避免与 Dispose() 并发释放产生竞态。
            lock (_portLock)
            {
                if (_port is null || _port.IsInvalid || _port.IsClosed) return;
                int hr = FilterApi.FilterSendMessage(_port, buf, size, IntPtr.Zero, 0, out _);
                if (hr != 0)
                    _logger.LogWarning("FilterSendMessage(config) 失败 0x{hr:X8}", hr);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    public void Dispose()
    {
        _connected = false;
        try { _cts?.Cancel(); } catch { }
        // 在锁内释放句柄,确保此刻没有其他线程正在对句柄做 P/Invoke。
        lock (_portLock)
        {
            _port?.Dispose();
            _port = null;
        }
        _enrichQueue.Writer.TryComplete();
        _channel.Writer.TryComplete();
    }
}
