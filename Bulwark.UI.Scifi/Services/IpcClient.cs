using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;
using Bulwark.Core.Ipc;
using Bulwark.Core.Models;

namespace Bulwark.UI.Services;

/// <summary>
/// UI 侧命名管道客户端。连接服务,接收 PromptRequest / LogEntry,
/// 并把用户裁决回传服务。自动重连。
/// </summary>
public sealed class IpcClient : IAsyncDisposable
{
    private NamedPipeClientStream? _pipe;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    /// <summary>当前是否已连接服务且可发送。</summary>
    public bool IsConnected => _pipe?.IsConnected == true;
    private CancellationTokenSource? _cts;
    private Task? _loop;

    /// <summary>收到待裁决事件时触发(在后台线程,UI 需自行切回 Dispatcher)。</summary>
    public event Action<SecurityEvent>? PromptReceived;

    /// <summary>收到"已拦截恶意行为"通知时触发(无需响应)。</summary>
    public event Action<SecurityEvent>? BlockNotificationReceived;

    /// <summary>收到日志时触发。</summary>
    public event Action<string>? LogReceived;

    /// <summary>
    /// 收到服务端「AI 病毒扫描请求」时调用的处理器(双击启动的程序)。
    /// 由 UI 设置为调用大模型研判的实现。返回扫描结论;未设置则视为不可用(服务 fail-open)。
    /// </summary>
    public Func<SecurityEvent, Task<AiScanResponsePayload>>? AiScanHandler { get; set; }

    /// <summary>连接状态变化。</summary>
    public event Action<bool>? ConnectionChanged;

    /// <summary>收到规则列表时触发。</summary>
    public event Action<System.Collections.Generic.List<DefenseRule>>? RulesReceived;

    /// <summary>收到运行时设置时触发。</summary>
    public event Action<RuntimeSettings>? SettingsReceived;

    /// <summary>收到文件信任列表时触发。</summary>
    public event Action<System.Collections.Generic.List<DefenseRule>>? TrustListReceived;

    /// <summary>收到隔离区列表时触发。</summary>
    public event Action<System.Collections.Generic.List<QuarantineItemPayload>>? QuarantineListReceived;

    /// <summary>收到隔离操作(还原/删除)结果回执时触发。</summary>
    public event Action<QuarantineActionResultPayload>? QuarantineActionReceived;

    /// <summary>收到自启动持久化项清单时触发。</summary>
    public event Action<PersistenceListResponsePayload>? PersistenceListReceived;

    /// <summary>收到「结构化事件日志」时触发(含完整事件+裁决,供活动日志/时间线)。</summary>
    public event Action<EventLogPayload>? EventLogReceived;

    /// <summary>收到「足迹清理报告」时触发(在后台线程,UI 需自行切回 Dispatcher)。</summary>
    public event Action<RemediationReportPayload>? RemediationReportReceived;

    /// <summary>收到一条 VT 扫描进度/结论更新时触发(驱动进度卡片 + VT 查询记录视图)。</summary>
    public event Action<VtScanRecord>? VtScanUpdateReceived;

    /// <summary>收到 VT 扫描历史记录列表时触发。</summary>
    public event Action<System.Collections.Generic.List<VtScanRecord>>? VtHistoryReceived;

    /// <summary>等待响应的 VT 请求:RequestId -> 完成源。</summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, TaskCompletionSource<VtResponsePayload>> _pendingVt = new();

    /// <summary>等待响应的手动隔离请求:RequestId -> 完成源。</summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, TaskCompletionSource<ManualQuarantineResultPayload>> _pendingManualQ = new();

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => ConnectLoopAsync(_cts.Token));
    }

    private async Task ConnectLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                _pipe = new NamedPipeClientStream(
                    ".", PipeNames.ControlPipe,
                    PipeDirection.InOut, PipeOptions.Asynchronous);

                await _pipe.ConnectAsync(token);

                using var reader = new StreamReader(_pipe);

                ConnectionChanged?.Invoke(true);

                // 先在后台启动读取循环,再发送 Hello,避免双方都在发送前等待对端读取而死锁。
                var readLoop = Task.Run(async () =>
                {
                    while (!token.IsCancellationRequested && _pipe.IsConnected)
                    {
                        var line = await reader.ReadLineAsync(token);
                        if (line is null) break;
                        Dispatch(line);
                    }
                }, token);

                await SendAsync(IpcMessage.Create(IpcMessageType.Hello,
                    new HelloPayload { ProcessId = Environment.ProcessId, Role = "ui" }), token);

                await readLoop;
            }
            catch (OperationCanceledException) { break; }
            catch
            {
                // 连接失败,稍后重试
            }
            finally
            {
                ConnectionChanged?.Invoke(false);
                // 断开时取消所有等待中的 VT 请求,避免调用方永久挂起。
                foreach (var kv in _pendingVt)
                    kv.Value.TrySetCanceled();
                _pendingVt.Clear();
                foreach (var kv in _pendingManualQ)
                    kv.Value.TrySetCanceled();
                _pendingManualQ.Clear();
                _pipe?.Dispose();
                _pipe = null;
            }

            if (!token.IsCancellationRequested)
                await Task.Delay(1000, token);
        }
    }

    private void Dispatch(string line)
    {
        var msg = IpcMessage.Deserialize(line);
        if (msg is null) return;

        switch (msg.Type)
        {
            case IpcMessageType.PromptRequest:
                var e = msg.GetPayload<SecurityEvent>();
                if (e is not null) PromptReceived?.Invoke(e);
                break;
            case IpcMessageType.BlockNotification:
                var be = msg.GetPayload<SecurityEvent>();
                if (be is not null) BlockNotificationReceived?.Invoke(be);
                break;
            case IpcMessageType.LogEntry:
                LogReceived?.Invoke(msg.Payload);
                break;
            case IpcMessageType.RulesResponse:
                var rp = msg.GetPayload<RulesResponsePayload>();
                if (rp is not null) RulesReceived?.Invoke(rp.Rules);
                break;
            case IpcMessageType.SettingsResponse:
                var st = msg.GetPayload<RuntimeSettings>();
                if (st is not null) SettingsReceived?.Invoke(st);
                break;
            case IpcMessageType.TrustListResponse:
                var tp = msg.GetPayload<TrustListResponsePayload>();
                if (tp is not null) TrustListReceived?.Invoke(tp.Entries);
                break;
            case IpcMessageType.VtQueryResponse:
                var vr = msg.GetPayload<VtResponsePayload>();
                if (vr is not null && _pendingVt.TryRemove(vr.RequestId, out var vtcs))
                    vtcs.TrySetResult(vr);
                break;
            case IpcMessageType.QuarantineListResponse:
                var ql = msg.GetPayload<QuarantineListResponsePayload>();
                if (ql is not null) QuarantineListReceived?.Invoke(ql.Items);
                break;
            case IpcMessageType.QuarantineActionResult:
                var qa = msg.GetPayload<QuarantineActionResultPayload>();
                if (qa is not null) QuarantineActionReceived?.Invoke(qa);
                break;
            case IpcMessageType.AiScanRequest:
                var scanEvent = msg.GetPayload<SecurityEvent>();
                if (scanEvent is not null) _ = HandleAiScanAsync(scanEvent);
                break;
            case IpcMessageType.RemediationReport:
                var rem = msg.GetPayload<RemediationReportPayload>();
                if (rem is not null) RemediationReportReceived?.Invoke(rem);
                break;
            case IpcMessageType.ManualQuarantineResponse:
                var mqr = msg.GetPayload<ManualQuarantineResultPayload>();
                if (mqr is not null && _pendingManualQ.TryRemove(mqr.RequestId, out var mqcs))
                    mqcs.TrySetResult(mqr);
                break;
            case IpcMessageType.PersistenceListResponse:
                var pl = msg.GetPayload<PersistenceListResponsePayload>();
                if (pl is not null) PersistenceListReceived?.Invoke(pl);
                break;
            case IpcMessageType.EventLogEntry:
                var el = msg.GetPayload<EventLogPayload>();
                if (el is not null) EventLogReceived?.Invoke(el);
                break;
            case IpcMessageType.VtScanUpdate:
                var vsu = msg.GetPayload<VtScanRecord>();
                if (vsu is not null) VtScanUpdateReceived?.Invoke(vsu);
                break;
            case IpcMessageType.VtHistoryResponse:
                var vh = msg.GetPayload<VtHistoryResponsePayload>();
                if (vh is not null) VtHistoryReceived?.Invoke(vh.Records);
                break;
        }
    }

    /// <summary>
    /// 处理服务端发来的 AI 病毒扫描请求:调用注入的 <see cref="AiScanHandler"/> 研判,
    /// 把结果回发服务。处理器未设置 / 异常时回 Available=false,使服务 fail-open 放行。
    /// </summary>
    private async Task HandleAiScanAsync(SecurityEvent e)
    {
        AiScanResponsePayload resp;
        try
        {
            var handler = AiScanHandler;
            resp = handler is not null
                ? await handler(e)
                : new AiScanResponsePayload { EventId = e.Id, Available = false };
        }
        catch
        {
            resp = new AiScanResponsePayload { EventId = e.Id, Available = false };
        }
        resp.EventId = e.Id;
        await SendAsync(IpcMessage.Create(IpcMessageType.AiScanResponse, resp), CancellationToken.None);
    }

    /// <summary>把用户裁决发送回服务。</summary>
    public Task SendVerdictAsync(Guid eventId, VerdictAction action, bool remember,
        RememberScope scope = RememberScope.Permanent)
    {
        var payload = new PromptResponsePayload
        {
            EventId = eventId,
            Action = action,
            Remember = remember,
            Scope = scope
        };
        return SendAsync(IpcMessage.Create(IpcMessageType.PromptResponse, payload), CancellationToken.None);
    }

    /// <summary>请求服务返回当前规则列表。</summary>
    public Task RequestRulesAsync()
        => SendAsync(IpcMessage.Create(IpcMessageType.RulesRequest, new { }), CancellationToken.None);

    /// <summary>请求服务删除指定规则。</summary>
    public Task DeleteRuleAsync(Guid ruleId)
        => SendAsync(IpcMessage.Create(IpcMessageType.DeleteRule,
            new DeleteRulePayload { RuleId = ruleId }), CancellationToken.None);

    /// <summary>请求服务新增一条规则。</summary>
    public Task AddRuleAsync(AddRulePayload payload)
        => SendAsync(IpcMessage.Create(IpcMessageType.AddRule, payload), CancellationToken.None);

    /// <summary>请求服务返回当前运行时设置。</summary>
    public Task RequestSettingsAsync()
        => SendAsync(IpcMessage.Create(IpcMessageType.SettingsRequest, new { }), CancellationToken.None);

    /// <summary>提交更新后的运行时设置。返回是否成功发送(未连接时为 false)。</summary>
    public Task<bool> UpdateSettingsAsync(RuntimeSettings settings)
        => SendAsync(IpcMessage.Create(IpcMessageType.SettingsUpdate, settings), CancellationToken.None);

    /// <summary>请求服务返回当前文件信任列表。</summary>
    public Task RequestTrustListAsync()
        => SendAsync(IpcMessage.Create(IpcMessageType.TrustListRequest, new { }), CancellationToken.None);

    /// <summary>请求服务新增一条文件信任。</summary>
    public Task AddTrustAsync(string actorPath, string? note = null)
        => SendAsync(IpcMessage.Create(IpcMessageType.AddTrust,
            new AddTrustPayload { ActorPath = actorPath, Note = note }), CancellationToken.None);

    /// <summary>请求服务移除一条文件信任。</summary>
    public Task RemoveTrustAsync(Guid ruleId)
        => SendAsync(IpcMessage.Create(IpcMessageType.RemoveTrust,
            new RemoveTrustPayload { RuleId = ruleId }), CancellationToken.None);

    /// <summary>请求服务返回隔离区条目列表。</summary>
    public Task RequestQuarantineListAsync()
        => SendAsync(IpcMessage.Create(IpcMessageType.QuarantineListRequest, new { }), CancellationToken.None);

    /// <summary>请求服务还原一个隔离条目到原始位置。</summary>
    public Task RestoreQuarantineAsync(Guid id)
        => SendAsync(IpcMessage.Create(IpcMessageType.QuarantineRestore,
            new QuarantineActionPayload { Id = id }), CancellationToken.None);

    /// <summary>请求服务永久删除一个隔离条目。</summary>
    public Task DeleteQuarantineAsync(Guid id)
        => SendAsync(IpcMessage.Create(IpcMessageType.QuarantineDelete,
            new QuarantineActionPayload { Id = id }), CancellationToken.None);

    /// <summary>请求服务扫描系统自启动持久化项(持久化审计视图)。结果经 <see cref="PersistenceListReceived"/> 回传。</summary>
    public Task RequestPersistenceListAsync()
        => SendAsync(IpcMessage.Create(IpcMessageType.PersistenceListRequest, new { }), CancellationToken.None);

    /// <summary>请求服务返回 VT 扫描历史记录列表。结果经 <see cref="VtHistoryReceived"/> 回传。</summary>
    public Task RequestVtHistoryAsync()
        => SendAsync(IpcMessage.Create(IpcMessageType.VtHistoryRequest, new { }), CancellationToken.None);

    /// <summary>
    /// 发起一个 VirusTotal 请求(测试连接 / 手动查询文件),等待服务端响应。
    /// 服务端持有 API Key,UI 仅做请求转发与结果展示。超时返回失败响应。
    /// </summary>
    public async Task<VtResponsePayload> SendVtRequestAsync(VtRequestPayload req, TimeSpan timeout)
    {
        if (!IsConnected)
            return new VtResponsePayload { RequestId = req.RequestId, Success = false, Message = "未连接服务" };

        var tcs = new TaskCompletionSource<VtResponsePayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingVt[req.RequestId] = tcs;
        try
        {
            using var cts = new CancellationTokenSource(timeout);
            await using var reg = cts.Token.Register(() => tcs.TrySetCanceled());

            bool sent = await SendAsync(IpcMessage.Create(IpcMessageType.VtQueryRequest, req), CancellationToken.None);
            if (!sent)
                return new VtResponsePayload { RequestId = req.RequestId, Success = false, Message = "发送失败:未连接服务" };

            return await tcs.Task;
        }
        catch (OperationCanceledException)
        {
            return new VtResponsePayload { RequestId = req.RequestId, Success = false, Message = "请求超时" };
        }
        finally
        {
            _pendingVt.TryRemove(req.RequestId, out _);
        }
    }

    /// <summary>测试 VirusTotal 连接 / 服务端 API Key 有效性。</summary>
    public Task<VtResponsePayload> TestVirusTotalAsync(TimeSpan? timeout = null)
        => SendVtRequestAsync(
            new VtRequestPayload { Kind = VtRequestKind.TestConnection },
            timeout ?? TimeSpan.FromSeconds(20));

    /// <summary>测试指定威胁情报源(VirusTotal / MalwareBazaar / OTX)的连接。</summary>
    public Task<VtResponsePayload> TestReputationSourceAsync(string source, TimeSpan? timeout = null)
        => SendVtRequestAsync(
            new VtRequestPayload { Kind = VtRequestKind.TestConnection, Source = source },
            timeout ?? TimeSpan.FromSeconds(20));

    /// <summary>手动查询某文件的 VirusTotal 哈希信誉。</summary>
    public Task<VtResponsePayload> QueryFileReputationAsync(string filePath, TimeSpan? timeout = null)
        => SendVtRequestAsync(
            new VtRequestPayload { Kind = VtRequestKind.QueryFile, FilePath = filePath },
            timeout ?? TimeSpan.FromSeconds(30));

    /// <summary>
    /// 请求服务对某文件执行「强制隔离」(清理报告里「重试隔离」)。等待结果,超时/未连接返回失败。
    /// </summary>
    public async Task<ManualQuarantineResultPayload> RequestManualQuarantineAsync(string path, TimeSpan? timeout = null)
    {
        var req = new ManualQuarantinePayload { Path = path };
        if (!IsConnected)
            return new ManualQuarantineResultPayload { RequestId = req.RequestId, Success = false, Message = "未连接服务" };

        var tcs = new TaskCompletionSource<ManualQuarantineResultPayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingManualQ[req.RequestId] = tcs;
        try
        {
            using var cts = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(30));
            await using var reg = cts.Token.Register(() => tcs.TrySetCanceled());

            bool sent = await SendAsync(IpcMessage.Create(IpcMessageType.ManualQuarantineRequest, req), CancellationToken.None);
            if (!sent)
                return new ManualQuarantineResultPayload { RequestId = req.RequestId, Success = false, Message = "发送失败:未连接服务" };

            return await tcs.Task;
        }
        catch (OperationCanceledException)
        {
            return new ManualQuarantineResultPayload { RequestId = req.RequestId, Success = false, Message = "请求超时" };
        }
        finally
        {
            _pendingManualQ.TryRemove(req.RequestId, out _);
        }
    }

    private async Task<bool> SendAsync(IpcMessage msg, CancellationToken token)
    {
        var pipe = _pipe;
        if (pipe is null || !pipe.IsConnected) return false;
        // 直接写入管道字节(UTF-8 + 换行)。绝不调用 PipeStream.Flush/FlushAsync:
        // 它映射到 Win32 FlushFileBuffers,会阻塞直到对端读空,易与对端发送形成死锁。
        var bytes = System.Text.Encoding.UTF8.GetBytes(msg.Serialize() + "\n");
        await _writeLock.WaitAsync(token);
        try
        {
            await pipe.WriteAsync(bytes, token);
            return true;
        }
        catch { return false; /* 断开时忽略 */ }
        finally { _writeLock.Release(); }
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        if (_loop is not null)
        {
            try { await _loop; } catch { }
        }
        _pipe?.Dispose();
        _writeLock.Dispose();
    }
}
