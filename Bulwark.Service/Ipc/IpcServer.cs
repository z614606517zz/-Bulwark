using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Bulwark.Core.Ipc;
using Bulwark.Core.Models;
using Bulwark.Service.Monitoring;

namespace Bulwark.Service.Ipc;

/// <summary>
/// 命名管道服务端。负责:
/// - 接受 UI 连接(单连接即可,UI 是唯一客户端)
/// - 向 UI 推送 PromptRequest / LogEntry
/// - 接收 UI 的 PromptResponse,并完成对应事件的裁决等待
///
/// 帧格式:每条 IpcMessage 序列化为一行 JSON,以 '\n' 结尾。
/// </summary>
public sealed class IpcServer : IAsyncDisposable
{
    private readonly ILogger<IpcServer> _logger;

    /// <summary>是否强制要求 UI 客户端带可信签名(由配置注入)。</summary>
    private readonly bool _enforceClientSignature;

    // 等待用户裁决的事件:EventId -> 完成源
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource<PromptResponsePayload>> _pending = new();

    // 等待 UI 端 AI 病毒扫描结果的事件:EventId -> 完成源
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource<AiScanResponsePayload>> _pendingScan = new();

    private NamedPipeServerStream? _pipe;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private CancellationTokenSource? _cts;
    private Task? _loop;

    public IpcServer(ILogger<IpcServer> logger, BulwarkOptions options)
    {
        _logger = logger;
        _enforceClientSignature = options.EnforceUiClientSignature;
    }

    public bool IsConnected => _pipe?.IsConnected == true;

    /// <summary>UI 请求规则列表时触发,返回当前规则集合。</summary>
    public Func<IReadOnlyCollection<DefenseRule>>? RulesRequested { get; set; }

    /// <summary>UI 请求删除某规则时触发。</summary>
    public Action<Guid>? RuleDeleteRequested { get; set; }

    /// <summary>UI 请求新增规则时触发。</summary>
    public Action<AddRulePayload>? RuleAddRequested { get; set; }

    /// <summary>UI 请求当前设置时触发,返回设置快照。</summary>
    public Func<RuntimeSettings>? SettingsRequested { get; set; }

    /// <summary>UI 提交设置更新时触发。</summary>
    public Action<RuntimeSettings>? SettingsUpdated { get; set; }

    /// <summary>UI 请求文件信任列表时触发,返回当前信任条目集合。</summary>
    public Func<IReadOnlyCollection<DefenseRule>>? TrustListRequested { get; set; }

    /// <summary>UI 请求新增文件信任时触发。</summary>
    public Action<AddTrustPayload>? TrustAddRequested { get; set; }

    /// <summary>UI 请求移除文件信任时触发。</summary>
    public Action<Guid>? TrustRemoveRequested { get; set; }

    /// <summary>
    /// UI 发起 VirusTotal 请求(测试连接 / 手动查询文件)时触发。
    /// 处理器异步返回结果,服务端据此回发 VtQueryResponse。
    /// </summary>
    public Func<VtRequestPayload, Task<VtResponsePayload>>? VtRequested { get; set; }

    /// <summary>UI 请求隔离区列表时触发,异步返回当前隔离条目。</summary>
    public Func<Task<QuarantineListResponsePayload>>? QuarantineListRequested { get; set; }

    /// <summary>UI 请求还原某隔离条目时触发,异步返回操作结果。</summary>
    public Func<Guid, Task<QuarantineActionResultPayload>>? QuarantineRestoreRequested { get; set; }

    /// <summary>UI 请求删除某隔离条目时触发,异步返回操作结果。</summary>
    public Func<Guid, Task<QuarantineActionResultPayload>>? QuarantineDeleteRequested { get; set; }

    /// <summary>UI 连接并报告其进程 PID 时触发(用于自我保护)。</summary>
    public Action<int>? UiProcessConnected { get; set; }

    /// <summary>UI 请求手动强制隔离某文件时触发(清理报告「重试隔离」)。返回 (成功, 提示)。</summary>
    public Func<string, Task<(bool ok, string message)>>? ManualQuarantineRequested { get; set; }

    /// <summary>UI 请求 VT 扫描历史记录列表时触发,返回历史记录。</summary>
    public Func<VtHistoryResponsePayload>? VtHistoryRequested { get; set; }

    /// <summary>UI 请求「立即从情报源刷新防护规则」时触发,异步返回刷新结果(含预览标记)。</summary>
    public Func<IntelRefreshRequestPayload, Task<IntelRefreshResultPayload>>? IntelRefreshRequested { get; set; }

    /// <summary>UI 端用户(经 AI 复核)确认采纳情报规则时触发,异步返回应用结果。</summary>
    public Func<IntelApplyRequestPayload, Task<IntelRefreshResultPayload>>? IntelApplyRequested { get; set; }

    public void Start(CancellationToken externalToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);
        _loop = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    private async Task AcceptLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                _pipe = CreateSecuredPipe();

                _logger.LogInformation("等待 UI 连接命名管道 {pipe} ...", PipeNames.ControlPipe);
                await _pipe.WaitForConnectionAsync(token);

                // 校验连接方:必须是本机管理员/SYSTEM 上下文,且(尽力)校验其可执行文件带可信签名。
                // 防止任意本地进程冒充 UI 关闭防护 / 加白名单 / 滥用自我保护。
                if (!ValidateClient(_pipe, out var clientPid, out var why))
                {
                    _logger.LogWarning("拒绝未授权的管道连接(PID {pid}):{why}", clientPid, why);
                    _pipe.Dispose();
                    _pipe = null;
                    await Task.Delay(200, token);
                    continue;
                }

                _logger.LogInformation("UI 已连接(PID {pid},已通过授权校验)。", clientPid);
                // 用 OS 报告的真实 PID 做自我保护,而非信任 UI 自报的 Hello.ProcessId(可伪造)。
                if (clientPid > 0)
                    UiProcessConnected?.Invoke(clientPid);

                using var reader = new StreamReader(_pipe);

                // 先发送 Hello(在后台,不阻塞读取),同时立即进入读取循环。
                // 管道缓冲区为 0 时 WriteAsync 会阻塞到对端读取,因此发送与读取必须并发。
                _ = SendAsync(IpcMessage.Create(IpcMessageType.Hello, new { service = "Bulwark" }), token);

                // 读取循环
                while (!token.IsCancellationRequested && _pipe.IsConnected)
                {
                    var line = await reader.ReadLineAsync(token);
                    if (line is null) break; // 断开
                    HandleIncoming(line);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "管道连接异常,重置后重试。");
            }
            finally
            {
                // 连接断开:取消所有挂起裁决(按超时/默认处理由上层决定)
                FailAllPending();
                _pipe?.Dispose();
                _pipe = null;
            }

            if (!token.IsCancellationRequested)
                await Task.Delay(500, token);
        }
    }

    /// <summary>
    /// 创建带访问控制的命名管道:仅 SYSTEM 与本机 Administrators 组可读写,
    /// 阻止普通/低权限进程冒充 UI 连接。
    /// </summary>
    private static NamedPipeServerStream CreateSecuredPipe()
    {
        const int inOut = 64 * 1024;

        if (OperatingSystem.IsWindows())
        {
            var security = new PipeSecurity();
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            security.AddAccessRule(new PipeAccessRule(system,
                PipeAccessRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(admins,
                PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                AccessControlType.Allow));
            // 显式拒绝 Everyone 之外的隐式访问:不添加任何其它 Allow 规则即可。

            return NamedPipeServerStreamAcl.Create(
                PipeNames.ControlPipe,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                inOut, inOut,
                security);
        }

        return new NamedPipeServerStream(
            PipeNames.ControlPipe, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, inOut, inOut);
    }

    /// <summary>
    /// 校验连接方身份。返回 OS 报告的客户端 PID(不可伪造)。
    /// 取得真实 PID,并按 <see cref="_enforceClientSignature"/> 决定是否强制要求映像带可信签名:
    ///   · 强制开启时:无法解析映像路径 / 未签名 -> 拒绝连接;
    ///   · 未开启(默认,兼容调试):未签名仅记录告警并放行。
    /// 管道 ACL 已限定为管理员/SYSTEM,这里是纵深防御的第二道。
    /// </summary>
    private bool ValidateClient(NamedPipeServerStream pipe, out int clientPid, out string why)
    {
        clientPid = 0;
        why = string.Empty;

        if (!OperatingSystem.IsWindows())
            return true; // 非 Windows 仅用于调试

        clientPid = TryGetClientPid(pipe);
        if (clientPid <= 0)
        {
            why = "无法获取客户端 PID";
            return false;
        }

        // 取客户端映像路径并校验签名。
        var imagePath = Monitoring.ProcessInspector.TryGetProcessImagePath(clientPid);
        if (string.IsNullOrEmpty(imagePath))
        {
            if (_enforceClientSignature)
            {
                why = "无法解析客户端映像路径,且已开启强制签名校验";
                return false;
            }
            // 拿不到路径(可能是受保护进程),保守放行(ACL 已兜底)。
            return true;
        }

        if (!Monitoring.ProcessInspector.IsSigned(imagePath))
        {
            if (_enforceClientSignature)
            {
                why = $"客户端 {imagePath} 未带可信签名(已开启强制签名校验)";
                return false;
            }
            _logger.LogWarning("管道客户端 {path} 未带可信签名(未开启强制校验,放行)。", imagePath);
        }
        return true;
    }

    [SupportedOSPlatform("windows")]
    private static int TryGetClientPid(NamedPipeServerStream pipe)
    {
        try
        {
            if (GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid))
                return (int)pid;
        }
        catch { /* ignore */ }
        return 0;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr hPipe, out uint clientProcessId);

    private void HandleIncoming(string line)
    {
        IpcMessage? msg;
        try { msg = IpcMessage.Deserialize(line); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "无法解析来自 UI 的消息: {line}", line);
            return;
        }
        if (msg is null) return;

        try
        {
            DispatchIncoming(msg);
        }
        catch (Exception ex)
        {
            // 处理器异常绝不能让读取循环中断(否则管道断开,UI 表现为"保存无效")
            _logger.LogError(ex, "处理 UI 消息 {type} 时出错。", msg.Type);
        }
    }

    private void DispatchIncoming(IpcMessage msg)
    {
        switch (msg.Type)
        {
            case IpcMessageType.PromptResponse:
                var resp = msg.GetPayload<PromptResponsePayload>();
                if (resp is not null && _pending.TryRemove(resp.EventId, out var tcs))
                    tcs.TrySetResult(resp);
                break;
            case IpcMessageType.AiScanResponse:
                var scan = msg.GetPayload<AiScanResponsePayload>();
                if (scan is not null && _pendingScan.TryRemove(scan.EventId, out var stcs))
                    stcs.TrySetResult(scan);
                break;
            case IpcMessageType.Hello:
                var hello = msg.GetPayload<HelloPayload>();
                // 注意:不再用 hello.ProcessId 做自我保护(可伪造)。
                // 真实 PID 已在连接校验时通过 GetNamedPipeClientProcessId 取得并注册。
                _logger.LogInformation("收到 UI Hello(自报 PID {pid},仅供参考)。",
                    hello?.ProcessId ?? 0);
                break;

            case IpcMessageType.RulesRequest:
                _ = SendRulesAsync();
                break;

            case IpcMessageType.DeleteRule:
                var del = msg.GetPayload<DeleteRulePayload>();
                if (del is not null)
                {
                    RuleDeleteRequested?.Invoke(del.RuleId);
                    _ = SendRulesAsync(); // 删除后回推最新列表
                }
                break;

            case IpcMessageType.AddRule:
                var add = msg.GetPayload<AddRulePayload>();
                if (add is not null)
                {
                    RuleAddRequested?.Invoke(add);
                    _ = SendRulesAsync(); // 新增后回推最新列表
                }
                break;

            case IpcMessageType.SettingsRequest:
                _ = SendSettingsAsync();
                break;

            case IpcMessageType.SettingsUpdate:
                var s = msg.GetPayload<RuntimeSettings>();
                if (s is not null)
                {
                    SettingsUpdated?.Invoke(s);
                    _ = SendSettingsAsync(); // 更新后回推最新设置
                }
                break;

            case IpcMessageType.TrustListRequest:
                _ = SendTrustListAsync();
                break;

            case IpcMessageType.AddTrust:
                var at = msg.GetPayload<AddTrustPayload>();
                if (at is not null && !string.IsNullOrWhiteSpace(at.ActorPath))
                {
                    TrustAddRequested?.Invoke(at);
                    _ = SendTrustListAsync(); // 新增后回推最新列表
                }
                break;

            case IpcMessageType.RemoveTrust:
                var rt = msg.GetPayload<RemoveTrustPayload>();
                if (rt is not null)
                {
                    TrustRemoveRequested?.Invoke(rt.RuleId);
                    _ = SendTrustListAsync(); // 移除后回推最新列表
                }
                break;

            case IpcMessageType.VtQueryRequest:
                var vt = msg.GetPayload<VtRequestPayload>();
                if (vt is not null)
                    _ = HandleVtRequestAsync(vt);
                break;

            case IpcMessageType.QuarantineListRequest:
                _ = SendQuarantineListAsync();
                break;

            case IpcMessageType.QuarantineRestore:
                var qr = msg.GetPayload<QuarantineActionPayload>();
                if (qr is not null)
                    _ = HandleQuarantineActionAsync(qr.Id, restore: true);
                break;

            case IpcMessageType.QuarantineDelete:
                var qd = msg.GetPayload<QuarantineActionPayload>();
                if (qd is not null)
                    _ = HandleQuarantineActionAsync(qd.Id, restore: false);
                break;

            case IpcMessageType.ManualQuarantineRequest:
                var mq = msg.GetPayload<ManualQuarantinePayload>();
                if (mq is not null)
                    _ = HandleManualQuarantineAsync(mq);
                break;

            case IpcMessageType.PersistenceListRequest:
                _ = SendPersistenceListAsync();
                break;

            case IpcMessageType.VtHistoryRequest:
                _ = SendVtHistoryAsync();
                break;

            case IpcMessageType.IntelRefreshRequest:
                var ir = msg.GetPayload<IntelRefreshRequestPayload>();
                if (ir is not null)
                    _ = HandleIntelRefreshAsync(ir);
                break;

            case IpcMessageType.IntelApplyRequest:
                var ia = msg.GetPayload<IntelApplyRequestPayload>();
                if (ia is not null)
                    _ = HandleIntelApplyAsync(ia);
                break;
        }
    }

    /// <summary>处理 UI 的「立即刷新情报规则」请求,异步执行并回推结果。</summary>
    private async Task HandleIntelRefreshAsync(IntelRefreshRequestPayload req)
    {
        IntelRefreshResultPayload result;
        try
        {
            result = IntelRefreshRequested is not null
                ? await IntelRefreshRequested.Invoke(req)
                : new IntelRefreshResultPayload { Message = "情报刷新未启用" };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "情报刷新请求处理失败");
            result = new IntelRefreshResultPayload { Success = false, Message = "刷新失败:" + ex.Message };
        }
        result.RequestId = req.RequestId;
        await SendAsync(IpcMessage.Create(IpcMessageType.IntelRefreshResponse, result), CancellationToken.None);
    }

    /// <summary>处理 UI 的「采纳(已 AI 复核的)情报规则」请求,异步应用并回推结果。</summary>
    private async Task HandleIntelApplyAsync(IntelApplyRequestPayload req)
    {
        IntelRefreshResultPayload result;
        try
        {
            result = IntelApplyRequested is not null
                ? await IntelApplyRequested.Invoke(req)
                : new IntelRefreshResultPayload { Message = "情报采纳未启用" };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "情报规则采纳处理失败");
            result = new IntelRefreshResultPayload { Success = false, Message = "采纳失败:" + ex.Message };
        }
        result.RequestId = req.RequestId;
        await SendAsync(IpcMessage.Create(IpcMessageType.IntelApplyResponse, result), CancellationToken.None);
    }

    /// <summary>向 UI 推送当前 VT 扫描历史记录列表。</summary>
    private async Task SendVtHistoryAsync()
    {
        var payload = VtHistoryRequested?.Invoke() ?? new VtHistoryResponsePayload();
        await SendAsync(IpcMessage.Create(IpcMessageType.VtHistoryResponse, payload), CancellationToken.None);
    }

    /// <summary>枚举系统自启动持久化项并回推 UI(只读审计)。在线程池上跑,避免阻塞接收循环。</summary>
    private async Task SendPersistenceListAsync()
    {
        try
        {
            var payload = await Task.Run(() =>
            {
                if (OperatingSystem.IsWindows())
                    return PersistenceScanner.Scan();
                return new PersistenceListResponsePayload { Message = "仅 Windows 支持持久化扫描" };
            });
            await SendAsync(IpcMessage.Create(IpcMessageType.PersistenceListResponse, payload), CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "持久化扫描失败");
            await SendAsync(IpcMessage.Create(IpcMessageType.PersistenceListResponse,
                new PersistenceListResponsePayload { Message = $"扫描失败:{ex.Message}" }), CancellationToken.None);
        }
    }

    /// <summary>处理 VT 请求并把结果回发 UI(以 RequestId 关联)。</summary>
    private async Task HandleVtRequestAsync(VtRequestPayload req)
    {
        VtResponsePayload resp;
        try
        {
            if (VtRequested is null)
                resp = new VtResponsePayload { RequestId = req.RequestId, Success = false, Message = "服务未启用威胁情报" };
            else
                resp = await VtRequested.Invoke(req);
        }
        catch (Exception ex)
        {
            resp = new VtResponsePayload { RequestId = req.RequestId, Success = false, Message = $"处理失败:{ex.Message}" };
        }
        resp.RequestId = req.RequestId;
        await SendAsync(IpcMessage.Create(IpcMessageType.VtQueryResponse, resp), CancellationToken.None);
    }

    /// <summary>处理手动强制隔离请求,把结果以 RequestId 关联回发 UI。</summary>
    private async Task HandleManualQuarantineAsync(ManualQuarantinePayload req)
    {
        ManualQuarantineResultPayload resp;
        try
        {
            if (ManualQuarantineRequested is null)
            {
                resp = new ManualQuarantineResultPayload
                {
                    RequestId = req.RequestId, Success = false, Message = "服务未启用隔离功能"
                };
            }
            else
            {
                var (ok, message) = await ManualQuarantineRequested.Invoke(req.Path);
                resp = new ManualQuarantineResultPayload
                {
                    RequestId = req.RequestId, Success = ok, Message = message
                };
            }
        }
        catch (Exception ex)
        {
            resp = new ManualQuarantineResultPayload
            {
                RequestId = req.RequestId, Success = false, Message = "处理失败:" + ex.Message
            };
        }
        await SendAsync(IpcMessage.Create(IpcMessageType.ManualQuarantineResponse, resp), CancellationToken.None);
    }

    /// <summary>向 UI 推送当前隔离区条目列表。</summary>
    private async Task SendQuarantineListAsync()
    {
        QuarantineListResponsePayload payload;
        try
        {
            payload = QuarantineListRequested is null
                ? new QuarantineListResponsePayload()
                : await QuarantineListRequested.Invoke();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "获取隔离区列表失败。");
            payload = new QuarantineListResponsePayload();
        }
        await SendAsync(IpcMessage.Create(IpcMessageType.QuarantineListResponse, payload), CancellationToken.None);
    }

    /// <summary>处理隔离条目的还原/删除,回发结果回执并刷新列表。</summary>
    private async Task HandleQuarantineActionAsync(Guid id, bool restore)
    {
        QuarantineActionResultPayload result;
        try
        {
            var handler = restore ? QuarantineRestoreRequested : QuarantineDeleteRequested;
            result = handler is null
                ? new QuarantineActionResultPayload { Id = id, Success = false, Message = "服务未启用隔离区" }
                : await handler.Invoke(id);
        }
        catch (Exception ex)
        {
            result = new QuarantineActionResultPayload { Id = id, Success = false, Message = $"操作失败:{ex.Message}" };
        }
        await SendAsync(IpcMessage.Create(IpcMessageType.QuarantineActionResult, result), CancellationToken.None);
        // 操作后回推最新列表,UI 无需自己再请求。
        await SendQuarantineListAsync();
    }

    /// <summary>向 UI 推送当前规则列表。</summary>
    private async Task SendRulesAsync()
    {
        var rules = RulesRequested?.Invoke() ?? Array.Empty<DefenseRule>();
        var payload = new RulesResponsePayload { Rules = rules.ToList() };
        await SendAsync(IpcMessage.Create(IpcMessageType.RulesResponse, payload), CancellationToken.None);
    }

    /// <summary>向 UI 推送当前运行时设置。</summary>
    private async Task SendSettingsAsync()
    {
        var settings = SettingsRequested?.Invoke() ?? new RuntimeSettings();
        await SendAsync(IpcMessage.Create(IpcMessageType.SettingsResponse, settings), CancellationToken.None);
    }

    /// <summary>向 UI 推送当前文件信任列表。</summary>
    private async Task SendTrustListAsync()
    {
        var entries = TrustListRequested?.Invoke() ?? Array.Empty<DefenseRule>();
        var payload = new TrustListResponsePayload { Entries = entries.ToList() };
        await SendAsync(IpcMessage.Create(IpcMessageType.TrustListResponse, payload), CancellationToken.None);
    }

    /// <summary>
    /// 向 UI 推送一个待裁决事件,并等待用户响应。
    /// 若超时或 UI 未连接,返回 null(由调用方按默认策略处置)。
    /// </summary>
    public async Task<PromptResponsePayload?> RequestPromptAsync(
        SecurityEvent e, TimeSpan timeout, CancellationToken token)
    {
        if (!IsConnected)
            return null;

        var tcs = new TaskCompletionSource<PromptResponsePayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[e.Id] = tcs;

        try
        {
            await SendAsync(IpcMessage.Create(IpcMessageType.PromptRequest, e), token);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeoutCts.CancelAfter(timeout);
            await using var reg = timeoutCts.Token.Register(() => tcs.TrySetCanceled());

            return await tcs.Task;
        }
        catch (OperationCanceledException)
        {
            return null; // 超时或取消
        }
        finally
        {
            _pending.TryRemove(e.Id, out _);
        }
    }

    /// <summary>
    /// 请求 UI 端对一个(用户双击启动的)程序做 AI 病毒扫描,并等待结果。
    /// UI 未连接 / 超时返回 null,调用方据此 fail-open(维持放行),绝不因 AI 不可用而误拦。
    /// </summary>
    public async Task<AiScanResponsePayload?> RequestAiScanAsync(
        SecurityEvent e, TimeSpan timeout, CancellationToken token)
    {
        if (!IsConnected)
            return null;

        var tcs = new TaskCompletionSource<AiScanResponsePayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingScan[e.Id] = tcs;

        try
        {
            await SendAsync(IpcMessage.Create(IpcMessageType.AiScanRequest, e), token);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeoutCts.CancelAfter(timeout);
            await using var reg = timeoutCts.Token.Register(() => tcs.TrySetCanceled());

            return await tcs.Task;
        }
        catch (OperationCanceledException)
        {
            return null; // 超时或取消
        }
        finally
        {
            _pendingScan.TryRemove(e.Id, out _);
        }
    }

    /// <summary>推送一条已处置日志(无需响应)。</summary>
    public Task PushLogAsync(object logPayload, CancellationToken token)
        => IsConnected
            ? SendAsync(IpcMessage.Create(IpcMessageType.LogEntry, logPayload), token)
            : Task.CompletedTask;

    /// <summary>推送一条"已拦截恶意行为"通知(无需响应),供 UI 弹出告知用户。</summary>
    public Task PushBlockNotificationAsync(SecurityEvent e, CancellationToken token)
        => IsConnected
            ? SendAsync(IpcMessage.Create(IpcMessageType.BlockNotification, e), token)
            : Task.CompletedTask;

    /// <summary>
    /// 推送一条「结构化事件日志」(完整事件 + 裁决),供活动日志视图回溯攻击时间线。无需响应。
    /// </summary>
    public Task PushEventLogAsync(SecurityEvent e, Bulwark.Core.Models.Verdict v, CancellationToken token)
        => IsConnected
            ? SendAsync(IpcMessage.Create(IpcMessageType.EventLogEntry,
                new EventLogPayload { Event = e, Action = v.Action, Source = v.Source }), token)
            : Task.CompletedTask;

    /// <summary>推送一次「足迹清理报告」(无需响应),供 UI 弹窗展示清理成功项与未清理项。</summary>
    public Task PushRemediationReportAsync(RemediationReportPayload report, CancellationToken token)
        => IsConnected
            ? SendAsync(IpcMessage.Create(IpcMessageType.RemediationReport, report), token)
            : Task.CompletedTask;

    /// <summary>推送一条 VT 扫描进度/结论更新(无需响应),驱动 UI 进度卡片与「VT 查询记录」视图。</summary>
    public Task PushVtScanUpdateAsync(VtScanRecord record, CancellationToken token)
        => IsConnected
            ? SendAsync(IpcMessage.Create(IpcMessageType.VtScanUpdate, record), token)
            : Task.CompletedTask;

    private async Task SendAsync(IpcMessage msg, CancellationToken token)
    {
        var pipe = _pipe;
        if (pipe is null || !pipe.IsConnected) return;
        // 直接写入管道字节(UTF-8 + 换行)。绝不调用 PipeStream.Flush/FlushAsync:
        // 它映射到 Win32 FlushFileBuffers,会阻塞直到对端读空,易与对端的发送形成死锁。
        var bytes = System.Text.Encoding.UTF8.GetBytes(msg.Serialize() + "\n");

        // 写入加超时兜底:即使 UI 端读取暂时停滞、管道缓冲区写满,单次写入也不会
        // 永久占用 _writeLock 把整条事件流(含裁决弹窗)拖死。超时即放弃本条推送,
        // 视为客户端无响应并断开,触发上层重连/重新接受连接,实现自愈。
        using var writeCts = CancellationTokenSource.CreateLinkedTokenSource(token);
        writeCts.CancelAfter(TimeSpan.FromSeconds(5));

        await _writeLock.WaitAsync(token);
        try
        {
            await pipe.WriteAsync(bytes, writeCts.Token);
        }
        catch (OperationCanceledException) when (writeCts.IsCancellationRequested && !token.IsCancellationRequested)
        {
            // 写入超时:UI 长时间未排空管道。主动断开管道,让 AcceptLoop 重置连接,
            // 避免后续所有写入持续阻塞。
            _logger.LogWarning("向 UI 推送消息超时(5s),管道可能已阻塞,重置连接。");
            try { _pipe?.Dispose(); } catch { /* ignore */ }
            _pipe = null;
        }
        finally { _writeLock.Release(); }
    }

    private void FailAllPending()
    {
        foreach (var kv in _pending)
            kv.Value.TrySetCanceled();
        _pending.Clear();
        // AI 扫描等待方也一并取消,使其 fail-open 放行,不被断开拖死。
        foreach (var kv in _pendingScan)
            kv.Value.TrySetCanceled();
        _pendingScan.Clear();
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        if (_loop is not null)
        {
            try { await _loop; } catch { /* ignore */ }
        }
        _pipe?.Dispose();
        _writeLock.Dispose();
    }
}
