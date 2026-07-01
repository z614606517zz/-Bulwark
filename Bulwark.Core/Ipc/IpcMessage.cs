using System.Text.Json;
using Bulwark.Core.Models;

namespace Bulwark.Core.Ipc;

/// <summary>
/// UI 与服务之间通过命名管道传输的消息类型。
/// </summary>
public enum IpcMessageType
{
    /// <summary>服务 -> UI:推送一个待用户裁决的事件。</summary>
    PromptRequest,
    /// <summary>UI -> 服务:用户对某事件的裁决回复。</summary>
    PromptResponse,
    /// <summary>服务 -> UI:推送一条已处置事件的日志(无需用户响应)。</summary>
    LogEntry,
    /// <summary>服务 -> UI:明确恶意行为已被直接拦截,推送通知弹窗(无需响应)。</summary>
    BlockNotification,
    /// <summary>UI <-> 服务:心跳/连接确认。</summary>
    Hello,
    /// <summary>UI -> 服务:请求当前规则列表。</summary>
    RulesRequest,
    /// <summary>服务 -> UI:返回规则列表。</summary>
    RulesResponse,
    /// <summary>UI -> 服务:删除指定规则。</summary>
    DeleteRule,
    /// <summary>UI -> 服务:新增一条规则。</summary>
    AddRule,
    /// <summary>UI -> 服务:请求当前运行时设置。</summary>
    SettingsRequest,
    /// <summary>服务 -> UI:返回运行时设置。</summary>
    SettingsResponse,
    /// <summary>UI -> 服务:更新运行时设置。</summary>
    SettingsUpdate,
    /// <summary>UI -> 服务:请求文件信任列表。</summary>
    TrustListRequest,
    /// <summary>服务 -> UI:返回文件信任列表。</summary>
    TrustListResponse,
    /// <summary>UI -> 服务:新增一条文件信任。</summary>
    AddTrust,
    /// <summary>UI -> 服务:移除一条文件信任。</summary>
    RemoveTrust,
    /// <summary>UI -> 服务:VirusTotal 请求(测试连接 / 手动查询某文件信誉)。</summary>
    VtQueryRequest,
    /// <summary>服务 -> UI:VirusTotal 请求的结果。</summary>
    VtQueryResponse,
    /// <summary>UI -> 服务:请求隔离区条目列表。</summary>
    QuarantineListRequest,
    /// <summary>服务 -> UI:返回隔离区条目列表。</summary>
    QuarantineListResponse,
    /// <summary>UI -> 服务:还原一个隔离条目到原始位置。</summary>
    QuarantineRestore,
    /// <summary>UI -> 服务:永久删除一个隔离条目。</summary>
    QuarantineDelete,
    /// <summary>服务 -> UI:隔离操作(还原/删除)结果回执。</summary>
    QuarantineActionResult,
    /// <summary>[已废弃] 原行为监控会话启动。保留占位以维持枚举序号稳定(按数字序列化)。</summary>
    [System.Obsolete("行为监控会话功能已移除,仅保留占位以维持 IPC 枚举序号稳定。")]
    ReservedBehaviorSessionStart,
    /// <summary>[已废弃] 原行为监控会话结果。保留占位以维持枚举序号稳定(按数字序列化)。</summary>
    [System.Obsolete("行为监控会话功能已移除,仅保留占位以维持 IPC 枚举序号稳定。")]
    ReservedBehaviorSessionResult,
    /// <summary>[已废弃] 原行为监控会话结束。保留占位以维持枚举序号稳定(按数字序列化)。</summary>
    [System.Obsolete("行为监控会话功能已移除,仅保留占位以维持 IPC 枚举序号稳定。")]
    ReservedBehaviorSessionEnd,
    /// <summary>[已废弃] 原 Windows Sandbox 启动。保留占位以维持枚举序号稳定(按数字序列化)。</summary>
    [System.Obsolete("Windows Sandbox 功能已移除,仅保留占位以维持 IPC 枚举序号稳定。")]
    ReservedSandboxLaunch,
    /// <summary>[已废弃] 原 Windows Sandbox 结果。保留占位以维持枚举序号稳定(按数字序列化)。</summary>
    [System.Obsolete("Windows Sandbox 功能已移除,仅保留占位以维持 IPC 枚举序号稳定。")]
    ReservedSandboxResult,
    /// <summary>
    /// 服务 -> UI:请求对一个(用户双击启动的)程序做 AI 病毒扫描。
    /// Payload 为待扫描的 <see cref="SecurityEvent"/>。UI 调用大模型研判后回 <see cref="AiScanResponse"/>。
    /// </summary>
    AiScanRequest,
    /// <summary>UI -> 服务:AI 病毒扫描结果(以事件 Id 关联请求)。</summary>
    AiScanResponse,
    /// <summary>服务 -> UI:确认恶意后的「足迹清理报告」(清理成功项 + 未能清理项及原因)。</summary>
    RemediationReport,
    /// <summary>UI -> 服务:手动强制隔离某文件(清理报告里「重试隔离」)。</summary>
    ManualQuarantineRequest,
    /// <summary>服务 -> UI:手动隔离结果。</summary>
    ManualQuarantineResponse,
    /// <summary>UI -> 服务:请求扫描系统自启动持久化项(持久化审计视图)。</summary>
    PersistenceListRequest,
    /// <summary>服务 -> UI:返回自启动持久化项清单(含风险评分与 ATT&CK 标注)。</summary>
    PersistenceListResponse,
    /// <summary>
    /// 服务 -> UI:推送一条「结构化事件日志」(含完整 SecurityEvent + 裁决),
    /// 供活动日志视图回溯任意事件(放行/询问/拦截)的攻击时间线。无需响应。
    /// </summary>
    EventLogEntry,
    /// <summary>
    /// 服务 -> UI:VirusTotal 上传扫描的实时进度/结论更新(随阶段多次推送,
    /// 以 <see cref="VtScanRecord.Id"/> 关联同一次扫描)。驱动进度卡片 + VT 查询记录视图。无需响应。
    /// </summary>
    VtScanUpdate,
    /// <summary>UI -> 服务:请求 VT 扫描历史记录列表(打开「VT 查询记录」视图时)。</summary>
    VtHistoryRequest,
    /// <summary>服务 -> UI:返回 VT 扫描历史记录列表。</summary>
    VtHistoryResponse,
    /// <summary>UI -> 服务:立即从情报源(ThreatFox)拉取并刷新一批防护规则(手动触发)。</summary>
    IntelRefreshRequest,
    /// <summary>服务 -> UI:情报刷新结果(应用规则条数 / IOC 数 / 说明)。</summary>
    IntelRefreshResponse,
    /// <summary>UI -> 服务:把用户(经 AI 复核后)确认采纳的情报规则应用到引擎。</summary>
    IntelApplyRequest,
    /// <summary>服务 -> UI:情报规则应用结果(实际生效条数 / 说明)。</summary>
    IntelApplyResponse
}

/// <summary>
/// 命名管道上传输的统一消息信封。Payload 为对应类型的 JSON 文本。
/// 采用「按行(\n)分隔的 JSON」帧格式,简单可靠。
/// </summary>
public sealed class IpcMessage
{
    public IpcMessageType Type { get; set; }
    public string Payload { get; set; } = string.Empty;

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static IpcMessage Create<T>(IpcMessageType type, T payload)
        => new() { Type = type, Payload = JsonSerializer.Serialize(payload, JsonOptions) };

    public T? GetPayload<T>()
        => JsonSerializer.Deserialize<T>(Payload, JsonOptions);

    public string Serialize()
        => JsonSerializer.Serialize(this, JsonOptions);

    public static IpcMessage? Deserialize(string line)
        => string.IsNullOrWhiteSpace(line) ? null : JsonSerializer.Deserialize<IpcMessage>(line, JsonOptions);
}

/// <summary>UI -> 服务 的裁决回复负载。</summary>
public sealed class PromptResponsePayload
{
    public System.Guid EventId { get; set; }
    public VerdictAction Action { get; set; }
    public bool Remember { get; set; }

    /// <summary>「记住」的作用范围(仅 Remember=true 时有意义):永久 / 本次会话 / 限时。</summary>
    public RememberScope Scope { get; set; } = RememberScope.Permanent;
}

/// <summary>「记住我的选择」生成规则的作用范围。降低永久误放行风险。</summary>
public enum RememberScope
{
    /// <summary>永久规则(落盘,长期有效)。</summary>
    Permanent,
    /// <summary>仅本次服务会话有效(不落盘,重启失效)。</summary>
    Session,
    /// <summary>有效 1 小时。</summary>
    OneHour,
    /// <summary>有效 1 天。</summary>
    OneDay
}

/// <summary>
/// UI -> 服务:AI 病毒扫描结果。服务以 <see cref="EventId"/> 关联其发起的扫描请求。
/// </summary>
public sealed class AiScanResponsePayload
{
    /// <summary>对应被扫描事件的 Id。</summary>
    public System.Guid EventId { get; set; }

    /// <summary>
    /// AI 是否可用并给出了有效结论。false 表示未配置 / 请求失败 / 超时,
    /// 服务据此 fail-open 维持放行,绝不因 AI 不可用而误拦。
    /// </summary>
    public bool Available { get; set; }

    /// <summary>AI 建议动作(仅 Allow / Block 有意义)。</summary>
    public VerdictAction Recommendation { get; set; } = VerdictAction.Allow;

    /// <summary>AI 给出的一句话研判说明(可空,用于日志与告警展示)。</summary>
    public string? Summary { get; set; }

    /// <summary>AI 置信度描述(高/中/低,可空)。</summary>
    public string? Confidence { get; set; }
}

/// <summary>
/// 服务 -> UI:确认恶意后的「足迹清理报告」。既列出清理成功的文件 / 自启动项,
/// 也明确告知用户哪些痕迹未能清理(及原因),做到透明而非假装全清。
/// </summary>
public sealed class RemediationReportPayload
{
    /// <summary>清理发生时间(UTC)。</summary>
    public System.DateTime TimestampUtc { get; set; } = System.DateTime.UtcNow;

    /// <summary>被处置的恶意主体路径。</summary>
    public string ActorPath { get; set; } = string.Empty;

    /// <summary>被处置的恶意主体 PID。</summary>
    public int ActorPid { get; set; }

    /// <summary>判定恶意的简要原因(命中规则 / 启发式 / AI 等)。</summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>主体载荷是否已隔离成功。</summary>
    public bool ActorQuarantined { get; set; }

    /// <summary>成功隔离的释放/关联文件原始路径。</summary>
    public System.Collections.Generic.List<string> QuarantinedFiles { get; set; } = new();

    /// <summary>成功删除的自启动持久化项(键路径\值名)。</summary>
    public System.Collections.Generic.List<string> RemovedRegistryValues { get; set; } = new();

    /// <summary>未能清理的项(连同原因 + 是否为文件),用于如实告知用户并支持「重试隔离」。</summary>
    public System.Collections.Generic.List<RemediationSkippedItem> Skipped { get; set; } = new();

    /// <summary>成功清理动作总数(文件 + 自启动)。</summary>
    public int SuccessCount => QuarantinedFiles.Count + RemovedRegistryValues.Count;
}

/// <summary>一条「未能清理」的残留项:目标、原因、是否为文件(文件项可在 UI 重试隔离)。</summary>
public sealed class RemediationSkippedItem
{
    /// <summary>残留目标(文件完整路径,或注册表项描述)。</summary>
    public string Target { get; set; } = string.Empty;

    /// <summary>未能清理的原因(人类可读)。</summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>是否为文件路径(true 时 UI 可提供「重试隔离」按钮)。</summary>
    public bool IsFile { get; set; }
}

/// <summary>UI -> 服务:用户手动请求强制隔离某个文件(用于清理报告里「重试隔离」)。</summary>
public sealed class ManualQuarantinePayload
{
    public System.Guid RequestId { get; set; } = System.Guid.NewGuid();

    /// <summary>要强制隔离的文件完整路径。</summary>
    public string Path { get; set; } = string.Empty;
}

/// <summary>服务 -> UI:手动隔离请求的结果(以 RequestId 关联)。</summary>
public sealed class ManualQuarantineResultPayload
{
    public System.Guid RequestId { get; set; }
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
}

/// <summary>服务 -> UI 的规则列表负载。</summary>
public sealed class RulesResponsePayload
{
    public System.Collections.Generic.List<DefenseRule> Rules { get; set; } = new();
}

/// <summary>UI -> 服务 的删除规则负载。</summary>
public sealed class DeleteRulePayload
{
    public System.Guid RuleId { get; set; }
}

/// <summary>UI -> 服务 的新增规则负载。</summary>
public sealed class AddRulePayload
{
    public string? ActorPath { get; set; }
    public EventType? Type { get; set; }
    public string? TargetPattern { get; set; }
    public VerdictAction Action { get; set; }
}

/// <summary>UI -> 服务 的握手负载(携带 UI 进程 PID 用于自我保护)。</summary>
public sealed class HelloPayload
{
    public int ProcessId { get; set; }
    public string Role { get; set; } = "ui";
}

/// <summary>服务 -> UI 的文件信任列表负载。</summary>
public sealed class TrustListResponsePayload
{
    public System.Collections.Generic.List<DefenseRule> Entries { get; set; } = new();
}

/// <summary>UI -> 服务 的新增文件信任负载。</summary>
public sealed class AddTrustPayload
{
    /// <summary>受信任文件的完整路径。</summary>
    public string ActorPath { get; set; } = string.Empty;

    /// <summary>可选备注/说明。</summary>
    public string? Note { get; set; }
}

/// <summary>UI -> 服务 的移除文件信任负载。</summary>
public sealed class RemoveTrustPayload
{
    public System.Guid RuleId { get; set; }
}

/// <summary>
/// UI -> 服务 的 VirusTotal 请求。两种用途:
///  - <see cref="Kind"/>=TestConnection:测试服务端 API Key 是否可用(用一个已知哈希);
///  - <see cref="Kind"/>=QueryFile:对 <see cref="FilePath"/> 指向的文件算哈希并查询信誉。
/// 用 <see cref="RequestId"/> 关联响应。
/// </summary>
public sealed class VtRequestPayload
{
    public System.Guid RequestId { get; set; } = System.Guid.NewGuid();
    public VtRequestKind Kind { get; set; }

    /// <summary>QueryFile 时:要查询的本地文件完整路径。</summary>
    public string? FilePath { get; set; }

    /// <summary>
    /// TestConnection 时:要测试的具体信誉源名称(VirusTotal / MalwareBazaar / OTX)。
    /// 为空表示测试全部已启用源。
    /// </summary>
    public string? Source { get; set; }
}

/// <summary>VirusTotal 请求类型。</summary>
public enum VtRequestKind
{
    /// <summary>测试连接 / API Key 有效性。</summary>
    TestConnection,
    /// <summary>查询指定文件的哈希信誉。</summary>
    QueryFile,
    /// <summary>请求各情报源的实时用量统计(今日已用 / 配额)。</summary>
    UsageStats
}

/// <summary>服务 -> UI 的 VirusTotal 响应。</summary>
public sealed class VtResponsePayload
{
    public System.Guid RequestId { get; set; }

    /// <summary>请求是否成功完成(网络/鉴权/查询均正常)。</summary>
    public bool Success { get; set; }

    /// <summary>失败或状态说明(成功时也可带友好提示)。</summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>查询到的信誉结论(可空:测试连接或未收录时可能为空)。</summary>
    public FileReputation? Reputation { get; set; }

    /// <summary>各情报源用量统计(仅 UsageStats 请求时填充)。</summary>
    public System.Collections.Generic.List<ReputationUsage>? Usages { get; set; }
}

/// <summary>
/// 隔离区条目的传输对象(UI 与服务共享)。与服务端 QuarantineManager 内部的
/// 元数据一一对应,仅作展示/操作用,不含仓库内文件的实际内容。
/// </summary>
public sealed class QuarantineItemPayload
{
    public System.Guid Id { get; set; }
    public string OriginalPath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public System.DateTime QuarantinedUtc { get; set; }
    public long Size { get; set; }
    public string? Sha256 { get; set; }
    public string Reason { get; set; } = string.Empty;
    public int ActorPid { get; set; }
}

/// <summary>服务 -> UI 的隔离区列表负载。</summary>
public sealed class QuarantineListResponsePayload
{
    public System.Collections.Generic.List<QuarantineItemPayload> Items { get; set; } = new();
}

/// <summary>UI -> 服务 的隔离条目操作(还原/删除)负载。</summary>
public sealed class QuarantineActionPayload
{
    public System.Guid Id { get; set; }
}

/// <summary>服务 -> UI 的隔离操作结果回执。</summary>
public sealed class QuarantineActionResultPayload
{
    public System.Guid Id { get; set; }
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
}

/// <summary>服务 -> UI 的自启动持久化项清单负载。</summary>
public sealed class PersistenceListResponsePayload
{
    /// <summary>扫描时间(UTC)。</summary>
    public System.DateTime ScannedUtc { get; set; } = System.DateTime.UtcNow;

    /// <summary>枚举到的持久化项(按风险分降序)。</summary>
    public System.Collections.Generic.List<PersistenceEntry> Entries { get; set; } = new();

    /// <summary>扫描过程中的说明/告警(如某些源因权限不足未能枚举)。</summary>
    public string Message { get; set; } = string.Empty;
}

/// <summary>
/// 服务 -> UI 的「结构化事件日志」负载:携带完整 <see cref="SecurityEvent"/>(含证据链 /
/// 技战术 / 进程链)与最终裁决。供活动日志视图列出所有值得回溯的事件,并支持点开攻击时间线。
/// </summary>
public sealed class EventLogPayload
{
    /// <summary>被处置的完整安全事件。</summary>
    public SecurityEvent Event { get; set; } = new();

    /// <summary>最终裁决动作(Allow / Block / Ask)。</summary>
    public VerdictAction Action { get; set; }

    /// <summary>裁决来源(规则 / 启发式 / 信任 / 用户 / 超时 / 默认)。</summary>
    public VerdictSource Source { get; set; }
}

/// <summary>服务 -> UI 的 VT 扫描历史记录列表负载(打开「VT 查询记录」视图时返回)。</summary>
public sealed class VtHistoryResponsePayload
{
    /// <summary>历史记录(按时间倒序,最近在前)。</summary>
    public System.Collections.Generic.List<VtScanRecord> Records { get; set; } = new();
}

/// <summary>UI -> 服务:手动触发「立即从情报源刷新防护规则」。用 RequestId 关联响应。</summary>
public sealed class IntelRefreshRequestPayload
{
    public System.Guid RequestId { get; set; } = System.Guid.NewGuid();

    /// <summary>
    /// 仅预览:为 true 时服务只拉取 IOC 并生成规则,<b>不</b>应用到引擎,把生成的规则
    /// (<see cref="IntelRefreshResultPayload.GeneratedRules"/>)回传给 UI,交 AI 复核 + 用户确认后再采纳。
    /// UI 手动点「情报刷新」走此模式;后台订阅循环仍直接应用(preview=false)。
    /// </summary>
    public bool PreviewOnly { get; set; }
}

/// <summary>服务 -> UI:情报刷新结果(以 RequestId 关联)。</summary>
public sealed class IntelRefreshResultPayload
{
    public System.Guid RequestId { get; set; }

    /// <summary>是否成功拉取并应用(feed 未启用 / 网络失败时为 false)。</summary>
    public bool Success { get; set; }

    /// <summary>本次拉取到的 IOC 条数。</summary>
    public int IocCount { get; set; }

    /// <summary>本次实际应用(生效)的防护规则条数。</summary>
    public int RulesApplied { get; set; }

    /// <summary>
    /// 预览模式下生成、但尚未应用的候选规则(供 UI 交 AI 复核 + 用户确认)。
    /// 非预览模式为空。
    /// </summary>
    public System.Collections.Generic.List<DefenseRule> GeneratedRules { get; set; } = new();

    /// <summary>
    /// 本批情报涉及的恶意家族 / 威胁类型描述(去重),供 UI 交 AI 大模型据此
    /// 合成针对性的「行为类」防护规则(进程创建 / 注册表持久化 / 注入等)。
    /// 形如「AgentTesla (payload)」。非预览模式为空。
    /// </summary>
    public System.Collections.Generic.List<string> ThreatContext { get; set; } = new();

    /// <summary>结果说明(成功/失败原因,人类可读)。</summary>
    public string Message { get; set; } = string.Empty;
}

/// <summary>
/// UI -> 服务:把用户(经 AI 复核)确认采纳的一批情报规则应用到引擎。用 RequestId 关联响应。
/// 服务端做增量合并(追加去重,不影响用户自定义/信任/内置规则)。
/// </summary>
public sealed class IntelApplyRequestPayload
{
    public System.Guid RequestId { get; set; } = System.Guid.NewGuid();

    /// <summary>用户确认采纳的规则(通常已带 ThreatFox 来源标记)。</summary>
    public System.Collections.Generic.List<DefenseRule> Rules { get; set; } = new();
}
