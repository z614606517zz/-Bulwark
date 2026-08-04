#pragma once

namespace bulwark::ipc {

// UI 与服务之间的消息类型。序号(0 起)是【上线契约】:.NET 端按数字序列化,
// 且保留了已废弃占位以维持序号稳定。C++ 端必须与 .NET Ipc/IpcMessage.cs
// 的 IpcMessageType 逐个数字对齐,否则过渡期两端无法互通。
enum class IpcMessageType {
    PromptRequest = 0,          // 服务->UI:待裁决事件
    PromptResponse,             // UI->服务:用户裁决
    LogEntry,                   // 服务->UI:已处置日志(纯字符串负载)
    BlockNotification,          // 服务->UI:已拦截通知
    Hello,                      // 双向:握手/心跳(携带 PID 自保护)
    RulesRequest,               // UI->服务:请求规则列表
    RulesResponse,              // 服务->UI:规则列表
    DeleteRule,                 // UI->服务:删除规则
    AddRule,                    // UI->服务:新增规则
    SettingsRequest,            // UI->服务:请求运行时设置
    SettingsResponse,           // 服务->UI:运行时设置
    SettingsUpdate,             // UI->服务:更新运行时设置
    TrustListRequest,           // UI->服务:请求信任列表
    TrustListResponse,          // 服务->UI:信任列表
    AddTrust,                   // UI->服务:新增文件信任
    RemoveTrust,                // UI->服务:移除文件信任
    VtQueryRequest,             // UI->服务:VT 请求(测试/查询)
    VtQueryResponse,            // 服务->UI:VT 结果
    QuarantineListRequest,      // UI->服务:请求隔离区列表
    QuarantineListResponse,     // 服务->UI:隔离区列表
    QuarantineRestore,          // UI->服务:还原隔离条目
    QuarantineDelete,           // UI->服务:永久删除隔离条目
    QuarantineActionResult,     // 服务->UI:隔离操作结果

    // ---- 已废弃占位(保序,勿复用)----
    ReservedBehaviorSessionStart,   // 23
    ReservedBehaviorSessionResult,  // 24
    ReservedBehaviorSessionEnd,     // 25
    ReservedSandboxLaunch,          // 26
    ReservedSandboxResult,          // 27

    AiScanRequest,              // 28 服务->UI:对双击启动程序做 AI 研判
    AiScanResponse,             // 29 UI->服务:AI 研判结果
    RemediationReport,          // 30 服务->UI:足迹清理报告
    ManualQuarantineRequest,    // 31 UI->服务:强制隔离某文件
    ManualQuarantineResponse,   // 32 服务->UI:手动隔离结果
    PersistenceListRequest,     // 33 UI->服务:请求自启动持久化项
    PersistenceListResponse,    // 34 服务->UI:自启动持久化清单
    EventLogEntry,              // 35 服务->UI:结构化事件日志
    VtScanUpdate,               // 36 服务->UI:VT 扫描进度/结论
    VtHistoryRequest,           // 37 UI->服务:请求 VT 历史
    VtHistoryResponse,          // 38 服务->UI:VT 历史列表
    IntelRefreshRequest,        // 39 UI->服务:刷新情报规则
    IntelRefreshResponse,       // 40 服务->UI:情报刷新结果
    IntelApplyRequest,          // 41 UI->服务:采纳情报规则
    IntelApplyResponse,         // 42 服务->UI:情报采纳结果
    PersistenceCleanupRequest,  // 43 UI->服务:清理自启动项(高危)
    PersistenceCleanupResponse, // 44 服务->UI:自启动清理结果
    EventHistoryRequest,        // 45 UI->服务:请求结构化事件历史
    EventHistoryResponse,       // 46 服务->UI:结构化事件历史
    EventHistoryClearRequest,   // 47 UI->服务:清空结构化事件历史(活动日志/拦截记录)
    VtDetailRequest,            // 48 UI->服务:请求某哈希的 VT 完整报告(每引擎检出+元数据+行为)
    VtDetailResponse,           // 49 服务->UI:VT 完整报告

    // ---- 事件时间线 / 攻击图(取证回溯)----
    EventTimelineRequest,       // 50 UI->服务:按时间窗/类型/裁决/风险/PID/关键字查询事件时间线
    EventTimelineResponse,      // 51 服务->UI:时间线查询结果(含统计)
    AttackGraphRequest,         // 52 UI->服务:以某事件/某 PID 为种子构建攻击图
    AttackGraphResponse,        // 53 服务->UI:攻击图(节点 + 边)

    // ---- 进程管理 ----
    ProcessListRequest,         // 54 UI->服务:请求在跑进程快照(含服务/计划任务溯源)
    ProcessListResponse,        // 55 服务->UI:进程快照
    ProcessActionRequest,       // 56 UI->服务:对某进程执行处置(结束/结束进程树/挂起/恢复/隔离/信任)
    ProcessActionResponse,      // 57 服务->UI:进程处置结果

    // ---- 攻击链组合引擎 ----
    AttackChainRequest,         // 58 UI->服务:请求组合表状态 + 命中记录
    AttackChainResponse,        // 59 服务->UI:组合表状态 + 命中记录
    AttackChainClearRequest,    // 60 UI->服务:清空命中记录
    AttackChainHitNotification, // 61 服务->UI:攻击链命中即时通知(右下角自动消失的 toast)
                                //    与 BlockNotification 分开的理由:后者只在【真拦下】时发,
                                //    而攻击链命中可能以 Block / Ask / Allow 三种处置收尾 ——
                                //    最需要告知用户的恰是 Allow 那种(静默模式降级、或被信任
                                //    通道放行),那时既没有拦截通知也没有询问弹窗,完全无声。
};

} // namespace bulwark::ipc
