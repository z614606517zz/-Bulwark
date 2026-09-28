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

    // ---- 在线更新 ----
    // 两个动作都是【异步】的:检查要一次网络往返,下载是几 MB。同步等待会把 IPC 线程
    // (以及它服务的弹窗、拦截通知)一起堵住 —— 与取证查询/进程列表同一约定。
    //
    // 网络与校验全在服务端做,UI 只驱动界面:更新端点与信誉代理是同一台服务器,而端点在
    // 发布包里是混淆存放的、令牌也只在服务端配置里。让 UI 直接去取就得把解混淆和令牌搬过去,
    // 等于把「端点不落明文」做废。
    UpdateCheckRequest,         // 62 UI->服务:检查更新(服务端取清单并比较版本)
    UpdateCheckResponse,        // 63 服务->UI:清单结论(有无新版本 / 版本号 / 更新说明)
    UpdateDownloadRequest,      // 64 UI->服务:下载并校验上一次检查得到的那个版本
    UpdateProgressNotification, // 65 服务->UI:下载/校验进度(第几个文件、当前阶段)
    UpdateDownloadResponse,     // 66 服务->UI:下载结果 + 通过校验的暂存目录

    // ---- 已废弃占位:磁盘垃圾清理(功能已移除;保序,勿复用)----
    // 删功能时只删处理代码、【不删枚举项】:类型按整数上线(IpcMessage::serialize),
    // 抽掉这 5 项会让下面的 UpdateApply* 从 72/73 滑到 67/68。已发布的 1.0.2 两端仍按
    // 旧号收发,新旧混跑(在线更新替换后旧界面还没重启)时,旧界面的 JunkScanRequest(67)
    // 会被新服务当成 UpdateApplyRequest 执行。两端收到这些号都走 default 静默忽略。
    ReservedJunkScanRequest,          // 67
    ReservedJunkScanResponse,         // 68
    ReservedJunkCleanRequest,         // 69
    ReservedJunkCleanResponse,        // 70
    ReservedJunkProgressNotification, // 71

    // ---- 在线更新的应用 ----
    // 替换动作【由服务自己做】,不再由 UI 拉起提权脚本。原因不是嫌脚本麻烦,是那条路
    // 走不通:脚本是外部进程,而本产品会自我保护 —— 写安装目录被内核 SelfGuard 拒、
    // 结束自己的进程被拒(且 Stop-Process 静默失败,脚本会以为停干净了)、跑脚本的
    // powershell.exe 还会被攻击链检测打成勒索软件。服务自身正是 SelfGuard 放行的主体。
    //
    // 也不需要先结束进程:Windows 锁的是运行中映像的内容而不是目录项,改名是允许的。
    // 所以流程是「旧的改名让位 -> 新的放到原名」,进程照常运行,下次启动用新映像。
    UpdateApplyRequest,         // 72 UI->服务:就地应用已下载并校验通过的更新
    UpdateApplyResponse,        // 73 服务->UI:应用结果(已替换几个 / 是否已回退 / 是否需重启)

    // ---- 已废弃占位:大文件查找(功能已移除;保序,勿复用)----
    ReservedLargeFileScanRequest,     // 74
    ReservedLargeFileScanResponse,    // 75
};

// 序号钉桩:删改枚举项导致序号漂移时在编译期失败,而不是等到两端混跑才串号。
// 新消息一律追加在末尾,并在这里补一条。
static_assert(static_cast<int>(IpcMessageType::ReservedBehaviorSessionStart) == 23);
static_assert(static_cast<int>(IpcMessageType::AiScanRequest) == 28);
static_assert(static_cast<int>(IpcMessageType::VtScanUpdate) == 36);
static_assert(static_cast<int>(IpcMessageType::EventTimelineRequest) == 50);
static_assert(static_cast<int>(IpcMessageType::ProcessActionResponse) == 57);
static_assert(static_cast<int>(IpcMessageType::AttackChainHitNotification) == 61);
static_assert(static_cast<int>(IpcMessageType::UpdateDownloadResponse) == 66);
static_assert(static_cast<int>(IpcMessageType::UpdateApplyRequest) == 72);
static_assert(static_cast<int>(IpcMessageType::UpdateApplyResponse) == 73);
static_assert(static_cast<int>(IpcMessageType::ReservedLargeFileScanResponse) == 75);

} // namespace bulwark::ipc
