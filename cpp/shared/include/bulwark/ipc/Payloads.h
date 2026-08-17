#pragma once
#include <QString>
#include <QStringList>
#include <QUuid>
#include <QList>
#include <QDateTime>
#include <QJsonObject>
#include <optional>
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/models/FileReputation.h"
#include "bulwark/models/ReputationUsage.h"
#include "bulwark/models/PersistenceEntry.h"
#include "bulwark/models/VtScanRecord.h"
#include "bulwark/models/AttackGraph.h"
#include "bulwark/models/ProcessEntry.h"
#include "bulwark/models/JunkEntry.h"

// IPC payload DTOs. Phase-0 seeds the handshake + verdict payloads to exercise
// the envelope end-to-end; the remaining ~30 payloads are ported in the
// service/UI phases when their exact usage is in front of us.
namespace bulwark::ipc {

// UI -> 服务:握手(携带 UI 进程 PID,供服务自我保护)。
struct HelloPayload {
    int processId = 0;
    QString role = QStringLiteral("ui");

    QJsonObject toJson() const;
    static HelloPayload fromJson(const QJsonObject& o);
};

// UI -> 服务:用户对某事件的裁决回复。
struct PromptResponsePayload {
    QUuid eventId;
    VerdictAction action = VerdictAction::Allow;
    bool remember = false;
    RememberScope scope = RememberScope::Permanent;

    QJsonObject toJson() const;
    static PromptResponsePayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:结构化事件日志(完整 SecurityEvent + 裁决),供活动日志/时间线回溯任意事件。
struct EventLogPayload {
    bulwark::SecurityEvent event;
    VerdictAction action = VerdictAction::Allow;
    VerdictSource source = VerdictSource::DefaultPolicy;
    // 实际执行结果(与 action 区分:action 是裁决意图,enforcement 是真的做了什么)。
    // UI 据此如实显示处置,杜绝假拦截。
    bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;

    QJsonObject toJson() const;
    static EventLogPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:结构化事件历史(最近 N 条 EventLogPayload,时间升序,与实时推送同构)。
struct EventHistoryResponsePayload {
    QList<EventLogPayload> events;

    QJsonObject toJson() const;
    static EventHistoryResponsePayload fromJson(const QJsonObject& o);
};

// 一条「未能清理」的残留项:目标 / 原因 / 是否文件(文件项 UI 可「重试隔离」)。
struct RemediationSkippedItem {
    QString target;   // file path, or a registry-item description
    QString reason;   // human-readable
    bool isFile = false;

    QJsonObject toJson() const;
    static RemediationSkippedItem fromJson(const QJsonObject& o);
};

// ===== 规则管理 =====
// 服务 -> UI:当前规则列表。
struct RulesResponsePayload {
    QList<bulwark::DefenseRule> rules;
    QJsonObject toJson() const;
    static RulesResponsePayload fromJson(const QJsonObject& o);
};

// UI -> 服务:删除规则。
struct DeleteRulePayload {
    QUuid ruleId;
    QJsonObject toJson() const;
    static DeleteRulePayload fromJson(const QJsonObject& o);
};

// UI -> 服务:新增规则(主体字符串由服务智能解析为精确/通配)。
struct AddRulePayload {
    QString actorPath;
    std::optional<bulwark::EventType> type;
    QString targetPattern;
    bulwark::VerdictAction action = bulwark::VerdictAction::Allow;
    QJsonObject toJson() const;
    static AddRulePayload fromJson(const QJsonObject& o);
};

// ===== 文件信任 =====
// 服务 -> UI:文件信任列表(本质是带信任标记的 Allow 规则)。
struct TrustListResponsePayload {
    QList<bulwark::DefenseRule> entries;
    QJsonObject toJson() const;
    static TrustListResponsePayload fromJson(const QJsonObject& o);
};

// UI -> 服务:新增信任(文件或文件夹)。isDirectory=true 时 actorPath 为目录,
// 该目录及其子目录下运行的所有程序都将「完全跳过检测」直接放行。
struct AddTrustPayload {
    QString actorPath;
    QString note;
    bool isDirectory = false;
    QJsonObject toJson() const;
    static AddTrustPayload fromJson(const QJsonObject& o);
};

// UI -> 服务:移除文件信任。
struct RemoveTrustPayload {
    QUuid ruleId;
    QJsonObject toJson() const;
    static RemoveTrustPayload fromJson(const QJsonObject& o);
};

// ===== 威胁情报 / VirusTotal =====
// UI -> 服务:VT 请求(测试连接 / 查询文件 / 用量统计)。
struct VtRequestPayload {
    QUuid requestId = QUuid::createUuid();
    bulwark::VtRequestKind kind = bulwark::VtRequestKind::TestConnection;
    QString filePath;
    QString source;
    QJsonObject toJson() const;
    static VtRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:VT 响应。
struct VtResponsePayload {
    QUuid requestId;
    bool success = false;
    QString message;
    std::optional<bulwark::FileReputation> reputation;
    std::optional<QList<bulwark::ReputationUsage>> usages;
    QJsonObject toJson() const;
    static VtResponsePayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:VT 扫描历史列表。
struct VtHistoryResponsePayload {
    QList<bulwark::VtScanRecord> records;
    QJsonObject toJson() const;
    static VtHistoryResponsePayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:某哈希的 VT 完整报告(供云信誉详情弹窗按需拉取,展示"更全面"的信息)。
// 含文件元数据、每引擎具体检出名、以及行为画像 IOC(聚合 VT + HybridAnalysis)。
struct VtDetailResponsePayload {
    QUuid requestId;
    QString sha256;
    bool success = false;
    QString message;                 // 失败/状态说明(如"未收录"/"未启用")
    // 文件元数据
    QString typeDescription;         // 文件类型(如 "Win32 EXE")
    qint64 sizeBytes = 0;
    QDateTime firstSubmissionUtc;    // VT 首次收录时间
    QDateTime lastAnalysisUtc;       // VT 最近分析时间
    int timesSubmitted = 0;          // 被提交次数
    int reputation = 0;              // VT 社区信誉分(可负)
    int malicious = 0;
    int totalEngines = 0;
    QString threatLabel;             // 建议威胁名
    QStringList knownNames;          // 已知别名(其他文件名)
    QStringList tags;                // VT 标签
    // 每引擎检出(仅命中项):"引擎名: 检出名"
    QStringList maliciousDetections;
    QStringList suspiciousDetections;
    // 行为画像 IOC(behaviour_summary,聚合 VT+HA)
    QStringList droppedFiles;
    QStringList registryKeys;
    QStringList contactedIps;
    QStringList contactedDomains;
    QJsonObject toJson() const;
    static VtDetailResponsePayload fromJson(const QJsonObject& o);
};

// ===== 隔离区 =====
// 隔离区条目传输对象。
struct QuarantineItemPayload {
    QUuid id;
    QString originalPath;
    QString fileName;
    QDateTime quarantinedUtc;
    qint64 size = 0;
    QString sha256;
    QString reason;
    int actorPid = 0;
    QJsonObject toJson() const;
    static QuarantineItemPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:隔离区列表。
struct QuarantineListResponsePayload {
    QList<QuarantineItemPayload> items;
    QJsonObject toJson() const;
    static QuarantineListResponsePayload fromJson(const QJsonObject& o);
};

// UI -> 服务:隔离条目操作(还原/删除)。
struct QuarantineActionPayload {
    QUuid id;
    QJsonObject toJson() const;
    static QuarantineActionPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:隔离操作结果回执。
struct QuarantineActionResultPayload {
    QUuid id;
    bool success = false;
    QString message;
    QJsonObject toJson() const;
    static QuarantineActionResultPayload fromJson(const QJsonObject& o);
};

// UI -> 服务:手动强制隔离某文件(清理报告「重试隔离」)。
struct ManualQuarantinePayload {
    QUuid requestId = QUuid::createUuid();
    QString path;
    QJsonObject toJson() const;
    static ManualQuarantinePayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:手动隔离结果。
struct ManualQuarantineResultPayload {
    QUuid requestId;
    bool success = false;
    QString message;
    QJsonObject toJson() const;
    static ManualQuarantineResultPayload fromJson(const QJsonObject& o);
};

// ===== 持久化审计 =====
// 服务 -> UI:自启动持久化项清单(含风险分与 ATT&CK 标注)。
struct PersistenceListResponsePayload {
    QDateTime scannedUtc = QDateTime::currentDateTimeUtc();
    QList<bulwark::PersistenceEntry> entries;
    QString message;
    QJsonObject toJson() const;
    static PersistenceListResponsePayload fromJson(const QJsonObject& o);
};

// UI -> 服务:清理某条自启动持久化项(高危,由用户在自启动项页显式点击触发)。
//
// 这条链路此前是断的:IpcMessageType 里早就留了 PersistenceCleanupRequest/Response 两个消息号,
// ThreatRemediator 也把 8 类持久化点的清理动作全实现了(removeRunValue / removeIfeoDebugger /
// resetWinlogonValue / clearAppInitDlls / quarantineStartupFile / deleteScheduledTask /
// disableService / tryQuarantinePayload),但【服务端没有 handler、UI 端没有发送方、页面上
// 连按钮都没有】—— 那 200 行成品代码一行都到不了,用户在自启动项页只能看不能清。
//
// 整条 PersistenceEntry 回传(而不是只传 id):清理动作要按 category 分派、要拿 location /
// name / imagePath 定位目标,而服务端不保存上一次扫描的结果(扫描是无状态的按需枚举)。
struct PersistenceCleanupRequestPayload {
    QUuid requestId = QUuid::createUuid();
    bulwark::PersistenceEntry entry;
    QJsonObject toJson() const;
    static PersistenceCleanupRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:自启动项清理结果。复用足迹清理的三段式(已隔离 / 已移除 / 未能处理),
// UI 可据 skipped 里的 isFile 提供「重试隔离」。
struct PersistenceCleanupResultPayload {
    QUuid requestId;
    bool success = false;              // 是否产生了至少一个实际动作
    QString entryId;                   // 对应请求里的 PersistenceEntry::id,供 UI 定位行
    QString message;                   // 可直接展示的结论
    QStringList quarantinedFiles;
    QStringList removedRegistryValues;
    QList<RemediationSkippedItem> skipped;
    QJsonObject toJson() const;
    static PersistenceCleanupResultPayload fromJson(const QJsonObject& o);
};

// ===== 在线更新 =====
// 服务 -> UI:清单结论。
//
// 刻意【不带】端点真实地址和令牌:UI 只需要知道「有没有新版本、是什么、说明写了什么」。
// endpointMasked 是掩码形式(如 https://***:8787),给用户看「在跟谁通信」而不泄露地址。
struct UpdateFileBrief {
    QString name;
    qint64  size = 0;
};
struct UpdateCheckResponsePayload {
    bool ok = false;              // 清单取到并解析成功(false => error 可直接展示)
    bool available = false;       // 服务器上有比本机更新的版本
    QString error;
    QString currentVersion;       // 本机构建版本,便于弹窗写「1.1.0 -> 1.2.0」
    QString version;              // 远端版本
    QString label;                // 展示标题
    QString notes;                // 更新说明(markdown 风格文本)
    QString publishedUtc;
    QString endpointMasked;       // 掩码端点,绝不含真实主机名
    qint64  totalBytes = 0;
    QList<UpdateFileBrief> files;
    QJsonObject toJson() const;
    static UpdateCheckResponsePayload fromJson(const QJsonObject& o);
};
// 服务 -> UI:下载/校验进度。stage 是可直接显示的中文短语(下载中/校验中/已校验)。
struct UpdateProgressPayload {
    int done = 0;
    int total = 0;
    QString fileName;
    QString stage;
    QJsonObject toJson() const;
    static UpdateProgressPayload fromJson(const QJsonObject& o);
};
// 服务 -> UI:下载结果。stagingDir 是【已通过全部校验】的载荷目录。
// 早期版本把它交给一个提权脚本去替换文件;现在替换由服务自己做(见 UpdateApplyRequest 处
// 的说明),这个字段保留下来只为在界面上如实告诉用户「东西下到哪了」,以及手动安装时能找到。
struct UpdateDownloadResponsePayload {
    bool ok = false;
    QString error;
    QString version;
    QString stagingDir;
    int verified = 0;
    QJsonObject toJson() const;
    static UpdateDownloadResponsePayload fromJson(const QJsonObject& o);
};
// 服务 -> UI:就地应用的结果。
//
// needsRestart 恒为真且【不代表失败】:替换用的是「旧映像改名让位、新文件放到原名」,
// 正在跑的进程仍从改名后的文件执行,所以新版本要下次启动才生效。界面必须如实说明这一点,
// 否则用户会以为点完就已经在跑新版了。
// rolledBack 为真时安装目录已还原,当前版本一个字节都没变。
struct UpdateApplyResponsePayload {
    bool ok = false;
    QString error;
    QString version;          // 本次应用的目标版本
    int replaced = 0;         // 已就位的新文件数
    bool rolledBack = false;
    bool needsRestart = true;
    QJsonObject toJson() const;
    static UpdateApplyResponsePayload fromJson(const QJsonObject& o);
};

// ===== AI 病毒扫描 =====
// UI -> 服务:AI 病毒扫描结果(以事件 Id 关联请求)。
struct AiScanResponsePayload {
    QUuid eventId;
    bool available = false;
    bulwark::VerdictAction recommendation = bulwark::VerdictAction::Allow;
    QString summary;
    QString confidence;
    QJsonObject toJson() const;
    static AiScanResponsePayload fromJson(const QJsonObject& o);
};

// ===== 足迹清理报告 =====
// 服务 -> UI:确认恶意后的足迹清理报告。
struct RemediationReportPayload {
    QDateTime timestampUtc = QDateTime::currentDateTimeUtc();
    QString actorPath;
    int actorPid = 0;
    QString reason;
    bool actorQuarantined = false;
    QStringList quarantinedFiles;
    QStringList removedRegistryValues;
    QList<RemediationSkippedItem> skipped;
    // 情报补充(VT 等沙箱行为画像):该样本已知会释放什么 / 外联何处 + 据此新注入的主动拦截规则数。
    QString intelSource;               // 提供画像的情报源名(可空)
    QStringList intelDroppedFiles;     // 已知释放文件名
    QStringList intelDroppedFilePaths; // 已知释放文件完整沙箱路径(供 AI 翻译到本机)
    QStringList intelDroppedFileHashes;// 已知释放文件 SHA256
    QStringList intelRegistryKeys;     // 已知写入的注册表键
    QStringList intelContactedIps;     // 已知 C2 外联 IP
    QStringList intelContactedDomains; // 已知 C2 外联域名
    QStringList intelServices;         // 已知创建/启动的服务名
    QStringList intelProcessNames;     // 已知创建的可执行名
    QStringList intelMutexes;          // 已知互斥体
    int intelRulesInjected = 0;        // 据画像新注入的主动拦截规则数
    QJsonObject toJson() const;
    static RemediationReportPayload fromJson(const QJsonObject& o);
};

// ===== 威胁情报订阅(ThreatFox) =====
// UI -> 服务:立即刷新情报规则(预览模式仅生成不落地)。
struct IntelRefreshRequestPayload {
    QUuid requestId = QUuid::createUuid();
    bool previewOnly = false;
    QJsonObject toJson() const;
    static IntelRefreshRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:情报刷新/采纳结果。
struct IntelRefreshResultPayload {
    QUuid requestId;
    bool success = false;
    int iocCount = 0;
    int rulesApplied = 0;
    QList<bulwark::DefenseRule> generatedRules;
    QStringList threatContext;
    QString message;
    QJsonObject toJson() const;
    static IntelRefreshResultPayload fromJson(const QJsonObject& o);
};

// UI -> 服务:采纳(经复核确认的)一批情报规则。
struct IntelApplyRequestPayload {
    QUuid requestId = QUuid::createUuid();
    QList<bulwark::DefenseRule> rules;
    QJsonObject toJson() const;
    static IntelApplyRequestPayload fromJson(const QJsonObject& o);
};

// ===== 事件时间线 =====
// UI -> 服务:时间线查询。空/零值一律表示「不限」,便于 UI 只填自己关心的条件。
// 查询走服务端落盘的 events.jsonl(比内存环形缓冲更深),故能回看比实时列表更久的历史。
struct TimelineRequestPayload {
    QUuid requestId = QUuid::createUuid();
    QDateTime fromUtc;                        // 无效 = 不限下界
    QDateTime toUtc;                          // 无效 = 不限上界
    QList<int> types;                         // EventType 序号;空 = 全部
    QList<int> actions;                       // VerdictAction 序号;空 = 全部
    int minRiskScore = 0;                     // 最低风险分
    int pid = 0;                              // 只看某进程(含其在时间窗内的进程树)
    bool includeProcessTree = false;          // pid 是否连带其子孙进程
    QString text;                             // 关键字(匹配 路径/目标/命令行/发布者)
    int limit = 500;                          // 返回上限(服务端硬上限 5000)
    QJsonObject toJson() const;
    static TimelineRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:时间线查询结果。events 按时间【升序】(与实时推送一致,UI 自行决定倒序展示)。
struct TimelineResponsePayload {
    QUuid requestId;
    QList<EventLogPayload> events;
    int scanned = 0;                          // 实际扫描过的历史条数
    int matched = 0;                          // 命中条数(可能大于 events.size(),被 limit 截断)
    bool truncated = false;
    QDateTime earliestUtc;                    // 历史里最早一条的时间(供 UI 显示可回溯范围)
    QString message;
    QJsonObject toJson() const;
    static TimelineResponsePayload fromJson(const QJsonObject& o);
};

// ===== 攻击图 =====
// UI -> 服务:以某条事件(优先)或某 PID 为种子构建攻击图。
struct AttackGraphRequestPayload {
    QUuid requestId = QUuid::createUuid();
    QUuid seedEventId;
    int rootPid = 0;
    int windowSeconds = 3600;                 // 取种子时间前后多久的事件参与关联(默认 1 小时)
    QJsonObject toJson() const;
    static AttackGraphRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:攻击图。
struct AttackGraphResponsePayload {
    QUuid requestId;
    bool success = false;
    QString message;
    bulwark::AttackGraph graph;
    QJsonObject toJson() const;
    static AttackGraphResponsePayload fromJson(const QJsonObject& o);
};

// ===== 进程管理 =====
// UI -> 服务:请求在跑进程快照。
struct ProcessListRequestPayload {
    QUuid requestId = QUuid::createUuid();
    bool includeCommandLine = true;           // 读命令行(需要权限,略慢)
    bool resolveOrigin = true;                // 解析启动来源(具体服务名 / 计划任务名)
    QJsonObject toJson() const;
    static ProcessListRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:进程快照。
struct ProcessListResponsePayload {
    QUuid requestId;
    QDateTime snapshotUtc = QDateTime::currentDateTimeUtc();
    QList<bulwark::ProcessEntry> processes;
    QString message;
    QJsonObject toJson() const;
    static ProcessListResponsePayload fromJson(const QJsonObject& o);
};

// 进程处置动作。全部由用户在 UI 显式点击触发 —— 这里没有任何「自动」路径。
enum class ProcessActionKind {
    Terminate = 0,     // 结束单个进程
    TerminateTree,     // 结束进程及其全部后代
    Suspend,           // 挂起(冻结全部线程)
    Resume,            // 恢复
    QuarantineImage,   // 结束进程并隔离其映像文件(高危,需 UI 二次确认)
    TrustImage,        // 把映像加入信任名单
    ComputeHash,       // 计算映像 SHA-256(详情页按需)
};

// UI -> 服务:对某进程执行处置。
struct ProcessActionRequestPayload {
    QUuid requestId = QUuid::createUuid();
    ProcessActionKind kind = ProcessActionKind::Terminate;
    int pid = 0;
    QString imagePath;                        // TrustImage / QuarantineImage / ComputeHash 用
    QJsonObject toJson() const;
    static ProcessActionRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:进程处置结果。failed 时 message 必须说明【为什么没做成】——
// 关键系统进程、自我保护、权限不足、进程已退出,都要如实回话,不允许静默成功。
struct ProcessActionResultPayload {
    QUuid requestId;
    ProcessActionKind kind = ProcessActionKind::Terminate;
    int pid = 0;
    bool success = false;
    QString message;
    QString sha256;                           // ComputeHash 的结果
    QJsonObject toJson() const;
    static ProcessActionResultPayload fromJson(const QJsonObject& o);
};

// ---- 攻击链组合引擎 --------------------------------------------------------- #
// 服务器从每日采集的真实样本沙箱记录里数出「哪几个动作凑在一起就足以定性」,客户端
// 下载该组合表并给每个进程记账。这里把「表的状态」与「命中记录」一起回给 UI。

// 一条命中记录(与服务端 ChainHitRecord 一一对应;此处独立定义以免 shared 依赖 service)。
struct AttackChainHitPayload {
    QDateTime whenUtc;
    QString actorPath;
    int actorPid = 0;
    QStringList titles;      // 凑齐的那几个动作(可读)
    QString grade;           // hard / strong / ask
    QString maxLevel;        // medium / high / critical
    int support = 0;         // 有多少真实样本作证
    QString families;        // 常见家族
    bool dryRun = true;      // 命中当时是否处于「只记录不拦截」
    QString action;          // 最终裁决 Allow / Block / Ask
    QString eventType;       // 触发补齐的那条事件类型
    QJsonObject toJson() const;
    static AttackChainHitPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:组合表状态 + 命中记录。
struct AttackChainResponsePayload {
    bool enabled = false;        // 引擎是否启用
    bool dryRun = true;          // 当前是否「只记录不拦截」
    int version = 0;             // 组合表【内部】版本号(0 = 尚未装载)。整数、单调递增,
                                 // 是客户端判断「要不要重新拉表」的唯一依据,不作展示。
    QString versionLabel;        // 给人看的版本号,如 "0.3"(服务器侧 0.1 起、每次内容变化 +0.1)。
                                 // 老服务器不下发时为空,界面回退显示 "v<内部版本号>"。
    int patterns = 0;            // 组合条数
    int markers = 0;             // 可观测标记数
    int trackedProcesses = 0;    // 当前正在记账的进程数
    QString endpoint;            // 掩码后的端点(绝不回明文地址)
    QString updateSchedule;      // 可读的更新计划(如「每天 06:00」)
    QList<AttackChainHitPayload> hits;   // 最新在前
    QJsonObject toJson() const;
    static AttackChainResponsePayload fromJson(const QJsonObject& o);
};

// ---- 磁盘垃圾清理 ----------------------------------------------------------- #
//
// 【请求里绝不出现路径】每个类别在服务端对应一组编译期固定的根目录,UI 能表达的只有
// 「清理哪几类」。理由见 bulwark/models/JunkEntry.h 顶部:接受调用方给的路径就等于把
// 一个任意文件删除原语暴露在管道上。
//
// 扫描与清理都是异步的(要遍历数万文件),响应经 JunkScanResponse / JunkCleanResponse 回推,
// 中途用 JunkProgressNotification 报进度 —— 没有进度的话,一次十几秒的扫描在界面上和卡死
// 没有区别。

// UI -> 服务:扫描。categories 为空 = 扫描全部已知类别(首次进入页面的默认动作)。
struct JunkScanRequestPayload {
    QUuid requestId = QUuid::createUuid();
    QList<int> categories;                 // junk::Category 序号;空 = 全部
    // 只统计「最后修改时间早于 N 小时」的文件。正在被安装程序使用的临时文件通常刚写下,
    // 这个阈值就是为了不把它们算进来(更不会去删)。<=0 表示用服务端配置的默认值。
    int minAgeHours = 0;
    QJsonObject toJson() const;
    static JunkScanRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:扫描结果。
struct JunkScanResponsePayload {
    QUuid requestId;
    QDateTime scannedUtc = QDateTime::currentDateTimeUtc();
    bool enabled = true;                   // 服务端是否启用了垃圾清理
    QList<bulwark::JunkCategoryResult> categories;
    qint64 totalBytes = 0;
    int totalFiles = 0;
    int minAgeHours = 0;                   // 本次实际生效的保留时长(UI 如实展示)
    bool truncated = false;                // 命中扫描上限,结果为下限估计
    int unreadable = 0;                    // 全程读不进去的子目录总数(权限不足)
    qint64 elapsedMs = 0;                  // 扫描总耗时。界面把它显示出来,「怎么这么快」
                                           // 就变成一个可核对的数字,而不是一个可疑现象
    QString message;
    QJsonObject toJson() const;
    static JunkScanResponsePayload fromJson(const QJsonObject& o);
};

// UI -> 服务:清理。categories 【必须】非空 —— 不提供「清理全部」的隐式语义:
// 删除动作只能来自用户对具体类别的显式勾选,空列表一律按「什么都不做」处理。
struct JunkCleanRequestPayload {
    QUuid requestId = QUuid::createUuid();
    QList<int> categories;                 // junk::Category 序号;空 = 不做任何事
    int minAgeHours = 0;                   // <=0 用服务端默认值
    QJsonObject toJson() const;
    static JunkCleanRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:清理结果(逐类别)。
struct JunkCleanResponsePayload {
    QUuid requestId;
    QDateTime finishedUtc = QDateTime::currentDateTimeUtc();
    bool success = false;                  // 是否至少有一个类别清理成功
    QList<bulwark::JunkCleanOutcome> outcomes;
    qint64 freedBytes = 0;
    int deletedFiles = 0;
    int skipped = 0;
    QString message;
    QJsonObject toJson() const;
    static JunkCleanResponsePayload fromJson(const QJsonObject& o);
};

// UI -> 服务:大文件查找。
//
// 与垃圾清理一致,请求里【没有路径】—— 扫描范围固定为本机的固定磁盘(排除网络盘与可移动
// 介质)。这里不接受路径不是为了防删除(本功能压根不删),而是为了不让一个管道消息能驱使
// 服务去遍历任意位置(比如一个巨大的网络共享)。
struct LargeFileScanRequestPayload {
    QUuid requestId = QUuid::createUuid();
    qint64 minBytes = 0;                   // 体积下限;<=0 用服务端默认(100 MB)
    int limit = 0;                         // 返回条数上限;<=0 用服务端默认(200)
    QJsonObject toJson() const;
    static LargeFileScanRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:大文件清单(按体积降序)。
struct LargeFileScanResponsePayload {
    QUuid requestId;
    QDateTime scannedUtc = QDateTime::currentDateTimeUtc();
    bool enabled = true;
    QList<bulwark::LargeFileEntry> files;
    qint64 minBytes = 0;                   // 本次实际生效的阈值
    qint64 totalBytes = 0;                 // 列出的这些文件合计占用
    int scannedFiles = 0;                  // 实际检视过多少个文件(让耗时可解释)
    int unreadable = 0;                    // 读不进去的目录数
    bool truncated = false;                // 命中时间 / 条数上限
    qint64 elapsedMs = 0;
    QString message;
    QJsonObject toJson() const;
    static LargeFileScanResponsePayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:扫描 / 清理进度。
struct JunkProgressPayload {
    QUuid requestId;
    bool cleaning = false;                 // false=扫描阶段,true=清理阶段
    int categoryIndex = 0;                 // 第几个类别(1 起)
    int categoryTotal = 0;                 // 共几个类别
    QString categoryTitle;
    QString currentPath;                   // 当前正在处理的位置(展示用)
    qint64 bytesSoFar = 0;
    int filesSoFar = 0;
    QJsonObject toJson() const;
    static JunkProgressPayload fromJson(const QJsonObject& o);
};

} // namespace bulwark::ipc
