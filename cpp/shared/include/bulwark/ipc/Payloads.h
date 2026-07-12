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
    QStringList intelRegistryKeys;     // 已知写入的注册表键
    QStringList intelContactedIps;     // 已知 C2 外联 IP
    QStringList intelContactedDomains; // 已知 C2 外联域名
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

} // namespace bulwark::ipc
