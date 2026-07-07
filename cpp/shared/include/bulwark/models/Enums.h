#pragma once
#include <QString>

// Domain enums shared across the whole product. Ordinals are wire-significant:
// the .NET side serializes most enums by NUMBER (System.Text.Json default), so
// these integer values must match Bulwark.Core exactly to stay interoperable
// during the strangler transition. EvidenceKind is the sole exception - the C#
// side tags it [JsonStringEnumConverter], so it travels as a STRING.
namespace bulwark {

enum class EventType {
    ProcessCreate = 0,   // 进程创建
    ProcessTerminate,    // 结束进程
    RemoteThread,        // 远程线程注入
    ImageLoad,           // 模块/驱动加载
    FileWrite,           // 文件写入/修改
    FileDelete,          // 文件删除
    RegistryWrite,       // 注册表写入
    NetworkConnect,      // 网络外联
    SelfProtect,         // 自我保护
    DnsQuery,            // DNS 解析(观测富化)
};

enum class VerdictAction {
    Allow = 0,   // 放行
    Block,       // 阻止
    Ask,         // 询问用户(引擎内部态,不回内核)
};

enum class VerdictSource {
    Rule = 0,        // 命中规则
    Heuristic,       // 启发式评分
    TrustedSigner,   // 受信签名放行
    UserPrompt,      // 用户弹窗
    Timeout,         // 超时兜底
    DefaultPolicy,   // 默认策略
};

// NOTE: string-serialized on the wire (matches C# JsonStringEnumConverter).
enum class EvidenceKind {
    Info = 0,        // 中性上下文
    SoftSignal,      // 软信号(需互证)
    HardIndicator,   // 硬恶意指标
    Corroboration,   // 互证升格
    Trust,           // 信任/放行依据
    Rule,            // 命中显式规则
    Decision,        // 最终裁决说明
};

enum class ReputationVerdict {
    Unknown = 0,   // 未查询/无结论
    Clean,         // 干净
    Suspicious,    // 可疑
    Malicious,     // 恶意
};

// "记住我的选择" 的作用范围。
enum class RememberScope {
    Permanent = 0,   // 永久落盘
    Session,         // 仅本次会话
    OneHour,         // 1 小时
    OneDay,          // 1 天
};

enum class VtRequestKind {
    TestConnection = 0,   // 测试连接/Key
    QueryFile,            // 查询文件哈希信誉
    UsageStats,           // 各源用量统计
};

// ---- EvidenceKind <-> string (wire form) ------------------------------------
inline QString evidenceKindToString(EvidenceKind k) {
    switch (k) {
        case EvidenceKind::Info:          return QStringLiteral("Info");
        case EvidenceKind::SoftSignal:    return QStringLiteral("SoftSignal");
        case EvidenceKind::HardIndicator: return QStringLiteral("HardIndicator");
        case EvidenceKind::Corroboration: return QStringLiteral("Corroboration");
        case EvidenceKind::Trust:         return QStringLiteral("Trust");
        case EvidenceKind::Rule:          return QStringLiteral("Rule");
        case EvidenceKind::Decision:      return QStringLiteral("Decision");
    }
    return QStringLiteral("Info");
}

inline EvidenceKind evidenceKindFromString(const QString& s) {
    if (s == QLatin1String("SoftSignal"))    return EvidenceKind::SoftSignal;
    if (s == QLatin1String("HardIndicator")) return EvidenceKind::HardIndicator;
    if (s == QLatin1String("Corroboration")) return EvidenceKind::Corroboration;
    if (s == QLatin1String("Trust"))         return EvidenceKind::Trust;
    if (s == QLatin1String("Rule"))          return EvidenceKind::Rule;
    if (s == QLatin1String("Decision"))      return EvidenceKind::Decision;
    return EvidenceKind::Info;
}

// ---- enum -> member-name string (matches C# Enum.ToString()) -----------------
// Used by ECS alert export, audit records and UI-facing serialization.
inline QString eventTypeToString(EventType t) {
    switch (t) {
        case EventType::ProcessCreate:    return QStringLiteral("ProcessCreate");
        case EventType::ProcessTerminate: return QStringLiteral("ProcessTerminate");
        case EventType::RemoteThread:     return QStringLiteral("RemoteThread");
        case EventType::ImageLoad:        return QStringLiteral("ImageLoad");
        case EventType::FileWrite:        return QStringLiteral("FileWrite");
        case EventType::FileDelete:       return QStringLiteral("FileDelete");
        case EventType::RegistryWrite:    return QStringLiteral("RegistryWrite");
        case EventType::NetworkConnect:   return QStringLiteral("NetworkConnect");
        case EventType::SelfProtect:      return QStringLiteral("SelfProtect");
        case EventType::DnsQuery:         return QStringLiteral("DnsQuery");
    }
    return QStringLiteral("ProcessCreate");
}

inline QString verdictActionToString(VerdictAction a) {
    switch (a) {
        case VerdictAction::Allow: return QStringLiteral("Allow");
        case VerdictAction::Block: return QStringLiteral("Block");
        case VerdictAction::Ask:   return QStringLiteral("Ask");
    }
    return QStringLiteral("Allow");
}

inline QString verdictSourceToString(VerdictSource s) {
    switch (s) {
        case VerdictSource::Rule:          return QStringLiteral("Rule");
        case VerdictSource::Heuristic:     return QStringLiteral("Heuristic");
        case VerdictSource::TrustedSigner: return QStringLiteral("TrustedSigner");
        case VerdictSource::UserPrompt:    return QStringLiteral("UserPrompt");
        case VerdictSource::Timeout:       return QStringLiteral("Timeout");
        case VerdictSource::DefaultPolicy: return QStringLiteral("DefaultPolicy");
    }
    return QStringLiteral("Rule");
}

} // namespace bulwark
