#pragma once
#include <QString>
#include <QStringList>
#include <QVector>
#include <QtGlobal>
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/models/ChainEventInfo.h"

namespace bulwark::engine {

// ATT&CK 风格战术阶段(位标志,精简版,聚焦终端可观测维度)。
enum class KillChainStage : quint32 {
    None             = 0,
    Execution        = 1u << 0,
    DefenseEvasion   = 1u << 1,
    Persistence      = 1u << 2,
    CredentialAccess = 1u << 3,
    LateralMovement  = 1u << 4,
    Impact           = 1u << 5,
    CommandControl   = 1u << 6,
    Discovery        = 1u << 7,
};
inline KillChainStage operator|(KillChainStage a, KillChainStage b) {
    return static_cast<KillChainStage>(quint32(a) | quint32(b));
}
inline KillChainStage operator&(KillChainStage a, KillChainStage b) {
    return static_cast<KillChainStage>(quint32(a) & quint32(b));
}
inline KillChainStage& operator|=(KillChainStage& a, KillChainStage b) { a = a | b; return a; }

// 杀伤链阶段分析器:把进程链上下文中的事件归类到战术阶段,按「同一进程树覆盖了多少
// 不同阶段」研判多阶段攻击(>=3 阶段才计分)。对应 .NET Engine/KillChainAnalyzer.cs
//(hasMaliciousStage 为 C++ 端 ThreatDetector 复用而补充的判定)。
struct KillChainAnalyzer {
    struct Result {
        int score = 0;
        QStringList reasons;
        KillChainStage stages = KillChainStage::None;
    };

    static Result analyze(const QVector<bulwark::ChainEventInfo>& context);
    // 是否命中「明确恶意」的后段战术(凭据访问/横向移动/破坏影响)——供升格为硬指标。
    static bool hasMaliciousStage(KillChainStage stages);
};

} // namespace bulwark::engine
