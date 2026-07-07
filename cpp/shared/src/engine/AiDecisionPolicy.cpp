#include "bulwark/engine/AiDecisionPolicy.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

using bulwark::VerdictAction;

bool AiDecisionPolicy::shouldConsultGrayZone(VerdictAction currentAction) {
    return currentAction == VerdictAction::Ask;
}

AiDecisionPolicy::Outcome AiDecisionPolicy::apply(const bulwark::SecurityEvent& e,
                                                  VerdictAction currentAction, bool aiAvailable,
                                                  VerdictAction aiRecommendation,
                                                  const QString& aiSummary) {
    // 1) AI 不可用:fail-open,维持原裁决(退回正常弹窗)。
    if (!aiAvailable)
        return { currentAction, false, QString::fromUtf8("AI 研判不可用,维持原裁决(fail-open)"), false };

    // 2) AI 判定恶意:灰区升格为 Block。
    if (aiRecommendation == VerdictAction::Block) {
        const QString note = aiSummary.trimmed().isEmpty()
            ? QString::fromUtf8("AI 研判:恶意(灰区升格为拦截)")
            : QString::fromUtf8("AI 研判:恶意(灰区升格为拦截)—— ") + aiSummary;
        return { VerdictAction::Block, currentAction != VerdictAction::Block, note, true };
    }

    // 3)/4) AI 判定干净。
    if (e.hasThreatIndicator) {
        // 存在硬指标:AI 单独不得压制,维持原裁决交用户裁决。
        return { currentAction, false,
                 QString::fromUtf8("AI 研判:未发现恶意,但存在硬恶意指标,仍交用户裁决"), false };
    }
    // 无硬指标的灰区软信号 + AI 干净:降级放行,减少打扰。
    return { VerdictAction::Allow, currentAction != VerdictAction::Allow,
             QString::fromUtf8("AI 研判:未发现恶意,灰区软信号降级放行(减少打扰)"), false };
}

} // namespace bulwark::engine
