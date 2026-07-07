#pragma once
#include <QString>
#include "bulwark/models/Enums.h"

namespace bulwark { struct SecurityEvent; }

namespace bulwark::engine {

// AI 灰区研判决策策略(纯函数·可单测)。把「大模型研判结果」如何折回最终裁决的规则集中
// 于此,使 Worker 热路径只负责编排(缓存 / IPC / 超时),决策本身一致且可解释。
//
// 折叠规则(严守低误报 + 不打扰 + AI 不可用绝不影响实时防护):
//   1) AI 不可用 / 超时 / 无明确结论          -> 维持原裁决(fail-open,退回正常弹窗);
//   2) AI 判定恶意                            -> 升格为 Block(灰区已隐含可疑,AI 与之互证);
//   3) AI 判定干净 且 本事件【无硬恶意指标】   -> 降级为 Allow(减少打扰);
//   4) AI 判定干净 但 本事件【存在硬恶意指标】 -> 维持原裁决(AI 单独不得压制硬指标)。
// 只在灰区生效,绝不把确定性 Block 改判、也不把强可信 Allow 改判。
// 对应 .NET Engine/AiDecisionPolicy.cs。
struct AiDecisionPolicy {
    struct Outcome {
        bulwark::VerdictAction action = bulwark::VerdictAction::Ask; // 折叠后的最终动作
        bool changed = false;                                        // 相对原裁决是否改变
        QString note;                                                // 可读说明(写证据链/审计)
        bool rememberMalicious = false;                              // 仅 AI 确定恶意时为 true
    };

    // 是否应对该事件发起灰区 AI 研判(仅裁决为 Ask 才咨询)。
    static bool shouldConsultGrayZone(bulwark::VerdictAction currentAction);

    // 把一次 AI 研判结果折回灰区裁决(currentAction 通常为 Ask)。
    static Outcome apply(const bulwark::SecurityEvent& e, bulwark::VerdictAction currentAction,
                         bool aiAvailable, bulwark::VerdictAction aiRecommendation,
                         const QString& aiSummary = QString());
};

} // namespace bulwark::engine
