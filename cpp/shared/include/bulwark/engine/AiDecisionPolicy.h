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
    //
    // blockOnFailure 对应 RuntimeSettings::aiScanBlockOnFailure(设置页「AI 不可用时按拦截处理」)。
    // 该开关此前在服务端【从未被读取】—— 设置页有开关但没有任何消费点,规则 1 恒为 fail-open。
    // 现在:开启时,AI 不可用 / 超时 / 无结论会把灰区事件升格为 Block(fail-closed),
    // 适合"宁可多拦"的高安全场景;默认关闭,保持原有的 fail-open 语义。
    // 注意它【只影响灰区(Ask)】:确定性 Block 与强可信 Allow 都不经过本策略,不受影响。
    static Outcome apply(const bulwark::SecurityEvent& e, bulwark::VerdictAction currentAction,
                         bool aiAvailable, bulwark::VerdictAction aiRecommendation,
                         const QString& aiSummary = QString(),
                         bool blockOnFailure = false);
};

} // namespace bulwark::engine
