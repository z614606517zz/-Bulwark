using Bulwark.Core.Models;

namespace Bulwark.Core.Engine;

/// <summary>
/// AI 灰区研判决策策略(纯函数·可单测)。
///
/// 把「大模型研判结果」如何折回最终裁决的规则集中在此,使 Worker 的热路径只负责
/// 编排(缓存 / IPC / 超时),决策本身可被独立测试,也保证行为一致、可解释。
///
/// 适用场景:规则引擎对一个事件给出 <see cref="VerdictAction.Ask"/>(灰区 —— 既不够
/// 确定性恶意可直接拦,也非强可信可直接放行,本要弹窗交用户裁决)。此时可选地先咨询 AI:
///
/// 折叠规则(严守低误报 + 不打扰 + AI 不可用绝不影响实时防护):
///   1) AI 不可用 / 超时 / 无明确结论            -> 维持原 Ask(fail-open,退回正常弹窗,行为与未启用一致);
///   2) AI 判定恶意                              -> 升格为 Block(灰区已隐含可疑,AI 与之互证);
///   3) AI 判定干净 且 本事件【无硬恶意指标】     -> 降级为 Allow(减少打扰,典型灰区软信号);
///   4) AI 判定干净 但 本事件【存在硬恶意指标】   -> 维持 Ask(AI 单独不得压制硬指标,仍交用户裁决)。
///
/// 注意:本策略只在「灰区(Ask)」生效,绝不把确定性 Block 改判,也不把强可信 Allow 改判。
/// </summary>
public static class AiDecisionPolicy
{
    /// <summary>
    /// 是否应对该事件发起灰区 AI 研判。仅灰区(裁决为 Ask)才咨询。
    /// 主体的「强可信/系统组件」豁免由调用方(持有 TrustPolicy)在调用前判定。
    /// </summary>
    public static bool ShouldConsultGrayZone(VerdictAction currentAction)
        => currentAction == VerdictAction.Ask;

    /// <summary>AI 灰区研判的折叠结果。</summary>
    public readonly struct Outcome
    {
        /// <summary>折叠后的最终动作。</summary>
        public VerdictAction Action { get; init; }

        /// <summary>相对原裁决是否发生改变。</summary>
        public bool Changed { get; init; }

        /// <summary>可读说明(写入证据链/原因)。</summary>
        public string Note { get; init; }

        /// <summary>该结论是否应按哈希记忆(仅 AI 确定恶意时为 true)。</summary>
        public bool RememberMalicious { get; init; }
    }

    /// <summary>
    /// 把一次 AI 研判结果折回灰区裁决。<paramref name="currentAction"/> 应为 Ask。
    /// </summary>
    /// <param name="e">被研判事件(用于读取是否存在硬恶意指标)。</param>
    /// <param name="currentAction">当前(灰区)裁决动作,通常为 Ask。</param>
    /// <param name="aiAvailable">AI 是否给出了有效结论。</param>
    /// <param name="aiRecommendation">AI 建议(仅在 aiAvailable 时有意义)。</param>
    public static Outcome Apply(SecurityEvent e, VerdictAction currentAction,
        bool aiAvailable, VerdictAction aiRecommendation, string? aiSummary = null)
    {
        // 1) AI 不可用:fail-open,维持原裁决(退回正常弹窗)。
        if (!aiAvailable)
            return new Outcome { Action = currentAction, Changed = false, Note = "AI 研判不可用,维持原裁决(fail-open)" };

        // 2) AI 判定恶意:灰区升格为 Block(与灰区隐含的可疑互证)。
        if (aiRecommendation == VerdictAction.Block)
        {
            return new Outcome
            {
                Action = VerdictAction.Block,
                Changed = currentAction != VerdictAction.Block,
                Note = string.IsNullOrWhiteSpace(aiSummary)
                    ? "AI 研判:恶意(灰区升格为拦截)"
                    : "AI 研判:恶意(灰区升格为拦截)—— " + aiSummary,
                RememberMalicious = true
            };
        }

        // 3) / 4) AI 判定干净。
        if (e is { HasThreatIndicator: true })
        {
            // 存在硬指标:AI 单独不得压制,维持 Ask 交用户裁决。
            return new Outcome
            {
                Action = currentAction,
                Changed = false,
                Note = "AI 研判:未发现恶意,但存在硬恶意指标,仍交用户裁决"
            };
        }

        // 无硬指标的灰区软信号 + AI 干净:降级放行,减少打扰。
        return new Outcome
        {
            Action = VerdictAction.Allow,
            Changed = currentAction != VerdictAction.Allow,
            Note = "AI 研判:未发现恶意,灰区软信号降级放行(减少打扰)"
        };
    }
}
