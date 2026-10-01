#pragma once
#include "design/Sheet.h"

#include "bulwark/models/SecurityEvent.h"

class AiScanner;
class CountdownBar;
class QPushButton;
class Segmented;

// The behavior prompt — the core HIPS interaction, laid out in the order the
// user has to think in:
//
//   ▌高危 82 · 行为防护
//   powershell.exe 正试图向 explorer.exe (PID 2204) 注入远程线程   ← what is happening
//   C:\…\powershell.exe   [已签名 · Microsoft] [本机首见] [VT 3/70] ← who is doing it
//   为什么提示  ● reason  ● reason  [T1055] [T1059.001] …            ← the evidence
//   ▸ 展开详情:命令行 · 父进程 · 启动来源 · SHA-256
//   ▌✦ AI 解读 [建议拦截] [置信度 高]                 2.4s · 1186 tok ← a plain-language reading
//   │  一两句通俗解读……                                                (only with an LLM configured)
//   记住选择  [仅本次 | 本次会话 | 1 小时 | 1 天 | 永久]              ← the decision
//   ━━━━━━━━━━━━━━░░░░  18 秒后自动放行
//   查看攻击时间线                                   [拦截]  [放行]
//
// The evidence scrolls inside a height-limited area; the AI reading, the
// decision row and the verdict buttons are always on screen. The countdown
// shows the real default (the emphasised button, the bar's caption and Enter
// all agree) and never pauses — the service keeps its own timeout. Esc /
// closing = 拦截 (the conservative path).
//
// The AI reading (「AI 解读」) is one more piece of evidence, never the verdict:
// it arrives asynchronously, changes neither the countdown, the default nor the
// emphasised button, and nothing of it goes back to the service. Shown only
// when an LLM is configured and the user hasn't switched it off (AiScanner).
//
// It appears in the bottom-right corner of the primary screen (Sheet::Placement::
// BottomRight), the same corner as the toast stack, and expanding the details
// grows it upward.
class PromptDialog : public Sheet
{
    Q_OBJECT
public:
    // timeoutSeconds > 0 arms an auto-decision countdown: when it elapses the
    // dialog closes itself with the default verdict (defaultAllow ? Allow :
    // Block), mirroring the service's PromptTimeoutSeconds policy. 0 disables
    // the countdown (the dialog waits indefinitely for a click).
    // `ai` (optional) supplies the 「AI 解读」; nullptr / not configured / switched
    // off = the reading is simply absent.
    explicit PromptDialog(const bulwark::SecurityEvent& event, QWidget* parent = nullptr,
                          int timeoutSeconds = 0, bool defaultAllow = true, AiScanner* ai = nullptr);

    bool allowed() const { return m_allowed; }
    bool remember() const;
    int scopeIndex() const; // 0 永久 / 1 会话 / 2 一小时 / 3 一天 (RememberScope)

private:
    void decide(bool allow);

    bulwark::SecurityEvent m_event;
    bool m_allowed = false;
    Segmented* m_scope = nullptr;       // 0 仅本次 · 1 本次会话 · 2 1 小时 · 3 1 天 · 4 永久
    CountdownBar* m_countdown = nullptr;
    int m_timeoutSeconds = 0;
    bool m_defaultAllow = true;
    QPushButton* m_allowBtn = nullptr;
    QPushButton* m_blockBtn = nullptr;
};
