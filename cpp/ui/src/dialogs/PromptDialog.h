#pragma once
#include "design/Sheet.h"

#include "bulwark/models/SecurityEvent.h"

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
//   记住选择  [仅本次 | 本次会话 | 1 小时 | 1 天 | 永久]              ← the decision
//   ━━━━━━━━━━━━━━░░░░  18 秒后自动放行
//   查看攻击时间线                                   [拦截]  [放行]
//
// The evidence scrolls inside a height-limited area; the decision row and the
// verdict buttons are always on screen. The countdown shows the real default
// (the emphasised button, the bar's caption and Enter all agree) and never
// pauses — the service keeps its own timeout. Esc / closing = 拦截 (the
// conservative path).
class PromptDialog : public Sheet
{
    Q_OBJECT
public:
    // timeoutSeconds > 0 arms an auto-decision countdown: when it elapses the
    // dialog closes itself with the default verdict (defaultAllow ? Allow :
    // Block), mirroring the service's PromptTimeoutSeconds policy. 0 disables
    // the countdown (the dialog waits indefinitely for a click).
    explicit PromptDialog(const bulwark::SecurityEvent& event, QWidget* parent = nullptr,
                          int timeoutSeconds = 0, bool defaultAllow = true);

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
