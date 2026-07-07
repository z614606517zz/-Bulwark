#pragma once
#include <QColor>
#include <QDialog>
#include <QPoint>

#include "bulwark/models/SecurityEvent.h"

class QComboBox;
class QCheckBox;
class QPushButton;
class QTimer;

// The behavior-prompt window — the core HIPS interaction. Shows a gray-zone
// SecurityEvent with the full evidence set (actor + signature/publisher, command
// line, target, SHA-256, risk factors, evidence-chain highlights, ATT&CK) and
// lets the user Allow/Block and optionally remember the choice (scope). A "查看
// 攻击时间线" link opens the full AttackTimelineWindow. Frameless, draggable.
class PromptDialog : public QDialog
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
    int scopeIndex() const; // 0 永久 / 1 会话 / 2 一小时 / 3 一天

protected:
    void mousePressEvent(QMouseEvent*) override;
    void mouseMoveEvent(QMouseEvent*) override;

private:
    void updateCountdown(); // refresh the default-action button's "(Ns)" suffix

    bulwark::SecurityEvent m_event;
    bool m_allowed = false;
    QCheckBox* m_remember = nullptr;
    QComboBox* m_scope = nullptr;
    QPoint m_dragOffset;

    // Auto-decision countdown (see ctor doc). m_timeoutSeconds <= 0 => disabled.
    int m_timeoutSeconds = 0;
    int m_remaining = 0;
    bool m_defaultAllow = true;
    QTimer* m_countdown = nullptr;
    QPushButton* m_allowBtn = nullptr;
    QPushButton* m_blockBtn = nullptr;
};
