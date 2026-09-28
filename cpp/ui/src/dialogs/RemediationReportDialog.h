#pragma once
#include "design/Sheet.h"

#include "bulwark/ipc/Payloads.h"

#include <QHash>
#include <QList>

class AiScanner;
class CountdownBar;
class FitScrollArea;
class IpcClient;
class QPushButton;
class QVBoxLayout;

// 「恶意足迹清理报告」 — surfaced after the service confirms an actor malicious,
// quarantines its payload and cleans its persistence footprint.
//
//   header   subject · PID · time
//   tiles    [已隔离 N] [已移除自启动 N] [未能清理 N] [新增拦截规则 N]  (click → group)
//   groups   quarantined files · removed autostarts · leftovers (retry) · intel
//   footer   auto-close (30 s, hover pauses, pin keeps it) · 复制报告 · 打开隔离区 ·
//            全部重试 · 关闭
//
// A report with leftovers never closes by itself — those need a decision. The
// AI cleanup script is not generated or run here any more: 「用 AI 生成清理方案」
// hands the profile to AiCleanupDialog, whose runner elevates (UAC) and writes
// the script with a UTF-8 BOM — one execution path, not two.
//
// Non-modal (it reports, it never blocks the user), frameless, draggable.
class RemediationReportDialog : public Sheet
{
    Q_OBJECT
public:
    RemediationReportDialog(const bulwark::ipc::RemediationReportPayload& report,
                            IpcClient* ipc, AiScanner* ai, QWidget* parent = nullptr);

protected:
    void enterEvent(QEnterEvent* e) override;
    void leaveEvent(QEvent* e) override;

private:
    QWidget* group(QVBoxLayout* into, const QString& key, const QString& title, const QColor& color, int count);
    void scrollToGroup(const QString& key);
    void retryAll();
    void openQuarantine();
    QString reportText() const;
    void setPinned(bool pinned);

    bulwark::ipc::RemediationReportPayload m_report;
    IpcClient* m_ipc = nullptr;
    AiScanner* m_ai = nullptr;
    FitScrollArea* m_scroll = nullptr;
    QHash<QString, QWidget*> m_groups;
    QList<QPair<QString, QPushButton*>> m_retry; // leftover file -> its retry button
    CountdownBar* m_autoClose = nullptr;
    QPushButton* m_pin = nullptr;
    bool m_pinned = false;
};
