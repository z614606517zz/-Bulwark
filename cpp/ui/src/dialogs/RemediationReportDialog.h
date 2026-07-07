#pragma once
#include <QDialog>
#include <QPoint>

#include "bulwark/ipc/Payloads.h"

class IpcClient;
class QShowEvent;

// "恶意足迹清理报告" — surfaced after the service confirms an actor malicious,
// quarantines its payload and cleans its persistence footprint. A light-theme
// card mirroring the behavior prompt's look: subject + verdict, a cleaned /
// un-cleaned tally, the quarantined payload / files / registry entries, and any
// items that couldn't be cleaned (with a one-click retry-quarantine for leftover
// files). Frameless, draggable, non-modal — it reports, it never blocks the user.
class RemediationReportDialog : public QDialog
{
    Q_OBJECT
public:
    RemediationReportDialog(const bulwark::ipc::RemediationReportPayload& report,
                            IpcClient* ipc, QWidget* parent = nullptr);

protected:
    void mousePressEvent(QMouseEvent*) override;
    void mouseMoveEvent(QMouseEvent*) override;
    void showEvent(QShowEvent*) override;

private:
    IpcClient* m_ipc = nullptr;
    QPoint m_dragOffset;
    bool m_centered = false;
};
