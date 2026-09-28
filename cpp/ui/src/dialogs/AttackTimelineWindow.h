#pragma once
#include <QDialog>

#include <optional>

#include "bulwark/models/SecurityEvent.h"
#include "dialogs/EventViews.h"

class IpcClient;
class QBoxLayout;

// The full view of one event — the same content as the event inspector, laid
// out in two columns for reading: the story on the left (why it was judged so,
// where it came from), the facts on the right (what was done, forensic fields).
//
// Opened from any event row (Enter / double-click / 「攻击时间线」) and from the
// behavior prompt. With `ipc` it also offers the attack graph: the timeline is
// this event's own evidence, the graph is its place in the process tree.
// `outcome` is what was decided and done about a recorded event; a live prompt
// has none yet.
class AttackTimelineWindow : public QDialog
{
    Q_OBJECT
public:
    explicit AttackTimelineWindow(const bulwark::SecurityEvent& event, QWidget* parent = nullptr,
                                  IpcClient* ipc = nullptr,
                                  std::optional<evtview::Outcome> outcome = std::nullopt);

protected:
    void resizeEvent(QResizeEvent* e) override;

private:
    QBoxLayout* m_columns = nullptr;
};
