#pragma once
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/ProcessEntry.h"

#include <QColor>
#include <QString>

class Inspector;
class IpcClient;
class QMenu;
class QWidget;

// Views of one running process, shared by the processes page (list + inspector)
// and the process detail window.
//
// Three red lines, same as the page always had: every action is an explicit
// click that first says what will happen; critical system processes and this
// product's own components are refused by the service and disabled here (with
// the reason spelled out); the static hint score only colours and sorts — it is
// never presented as a verdict.
namespace procview {

// 「提示」: a summary of static features, deliberately not called 「风险」.
struct Hint {
    QString text;
    QColor color;
    int rank = 0; // sort key: suspicious first, own / trusted / critical last
};
Hint hint(const bulwark::ProcessEntry& e);
// The process's colour (list glyph, inspector header): its hint when there is
// one, trusted green, own / critical azurite — status first — and otherwise the
// hue of who launched it (evtfmt::originColor).
QColor tone(const bulwark::ProcessEntry& e);
QString signatureText(const bulwark::ProcessEntry& e);
QColor signatureColor(const bulwark::ProcessEntry& e);
// Why terminate / suspend / quarantine are unavailable (empty = available).
QString lockReason(const bulwark::ProcessEntry& e);
QString searchText(const bulwark::ProcessEntry& e);

// Inspector content. With `actions` the footer carries the process actions;
// without, the view is read-only (only the on-demand SHA-256).
void fill(Inspector* in, const bulwark::ProcessEntry& e, IpcClient* ipc, bool actions);
void fillMenu(QMenu* menu, QWidget* context, const bulwark::ProcessEntry& e, IpcClient* ipc,
              bool withDetailWindow);
// Confirm (what happens, whether it can be undone), then send. The result comes
// back as IpcClient::processActionResult; the page reports it.
void run(QWidget* context, IpcClient* ipc, const bulwark::ProcessEntry& e, bulwark::ipc::ProcessActionKind kind);
void openDetail(QWidget* parent, const bulwark::ProcessEntry& e, IpcClient* ipc);

} // namespace procview
