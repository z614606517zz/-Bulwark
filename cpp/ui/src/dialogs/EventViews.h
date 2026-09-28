#pragma once
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/SecurityEvent.h"
#include "design/RecordModel.h"

#include <QColor>
#include <QList>
#include <QPair>
#include <QString>
#include <QUuid>

#include <optional>

class Inspector;
class IpcClient;
class QMenu;
class QVBoxLayout;
class QWidget;

// Views of one security event, shared by every place an event shows up — the
// event record list, the timeline, the attack-timeline window and the prompt's
// "查看攻击时间线". The same event reads the same, and offers the same next
// steps, wherever the user meets it.
namespace evtview {

// What was decided and what was actually done (a record has both; a live prompt
// has neither yet).
struct Outcome {
    bulwark::VerdictAction action = bulwark::VerdictAction::Allow;
    bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;
};
inline Outcome outcomeOf(const bulwark::ipc::EventLogPayload& p) { return {p.action, p.enforcement}; }

// ---- list rows ------------------------------------------------------------------

// "powershell.exe · 注入远程线程" / target · risk · disposition · time.
RecordView recordView(const bulwark::ipc::EventLogPayload& p);
// Everything a search should find an event by (paths, target, command line…).
QString searchText(const bulwark::SecurityEvent& e);
// Stable identity of an event for re-selection and navigation.
inline QString keyOf(const bulwark::SecurityEvent& e) { return e.id.toString(QUuid::WithoutBraces); }

// ---- building blocks (inspector + full window) --------------------------------------

// Signature / first-seen / reputation facts as chips.
QList<QPair<QString, QColor>> factChips(const bulwark::SecurityEvent& e);
// Why it was judged so: the evidence chain (or plain risk reasons).
QWidget* evidenceList(const bulwark::SecurityEvent& e);
// Where it came from: launch origin (service / scheduled task) + process chain.
QWidget* processChain(const bulwark::SecurityEvent& e);
// Forensic fields (paths, command line, hash, originator…), copyable.
void addForensicFields(QVBoxLayout* section, const bulwark::SecurityEvent& e);

// ---- the inspector + actions ----------------------------------------------------------

void fillInspector(Inspector* in, const bulwark::ipc::EventLogPayload& p, IpcClient* ipc,
                   const QString& trustSource);
void fillContextMenu(QMenu* menu, QWidget* context, const bulwark::ipc::EventLogPayload& p,
                     IpcClient* ipc, const QString& trustSource);

// Full two-column view of one event (non-modal, deletes itself on close).
void openTimeline(QWidget* parent, const bulwark::SecurityEvent& e, IpcClient* ipc,
                  std::optional<Outcome> outcome = std::nullopt);
// The attack graph around an event (seed) or, without one, around a PID.
void openGraph(QWidget* context, IpcClient* ipc, const QUuid& seedEventId, int pid, const QString& title);

// Trust a program (or a folder) after an explicit confirmation that spells out
// the cost — trust is the pipeline's first, unconditional allow and also skips
// every background scan. The outcome is confirmed against the trust list the
// service echoes back and reported as a banner near `context`.
void trust(QWidget* context, IpcClient* ipc, const QString& path, bool isDirectory, const QString& source);

} // namespace evtview
