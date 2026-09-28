#pragma once
#include "bulwark/ipc/Payloads.h"
#include "design/RecordModel.h"
#include "dialogs/EventFormat.h"

#include <QColor>
#include <QString>

class Inspector;
class IpcClient;
class QMenu;
class QWidget;

// Views of one attack-chain hit: several actions seen on the SAME process that
// together match a combination mined from real malware samples. Shared by the
// attack-chain page and its detail window.
//
// Honesty rules carried over from the table this replaces: a hit recorded while
// the engine only recorded (dry-run) never took part in the verdict, and the
// verdict shown is the event's verdict string — not an enforcement result, so a
// Block reads 「判为拦截」, never 「已拦截」.
namespace chainview {

QColor gradeColor(const QString& grade);   // hard / strong / ask
QString gradeLabel(const QString& grade);  // 确定恶意 / 高度可疑 / 需询问
QColor levelColor(const QString& level);   // critical / high / medium
QString levelLabel(const QString& level);
evtfmt::Badge verdict(const QString& action);
QString eventLabel(const QString& rawType); // wire enum name -> evtfmt::typeLabel

QString keyOf(const bulwark::ipc::AttackChainHitPayload& h);
RecordView recordView(const bulwark::ipc::AttackChainHitPayload& h);

void fill(Inspector* in, const bulwark::ipc::AttackChainHitPayload& h, IpcClient* ipc, bool withWindow);
void fillMenu(QMenu* menu, QWidget* context, const bulwark::ipc::AttackChainHitPayload& h, IpcClient* ipc,
              bool withWindow);
void openDetail(QWidget* parent, const bulwark::ipc::AttackChainHitPayload& h, IpcClient* ipc);

} // namespace chainview
