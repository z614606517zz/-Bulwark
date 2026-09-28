#include "dialogs/AttackChainDetailDialog.h"
#include "dialogs/ChainViews.h"
#include "dialogs/EventFormat.h"
#include "design/Backdrop.h"
#include "design/Inspector.h"

#include <QVBoxLayout>

using evtfmt::u;

AttackChainDetailDialog::AttackChainDetailDialog(const bulwark::ipc::AttackChainHitPayload& hit, QWidget* parent,
                                                 IpcClient* ipc)
    : QDialog(parent)
{
    const QString name = evtfmt::actorName(hit.actorPath);
    setWindowTitle(u("攻击链命中 · %1").arg(name));
    setAccessibleName(windowTitle());
    Backdrop::install(this); // same work-area material as the main window
    resize(600, 760);
    setMinimumSize(440, 480);
    setSizeGripEnabled(true);

    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(14, 14, 14, 14);
    auto* in = new Inspector;
    chainview::fill(in, hit, ipc, /*withWindow*/ false);
    connect(in, &Inspector::closeRequested, this, &QDialog::accept);
    v->addWidget(in);
}
