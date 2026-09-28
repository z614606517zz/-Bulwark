#include "dialogs/ProcessDetailDialog.h"
#include "dialogs/EventFormat.h"
#include "dialogs/ProcessViews.h"
#include "design/Backdrop.h"
#include "design/Inspector.h"

#include <QVBoxLayout>

using evtfmt::u;

ProcessDetailDialog::ProcessDetailDialog(const bulwark::ProcessEntry& e, IpcClient* ipc, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(u("进程详情 · %1").arg(e.name));
    setAccessibleName(windowTitle());
    Backdrop::install(this); // same work-area material as the main window
    resize(600, 760);
    setMinimumSize(440, 480);
    setSizeGripEnabled(true);

    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(14, 14, 14, 14);
    auto* in = new Inspector;
    procview::fill(in, e, ipc, /*actions*/ false);
    connect(in, &Inspector::closeRequested, this, &QDialog::accept);
    v->addWidget(in);
}
