#include "design/Confirm.h"
#include "design/Components.h"
#include "design/Sheet.h"
#include "design/Theme.h"
#include "widgets/WrapLabel.h"

#include <QCheckBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

namespace {
QString u(const char* s) { return QString::fromUtf8(s); }
} // namespace

bool ui::confirm(QWidget* parent, const ConfirmSpec& spec)
{
    QColor tone;
    QString icon;
    switch (spec.risk) {
    case Risk::Info:    tone = theme::info();    icon = QStringLiteral("info");         break;
    case Risk::Caution: tone = theme::warning(); icon = QStringLiteral("shield-alert"); break;
    case Risk::Danger:  tone = theme::danger();  icon = QStringLiteral("alert");        break;
    }
    const bool needAck = spec.requireAck.value_or(spec.risk == Risk::Danger);

    Sheet sheet(parent);
    sheet.setSheetWidth(500);
    sheet.setHeader(icon, tone, spec.title);
    QVBoxLayout* body = sheet.body();

    if (!spec.summary.isEmpty()) {
        auto* s = ui::label(spec.summary, "secondary");
        s->setWordWrap(true);
        body->addWidget(s);
    }

    if (!spec.subject.isEmpty()) {
        auto* box = ui::cardAlt();
        auto* bv = new QVBoxLayout(box);
        bv->setContentsMargins(14, 10, 14, 12);
        bv->setSpacing(4);
        if (!spec.subjectLabel.isEmpty())
            bv->addWidget(ui::label(spec.subjectLabel, "caption"));
        auto* subj = new WrapLabel(spec.subject);
        subj->setProperty("role", "mono");
        subj->setAccessibleName(spec.subjectLabel.isEmpty() ? u("操作对象") : spec.subjectLabel);
        bv->addWidget(subj);
        body->addWidget(box);
    }

    if (!spec.consequences.isEmpty()) {
        auto* list = new QVBoxLayout;
        list->setSpacing(6);
        for (const QString& c : spec.consequences) {
            auto* row = new QHBoxLayout;
            row->setSpacing(10);
            // The dot sits on the first text line's centre, not the box top.
            auto* dotBox = new QWidget;
            auto* db = new QVBoxLayout(dotBox);
            db->setContentsMargins(0, 7, 0, 0);
            db->addWidget(ui::statusDot(tone));
            row->addWidget(dotBox, 0, Qt::AlignTop);
            auto* t = ui::label(c);
            t->setWordWrap(true);
            row->addWidget(t, 1);
            list->addLayout(row);
        }
        body->addLayout(list);
    }

    QCheckBox* ack = nullptr;
    if (needAck) {
        ack = new QCheckBox(spec.ackText.isEmpty() ? u("我已了解上述后果") : spec.ackText);
        ack->setCursor(Qt::PointingHandCursor);
        body->addSpacing(2);
        body->addWidget(ack);
    }

    QPushButton* cancel = sheet.addButton(spec.cancelText.isEmpty() ? u("取消") : spec.cancelText,
                                          "ghost", [&sheet] { sheet.reject(); });
    QPushButton* ok = sheet.addButton(spec.confirmText.isEmpty() ? u("确定") : spec.confirmText,
                                      spec.risk == Risk::Danger ? "danger" : "primary",
                                      [&sheet] { sheet.accept(); });
    ok->setAccessibleDescription(spec.summary);
    if (ack) {
        ok->setEnabled(false);
        ok->setToolTip(u("先勾选「%1」").arg(ack->text()));
        QObject::connect(ack, &QCheckBox::toggled, ok, &QWidget::setEnabled);
    }
    // Enter must never confirm a dangerous action by accident.
    QPushButton* def = spec.risk == Risk::Danger ? cancel : ok;
    cancel->setAutoDefault(def == cancel);
    ok->setAutoDefault(def == ok);
    def->setDefault(true);
    def->setFocus();

    return sheet.exec() == QDialog::Accepted;
}

void ui::notice(QWidget* parent, NoticeTone tone, const QString& title, const QString& body,
                const QString& detail)
{
    QColor c;
    QString icon;
    switch (tone) {
    case NoticeTone::Info:    c = theme::info();    icon = QStringLiteral("info");  break;
    case NoticeTone::Warning: c = theme::warning(); icon = QStringLiteral("alert"); break;
    case NoticeTone::Danger:  c = theme::danger();  icon = QStringLiteral("x-circle"); break;
    }
    Sheet sheet(parent);
    sheet.setSheetWidth(480);
    sheet.setHeader(icon, c, title);
    auto* b = ui::label(body, "secondary");
    b->setWordWrap(true);
    b->setTextInteractionFlags(Qt::TextSelectableByMouse);
    sheet.body()->addWidget(b);
    if (!detail.isEmpty()) {
        auto* box = ui::cardAlt();
        auto* bv = new QVBoxLayout(box);
        bv->setContentsMargins(14, 10, 14, 12);
        auto* d = new WrapLabel(detail);
        d->setProperty("role", "mono");
        bv->addWidget(d);
        sheet.body()->addWidget(box);
    }
    QPushButton* ok = sheet.addButton(u("知道了"), "primary", [&sheet] { sheet.accept(); });
    ok->setDefault(true);
    ok->setFocus();
    sheet.exec();
}
