#pragma once
#include "Theme.h"
#include "widgets/AppIcon.h"
#include "widgets/Ui.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QVBoxLayout>

// Shared card building blocks used by the dashboard and card/form pages.
namespace ui {

// A rounded, softly-tinted square holding a centred icon.
inline QFrame* iconBadge(const QString& name, const QColor& color, int box, int iconPx)
{
    auto* f = new QFrame;
    f->setFixedSize(box, box);
    f->setStyleSheet(QStringLiteral("background:%1; border-radius:%2px;")
                         .arg(theme::blend(color, theme::surface(), 0.18).name())
                         .arg(box / 4));
    auto* lay = new QVBoxLayout(f);
    lay->setContentsMargins(0, 0, 0, 0);
    auto* ic = new AppIcon(name);
    ic->setColor(color);
    ic->setPx(iconPx);
    lay->addWidget(ic);
    return f;
}

// A label with explicit size / weight / colour (bypasses role styling).
inline QLabel* coloredText(const QString& text, int pt, int weight, const QColor& c)
{
    auto* l = new QLabel(text);
    l->setStyleSheet(QStringLiteral("font-size:%1pt; font-weight:%2; color:%3;")
                         .arg(pt).arg(weight).arg(c.name()));
    return l;
}

inline QLabel* statusDot(const QColor& c)
{
    auto* d = new QLabel;
    d->setFixedSize(9, 9);
    d->setStyleSheet(QStringLiteral("background:%1; border-radius:4px;").arg(c.name()));
    return d;
}

// A metric card: icon badge + optional delta pill, big value, caption.
inline QFrame* statCard(const QString& icon, const QColor& color, const QString& value,
                        const QString& name, const QString& delta = QString(),
                        const QColor& deltaColor = QColor())
{
    auto* c = card();
    c->setMinimumHeight(112);
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(18, 16, 18, 16);
    v->setSpacing(10);

    auto* top = new QHBoxLayout;
    top->setContentsMargins(0, 0, 0, 0);
    top->addWidget(iconBadge(icon, color, 38, 20));
    top->addStretch();
    if (!delta.isEmpty())
        top->addWidget(pill(delta, deltaColor.isValid() ? deltaColor : color), 0, Qt::AlignTop);
    v->addLayout(top);

    v->addWidget(coloredText(value, 24, 800, theme::textPrimary()));
    v->addWidget(label(name, "secondary"));
    return c;
}

} // namespace ui
