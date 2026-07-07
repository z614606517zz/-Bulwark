#include "widgets/ToggleSwitch.h"
#include "Theme.h"

#include <QPainter>

ToggleSwitch::ToggleSwitch(bool on, QWidget* parent) : QAbstractButton(parent)
{
    setCheckable(true);
    setChecked(on);
    setCursor(Qt::PointingHandCursor);
}

QSize ToggleSwitch::sizeHint() const { return {44, 26}; }

void ToggleSwitch::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    const qreal w = 40, h = 22;
    const qreal x = (width() - w) / 2.0, y = (height() - h) / 2.0;
    const bool on = isChecked();

    p.setPen(Qt::NoPen);
    p.setBrush(on ? theme::accent() : theme::surfaceHi());
    p.drawRoundedRect(QRectF(x, y, w, h), h / 2, h / 2);

    const qreal r = h - 6;
    const qreal kx = on ? (x + w - 3 - r) : (x + 3);
    p.setBrush(on ? theme::accentInk() : theme::textSecondary());
    p.drawEllipse(QRectF(kx, y + 3, r, r));
}
