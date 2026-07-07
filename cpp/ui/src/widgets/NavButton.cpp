#include "widgets/NavButton.h"
#include "widgets/AppIcon.h"
#include "Theme.h"

#include <QEnterEvent>
#include <QPainter>

NavButton::NavButton(const QString& iconName, const QString& text, QWidget* parent)
    : QAbstractButton(parent), m_icon(iconName)
{
    setText(text);
    setCheckable(true);
    setCursor(Qt::PointingHandCursor);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
}

QSize NavButton::sizeHint() const { return {200, 44}; }

void NavButton::enterEvent(QEnterEvent*) { m_hover = true; update(); }
void NavButton::leaveEvent(QEvent*)      { m_hover = false; update(); }

void NavButton::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    const QRectF r = QRectF(rect()).adjusted(0, 2, 0, -2);
    const bool active = isChecked();

    QColor bg = active ? theme::surfaceHi()
                       : (m_hover ? theme::surfaceAlt() : QColor(0, 0, 0, 0));
    if (bg.alpha() > 0) {
        p.setPen(Qt::NoPen);
        p.setBrush(bg);
        p.drawRoundedRect(r, 10, 10);
    }

    if (active) {
        p.setBrush(theme::accent());
        p.setPen(Qt::NoPen);
        p.drawRoundedRect(QRectF(r.left(), r.center().y() - 10, 3, 20), 1.5, 1.5);
    }

    const QColor fg = active ? theme::accent()
                             : (m_hover ? theme::textPrimary() : theme::textSecondary());
    AppIcon::draw(p, m_icon, QRectF(r.left() + 14, r.center().y() - 10, 20, 20), fg,
                  active ? 1.9 : 1.7);

    p.setPen(active || m_hover ? theme::textPrimary() : theme::textSecondary());
    QFont f = font();
    f.setPointSizeF(10.5);
    f.setWeight(active ? QFont::DemiBold : QFont::Medium);
    p.setFont(f);
    p.drawText(QRectF(r.left() + 44, r.top(), r.width() - 52, r.height()),
               Qt::AlignVCenter | Qt::AlignLeft, text());
}
