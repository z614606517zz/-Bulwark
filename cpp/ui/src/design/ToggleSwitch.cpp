#include "design/ToggleSwitch.h"
#include "design/Theme.h"

#include <QEnterEvent>
#include <QFocusEvent>
#include <QLinearGradient>
#include <QPainter>
#include <QVariantAnimation>

ToggleSwitch::ToggleSwitch(bool on, QWidget* parent) : QAbstractButton(parent)
{
    setCheckable(true);
    setCursor(Qt::PointingHandCursor);
    m_anim = new QVariantAnimation(this);
    m_anim->setDuration(140);
    m_anim->setEasingCurve(QEasingCurve::OutCubic);
    connect(m_anim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
        m_pos = v.toReal();
        update();
    });
    setChecked(on);          // routes through checkStateSet(): knob snaps into place
    m_pos = on ? 1.0 : 0.0;
}

QSize ToggleSwitch::sizeHint() const { return {48, 30}; }

void ToggleSwitch::checkStateSet()
{
    QAbstractButton::checkStateSet();
    m_anim->stop();
    m_pos = isChecked() ? 1.0 : 0.0;
    update();
}

void ToggleSwitch::nextCheckState()
{
    QAbstractButton::nextCheckState();
    m_anim->stop();
    m_anim->setStartValue(m_pos);
    m_anim->setEndValue(isChecked() ? 1.0 : 0.0);
    m_anim->start();
}

void ToggleSwitch::enterEvent(QEnterEvent*) { m_hover = true; update(); }
void ToggleSwitch::leaveEvent(QEvent*)      { m_hover = false; update(); }

void ToggleSwitch::focusInEvent(QFocusEvent* e)
{
    m_keyboardFocus = e->reason() == Qt::TabFocusReason || e->reason() == Qt::BacktabFocusReason;
    QAbstractButton::focusInEvent(e);
    update();
}

void ToggleSwitch::focusOutEvent(QFocusEvent* e)
{
    m_keyboardFocus = false;
    QAbstractButton::focusOutEvent(e);
    update();
}

void ToggleSwitch::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    if (!isEnabled())
        p.setOpacity(0.45);

    constexpr qreal w = 40.0, h = 22.0;
    const QRectF track((width() - w) / 2.0, (height() - h) / 2.0, w, h);
    const qreal t = qBound<qreal>(0.0, m_pos, 1.0);

    // Off track (with rim), then the brand-gradient "on" track faded in by t.
    p.setPen(QPen(theme::tint(theme::borderStrong(), 1.0 - t), 1.0));
    p.setBrush(m_hover ? theme::blend(theme::textPrimary(), theme::surfaceHi(), 0.06)
                       : theme::surfaceHi());
    p.drawRoundedRect(track.adjusted(0.5, 0.5, -0.5, -0.5), h / 2.0, h / 2.0);
    if (t > 0.0) {
        QLinearGradient g(track.topLeft(), track.topRight());
        g.setColorAt(0.0, theme::accentStrong());
        g.setColorAt(1.0, theme::accentDeep());
        p.save();
        p.setOpacity(p.opacity() * t);
        p.setPen(Qt::NoPen);
        p.setBrush(g);
        p.drawRoundedRect(track, h / 2.0, h / 2.0);
        p.restore();
    }

    // Knob: slate when off, white when on.
    const qreal d = h - 6.0;
    const QRectF knob(track.left() + 3.0 + (w - 6.0 - d) * t, track.top() + 3.0, d, d);
    p.setPen(Qt::NoPen);
    p.setBrush(theme::blend(theme::accentInk(), theme::textSecondary(), t));
    p.drawEllipse(knob);

    if (m_keyboardFocus && hasFocus()) {
        p.setPen(QPen(theme::accent(), 1.5));
        p.setBrush(Qt::NoBrush);
        p.drawRoundedRect(track.adjusted(-3.0, -3.0, 3.0, 3.0), h / 2.0 + 3.0, h / 2.0 + 3.0);
    }
}
