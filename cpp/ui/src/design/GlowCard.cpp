#include "design/GlowCard.h"
#include "design/Theme.h"

#include <QPainter>
#include <QPainterPath>
#include <QRadialGradient>

GlowCard::GlowCard(QWidget* parent) : QFrame(parent)
{
    setFrameShape(QFrame::NoFrame);
}

void GlowCard::setTone(Tone tone)
{
    m_tone = tone;
    update();
}

void GlowCard::setRadius(qreal radius)
{
    m_radius = radius;
    update();
}

void GlowCard::setGlow(const QColor& color, QPointF anchor, qreal reach, qreal strength)
{
    m_glow = color;
    m_anchor = anchor;
    m_reach = reach;
    m_strength = strength;
    update();
}

void GlowCard::clearGlow()
{
    m_glow = QColor();
    update();
}

void GlowCard::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    // Half-pixel inset so the 1px rim lands on whole device pixels.
    const QRectF r = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
    if (r.width() < 2 || r.height() < 2)
        return;
    QPainterPath shape;
    shape.addRoundedRect(r, m_radius, m_radius);

    QColor top, bottom, rimTop, rim;
    switch (m_tone) {
    case Tone::Flat:
        top = theme::surfaceTop();
        bottom = theme::surface();
        rimTop = theme::borderLit();
        rim = theme::border();
        break;
    case Tone::Inset:
        top = theme::field();
        bottom = theme::field();
        rimTop = theme::border();
        rim = theme::border();
        break;
    case Tone::Floating:
        top = theme::blend(theme::textPrimary(), theme::raised(), 0.035);
        bottom = theme::raised();
        rimTop = theme::blend(theme::textPrimary(), theme::borderStrong(), 0.14);
        rim = theme::borderStrong();
        break;
    case Tone::Rail:
        top = theme::railInset();
        bottom = theme::railInset();
        rimTop = theme::blend(theme::accentSoft(), theme::railBorder(), 0.14);
        rim = theme::railBorder();
        break;
    }

    QLinearGradient fill(r.topLeft(), r.bottomLeft());
    fill.setColorAt(0.0, top);
    fill.setColorAt(1.0, bottom);
    p.fillPath(shape, fill);

    if (m_glow.isValid()) {
        const QPointF c(r.left() + r.width() * m_anchor.x(), r.top() + r.height() * m_anchor.y());
        const qreal reach = qMax(r.width(), r.height()) * m_reach;
        QRadialGradient g(c, qMax<qreal>(1.0, reach));
        g.setColorAt(0.0, theme::tint(m_glow, m_strength));
        g.setColorAt(0.45, theme::tint(m_glow, m_strength * 0.32));
        g.setColorAt(1.0, theme::tint(m_glow, 0.0));
        p.save();
        p.setClipPath(shape);
        p.fillRect(r, g);
        p.restore();
    }

    // Rim: bright along the top ~24px, settling to the hairline colour below.
    QLinearGradient edge(r.topLeft(), r.bottomLeft());
    edge.setColorAt(0.0, rimTop);
    edge.setColorAt(qMin<qreal>(1.0, 24.0 / r.height()), rim);
    edge.setColorAt(1.0, rim);
    p.setPen(QPen(QBrush(edge), 1.0));
    p.setBrush(Qt::NoBrush);
    p.drawPath(shape);
}
