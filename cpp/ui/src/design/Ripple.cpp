#include "design/Ripple.h"
#include "design/Motion.h"
#include "design/Theme.h"

#include <QApplication>
#include <QEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QRadialGradient>
#include <QRegularExpression>
#include <QToolButton>
#include <QVariantAnimation>
#include <QWidget>

#include <cmath>

namespace {

constexpr int kMs = 420;
constexpr qreal kPeakAlpha = 0.15;

// The corner radius the button is actually drawn with, so the circle is clipped
// to the button's shape instead of a guess:
//   • a widget with its own "border-radius: Npx" (the list shell's 「N 条新记录」
//     pill) says so in its style sheet;
//   • otherwise the global sheet's values (design/Theme.cpp): 10 px for a push
//     button, 8 px for a small one and for tool buttons.
qreal cornerRadius(const QWidget* w)
{
    static const QRegularExpression rx(QStringLiteral("border-radius:\\s*(\\d+(?:\\.\\d+)?)px"));
    const QRegularExpressionMatch m = rx.match(w->styleSheet());
    if (m.hasMatch())
        return m.captured(1).toDouble();
    if (qobject_cast<const QToolButton*>(w))
        return 8.0;
    return w->property("size").toString() == QLatin1String("sm") ? 8.0 : 10.0;
}

// The overlay that paints one ripple over its button and removes itself when the
// ripple has faded. Transparent to the mouse, so the button's own press, release
// and hover behaviour is exactly as it was.
class Ripple final : public QWidget
{
public:
    Ripple(QWidget* host, const QPointF& at, const QColor& color)
        : QWidget(host), m_at(at), m_color(color), m_radius(cornerRadius(host))
    {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_NoSystemBackground);
        setFocusPolicy(Qt::NoFocus);
        setGeometry(host->rect());
        // Far enough to reach the corner furthest from the press.
        const QRectF r(host->rect());
        for (const QPointF& c : {r.topLeft(), r.topRight(), r.bottomLeft(), r.bottomRight()})
            m_reach = qMax(m_reach, std::hypot(c.x() - at.x(), c.y() - at.y()));

        auto* anim = new QVariantAnimation(this);
        anim->setStartValue(0.0);
        anim->setEndValue(1.0);
        anim->setDuration(motion::duration(kMs));
        connect(anim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
            m_t = v.toReal();
            update();
        });
        connect(anim, &QVariantAnimation::finished, this, &QObject::deleteLater);
        anim->start();
        show();
        raise();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        const qreal grown = motion::outCubic(m_t) * m_reach;
        if (grown <= 0.5)
            return;
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        QPainterPath clip;
        clip.addRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), m_radius, m_radius);
        p.setClipPath(clip);
        // Brightest at the press, fading to nothing at its edge — and the whole
        // circle fades out as it spreads, so it never ends on a visible boundary.
        const qreal alpha = kPeakAlpha * (1.0 - motion::inCubic(m_t));
        QRadialGradient g(m_at, grown);
        g.setColorAt(0.0, theme::tint(m_color, alpha));
        g.setColorAt(0.65, theme::tint(m_color, alpha * 0.75));
        g.setColorAt(1.0, theme::tint(m_color, 0.0));
        p.setPen(Qt::NoPen);
        p.setBrush(g);
        p.drawEllipse(m_at, grown, grown);
    }

private:
    QPointF m_at;
    QColor m_color;
    qreal m_radius = 10.0;
    qreal m_reach = 0.0;
    qreal m_t = 0.0;
};

class RippleFilter final : public QObject
{
public:
    using QObject::QObject;

protected:
    bool eventFilter(QObject* watched, QEvent* ev) override
    {
        if (ev->type() != QEvent::MouseButtonPress || !watched->isWidgetType())
            return false;
        auto* w = static_cast<QWidget*>(watched);
        const bool ordinary = qobject_cast<QPushButton*>(w) || qobject_cast<QToolButton*>(w);
        if (!ordinary || !w->isEnabled() || w->width() < 8 || w->height() < 8)
            return false;
        auto* me = static_cast<QMouseEvent*>(ev);
        if (me->button() != Qt::LeftButton || !w->rect().contains(me->position().toPoint()))
            return false;
        // One at a time: a double click shouldn't stack two circles. (findChild
        // wants a Q_OBJECT; this class deliberately has none — it has no signals
        // or slots of its own and lives entirely in this file.)
        Ripple* running = nullptr;
        for (QObject* child : w->children())
            if ((running = dynamic_cast<Ripple*>(child)))
                break;
        delete running;
        // Ink on a filled brand button, otherwise the text colour — the ripple is
        // the button's own palette breathing, not a new colour in the design.
        const bool primary = w->property("variant").toString() == QLatin1String("primary");
        new Ripple(w, me->position(), primary ? theme::accentInk() : theme::textPrimary());
        return false; // the button still gets its press
    }
};

} // namespace

void ui::installRipples(QApplication& app)
{
    if (!motion::enabled())
        return;
    app.installEventFilter(new RippleFilter(&app));
}
