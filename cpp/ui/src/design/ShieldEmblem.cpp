#include "design/ShieldEmblem.h"
#include "design/Icons.h"
#include "design/Theme.h"

#include <QConicalGradient>
#include <QPainter>
#include <QRadialGradient>
#include <QTimer>
#include <QtMath>

#include <cmath>

#ifdef Q_OS_WIN
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#endif

namespace {

// Windows "Show animations in Windows" (Settings > Accessibility > Visual effects).
bool systemAllowsMotion()
{
#ifdef Q_OS_WIN
    BOOL on = TRUE;
    if (SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &on, 0))
        return on != FALSE;
#endif
    return true;
}

} // namespace

ShieldEmblem::ShieldEmblem(QWidget* parent) : QWidget(parent)
{
    setAttribute(Qt::WA_TransparentForMouseEvents);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    setFixedSize(sizeHint());
    m_motionAllowed = systemAllowsMotion();
    m_timer = new QTimer(this);
    m_timer->setInterval(33); // ~30 fps is plenty for a slow sweep
    connect(m_timer, &QTimer::timeout, this, qOverload<>(&QWidget::update));
    setAccessibleName(QString::fromUtf8("防护状态"));
}

QColor ShieldEmblem::colorFor(State s)
{
    switch (s) {
    case State::Protected: return theme::success();
    case State::Partial:   return theme::warning();
    case State::Off:       return theme::danger();
    case State::Unknown:   break;
    }
    return theme::textMuted();
}

void ShieldEmblem::setState(State s)
{
    if (s == m_state)
        return;
    m_state = s;
    syncAnimation();
    update();
}

bool ShieldEmblem::live() const
{
    return m_state == State::Protected || m_state == State::Partial;
}

void ShieldEmblem::syncAnimation()
{
    const bool run = live() && m_motionAllowed && isVisible();
    if (run && !m_timer->isActive()) {
        if (!m_clock.isValid())
            m_clock.start();
        m_timer->start();
    } else if (!run && m_timer->isActive()) {
        m_timer->stop();
    }
}

void ShieldEmblem::showEvent(QShowEvent* e)
{
    QWidget::showEvent(e);
    syncAnimation();
}

void ShieldEmblem::hideEvent(QHideEvent* e)
{
    QWidget::hideEvent(e);
    syncAnimation();
}

void ShieldEmblem::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    const qreal side = qMin(width(), height());
    const QPointF c(width() / 2.0, height() / 2.0);
    const QColor col = colorFor(m_state);
    const bool animated = live() && m_motionAllowed && m_clock.isValid();
    const qreal t = animated ? m_clock.elapsed() / 1000.0 : 0.0;

    // 1) Ambient glow — breathes slowly while protection is live.
    const qreal breathe = animated ? 0.82 + 0.18 * std::sin(t * 2.0 * M_PI / 3.6) : (live() ? 0.9 : 0.6);
    QRadialGradient glow(c, side * 0.5);
    glow.setColorAt(0.0, theme::tint(col, 0.28 * breathe));
    glow.setColorAt(0.55, theme::tint(col, 0.08 * breathe));
    glow.setColorAt(1.0, theme::tint(col, 0.0));
    p.setPen(Qt::NoPen);
    p.setBrush(glow);
    p.drawEllipse(c, side * 0.5, side * 0.5);

    // 2) Instrument ticks; every fifth is longer.
    QPen tick(theme::tint(col, 0.26), 1.1);
    tick.setCapStyle(Qt::RoundCap);
    p.setPen(tick);
    const qreal outer = side * 0.462;
    for (int k = 0; k < 60; ++k) {
        const qreal a = k * (2.0 * M_PI / 60.0);
        const qreal inner = (k % 5 == 0) ? side * 0.418 : side * 0.438;
        p.drawLine(QPointF(c.x() + inner * std::cos(a), c.y() + inner * std::sin(a)),
                   QPointF(c.x() + outer * std::cos(a), c.y() + outer * std::sin(a)));
    }

    // 3) Ring track.
    const qreal ringR = side * 0.375;
    const QRectF ring(c.x() - ringR, c.y() - ringR, ringR * 2.0, ringR * 2.0);
    p.setPen(QPen(theme::tint(col, 0.32), 1.5));
    p.setBrush(Qt::NoBrush);
    p.drawEllipse(ring);

    // 4) Radar sweep (live states only): a comet arc travelling clockwise with
    //    its tail fading behind it. Static (parked at 12 o'clock) if motion is off.
    if (live()) {
        qreal head = 90.0 - t * 80.0; // degrees, Qt convention (counter-clockwise positive)
        head = std::fmod(head, 360.0);
        if (head < 0.0)
            head += 360.0;
        QConicalGradient cg(c, head);
        cg.setColorAt(0.0, theme::tint(col, 0.95));
        cg.setColorAt(0.28, theme::tint(col, 0.0));
        cg.setColorAt(1.0, theme::tint(col, 0.0));
        QPen sweep(QBrush(cg), 3.0);
        sweep.setCapStyle(Qt::FlatCap);
        p.setPen(sweep);
        p.drawArc(ring, int(head * 16.0), 100 * 16);
        const qreal ha = qDegreesToRadians(head);
        p.setPen(Qt::NoPen);
        p.setBrush(col);
        p.drawEllipse(QPointF(c.x() + ringR * std::cos(ha), c.y() - ringR * std::sin(ha)), 2.6, 2.6);
    }

    // 5) Inner disc, lit from above.
    const qreal discR = side * 0.285;
    QRadialGradient disc(QPointF(c.x(), c.y() - discR * 0.45), discR * 1.45);
    disc.setColorAt(0.0, theme::blend(col, theme::surface(), 0.30));
    disc.setColorAt(1.0, theme::blend(col, theme::surface(), 0.07));
    p.setPen(QPen(theme::tint(col, 0.55), 1.2));
    p.setBrush(disc);
    p.drawEllipse(c, discR, discR);

    // 6) The shield itself.
    const char* glyph = m_state == State::Protected ? "trust"
                        : m_state == State::Partial ? "shield-alert"
                        : m_state == State::Off     ? "shield-x"
                                                    : "shield";
    const qreal g = discR * 1.22;
    AppIcon::draw(p, QString::fromLatin1(glyph), QRectF(c.x() - g / 2.0, c.y() - g / 2.0, g, g), col,
                  qMax<qreal>(2.0, side * 0.018));
}
