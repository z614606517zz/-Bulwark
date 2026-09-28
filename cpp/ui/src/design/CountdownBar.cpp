#include "design/CountdownBar.h"
#include "design/Motion.h"
#include "design/Theme.h"

#include <QFontMetrics>
#include <QPainter>
#include <QTimer>

#include <cmath>

CountdownBar::CountdownBar(QWidget* parent) : QWidget(parent), m_color(theme::accent())
{
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_timer = new QTimer(this);
    // Smooth when motion is allowed; otherwise a calm step every quarter second.
    m_timer->setInterval(motion::enabled() ? 50 : 250);
    connect(m_timer, &QTimer::timeout, this, &CountdownBar::tick);
    setAccessibleName(QString::fromUtf8("倒计时"));
}

void CountdownBar::start(int ms)
{
    m_total = qMax(1, ms);
    m_base = m_total;
    m_running = true;
    m_paused = false;
    m_lastSecond = -1;
    m_clock.start();
    m_timer->start();
    tick();
}

void CountdownBar::stop()
{
    m_running = false;
    m_paused = false;
    m_timer->stop();
    update();
}

void CountdownBar::pause()
{
    if (!m_running || m_paused)
        return;
    m_base = remainingMs();
    m_paused = true;
    m_timer->stop();
    update();
}

void CountdownBar::resume()
{
    if (!m_running || !m_paused)
        return;
    m_paused = false;
    m_clock.start();
    m_timer->start();
    update();
}

int CountdownBar::remainingMs() const
{
    if (!m_running)
        return 0;
    if (m_paused)
        return m_base;
    return qMax(0, m_base - int(m_clock.elapsed()));
}

void CountdownBar::setColor(const QColor& c)
{
    m_color = c;
    update();
}

void CountdownBar::setFormatter(std::function<QString(int)> fmt)
{
    m_fmt = std::move(fmt);
    updateGeometry();
    update();
}

QSize CountdownBar::sizeHint() const
{
    return {200, m_fmt ? qMax(18, fontMetrics().height() + 2) : 6};
}

QSize CountdownBar::minimumSizeHint() const
{
    // Room for a short bar plus the full caption (measured at its longest).
    if (!m_fmt)
        return {40, 6};
    QFont f = font();
    f.setPointSizeF(9.0);
    const int capW = QFontMetrics(f).horizontalAdvance(m_fmt(88)) + 2;
    return {48 + 10 + capW, sizeHint().height()};
}

QString CountdownBar::caption() const
{
    if (!m_fmt)
        return QString();
    return m_fmt(int(std::ceil(remainingMs() / 1000.0)));
}

void CountdownBar::tick()
{
    const int left = remainingMs();
    const int secs = int(std::ceil(left / 1000.0));
    if (secs != m_lastSecond) {
        m_lastSecond = secs;
        const QString cap = caption();
        if (!cap.isEmpty())
            setAccessibleDescription(cap);
        emit secondChanged(secs);
    }
    update();
    if (m_running && !m_paused && left <= 0) {
        m_running = false;
        m_timer->stop();
        emit finished();
    }
}

void CountdownBar::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const QString cap = caption();
    QFont f = font();
    f.setPointSizeF(9.0);
    constexpr int gap = 10;
    const int capW = cap.isEmpty() ? 0 : QFontMetrics(f).horizontalAdvance(cap) + 2;
    const qreal barW = qMax(10, width() - (cap.isEmpty() ? 0 : capW + gap));
    const qreal h = 4.0;
    const QRectF track(0, (height() - h) / 2.0, barW, h);
    p.setPen(Qt::NoPen);
    p.setBrush(theme::tint(m_color, 0.16));
    p.drawRoundedRect(track, h / 2, h / 2);
    const qreal frac = m_total > 0 ? qBound<qreal>(0.0, qreal(remainingMs()) / m_total, 1.0) : 0.0;
    if (frac > 0.0) {
        QLinearGradient g(track.topLeft(), track.topRight());
        g.setColorAt(0.0, theme::blend(m_color, theme::surface(), 0.75));
        g.setColorAt(1.0, m_color);
        p.setBrush(g);
        p.drawRoundedRect(QRectF(track.left(), track.top(), track.width() * frac, h), h / 2, h / 2);
    }
    if (!cap.isEmpty()) {
        p.setFont(f);
        p.setPen(m_paused ? theme::textSecondary() : theme::textMuted());
        p.drawText(QRectF(barW + gap, 0, capW, height()), Qt::AlignVCenter | Qt::AlignLeft, cap);
    }
}
