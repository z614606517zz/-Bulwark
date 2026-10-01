#include "design/CountdownBar.h"
#include "design/Motion.h"
#include "design/Theme.h"

#include <QCursor>
#include <QFontMetrics>
#include <QPainter>
#include <QRect>
#include <QTimer>

#include <cmath>

namespace {
// 悬停轮询间隔。够快到「指针挪上去」的那一刻几乎立刻停住(120ms 内最多再走掉 120ms 倒计时),
// 又不至于变成一个空转的忙循环 —— 每次只是一次 GetCursorPos 加一次矩形判断,不触发任何重绘。
constexpr int kHoverPollMs = 120;
} // namespace

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
    if (m_hoverTimer) {
        // 从「指针没在这上面动过」开始记:卡片刚好弹在静止指针底下时照常倒数。
        m_hoverArmed = false;
        m_lastCursor = QCursor::pos();
        m_hoverTimer->start();
    }
    tick();
}

void CountdownBar::stop()
{
    m_running = false;
    m_paused = false;
    m_hoverArmed = false;
    m_timer->stop();
    if (m_hoverTimer)
        m_hoverTimer->stop();
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

void CountdownBar::ensureRemaining(int ms)
{
    if (!m_running) {
        start(ms);
        return;
    }
    if (remainingMs() >= ms)
        return;
    // 只改「从多少开始数」,不碰暂停与悬停判定:用户正把指针停在卡片上读的时候,补时不能让它突然走起来。
    m_base = ms;
    m_total = qMax(m_total, ms);
    if (!m_paused)
        m_clock.start();
    m_lastSecond = -1;
    tick();
}

int CountdownBar::remainingMs() const
{
    if (!m_running)
        return 0;
    if (m_paused)
        return m_base;
    return qMax(0, m_base - int(m_clock.elapsed()));
}

void CountdownBar::setHoverPause(QWidget* target)
{
    m_hoverTarget = target;
    if (!target)
        return;
    if (!m_hoverTimer) {
        m_hoverTimer = new QTimer(this);
        m_hoverTimer->setInterval(kHoverPollMs);
        connect(m_hoverTimer, &QTimer::timeout, this, &CountdownBar::syncHoverPause);
    }
    if (m_running)
        m_hoverTimer->start();
}

// 悬停暂停只认一件事:指针此刻是不是真的停在这张卡片上。
//
// 【为什么不能靠 enterEvent / leaveEvent】卡片弹出时如果正好落在静止的指针底下,Windows 会补一条
// 「无按键的鼠标移动」来表示进入,Qt 据此发 QEvent::Enter —— 倒计时当场被暂停;而 Leave 要等指针
// 【下一次移动】才有机会送到。用户此刻没碰鼠标(在看别处、或指针本来就停在右下角托盘那一带),
// 这条通知就永远停在屏幕上不再自己关闭。toast 因为上面一条退场而滑到静止指针底下、以及卡片移开
// 但指针不动,都是同一个死结:暂停进得去、出不来。
//
// 所以这里直接问指针在哪,并且把「悬停」定义成【指针在卡片上动过】:
//   · 用户把鼠标挪上去读       -> 动过 -> 暂停,停多久都不催;挪开即继续(轮询保证一定继续)。
//   · 卡片自己跑到静止指针底下 -> 没动过 -> 照常倒数,到点自动关闭。
void CountdownBar::syncHoverPause()
{
    if (!m_running || !m_hoverTarget) {
        if (m_hoverTimer)
            m_hoverTimer->stop();
        return;
    }
    const QPoint now = QCursor::pos();
    const bool moved = now != m_lastCursor;
    m_lastCursor = now;
    if (!pointerOnTarget(now)) {
        m_hoverArmed = false;
        resume(); // 没在暂停就什么也不做
        return;
    }
    if (moved)
        m_hoverArmed = true;
    if (m_hoverArmed)
        pause();
}

bool CountdownBar::pointerOnTarget(const QPoint& globalPos) const
{
    const QWidget* t = m_hoverTarget.data();
    if (!t || !t->isVisible())
        return false;
    const QWidget* win = t->window();
    if (!win || !win->isVisible() || win->isMinimized())
        return false;
    // 用 target 自己的矩形,而不是整个窗口的 frameGeometry:这些浮窗四周留了一圈画阴影的透明
    // 边距,按窗口算会把「指针在卡片外面的空白上」也当成悬停。
    return QRect(t->mapToGlobal(QPoint(0, 0)), t->size()).contains(globalPos);
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
        if (m_hoverTimer)
            m_hoverTimer->stop();
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
