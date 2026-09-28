#include "design/Backdrop.h"
#include "design/Theme.h"

#include <QEvent>
#include <QLinearGradient>
#include <QPaintEvent>
#include <QPainter>
#include <QRadialGradient>
#include <QRandomGenerator>
#include <QResizeEvent>

#include <cmath>

namespace {

// Blits the part of `cache` under `dirty` (logical px) onto the painter's device.
void blit(QPainter& p, const QPixmap& cache, const QRect& dirty)
{
    const qreal dpr = cache.devicePixelRatio();
    p.drawPixmap(QRectF(dirty), cache,
                 QRectF(dirty.x() * dpr, dirty.y() * dpr, dirty.width() * dpr, dirty.height() * dpr));
}

// See Backdrop::install().
class WindowMaterial final : public QObject
{
public:
    explicit WindowMaterial(QWidget* window) : QObject(window) {}

protected:
    bool eventFilter(QObject* obj, QEvent* ev) override
    {
        auto* w = static_cast<QWidget*>(obj);
        if (ev->type() == QEvent::Resize) {
            m_cache = QPixmap();
        } else if (ev->type() == QEvent::Paint) {
            if (m_cache.isNull() || !qFuzzyCompare(m_cache.devicePixelRatio(), w->devicePixelRatioF()))
                m_cache = Backdrop::render(Backdrop::Kind::Content, w->size(), w->devicePixelRatioF());
            QPainter p(w);
            blit(p, m_cache, static_cast<QPaintEvent*>(ev)->rect());
        }
        return false; // the window still paints (and its children still paint) as usual
    }

private:
    QPixmap m_cache;
};

} // namespace

Backdrop::Backdrop(Kind kind, QWidget* parent) : QFrame(parent), m_kind(kind)
{
    setFrameShape(QFrame::NoFrame);
    setAttribute(Qt::WA_OpaquePaintEvent); // we cover every pixel
}

void Backdrop::install(QWidget* window)
{
    if (window)
        window->installEventFilter(new WindowMaterial(window));
}

void Backdrop::resizeEvent(QResizeEvent* e)
{
    QFrame::resizeEvent(e);
    m_cache = QPixmap();
}

void Backdrop::paintCourses(QPainter& p, const QRectF& r, const QBrush& joints, qreal courseHeight)
{
    if (r.width() < 1.0 || r.height() < 1.0 || courseHeight < 4.0)
        return;
    p.save();
    p.setClipRect(r, Qt::IntersectClip);
    p.setRenderHint(QPainter::Antialiasing, false); // crisp 1px joints
    p.setPen(QPen(joints, 1.0));
    QRandomGenerator gen(0x0B1A5u);
    const int left = int(std::floor(r.left()));
    const int right = int(std::ceil(r.right()));
    const int rows = int(r.height() / courseHeight) + 2;
    for (int row = 0; row < rows; ++row) {
        const int y = int(std::floor(r.top() + row * courseHeight));
        const int yNext = int(std::floor(r.top() + (row + 1) * courseHeight));
        p.drawLine(left, y, right, y); // bed joint
        // Head joints: blocks 1.6–3.4 course heights long, each course starting at its
        // own offset so joints never line up vertically — that is what makes it read as
        // laid stone rather than tiles.
        qreal x = r.left() - gen.bounded(courseHeight * 3.0);
        for (;;) {
            x += courseHeight * (1.6 + gen.bounded(1.8));
            if (x >= r.right())
                break;
            const int xi = int(std::floor(x));
            p.drawLine(xi, y + 1, xi, yNext - 1);
        }
    }
    p.restore();
}

QPixmap Backdrop::render(Kind kind, const QSize& size, qreal dpr)
{
    const int w = qMax(1, size.width());
    const int h = qMax(1, size.height());
    QPixmap pm(qMax(1, int(w * dpr)), qMax(1, int(h * dpr)));
    pm.setDevicePixelRatio(dpr);

    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);
    const QRectF r(0, 0, w, h);
    const qreal span = qMax(r.width(), r.height());
    const QColor black(0, 0, 0);
    const QColor warmWhite(0xFF, 0xF1, 0xDC);

    auto light = [&](const QPointF& c, qreal radius, const QColor& color, qreal alpha) {
        QRadialGradient g(c, qMax<qreal>(1.0, radius));
        g.setColorAt(0.0, theme::tint(color, alpha));
        g.setColorAt(0.5, theme::tint(color, alpha * 0.35));
        g.setColorAt(1.0, theme::tint(color, 0.0));
        p.fillRect(r, g);
    };

    if (kind == Kind::Content) {
        // Warm graphite, lit from above and settling darker toward the floor.
        QLinearGradient base(r.topLeft(), r.bottomLeft());
        base.setColorAt(0.0, theme::blend(warmWhite, theme::bg(), 0.030));
        base.setColorAt(0.55, theme::bg());
        base.setColorAt(1.0, theme::blend(black, theme::bg(), 0.22));
        p.fillRect(r, base);
        // Cool jade spill from the rail, warm brass wash from the far corner: two
        // light sources of different temperature instead of one tinted fog.
        light(QPointF(0.0, r.height() * 0.30), span * 0.45, theme::accent(), 0.050);
        light(QPointF(r.width() * 0.96, -r.height() * 0.08), span * 0.62, theme::brass(), 0.055);
        p.fillRect(r, theme::grainBrush());
        p.end(); // finish painting before the pixmap is handed out
        return pm;
    }

    // Rail: jade-ink, a touch of jade at the top, deeper at the foot.
    QLinearGradient base(r.topLeft(), r.bottomLeft());
    base.setColorAt(0.0, theme::blend(theme::accent(), theme::bgSidebar(), 0.07));
    base.setColorAt(1.0, theme::blend(black, theme::bgSidebar(), 0.25));
    p.fillRect(r, base);
    QLinearGradient wall(r.topLeft(), r.bottomLeft()); // strongest behind the brand, fading down the rail
    wall.setColorAt(0.0, theme::tint(theme::accentSoft(), 0.085));
    wall.setColorAt(1.0, theme::tint(theme::accentSoft(), 0.02));
    paintCourses(p, r, QBrush(wall));
    light(QPointF(40.0, 36.0), 170.0, theme::accent(), 0.13); // behind the brand mark
    p.fillRect(r, theme::grainBrush());

    // Brass inlay where the rail meets the work area: a dark joint, then the lit edge.
    p.setRenderHint(QPainter::Antialiasing, false);
    const int edge = qMax(2, w);
    p.setPen(theme::blend(black, theme::bgSidebar(), 0.5));
    p.drawLine(edge - 2, 0, edge - 2, h);
    QLinearGradient inlay(r.topLeft(), r.bottomLeft());
    inlay.setColorAt(0.0, theme::tint(theme::brass(), 0.55));
    inlay.setColorAt(0.5, theme::tint(theme::brass(), 0.22));
    inlay.setColorAt(1.0, theme::tint(theme::brass(), 0.35));
    p.setPen(QPen(QBrush(inlay), 1.0));
    p.drawLine(edge - 1, 0, edge - 1, h);
    p.end();
    return pm;
}

void Backdrop::paintEvent(QPaintEvent* e)
{
    if (m_cache.isNull() || !qFuzzyCompare(m_cache.devicePixelRatio(), devicePixelRatioF()))
        m_cache = render(m_kind, size(), devicePixelRatioF());
    QPainter p(this);
    blit(p, m_cache, e->rect());
}
