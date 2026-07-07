#include "widgets/AppIcon.h"
#include "Theme.h"

#include <QPainter>
#include <QPainterPath>
#include <QtMath>

AppIcon::AppIcon(const QString& name, QWidget* parent)
    : QWidget(parent), m_name(name), m_color(theme::textSecondary())
{
    setAttribute(Qt::WA_TransparentForMouseEvents);
}

void AppIcon::setName(const QString& name) { m_name = name; update(); }
void AppIcon::setColor(const QColor& c)    { m_color = c; update(); }
void AppIcon::setPx(int px)                { m_px = px; updateGeometry(); update(); }

void AppIcon::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    const qreal side = qMin<qreal>(m_px, qMin(width(), height()));
    const QRectF r((width() - side) / 2.0, (height() - side) / 2.0, side, side);
    draw(p, m_name, r, m_color);
}

QPixmap AppIcon::pixmap(const QString& name, const QColor& color, int px, qreal penWidth)
{
    const qreal dpr = 2.0;
    QPixmap pm(int(px * dpr), int(px * dpr));
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    draw(p, name, QRectF(0, 0, px, px), color, penWidth);
    return pm;
}

QIcon AppIcon::icon(const QString& name, const QColor& color, int px)
{
    return QIcon(pixmap(name, color, px));
}

QIcon AppIcon::appBadge()
{
    // A filled teal rounded-square badge with a white shield. Baked at several
    // sizes so the window/taskbar/tray each pick a crisp variant instead of
    // scaling one bitmap. Proportions match the 64px tray design; the shield
    // stroke stays a constant 1.5 grid units across sizes (2.4 * px / 64).
    QIcon out;
    for (int px : {16, 20, 24, 32, 48, 64, 128, 256}) {
        QPixmap pm(px, px);
        pm.fill(Qt::transparent);
        QPainter p(&pm);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(Qt::NoPen);
        p.setBrush(theme::accent());
        const qreal margin = px * (3.0 / 64.0);
        const qreal radius = px * 0.26;
        p.drawRoundedRect(QRectF(margin, margin, px - 2 * margin, px - 2 * margin), radius, radius);
        AppIcon::draw(p, QStringLiteral("shield"),
                      QRectF(px * 0.20, px * 0.18, px * 0.60, px * 0.62),
                      theme::accentInk(), 2.4 * px / 64.0);
        p.end();
        out.addPixmap(pm);
    }
    return out;
}

void AppIcon::draw(QPainter& p, const QString& name, const QRectF& rect,
                   const QColor& color, qreal penWidth)
{
    const qreal s = qMin(rect.width(), rect.height()) / 24.0;
    if (s <= 0.0)
        return;

    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    const qreal grid = 24.0 * s;
    p.translate(rect.left() + (rect.width() - grid) / 2.0,
                rect.top() + (rect.height() - grid) / 2.0);
    p.scale(s, s);

    QPen pen(color, penWidth / s);
    pen.setCapStyle(Qt::RoundCap);
    pen.setJoinStyle(Qt::RoundJoin);
    p.setPen(pen);
    p.setBrush(Qt::NoBrush);

    auto L = [&](qreal x1, qreal y1, qreal x2, qreal y2) {
        p.drawLine(QLineF(x1, y1, x2, y2));
    };
    auto dot = [&](qreal x, qreal y, qreal rad) {
        p.save();
        p.setBrush(color);
        p.setPen(Qt::NoPen);
        p.drawEllipse(QPointF(x, y), rad, rad);
        p.restore();
    };

    if (name == QLatin1String("dashboard")) {
        p.drawRoundedRect(QRectF(3, 3, 7, 8), 1.6, 1.6);
        p.drawRoundedRect(QRectF(14, 3, 7, 5), 1.6, 1.6);
        p.drawRoundedRect(QRectF(14, 12, 7, 9), 1.6, 1.6);
        p.drawRoundedRect(QRectF(3, 14, 7, 7), 1.6, 1.6);
    } else if (name == QLatin1String("shield") || name == QLatin1String("shield-x")
               || name == QLatin1String("trust")) {
        QPainterPath sh;
        sh.moveTo(12, 2.5);
        sh.lineTo(19.5, 5.3);
        sh.lineTo(19.5, 11.7);
        sh.quadTo(19.5, 17.0, 12, 21.5);
        sh.quadTo(4.5, 17.0, 4.5, 11.7);
        sh.lineTo(4.5, 5.3);
        sh.closeSubpath();
        p.drawPath(sh);
        if (name == QLatin1String("shield-x")) {
            L(9.7, 9.9, 14.3, 14.5);
            L(14.3, 9.9, 9.7, 14.5);
        } else if (name == QLatin1String("trust")) {
            QPainterPath c;
            c.moveTo(9.0, 11.9);
            c.lineTo(11.1, 14.0);
            c.lineTo(15.2, 9.6);
            p.drawPath(c);
        }
    } else if (name == QLatin1String("activity")) {
        QPolygonF poly({{3, 12}, {7, 12}, {9.5, 5}, {13.5, 19}, {16, 12}, {21, 12}});
        p.drawPolyline(poly);
    } else if (name == QLatin1String("sliders")) {
        L(4, 8.5, 20, 8.5);
        dot(14.5, 8.5, 2.4);
        L(4, 15.5, 20, 15.5);
        dot(8.5, 15.5, 2.4);
    } else if (name == QLatin1String("lock")) {
        QPainterPath sk;
        sk.moveTo(8.5, 10.5);
        sk.lineTo(8.5, 8.0);
        sk.cubicTo(8.5, 4.7, 15.5, 4.7, 15.5, 8.0);
        sk.lineTo(15.5, 10.5);
        p.drawPath(sk);
        p.drawRoundedRect(QRectF(6, 10.5, 12, 9.5), 2.0, 2.0);
    } else if (name == QLatin1String("power")) {
        L(12, 3, 12, 11.5);
        p.drawArc(QRectF(5, 4.5, 14, 14), 120 * 16, 300 * 16);
    } else if (name == QLatin1String("cloud")) {
        QPainterPath c;
        c.addEllipse(QPointF(9, 14.5), 3.6, 3.6);
        c.addEllipse(QPointF(15.5, 14.0), 4.2, 4.2);
        c.addEllipse(QPointF(12, 10.8), 4.2, 4.2);
        c.addRect(QRectF(5.4, 14.0, 14.3, 4.2));
        p.drawPath(c.simplified());
    } else if (name == QLatin1String("sparkles")) {
        QPainterPath st;
        st.moveTo(11, 4);
        st.quadTo(11.7, 9.5, 17, 10.5);
        st.quadTo(11.7, 11.5, 11, 17);
        st.quadTo(10.3, 11.5, 5, 10.5);
        st.quadTo(10.3, 9.5, 11, 4);
        p.drawPath(st);
        QPainterPath sm;
        sm.moveTo(18, 13);
        sm.quadTo(18.3, 14.7, 20, 15);
        sm.quadTo(18.3, 15.3, 18, 17);
        sm.quadTo(17.7, 15.3, 16, 15);
        sm.quadTo(17.7, 14.7, 18, 13);
        p.drawPath(sm);
    } else if (name == QLatin1String("settings")) {
        p.drawEllipse(QPointF(12, 12), 6.0, 6.0);
        p.drawEllipse(QPointF(12, 12), 2.6, 2.6);
        for (int k = 0; k < 8; ++k) {
            const qreal a = k * (M_PI / 4.0);
            const qreal cx = qCos(a), cy = qSin(a);
            L(12 + 6.0 * cx, 12 + 6.0 * cy, 12 + 9.0 * cx, 12 + 9.0 * cy);
        }
    } else if (name == QLatin1String("link")) {
        dot(7, 17, 2.2);
        dot(17, 7, 2.2);
        L(8.6, 15.4, 15.4, 8.6);
    } else if (name == QLatin1String("search")) {
        p.drawEllipse(QPointF(11, 11), 6.0, 6.0);
        L(15.4, 15.4, 20, 20);
    } else if (name == QLatin1String("close")) {
        L(6, 6, 18, 18);
        L(18, 6, 6, 18);
    } else if (name == QLatin1String("check")) {
        QPolygonF poly({{5, 12.5}, {9.5, 17}, {19, 7}});
        p.drawPolyline(poly);
    } else if (name == QLatin1String("alert")) {
        QPainterPath t;
        t.moveTo(12, 3.8);
        t.lineTo(21, 19.6);
        t.lineTo(3, 19.6);
        t.closeSubpath();
        p.drawPath(t);
        L(12, 10, 12, 14.4);
        dot(12, 17.2, 0.9);
    } else if (name == QLatin1String("refresh")) {
        p.drawArc(QRectF(4.5, 4.5, 15, 15), 65 * 16, 290 * 16);
        QPolygonF head({{15.5, 3.5}, {19.5, 5.5}, {17.6, 9.4}});
        p.drawPolyline(head);
    } else if (name == QLatin1String("clock")) {
        p.drawEllipse(QPointF(12, 12), 8.6, 8.6);
        L(12, 7.5, 12, 12);
        L(12, 12, 15.5, 13.8);
    } else if (name == QLatin1String("file")) {
        QPainterPath f;
        f.moveTo(7, 3);
        f.lineTo(14, 3);
        f.lineTo(18, 7);
        f.lineTo(18, 21);
        f.lineTo(7, 21);
        f.closeSubpath();
        p.drawPath(f);
        QPainterPath fold;
        fold.moveTo(14, 3);
        fold.lineTo(14, 7);
        fold.lineTo(18, 7);
        p.drawPath(fold);
    } else if (name == QLatin1String("chevron")) {
        QPolygonF poly({{9.5, 6}, {15.5, 12}, {9.5, 18}});
        p.drawPolyline(poly);
    } else if (name == QLatin1String("plus")) {
        L(12, 5, 12, 19);
        L(5, 12, 19, 12);
    } else if (name == QLatin1String("trash")) {
        L(5, 7, 19, 7);
        QPainterPath h;
        h.moveTo(9.5, 7);
        h.lineTo(9.5, 5);
        h.lineTo(14.5, 5);
        h.lineTo(14.5, 7);
        p.drawPath(h);
        QPainterPath b;
        b.moveTo(7, 7);
        b.lineTo(8, 20);
        b.lineTo(16, 20);
        b.lineTo(17, 7);
        p.drawPath(b);
    } else if (name == QLatin1String("eye")) {
        QPainterPath e;
        e.moveTo(3, 12);
        e.quadTo(12, 4.5, 21, 12);
        e.quadTo(12, 19.5, 3, 12);
        e.closeSubpath();
        p.drawPath(e);
        p.drawEllipse(QPointF(12, 12), 3.0, 3.0);
    } else if (name == QLatin1String("target")) {
        p.drawEllipse(QPointF(12, 12), 8.6, 8.6);
        p.drawEllipse(QPointF(12, 12), 4.6, 4.6);
        dot(12, 12, 1.2);
    } else if (name == QLatin1String("globe")) {
        p.drawEllipse(QPointF(12, 12), 8.6, 8.6);
        p.drawEllipse(QPointF(12, 12), 3.4, 8.6);
        L(3.4, 12, 20.6, 12);
    } else {
        // fallback: a small ring
        p.drawEllipse(QPointF(12, 12), 3.5, 3.5);
    }

    p.restore();
}
