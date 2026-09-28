#include "design/Icons.h"
#include "design/Theme.h"

#include <QGuiApplication>
#include <QList>
#include <QPainter>
#include <QPainterPath>
#include <QPolygonF>
#include <QtMath>

#include <initializer_list>

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
    // The stroke grows gently with the glyph so big badge icons don't look
    // hairline-thin next to 16px toolbar icons: ~1.7px at 20px, capped at 2.6px.
    draw(p, m_name, r, m_color, qBound<qreal>(1.4, side * 0.085, 2.6));
}

QPixmap AppIcon::pixmap(const QString& name, const QColor& color, int px, qreal penWidth)
{
    // Render at (at least) 2x so the icon stays crisp on every screen scale.
    const qreal dpr = qMax<qreal>(2.0, qGuiApp ? qGuiApp->devicePixelRatio() : 2.0);
    QPixmap pm(qCeil(px * dpr), qCeil(px * dpr));
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

QPainterPath AppIcon::shieldPath()
{
    // A heater shield with a gently curved crown, on the 24-grid.
    QPainterPath s;
    s.moveTo(12.0, 2.6);
    s.cubicTo(14.4, 4.3, 16.9, 5.2, 19.5, 5.4);
    s.lineTo(19.5, 11.2);
    s.cubicTo(19.5, 16.1, 16.3, 19.5, 12.0, 21.4);
    s.cubicTo(7.7, 19.5, 4.5, 16.1, 4.5, 11.2);
    s.lineTo(4.5, 5.4);
    s.cubicTo(7.1, 5.2, 9.6, 4.3, 12.0, 2.6);
    s.closeSubpath();
    return s;
}

void AppIcon::drawBadge(QPainter& p, const QRectF& rect)
{
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);

    const qreal side = qMin(rect.width(), rect.height());
    const QRectF sq(rect.center().x() - side / 2.0, rect.center().y() - side / 2.0, side, side);
    const qreal radius = side * 0.27;
    QPainterPath body;
    body.addRoundedRect(sq, radius, radius);

    // Jade body falling off into its own shadow (one hue, not a hue-shifting gradient).
    QLinearGradient g(sq.topLeft(), sq.bottomRight());
    g.setColorAt(0.0, QColor(0x2F, 0xB8, 0x98));
    g.setColorAt(1.0, QColor(0x0C, 0x62, 0x55));
    p.fillPath(body, g);

    // Sheen: light falling across the upper half gives the mark some volume.
    QLinearGradient sheen(sq.topLeft(), QPointF(sq.left(), sq.top() + side * 0.62));
    sheen.setColorAt(0.0, QColor(255, 255, 255, 52));
    sheen.setColorAt(1.0, QColor(255, 255, 255, 0));
    p.fillPath(body, sheen);

    // Brass bezel — only where it can be drawn cleanly (it would blur into mud at 16–24 px).
    if (side >= 28.0) {
        QPainterPath bezel;
        const qreal inset = side * 0.028;
        bezel.addRoundedRect(sq.adjusted(inset, inset, -inset, -inset), radius - inset, radius - inset);
        QLinearGradient bz(sq.topLeft(), sq.bottomLeft());
        bz.setColorAt(0.0, QColor(0xE2, 0xC2, 0x8A, 230));
        bz.setColorAt(1.0, QColor(0x8E, 0x6B, 0x3B, 200));
        p.setPen(QPen(QBrush(bz), side * 0.035));
        p.setBrush(Qt::NoBrush);
        p.drawPath(bezel);
    }

    // A solid ivory shield with the check "cut" into it in the badge colour.
    const qreal gs = side * 0.66 / 24.0;
    p.translate(sq.center().x() - 12.0 * gs, sq.center().y() - 12.0 * gs + side * 0.01);
    p.scale(gs, gs);
    p.setPen(Qt::NoPen);
    p.setBrush(QColor(0xFF, 0xFA, 0xF0, 248));
    p.drawPath(shieldPath());

    QPen check(QColor(0x12, 0x7A, 0x69), 2.6); // grid units
    check.setCapStyle(Qt::RoundCap);
    check.setJoinStyle(Qt::RoundJoin);
    p.setPen(check);
    p.setBrush(Qt::NoBrush);
    p.drawPolyline(QPolygonF(QList<QPointF>{{8.4, 12.1}, {11.0, 14.6}, {15.8, 9.6}}));
    p.restore();
}

QIcon AppIcon::appBadge()
{
    QIcon out;
    for (int px : {16, 20, 24, 32, 40, 48, 64, 128, 256}) {
        QPixmap pm(px, px);
        pm.fill(Qt::transparent);
        QPainter p(&pm);
        const qreal m = px * 0.03; // breathing room so the anti-aliased rim isn't clipped
        drawBadge(p, QRectF(m, m, px - 2 * m, px - 2 * m));
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

    auto L = [&](qreal x1, qreal y1, qreal x2, qreal y2) { p.drawLine(QLineF(x1, y1, x2, y2)); };
    auto poly = [&](std::initializer_list<QPointF> pts) { p.drawPolyline(QPolygonF(QList<QPointF>(pts))); };
    auto ring = [&](qreal x, qreal y, qreal r) { p.drawEllipse(QPointF(x, y), r, r); };
    auto rrect = [&](qreal x, qreal y, qreal w, qreal h, qreal r) {
        p.drawRoundedRect(QRectF(x, y, w, h), r, r);
    };
    auto dot = [&](qreal x, qreal y, qreal r) {
        p.save();
        p.setPen(Qt::NoPen);
        p.setBrush(color);
        p.drawEllipse(QPointF(x, y), r, r);
        p.restore();
    };
    const auto is = [&name](const char* key) { return name == QLatin1String(key); };

    if (is("dashboard")) {
        rrect(3.0, 3.0, 7.5, 8.5, 1.8);
        rrect(13.5, 3.0, 7.5, 5.0, 1.8);
        rrect(13.5, 11.0, 7.5, 10.0, 1.8);
        rrect(3.0, 14.5, 7.5, 6.5, 1.8);
    } else if (is("shield") || is("shield-x") || is("trust") || is("shield-check")
               || is("shield-alert")) {
        p.drawPath(shieldPath());
        if (is("shield-x")) {
            L(9.6, 9.4, 14.4, 14.2);
            L(14.4, 9.4, 9.6, 14.2);
        } else if (is("trust") || is("shield-check")) {
            poly({{8.8, 12.0}, {11.1, 14.3}, {15.4, 9.8}});
        } else if (is("shield-alert")) {
            L(12.0, 7.9, 12.0, 12.2);
            dot(12.0, 15.4, 1.15);
        }
    } else if (is("activity")) {
        poly({{2.5, 12.0}, {6.2, 12.0}, {9.2, 4.5}, {14.8, 19.5}, {17.8, 12.0}, {21.5, 12.0}});
    } else if (is("clock")) {
        ring(12.0, 12.0, 9.2);
        poly({{12.0, 7.2}, {12.0, 12.0}, {15.4, 13.9}});
    } else if (is("target")) {
        ring(12.0, 12.0, 9.2);
        ring(12.0, 12.0, 5.2);
        dot(12.0, 12.0, 1.6);
    } else if (is("sliders")) {
        struct Row { qreal y, knob; };
        for (const Row r : {Row{6.5, 15.5}, Row{12.0, 8.5}, Row{17.5, 13.5}}) {
            L(3.5, r.y, r.knob - 2.6, r.y);
            L(r.knob + 2.6, r.y, 20.5, r.y);
            ring(r.knob, r.y, 2.2);
        }
    } else if (is("lock")) {
        rrect(4.5, 10.5, 15.0, 10.5, 2.6);
        QPainterPath shackle;
        shackle.moveTo(8.0, 10.5);
        shackle.lineTo(8.0, 7.5);
        shackle.cubicTo(8.0, 2.2, 16.0, 2.2, 16.0, 7.5);
        shackle.lineTo(16.0, 10.5);
        p.drawPath(shackle);
        dot(12.0, 15.7, 1.25);
    } else if (is("power")) {
        L(12.0, 2.8, 12.0, 11.0);
        p.drawArc(QRectF(3.8, 4.6, 16.4, 16.4), 130 * 16, 280 * 16);
    } else if (is("cloud")) {
        QPainterPath c;
        c.setFillRule(Qt::WindingFill); // union of the puffs, not their XOR
        c.addEllipse(QPointF(7.6, 14.6), 4.0, 4.0);
        c.addEllipse(QPointF(12.4, 11.2), 5.4, 5.4);
        c.addEllipse(QPointF(17.0, 14.4), 4.2, 4.2);
        c.addRect(QRectF(7.6, 14.4, 9.4, 4.2));
        p.drawPath(c.simplified());
    } else if (is("link")) {
        p.save();
        p.translate(12.0, 12.0);
        p.rotate(-45.0);
        p.drawRoundedRect(QRectF(-9.2, -3.3, 10.6, 6.6), 3.3, 3.3);
        p.drawRoundedRect(QRectF(-1.4, -3.3, 10.6, 6.6), 3.3, 3.3);
        p.restore();
    } else if (is("sparkles")) {
        QPainterPath star;
        star.moveTo(10.0, 3.5);
        star.quadTo(10.8, 9.2, 16.5, 10.0);
        star.quadTo(10.8, 10.8, 10.0, 16.5);
        star.quadTo(9.2, 10.8, 3.5, 10.0);
        star.quadTo(9.2, 9.2, 10.0, 3.5);
        p.drawPath(star);
        QPainterPath small;
        small.moveTo(18.0, 13.5);
        small.quadTo(18.4, 15.6, 20.5, 16.0);
        small.quadTo(18.4, 16.4, 18.0, 18.5);
        small.quadTo(17.6, 16.4, 15.5, 16.0);
        small.quadTo(17.6, 15.6, 18.0, 13.5);
        p.drawPath(small);
        dot(18.6, 4.9, 1.1);
    } else if (is("settings")) {
        // Eight-tooth gear: valley radius 7.3, tooth radius 9.6, soft joins.
        auto polar = [](qreal radius, qreal deg) {
            const qreal a = qDegreesToRadians(deg);
            return QPointF(12.0 + radius * qCos(a), 12.0 + radius * qSin(a));
        };
        QPolygonF gear;
        for (int k = 0; k < 8; ++k) {
            const qreal c = k * 45.0;
            gear << polar(7.3, c - 13.0) << polar(9.6, c - 8.5)
                 << polar(9.6, c + 8.5) << polar(7.3, c + 13.0);
        }
        gear << gear.first();
        p.drawPolygon(gear);
        ring(12.0, 12.0, 3.1);
    } else if (is("search")) {
        ring(10.8, 10.8, 6.8);
        L(15.8, 15.8, 20.5, 20.5);
    } else if (is("close")) {
        L(6.2, 6.2, 17.8, 17.8);
        L(17.8, 6.2, 6.2, 17.8);
    } else if (is("check")) {
        poly({{4.8, 12.6}, {9.6, 17.2}, {19.2, 7.2}});
    } else if (is("alert")) {
        QPainterPath t;
        t.moveTo(12.0, 3.6);
        t.lineTo(21.4, 19.8);
        t.lineTo(2.6, 19.8);
        t.closeSubpath();
        p.drawPath(t);
        L(12.0, 9.6, 12.0, 13.8);
        dot(12.0, 16.8, 1.15);
    } else if (is("info")) {
        ring(12.0, 12.0, 9.2);
        L(12.0, 11.0, 12.0, 16.4);
        dot(12.0, 7.7, 1.15);
    } else if (is("refresh")) {
        QPainterPath a;
        a.moveTo(20.5, 12.0);
        a.arcTo(QRectF(3.5, 3.5, 17.0, 17.0), 0.0, -270.0); // clockwise round to the top
        a.cubicTo(14.4, 3.5, 16.7, 4.5, 18.4, 6.2);
        a.lineTo(20.5, 8.3);
        p.drawPath(a);
        poly({{20.5, 3.6}, {20.5, 8.3}, {15.8, 8.3}});
    } else if (is("refresh-cw")) {
        QPainterPath a;
        a.moveTo(3.5, 12.0);
        a.arcTo(QRectF(3.5, 3.5, 17.0, 17.0), 180.0, -90.0);
        a.cubicTo(14.4, 3.5, 16.7, 4.5, 18.4, 6.2);
        a.lineTo(20.5, 8.3);
        QPainterPath b;
        b.moveTo(20.5, 12.0);
        b.arcTo(QRectF(3.5, 3.5, 17.0, 17.0), 0.0, -90.0);
        b.cubicTo(9.6, 20.5, 7.3, 19.5, 5.6, 17.8);
        b.lineTo(3.5, 15.7);
        p.drawPath(a);
        p.drawPath(b);
        poly({{20.5, 3.6}, {20.5, 8.3}, {15.8, 8.3}});
        poly({{8.2, 15.7}, {3.5, 15.7}, {3.5, 20.4}});
    } else if (is("file")) {
        QPainterPath f;
        f.moveTo(14.5, 2.8);
        f.lineTo(7.2, 2.8);
        f.quadTo(5.2, 2.8, 5.2, 4.8);
        f.lineTo(5.2, 19.2);
        f.quadTo(5.2, 21.2, 7.2, 21.2);
        f.lineTo(16.8, 21.2);
        f.quadTo(18.8, 21.2, 18.8, 19.2);
        f.lineTo(18.8, 7.1);
        f.closeSubpath();
        p.drawPath(f);
        poly({{14.5, 2.8}, {14.5, 7.1}, {18.8, 7.1}});
    } else if (is("chevron") || is("chevron-right")) {
        poly({{9.5, 6.0}, {15.5, 12.0}, {9.5, 18.0}});
    } else if (is("chevron-down")) {
        poly({{6.0, 9.5}, {12.0, 15.5}, {18.0, 9.5}});
    } else if (is("chevron-up")) {
        poly({{6.0, 14.5}, {12.0, 8.5}, {18.0, 14.5}});
    } else if (is("arrow-right")) {
        L(4.5, 12.0, 19.5, 12.0);
        poly({{13.5, 6.0}, {19.5, 12.0}, {13.5, 18.0}});
    } else if (is("plus")) {
        L(12.0, 5.0, 12.0, 19.0);
        L(5.0, 12.0, 19.0, 12.0);
    } else if (is("minus")) {
        L(5.0, 12.0, 19.0, 12.0);
    } else if (is("trash")) {
        L(3.8, 6.4, 20.2, 6.4);
        QPainterPath lid;
        lid.moveTo(8.8, 6.4);
        lid.lineTo(8.8, 4.6);
        lid.quadTo(8.8, 3.0, 10.4, 3.0);
        lid.lineTo(13.6, 3.0);
        lid.quadTo(15.2, 3.0, 15.2, 4.6);
        lid.lineTo(15.2, 6.4);
        p.drawPath(lid);
        QPainterPath bin;
        bin.moveTo(6.2, 6.4);
        bin.lineTo(7.1, 19.4);
        bin.quadTo(7.3, 21.0, 8.9, 21.0);
        bin.lineTo(15.1, 21.0);
        bin.quadTo(16.7, 21.0, 16.9, 19.4);
        bin.lineTo(17.8, 6.4);
        p.drawPath(bin);
        L(10.2, 10.6, 10.2, 16.8);
        L(13.8, 10.6, 13.8, 16.8);
    } else if (is("eye")) {
        QPainterPath e;
        e.moveTo(2.4, 12.0);
        e.cubicTo(5.6, 6.2, 18.4, 6.2, 21.6, 12.0);
        e.cubicTo(18.4, 17.8, 5.6, 17.8, 2.4, 12.0);
        e.closeSubpath();
        p.drawPath(e);
        ring(12.0, 12.0, 3.0);
    } else if (is("globe")) {
        ring(12.0, 12.0, 9.2);
        p.drawEllipse(QPointF(12.0, 12.0), 3.9, 9.2);
        L(2.8, 12.0, 21.2, 12.0);
    } else if (is("cpu")) {
        rrect(5.0, 5.0, 14.0, 14.0, 2.4);
        rrect(9.0, 9.0, 6.0, 6.0, 1.2);
        for (const qreal k : {9.0, 15.0}) {
            L(k, 2.2, k, 5.0);
            L(k, 19.0, k, 21.8);
            L(2.2, k, 5.0, k);
            L(19.0, k, 21.8, k);
        }
    } else if (is("server")) {
        rrect(3.5, 3.5, 17.0, 7.0, 2.0);
        rrect(3.5, 13.5, 17.0, 7.0, 2.0);
        dot(7.4, 7.0, 1.1);
        dot(7.4, 17.0, 1.1);
    } else if (is("layers")) {
        QPainterPath top;
        top.moveTo(12.0, 2.8);
        top.lineTo(21.2, 7.6);
        top.lineTo(12.0, 12.4);
        top.lineTo(2.8, 7.6);
        top.closeSubpath();
        p.drawPath(top);
        poly({{2.8, 12.0}, {12.0, 16.8}, {21.2, 12.0}});
        poly({{2.8, 16.4}, {12.0, 21.2}, {21.2, 16.4}});
    } else if (is("zap")) {
        QPainterPath z;
        z.moveTo(13.2, 2.6);
        z.lineTo(4.0, 13.6);
        z.lineTo(12.0, 13.6);
        z.lineTo(10.8, 21.4);
        z.lineTo(20.0, 10.4);
        z.lineTo(12.0, 10.4);
        z.closeSubpath();
        p.drawPath(z);
    } else if (is("more")) {
        dot(5.6, 12.0, 1.6);
        dot(12.0, 12.0, 1.6);
        dot(18.4, 12.0, 1.6);
    } else if (is("copy")) {
        QPainterPath back;
        back.moveTo(5.5, 15.5);
        back.quadTo(3.5, 15.5, 3.5, 13.5);
        back.lineTo(3.5, 5.5);
        back.quadTo(3.5, 3.5, 5.5, 3.5);
        back.lineTo(13.5, 3.5);
        back.quadTo(15.5, 3.5, 15.5, 5.5);
        p.drawPath(back);
        rrect(8.5, 8.5, 12.0, 12.0, 2.0);
    } else if (is("folder")) {
        QPainterPath f;
        f.moveTo(4.6, 4.0);
        f.lineTo(9.0, 4.0);
        f.lineTo(11.0, 6.6);
        f.lineTo(19.4, 6.6);
        f.quadTo(21.0, 6.6, 21.0, 8.2);
        f.lineTo(21.0, 18.4);
        f.quadTo(21.0, 20.0, 19.4, 20.0);
        f.lineTo(4.6, 20.0);
        f.quadTo(3.0, 20.0, 3.0, 18.4);
        f.lineTo(3.0, 5.6);
        f.quadTo(3.0, 4.0, 4.6, 4.0);
        f.closeSubpath();
        p.drawPath(f);
    } else if (is("upload") || is("download")) {
        QPainterPath tray;
        tray.moveTo(4.0, 15.0);
        tray.lineTo(4.0, 18.0);
        tray.quadTo(4.0, 20.0, 6.0, 20.0);
        tray.lineTo(18.0, 20.0);
        tray.quadTo(20.0, 20.0, 20.0, 18.0);
        tray.lineTo(20.0, 15.0);
        p.drawPath(tray);
        if (is("upload")) {
            L(12.0, 15.0, 12.0, 3.8);
            poly({{7.6, 8.2}, {12.0, 3.8}, {16.4, 8.2}});
        } else {
            L(12.0, 3.8, 12.0, 15.0);
            poly({{7.6, 10.6}, {12.0, 15.0}, {16.4, 10.6}});
        }
    } else if (is("pause")) {
        rrect(6.5, 5.0, 3.6, 14.0, 1.2);
        rrect(13.9, 5.0, 3.6, 14.0, 1.2);
    } else if (is("play")) {
        QPainterPath t;
        t.moveTo(8.0, 5.0);
        t.lineTo(19.0, 12.0);
        t.lineTo(8.0, 19.0);
        t.closeSubpath();
        p.drawPath(t);
    } else if (is("filter")) {
        QPainterPath f;
        f.moveTo(3.5, 4.5);
        f.lineTo(20.5, 4.5);
        f.lineTo(13.8, 12.2);
        f.lineTo(13.8, 19.5);
        f.lineTo(10.2, 17.8);
        f.lineTo(10.2, 12.2);
        f.closeSubpath();
        p.drawPath(f);
    } else if (is("external")) {
        poly({{14.5, 3.5}, {20.5, 3.5}, {20.5, 9.5}});
        L(10.5, 13.5, 20.5, 3.5);
        QPainterPath bx;
        bx.moveTo(17.5, 13.5);
        bx.lineTo(17.5, 18.5);
        bx.quadTo(17.5, 20.5, 15.5, 20.5);
        bx.lineTo(5.5, 20.5);
        bx.quadTo(3.5, 20.5, 3.5, 18.5);
        bx.lineTo(3.5, 8.5);
        bx.quadTo(3.5, 6.5, 5.5, 6.5);
        bx.lineTo(10.5, 6.5);
        p.drawPath(bx);
    } else if (is("panel-left")) {
        rrect(3.0, 4.0, 18.0, 16.0, 2.4);
        L(9.0, 4.0, 9.0, 20.0);
    } else if (is("chevron-left")) {
        poly({{14.5, 6.0}, {8.5, 12.0}, {14.5, 18.0}});
    } else if (is("chevrons-left")) {
        poly({{11.5, 6.0}, {5.5, 12.0}, {11.5, 18.0}});
        poly({{18.5, 6.0}, {12.5, 12.0}, {18.5, 18.0}});
    } else if (is("chevrons-right")) {
        poly({{5.5, 6.0}, {11.5, 12.0}, {5.5, 18.0}});
        poly({{12.5, 6.0}, {18.5, 12.0}, {12.5, 18.0}});
    } else if (is("arrow-up")) {
        L(12.0, 19.5, 12.0, 4.5);
        poly({{6.0, 10.5}, {12.0, 4.5}, {18.0, 10.5}});
    } else if (is("arrow-left")) {
        L(19.5, 12.0, 4.5, 12.0);
        poly({{10.5, 6.0}, {4.5, 12.0}, {10.5, 18.0}});
    } else if (is("check-circle")) {
        ring(12.0, 12.0, 9.2);
        poly({{8.2, 12.3}, {10.9, 14.9}, {15.9, 9.6}});
    } else if (is("x-circle")) {
        ring(12.0, 12.0, 9.2);
        L(9.2, 9.2, 14.8, 14.8);
        L(14.8, 9.2, 9.2, 14.8);
    } else if (is("bar-chart")) {
        rrect(5.0, 11.0, 3.0, 8.0, 1.0);
        rrect(10.5, 5.5, 3.0, 13.5, 1.0);
        rrect(16.0, 13.5, 3.0, 5.5, 1.0);
        L(3.5, 20.5, 20.5, 20.5);
    } else if (is("list")) {
        for (const qreal y : {6.5, 12.0, 17.5}) {
            dot(4.6, y, 1.15);
            L(8.6, y, 20.0, y);
        }
    } else if (is("tree")) {
        ring(6.0, 5.5, 2.2);
        ring(6.0, 18.5, 2.2);
        ring(18.0, 12.0, 2.2);
        L(6.0, 7.7, 6.0, 16.3);
        QPainterPath br;
        br.moveTo(6.0, 8.2);
        br.cubicTo(6.0, 11.4, 9.0, 12.0, 15.8, 12.0);
        p.drawPath(br);
    } else if (is("hash")) {
        L(9.6, 3.5, 7.6, 20.5);
        L(16.4, 3.5, 14.4, 20.5);
        L(4.2, 9.0, 20.4, 9.0);
        L(3.6, 15.0, 19.8, 15.0);
    } else if (is("terminal")) {
        rrect(2.8, 4.0, 18.4, 16.0, 2.4);
        poly({{6.8, 9.0}, {9.8, 12.0}, {6.8, 15.0}});
        L(12.0, 15.0, 17.0, 15.0);
    } else if (is("user")) {
        ring(12.0, 8.0, 4.0);
        QPainterPath sh;
        sh.moveTo(4.5, 20.5);
        sh.cubicTo(4.5, 16.6, 7.9, 14.0, 12.0, 14.0);
        sh.cubicTo(16.1, 14.0, 19.5, 16.6, 19.5, 20.5);
        p.drawPath(sh);
    } else if (is("key")) {
        ring(7.6, 16.0, 4.3);
        L(10.7, 12.9, 20.5, 3.1);
        L(15.8, 7.9, 18.6, 10.7);
        L(18.4, 5.2, 20.8, 7.6);
    } else if (is("bell")) {
        QPainterPath b;
        b.moveTo(6.0, 9.8);
        b.cubicTo(6.0, 6.2, 8.7, 3.5, 12.0, 3.5);
        b.cubicTo(15.3, 3.5, 18.0, 6.2, 18.0, 9.8);
        b.cubicTo(18.0, 15.0, 20.3, 17.0, 20.3, 17.0);
        b.lineTo(3.7, 17.0);
        b.cubicTo(3.7, 17.0, 6.0, 15.0, 6.0, 9.8);
        b.closeSubpath();
        p.drawPath(b);
        QPainterPath cl;
        cl.moveTo(10.2, 20.2);
        cl.quadTo(12.0, 21.8, 13.8, 20.2);
        p.drawPath(cl);
    } else if (is("undo")) {
        QPainterPath a;
        a.moveTo(4.5, 9.5);
        a.lineTo(14.5, 9.5);
        a.cubicTo(17.6, 9.5, 20.0, 11.9, 20.0, 15.0);
        a.cubicTo(20.0, 18.1, 17.6, 20.5, 14.5, 20.5);
        a.lineTo(11.0, 20.5);
        p.drawPath(a);
        poly({{8.8, 5.2}, {4.5, 9.5}, {8.8, 13.8}});
    } else if (is("maximize")) {
        poly({{3.5, 8.5}, {3.5, 3.5}, {8.5, 3.5}});
        poly({{15.5, 3.5}, {20.5, 3.5}, {20.5, 8.5}});
        poly({{20.5, 15.5}, {20.5, 20.5}, {15.5, 20.5}});
        poly({{8.5, 20.5}, {3.5, 20.5}, {3.5, 15.5}});
    } else if (is("minimize")) {
        poly({{8.5, 3.5}, {8.5, 8.5}, {3.5, 8.5}});
        poly({{20.5, 8.5}, {15.5, 8.5}, {15.5, 3.5}});
        poly({{15.5, 20.5}, {15.5, 15.5}, {20.5, 15.5}});
        poly({{3.5, 15.5}, {8.5, 15.5}, {8.5, 20.5}});
    } else if (is("pin")) {
        L(12.0, 16.0, 12.0, 21.0);
        QPainterPath pn;
        pn.moveTo(8.8, 3.5);
        pn.lineTo(15.2, 3.5);
        pn.lineTo(14.2, 9.5);
        pn.lineTo(17.5, 13.0);
        pn.lineTo(17.5, 16.0);
        pn.lineTo(6.5, 16.0);
        pn.lineTo(6.5, 13.0);
        pn.lineTo(9.8, 9.5);
        pn.closeSubpath();
        p.drawPath(pn);
    } else if (is("calendar")) {
        rrect(3.5, 5.0, 17.0, 15.5, 2.4);
        L(3.5, 9.8, 20.5, 9.8);
        L(8.0, 3.0, 8.0, 6.6);
        L(16.0, 3.0, 16.0, 6.6);
    } else {
        ring(12.0, 12.0, 3.5); // unknown name: visible placeholder, never blank
    }

    p.restore();
}
