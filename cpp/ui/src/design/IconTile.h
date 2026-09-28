#pragma once
#include "design/Icons.h"
#include "design/Theme.h"

#include <QColor>
#include <QLinearGradient>
#include <QPainter>
#include <QString>
#include <QWidget>

// The rounded glyph tile of ui::iconBadge(), painted directly so its glyph and
// colour can change at runtime (inspector headers, empty states, sheets). Same
// recipe: a diagonal tint of the colour, a matching rim, the glyph centred.
class IconTile : public QWidget
{
public:
    IconTile(const QString& icon, const QColor& color, int box, int iconPx, QWidget* parent = nullptr)
        : QWidget(parent), m_icon(icon), m_color(color), m_iconPx(iconPx)
    {
        setFixedSize(box, box);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

    void set(const QString& icon, const QColor& color)
    {
        m_icon = icon;
        m_color = color;
        update();
    }

    QString icon() const { return m_icon; }
    QColor color() const { return m_color; }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF r = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
        const qreal radius = width() * 0.3;
        QLinearGradient g(r.topLeft(), r.bottomRight());
        g.setColorAt(0.0, theme::blend(m_color, theme::surface(), 0.26));
        g.setColorAt(1.0, theme::blend(m_color, theme::surface(), 0.10));
        p.setPen(QPen(theme::blend(m_color, theme::surface(), 0.34), 1.0));
        p.setBrush(g);
        p.drawRoundedRect(r, radius, radius);
        const qreal s = m_iconPx;
        AppIcon::draw(p, m_icon, QRectF((width() - s) / 2.0, (height() - s) / 2.0, s, s), m_color,
                      qBound<qreal>(1.4, s * 0.09, 2.4));
    }

private:
    QString m_icon;
    QColor m_color;
    int m_iconPx;
};
