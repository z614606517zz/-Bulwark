#pragma once
#include "design/Icons.h"
#include "design/Motion.h"
#include "design/Theme.h"

#include <QColor>
#include <QLinearGradient>
#include <QPainter>
#include <QString>
#include <QVariantAnimation>
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

    // A short spring as the tile arrives (toast notifications): the plate grows
    // into place while the glyph overshoots a hair before settling. Both stay
    // inside the tile's own box, so nothing is clipped and the resting look is
    // untouched. Does nothing when motion is off.
    void pop()
    {
        if (!motion::enabled())
            return;
        if (!m_pop) {
            m_pop = new QVariantAnimation(this);
            m_pop->setStartValue(0.0);
            m_pop->setEndValue(1.0);
            m_pop->setDuration(340);
            QObject::connect(m_pop, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
                m_t = v.toReal();
                update();
            });
        }
        m_pop->stop();
        m_t = 0.0;
        m_pop->start();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        // While popping: the plate eases up from 84 %, the glyph springs past its
        // size and settles (motion::outBack). At rest both are exactly 1.
        const bool popping = m_pop && m_pop->state() == QAbstractAnimation::Running;
        const qreal plate = popping ? 0.84 + 0.16 * motion::outCubic(m_t) : 1.0;
        const qreal glyph = popping ? 0.70 + 0.30 * motion::outBack(m_t) : 1.0;

        const qreal inset = width() * (1.0 - plate) / 2.0;
        const QRectF r = QRectF(rect()).adjusted(inset + 0.5, inset + 0.5, -inset - 0.5, -inset - 0.5);
        const qreal radius = r.width() * 0.3;
        QLinearGradient g(r.topLeft(), r.bottomRight());
        g.setColorAt(0.0, theme::blend(m_color, theme::surface(), 0.26));
        g.setColorAt(1.0, theme::blend(m_color, theme::surface(), 0.10));
        p.setPen(QPen(theme::blend(m_color, theme::surface(), 0.34), 1.0));
        p.setBrush(g);
        p.drawRoundedRect(r, radius, radius);
        const qreal s = m_iconPx * glyph;
        AppIcon::draw(p, m_icon, QRectF((width() - s) / 2.0, (height() - s) / 2.0, s, s), m_color,
                      qBound<qreal>(1.4, m_iconPx * 0.09, 2.4));
    }

private:
    QString m_icon;
    QColor m_color;
    int m_iconPx;
    QVariantAnimation* m_pop = nullptr;
    qreal m_t = 0.0;
};
