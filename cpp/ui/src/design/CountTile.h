#pragma once
#include "design/Theme.h"

#include <QAbstractButton>
#include <QColor>
#include <QEnterEvent>
#include <QFontMetrics>
#include <QPainter>
#include <QString>

// A compact count tile — big number + label, tinted in its colour — that acts
// as a button (jump to / expand the group it counts). A zero tile is quiet and
// not clickable. Used by the cleanup report, the AI cleanup wizard and other
// summary rows.
class CountTile : public QAbstractButton
{
    Q_OBJECT
public:
    CountTile(const QString& label, int count, const QColor& color, QWidget* parent = nullptr)
        : QAbstractButton(parent), m_label(label), m_color(color)
    {
        setMinimumHeight(64);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        setCount(count);
    }

    void setCount(int count)
    {
        m_count = count;
        setEnabled(count > 0);
        setCursor(count > 0 ? Qt::PointingHandCursor : Qt::ArrowCursor);
        setFocusPolicy(count > 0 ? Qt::TabFocus : Qt::NoFocus);
        setAccessibleName(QStringLiteral("%1 %2").arg(m_label).arg(count));
        update();
    }
    int count() const { return m_count; }

    QSize sizeHint() const override { return {120, 64}; }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF r = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
        const bool live = m_count > 0;
        const bool on = isCheckable() && isChecked();
        const QColor c = live ? m_color : theme::textMuted();
        const qreal rimA = live ? (on ? 0.7 : (m_hover ? 0.5 : 0.32)) : 0.18;
        p.setPen(QPen(hasFocus() ? theme::accent() : theme::blend(c, theme::surface(), rimA),
                      hasFocus() || on ? 1.5 : 1.0));
        p.setBrush(theme::blend(c, theme::field(), live ? (on || m_hover ? 0.16 : 0.10) : 0.03));
        p.drawRoundedRect(r, 12, 12);
        QFont nf = font();
        nf.setPointSizeF(17);
        nf.setWeight(QFont::Bold);
        p.setFont(nf);
        p.setPen(live ? c : theme::textMuted());
        p.drawText(QRectF(r.left() + 14, r.top() + 6, r.width() - 28, 32), Qt::AlignLeft | Qt::AlignVCenter,
                   QString::number(m_count));
        QFont lf = font();
        lf.setPointSizeF(9);
        p.setFont(lf);
        p.setPen(live ? theme::textSecondary() : theme::textMuted());
        p.drawText(QRectF(r.left() + 14, r.top() + 36, r.width() - 20, 20), Qt::AlignLeft | Qt::AlignVCenter,
                   QFontMetrics(lf).elidedText(m_label, Qt::ElideRight, int(r.width() - 20)));
    }
    void enterEvent(QEnterEvent* e) override { m_hover = true; update(); QAbstractButton::enterEvent(e); }
    void leaveEvent(QEvent* e) override { m_hover = false; update(); QAbstractButton::leaveEvent(e); }

private:
    QString m_label;
    int m_count = 0;
    QColor m_color;
    bool m_hover = false;
};
