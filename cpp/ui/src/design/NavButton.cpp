#include "design/NavButton.h"
#include "design/Icons.h"
#include "design/Theme.h"

#include <QEnterEvent>
#include <QFocusEvent>
#include <QLinearGradient>
#include <QPainter>
#include <QVariantAnimation>

namespace {
// How much of the page hue an idle glyph carries: enough to find a page by its
// colour, little enough that the rail stays a quiet stone surface.
constexpr qreal kIdleTint = 0.60;
} // namespace

NavButton::NavButton(const QString& iconName, const QString& text, QWidget* parent)
    : QAbstractButton(parent), m_icon(iconName), m_badgeColor(theme::danger()), m_identity(theme::accent())
{
    setText(text);
    setCheckable(true);
    setCursor(Qt::PointingHandCursor);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    syncAccessible();

    m_anim = new QVariantAnimation(this);
    m_anim->setDuration(120);
    m_anim->setEasingCurve(QEasingCurve::OutCubic);
    connect(m_anim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
        m_hover = v.toReal();
        update();
    });
}

QSize NavButton::sizeHint() const { return m_compact ? QSize(44, 36) : QSize(200, 35); }

void NavButton::setCompact(bool compact)
{
    if (compact == m_compact)
        return;
    m_compact = compact;
    setToolTip(compact ? text() : QString());
    updateGeometry();
    update();
}

void NavButton::setBadge(int count, const QColor& color)
{
    count = qMax(0, count);
    if (color.isValid())
        m_badgeColor = color;
    if (count == m_badge)
        return;
    m_badge = count;
    syncAccessible();
    update();
}

void NavButton::setIdentity(const QColor& hue)
{
    m_identity = hue.isValid() ? hue : theme::accent();
    update();
}

void NavButton::syncAccessible()
{
    setAccessibleName(m_badge > 0 ? QString::fromUtf8("%1,%2 条未读").arg(text()).arg(m_badge) : text());
}

void NavButton::fadeHover(qreal to)
{
    m_anim->stop();
    m_anim->setStartValue(m_hover);
    m_anim->setEndValue(to);
    m_anim->start();
}

void NavButton::enterEvent(QEnterEvent*) { fadeHover(1.0); }
void NavButton::leaveEvent(QEvent*)      { fadeHover(0.0); }

void NavButton::focusInEvent(QFocusEvent* e)
{
    m_keyboardFocus = e->reason() == Qt::TabFocusReason || e->reason() == Qt::BacktabFocusReason;
    QAbstractButton::focusInEvent(e);
    update();
}

void NavButton::focusOutEvent(QFocusEvent* e)
{
    m_keyboardFocus = false;
    QAbstractButton::focusOutEvent(e);
    update();
}

void NavButton::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    const QRectF r = QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5);
    const bool active = isChecked();
    constexpr qreal radius = 10.0;
    const QColor hue = m_identity;

    if (active) {
        // A wash in the page's hue that fades out to the right, plus a whisper of a rim.
        QLinearGradient wash(r.topLeft(), r.topRight());
        wash.setColorAt(0.0, theme::tint(hue, 0.22));
        wash.setColorAt(1.0, theme::tint(hue, m_compact ? 0.12 : 0.04));
        p.setPen(QPen(theme::tint(hue, 0.20), 1.0));
        p.setBrush(wash);
        p.drawRoundedRect(r, radius, radius);

        // Indicator bar: the brass inlay (brass marks place, never state).
        const QRectF bar(r.left() + 1.0, r.center().y() - 9.0, 3.0, 18.0);
        QLinearGradient ig(bar.topLeft(), bar.bottomLeft());
        ig.setColorAt(0.0, theme::blend(theme::accentInk(), theme::brass(), 0.35));
        ig.setColorAt(1.0, theme::brass());
        p.setPen(Qt::NoPen);
        p.setBrush(ig);
        p.drawRoundedRect(bar, 1.5, 1.5);
    } else if (m_hover > 0.001) {
        p.setPen(Qt::NoPen);
        p.setBrush(theme::tint(theme::textPrimary(), 0.05 * m_hover));
        p.drawRoundedRect(r, radius, radius);
    }

    if (m_keyboardFocus && hasFocus()) {
        p.setPen(QPen(theme::accent(), 1.5));
        p.setBrush(Qt::NoBrush);
        p.drawRoundedRect(r.adjusted(0.5, 0.5, -0.5, -0.5), radius, radius);
    }

    // Idle glyphs carry a trace of the page hue; hover and the active item light
    // it up to the hue's pale highlight (for jade: exactly accentSoft).
    const QColor lit = hue == theme::accent() ? theme::accentSoft() : theme::soft(hue);
    const QColor idle = theme::blend(hue, theme::textMuted(), kIdleTint);
    const QColor glyph = active ? lit : theme::blend(lit, idle, m_hover);
    const QRectF iconRect = m_compact ? QRectF(r.center().x() - 9, r.center().y() - 9, 18, 18)
                                      : QRectF(r.left() + 14, r.center().y() - 9, 18, 18);
    AppIcon::draw(p, m_icon, iconRect, glyph, active ? 1.8 : 1.6);

    // Badge text: counts above 99 read "99+".
    const QString badgeText = m_badge > 99 ? QStringLiteral("99+") : QString::number(m_badge);
    QFont bf = font();
    bf.setPointSizeF(m_compact ? 7.5 : 8.0);
    bf.setWeight(QFont::Bold);
    const QFontMetricsF bfm(bf);

    if (m_compact) {
        if (m_badge > 0) {
            const qreal bw = qMax<qreal>(15.0, bfm.horizontalAdvance(badgeText) + 8);
            const QRectF b(iconRect.right() - 5, iconRect.top() - 7, bw, 15);
            p.setPen(QPen(theme::bgSidebar(), 2.0));
            p.setBrush(m_badgeColor);
            p.drawRoundedRect(b, 7.5, 7.5);
            p.setFont(bf);
            p.setPen(theme::accentInk());
            p.drawText(b, Qt::AlignCenter, badgeText);
        }
        return;
    }

    qreal textRight = r.right() - 8;
    if (m_badge > 0) {
        const qreal bw = qMax<qreal>(20.0, bfm.horizontalAdvance(badgeText) + 12);
        const QRectF b(r.right() - 8 - bw, r.center().y() - 9, bw, 18);
        p.setPen(QPen(theme::blend(m_badgeColor, theme::bgSidebar(), 0.45), 1.0));
        p.setBrush(theme::blend(m_badgeColor, theme::bgSidebar(), 0.22));
        p.drawRoundedRect(b, 9, 9);
        p.setFont(bf);
        p.setPen(theme::blend(m_badgeColor, theme::textPrimary(), 0.35));
        p.drawText(b, Qt::AlignCenter, badgeText);
        textRight = b.left() - 6;
    }

    QFont f = font();
    f.setPointSizeF(10.0);
    f.setWeight(active ? QFont::DemiBold : QFont::Normal);
    p.setFont(f);
    p.setPen(active ? theme::textPrimary()
                    : theme::blend(theme::textPrimary(), theme::textSecondary(), m_hover));
    const QRectF tr(r.left() + 44, r.top(), qMax<qreal>(0, textRight - (r.left() + 44)), r.height());
    p.drawText(tr, Qt::AlignVCenter | Qt::AlignLeft,
               QFontMetricsF(f).elidedText(text(), Qt::ElideRight, tr.width()));
}
