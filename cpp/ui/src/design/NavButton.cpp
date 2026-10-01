#include "design/NavButton.h"
#include "design/Icons.h"
#include "design/Motion.h"
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
    m_anim->setDuration(motion::duration(120));
    m_anim->setEasingCurve(QEasingCurve::OutCubic);
    connect(m_anim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
        m_hover = v.toReal();
        update();
    });

    // Selection follows the checked state however it changes (a click, the
    // exclusive group unchecking the item being left, navigateTo()).
    m_selAnim = new QVariantAnimation(this);
    m_selAnim->setEasingCurve(QEasingCurve::OutCubic);
    connect(m_selAnim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
        m_select = v.toReal();
        update();
    });
    connect(this, &QAbstractButton::toggled, this, &NavButton::animateSelection);
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
    if (m_anim->duration() <= 0) { // animations off: straight to the end state
        m_hover = to;
        update();
        return;
    }
    m_anim->setStartValue(m_hover);
    m_anim->setEndValue(to);
    m_anim->start();
}

void NavButton::animateSelection(bool on)
{
    const qreal to = on ? 1.0 : 0.0;
    m_selAnim->stop();
    m_selecting = on;
    // Becoming active takes a little longer than letting go, so the rail never
    // shows two lit items for long. Off screen (or animations off) it just jumps.
    const int ms = motion::onScreen(this) ? motion::duration(on ? 220 : 160) : 0;
    if (ms <= 0) {
        m_select = to;
        update();
        return;
    }
    m_selAnim->setDuration(ms);
    m_selAnim->setStartValue(m_select);
    m_selAnim->setEndValue(to);
    m_selAnim->start();
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
    // How lit the item is: exactly 0 or 1 at rest (so the resting looks below are
    // the plain idle / active recipes), in between while the selection moves.
    const qreal sel = m_select;
    constexpr qreal radius = 10.0;
    const QColor hue = m_identity;

    // Hover lift — only on the part of the item that isn't lit.
    const qreal lift = m_hover * (1.0 - sel);
    if (lift > 0.001) {
        p.setPen(Qt::NoPen);
        p.setBrush(theme::tint(theme::textPrimary(), 0.05 * lift));
        p.drawRoundedRect(r, radius, radius);
    }
    if (sel > 0.001) {
        // A wash in the page's hue that fades out to the right, plus a whisper of a rim.
        QLinearGradient wash(r.topLeft(), r.topRight());
        wash.setColorAt(0.0, theme::tint(hue, 0.22 * sel));
        wash.setColorAt(1.0, theme::tint(hue, (m_compact ? 0.12 : 0.04) * sel));
        p.setPen(QPen(theme::tint(hue, 0.20 * sel), 1.0));
        p.setBrush(wash);
        p.drawRoundedRect(r, radius, radius);

        // Indicator bar: the brass inlay (brass marks place, never state). It grows
        // out of its centre when the item is chosen — overshooting a hair before it
        // settles — and shrinks back into it when the item is left.
        const qreal grow = m_selecting ? motion::outBack(sel) : sel;
        const qreal barH = 18.0 * grow;
        const QRectF bar(r.left() + 1.0, r.center().y() - barH / 2.0, 3.0, barH);
        QLinearGradient ig(bar.topLeft(), bar.bottomLeft());
        ig.setColorAt(0.0, theme::blend(theme::accentInk(), theme::brass(), 0.35));
        ig.setColorAt(1.0, theme::brass());
        p.setPen(Qt::NoPen);
        p.setBrush(ig);
        p.setOpacity(qMin<qreal>(1.0, sel * 2.0));
        p.drawRoundedRect(bar, 1.5, 1.5);
        p.setOpacity(1.0);
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
    const QColor glyph = theme::blend(lit, theme::blend(lit, idle, m_hover), sel);
    const qreal glyphPen = sel >= 1.0 ? 1.8 : (sel <= 0.0 ? 1.6 : 1.6 + 0.2 * sel);
    const QRectF iconRect = m_compact ? QRectF(r.center().x() - 9, r.center().y() - 9, 18, 18)
                                      : QRectF(r.left() + 14, r.center().y() - 9, 18, 18);
    AppIcon::draw(p, m_icon, iconRect, glyph, glyphPen);

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
    p.setPen(theme::blend(theme::textPrimary(),
                          theme::blend(theme::textPrimary(), theme::textSecondary(), m_hover), sel));
    const QRectF tr(r.left() + 44, r.top(), qMax<qreal>(0, textRight - (r.left() + 44)), r.height());
    p.drawText(tr, Qt::AlignVCenter | Qt::AlignLeft,
               QFontMetricsF(f).elidedText(text(), Qt::ElideRight, tr.width()));
}
