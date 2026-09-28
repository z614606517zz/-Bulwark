#include "design/FilterChip.h"
#include "design/Icons.h"
#include "design/Theme.h"

#include <QAction>
#include <QActionGroup>
#include <QEnterEvent>
#include <QFocusEvent>
#include <QKeyEvent>
#include <QMenu>
#include <QPainter>

namespace {
constexpr int kH = 34;
constexpr int kPadL = 14;
constexpr int kChevron = 12;
constexpr int kGap = 6;
constexpr int kPadR = 11;
} // namespace

FilterChip::FilterChip(const QString& label, QWidget* parent)
    : QAbstractButton(parent), m_label(label)
{
    setCursor(Qt::PointingHandCursor);
    setFocusPolicy(Qt::StrongFocus);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    connect(this, &QAbstractButton::clicked, this, &FilterChip::openMenu);
    syncAccessible();
}

void FilterChip::addOption(const QString& text, const QVariant& value)
{
    m_options.append({text, value});
    syncAccessible();
    updateGeometry();
}

void FilterChip::clearOptions()
{
    m_options.clear();
    m_index = 0;
    syncAccessible();
    updateGeometry();
    update();
}

QVariant FilterChip::currentData() const
{
    return (m_index >= 0 && m_index < m_options.size()) ? m_options[m_index].second : QVariant();
}

QString FilterChip::currentText() const
{
    return (m_index >= 0 && m_index < m_options.size()) ? m_options[m_index].first : QString();
}

void FilterChip::setCurrentIndex(int index)
{
    if (index < 0 || index >= m_options.size() || index == m_index)
        return;
    m_index = index;
    syncAccessible();
    updateGeometry();
    update();
    emit currentChanged(index);
}

QString FilterChip::shownText() const
{
    return isActive() ? QStringLiteral("%1 · %2").arg(m_label, currentText()) : m_label;
}

QSize FilterChip::sizeHint() const
{
    QFont f = font();
    f.setPointSizeF(9.5);
    f.setWeight(isActive() ? QFont::DemiBold : QFont::Medium);
    const int tw = QFontMetrics(f).horizontalAdvance(shownText());
    return {kPadL + tw + kGap + kChevron + kPadR, kH};
}

void FilterChip::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const QRectF r = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
    const qreal radius = r.height() / 2.0;
    const bool active = isActive();

    QColor fill = Qt::transparent;
    QColor rim = theme::borderStrong();
    if (active) {
        fill = theme::blend(theme::accent(), theme::surface(), m_hover ? 0.20 : 0.14);
        rim = theme::blend(theme::accent(), theme::surface(), 0.50);
    } else if (m_hover) {
        fill = theme::tint(theme::textPrimary(), 0.045);
        rim = theme::blend(theme::textPrimary(), theme::borderStrong(), 0.14);
    }
    if (m_keyboardFocus && hasFocus())
        rim = theme::accent();
    p.setPen(QPen(rim, m_keyboardFocus && hasFocus() ? 1.5 : 1.0));
    p.setBrush(fill);
    p.drawRoundedRect(r, radius, radius);

    QFont f = font();
    f.setPointSizeF(9.5);
    f.setWeight(active ? QFont::DemiBold : QFont::Medium);
    p.setFont(f);
    const QColor text = !isEnabled() ? theme::textDisabled()
                        : active     ? theme::textPrimary()
                                     : theme::textSecondary();
    p.setPen(text);
    const QRectF tr(kPadL, 0, width() - kPadL - kGap - kChevron - kPadR, height());
    p.drawText(tr, Qt::AlignVCenter | Qt::AlignLeft,
               QFontMetrics(f).elidedText(shownText(), Qt::ElideRight, int(tr.width())));
    AppIcon::draw(p, QStringLiteral("chevron-down"),
                  QRectF(width() - kPadR - kChevron, (height() - kChevron) / 2.0, kChevron, kChevron),
                  active ? theme::accentSoft() : theme::textMuted(), 1.6);
}

void FilterChip::enterEvent(QEnterEvent* e)
{
    m_hover = true;
    update();
    QAbstractButton::enterEvent(e);
}

void FilterChip::leaveEvent(QEvent* e)
{
    m_hover = false;
    update();
    QAbstractButton::leaveEvent(e);
}

void FilterChip::focusInEvent(QFocusEvent* e)
{
    m_keyboardFocus = e->reason() == Qt::TabFocusReason || e->reason() == Qt::BacktabFocusReason;
    QAbstractButton::focusInEvent(e);
    update();
}

void FilterChip::focusOutEvent(QFocusEvent* e)
{
    m_keyboardFocus = false;
    QAbstractButton::focusOutEvent(e);
    update();
}

void FilterChip::keyPressEvent(QKeyEvent* e)
{
    if (e->key() == Qt::Key_Return || e->key() == Qt::Key_Enter || e->key() == Qt::Key_Down) {
        openMenu();
        return;
    }
    QAbstractButton::keyPressEvent(e);
}

void FilterChip::openMenu()
{
    if (m_options.isEmpty())
        return;
    QMenu menu(this);
    menu.setAccessibleName(m_label);
    auto* group = new QActionGroup(&menu);
    group->setExclusive(true);
    QList<QAction*> acts;
    for (int i = 0; i < m_options.size(); ++i) {
        QAction* a = menu.addAction(m_options[i].first);
        a->setCheckable(true);
        a->setChecked(i == m_index);
        group->addAction(a);
        acts.append(a);
        if (i == 0 && m_options.size() > 1)
            menu.addSeparator();
    }
    if (m_index >= 0 && m_index < acts.size())
        menu.setActiveAction(acts[m_index]);
    const QAction* chosen = menu.exec(mapToGlobal(QPoint(0, height() + 4)));
    const int idx = int(acts.indexOf(const_cast<QAction*>(chosen)));
    if (idx >= 0)
        setCurrentIndex(idx);
}

void FilterChip::syncAccessible()
{
    setAccessibleName(QStringLiteral("%1:%2").arg(m_label, m_options.isEmpty() ? QString() : currentText()));
}
