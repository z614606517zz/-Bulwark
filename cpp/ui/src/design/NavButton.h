#pragma once
#include <QAbstractButton>
#include <QColor>

class QVariantAnimation;

// A sidebar navigation item: glyph + label, checkable (lives in an exclusive
// QButtonGroup). Custom-painted — no child widgets. Every item wears the
// identity hue of the page it opens (design/Identity.h; jade by default):
//   idle     glyph faintly tinted with the hue, secondary label
//   hover    faint lift that fades in/out (~120 ms), glyph brightens
//   active   wash in the hue fading to the right, brass indicator bar (brass
//            marks place, whatever the hue), pale glyph in the hue. Becoming
//            active the wash fades in and the bar grows out of its centre
//            (~220 ms); the item being left fades back to idle a little faster
//   focus    keyboard focus draws an accent ring (mouse clicks don't)
//   compact  (collapsed rail) glyph only, label moves to the tooltip
//   badge    unread count: a capsule at the right end, or on the glyph's
//            shoulder when compact. Also spoken ("拦截记录,3 条未读").
class NavButton : public QAbstractButton
{
    Q_OBJECT
public:
    NavButton(const QString& iconName, const QString& text, QWidget* parent = nullptr);
    QSize sizeHint() const override;

    void setCompact(bool compact);
    bool isCompact() const { return m_compact; }

    // 0 hides the badge.
    void setBadge(int count, const QColor& color = QColor());
    int badge() const { return m_badge; }

    // The page's identity hue; invalid = jade.
    void setIdentity(const QColor& hue);
    QColor identity() const { return m_identity; }

protected:
    void paintEvent(QPaintEvent*) override;
    void enterEvent(QEnterEvent*) override;
    void leaveEvent(QEvent*) override;
    void focusInEvent(QFocusEvent*) override;
    void focusOutEvent(QFocusEvent*) override;

private:
    void fadeHover(qreal to);
    void animateSelection(bool on);
    void syncAccessible();

    QString m_icon;
    qreal m_hover = 0.0;
    qreal m_select = 0.0;     // 0 idle … 1 active (follows isChecked(), animated)
    bool m_selecting = false; // direction of the running selection change
    bool m_keyboardFocus = false;
    bool m_compact = false;
    int m_badge = 0;
    QColor m_badgeColor;
    QColor m_identity;
    QVariantAnimation* m_anim = nullptr;
    QVariantAnimation* m_selAnim = nullptr;
};
