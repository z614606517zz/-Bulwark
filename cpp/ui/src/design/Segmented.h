#pragma once
#include <QColor>
#include <QList>
#include <QVariant>
#include <QWidget>

class QButtonGroup;
class QHBoxLayout;
class SegmentButton;

// A segmented control: mutually exclusive options in one pill-shaped track, each
// optionally carrying a live count — "[全部 1219 | 拦截 12 | 询问 3 | 放行 1204]".
// It is the primary filter on every list page (what the list is showing), so it
// is painted, not styled: a lit "thumb" (tinted with the page's identity hue)
// marks the current segment, counts sit in a quieter colour (or the segment's
// accent when non-zero).
//
// Keyboard: the control is one tab stop (the current segment); ←/→ (and Home /
// End) move the selection, like a native radio group. Each segment is a real
// QAbstractButton, so screen readers announce "拦截 12 条, 已选中".
class Segmented : public QWidget
{
    Q_OBJECT
public:
    explicit Segmented(QWidget* parent = nullptr);

    int addSegment(const QString& text, const QVariant& data = QVariant());
    int count() const { return int(m_buttons.size()); }

    void setText(int index, const QString& text);
    // -1 hides the count.
    void setCount(int index, int count);
    // Colour for the count when it is > 0 (e.g. danger for 拦截, warning for 询问).
    void setAccent(int index, const QColor& color);

    int currentIndex() const;
    QVariant currentData() const;
    QVariant data(int index) const;
    int indexOfData(const QVariant& data) const;
    // Emits currentChanged() when the index actually changes.
    void setCurrentIndex(int index);

    // Smaller variant for secondary pickers (the timeline's time range).
    void setCompact(bool compact);
    bool isCompact() const { return m_compact; }

    // The page's identity hue (design/Identity.h) tints the thumb and its rim;
    // invalid = the neutral stone thumb. Labels and status-coloured counts keep
    // their colours.
    void setIdentity(const QColor& hue);
    QColor identity() const { return m_identity; }

signals:
    void currentChanged(int index);

protected:
    void paintEvent(QPaintEvent*) override;

private:
    friend class SegmentButton;
    void step(int from, int delta);
    void syncFocus();

    QButtonGroup* m_group = nullptr;
    QHBoxLayout* m_row = nullptr;
    QList<SegmentButton*> m_buttons;
    bool m_compact = false;
    QColor m_identity;
};
