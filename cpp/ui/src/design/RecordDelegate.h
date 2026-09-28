#pragma once
#include <QColor>
#include <QListView>
#include <QRect>
#include <QStyledItemDelegate>

#include <functional>

class QTimer;

// Paints one record as two lines plus a right-hand status cluster:
//
//   [glyph]  powershell.exe · 远程线程注入            82  [已拦截]  3 分钟前
//            explorer.exe (PID 2204)  [chip] [chip]
//
// Group-header rows (RecordView::header) paint as a small eyebrow title with a
// count and — when the list allows collapsing — a chevron. Everything comes from
// the rec:: roles of RecordModel; the delegate owns no data, apart from the
// page's identity hue for header titles that bring no colour of their own.
class RecordDelegate : public QStyledItemDelegate
{
public:
    explicit RecordDelegate(QObject* parent = nullptr);

    static constexpr int kRowH = 60;
    static constexpr int kHeaderH = 38;
    static constexpr int kStickyH = 32;

    // Timeline style: a vertical rail threads the rows of a group together.
    void setRail(bool on) { m_rail = on; }
    bool rail() const { return m_rail; }
    void setCollapsible(bool on) { m_collapsible = on; }
    bool collapsible() const { return m_collapsible; }
    // Given by the view: is this group collapsed (chevron direction)?
    void setCollapsedProbe(std::function<bool(const QString&)> probe) { m_isCollapsed = std::move(probe); }
    // The page's identity hue: the title of a group header that has no colour of
    // its own (no status, no kind) is set in it. Invalid = muted.
    void setIdentity(const QColor& hue) { m_identity = hue; }
    QColor identity() const { return m_identity; }

    void paint(QPainter* p, const QStyleOptionViewItem& opt, const QModelIndex& idx) const override;
    QSize sizeHint(const QStyleOptionViewItem& opt, const QModelIndex& idx) const override;

    // Header band painter, shared with the view's pinned (sticky) header.
    void paintHeader(QPainter* p, const QRect& band, const QModelIndex& header, bool pinned) const;

private:
    void paintRecord(QPainter* p, const QStyleOptionViewItem& opt, const QModelIndex& idx) const;

    bool m_rail = false;
    bool m_collapsible = false;
    QColor m_identity;
    std::function<bool(const QString&)> m_isCollapsed;
};

// The list view for records: transparent (it sits inside a card), per-pixel
// scrolling, hover tracking, and — for grouped lists — a pinned group header
// that stays at the top while its records scroll beneath it. Clicking a header
// (pinned or in place) emits headerClicked() for collapse/expand.
//
// Relative timestamps ("3 分钟前") are re-rendered every 30 s.
class RecordListView : public QListView
{
    Q_OBJECT
public:
    explicit RecordListView(QWidget* parent = nullptr);

    RecordDelegate* recordDelegate() const { return m_delegate; }
    void setStickyHeaders(bool on);

signals:
    void headerClicked(const QString& group);

public:
    // Run any pending item layout now (so visualRect() is current).
    void settleLayout() { executeDelayedItemsLayout(); }

protected:
    void paintEvent(QPaintEvent* e) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseDoubleClickEvent(QMouseEvent* e) override;
    void scrollContentsBy(int dx, int dy) override;

private:
    QModelIndex headerFor(const QModelIndex& idx) const;

    RecordDelegate* m_delegate = nullptr;
    QTimer* m_clock = nullptr;
    bool m_sticky = false;
    mutable QRect m_stickyRect;
    mutable QString m_stickyGroup;
};
