#pragma once
#include "design/GlowCard.h"
#include "design/RecordModel.h"

#include <QPersistentModelIndex>
#include <QPointer>
#include <QVariant>
#include <QWidget>

#include <functional>

class EmptyState;
class FilterChip;
class Inspector;
class QAbstractItemView;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QMenu;
class QPushButton;
class QVariantAnimation;
class QVBoxLayout;
class RecordListView;
class Segmented;

// The floating bar that appears at the bottom of a list while several records
// are selected: "已选 3 项 · [还原] [永久删除] · ✕".
class BatchBar : public GlowCard
{
    Q_OBJECT
public:
    explicit BatchBar(QWidget* parent = nullptr);
    void setCount(int n);
    QPushButton* addAction(const QString& icon, const QString& text, const char* variant,
                           std::function<void()> fn);
    bool hasActions() const { return m_actions > 0; }

signals:
    void clearRequested();

private:
    QLabel* m_count = nullptr;
    QHBoxLayout* m_row = nullptr;
    int m_actions = 0;
};

// ═════════════════════════════════════════════════════════════════════════════
//  ListShell — the skeleton every list page shares
// ═════════════════════════════════════════════════════════════════════════════
//
//   [top widgets: status banner …]
//   [Segmented] [chip ▾] [chip ▾] [extra]            [搜索…]  匹配 12 / 1219
//   [above-list widgets: density bar …]
//   ┌ list card ─────────────────────────────┐ ┌ inspector ─────────┐
//   │  view                     ↑ 12 条新事件 │ │  slides in on      │
//   │  (empty state overlay)                  │ │  selection         │
//   │            [batch bar]                  │ │                    │
//   └─────────────────────────────────────────┘ └────────────────────┘
//
// Below ~880 px of content width the inspector becomes a drawer over the list
// (with a scrim that closes it). Esc closes the inspector, or clears the search
// when the inspector is already closed. MainWindow routes Ctrl+F to the search
// box (objectName "PageSearch").
class ListShell : public QWidget
{
    Q_OBJECT
public:
    explicit ListShell(QWidget* parent = nullptr);

    // ---- filter bar ----
    Segmented* segments() const { return m_segments; }  // hidden until a segment is added
    FilterChip* addChip(const QString& label);
    void addFilterWidget(QWidget* w);
    QLineEdit* searchBox() const { return m_search; }
    void setMatch(int shown, int total);
    void addTop(QWidget* w);
    void addAboveList(QWidget* w);

    // ---- content ----
    void setView(QAbstractItemView* view);
    QAbstractItemView* view() const { return m_view; }
    Inspector* inspector() const { return m_inspector; }
    bool isInspectorOpen() const { return m_open; }
    void setInspectorOpen(bool open);
    EmptyState* emptyState() const { return m_empty; }
    void setEmptyVisible(bool visible);
    BatchBar* batchBar() const { return m_batch; }
    void setBatchVisible(bool visible);
    // "↑ 12 条新事件" pill at the top of the list; n <= 0 hides it.
    void showNewItems(int n, const QString& text = QString());

    // ---- identity ----
    // The page's identity hue (design/Identity.h): a soft light in the list card
    // and the segment thumb; RecordBrowser adds neutral group headers and its
    // empty states. A page sets it once, from identity::page(<its nav key>), and
    // hands identity() to any control of its own that should wear it.
    virtual void setIdentity(const QColor& hue);
    QColor identity() const { return m_identity; }

signals:
    void newItemsClicked();
    void inspectorClosed();
    void escapePressed();

protected:
    void keyPressEvent(QKeyEvent* e) override;
    bool eventFilter(QObject* watched, QEvent* e) override;
    void showEvent(QShowEvent* e) override;
    void syncSegmentsVisible();

private:
    void layoutContent();
    void positionOverlays();

    QVBoxLayout* m_top = nullptr;
    QHBoxLayout* m_bar = nullptr;
    QHBoxLayout* m_chips = nullptr;
    QVBoxLayout* m_above = nullptr;
    Segmented* m_segments = nullptr;
    QLineEdit* m_search = nullptr;
    QLabel* m_match = nullptr;

    QWidget* m_content = nullptr;
    GlowCard* m_card = nullptr;
    QVBoxLayout* m_cardLayout = nullptr;
    QAbstractItemView* m_view = nullptr;
    Inspector* m_inspector = nullptr;
    QWidget* m_scrim = nullptr;
    EmptyState* m_empty = nullptr;
    BatchBar* m_batch = nullptr;
    QPushButton* m_newPill = nullptr;
    QVariantAnimation* m_anim = nullptr;
    qreal m_progress = 0.0;
    bool m_open = false;
    bool m_batchShown = false;
    QColor m_identity;
};

// ═════════════════════════════════════════════════════════════════════════════
//  RecordBrowser — ListShell + record list, wired up
// ═════════════════════════════════════════════════════════════════════════════
//
// Owns a RecordModel / RecordFilter / RecordListView. A page supplies the rows
// (through a RecordStore<T> bound to model()), a predicate for its segments and
// chips, and builders for the inspector / context menu / activation. The
// browser does the rest: search, "匹配 x / y", the right empty state, keeping
// the selection (and the open inspector) across refreshes, anchoring the
// viewport when live rows arrive on top while the user is reading further down,
// and the batch bar for multi-selection.
class RecordBrowser : public ListShell
{
    Q_OBJECT
public:
    enum class Empty { None, Disconnected, Loading, NoData, NoMatch };

    explicit RecordBrowser(QWidget* parent = nullptr);

    RecordModel* model() const { return m_model; }
    RecordFilter* filter() const { return m_filter; }
    RecordListView* list() const { return m_list; }

    void setGrouped(bool grouped, bool collapsible = false, bool rail = false);
    void setMultiSelect(bool on);
    void setLiveTop(bool on) { m_liveTop = on; }
    void setIdentity(const QColor& hue) override;

    void setPredicate(std::function<bool(int sourceRow)> pred);
    void setInspectorBuilder(std::function<void(Inspector*, int sourceRow)> build);
    void setActivateHandler(std::function<void(int sourceRow)> fn);
    void setContextMenuBuilder(std::function<void(QMenu*, const QList<int>& sourceRows)> fn);
    // Called by 「清除筛选」 (after the browser has cleared the search box).
    void setClearFilters(std::function<void()> fn) { m_clearFilters = std::move(fn); }

    // ---- empty states ----
    void setConnected(bool connected);
    void setNeedsConnection(bool on) { m_needsConnection = on; refreshEmpty(); }
    void setLoading(bool loading);
    void setDisconnectedText(const QString& body);
    void setNoDataContent(const QString& icon, const QString& title, const QString& body,
                          const QString& actionText = QString(), std::function<void()> action = {});
    Empty emptyKind() const { return m_emptyKind; }

    // ---- selection ----
    void refilter();                 // re-run the predicate (page criteria changed)
    QList<int> selectedSourceRows() const;
    int currentSourceRow() const;
    QVariant currentKey() const;
    // Select the record with `key`. `reveal` clears search / filters when the
    // record is currently filtered out (navigation "go to that event").
    bool selectKey(const QVariant& key, bool openInspector = true, bool reveal = true);
    void rebuildInspector();         // current record's data changed
    void clearSelection();

signals:
    void currentRowChanged(int sourceRow);
    void selectionCountChanged(int n);

private:
    void updateCounts();
    void refreshEmpty();
    void onCurrentChanged(const QModelIndex& current);
    void showInspectorFor(int sourceRow);
    void showContextMenu(const QPoint& pos);

    RecordModel* m_model = nullptr;
    RecordFilter* m_filter = nullptr;
    RecordListView* m_list = nullptr;

    std::function<void(Inspector*, int)> m_buildInspector;
    std::function<void(int)> m_activate;
    std::function<void(QMenu*, const QList<int>&)> m_contextMenu;
    std::function<void()> m_clearFilters;
    std::function<void()> m_noDataAction;

    bool m_connected = false;
    bool m_needsConnection = true;
    bool m_loading = false;
    bool m_liveTop = false;
    Empty m_emptyKind = Empty::None;
    QString m_disconnectedBody;
    QString m_noDataIcon, m_noDataTitle, m_noDataBody, m_noDataActionText;

    // selection / anchoring across model changes
    QVariant m_keptKey;
    bool m_keptInspector = false;
    int m_keptScroll = 0;
    QPersistentModelIndex m_anchor;
    int m_anchorY = 0;
    bool m_anchoring = false;
    bool m_selecting = false;
    int m_newCount = 0;
};
