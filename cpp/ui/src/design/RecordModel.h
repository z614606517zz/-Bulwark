#pragma once
#include <QAbstractListModel>
#include <QColor>
#include <QDateTime>
#include <QHash>
#include <QList>
#include <QPair>
#include <QSet>
#include <QSortFilterProxyModel>
#include <QStringList>
#include <QVariant>

#include <functional>
#include <utility>

// ═════════════════════════════════════════════════════════════════════════════
//  Record lists — the data side of every list page
// ═════════════════════════════════════════════════════════════════════════════
//
//  RecordView     what one row shows (two lines + a right-hand status cluster),
//                 already formatted by the page. Pages never touch the model's
//                 roles directly.
//  RecordModel    the rows, optionally with group-header rows between them.
//  RecordFilter   page predicate (segments / chips) + multi-term search +
//                 collapsed groups. A header stays visible while any of its
//                 records matches.
//  RecordStore<T> keeps the page's payload objects (SecurityEvent, DefenseRule…)
//                 in lock-step with the rows, so a selection maps straight back
//                 to the object it shows.
//
//  The delegate (RecordDelegate) paints rows; RecordBrowser (ListShell.h) wires
//  all of it to the filter bar, the inspector and the empty states.

namespace rec {
enum Role : int {
    Subtitle = Qt::UserRole + 1,
    SubtitleMono,
    Icon,
    IconColor,
    Score,
    ScoreColor,
    Pill,
    PillColor,
    Meta,
    Time,
    Chips,
    Dim,
    Header,
    Group,
    GroupCount,
    GroupColor,
    GroupNote,
    Accent,
    Key,
    Leading, // header rows: first header of the list (no top gap)
    ChipColors,
};
} // namespace rec

struct RecordView {
    QString icon;             // glyph name (AppIcon)
    QColor iconColor;
    QString title;            // line 1: "powershell.exe · 远程线程注入"
    QString subtitle;         // line 2: target / path
    bool subtitleMono = false;
    QString score;            // right cluster: "82"
    QColor scoreColor;
    QString pill;             // right cluster: "已拦截"
    QColor pillColor;
    QString meta;             // right cluster: static text ("12.3 MB")
    QDateTime time;           // right cluster: relative time (preferred over meta)
    QStringList chips;        // line 2 capsules after the subtitle
    QList<QColor> chipColors; // per chip, by index; missing / invalid = neutral capsule.
                              // A status colour only when the chip states a status
                              // (grade, "硬拦截"); otherwise a kind hue (launch origin).
    bool dim = false;         // de-emphasised (disabled rule, stale item)
    QColor accent;            // optional left status strip
    QString tooltip;
    QString haystack;         // search text; built from the visible text when empty
    QVariant key;             // identity (for re-selection after refresh / navigation)

    // group headers
    bool header = false;
    QString group;            // group key (headers and their members)
    int groupCount = 0;
    QColor groupColor;
    QString groupNote;        // right-side note on the header ("风险最高 82")
};

class RecordModel : public QAbstractListModel
{
public:
    explicit RecordModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    Qt::ItemFlags flags(const QModelIndex& index) const override;

    void reset(QList<RecordView> rows);
    void insertTop(QList<RecordView> rows);  // flat lists only (live streams)
    void removeTail(int n);
    void setRow(int row, RecordView v);

    int size() const { return int(m_rows.size()); }
    const RecordView& at(int row) const { return m_rows.at(row); }
    bool isHeader(int row) const { return row >= 0 && row < m_rows.size() && m_rows.at(row).header; }
    bool hasHeaders() const { return !m_spans.isEmpty(); }
    // Rows [first, last] belonging to the header at `headerRow` (empty span = {1, 0}).
    QPair<int, int> groupSpan(int headerRow) const { return m_spans.value(headerRow, {1, 0}); }
    int recordCount() const { return m_records; }
    int rowOfKey(const QVariant& key) const;

private:
    static void normalize(RecordView& v);
    void rebuildIndex();

    QList<RecordView> m_rows;
    QHash<int, QPair<int, int>> m_spans;
    int m_records = 0;
};

class RecordFilter : public QSortFilterProxyModel
{
public:
    explicit RecordFilter(QObject* parent = nullptr);

    void setRecords(RecordModel* model);
    RecordModel* records() const { return m_model; }

    // Page filter (segments / chips): true = keep the source row.
    void setPredicate(std::function<bool(int sourceRow)> pred);
    // Whitespace-separated terms, all must appear (case-insensitive).
    void setSearch(const QString& text);
    QString search() const { return m_search; }
    void setCollapsed(const QString& group, bool collapsed);
    bool isCollapsed(const QString& group) const { return m_collapsed.contains(group); }
    QSet<QString> collapsedGroups() const { return m_collapsed; }

    void refresh(); // re-run the filter after the page's own criteria changed

    bool matches(int sourceRow) const; // predicate + search, ignoring collapse
    int matchedRecords() const;        // records passing predicate + search
    int totalRecords() const;

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;

private:
    RecordModel* m_model = nullptr;
    std::function<bool(int)> m_pred;
    QString m_search;
    QStringList m_terms;
    QSet<QString> m_collapsed;
};

// Payload objects kept in lock-step with the rows of a RecordModel.
//
// Flat mode (reset / prependMany / trim): row i shows item i.
// Grouped mode (resetGrouped): header rows are interleaved; itemIndex() maps a
// row back to its item (-1 for headers).
template <class T>
class RecordStore
{
public:
    using ViewFn = std::function<RecordView(const T&)>;

    RecordStore(RecordModel* model, ViewFn view) : m_model(model), m_view(std::move(view)) {}

    void reset(const QList<T>& items)
    {
        m_grouped = false;
        m_items = items;
        m_rowToItem.clear();
        QList<RecordView> rows;
        rows.reserve(items.size());
        for (const T& it : items)
            rows.append(m_view(it));
        m_model->reset(std::move(rows));
    }

    // `newestFirst[0]` ends up on top.
    void prependMany(const QList<T>& newestFirst)
    {
        if (newestFirst.isEmpty() || m_grouped)
            return;
        QList<RecordView> rows;
        rows.reserve(newestFirst.size());
        for (const T& it : newestFirst)
            rows.append(m_view(it));
        for (qsizetype i = newestFirst.size() - 1; i >= 0; --i)
            m_items.prepend(newestFirst[i]); // amortised O(1) in Qt 6
        m_model->insertTop(std::move(rows));
    }

    void prepend(const T& item) { prependMany(QList<T>{item}); }

    void trim(int maxItems)
    {
        if (m_grouped)
            return;
        const int n = int(m_items.size()) - maxItems;
        if (n <= 0)
            return;
        m_items.remove(maxItems, n);
        m_model->removeTail(n);
    }

    // Rows per group, in `order` first (then first-seen order for the rest).
    // Items keep their relative order within a group, so sort them beforehand.
    void resetGrouped(const QList<T>& items, const std::function<QString(const T&)>& groupOf,
                      const std::function<RecordView(const QString& group, const QList<const T*>& members)>& header,
                      const QStringList& order = QStringList())
    {
        m_grouped = true;
        m_items = items;
        QStringList groups = order;
        QHash<QString, QList<int>> buckets;
        for (int i = 0; i < m_items.size(); ++i) {
            const QString g = groupOf(m_items[i]);
            if (!groups.contains(g))
                groups.append(g);
            buckets[g].append(i);
        }
        QList<RecordView> rows;
        m_rowToItem.clear();
        for (const QString& g : std::as_const(groups)) {
            const auto it = buckets.constFind(g);
            if (it == buckets.constEnd() || it->isEmpty())
                continue;
            QList<const T*> members;
            for (int i : *it)
                members.append(&m_items[i]);
            RecordView h = header(g, members);
            h.header = true;
            h.group = g;
            h.groupCount = int(it->size());
            rows.append(h);
            m_rowToItem.append(-1);
            for (int i : *it) {
                RecordView v = m_view(m_items[i]);
                v.group = g;
                rows.append(v);
                m_rowToItem.append(i);
            }
        }
        m_model->reset(std::move(rows));
    }

    // Re-render one item in place (e.g. a scan record moving through its stages).
    void update(int itemIndex, const T& item)
    {
        if (itemIndex < 0 || itemIndex >= m_items.size())
            return;
        m_items[itemIndex] = item;
        const int row = rowOfItem(itemIndex);
        if (row < 0)
            return;
        RecordView v = m_view(item);
        if (m_grouped)
            v.group = m_model->at(row).group;
        m_model->setRow(row, std::move(v));
    }

    int itemIndex(int sourceRow) const
    {
        if (!m_grouped)
            return (sourceRow >= 0 && sourceRow < m_items.size()) ? sourceRow : -1;
        return (sourceRow >= 0 && sourceRow < m_rowToItem.size()) ? m_rowToItem[sourceRow] : -1;
    }
    int rowOfItem(int itemIndex) const
    {
        if (!m_grouped)
            return (itemIndex >= 0 && itemIndex < m_items.size()) ? itemIndex : -1;
        return int(m_rowToItem.indexOf(itemIndex));
    }
    const T* itemAt(int sourceRow) const
    {
        const int i = itemIndex(sourceRow);
        return i >= 0 ? &m_items[i] : nullptr;
    }
    const QList<T>& items() const { return m_items; }
    int size() const { return int(m_items.size()); }
    bool isEmpty() const { return m_items.isEmpty(); }
    RecordModel* model() const { return m_model; }

private:
    RecordModel* m_model;
    ViewFn m_view;
    QList<T> m_items;
    QList<int> m_rowToItem;
    bool m_grouped = false;
};
