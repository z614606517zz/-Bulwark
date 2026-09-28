#include "design/RecordModel.h"

#include <QRegularExpression>

// ---- RecordModel ---------------------------------------------------------------

RecordModel::RecordModel(QObject* parent) : QAbstractListModel(parent) {}

int RecordModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : int(m_rows.size());
}

QVariant RecordModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_rows.size())
        return {};
    const RecordView& v = m_rows.at(index.row());
    switch (role) {
    case Qt::DisplayRole:     return v.title;
    case Qt::ToolTipRole:     return v.tooltip.isEmpty() ? QVariant() : QVariant(v.tooltip);
    case Qt::AccessibleTextRole: {
        // What a screen reader announces for the row: every visible part, in
        // reading order (the painted row has no text of its own).
        QStringList parts{v.title};
        if (!v.subtitle.isEmpty()) parts << v.subtitle;
        if (!v.score.isEmpty())    parts << QString::fromUtf8("风险 ") + v.score;
        if (!v.pill.isEmpty())     parts << v.pill;
        if (!v.meta.isEmpty())     parts << v.meta;
        if (v.header)              parts << QString::fromUtf8("%1 项").arg(v.groupCount);
        return parts.join(QStringLiteral(", "));
    }
    case rec::Subtitle:     return v.subtitle;
    case rec::SubtitleMono: return v.subtitleMono;
    case rec::Icon:         return v.icon;
    case rec::IconColor:    return v.iconColor;
    case rec::Score:        return v.score;
    case rec::ScoreColor:   return v.scoreColor;
    case rec::Pill:         return v.pill;
    case rec::PillColor:    return v.pillColor;
    case rec::Meta:         return v.meta;
    case rec::Time:         return v.time;
    case rec::Chips:        return v.chips;
    case rec::ChipColors: {
        QVariantList colors;
        colors.reserve(v.chipColors.size());
        for (const QColor& c : v.chipColors)
            colors << c;
        return colors;
    }
    case rec::Dim:          return v.dim;
    case rec::Header:       return v.header;
    case rec::Group:        return v.group;
    case rec::GroupCount:   return v.groupCount;
    case rec::GroupColor:   return v.groupColor;
    case rec::GroupNote:    return v.groupNote;
    case rec::Accent:       return v.accent;
    case rec::Key:          return v.key;
    case rec::Leading:      return index.row() == 0;
    default:                return {};
    }
}

Qt::ItemFlags RecordModel::flags(const QModelIndex& index) const
{
    if (!index.isValid())
        return Qt::NoItemFlags;
    // Group headers can't be selected or become current: ↑/↓ walk the records only.
    if (isHeader(index.row()))
        return Qt::NoItemFlags;
    return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
}

void RecordModel::normalize(RecordView& v)
{
    if (v.haystack.isEmpty()) {
        QStringList parts{v.title, v.subtitle, v.pill, v.score, v.meta, v.tooltip};
        parts << v.chips;
        v.haystack = parts.join(QLatin1Char(' '));
    }
}

void RecordModel::rebuildIndex()
{
    m_spans.clear();
    m_records = 0;
    int header = -1;
    for (int i = 0; i < m_rows.size(); ++i) {
        if (m_rows[i].header) {
            if (header >= 0)
                m_spans.insert(header, {header + 1, i - 1});
            header = i;
        } else {
            ++m_records;
        }
    }
    if (header >= 0)
        m_spans.insert(header, {header + 1, int(m_rows.size()) - 1});
}

void RecordModel::reset(QList<RecordView> rows)
{
    for (RecordView& v : rows)
        normalize(v);
    beginResetModel();
    m_rows = std::move(rows);
    rebuildIndex();
    endResetModel();
}

void RecordModel::insertTop(QList<RecordView> rows)
{
    if (rows.isEmpty())
        return;
    for (RecordView& v : rows)
        normalize(v);
    beginInsertRows(QModelIndex(), 0, int(rows.size()) - 1);
    for (qsizetype i = rows.size() - 1; i >= 0; --i)
        m_rows.prepend(std::move(rows[i]));
    m_records += int(rows.size());
    endInsertRows();
}

void RecordModel::removeTail(int n)
{
    n = qMin(n, int(m_rows.size()));
    if (n <= 0)
        return;
    const int first = int(m_rows.size()) - n;
    beginRemoveRows(QModelIndex(), first, int(m_rows.size()) - 1);
    m_rows.remove(first, n);
    endRemoveRows();
    rebuildIndex();
}

void RecordModel::setRow(int row, RecordView v)
{
    if (row < 0 || row >= m_rows.size())
        return;
    normalize(v);
    m_rows[row] = std::move(v);
    const QModelIndex idx = index(row, 0);
    emit dataChanged(idx, idx);
}

int RecordModel::rowOfKey(const QVariant& key) const
{
    if (!key.isValid())
        return -1;
    for (int i = 0; i < m_rows.size(); ++i)
        if (!m_rows[i].header && m_rows[i].key == key)
            return i;
    return -1;
}

// ---- RecordFilter ---------------------------------------------------------------

RecordFilter::RecordFilter(QObject* parent) : QSortFilterProxyModel(parent)
{
    setDynamicSortFilter(true);
}

void RecordFilter::setRecords(RecordModel* model)
{
    m_model = model;
    setSourceModel(model);
}

void RecordFilter::setPredicate(std::function<bool(int)> pred)
{
    m_pred = std::move(pred);
    refresh();
}

void RecordFilter::setSearch(const QString& text)
{
    const QString t = text.trimmed();
    if (t == m_search)
        return;
    m_search = t;
    static const QRegularExpression ws(QStringLiteral("\\s+"));
    m_terms = t.isEmpty() ? QStringList() : t.split(ws, Qt::SkipEmptyParts);
    refresh();
}

void RecordFilter::setCollapsed(const QString& group, bool collapsed)
{
    if (collapsed == m_collapsed.contains(group))
        return;
    if (collapsed)
        m_collapsed.insert(group);
    else
        m_collapsed.remove(group);
    refresh();
}

void RecordFilter::refresh()
{
    invalidateFilter();
}

bool RecordFilter::matches(int sourceRow) const
{
    if (!m_model || sourceRow < 0 || sourceRow >= m_model->size())
        return false;
    if (m_pred && !m_pred(sourceRow))
        return false;
    if (!m_terms.isEmpty()) {
        const QString& hay = m_model->at(sourceRow).haystack;
        for (const QString& term : m_terms)
            if (!hay.contains(term, Qt::CaseInsensitive))
                return false;
    }
    return true;
}

int RecordFilter::matchedRecords() const
{
    if (!m_model)
        return 0;
    int n = 0;
    for (int r = 0; r < m_model->size(); ++r)
        if (!m_model->isHeader(r) && matches(r))
            ++n;
    return n;
}

int RecordFilter::totalRecords() const
{
    return m_model ? m_model->recordCount() : 0;
}

bool RecordFilter::filterAcceptsRow(int sourceRow, const QModelIndex&) const
{
    if (!m_model || sourceRow < 0 || sourceRow >= m_model->size())
        return false;
    const RecordView& v = m_model->at(sourceRow);
    if (v.header) {
        const auto [first, last] = m_model->groupSpan(sourceRow);
        for (int r = first; r <= last; ++r)
            if (matches(r))
                return true;
        return false;
    }
    if (!matches(sourceRow))
        return false;
    return v.group.isEmpty() || !m_collapsed.contains(v.group);
}
