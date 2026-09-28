#include "design/FlowLayout.h"

#include <QWidget>

FlowLayout::FlowLayout(QWidget* parent, int hSpacing, int vSpacing)
    : QLayout(parent), m_hSpace(hSpacing), m_vSpace(vSpacing)
{
    setContentsMargins(0, 0, 0, 0);
}

FlowLayout::~FlowLayout()
{
    while (QLayoutItem* item = takeAt(0))
        delete item;
}

void FlowLayout::addItem(QLayoutItem* item) { m_items.append(item); }
int FlowLayout::count() const { return int(m_items.size()); }

QLayoutItem* FlowLayout::itemAt(int index) const
{
    return (index >= 0 && index < m_items.size()) ? m_items.at(index) : nullptr;
}

QLayoutItem* FlowLayout::takeAt(int index)
{
    if (index < 0 || index >= m_items.size())
        return nullptr;
    return m_items.takeAt(index);
}

void FlowLayout::clear()
{
    while (QLayoutItem* item = takeAt(0)) {
        if (QWidget* w = item->widget()) {
            w->hide(); // out of the layout but still painted until the deferred delete runs
            w->deleteLater();
        }
        delete item;
    }
    invalidate();
}

Qt::Orientations FlowLayout::expandingDirections() const { return {}; }
bool FlowLayout::hasHeightForWidth() const { return true; }

int FlowLayout::heightForWidth(int width) const
{
    return doLayout(QRect(0, 0, width, 0), true);
}

void FlowLayout::setGeometry(const QRect& rect)
{
    QLayout::setGeometry(rect);
    doLayout(rect, false);
}

QSize FlowLayout::sizeHint() const { return minimumSize(); }

QSize FlowLayout::minimumSize() const
{
    QSize size;
    for (const QLayoutItem* item : m_items)
        size = size.expandedTo(item->minimumSize());
    const QMargins m = contentsMargins();
    size += QSize(m.left() + m.right(), m.top() + m.bottom());
    return size;
}

int FlowLayout::doLayout(const QRect& rect, bool testOnly) const
{
    const QMargins m = contentsMargins();
    const QRect area = rect.adjusted(m.left(), m.top(), -m.right(), -m.bottom());
    int x = area.x();
    int y = area.y();
    int lineHeight = 0;

    for (QLayoutItem* item : m_items) {
        if (item->isEmpty())
            continue;
        const QSize hint = item->sizeHint();
        // An item wider than the whole row still gets its own line, clamped to the row.
        const int w = qMin(hint.width(), qMax(1, area.width()));
        int nextX = x + w + m_hSpace;
        if (nextX - m_hSpace > area.right() + 1 && lineHeight > 0) {
            x = area.x();
            y += lineHeight + m_vSpace;
            nextX = x + w + m_hSpace;
            lineHeight = 0;
        }
        if (!testOnly)
            item->setGeometry(QRect(QPoint(x, y), QSize(w, hint.height())));
        x = nextX;
        lineHeight = qMax(lineHeight, hint.height());
    }
    return y + lineHeight - rect.y() + m.bottom();
}
