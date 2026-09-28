#pragma once
#include "design/Components.h"
#include "design/Icons.h"
#include "design/Theme.h"
#include "widgets/TableColumns.h"

#include <QFont>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QWidget>

// Helpers for the list/table pages: a consistently configured QTableWidget
// (its look comes from the style sheet), a search field with a leading glyph,
// status-pill cells and compact toolbar buttons.
namespace ui {

inline QTableWidget* table(const QStringList& headers)
{
    auto* t = new QTableWidget;
    t->setColumnCount(headers.size());
    t->setHorizontalHeaderLabels(headers);
    t->verticalHeader()->setVisible(false);
    t->horizontalHeader()->setHighlightSections(false);
    t->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    // 列宽:Interactive = 用户可以拖列边界(Stretch 是拖不动的,而且强行平分列宽,
    // 路径列必被截断)。每页紧接着用 ui::columns() 给出各列的默认宽度与伸缩权重;
    // 没给规格的表格退化成「最后一列占满剩余」,至少不至于挤成一团。
    t->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    t->horizontalHeader()->setStretchLastSection(true);
    t->horizontalHeader()->setDefaultSectionSize(140);
    t->horizontalHeader()->setMinimumSectionSize(70);
    t->verticalHeader()->setDefaultSectionSize(46);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setShowGrid(false);
    t->setAlternatingRowColors(true);
    t->setWordWrap(false);
    // 键盘可达:Tab 能进表格、方向键能换行、读屏软件能拿到当前行。拦截记录、隔离区、
    // 防护规则这些正是用户要逐行审阅和处置的地方。焦点虚线框由样式表的 outline:none 去掉。
    t->setFocusPolicy(Qt::StrongFocus);
    return t;
}

inline QTableWidgetItem* textItem(const QString& text, bool secondary = false, bool mono = false)
{
    auto* it = new QTableWidgetItem(text);
    if (secondary)
        it->setForeground(theme::textSecondary());
    if (mono) {
        QFont f;
        f.setFamilies({QStringLiteral("Cascadia Mono"), QStringLiteral("Consolas")});
        f.setPointSizeF(9.5);
        it->setFont(f);
    }
    return it;
}

// Place a status pill inside a table cell (left-aligned, vertically centred).
inline void pillCell(QTableWidget* t, int row, int col, const QString& text, const QColor& c)
{
    auto* w = new QWidget;
    w->setStyleSheet(QStringLiteral("background:transparent;"));
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(8, 0, 8, 0);
    h->addWidget(pill(text, c));
    h->addStretch();
    t->setCellWidget(row, col, w);
}

// A search field with a leading magnifier glyph.
inline QLineEdit* searchBox(const QString& placeholder, int width = 280)
{
    auto* e = new QLineEdit;
    e->setPlaceholderText(placeholder);
    e->setClearButtonEnabled(true);
    e->addAction(AppIcon::icon(QStringLiteral("search"), theme::textMuted(), 16),
                 QLineEdit::LeadingPosition);
    e->setFixedWidth(width);
    return e;
}

// A compact glyph + text button for toolbars (variant: primary / ghost / danger).
inline QPushButton* toolButton(const QString& iconName, const QString& text,
                               const char* variant, const QColor& iconColor)
{
    auto* b = new QPushButton(text);
    b->setProperty("variant", variant);
    b->setCursor(Qt::PointingHandCursor);
    b->setIcon(AppIcon::icon(iconName, iconColor, 16));
    return b;
}

} // namespace ui
