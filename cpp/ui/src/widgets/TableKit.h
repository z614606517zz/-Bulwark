#pragma once
#include "Theme.h"
#include "widgets/AppIcon.h"
#include "widgets/Ui.h"

#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QWidget>

// Helpers for the list/table pages: a consistently-styled QTableWidget, a
// search field with a leading icon, pill/status cells and small action buttons.
namespace ui {

inline QTableWidget* table(const QStringList& headers)
{
    auto* t = new QTableWidget;
    t->setColumnCount(headers.size());
    t->setHorizontalHeaderLabels(headers);
    t->verticalHeader()->setVisible(false);
    t->horizontalHeader()->setHighlightSections(false);
    t->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    t->horizontalHeader()->setMinimumSectionSize(70);
    t->verticalHeader()->setDefaultSectionSize(48);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setShowGrid(false);
    t->setAlternatingRowColors(true);
    t->setWordWrap(false);
    t->setFocusPolicy(Qt::NoFocus);
    return t;
}

inline QTableWidgetItem* textItem(const QString& text, bool secondary = false, bool mono = false)
{
    auto* it = new QTableWidgetItem(text);
    if (secondary)
        it->setForeground(theme::textSecondary());
    if (mono)
        it->setFont(QFont(QStringLiteral("Cascadia Mono")));
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

// A search field with a leading magnifier icon.
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

// A compact icon+text button used in toolbars (primary/ghost via `variant`).
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
