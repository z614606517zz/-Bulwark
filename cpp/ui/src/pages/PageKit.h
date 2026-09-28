#pragma once
#include "design/Components.h"
#include "design/ListShell.h"
#include "ipc/IpcClient.h"

#include <QHBoxLayout>
#include <QLineEdit>
#include <QMenu>
#include <QPushButton>
#include <QSettings>
#include <QTimer>
#include <QToolButton>

#include <functional>

// Small wiring shared by the list pages (events, timeline, chain, processes,
// rules, trust, quarantine, autostart). Everything here used to be copied into
// each page function; now each page states only what is specific to it.
namespace pagekit {

// The page's header action row (right side of the shell's page header).
inline QHBoxLayout* headerActions(QWidget* page)
{
    QHBoxLayout* row = nullptr;
    QWidget* w = ui::actionRow(&row);
    ui::setPageActions(page, w);
    return row;
}

inline QPushButton* headerButton(QHBoxLayout* row, const QString& icon, const QString& text,
                                 const char* variant = "ghost")
{
    auto* b = ui::button(text, variant, icon);
    row->addWidget(b);
    return b;
}

// "⋯" at the end of the header row; returns the menu to fill.
inline QMenu* headerMenu(QHBoxLayout* row)
{
    auto* menu = new QMenu(row->parentWidget());
    row->addWidget(ui::moreButton(menu));
    return menu;
}

inline QAction* menuAction(QMenu* menu, const QString& icon, const QString& text, QObject* context,
                           std::function<void()> fn)
{
    QAction* a = menu->addAction(icon.isEmpty() ? QIcon() : AppIcon::icon(icon, theme::textSecondary(), 16), text);
    QObject::connect(a, &QAction::triggered, context, [fn = std::move(fn)] {
        if (fn)
            fn();
    });
    return a;
}

// Keep `browser` in step with the service connection and run `load` (after
// `delayMs`, so start-up isn't one burst of requests) whenever it connects —
// including right away when it already is. Timers are scoped to the page.
inline void onConnected(QWidget* page, IpcClient* ipc, RecordBrowser* browser, int delayMs, std::function<void()> load)
{
    auto run = [page, delayMs, load = std::move(load)] {
        QTimer::singleShot(delayMs, page, [load] { if (load) load(); });
    };
    QObject::connect(ipc, &IpcClient::connectionChanged, page, [browser, run](bool c) {
        if (browser)
            browser->setConnected(c);
        if (c)
            run();
    });
    if (browser)
        browser->setConnected(ipc->isConnected());
    if (ipc->isConnected())
        run();
}

// A remembered UI choice (segment, view mode) under "ui/<page>/<key>".
inline QString remembered(const QString& page, const QString& key, const QString& fallback)
{
    return QSettings().value(QStringLiteral("ui/%1/%2").arg(page, key), fallback).toString();
}

inline void remember(const QString& page, const QString& key, const QString& value)
{
    QSettings().setValue(QStringLiteral("ui/%1/%2").arg(page, key), value);
}

} // namespace pagekit
