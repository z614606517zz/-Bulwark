#pragma once
#include <QString>
#include <QStringList>

#include <functional>

class QWidget;

namespace ui {

// Makes `target` accept files / folders dragged in from Explorer. While a drag
// carrying local paths hovers, an overlay covers the target — dashed accent rim,
// an upload glyph and `hint` ("松开以查询云信誉") — so the user can see the drop
// will land. `accept` (optional) filters individual paths (e.g. folders only);
// drops with no acceptable path are refused. Remote URLs are ignored.
void acceptFileDrops(QWidget* target, const QString& hint,
                     std::function<void(const QStringList& paths)> onDrop,
                     std::function<bool(const QString& path)> accept = {});

} // namespace ui
