#pragma once
#include <QString>

class QWidget;

namespace ui {

// Pick one existing file / folder with the native Windows "open" dialog — the same dialog
// QFileDialog::getOpenFileName / getExistingDirectory put up — except that hidden folders can be
// reached: hidden and system items are listed, and the file picker also pins AppData and
// ProgramData at the top of the navigation pane.
//
// Why not QFileDialog: Qt only asks the native dialog for hidden items when Explorer itself shows
// them (Explorer\Advanced\Hidden == 1), and offers no option to force it. Under the Windows default
// the dialog cannot even browse into %LOCALAPPDATA% or %ProgramData% — both folders carry the
// hidden attribute — and that is where a large share of installed programs live. The pins are
// needed on top of listing hidden items, because the user-profile folder keeps hiding AppData
// regardless; the folder picker leaves them out on purpose (see showOpenDialog in the .cpp).
// Hidden entries elsewhere show up dimmed.
//
// `filter` uses QFileDialog's syntax ("程序 (*.exe *.dll);;所有文件 (*.*)"); the first entry is
// preselected. Returns the path with '/' separators like QFileDialog, or an empty string when the
// user cancels. Falls back to QFileDialog if the native dialog can't be created.
QString pickExistingFile(QWidget* parent, const QString& title, const QString& filter);
QString pickExistingFolder(QWidget* parent, const QString& title);

} // namespace ui
