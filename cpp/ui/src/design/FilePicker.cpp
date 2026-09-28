#include "design/FilePicker.h"

#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QStringList>
#include <QWidget>
#include <QtGlobal>

#ifdef Q_OS_WIN
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <shobjidl.h>
#  include <wrl/client.h>

#  include <string>
#  include <vector>
#endif

#ifdef Q_OS_WIN
namespace {

using Microsoft::WRL::ComPtr;

enum class Outcome { Picked, Cancelled, Unavailable };

// Same clean-up Qt runs after its own native dialogs (QWindowsDialogs::eatMouseMove): a
// double-click that picks a file closes the dialog on the second button-down, and the mouse moves
// queued behind it still carry that button state — Qt would read them as a press / drag on
// whatever widget is now under the cursor. Drop them and repost only the last one, buttons up.
void eatMouseMove()
{
    MSG msg = {};
    while (::PeekMessageW(&msg, nullptr, WM_MOUSEMOVE, WM_MOUSEMOVE, PM_REMOVE)) {
    }
    if (msg.message == WM_MOUSEMOVE)
        ::PostMessageW(msg.hwnd, msg.message, 0, msg.lParam);
}

struct FileType {
    std::wstring name; // shown in the type box, e.g. "程序 (*.exe *.dll)"
    std::wstring spec; // "*.exe;*.dll"
};

// QFileDialog filter syntax -> IFileDialog file types:
// "程序 (*.exe *.dll);;所有文件 (*.*)" -> {"程序 (*.exe *.dll)", "*.exe;*.dll"}, {"所有文件 (*.*)", "*.*"}
std::vector<FileType> parseFilter(const QString& filter)
{
    std::vector<FileType> out;
    const QStringList entries = filter.split(QStringLiteral(";;"), Qt::SkipEmptyParts);
    for (const QString& raw : entries) {
        const QString entry = raw.trimmed();
        const qsizetype open = entry.lastIndexOf(QLatin1Char('('));
        const qsizetype close = entry.lastIndexOf(QLatin1Char(')'));
        const QString patterns = (open >= 0 && close > open) ? entry.mid(open + 1, close - open - 1) : entry;
        const QStringList list = patterns.split(QLatin1Char(' '), Qt::SkipEmptyParts);
        if (!list.isEmpty())
            out.push_back({entry.toStdWString(), list.join(QLatin1Char(';')).toStdWString()});
    }
    return out;
}

// FOS_FORCESHOWHIDDEN alone does not reach the most common hidden install root: with Explorer's
// default "don't show hidden items", the dialog lists ProgramData in C:\ and Default in C:\Users,
// but inside the user-profile folder it still leaves AppData out. So AppData, and ProgramData with
// it, are pinned at the top of the navigation pane (they show up under 「应用程序链接」).
void pinHiddenRoots(IFileOpenDialog* dialog)
{
    const QString localAppData = qEnvironmentVariable("LOCALAPPDATA"); // <profile>\AppData\Local
    const QStringList roots = {
        localAppData.isEmpty() ? QString() : QFileInfo(localAppData).absolutePath(),
        qEnvironmentVariable("ProgramData"),
    };
    for (const QString& root : roots) {
        if (root.isEmpty() || !QFileInfo(root).isDir())
            continue;
        const QString native = QDir::toNativeSeparators(root);
        ComPtr<IShellItem> item;
        if (SUCCEEDED(::SHCreateItemFromParsingName(reinterpret_cast<const wchar_t*>(native.utf16()), nullptr,
                                                    IID_PPV_ARGS(item.GetAddressOf()))))
            dialog->AddPlace(item.Get(), FDAP_TOP);
    }
}

Outcome showOpenDialog(QWidget* parent, const QString& title, const QString& filter, bool folders,
                       QString* picked)
{
    // Qt's GUI thread is already an STA (the platform plugin calls OleInitialize), so this only
    // takes another reference (S_FALSE), balanced by ComScope. An MTA thread can't host the dialog
    // at all (RPC_E_CHANGED_MODE) — leave that case to QFileDialog.
    if (FAILED(::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)))
        return Outcome::Unavailable;
    struct ComScope {
        ~ComScope() { ::CoUninitialize(); }
    } comScope; // declared before any COM pointer, so it runs after they have all been released

    ComPtr<IFileOpenDialog> dialog;
    if (FAILED(::CoCreateInstance(__uuidof(FileOpenDialog), nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(dialog.GetAddressOf()))))
        return Outcome::Unavailable;

    FILEOPENDIALOGOPTIONS options = 0;
    if (FAILED(dialog->GetOptions(&options)))
        return Outcome::Unavailable;
    // FORCESHOWHIDDEN (with the pins below) is the reason this helper exists. FORCEFILESYSTEM: only
    // items that exist on disk can be returned (SFGAO_FILESYSTEM), so SIGDN_FILESYSPATH below always
    // has a real path to give — never a Control Panel / phone / library item.
    options |= FOS_FORCESHOWHIDDEN | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_FILEMUSTEXIST
             | FOS_NOCHANGEDIR;
    if (folders)
        options |= FOS_PICKFOLDERS;
    if (FAILED(dialog->SetOptions(options)))
        return Outcome::Unavailable;

    if (!title.isEmpty())
        dialog->SetTitle(reinterpret_cast<const wchar_t*>(title.utf16()));
    // Not in the folder picker: its caller is 「信任文件夹…」, where the pin would put "the whole of
    // AppData" — the most common drop location — one click away as a folder to trust, and the
    // broad-folder warning there (isBroadFolder in EventViews.cpp) doesn't cover it. Hidden folders
    // are still listed; an AppData path can be typed or pasted into the address bar.
    if (!folders)
        pinHiddenRoots(dialog.Get());

    // The filter specs point into `types`; both stay alive until Show() has returned.
    const std::vector<FileType> types = folders ? std::vector<FileType>() : parseFilter(filter);
    std::vector<COMDLG_FILTERSPEC> specs;
    specs.reserve(types.size());
    for (const FileType& t : types)
        specs.push_back({t.name.c_str(), t.spec.c_str()});
    if (!specs.empty() && SUCCEEDED(dialog->SetFileTypes(static_cast<UINT>(specs.size()), specs.data())))
        dialog->SetFileTypeIndex(1); // 1-based

    HWND owner = nullptr;
    if (QWidget* top = parent ? parent->window() : nullptr)
        owner = reinterpret_cast<HWND>(top->winId());

    const HRESULT shown = dialog->Show(owner); // modal to `owner`; returns once the user is done
    eatMouseMove();
    if (FAILED(shown)) {
        if (shown != HRESULT_FROM_WIN32(ERROR_CANCELLED))
            qWarning("ui::FilePicker: IFileDialog::Show failed (0x%08lx)", static_cast<unsigned long>(shown));
        return Outcome::Cancelled;
    }

    ComPtr<IShellItem> item;
    if (FAILED(dialog->GetResult(item.GetAddressOf())) || !item)
        return Outcome::Cancelled;
    PWSTR path = nullptr;
    if (FAILED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) || !path)
        return Outcome::Cancelled;
    *picked = QDir::fromNativeSeparators(QString::fromWCharArray(path));
    ::CoTaskMemFree(path);
    return Outcome::Picked;
}

} // namespace
#endif // Q_OS_WIN

QString ui::pickExistingFile(QWidget* parent, const QString& title, const QString& filter)
{
#ifdef Q_OS_WIN
    QString picked;
    if (showOpenDialog(parent, title, filter, /*folders*/ false, &picked) != Outcome::Unavailable)
        return picked;
#endif
    return QFileDialog::getOpenFileName(parent, title, QString(), filter);
}

QString ui::pickExistingFolder(QWidget* parent, const QString& title)
{
#ifdef Q_OS_WIN
    QString picked;
    if (showOpenDialog(parent, title, QString(), /*folders*/ true, &picked) != Outcome::Unavailable)
        return picked;
#endif
    return QFileDialog::getExistingDirectory(parent, title);
}
