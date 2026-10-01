// 信任名单 —— 受信任的程序与文件夹直接放行。
//
// 信任是裁决流水线第 1 步的【无条件放行通道】,并且会让后台跳过全部扫描(云查毒 / IP 情报)。
// 所以这页把「信任的到底是什么」放在最显眼的位置:文件夹单独成组并用警示色 ——
// 信任错一个目录,就等于对整个目录停掉了防护。
//
// 添加(选择文件 / 文件夹,或从资源管理器拖进来)一律先确认、说清代价;增删都以服务端回推的
// 最新列表为准再报告结果。
#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "dialogs/EventViews.h"
#include "design/Banner.h"
#include "design/Confirm.h"
#include "design/DropZone.h"
#include "design/FilePicker.h"
#include "design/Format.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "ipc/IpcClient.h"

#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QMenu>
#include <QPushButton>
#include <QTimer>
#include <QUrl>

#include <algorithm>
#include <memory>

using evtfmt::u;
using bulwark::DefenseRule;

namespace {

const QString kFolders = QStringLiteral("folders");
const QString kFiles = QStringLiteral("files");

bool isDir(const DefenseRule& r) { return r.actorPath.isEmpty() && !r.actorPattern.isEmpty(); }

// The folder a directory trust covers ("D:\Tools\*" -> "D:\Tools").
QString pathOf(const DefenseRule& r)
{
    if (!isDir(r))
        return evtfmt::nativePath(r.actorPath);
    QString p = evtfmt::nativePath(r.actorPattern);
    if (p.endsWith(QStringLiteral("\\*")))
        p.chop(2);
    return p;
}

QString noteOf(const DefenseRule& r)
{
    QString n = r.note;
    const QString tag = DefenseRule::trustNoteTag();
    if (n.startsWith(tag))
        n = n.mid(tag.size()).trimmed();
    return n;
}

// A trusted folder keeps its caution colour — trusting the wrong one switches
// protection off for everything in it. A trusted program is shown in the file
// hue (design/Identity.h) rather than azurite: it is a kind, not an info state.
QColor tintOf(const DefenseRule& r)
{
    return isDir(r) ? theme::warning() : identity::kind(identity::Kind::File);
}

QString leafName(const QString& path)
{
    const QString n = QFileInfo(path).fileName();
    return n.isEmpty() ? path : n;
}

RecordView trustView(const DefenseRule& r)
{
    RecordView v;
    const bool dir = isDir(r);
    const QString path = pathOf(r);
    v.icon = dir ? QStringLiteral("folder") : QStringLiteral("file");
    v.iconColor = tintOf(r);
    v.title = leafName(path);
    v.subtitle = path;
    v.subtitleMono = true;
    if (const QString n = noteOf(r); !n.isEmpty())
        v.chips << n;
    v.time = r.createdUtc;
    v.tooltip = path;
    v.haystack = path + QLatin1Char(' ') + r.note;
    v.key = r.id.toString(QUuid::WithoutBraces);
    return v;
}

} // namespace

QWidget* pages::trust(IpcClient* ipc)
{
    auto* page = new RecordBrowser;
    page->setIdentity(identity::page(nav::Trust));
    page->setGrouped(true, /*collapsible*/ true);
    page->searchBox()->setPlaceholderText(u("搜索路径 / 备注…"));
    auto store = std::make_shared<RecordStore<DefenseRule>>(page->model(), &trustView);

    // ui::pick* instead of QFileDialog: Qt's native dialog hides hidden folders unless Explorer shows
    // them, so under the Windows default %LOCALAPPDATA% / %ProgramData% — home to many installed
    // programs — can't even be browsed into (see design/FilePicker.h).
    //
    // Besides .exe the filter offers .com / .scr, which also run as processes. Scripts and installers
    // are left out on purpose: a trust entry is compared with the acting process's image path only,
    // and for a .ps1 / .bat / .msi that process is powershell / cmd / msiexec, so the entry would
    // never match. 「所有文件」 is still there for anything else.
    const auto addFile = [page, ipc] {
        const QString f = ui::pickExistingFile(page, u("选择要信任的程序"),
                                               u("可执行文件 (*.exe *.com *.scr *.dll);;所有文件 (*.*)"));
        if (!f.isEmpty())
            evtview::trust(page, ipc, f, false, u("用户手动信任"));
    };
    const auto addFolder = [page, ipc] {
        const QString d = ui::pickExistingFolder(page, u("选择要信任的文件夹(其中运行的所有程序将不再检测)"));
        if (!d.isEmpty())
            evtview::trust(page, ipc, d, true, u("用户手动信任文件夹"));
    };
    page->setNoDataContent(QStringLiteral("trust"), u("信任名单是空的"),
                           u("被信任的程序或文件夹会直接放行,并跳过全部检测。只把你确认安全的东西放进来。"),
                           u("信任程序…"), addFile);

    page->setInspectorBuilder([store, ipc, page](Inspector* in, int row) {
        const DefenseRule* r = store->itemAt(row);
        if (!r)
            return;
        const bool dir = isDir(*r);
        const QString path = pathOf(*r);
        in->setHeader(dir ? QStringLiteral("folder") : QStringLiteral("file"), tintOf(*r), leafName(path),
                      dir ? u("信任的文件夹") : u("信任的程序"));
        in->addLead(dir ? u("这个文件夹及其子目录中运行的所有程序都完全跳过检测,直接放行。")
                        : u("这个程序的所有行为都直接放行,并跳过云查毒与 IP 情报。"));
        QVBoxLayout* s = in->addSection(u("信任项"));
        in->addField(s, dir ? u("文件夹") : u("程序"), path, Inspector::Mono | Inspector::Copy);
        if (dir)
            in->addField(s, u("匹配"), evtfmt::nativePath(r->actorPattern), Inspector::Mono);
        in->addField(s, u("备注"), noteOf(*r));
        in->addField(s, u("添加时间"), fmt::absoluteTime(r->createdUtc));
        in->addField(s, u("规则 ID"), r->id.toString(QUuid::WithoutBraces), Inspector::Mono | Inspector::Copy);
        if (dir)
            in->setNote(u("今后放进这个文件夹的新程序同样不受检测。"), theme::warning());

        const DefenseRule rule = *r;
        in->addAction(QStringLiteral("trash"), u("移除信任"), "danger", [page, ipc, rule, path, dir] {
            if (!ipc->isConnected()) {
                ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法移除信任项。"));
                return;
            }
            ui::ConfirmSpec c;
            c.title = dir ? u("移除信任的文件夹") : u("移除信任的程序");
            c.summary = u("移除后恢复正常检测:它的行为会重新经过规则与威胁检测。");
            c.subjectLabel = dir ? u("文件夹") : u("程序");
            c.subject = path;
            c.confirmText = u("移除信任");
            if (!ui::confirm(page, c))
                return;
            const QUuid id = rule.id;
            auto* guard = new QObject(page);
            QObject::connect(ipc, &IpcClient::trustReceived, guard,
                             [guard, page, id, path](const QList<DefenseRule>& list) {
                if (std::any_of(list.cbegin(), list.cend(), [id](const DefenseRule& x) { return x.id == id; }))
                    return; // may answer an earlier request; wait for the next one
                ui::notify(page, ui::Tone::Success, u("已移除信任:%1").arg(path));
                guard->deleteLater();
            });
            QTimer::singleShot(8000, guard, [guard, page, path] {
                ui::notify(page, ui::Tone::Warning, u("「%1」仍在信任名单里,移除没有生效。").arg(path));
                guard->deleteLater();
            });
            ipc->removeTrust(id);
        });
        in->addAction(QStringLiteral("folder"), u("打开位置"), "ghost", [path, dir] {
            QDesktopServices::openUrl(QUrl::fromLocalFile(dir ? path : QFileInfo(path).absolutePath()));
        });
    });
    page->setContextMenuBuilder([page, store](QMenu* m, const QList<int>& rows) {
        if (rows.size() != 1)
            return;
        const DefenseRule* r = store->itemAt(rows.first());
        if (!r)
            return;
        const QString path = pathOf(*r);
        pagekit::menuAction(m, QStringLiteral("copy"), u("复制路径"), page, [path] {
            if (QClipboard* cb = QGuiApplication::clipboard())
                cb->setText(path);
        });
    });

    // ---- header: trust folder · trust program · ⋯ refresh ------------------------------------------------
    QHBoxLayout* actions = pagekit::headerActions(page);
    QObject::connect(pagekit::headerButton(actions, QStringLiteral("folder"), u("信任文件夹…")), &QPushButton::clicked,
                     page, addFolder);
    QObject::connect(pagekit::headerButton(actions, QStringLiteral("plus"), u("信任程序…"), "primary"),
                     &QPushButton::clicked, page, addFile);
    QMenu* more = pagekit::headerMenu(actions);
    const auto reload = [page, ipc] {
        if (!ipc->isConnected())
            return;
        page->setLoading(true);
        ipc->requestTrust();
    };
    pagekit::menuAction(more, QStringLiteral("refresh"), u("刷新列表"), page, reload);

    // Drag files / folders in from Explorer: each one still asks first.
    ui::acceptFileDrops(page, u("松开以加入信任名单"), [page, ipc](const QStringList& paths) {
        for (const QString& p : paths)
            evtview::trust(page, ipc, p, QFileInfo(p).isDir(), u("拖入信任"));
    });

    QObject::connect(ipc, &IpcClient::trustReceived, page, [page, store](const QList<DefenseRule>& entries) {
        QList<DefenseRule> list = entries;
        std::stable_sort(list.begin(), list.end(),
                         [](const DefenseRule& a, const DefenseRule& b) { return a.createdUtc > b.createdUtc; });
        store->resetGrouped(
            list, [](const DefenseRule& r) { return isDir(r) ? kFolders : kFiles; },
            [](const QString& g, const QList<const DefenseRule*>&) {
                RecordView h;
                const bool folders = g == kFolders;
                h.title = folders ? u("文件夹") : u("程序");
                h.groupNote = folders ? u("整个目录跳过检测") : QString();
                h.groupColor = folders ? theme::warning() : QColor();
                return h;
            },
            {kFolders, kFiles});
        page->setLoading(false);
    });
    pagekit::onConnected(page, ipc, page, 0, reload);
    return page;
}
