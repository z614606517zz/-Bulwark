// 隔离区 —— 被移出原位置的威胁文件:还原 / 永久删除,可多选批量处理。
//
// 每一步都先确认(还原会让文件回到原路径、可能再次运行;删除不可撤销),结果以服务端逐条回执
// (quarantineActionResult)为准汇总成一条横幅 —— 成功几个、哪几个没成功、为什么。
#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "design/Banner.h"
#include "design/Confirm.h"
#include "design/Format.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "ipc/IpcClient.h"
#include "Nav.h"

#include <QDesktopServices>
#include <QFileInfo>
#include <QHash>
#include <QMenu>
#include <QPushButton>
#include <QTimer>
#include <QUrl>

#include <algorithm>
#include <memory>

using evtfmt::u;
using bulwark::ipc::QuarantineItemPayload;

namespace {

RecordView itemView(const QuarantineItemPayload& it)
{
    RecordView v;
    v.icon = QStringLiteral("lock");
    v.iconColor = theme::warning();
    v.title = it.fileName.isEmpty() ? QFileInfo(it.originalPath).fileName() : it.fileName;
    v.subtitle = evtfmt::nativePath(it.originalPath);
    v.subtitleMono = true;
    if (!it.reason.isEmpty())
        v.chips << it.reason;
    v.chips << fmt::bytes(it.size); // the right cluster shows the time; size rides with the facts
    v.meta = fmt::bytes(it.size);
    v.time = it.quarantinedUtc;
    v.tooltip = evtfmt::nativePath(it.originalPath);
    v.haystack = QStringList{it.fileName, it.originalPath, it.reason, it.sha256}.join(QLatin1Char(' '));
    v.key = it.id.toString(QUuid::WithoutBraces);
    return v;
}

enum class Op { Restore, Delete };

// One batch of restore / delete requests, reported as ONE banner once every
// receipt is in (or after a timeout, naming what never answered).
struct Batch {
    Op op = Op::Restore;
    QHash<QUuid, QString> waiting; // id -> file name
    QStringList done;
    QStringList failed;            // "name:reason"
};

} // namespace

QWidget* pages::quarantine(IpcClient* ipc)
{
    auto* page = new RecordBrowser;
    page->setIdentity(identity::page(nav::Quarantine));
    page->setMultiSelect(true);
    page->searchBox()->setPlaceholderText(u("搜索文件名 / 原路径 / 原因 / SHA-256…"));
    page->setNoDataContent(QStringLiteral("lock"), u("隔离区是空的"),
                           u("被判定为恶意并移出原位置的文件会出现在这里,可以还原或永久删除。"));
    auto store = std::make_shared<RecordStore<QuarantineItemPayload>>(page->model(), &itemView);
    auto batch = std::make_shared<Batch>();
    auto batchSeq = std::make_shared<int>(0);

    const auto finish = [page, batch] {
        if (batch->done.isEmpty() && batch->failed.isEmpty() && batch->waiting.isEmpty())
            return;
        const QString verb = batch->op == Op::Restore ? u("还原") : u("永久删除");
        QStringList bad = batch->failed;
        for (const QString& name : std::as_const(batch->waiting))
            bad << u("%1:没有收到服务回执").arg(name);
        QString text;
        if (bad.isEmpty())
            text = batch->done.size() == 1 ? u("已%1 %2。").arg(verb, batch->done.first())
                                           : u("已%1 %2 个文件。").arg(verb).arg(batch->done.size());
        else if (batch->done.isEmpty())
            text = u("未能%1:%2").arg(verb, bad.join(u(";")));
        else
            text = u("已%1 %2 个;%3 个未能%1:%4").arg(verb).arg(batch->done.size()).arg(bad.size()).arg(bad.join(u(";")));
        Banner* b = ui::notify(page, bad.isEmpty() ? ui::Tone::Success : ui::Tone::Danger, text);
        if (b && bad.isEmpty() && batch->op == Op::Restore)
            b->setTimeout(6000);
        *batch = Batch{};
    };

    const auto runOp = [page, ipc, store, batch, batchSeq, finish](Op op, const QList<int>& rows) {
        QList<QuarantineItemPayload> items;
        for (int r : rows)
            if (const QuarantineItemPayload* it = store->itemAt(r))
                items << *it;
        if (items.isEmpty())
            return;
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法操作隔离区。"));
            return;
        }
        QStringList names;
        for (const QuarantineItemPayload& it : items)
            names << (it.fileName.isEmpty() ? evtfmt::nativePath(it.originalPath) : it.fileName);
        ui::ConfirmSpec c;
        if (op == Op::Restore) {
            c.risk = ui::Risk::Caution;
            c.title = items.size() == 1 ? u("还原文件") : u("还原 %1 个文件").arg(items.size());
            c.summary = u("文件会被放回隔离前的原路径。");
            c.consequences << u("如果它确实是恶意程序,还原后可能再次运行");
            c.confirmText = u("还原");
        } else {
            c.risk = ui::Risk::Danger;
            c.title = items.size() == 1 ? u("永久删除文件") : u("永久删除 %1 个文件").arg(items.size());
            c.summary = u("文件会从隔离区里彻底删除。");
            c.consequences << u("删除后无法还原,也无法再用于取证分析");
            c.confirmText = u("永久删除");
        }
        c.subjectLabel = items.size() == 1 ? u("文件") : u("文件(%1 个)").arg(items.size());
        c.subject = items.size() == 1 ? evtfmt::nativePath(items.first().originalPath)
                                      : names.mid(0, 8).join(QLatin1Char('\n'))
                                            + (names.size() > 8 ? u("\n… 另有 %1 个").arg(names.size() - 8) : QString());
        if (!ui::confirm(page, c))
            return;
        finish(); // flush an earlier batch still waiting
        batch->op = op;
        for (int i = 0; i < items.size(); ++i)
            batch->waiting.insert(items[i].id, names[i]);
        const int seq = ++*batchSeq;
        QTimer::singleShot(10000, page, [batchSeq, seq, finish] {
            if (*batchSeq == seq)
                finish();
        });
        for (const QuarantineItemPayload& it : items) {
            if (op == Op::Restore)
                ipc->quarantineRestore(it.id);
            else
                ipc->quarantineDelete(it.id);
        }
        page->clearSelection();
    };

    QObject::connect(ipc, &IpcClient::quarantineActionResult, page,
                     [batch, finish](const bulwark::ipc::QuarantineActionResultPayload& r) {
        const auto it = batch->waiting.constFind(r.id);
        if (it == batch->waiting.constEnd())
            return;
        const QString name = it.value();
        batch->waiting.remove(r.id);
        if (r.success)
            batch->done << name;
        else
            batch->failed << u("%1:%2").arg(name, r.message.isEmpty() ? u("服务没有给出原因") : r.message);
        if (batch->waiting.isEmpty())
            finish();
    });

    // ---- batch bar · inspector · menu -------------------------------------------------------------------
    page->batchBar()->addAction(QStringLiteral("undo"), u("还原"), "ghost",
                                [page, runOp] { runOp(Op::Restore, page->selectedSourceRows()); });
    page->batchBar()->addAction(QStringLiteral("trash"), u("永久删除"), "danger",
                                [page, runOp] { runOp(Op::Delete, page->selectedSourceRows()); });

    page->setInspectorBuilder([store, runOp](Inspector* in, int row) {
        const QuarantineItemPayload* it = store->itemAt(row);
        if (!it)
            return;
        in->setHeader(QStringLiteral("lock"), theme::warning(), it->fileName.isEmpty() ? u("隔离文件") : it->fileName,
                      fmt::bytes(it->size) + u(" · 隔离于 ") + fmt::relativeTime(it->quarantinedUtc));
        in->addLead(u("已从原位置移入隔离区。还原会把它放回原路径;永久删除不可撤销。"));
        const Inspector::FieldFlags monoCopy = Inspector::Mono | Inspector::Copy;
        QVBoxLayout* s = in->addSection(u("文件"));
        in->addField(s, u("原始路径"), evtfmt::nativePath(it->originalPath), monoCopy);
        in->addField(s, u("隔离原因"), it->reason);
        in->addField(s, u("大小"), fmt::bytes(it->size));
        in->addField(s, QStringLiteral("SHA-256"), it->sha256, monoCopy);
        in->addField(s, u("隔离时间"), fmt::absoluteTime(it->quarantinedUtc));
        if (it->actorPid > 0)
            in->addField(s, u("当时的进程"), QStringLiteral("PID %1").arg(it->actorPid), Inspector::Mono);

        in->addAction(QStringLiteral("undo"), u("还原"), "ghost", [runOp, row] { runOp(Op::Restore, {row}); });
        in->addAction(QStringLiteral("trash"), u("永久删除"), "danger", [runOp, row] { runOp(Op::Delete, {row}); });
        auto* menu = new QMenu;
        const QString sha = it->sha256;
        const QString path = evtfmt::nativePath(it->originalPath);
        if (!sha.isEmpty()) {
            pagekit::menuAction(menu, QStringLiteral("cloud"), u("查询云信誉"), in, [sha, path] {
                nav::go(QString::fromLatin1(nav::Reputation),
                        {{QStringLiteral("sha256"), sha}, {QStringLiteral("path"), path}});
            });
            pagekit::menuAction(menu, QStringLiteral("copy"), u("复制 SHA-256"), in, [sha] {
                if (QClipboard* cb = QGuiApplication::clipboard())
                    cb->setText(sha);
            });
        }
        pagekit::menuAction(menu, QStringLiteral("folder"), u("打开原位置所在文件夹"), in, [path] {
            QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(path).absolutePath()));
        });
        in->addMenu(menu);
    });
    page->setContextMenuBuilder([page, runOp](QMenu* m, const QList<int>& rows) {
        if (rows.isEmpty())
            return;
        const QString n = rows.size() == 1 ? QString() : u(" %1 个文件").arg(rows.size());
        pagekit::menuAction(m, QStringLiteral("undo"), u("还原") + n, page, [runOp, rows] { runOp(Op::Restore, rows); });
        pagekit::menuAction(m, QStringLiteral("trash"), u("永久删除") + n + u("…"), page,
                            [runOp, rows] { runOp(Op::Delete, rows); });
    });

    // ---- header: ⋯ refresh ---------------------------------------------------------------------------------
    QHBoxLayout* actions = pagekit::headerActions(page);
    auto* total = ui::label(QString(), "muted");
    actions->addWidget(total);
    QMenu* more = pagekit::headerMenu(actions);
    const auto reload = [page, ipc] {
        if (!ipc->isConnected())
            return;
        page->setLoading(true);
        ipc->requestQuarantine();
    };
    pagekit::menuAction(more, QStringLiteral("refresh"), u("刷新列表"), page, reload);

    QObject::connect(ipc, &IpcClient::quarantineReceived, page,
                     [page, store, total](const QList<QuarantineItemPayload>& items) {
        QList<QuarantineItemPayload> list = items;
        std::stable_sort(list.begin(), list.end(), [](const QuarantineItemPayload& a, const QuarantineItemPayload& b) {
            return a.quarantinedUtc > b.quarantinedUtc;
        });
        store->reset(list);
        page->setLoading(false);
        qint64 bytes = 0;
        for (const QuarantineItemPayload& it : items)
            bytes += it.size;
        total->setText(items.isEmpty() ? QString() : u("共占用 %1").arg(fmt::bytes(bytes)));
    });
    pagekit::onConnected(page, ipc, page, 0, reload);
    return page;
}
