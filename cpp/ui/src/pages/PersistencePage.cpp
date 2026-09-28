// 自启动项 —— 按需枚举 9 类持久化点(只读扫描),按类别分组、按风险着色;清理是唯一的写操作。
//
// 扫描本身绝不修改任何自启动项。清理(服务端 ThreatRemediator)必须由用户在检查器里显式点击,
// 先确认并说清后果:文件类载荷进隔离区(可还原),注册表 / 计划任务 / 服务的移除【不可撤销】,
// 清理后该项会加入内核注册表硬拦,阻止被立刻重建。结果按服务端回执如实展示,并保留在该项的
// 检查器里(清理失败时那一项仍在列表中,原因就在它下面)。
#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "dialogs/EventViews.h"
#include "design/Banner.h"
#include "design/Confirm.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Segmented.h"
#include "ipc/IpcClient.h"
#include "Nav.h"

#include <QDesktopServices>
#include <QFileInfo>
#include <QHash>
#include <QMenu>
#include <QPushButton>
#include <QUrl>

#include <algorithm>
#include <memory>

using evtfmt::u;
using bulwark::PersistenceCategory;
using bulwark::PersistenceEntry;

namespace {

enum Seg { SegAll = 0, SegWatch, SegUnsigned };

QString categoryLabel(PersistenceCategory c)
{
    using C = PersistenceCategory;
    switch (c) {
    case C::RegistryRun:     return u("注册表 Run");
    case C::RegistryRunOnce: return u("注册表 RunOnce");
    case C::StartupFolder:   return u("启动文件夹");
    case C::ScheduledTask:   return u("计划任务");
    case C::Service:         return u("服务");
    case C::WmiSubscription: return u("WMI 订阅");
    case C::IfeoDebugger:    return u("映像劫持");
    case C::Winlogon:        return u("Winlogon");
    case C::AppInitDll:      return u("AppInit_DLLs");
    case C::Other:           break;
    }
    return u("其它");
}

QString categoryGlyph(PersistenceCategory c)
{
    using C = PersistenceCategory;
    switch (c) {
    case C::RegistryRun:
    case C::RegistryRunOnce: return QStringLiteral("sliders");
    case C::StartupFolder:   return QStringLiteral("folder");
    case C::ScheduledTask:   return QStringLiteral("clock");
    case C::Service:         return QStringLiteral("server");
    case C::WmiSubscription: return QStringLiteral("zap");
    case C::IfeoDebugger:    return QStringLiteral("target");
    case C::Winlogon:        return QStringLiteral("user");
    case C::AppInitDll:      return QStringLiteral("layers");
    case C::Other:           break;
    }
    return QStringLiteral("power");
}

// The kind of each persistence point (design/Identity.h), the colour twin of
// categoryGlyph(): registry violet, startup folder olive, scheduled task rose,
// service orchid… — the same hues as those things everywhere else. Shown for an
// entry only while its risk has nothing to say (entryColor).
identity::Kind categoryKind(PersistenceCategory c)
{
    using C = PersistenceCategory;
    using K = identity::Kind;
    switch (c) {
    case C::RegistryRun:
    case C::RegistryRunOnce:
    case C::Winlogon:        return K::Registry;
    case C::StartupFolder:   return K::File;
    case C::ScheduledTask:   return K::Task;
    case C::Service:         return K::Service;
    case C::WmiSubscription: return K::Network;
    case C::IfeoDebugger:    return K::Process;
    case C::AppInitDll:      return K::Module;
    case C::Other:           break;
    }
    return K::Neutral;
}

// Invalid for 「其它」: its group header then takes the page's own hue.
QColor categoryColor(PersistenceCategory c)
{
    const identity::Kind k = categoryKind(c);
    return k == identity::Kind::Neutral ? QColor() : identity::kind(k);
}

QColor entryColor(const PersistenceEntry& e)
{
    if (e.riskScore >= 50)
        return evtfmt::riskColor(e.riskScore);
    const QColor k = categoryColor(e.category);
    return k.isValid() ? k : theme::textSecondary();
}

QString commandOf(const PersistenceEntry& e) { return e.command.isEmpty() ? e.imagePath : e.command; }

evtfmt::Badge signatureOf(const PersistenceEntry& e)
{
    if (!e.isSigned.has_value())
        return {QString(), QColor()};
    return *e.isSigned ? evtfmt::Badge{u("已签名"), theme::success()} : evtfmt::Badge{u("无签名"), theme::warning()};
}

RecordView entryView(const PersistenceEntry& e)
{
    RecordView v;
    v.icon = categoryGlyph(e.category);
    v.iconColor = entryColor(e);
    v.title = e.name.isEmpty() ? categoryLabel(e.category) : e.name;
    v.subtitle = commandOf(e);
    v.subtitleMono = true;
    for (int i = 0; i < e.techniques.size() && i < 2; ++i)
        v.chips << e.techniques.at(i);
    if (e.riskScore > 0) {
        v.score = QString::number(e.riskScore);
        v.scoreColor = evtfmt::riskColor(e.riskScore);
    }
    const evtfmt::Badge sig = signatureOf(e);
    v.pill = sig.text;
    v.pillColor = sig.color;
    v.accent = e.riskScore >= 80 ? theme::danger() : QColor();
    v.tooltip = e.location;
    v.haystack = QStringList{e.name, e.location, e.command, e.imagePath, e.publisher, categoryLabel(e.category),
                             e.techniques.join(QLatin1Char(' ')), e.riskReasons.join(QLatin1Char(' '))}
                     .join(QLatin1Char(' '));
    v.key = e.id;
    return v;
}

} // namespace

QWidget* pages::persistence(IpcClient* ipc)
{
    auto* page = new RecordBrowser;
    page->setIdentity(identity::page(nav::Persistence));
    page->setGrouped(true, /*collapsible*/ true);
    page->searchBox()->setPlaceholderText(u("搜索名称 / 位置 / 命令 / 发布者…"));
    auto store = std::make_shared<RecordStore<PersistenceEntry>>(page->model(), &entryView);
    // 清理回执按条目 id 留存:清理失败的那一项仍在列表里,原因就显示在它的检查器中。
    auto results = std::make_shared<QHash<QString, bulwark::ipc::PersistenceCleanupResultPayload>>();

    const auto scan = [page, ipc] {
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法扫描自启动项。"));
            return;
        }
        page->setLoading(true);
        ipc->requestPersistence();
    };
    page->setNoDataContent(QStringLiteral("power"), u("还没有扫描自启动项"),
                           u("枚举注册表 Run、启动文件夹、计划任务、服务、WMI 订阅、映像劫持等 9 类开机持久化位置。"
                             "扫描是只读的,不会修改任何一项。"),
                           u("立即扫描"), scan);

    // ---- filters ---------------------------------------------------------------------------------------
    Segmented* seg = page->segments();
    seg->addSegment(u("全部"));
    seg->addSegment(u("需留意"));
    seg->addSegment(u("无签名"));
    seg->setAccent(SegWatch, theme::warning());
    page->setPredicate([store, seg](int row) {
        const PersistenceEntry* e = store->itemAt(row);
        if (!e)
            return true;
        switch (seg->currentIndex()) {
        case SegWatch:    return e->riskScore >= 50;
        case SegUnsigned: return e->isSigned.has_value() && !*e->isSigned;
        default:          return true;
        }
    });
    page->setClearFilters([seg] { seg->setCurrentIndex(SegAll); });
    QObject::connect(seg, &Segmented::currentChanged, page, [page] { page->refilter(); });
    const auto updateCounts = [store, seg] {
        int n[3] = {0, 0, 0};
        for (const PersistenceEntry& e : store->items()) {
            ++n[SegAll];
            if (e.riskScore >= 50) ++n[SegWatch];
            if (e.isSigned.has_value() && !*e.isSigned) ++n[SegUnsigned];
        }
        for (int i = 0; i < 3; ++i)
            seg->setCount(i, n[i]);
    };

    // ---- inspector ---------------------------------------------------------------------------------------
    page->setInspectorBuilder([store, ipc, page, results](Inspector* in, int row) {
        const PersistenceEntry* pe = store->itemAt(row);
        if (!pe)
            return;
        const PersistenceEntry e = *pe;
        in->setHeader(categoryGlyph(e.category), entryColor(e), e.name.isEmpty() ? categoryLabel(e.category) : e.name,
                      categoryLabel(e.category));
        in->addLead(e.category == PersistenceCategory::Service
                        ? u("以 Windows 服务的形式注册在系统里,可随系统启动自动运行。")
                        : u("每次开机或登录时,都会自动运行这一项。"));
        QList<QPair<QString, QColor>> chips;
        if (e.riskScore > 0)
            chips << qMakePair(QStringLiteral("%1 %2").arg(evtfmt::riskLevel(e.riskScore)).arg(e.riskScore),
                               evtfmt::riskColor(e.riskScore));
        if (const evtfmt::Badge sig = signatureOf(e); !sig.text.isEmpty())
            chips << qMakePair(e.publisher.isEmpty() ? sig.text : sig.text + u(" · ") + e.publisher, sig.color);
        for (const QString& t : e.techniques)
            chips << qMakePair(t, theme::info());
        if (!chips.isEmpty())
            in->addChips(nullptr, chips);

        if (const auto it = results->constFind(e.id); it != results->constEnd()) {
            QVBoxLayout* rs = in->addSection(u("上次清理"));
            in->addText(rs, it->message, it->success ? "secondary" : "title");
            for (const bulwark::ipc::RemediationSkippedItem& s : it->skipped)
                in->addText(rs, u("未能处理:%1 —— %2").arg(s.target, s.reason), "muted");
        }

        const Inspector::FieldFlags monoCopy = Inspector::Mono | Inspector::Copy;
        QVBoxLayout* s = in->addSection(u("自启动项"));
        in->addField(s, u("类别"), categoryLabel(e.category));
        in->addField(s, u("位置"), e.location, monoCopy);
        in->addField(s, u("名称"), e.name);
        in->addField(s, u("命令"), e.command, monoCopy);
        if (!e.imagePath.isEmpty() && e.imagePath != e.command)
            in->addField(s, u("映像路径"), evtfmt::nativePath(e.imagePath), monoCopy);
        in->addField(s, u("数字签名"), !e.isSigned.has_value() ? u("未采集")
                                        : *e.isSigned ? (e.publisher.isEmpty() ? u("有效") : u("有效 · ") + e.publisher)
                                                      : u("无 / 无效"));
        if (!e.riskReasons.isEmpty()) {
            s = in->addSection(u("风险因素"));
            for (const QString& r : e.riskReasons)
                in->addText(s, QStringLiteral("· ") + r);
        }

        in->addAction(QStringLiteral("shield-x"), u("清理此项…"), "danger", [page, ipc, e] {
            if (!ipc->isConnected()) {
                ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法执行清理。"));
                return;
            }
            // 清理是不可逆动作(改注册表 / 删计划任务 / 停服务),必须显式二次确认并说清后果。
            ui::ConfirmSpec c;
            c.risk = ui::Risk::Danger;
            c.title = u("清理自启动项");
            c.summary = u("将移除这一项开机持久化,并处理它指向的程序。");
            c.consequences << u("指向的可执行文件会被移入隔离区(可以还原)")
                           << u("注册表项 / 计划任务 / 服务的移除不可撤销")
                           << u("清理后该项会被加入内核注册表硬拦,阻止被立刻重建")
                           << u("如果这是你自己安装的正常软件,请改用「信任名单」,不要清理");
            c.subjectLabel = categoryLabel(e.category);
            c.subject = u("%1\n%2\n%3").arg(e.name, e.location, commandOf(e));
            c.confirmText = u("清理");
            if (!ui::confirm(page, c))
                return;
            ui::notify(page, ui::Tone::Info, u("正在清理「%1」…").arg(e.name));
            ipc->requestPersistenceCleanup(e);
        });
        auto* menu = new QMenu;
        const QString image = evtfmt::nativePath(e.imagePath);
        if (!image.isEmpty()) {
            pagekit::menuAction(menu, QStringLiteral("trust"), u("信任这个程序…"), in,
                                [in, ipc, image] { evtview::trust(in, ipc, image, false, u("从自启动项信任")); });
            pagekit::menuAction(menu, QStringLiteral("folder"), u("打开所在文件夹"), in, [image] {
                QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(image).absolutePath()));
            });
        }
        if (!commandOf(e).isEmpty())
            pagekit::menuAction(menu, QStringLiteral("copy"), u("复制命令"), in, [cmd = commandOf(e)] {
                if (QClipboard* cb = QGuiApplication::clipboard())
                    cb->setText(cmd);
            });
        in->addMenu(menu);
        if (e.riskScore < 50)
            in->setNote(u("风险不高、来源熟悉的项,多半是正常软件:需要放行就信任它,不要清理。"));
    });

    // ---- header: rescan -----------------------------------------------------------------------------------
    QHBoxLayout* actions = pagekit::headerActions(page);
    QObject::connect(pagekit::headerButton(actions, QStringLiteral("refresh"), u("重新扫描")), &QPushButton::clicked,
                     page, scan);

    // ---- data -----------------------------------------------------------------------------------------------
    QObject::connect(ipc, &IpcClient::persistenceReceived, page,
                     [page, store, updateCounts, scan](const bulwark::ipc::PersistenceListResponsePayload& p) {
        QList<PersistenceEntry> list = p.entries;
        std::stable_sort(list.begin(), list.end(),
                         [](const PersistenceEntry& a, const PersistenceEntry& b) { return a.riskScore > b.riskScore; });
        QStringList order;
        for (int c = 0; c <= int(PersistenceCategory::Other); ++c)
            order << QString::number(c);
        store->resetGrouped(
            list, [](const PersistenceEntry& e) { return QString::number(int(e.category)); },
            [](const QString&, const QList<const PersistenceEntry*>& members) {
                RecordView h;
                const PersistenceCategory c = members.isEmpty() ? PersistenceCategory::Other : members.first()->category;
                h.title = categoryLabel(c);
                int watch = 0;
                int maxRisk = 0;
                for (const PersistenceEntry* m : members) {
                    if (m->riskScore >= 50)
                        ++watch;
                    maxRisk = std::max(maxRisk, m->riskScore);
                }
                h.groupNote = watch ? u("需留意 %1 · 最高 %2").arg(watch).arg(maxRisk) : QString();
                // A group needing attention says so in its risk colour; a quiet one
                // is titled in the hue of its kind, like its rows.
                h.groupColor = watch ? evtfmt::riskColor(maxRisk) : categoryColor(c);
                return h;
            },
            order);
        page->setLoading(false);
        updateCounts();
        page->setNoDataContent(QStringLiteral("power"), u("没有发现自启动项"),
                               p.message.isEmpty() ? u("这 9 类开机持久化位置里没有枚举到任何一项。") : p.message,
                               u("重新扫描"), scan);
        if (!p.message.isEmpty() && !p.entries.isEmpty())
            ui::notify(page, ui::Tone::Info, p.message);
    });

    QObject::connect(ipc, &IpcClient::persistenceCleanupDone, page,
                     [page, results, scan](const bulwark::ipc::PersistenceCleanupResultPayload& r) {
        if (!r.entryId.isEmpty())
            results->insert(r.entryId, r);
        if (r.success) {
            QStringList parts;
            if (!r.quarantinedFiles.isEmpty())
                parts << u("隔离 %1 个文件").arg(r.quarantinedFiles.size());
            if (!r.removedRegistryValues.isEmpty())
                parts << u("移除 %1 项持久化").arg(r.removedRegistryValues.size());
            if (!r.skipped.isEmpty())
                parts << u("%1 项未能处理(见该项详情)").arg(r.skipped.size());
            Banner* b = ui::notify(page, r.skipped.isEmpty() ? ui::Tone::Success : ui::Tone::Warning,
                                   (r.message.isEmpty() ? u("已清理。") : r.message)
                                       + (parts.isEmpty() ? QString() : u("(") + parts.join(u(",")) + u(")")));
            if (b && !r.quarantinedFiles.isEmpty())
                b->setAction(u("查看隔离区"), [] { nav::go(QString::fromLatin1(nav::Quarantine)); });
            scan(); // 清完立刻重扫,让列表反映真实现状(而不是留一条已消失的行)
        } else {
            // 服务端的护栏拒绝(已加白 / 本产品自身 / 目标已不存在)也走这里,如实展示原因。
            ui::notify(page, ui::Tone::Danger, r.message.isEmpty() ? u("清理没有成功,服务没有给出原因。") : r.message);
            page->rebuildInspector();
        }
    });

    // 连接后不自动扫描(扫描要枚举全部持久化点并验签);保持「立即扫描」的空状态。
    QObject::connect(ipc, &IpcClient::connectionChanged, page, [page](bool c) { page->setConnected(c); });
    page->setConnected(ipc->isConnected());
    // nav::go("persistence", {scan: true}) —— 仪表盘的「扫描自启动项」:用户显式点的,才扫。
    nav::onArrive(page, QString::fromLatin1(nav::Persistence), [scan](const QVariantMap& args) {
        if (args.value(QStringLiteral("scan")).toBool())
            scan();
    });
    updateCounts();
    return page;
}
