// 事件记录 —— 拦截 / 询问 / 放行的全部安全事件,一个列表 + 右侧检查器。
//
// 这一页合并了原来的「拦截记录」与「活动日志」:两者本来就读同一份事件历史,分成两页
// 只是让用户在两个几乎一样的表格之间来回找同一条事件。现在用顶部分段(全部 / 拦截 / 询问 /
// 放行)切换视角,选中哪段会被记住;toast 的「查看详情」直接落到「拦截」段。
//
// 处置一律按【真实执行结果】显示(evtfmt::disposition):判了 Block 但没能执行的,
// 写「仅告警·未拦截」/「拦截失败」,绝不写成「已拦截」。
#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "dialogs/EventViews.h"
#include "design/Banner.h"
#include "design/Confirm.h"
#include "design/FilterChip.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Segmented.h"
#include "ipc/IpcClient.h"
#include "Nav.h"

#include <QMenu>
#include <QPushButton>
#include <QTimer>

#include <algorithm>
#include <memory>

using evtfmt::u;
using bulwark::ipc::EventLogPayload;

namespace {

constexpr int kMaxRows = 1000; // live-fed list: bound the memory, the timeline page goes deeper
enum Seg { SegAll = 0, SegBlock, SegAsk, SegAllow };
const char* const kSegKeys[] = {"all", "block", "ask", "allow"};

int segFromKey(const QString& key, int fallback)
{
    for (int i = 0; i < 4; ++i)
        if (key == QLatin1String(kSegKeys[i]))
            return i;
    return fallback;
}

QWidget* buildEventsPage(IpcClient* ipc, int defaultSeg)
{
    auto* page = new RecordBrowser;
    page->setIdentity(identity::page(nav::Events));
    page->setLiveTop(true);
    page->searchBox()->setPlaceholderText(u("搜索程序 / 目标 / 命令行…"));
    page->setNoDataContent(QStringLiteral("activity"), u("暂无事件记录"),
                           u("防护运行后,被拦截、询问与放行的安全事件都会实时记在这里。"));
    auto store = std::make_shared<RecordStore<EventLogPayload>>(page->model(), &evtview::recordView);
    const QString trustSource = u("从事件记录信任");

    // ---- filter bar -------------------------------------------------------------------
    Segmented* seg = page->segments();
    seg->addSegment(u("全部"));
    seg->addSegment(u("拦截"));
    seg->addSegment(u("询问"));
    seg->addSegment(u("放行"));
    seg->setAccent(SegBlock, theme::danger());
    seg->setAccent(SegAsk, theme::warning());
    seg->setCurrentIndex(segFromKey(pagekit::remembered(QStringLiteral("events"), QStringLiteral("segment"),
                                                       QString::fromLatin1(kSegKeys[defaultSeg])),
                                    defaultSeg));

    FilterChip* typeChip = page->addChip(u("类型"));
    typeChip->addOption(u("全部"));
    for (int i = 0; i <= int(bulwark::EventType::DnsQuery); ++i)
        typeChip->addOption(evtfmt::typeShort(bulwark::EventType(i)), i);
    FilterChip* riskChip = page->addChip(u("风险"));
    riskChip->addOption(u("全部"), 0);
    riskChip->addOption(u("可疑及以上"), 50);
    riskChip->addOption(u("仅高危"), 80);

    page->setPredicate([store, seg, typeChip, riskChip](int row) {
        const EventLogPayload* p = store->itemAt(row);
        if (!p)
            return true;
        using V = bulwark::VerdictAction;
        switch (seg->currentIndex()) {
        case SegBlock: if (p->action != V::Block) return false; break;
        case SegAsk:   if (p->action != V::Ask) return false; break;
        case SegAllow: if (p->action != V::Allow) return false; break;
        default: break;
        }
        if (typeChip->isActive() && int(p->event.type) != typeChip->currentData().toInt())
            return false;
        if (riskChip->isActive() && p->event.riskScore < riskChip->currentData().toInt())
            return false;
        return true;
    });
    page->setClearFilters([seg, typeChip, riskChip] {
        seg->setCurrentIndex(SegAll);
        typeChip->reset();
        riskChip->reset();
    });
    const auto updateCounts = [store, seg] {
        int n[4] = {0, 0, 0, 0};
        for (const EventLogPayload& p : store->items()) {
            ++n[SegAll];
            if (p.action == bulwark::VerdictAction::Block) ++n[SegBlock];
            else if (p.action == bulwark::VerdictAction::Ask) ++n[SegAsk];
            else ++n[SegAllow];
        }
        for (int i = 0; i < 4; ++i)
            seg->setCount(i, n[i]);
    };
    QObject::connect(seg, &Segmented::currentChanged, page, [page](int i) {
        pagekit::remember(QStringLiteral("events"), QStringLiteral("segment"), QString::fromLatin1(kSegKeys[i]));
        page->refilter();
    });
    for (FilterChip* c : {typeChip, riskChip})
        QObject::connect(c, &FilterChip::currentChanged, page, [page] { page->refilter(); });

    // ---- record -> inspector / window / menu ------------------------------------------------
    page->setInspectorBuilder([store, ipc, trustSource](Inspector* in, int row) {
        if (const EventLogPayload* p = store->itemAt(row))
            evtview::fillInspector(in, *p, ipc, trustSource);
    });
    page->setActivateHandler([page, store, ipc](int row) {
        if (const EventLogPayload* p = store->itemAt(row))
            evtview::openTimeline(page, p->event, ipc, evtview::outcomeOf(*p));
    });
    page->setContextMenuBuilder([page, store, ipc, trustSource](QMenu* m, const QList<int>& rows) {
        if (rows.size() != 1)
            return;
        if (const EventLogPayload* p = store->itemAt(rows.first()))
            evtview::fillContextMenu(m, page, *p, ipc, trustSource);
    });

    // ---- header: pause live updates · ⋯ clear history ----------------------------------------
    QHBoxLayout* actions = pagekit::headerActions(page);
    auto* pause = pagekit::headerButton(actions, QStringLiteral("pause"), u("暂停实时"));
    pause->setCheckable(true);
    pause->setToolTip(u("暂停后新事件先攒着不插进列表,方便对照查看;继续时一次补上。"));
    QMenu* more = pagekit::headerMenu(actions);
    auto queue = std::make_shared<QList<EventLogPayload>>(); // newest first, while paused
    const auto syncPause = [pause, queue] {
        if (!pause->isChecked()) {
            pause->setText(u("暂停实时"));
            pause->setIcon(AppIcon::icon(QStringLiteral("pause"), theme::textSecondary(), 16));
        } else {
            pause->setText(queue->isEmpty() ? u("继续") : u("继续 · %1 条新事件").arg(queue->size()));
            pause->setIcon(AppIcon::icon(QStringLiteral("play"), theme::accentSoft(), 16));
        }
    };
    QObject::connect(pause, &QPushButton::toggled, page, [store, queue, syncPause, updateCounts](bool paused) {
        if (!paused && !queue->isEmpty()) {
            store->prependMany(*queue);
            store->trim(kMaxRows);
            queue->clear();
            updateCounts();
        }
        syncPause();
    });

    auto clearPending = std::make_shared<bool>(false);
    pagekit::menuAction(more, QStringLiteral("trash"), u("清空事件历史…"), page, [page, ipc, clearPending] {
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法清空事件历史。"));
            return;
        }
        ui::ConfirmSpec s;
        s.risk = ui::Risk::Danger;
        s.title = u("清空全部事件历史");
        s.summary = u("事件记录与事件时间线读取的是同一份历史:清空后两处都会变空。");
        s.consequences << u("服务端的历史文件一并清空,重启后也不会再回填") << u("此操作不可撤销");
        s.confirmText = u("清空");
        if (!ui::confirm(page, s))
            return;
        *clearPending = true;
        ipc->clearEventHistory(); // 服务清完会回推(已空的)历史
        QTimer::singleShot(8000, page, [page, clearPending] {
            if (!*clearPending)
                return;
            *clearPending = false;
            ui::notify(page, ui::Tone::Warning, u("没有收到服务的清空确认,列表可能还不是最新状态。"));
        });
    });

    // ---- data ------------------------------------------------------------------------------
    QObject::connect(ipc, &IpcClient::eventLogReceived, page,
                     [store, pause, queue, syncPause, updateCounts](const EventLogPayload& p) {
        if (pause->isChecked()) {
            queue->prepend(p);
            if (queue->size() > kMaxRows)
                queue->removeLast();
            syncPause();
            return;
        }
        store->prepend(p);
        store->trim(kMaxRows);
        updateCounts();
    });
    QObject::connect(ipc, &IpcClient::eventHistoryReceived, page,
                     [page, store, queue, syncPause, updateCounts, clearPending](const QList<EventLogPayload>& events) {
        QList<EventLogPayload> rows(events.crbegin(), events.crend()); // oldest->newest on the wire; newest on top
        if (rows.size() > kMaxRows)
            rows.resize(kMaxRows);
        queue->clear();
        syncPause();
        store->reset(rows);
        page->setLoading(false);
        updateCounts();
        if (*clearPending) {
            *clearPending = false;
            ui::notify(page, events.isEmpty() ? ui::Tone::Success : ui::Tone::Warning,
                       events.isEmpty() ? u("事件历史已清空。") : u("服务回推的历史仍有 %1 条记录,清空可能没有完成。").arg(events.size()));
        }
    });
    // 启动不卡:历史回填(最多 500 条)延后到窗口可交互之后再拉。
    pagekit::onConnected(page, ipc, page, 500, [page, ipc] {
        if (!ipc->isConnected())
            return;
        page->setLoading(true);
        ipc->requestEventHistory();
    });

    // ---- navigation: nav::go("events", {segment, select}) ------------------------------------
    nav::onArrive(page, QString::fromLatin1(nav::Events), [page, seg](const QVariantMap& args) {
        if (args.contains(QStringLiteral("segment")))
            seg->setCurrentIndex(segFromKey(args.value(QStringLiteral("segment")).toString(), seg->currentIndex()));
        if (args.contains(QStringLiteral("select")))
            page->selectKey(args.value(QStringLiteral("select")).toString());
    });
    updateCounts();
    return page;
}

} // namespace

// 拦截记录 / 活动日志 两个入口保留(同一页,默认分段不同),方便外部代码与历史调用方。
QWidget* pages::interceptions(IpcClient* ipc) { return buildEventsPage(ipc, SegBlock); }
QWidget* pages::activity(IpcClient* ipc) { return buildEventsPage(ipc, SegAll); }
