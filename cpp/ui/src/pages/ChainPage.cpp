// 攻击链 —— 组合表状态 + 命中记录。
//
// 这页回答两个问题:
//   1) 「我这台机器上装的是哪一版组合表、还灵不灵」——顶部状态条:引擎状态 / 版本 / 组合条数 / 标记数;
//   2) 「它到底逮到过什么」——每次凑齐组合的记录:谁、凑齐了哪几个动作、多少样本作证、裁决是什么。
//
// 为什么不并进「事件记录」:一次攻击链命中横跨【多条】事件(凑齐组合的那几个动作分散在不同
// 事件里),挂到任何单条事件上都看不到全貌,所以服务端单独存了一份记录,这页单独读它。
//
// dry-run 的显示要诚实:默认「只记录不拦截」,此时命中【不影响裁决】。若不明说,用户会误以为
// 这些记录都已被拦下 —— 故状态条、每行的「只记录」标记与检查器都如实说明。
#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "dialogs/ChainViews.h"
#include "dialogs/EventFormat.h"
#include "design/Banner.h"
#include "design/Confirm.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Segmented.h"
#include "design/StatusStrip.h"
#include "ipc/IpcClient.h"
#include "Nav.h"

#include <QMenu>
#include <QPushButton>

#include <memory>

using evtfmt::u;
using bulwark::ipc::AttackChainHitPayload;

namespace {
enum Seg { SegAll = 0, SegHard, SegStrong, SegAsk };
const char* const kGrades[] = {"", "hard", "strong", "ask"};
} // namespace

QWidget* pages::attackChain(IpcClient* ipc)
{
    auto* page = new RecordBrowser;
    page->setIdentity(identity::page(nav::Chain));
    page->setLiveTop(true);
    page->searchBox()->setPlaceholderText(u("搜索主体 / 动作 / 家族…"));
    auto store = std::make_shared<RecordStore<AttackChainHitPayload>>(page->model(), &chainview::recordView);

    // ---- engine state strip --------------------------------------------------------------------------
    auto* strip = new StatusStrip;
    strip->setState(QStringLiteral("link"), theme::textMuted(), u("正在读取攻击链引擎状态…"));
    page->addTop(strip);
    const auto noData = [page](bool enabled, bool dryRun) {
        page->setNoDataContent(QStringLiteral("link"), u("还没有攻击链命中"),
                               !enabled ? u("攻击链引擎未启用,不会产生命中记录。")
                               : dryRun ? u("组合凑齐时会记在这里(当前只记录、不参与拦截)。")
                                        : u("同一进程上出现的几个动作与真实恶意样本的组合一致时,会记在这里。"));
    };
    noData(true, true);

    // ---- segments by strength ----------------------------------------------------------------------
    Segmented* seg = page->segments();
    seg->addSegment(u("全部"));
    seg->addSegment(u("确定恶意"));
    seg->addSegment(u("高度可疑"));
    seg->addSegment(u("需询问"));
    seg->setAccent(SegHard, theme::danger());
    seg->setAccent(SegStrong, theme::warning());
    seg->setAccent(SegAsk, theme::info());
    page->setPredicate([store, seg](int row) {
        const AttackChainHitPayload* h = store->itemAt(row);
        const int i = seg->currentIndex();
        if (!h || i <= SegAll || i > SegAsk)
            return true;
        return h->grade == QLatin1String(kGrades[i]);
    });
    page->setClearFilters([seg] { seg->setCurrentIndex(SegAll); });
    QObject::connect(seg, &Segmented::currentChanged, page, [page] { page->refilter(); });
    const auto updateCounts = [store, seg] {
        int n[4] = {0, 0, 0, 0};
        for (const AttackChainHitPayload& h : store->items()) {
            ++n[SegAll];
            for (int i = 1; i < 4; ++i)
                if (h.grade == QLatin1String(kGrades[i]))
                    ++n[i];
        }
        for (int i = 0; i < 4; ++i)
            seg->setCount(i, n[i]);
    };

    page->setInspectorBuilder([store, ipc](Inspector* in, int row) {
        if (const AttackChainHitPayload* h = store->itemAt(row))
            chainview::fill(in, *h, ipc, /*withWindow*/ true);
    });
    page->setActivateHandler([page, store, ipc](int row) {
        if (const AttackChainHitPayload* h = store->itemAt(row))
            chainview::openDetail(page, *h, ipc);
    });
    page->setContextMenuBuilder([page, store, ipc](QMenu* m, const QList<int>& rows) {
        if (rows.size() == 1)
            if (const AttackChainHitPayload* h = store->itemAt(rows.first()))
                chainview::fillMenu(m, page, *h, ipc, true);
    });

    // ---- header: refresh · ⋯ clear -----------------------------------------------------------------
    const auto reload = [page, ipc] {
        if (!ipc->isConnected())
            return;
        page->setLoading(true);
        ipc->requestAttackChain();
    };
    QHBoxLayout* actions = pagekit::headerActions(page);
    QObject::connect(pagekit::headerButton(actions, QStringLiteral("refresh"), u("刷新")), &QPushButton::clicked, page,
                     reload);
    QMenu* more = pagekit::headerMenu(actions);
    pagekit::menuAction(more, QStringLiteral("trash"), u("清空命中记录…"), page, [page, ipc] {
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法清空。"));
            return;
        }
        ui::ConfirmSpec s;
        s.risk = ui::Risk::Danger;
        s.title = u("清空攻击链命中记录");
        s.summary = u("将清空全部攻击链命中记录,包括落盘文件。");
        s.consequences << u("只影响这一页的历史展示,不会改变组合表或防护策略") << u("此操作不可撤销");
        s.confirmText = u("清空");
        if (ui::confirm(page, s))
            ipc->clearAttackChainHits(); // 服务端清完会主动回推空列表,无需再请求
    });

    // ---- data -----------------------------------------------------------------------------------------
    QObject::connect(ipc, &IpcClient::attackChainReceived, page,
                     [page, store, strip, noData, updateCounts](const bulwark::ipc::AttackChainResponsePayload& p) {
        QString title;
        QString text;
        QColor color;
        QString icon = QStringLiteral("link");
        if (!p.enabled) {
            color = theme::textMuted();
            title = u("攻击链引擎未启用");
            text = u("在 appsettings.json 里把 AttackChainEngine.Enabled 设为 true 后生效。");
        } else if (p.version <= 0) {
            color = theme::warning();
            title = u("等待组合表");
            text = u("引擎已启用,但还没有装载到组合表,正在等首次同步。");
            icon = QStringLiteral("clock");
        } else if (p.dryRun) {
            color = theme::warning();
            title = u("只记录不拦截");
            text = u("下列命中都没有参与拦截判定。要让攻击链真正生效,把 appsettings.json 里的 "
                     "AttackChainEngine.DryRun 改为 false。");
            icon = QStringLiteral("eye");
        } else {
            color = theme::success();
            title = u("参与拦截判定");
            text = u("组合凑齐即作为硬指标进入裁决流水线,按强度判为拦截或弹窗询问。");
            icon = QStringLiteral("shield-check");
        }
        QStringList meta;
        if (p.version > 0) {
            // 展示服务器给的可读版本号;老服务端不下发时回退到内部整数版本号。
            meta << (p.versionLabel.isEmpty() ? QStringLiteral("v%1").arg(p.version) : u("组合表 ") + p.versionLabel)
                 << u("%1 条组合").arg(p.patterns) << u("%1 个标记").arg(p.markers);
        }
        if (p.enabled)
            meta << u("记账 %1 个进程").arg(p.trackedProcesses);
        strip->setState(icon, color, title, text, meta.join(u(" · ")));
        QStringList tip;
        if (p.version > 0 && !p.versionLabel.isEmpty())
            tip << u("内部版本号 v%1(客户端据此判断是否需要重新下载)").arg(p.version);
        if (!p.updateSchedule.isEmpty())
            tip << u("更新计划:") + p.updateSchedule;
        if (!p.endpoint.isEmpty())
            tip << u("组合表来源:") + p.endpoint;
        strip->setToolTip(tip.join(QLatin1Char('\n')));

        noData(p.enabled, p.dryRun);
        store->reset(p.hits); // 服务端:最新在前
        page->setLoading(false);
        updateCounts();
    });
    // 实时命中(与 toast 同源):直接插到最上面,不必整表重拉。
    QObject::connect(ipc, &IpcClient::attackChainHit, page, [store, updateCounts](const AttackChainHitPayload& h) {
        store->prepend(h);
        updateCounts();
    });
    pagekit::onConnected(page, ipc, page, 0, reload);

    nav::onArrive(page, QString::fromLatin1(nav::Chain), [page, reload](const QVariantMap& args) {
        if (args.contains(QStringLiteral("select")))
            page->selectKey(args.value(QStringLiteral("select")).toString());
        else if (args.value(QStringLiteral("refresh")).toBool())
            reload();
    });
    updateCounts();
    return page;
}
