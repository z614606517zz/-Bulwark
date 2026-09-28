// 进程管理 —— 在跑进程快照 + 用户主动处置。
//
// 定位:这不是任务管理器的复刻,而是「带取证与溯源的进程视图」。三件事是别处看不到的:
//   ① 启动来源:svchost.exe 显示成具体服务名,任务宿主派生的进程显示成具体计划任务名;
//   ② 签名与提示分:未签名 / 签名失配 / 跑在用户可写目录 / 伪装系统进程名,一眼可见;
//   ③ 处置就在手边:检查器底部与右键菜单里的结束 / 结束进程树 / 挂起 / 隔离映像 / 加信任。
//
// 列表 / 进程树两种视图可切换(记住选择)。列可点表头排序(数值列按真实数值排),默认按
// 「提示」降序,打开页面第一眼就落在最值得看的进程上。
//
// 三条红线:所有处置都要用户显式点击并先确认(页面本身不做任何自动动作)、关键系统进程与本软件
// 自身组件由服务端拒绝(这里也置灰并写明原因)、提示分只做着色排序、绝不当成判定结论。
#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "dialogs/ProcessViews.h"
#include "design/Banner.h"
#include "design/EmptyState.h"
#include "design/Format.h"
#include "design/Icons.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Segmented.h"
#include "design/ToggleSwitch.h"
#include "ipc/IpcClient.h"

#include <QApplication>
#include <QHash>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPainter>
#include <QPointer>
#include <QRegularExpression>
#include <QScrollBar>
#include <QSet>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QStyledItemDelegate>
#include <QTimer>
#include <QTreeView>

#include <functional>
#include <memory>
#include <utility>

using evtfmt::u;
using bulwark::ProcessEntry;
using Kind = bulwark::ipc::ProcessActionKind;

namespace {

enum Col { ColName = 0, ColPid, ColMem, ColSig, ColHint, ColCount };
constexpr int kIndexRole = Qt::UserRole + 1; // snapshot index (name column)
constexpr int kSortRole = Qt::UserRole + 2;
constexpr int kSubRole = Qt::UserRole + 3;   // second line of the name cell
constexpr int kToneRole = Qt::UserRole + 4;  // glyph colour
constexpr int kDescRole = Qt::UserRole + 5;  // file description, after the name
constexpr int kGlyphRole = Qt::UserRole + 6; // glyph: who launched it (service / task / …)
constexpr int kRowH = 50;

enum Seg { SegAll = 0, SegWatch, SegUnsigned, SegHosted };

using Entries = QList<ProcessEntry>;

bool needsAttention(const ProcessEntry& e)
{
    return !e.isProtectedSelf && !e.isTrusted && !e.isCritical && (e.riskScore > 0 || e.signatureMismatch);
}

bool hosted(const ProcessEntry& e)
{
    return e.originKind == bulwark::ProcessOriginKind::Service
        || e.originKind == bulwark::ProcessOriginKind::ScheduledTask;
}

// Glyph colour of a process row: its hint / trust / protection state when it
// has one (status wins), otherwise the hue of who launched it (services orchid,
// scheduled tasks rose, interactive left neutral) — see procview::tone().
QColor toneOf(const ProcessEntry& e)
{
    return procview::tone(e);
}

// What would make the inspector content stale (memory ticks don't).
QString signatureOf(const ProcessEntry& e)
{
    return QStringLiteral("%1|%2|%3|%4|%5|%6")
        .arg(e.pid)
        .arg(e.imagePath)
        .arg(int(e.isTrusted))
        .arg(e.riskScore)
        .arg(e.originLabel())
        .arg(int(e.isSigned));
}

// Two-line name cell: bold name + muted description / launch origin or path.
class NameDelegate : public QStyledItemDelegate
{
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter* p, const QStyleOptionViewItem& opt, const QModelIndex& idx) const override
    {
        QStyleOptionViewItem o(opt);
        initStyleOption(&o, idx);
        o.text.clear();
        o.icon = QIcon();
        const QWidget* w = opt.widget;
        QStyle* st = w ? w->style() : QApplication::style();
        st->drawControl(QStyle::CE_ItemViewItem, &o, p, w);

        p->save();
        p->setRenderHint(QPainter::Antialiasing, true);
        const QRect r = opt.rect.adjusted(8, 0, -8, 0);
        const QColor tone = idx.data(kToneRole).value<QColor>();
        const QString glyph = idx.data(kGlyphRole).toString();
        AppIcon::draw(*p, glyph.isEmpty() ? QStringLiteral("target") : glyph,
                      QRectF(r.left(), r.center().y() - 8, 16, 16), tone.isValid() ? tone : theme::textMuted(), 1.5);
        const QRect text = r.adjusted(26, 7, 0, -7);
        const int half = text.height() / 2;

        QFont nf = opt.font;
        nf.setWeight(QFont::DemiBold);
        const QFontMetrics nfm(nf);
        const QString name = nfm.elidedText(idx.data(Qt::DisplayRole).toString(), Qt::ElideRight, text.width());
        p->setFont(nf);
        p->setPen(theme::textPrimary());
        p->drawText(QRect(text.left(), text.top(), text.width(), half), Qt::AlignLeft | Qt::AlignVCenter, name);
        const int used = nfm.horizontalAdvance(name) + 10;
        const QString desc = idx.data(kDescRole).toString();
        QFont sf = opt.font;
        sf.setPointSizeF(std::max(7.5, opt.font.pointSizeF() - 1.0));
        const QFontMetrics sfm(sf);
        p->setFont(sf);
        if (!desc.isEmpty() && used < text.width() - 40) {
            p->setPen(theme::textSecondary());
            p->drawText(QRect(text.left() + used, text.top(), text.width() - used, half), Qt::AlignLeft | Qt::AlignVCenter,
                        sfm.elidedText(desc, Qt::ElideRight, text.width() - used));
        }
        p->setPen(theme::textMuted());
        p->drawText(QRect(text.left(), text.top() + half, text.width(), text.height() - half),
                    Qt::AlignLeft | Qt::AlignVCenter,
                    sfm.elidedText(idx.data(kSubRole).toString(), Qt::ElideMiddle, text.width()));
        p->restore();
    }

    QSize sizeHint(const QStyleOptionViewItem& opt, const QModelIndex& idx) const override
    {
        const QSize s = QStyledItemDelegate::sizeHint(opt, idx);
        return {std::max(s.width(), 240), kRowH};
    }
};

// Tree view that draws its own expand chevrons (the style's branch lines don't
// belong on this dark canvas).
class ProcTree : public QTreeView
{
public:
    ProcTree()
    {
        setObjectName(QStringLiteral("ProcessTree"));
        setUniformRowHeights(true);
        setSortingEnabled(true);
        setSelectionBehavior(QAbstractItemView::SelectRows);
        setSelectionMode(QAbstractItemView::SingleSelection);
        setEditTriggers(QAbstractItemView::NoEditTriggers);
        setAllColumnsShowFocus(true);
        setExpandsOnDoubleClick(false);
        setContextMenuPolicy(Qt::CustomContextMenu);
        setAccessibleName(QString::fromUtf8("进程列表"));
        setIndentation(18);
    }

protected:
    void drawBranches(QPainter* p, const QRect& rect, const QModelIndex& index) const override
    {
        if (!model() || !model()->hasChildren(index))
            return;
        p->save();
        p->setRenderHint(QPainter::Antialiasing, true);
        const QRectF r(rect.right() - 17, rect.center().y() - 6, 12, 12);
        AppIcon::draw(*p, isExpanded(index) ? QStringLiteral("chevron-down") : QStringLiteral("chevron-right"), r,
                      theme::textMuted(), 1.6);
        p->restore();
    }
};

// Page predicate + multi-term search; recursive in tree mode (a parent stays
// visible while any descendant matches).
class ProcFilter : public QSortFilterProxyModel
{
public:
    std::shared_ptr<Entries> entries;
    std::function<bool(const ProcessEntry&)> pred;

    void setSearch(const QString& text)
    {
        static const QRegularExpression ws(QStringLiteral("\\s+"));
        m_terms = text.split(ws, Qt::SkipEmptyParts);
        refresh();
    }
    void refresh() { invalidateFilter(); }

    bool matches(const ProcessEntry& e) const
    {
        if (pred && !pred(e))
            return false;
        if (m_terms.isEmpty())
            return true;
        const QString hay = procview::searchText(e);
        for (const QString& t : m_terms)
            if (!hay.contains(t, Qt::CaseInsensitive))
                return false;
        return true;
    }

protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override
    {
        const int i = sourceModel()->index(row, ColName, parent).data(kIndexRole).toInt();
        return entries && i >= 0 && i < entries->size() && matches(entries->at(i));
    }

private:
    QStringList m_terms;
};

} // namespace

QWidget* pages::processes(IpcClient* ipc)
{
    auto* shell = new ListShell;
    shell->setIdentity(identity::page(nav::Processes));
    shell->searchBox()->setPlaceholderText(u("进程名 / 路径 / 服务 / 任务 / PID…"));
    auto entries = std::make_shared<Entries>();
    auto loading = std::make_shared<bool>(false);

    auto* model = new QStandardItemModel(shell);
    model->setHorizontalHeaderLabels({u("进程"), QStringLiteral("PID"), u("内存"), u("签名"), u("提示")});
    auto* proxy = new ProcFilter;
    proxy->setParent(shell);
    proxy->entries = entries;
    proxy->setSourceModel(model);
    proxy->setSortRole(kSortRole);
    proxy->setRecursiveFilteringEnabled(true);
    auto* view = new ProcTree;
    view->setModel(proxy);
    view->setItemDelegateForColumn(ColName, new NameDelegate(view));
    QHeaderView* hdr = view->header();
    hdr->setStretchLastSection(false);
    hdr->setSectionResizeMode(ColName, QHeaderView::Stretch);
    const std::pair<int, int> widths[] = {{ColPid, 78}, {ColMem, 96}, {ColSig, 92}, {ColHint, 108}};
    for (const auto& [col, width] : widths) {
        hdr->setSectionResizeMode(col, QHeaderView::Interactive);
        view->setColumnWidth(col, width);
    }
    view->sortByColumn(ColHint, Qt::DescendingOrder);
    shell->setView(view);

    // ---- filters: quick segments · list / tree ---------------------------------------------------------
    Segmented* seg = shell->segments();
    seg->addSegment(u("全部"));
    seg->addSegment(u("需留意"));
    seg->addSegment(u("无签名"));
    seg->addSegment(u("服务 / 计划任务"));
    seg->setAccent(SegWatch, theme::warning());
    auto* mode = new Segmented;
    mode->setCompact(true);
    mode->setIdentity(shell->identity());
    mode->setAccessibleName(u("视图"));
    mode->addSegment(u("列表"), QStringLiteral("list"));
    mode->addSegment(u("进程树"), QStringLiteral("tree"));
    mode->setCurrentIndex(pagekit::remembered(QStringLiteral("processes"), QStringLiteral("view"),
                                              QStringLiteral("list")) == QLatin1String("tree")
                              ? 1
                              : 0);
    shell->addFilterWidget(mode);
    proxy->pred = [seg](const ProcessEntry& e) {
        switch (seg->currentIndex()) {
        case SegWatch:    return needsAttention(e);
        case SegUnsigned: return !e.isSigned;
        case SegHosted:   return hosted(e);
        default:          return true;
        }
    };

    // ---- snapshot -> model ---------------------------------------------------------------------------------
    auto itemByPid = std::make_shared<QHash<int, QStandardItem*>>();
    auto collapsed = std::make_shared<QSet<int>>();
    const auto pidAt = [proxy, model, entries](const QModelIndex& proxyIndex) -> int {
        const QModelIndex src = proxy->mapToSource(proxyIndex.siblingAtColumn(ColName));
        const QStandardItem* it = model->itemFromIndex(src);
        const int i = it ? it->data(kIndexRole).toInt() : -1;
        return (i >= 0 && i < entries->size()) ? entries->at(i).pid : 0;
    };
    const auto entryAt = [proxy, model, entries](const QModelIndex& proxyIndex) -> const ProcessEntry* {
        if (!proxyIndex.isValid())
            return nullptr;
        const QStandardItem* it = model->itemFromIndex(proxy->mapToSource(proxyIndex.siblingAtColumn(ColName)));
        const int i = it ? it->data(kIndexRole).toInt() : -1;
        return (i >= 0 && i < entries->size()) ? &entries->at(i) : nullptr;
    };
    const auto rebuild = [model, entries, itemByPid, view, mode, collapsed, proxy] {
        const bool tree = mode->currentIndex() == 1;
        model->removeRows(0, model->rowCount());
        itemByPid->clear();
        QList<QList<QStandardItem*>> rows;
        rows.reserve(entries->size());
        QHash<int, int> indexOfPid;
        for (int i = 0; i < entries->size(); ++i) {
            const ProcessEntry& e = entries->at(i);
            const procview::Hint h = procview::hint(e);
            auto* name = new QStandardItem(e.name.isEmpty() ? u("(未知)") : e.name);
            name->setData(i, kIndexRole);
            name->setData(e.name.toLower(), kSortRole);
            name->setData(!e.originLabel().isEmpty() ? e.originLabel() : evtfmt::nativePath(e.imagePath), kSubRole);
            name->setData(toneOf(e), kToneRole);
            name->setData(evtfmt::originGlyph(e.originKind), kGlyphRole);
            name->setData(e.fileDescription, kDescRole);
            name->setToolTip(evtfmt::nativePath(e.imagePath));
            auto* pid = new QStandardItem(QString::number(e.pid));
            pid->setData(e.pid, kSortRole);
            auto* mem = new QStandardItem(e.workingSetBytes > 0 ? fmt::bytes(e.workingSetBytes) : u("—"));
            mem->setData(qlonglong(e.workingSetBytes), kSortRole);
            auto* sig = new QStandardItem(procview::signatureText(e));
            sig->setForeground(procview::signatureColor(e));
            sig->setData(e.signatureMismatch ? 2 : (e.isSigned ? 0 : 1), kSortRole);
            auto* hint = new QStandardItem(h.text);
            hint->setForeground(h.color);
            hint->setData(h.rank, kSortRole);
            if (!e.riskReasons.isEmpty())
                hint->setToolTip(e.riskReasons.join(QLatin1Char('\n')));
            const QList<QStandardItem*> row{name, pid, mem, sig, hint};
            for (QStandardItem* it : row)
                it->setEditable(false);
            rows.append(row);
            itemByPid->insert(e.pid, name);
            indexOfPid.insert(e.pid, i);
        }
        // Parent links: by parentPid, but only to a process that started before the child
        // (PIDs are reused) and never into a cycle.
        QList<int> parentOf(entries->size(), -1);
        if (tree) {
            for (int i = 0; i < entries->size(); ++i) {
                const ProcessEntry& e = entries->at(i);
                const int p = indexOfPid.value(e.parentPid, -1);
                if (p < 0 || p == i || e.parentPid == 0)
                    continue;
                const ProcessEntry& pe = entries->at(p);
                if (pe.startTimeUtc.isValid() && e.startTimeUtc.isValid() && pe.startTimeUtc > e.startTimeUtc)
                    continue;
                parentOf[i] = p;
            }
            for (int i = 0; i < entries->size(); ++i) {
                int j = parentOf[i];
                for (int depth = 0; j >= 0 && depth < 64; ++depth) {
                    if (j == i) {
                        parentOf[i] = -1;
                        break;
                    }
                    j = parentOf[j];
                }
            }
        }
        for (int i = 0; i < rows.size(); ++i) {
            if (parentOf[i] >= 0)
                rows[parentOf[i]].first()->appendRow(rows[i]);
            else
                model->appendRow(rows[i]);
        }
        view->setRootIsDecorated(tree);
        view->setIndentation(tree ? 18 : 0);
        if (tree) {
            view->expandAll();
            for (int pid : std::as_const(*collapsed))
                if (QStandardItem* it = itemByPid->value(pid, nullptr))
                    view->collapse(proxy->mapFromSource(it->index()));
        }
    };

    // ---- empty states · counts ---------------------------------------------------------------------------
    const auto reload = [ipc, loading] {
        if (!ipc->isConnected())
            return;
        *loading = true;
        ipc->requestProcesses();
    };
    const auto refreshCounts = [shell, seg, proxy, entries, ipc, loading, reload] {
        int n[4] = {0, 0, 0, 0};
        int shown = 0;
        for (const ProcessEntry& e : std::as_const(*entries)) {
            ++n[SegAll];
            if (needsAttention(e)) ++n[SegWatch];
            if (!e.isSigned) ++n[SegUnsigned];
            if (hosted(e)) ++n[SegHosted];
            if (proxy->matches(e)) ++shown;
        }
        for (int i = 0; i < 4; ++i)
            seg->setCount(i, n[i]);
        shell->setMatch(shown, int(entries->size()));
        EmptyState* es = shell->emptyState();
        if (entries->isEmpty()) {
            if (!ipc->isConnected()) {
                es->setContent(QStringLiteral("server"), theme::textMuted(), u("未连接后台服务"),
                               u("界面还没有与后台服务建立连接,暂时读不到在跑的进程。服务恢复后会自动刷新。"));
                es->setAction(QString(), {});
            } else if (*loading) {
                es->setContent(QStringLiteral("refresh"), shell->identity(), u("正在读取进程快照…"), QString());
                es->setAction(QString(), {});
            } else {
                es->setContent(QStringLiteral("target"), shell->identity(), u("没有读到进程"),
                               u("服务返回了空的进程快照。"));
                es->setAction(u("重新读取"), reload, "primary");
            }
            shell->setEmptyVisible(true);
        } else if (shown == 0) {
            es->setContent(QStringLiteral("search"), theme::textMuted(), u("没有匹配的进程"),
                           u("当前的筛选或搜索条件下没有进程。"));
            es->setAction(u("清除筛选"), [shell, seg] {
                shell->searchBox()->clear();
                seg->setCurrentIndex(SegAll);
            });
            shell->setEmptyVisible(true);
        } else {
            shell->setEmptyVisible(false);
        }
    };

    // ---- inspector -----------------------------------------------------------------------------------------
    auto shownSig = std::make_shared<QString>();
    const auto showInspector = [shell, ipc, shownSig](const ProcessEntry& e) {
        Inspector* in = shell->inspector();
        in->setUpdatesEnabled(false);
        in->clear();
        procview::fill(in, e, ipc, /*actions*/ true);
        in->setUpdatesEnabled(true);
        *shownSig = signatureOf(e);
        shell->setInspectorOpen(true);
    };
    QObject::connect(view->selectionModel(), &QItemSelectionModel::currentChanged, shell,
                     [shell, entryAt, showInspector](const QModelIndex& cur) {
        if (!shell->isInspectorOpen())
            return;
        if (const ProcessEntry* e = entryAt(cur))
            showInspector(*e);
    });
    QObject::connect(view, &QAbstractItemView::clicked, shell, [shell, entryAt, showInspector](const QModelIndex& i) {
        if (shell->isInspectorOpen())
            return; // currentChanged already rebuilt it
        if (const ProcessEntry* e = entryAt(i))
            showInspector(*e);
    });
    QObject::connect(view, &QAbstractItemView::activated, shell, [shell, entryAt, ipc](const QModelIndex& i) {
        if (const ProcessEntry* e = entryAt(i))
            procview::openDetail(shell, *e, ipc);
    });
    QObject::connect(view, &QWidget::customContextMenuRequested, shell, [shell, view, entryAt, ipc](const QPoint& pos) {
        const QModelIndex i = view->indexAt(pos);
        const ProcessEntry* pe = entryAt(i);
        if (!pe)
            return;
        view->selectionModel()->setCurrentIndex(i, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        const ProcessEntry e = *pe;
        const QString locked = procview::lockReason(e);
        QMenu menu(shell);
        menu.setToolTipsVisible(true);
        QAction* kill = pagekit::menuAction(&menu, QStringLiteral("close"), u("结束进程"), shell,
                                            [shell, ipc, e] { procview::run(shell, ipc, e, Kind::Terminate); });
        QAction* tree = pagekit::menuAction(&menu, QStringLiteral("tree"), u("结束进程树"), shell,
                                            [shell, ipc, e] { procview::run(shell, ipc, e, Kind::TerminateTree); });
        if (!locked.isEmpty())
            for (QAction* a : {kill, tree}) {
                a->setEnabled(false);
                a->setToolTip(locked);
            }
        menu.addSeparator();
        procview::fillMenu(&menu, shell, e, ipc, true);
        menu.exec(view->viewport()->mapToGlobal(pos));
    });
    QObject::connect(view, &QTreeView::collapsed, shell,
                     [collapsed, pidAt](const QModelIndex& i) { collapsed->insert(pidAt(i)); });
    QObject::connect(view, &QTreeView::expanded, shell,
                     [collapsed, pidAt](const QModelIndex& i) { collapsed->remove(pidAt(i)); });

    // ---- filter wiring ---------------------------------------------------------------------------------------
    QObject::connect(shell->searchBox(), &QLineEdit::textChanged, shell, [proxy, refreshCounts](const QString& t) {
        proxy->setSearch(t);
        refreshCounts();
    });
    QObject::connect(seg, &Segmented::currentChanged, shell, [proxy, refreshCounts] {
        proxy->refresh();
        refreshCounts();
    });

    // ---- data ---------------------------------------------------------------------------------------------------
    const auto applySnapshot = [shell, view, entries, rebuild, refreshCounts, itemByPid, proxy, entryAt, pidAt, shownSig,
                                showInspector](const Entries& list) {
        // 刷新时保住当前选中的进程与滚动位置,不然自动刷新会把选择弹掉。
        const int keepPid = pidAt(view->currentIndex());
        const int scroll = view->verticalScrollBar()->value();
        *entries = list;
        rebuild();
        refreshCounts();
        if (keepPid > 0) {
            if (QStandardItem* it = itemByPid->value(keepPid, nullptr)) {
                const QModelIndex pi = proxy->mapFromSource(it->index());
                if (pi.isValid()) {
                    view->selectionModel()->blockSignals(true);
                    view->selectionModel()->setCurrentIndex(
                        pi, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
                    view->selectionModel()->blockSignals(false);
                    view->viewport()->update();
                    if (shell->isInspectorOpen())
                        if (const ProcessEntry* e = entryAt(pi); e && signatureOf(*e) != *shownSig)
                            showInspector(*e);
                }
            } else if (shell->isInspectorOpen()) {
                shell->setInspectorOpen(false); // the process has exited
                ui::notify(shell, ui::Tone::Info, u("PID %1 已经退出,详情已关闭。").arg(keepPid));
            }
        }
        QTimer::singleShot(0, view, [view, scroll] { view->verticalScrollBar()->setValue(scroll); });
    };
    QObject::connect(ipc, &IpcClient::processListReceived, shell,
                     [loading, applySnapshot](const bulwark::ipc::ProcessListResponsePayload& p) {
        *loading = false;
        applySnapshot(p.processes);
    });
    QObject::connect(mode, &Segmented::currentChanged, shell, [mode, applySnapshot, entries] {
        pagekit::remember(QStringLiteral("processes"), QStringLiteral("view"),
                          mode->currentData().toString());
        const Entries copy = *entries;
        applySnapshot(copy);
    });

    // 处置结果一律给回执:成功要说明做了什么,失败必须说明为什么没做成
    //(关键进程 / 自我保护 / 权限不足 / 进程已退出),绝不让用户以为「点了就生效了」。
    QObject::connect(ipc, &IpcClient::processActionResult, shell,
                     [shell, ipc, reload](const bulwark::ipc::ProcessActionResultPayload& r) {
        if (r.kind == Kind::ComputeHash)
            return; // 检查器 / 详情窗口自己处理
        ui::notify(shell, r.success ? ui::Tone::Success : ui::Tone::Danger,
                   r.message.isEmpty() ? (r.success ? u("操作已完成。") : u("操作未成功,服务没有给出原因。")) : r.message);
        if (ipc->isConnected())
            reload();
    });

    // ---- header: auto refresh · refresh -------------------------------------------------------------------------
    QHBoxLayout* actions = pagekit::headerActions(shell);
    auto* autoSwitch = new ToggleSwitch(false);
    autoSwitch->setAccessibleName(u("每 5 秒自动刷新"));
    autoSwitch->setToolTip(u("一次快照要枚举几百个进程并验签,默认不自动刷新;需要盯着看时再打开。"));
    actions->addWidget(autoSwitch);
    actions->addWidget(ui::label(u("自动刷新"), "secondary"));
    actions->addSpacing(6);
    QObject::connect(pagekit::headerButton(actions, QStringLiteral("refresh"), u("刷新")), &QPushButton::clicked, shell,
                     [reload, refreshCounts] {
                         reload();
                         refreshCounts();
                     });
    auto* timer = new QTimer(shell);
    timer->setInterval(5000);
    QObject::connect(timer, &QTimer::timeout, shell, reload);
    QObject::connect(autoSwitch, &QAbstractButton::toggled, shell, [timer](bool on) {
        if (on)
            timer->start();
        else
            timer->stop();
    });

    QObject::connect(ipc, &IpcClient::connectionChanged, shell, [shell, reload, refreshCounts](bool c) {
        refreshCounts();
        if (c)
            QTimer::singleShot(1500, shell, [reload, refreshCounts] {
                reload();
                refreshCounts();
            });
    });
    if (ipc->isConnected())
        QTimer::singleShot(1500, shell, [reload, refreshCounts] {
            reload();
            refreshCounts();
        });
    refreshCounts();
    return shell;
}
