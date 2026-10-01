#include "design/ListShell.h"
#include "design/Components.h"
#include "design/EmptyState.h"
#include "design/FilterChip.h"
#include "design/Inspector.h"
#include "design/Motion.h"
#include "design/RecordDelegate.h"
#include "design/Segmented.h"
#include "design/TableKit.h"
#include "design/Theme.h"

#include <QAbstractItemView>
#include <QEvent>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QPushButton>
#include <QScrollBar>
#include <QSet>
#include <QTimer>
#include <QToolButton>
#include <QVariantAnimation>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>
#include <utility>

namespace {

constexpr int kDrawerBreak = 880; // content width below which the inspector overlays the list
constexpr int kGap = 16;

QString u(const char* s) { return QString::fromUtf8(s); }

// Dims the list behind the inspector drawer; a click on it closes the drawer.
class Scrim : public QWidget
{
public:
    explicit Scrim(QWidget* parent) : QWidget(parent) {}
    std::function<void()> onClick;
    qreal level = 0.0;

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.fillRect(rect(), theme::tint(theme::blend(QColor(0, 0, 0), theme::bg(), 0.7), 0.55 * level));
    }
    void mousePressEvent(QMouseEvent* e) override
    {
        if (onClick)
            onClick();
        e->accept();
    }
};

} // namespace

// ---- BatchBar -------------------------------------------------------------------

BatchBar::BatchBar(QWidget* parent) : GlowCard(parent)
{
    setTone(Tone::Floating);
    setRadius(23);
    setFixedHeight(46);
    auto* h = new QHBoxLayout(this);
    h->setContentsMargins(18, 6, 8, 6);
    h->setSpacing(8);
    m_count = ui::label(QString(), "title");
    h->addWidget(m_count);
    h->addSpacing(2);
    m_all = ui::button(u("全选"), "ghost", QString(), true);
    connect(m_all, &QPushButton::clicked, this, [this] { emit selectAllRequested(!m_allSelected); });
    h->addWidget(m_all);
    auto* sep = new QFrame;
    sep->setObjectName(QStringLiteral("Divider"));
    sep->setFixedSize(1, 20);
    h->addWidget(sep);
    m_row = new QHBoxLayout;
    m_row->setSpacing(8);
    h->addLayout(m_row);
    m_close = ui::iconButton(QStringLiteral("close"), u("取消选择"), theme::textMuted(), 14);
    connect(m_close, &QToolButton::clicked, this, &BatchBar::clearRequested);
    h->addWidget(m_close);
    ui::elevate(this, 22, 6, 150);
    setAccessibleName(u("批量操作"));
    setCount(0, 0);
}

void BatchBar::setCount(int selected, int listed)
{
    m_count->setText(u("已选 %1 项").arg(selected));
    m_allSelected = listed > 0 && selected >= listed;
    m_all->setText(m_allSelected ? u("取消全选") : u("全选"));
    m_all->setToolTip(m_allSelected ? u("清除全部选择") : u("选中列表里当前显示的全部记录"));
    m_all->setEnabled(listed > 0);
    for (QPushButton* b : std::as_const(m_buttons))
        b->setEnabled(selected > 0);
    adjustSize();
}

void BatchBar::setCheckMode(bool on)
{
    const QString tip = on ? u("退出批量选择") : u("取消选择");
    m_close->setToolTip(tip);
    m_close->setAccessibleName(tip);
}

QPushButton* BatchBar::addAction(const QString& icon, const QString& text, const char* variant,
                                 std::function<void()> fn)
{
    auto* b = ui::button(text, variant, icon, true);
    connect(b, &QPushButton::clicked, this, [fn = std::move(fn)] {
        if (fn)
            fn();
    });
    m_row->addWidget(b);
    m_buttons.append(b);
    adjustSize();
    return b;
}

// ---- ListShell ----------------------------------------------------------------

ListShell::ListShell(QWidget* parent) : QWidget(parent)
{
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(theme::metric::pagePad, 12, theme::metric::pagePad, theme::metric::pagePad);
    v->setSpacing(12);

    m_top = new QVBoxLayout;
    m_top->setSpacing(10);
    v->addLayout(m_top);

    m_bar = new QHBoxLayout;
    m_bar->setSpacing(10);
    m_segments = new Segmented;
    m_segments->setAccessibleName(u("筛选"));
    m_segments->hide();
    m_bar->addWidget(m_segments);
    m_chips = new QHBoxLayout;
    m_chips->setSpacing(8);
    m_bar->addLayout(m_chips);
    m_bar->addStretch(1);
    m_search = ui::searchBox(u("搜索…"), 240);
    m_search->setObjectName(QStringLiteral("PageSearch"));
    m_search->setMinimumWidth(150);
    m_search->setMaximumWidth(300);
    m_search->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_search->setAccessibleName(u("搜索"));
    m_search->setToolTip(u("本地实时过滤 · 多个关键词用空格分隔 · Ctrl+F"));
    m_bar->addWidget(m_search, 1);
    m_match = ui::label(QString(), "muted");
    m_match->setMinimumWidth(70);
    m_match->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    m_bar->addWidget(m_match);
    v->addLayout(m_bar);

    m_above = new QVBoxLayout;
    m_above->setSpacing(8);
    v->addLayout(m_above);

    m_content = new QWidget;
    m_content->installEventFilter(this);
    v->addWidget(m_content, 1);

    m_card = new GlowCard(m_content);
    m_card->setObjectName(QStringLiteral("Card"));
    m_cardLayout = new QVBoxLayout(m_card);
    m_cardLayout->setContentsMargins(4, 6, 4, 6);
    m_card->installEventFilter(this);

    m_empty = new EmptyState(m_card);
    m_empty->hide();
    m_batch = new BatchBar(m_card);
    m_batch->hide();

    m_newPill = new QPushButton(m_card);
    m_newPill->setCursor(Qt::PointingHandCursor);
    m_newPill->setIcon(AppIcon::icon(QStringLiteral("arrow-up"), theme::accentInk(), 14));
    m_newPill->setFixedHeight(30);
    // Radius = half the fixed height: Qt drops the rounding altogether when it's larger.
    m_newPill->setStyleSheet(QStringLiteral(
        "QPushButton{background:%1;color:%4;border:1px solid %2;border-radius:15px;"
        "padding:0px 14px;font-size:9pt;font-weight:600;}"
        "QPushButton:hover{background:%3;}")
        .arg(theme::accentStrong().name(), theme::accentSoft().name(),
             theme::blend(theme::accentSoft(), theme::accentStrong(), 0.25).name(), theme::accentInk().name()));
    m_newPill->hide();
    connect(m_newPill, &QPushButton::clicked, this, &ListShell::newItemsClicked);

    auto* scrim = new Scrim(m_content);
    scrim->onClick = [this] { setInspectorOpen(false); };
    scrim->hide();
    m_scrim = scrim;

    m_inspector = new Inspector(m_content);
    m_inspector->hide();
    connect(m_inspector, &Inspector::closeRequested, this, [this] {
        setInspectorOpen(false);
        if (m_view)
            m_view->setFocus(Qt::OtherFocusReason);
    });

    m_anim = new QVariantAnimation(this);
    m_anim->setEasingCurve(QEasingCurve::OutCubic);
    connect(m_anim, &QVariantAnimation::valueChanged, this, [this](const QVariant& val) {
        m_progress = val.toReal();
        layoutContent();
    });
    connect(m_anim, &QVariantAnimation::finished, this, [this] {
        if (!m_open) {
            m_inspector->hide();
            m_scrim->hide();
        }
    });
}

FilterChip* ListShell::addChip(const QString& label)
{
    auto* c = new FilterChip(label);
    m_chips->addWidget(c);
    return c;
}

void ListShell::addFilterWidget(QWidget* w)
{
    m_chips->addWidget(w);
}

void ListShell::setMatch(int shown, int total)
{
    syncSegmentsVisible();
    m_match->setText(shown == total ? u("共 %1 条").arg(total) : u("匹配 %1 / %2").arg(shown).arg(total));
}

void ListShell::addTop(QWidget* w) { m_top->addWidget(w); }
void ListShell::addAboveList(QWidget* w) { m_above->addWidget(w); }

void ListShell::setView(QAbstractItemView* view)
{
    m_view = view;
    m_cardLayout->addWidget(view);
    m_empty->raise();
    m_newPill->raise();
    m_batch->raise();
}

void ListShell::syncSegmentsVisible()
{
    m_segments->setVisible(m_segments->count() > 0);
}

void ListShell::showEvent(QShowEvent* e)
{
    syncSegmentsVisible();
    QWidget::showEvent(e);
}

void ListShell::setInspectorOpen(bool open)
{
    if (open == m_open) {
        if (open)
            m_inspector->show();
        return;
    }
    m_open = open;
    if (open) {
        m_inspector->show();
        m_inspector->raise();
    }
    m_anim->stop();
    const int ms = motion::duration(200);
    if (ms <= 0) {
        m_progress = open ? 1.0 : 0.0;
        layoutContent();
        if (!open) {
            m_inspector->hide();
            m_scrim->hide();
        }
    } else {
        m_anim->setDuration(ms);
        m_anim->setStartValue(m_progress);
        m_anim->setEndValue(open ? 1.0 : 0.0);
        m_anim->start();
    }
    if (!open)
        emit inspectorClosed();
}

void ListShell::layoutContent()
{
    const int W = m_content->width();
    const int H = m_content->height();
    if (W <= 0 || H <= 0)
        return;
    const bool drawer = W < kDrawerBreak;
    const int iw = drawer ? std::clamp(W - 56, 300, 420) : std::clamp(int(W * 0.38), 340, 440);
    const qreal p = m_progress;
    auto* scrim = static_cast<Scrim*>(m_scrim);
    if (drawer) {
        m_card->setGeometry(0, 0, W, H);
        m_inspector->setGeometry(W - int(std::lround(iw * p)), 0, iw, H);
        scrim->level = p;
        scrim->setGeometry(0, 0, W, H);
        scrim->setVisible(p > 0.001);
        scrim->update();
        scrim->raise();
        m_inspector->raise();
    } else {
        const int shift = int(std::lround((iw + kGap) * p));
        m_card->setGeometry(0, 0, W - shift, H);
        m_inspector->setGeometry(W - shift + kGap, 0, iw, H);
        scrim->hide();
    }
}

void ListShell::positionOverlays()
{
    const QRect r = m_card->rect();
    m_empty->setGeometry(r.adjusted(1, 1, -1, -1));
    if (m_newPill->isVisible()) {
        m_newPill->adjustSize();
        m_newPill->move((r.width() - m_newPill->width()) / 2, 12);
    }
    if (m_batch->isVisible()) {
        m_batch->adjustSize();
        const int w = qMin(m_batch->sizeHint().width(), r.width() - 24);
        m_batch->resize(w, m_batch->height());
        m_batch->move((r.width() - w) / 2, r.height() - m_batch->height() - 16);
    }
}

void ListShell::setEmptyVisible(bool visible)
{
    m_empty->setVisible(visible);
    if (visible) {
        positionOverlays();
        m_empty->raise();
        m_newPill->raise();
        m_batch->raise();
    }
}

void ListShell::setBatchVisible(bool visible)
{
    const bool show = visible && m_batch->hasActions();
    m_batchShown = show;
    m_batch->setVisible(show);
    if (show) {
        positionOverlays();
        m_batch->raise();
    }
}

void ListShell::showNewItems(int n, const QString& text)
{
    if (n <= 0) {
        m_newPill->hide();
        return;
    }
    m_newPill->setText(text.isEmpty() ? u("%1 条新记录").arg(n) : text);
    m_newPill->setAccessibleName(m_newPill->text() + u(",点击回到顶部"));
    m_newPill->show();
    positionOverlays();
    m_newPill->raise();
}

void ListShell::setIdentity(const QColor& hue)
{
    m_identity = hue;
    m_segments->setIdentity(hue);
    // Light falling into the list from its top-left corner, below the page's
    // title tile — the recipe of the inspector's header light, spread wider.
    if (hue.isValid())
        m_card->setGlow(hue, QPointF(0.0, 0.0), 0.55, 0.10);
    else
        m_card->clearGlow();
}

void ListShell::keyPressEvent(QKeyEvent* e)
{
    if (e->key() == Qt::Key_Escape) {
        if (m_open) {
            setInspectorOpen(false);
            if (m_view)
                m_view->setFocus(Qt::OtherFocusReason);
            e->accept();
            return;
        }
        if (!m_search->text().isEmpty()) {
            m_search->clear();
            e->accept();
            return;
        }
        emit escapePressed();
    }
    QWidget::keyPressEvent(e);
}

bool ListShell::eventFilter(QObject* watched, QEvent* e)
{
    if (e->type() == QEvent::Resize) {
        if (watched == m_content)
            layoutContent();
        else if (watched == m_card)
            positionOverlays();
    }
    return QWidget::eventFilter(watched, e);
}

// ---- RecordBrowser --------------------------------------------------------------

RecordBrowser::RecordBrowser(QWidget* parent) : ListShell(parent)
{
    m_model = new RecordModel(this);
    m_filter = new RecordFilter(this);
    m_filter->setRecords(m_model);
    m_list = new RecordListView;
    m_list->setModel(m_filter);
    m_list->setAccessibleName(u("记录列表"));
    setView(m_list);
    m_list->recordDelegate()->setCollapsedProbe(
        [this](const QString& g) { return m_filter->isCollapsed(g); });

    connect(searchBox(), &QLineEdit::textChanged, this, [this](const QString& t) {
        m_filter->setSearch(t);
        updateCounts();
    });

    QItemSelectionModel* sel = m_list->selectionModel();
    connect(sel, &QItemSelectionModel::currentChanged, this,
            [this](const QModelIndex& cur, const QModelIndex&) { onCurrentChanged(cur); });
    connect(sel, &QItemSelectionModel::selectionChanged, this, [this] {
        emit selectionCountChanged(syncBatch());
    });
    connect(m_list, &QAbstractItemView::clicked, this, [this](const QModelIndex& i) {
        if (m_checkMode)
            return; // the click toggled the record's check box, nothing more
        if (!i.isValid() || i.data(rec::Header).toBool() || !m_buildInspector)
            return;
        if (selectedSourceRows().size() > 1)
            return; // building a multi-selection: leave the inspector alone
        if (!isInspectorOpen())
            showInspectorFor(m_filter->mapToSource(i).row());
    });
    connect(m_list, &QAbstractItemView::activated, this, [this](const QModelIndex& i) {
        if (m_checkMode)
            return; // Space toggles; there is no single record to open
        if (!i.isValid() || i.data(rec::Header).toBool())
            return;
        const int src = m_filter->mapToSource(i).row();
        if (m_activate)
            m_activate(src);
        else if (m_buildInspector)
            showInspectorFor(src); // no full window: Enter opens the inspector
    });
    connect(m_list, &RecordListView::headerClicked, this, [this](const QString& g) {
        if (!m_list->recordDelegate()->collapsible())
            return;
        m_filter->setCollapsed(g, !m_filter->isCollapsed(g));
        m_list->viewport()->update();
    });
    connect(m_list, &QWidget::customContextMenuRequested, this, &RecordBrowser::showContextMenu);
    connect(batchBar(), &BatchBar::clearRequested, this, [this] {
        if (m_checkMode)
            setCheckMode(false);
        else
            clearSelection();
    });
    connect(batchBar(), &BatchBar::selectAllRequested, this, [this](bool select) {
        if (select)
            m_list->selectAll();
        else
            m_list->clearSelection();
    });
    // Esc peels off the inspector, then the search (ListShell), then check mode.
    connect(this, &ListShell::escapePressed, this, [this] {
        if (m_checkMode)
            setCheckMode(false);
    });

    connect(this, &ListShell::newItemsClicked, this, [this] {
        m_newCount = 0;
        showNewItems(0);
        m_list->scrollToTop();
    });
    connect(m_list->verticalScrollBar(), &QScrollBar::valueChanged, this, [this](int value) {
        if (value == 0 && m_newCount > 0 && !m_anchoring) {
            m_newCount = 0;
            showNewItems(0);
        }
    });

    // Keep the selection (and an open inspector) across a full refresh. A
    // multi-selection — and anything in check mode — is kept whole, by key: a
    // service snapshot landing mid-selection must not throw the user's ticks away.
    connect(m_model, &QAbstractItemModel::modelAboutToBeReset, this, [this] {
        m_keptKey = currentKey();
        m_keptKeys.clear();
        const QList<int> rows = selectedSourceRows();
        if (m_checkMode || rows.size() > 1)
            for (int src : rows)
                m_keptKeys.append(m_model->at(src).key);
        m_keptInspector = isInspectorOpen();
        m_keptScroll = m_list->verticalScrollBar()->value();
    });
    connect(m_model, &QAbstractItemModel::modelReset, this, [this] {
        updateCounts();
        const QVariant key = std::exchange(m_keptKey, QVariant());
        const QList<QVariant> keys = std::exchange(m_keptKeys, QList<QVariant>());
        if (m_checkMode || !keys.isEmpty()) {
            const bool haveCurrent = restoreSelection(keys, key);
            if (m_keptInspector) {
                if (haveCurrent && !m_checkMode)
                    showInspectorFor(currentSourceRow());
                else
                    setInspectorOpen(false);
            }
        } else if (key.isValid()) {
            if (!selectKey(key, m_keptInspector, /*reveal*/ false) && m_keptInspector)
                setInspectorOpen(false);
        } else if (m_keptInspector) {
            setInspectorOpen(false);
        }
        const int scroll = m_keptScroll;
        QTimer::singleShot(0, this, [this, scroll] { m_list->verticalScrollBar()->setValue(scroll); });
    });

    // Live rows arriving on top while the user reads further down: hold the
    // viewport still and offer a "↑ N 条新记录" shortcut instead of jumping.
    connect(m_filter, &QAbstractItemModel::rowsAboutToBeInserted, this,
            [this](const QModelIndex&, int first, int) {
        if (!m_liveTop || first != 0 || m_anchoring)
            return;
        const bool reading = m_list->verticalScrollBar()->value() > 0 || isInspectorOpen();
        if (!reading)
            return;
        m_list->settleLayout();
        const QModelIndex top = m_list->indexAt(QPoint(24, 1));
        if (!top.isValid())
            return;
        m_anchor = top;
        m_anchorY = m_list->visualRect(top).top();
        m_anchoring = true;
    });
    connect(m_filter, &QAbstractItemModel::rowsInserted, this, [this](const QModelIndex&, int first, int last) {
        updateCounts();
        if (!m_liveTop || first != 0 || !m_anchoring)
            return;
        m_newCount += last - first + 1;
        showNewItems(m_newCount, u("%1 条新记录").arg(m_newCount));
        QTimer::singleShot(0, this, [this] {
            if (!m_anchoring)
                return;
            m_list->settleLayout();
            if (m_anchor.isValid()) {
                const int y = m_list->visualRect(m_anchor).top();
                QScrollBar* sb = m_list->verticalScrollBar();
                sb->setValue(sb->value() + (y - m_anchorY));
            }
            m_anchoring = false;
        });
    });
    connect(m_filter, &QAbstractItemModel::rowsRemoved, this, [this] { updateCounts(); });
    connect(m_filter, &QAbstractItemModel::dataChanged, this, [this](const QModelIndex& a, const QModelIndex& b) {
        const QModelIndex cur = m_list->currentIndex();
        if (isInspectorOpen() && cur.isValid() && cur.row() >= a.row() && cur.row() <= b.row())
            rebuildInspector();
    });

    setNoDataContent(QStringLiteral("list"), u("暂无记录"), QString());
    refreshEmpty();
}

void RecordBrowser::setGrouped(bool grouped, bool collapsible, bool rail)
{
    m_list->setUniformItemSizes(!grouped);
    m_list->setStickyHeaders(grouped);
    m_list->recordDelegate()->setCollapsible(grouped && collapsible);
    m_list->recordDelegate()->setRail(rail);
    m_list->viewport()->update();
}

void RecordBrowser::setIdentity(const QColor& hue)
{
    ListShell::setIdentity(hue);
    m_list->recordDelegate()->setIdentity(hue);
    m_list->viewport()->update();
    refreshEmpty();
}

void RecordBrowser::setMultiSelect(bool on)
{
    m_multi = on;
    if (!m_checkMode)
        m_list->setSelectionMode(on ? QAbstractItemView::ExtendedSelection
                                    : QAbstractItemView::SingleSelection);
}

void RecordBrowser::setCheckMode(bool on)
{
    if (on == m_checkMode)
        return;
    m_checkMode = on;
    if (on && isInspectorOpen())
        setInspectorOpen(false);
    m_list->clearSelection();
    // MultiSelection: a click / Space toggles one row and leaves the others alone.
    m_list->setSelectionMode(on ? QAbstractItemView::MultiSelection
                             : m_multi ? QAbstractItemView::ExtendedSelection
                                       : QAbstractItemView::SingleSelection);
    m_list->recordDelegate()->setCheckable(on);
    m_list->viewport()->update();
    batchBar()->setCheckMode(on);
    syncBatch();
    if (on)
        m_list->setFocus(Qt::OtherFocusReason); // Space / ↑↓ work straight away
    emit checkModeChanged(on);
}

void RecordBrowser::setPredicate(std::function<bool(int)> pred)
{
    m_filter->setPredicate(std::move(pred));
    updateCounts();
}

void RecordBrowser::setInspectorBuilder(std::function<void(Inspector*, int)> build)
{
    m_buildInspector = std::move(build);
}

void RecordBrowser::setActivateHandler(std::function<void(int)> fn)
{
    m_activate = std::move(fn);
}

void RecordBrowser::setContextMenuBuilder(std::function<void(QMenu*, const QList<int>&)> fn)
{
    m_contextMenu = std::move(fn);
}

void RecordBrowser::setConnected(bool connected)
{
    m_connected = connected;
    refreshEmpty();
}

void RecordBrowser::setLoading(bool loading)
{
    m_loading = loading;
    refreshEmpty();
}

void RecordBrowser::setDisconnectedText(const QString& body)
{
    m_disconnectedBody = body;
    refreshEmpty();
}

void RecordBrowser::setNoDataContent(const QString& icon, const QString& title, const QString& body,
                                     const QString& actionText, std::function<void()> action)
{
    m_noDataIcon = icon;
    m_noDataTitle = title;
    m_noDataBody = body;
    m_noDataActionText = actionText;
    m_noDataAction = std::move(action);
    refreshEmpty();
}

void RecordBrowser::refilter()
{
    m_filter->refresh();
    updateCounts();
}

void RecordBrowser::updateCounts()
{
    setMatch(m_filter->matchedRecords(), m_filter->totalRecords());
    refreshEmpty();
    syncBatch(); // rows came or went: the count and 全选 / 取消全选 may be stale
}

int RecordBrowser::syncBatch()
{
    const int n = int(selectedSourceRows().size());
    if (!batchBar()->hasActions())
        return n; // nothing to do in bulk on this page: the bar never shows
    int listed = 0;
    for (int r = 0, rows = m_filter->rowCount(); r < rows; ++r)
        if (!m_filter->index(r, 0).data(rec::Header).toBool())
            ++listed;
    batchBar()->setCount(n, listed);
    const bool show = m_checkMode || n >= 2;
    setBatchVisible(show);
    // The bar floats over the bottom of the list: keep the last record reachable above it.
    m_list->setBottomInset(show ? batchBar()->height() + 18 : 0);
    return n;
}

bool RecordBrowser::restoreSelection(const QList<QVariant>& keys, const QVariant& current)
{
    QSet<QString> wanted;
    for (const QVariant& k : keys) {
        const QString s = k.toString();
        if (!s.isEmpty())
            wanted.insert(s);
    }
    // One range per run of adjacent rows (select-all stays a single range).
    QItemSelection sel;
    QModelIndex cur;
    int runStart = -1;
    const int rows = m_filter->rowCount();
    for (int r = 0; r <= rows; ++r) {
        bool hit = false;
        if (r < rows) {
            const QModelIndex pi = m_filter->index(r, 0);
            const int src = m_filter->mapToSource(pi).row();
            if (src >= 0 && !m_model->isHeader(src)) {
                const QVariant& k = m_model->at(src).key;
                if (!wanted.isEmpty()) {
                    const QString s = k.toString();
                    hit = !s.isEmpty() && wanted.contains(s);
                }
                if (!cur.isValid() && current.isValid() && k == current)
                    cur = pi;
            }
        }
        if (hit && runStart < 0) {
            runStart = r;
        } else if (!hit && runStart >= 0) {
            sel.select(m_filter->index(runStart, 0), m_filter->index(r - 1, 0));
            runStart = -1;
        }
    }
    QItemSelectionModel* sm = m_list->selectionModel();
    m_selecting = true;
    if (cur.isValid())
        sm->setCurrentIndex(cur, QItemSelectionModel::NoUpdate);
    sm->select(sel, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    m_selecting = false;
    return cur.isValid();
}

void RecordBrowser::refreshEmpty()
{
    const int total = m_filter->totalRecords();
    Empty k = Empty::None;
    if (total == 0 && m_needsConnection && !m_connected)
        k = Empty::Disconnected;
    else if (total == 0 && m_loading)
        k = Empty::Loading;
    else if (total == 0)
        k = Empty::NoData;
    else if (m_filter->matchedRecords() == 0)
        k = Empty::NoMatch;
    m_emptyKind = k;

    EmptyState* es = emptyState();
    switch (k) {
    case Empty::None:
        break;
    case Empty::Disconnected:
        es->setContent(QStringLiteral("server"), theme::textMuted(), u("未连接后台服务"),
                       m_disconnectedBody.isEmpty()
                           ? u("界面还没有与后台服务建立连接,暂时读不到这里的数据。服务恢复后会自动刷新。")
                           : m_disconnectedBody);
        es->setAction(QString(), {});
        break;
    // Loading and "nothing here yet" are the page speaking about itself: its own
    // hue. "Not connected" and "filtered out" stay muted — they are conditions,
    // not the page.
    case Empty::Loading:
        es->setContent(QStringLiteral("refresh"), identity().isValid() ? identity() : theme::accent(),
                       u("正在读取…"), QString());
        es->setAction(QString(), {});
        break;
    case Empty::NoData:
        es->setContent(m_noDataIcon, identity().isValid() ? identity() : theme::textSecondary(), m_noDataTitle,
                       m_noDataBody);
        es->setAction(m_noDataActionText, m_noDataAction, "primary");
        break;
    case Empty::NoMatch:
        es->setContent(QStringLiteral("search"), theme::textMuted(), u("没有匹配的记录"),
                       u("当前的筛选或搜索条件下没有记录。"));
        es->setAction(u("清除筛选"), [this] {
            searchBox()->clear();
            if (m_clearFilters)
                m_clearFilters();
            refilter();
        });
        break;
    }
    setEmptyVisible(k != Empty::None);
}

void RecordBrowser::onCurrentChanged(const QModelIndex& current)
{
    if (!current.isValid()) {
        if (isInspectorOpen() && !m_selecting)
            setInspectorOpen(false);
        return;
    }
    const int src = m_filter->mapToSource(current).row();
    emit currentRowChanged(src);
    if (m_selecting)
        return;
    if (isInspectorOpen() && m_buildInspector && selectedSourceRows().size() <= 1)
        showInspectorFor(src);
}

void RecordBrowser::showInspectorFor(int sourceRow)
{
    if (!m_buildInspector || sourceRow < 0 || m_model->isHeader(sourceRow))
        return;
    Inspector* in = inspector();
    in->setUpdatesEnabled(false);
    in->clear();
    m_buildInspector(in, sourceRow);
    in->setUpdatesEnabled(true);
    setInspectorOpen(true);
}

void RecordBrowser::rebuildInspector()
{
    const int src = currentSourceRow();
    if (isInspectorOpen() && src >= 0)
        showInspectorFor(src);
}

QList<int> RecordBrowser::selectedSourceRows() const
{
    QList<int> rows;
    for (const QModelIndex& i : m_list->selectionModel()->selectedRows()) {
        const int src = m_filter->mapToSource(i).row();
        if (src >= 0 && !m_model->isHeader(src))
            rows.append(src);
    }
    std::sort(rows.begin(), rows.end());
    return rows;
}

int RecordBrowser::currentSourceRow() const
{
    const QModelIndex cur = m_list->currentIndex();
    if (!cur.isValid())
        return -1;
    const int src = m_filter->mapToSource(cur).row();
    return m_model->isHeader(src) ? -1 : src;
}

QVariant RecordBrowser::currentKey() const
{
    const int src = currentSourceRow();
    return src >= 0 ? m_model->at(src).key : QVariant();
}

bool RecordBrowser::selectKey(const QVariant& key, bool openInspector, bool reveal)
{
    const int src = m_model->rowOfKey(key);
    if (src < 0)
        return false;
    QModelIndex pi = m_filter->mapFromSource(m_model->index(src, 0));
    if (!pi.isValid() && reveal) {
        searchBox()->clear();
        if (m_clearFilters)
            m_clearFilters();
        const QString group = m_model->at(src).group;
        if (!group.isEmpty())
            m_filter->setCollapsed(group, false);
        refilter();
        pi = m_filter->mapFromSource(m_model->index(src, 0));
    }
    if (!pi.isValid())
        return false;
    if (m_checkMode)
        setCheckMode(false); // going to one record: the batch selection is over
    m_selecting = true;
    m_list->selectionModel()->setCurrentIndex(pi, QItemSelectionModel::ClearAndSelect);
    m_selecting = false;
    m_list->scrollTo(pi, QAbstractItemView::PositionAtCenter);
    if (openInspector)
        showInspectorFor(src);
    return true;
}

void RecordBrowser::clearSelection()
{
    m_list->clearSelection();
    syncBatch(); // hides the bar — unless in check mode, where it stays with its actions disabled
}

void RecordBrowser::showContextMenu(const QPoint& pos)
{
    if (!m_contextMenu)
        return;
    const QModelIndex i = m_list->indexAt(pos);
    if (!i.isValid() || i.data(rec::Header).toBool())
        return;
    if (!m_list->selectionModel()->isSelected(i)) {
        // Check mode: right-clicking an unticked record ticks it too (the menu acts
        // on everything ticked) instead of throwing the ticked set away.
        const QItemSelectionModel::SelectionFlags how =
            m_checkMode ? (QItemSelectionModel::Select | QItemSelectionModel::Rows)
                        : QItemSelectionModel::SelectionFlags(QItemSelectionModel::ClearAndSelect);
        m_list->selectionModel()->setCurrentIndex(i, how);
    }
    QMenu menu(this);
    m_contextMenu(&menu, selectedSourceRows());
    if (!menu.isEmpty())
        menu.exec(m_list->viewport()->mapToGlobal(pos));
}
