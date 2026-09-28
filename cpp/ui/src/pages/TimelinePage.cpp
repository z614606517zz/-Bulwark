// 事件时间线 —— 按时间窗 / 进程回溯历史事件,并从任一条展开攻击关系图。
//
// 与「事件记录」的分工:事件记录是实时流水(最近 1000 条,一直往上追加),回答「刚刚发生了
// 什么」;时间线是查询视图,回答「昨天下午三点前后这台机器上发生了什么」。查询走服务端落盘的
// events.jsonl(比内存缓冲深得多),所以能回看远超实时列表的历史。
//
// 结果按小时分组(可折叠),一条竖线把同一小时里的事件串起来 —— 时间线的语义就是「按时间
// 倒序读」,所以刻意不提供按别的字段重排。上方的密度条显示事件在时间窗里的分布,拖动可以
// 只看其中一段。
#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "dialogs/EventViews.h"
#include "design/Banner.h"
#include "design/FilterChip.h"
#include "design/Format.h"
#include "design/GlowCard.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Segmented.h"
#include "ipc/IpcClient.h"
#include "widgets/ElidingLabel.h"
#include "Nav.h"

#include <QCheckBox>
#include <QHBoxLayout>
#include <QIntValidator>
#include <QLineEdit>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QSignalBlocker>
#include <QTimeZone>
#include <QToolTip>

#include <algorithm>
#include <cmath>
#include <functional>
#include <iterator>
#include <memory>

using evtfmt::u;
using bulwark::ipc::EventLogPayload;

namespace {

enum Seg { SegAll = 0, SegBlock, SegAsk, SegAllow };

struct RangeOption {
    const char* key;
    const char* label;
    int seconds; // 0 = all history
};
const RangeOption kRanges[] = {
    {"15m", "15 分钟", 15 * 60},  {"1h", "1 小时", 3600},       {"6h", "6 小时", 6 * 3600},
    {"24h", "24 小时", 24 * 3600}, {"7d", "7 天", 7 * 24 * 3600}, {"all", "全部", 0},
};
constexpr int kDefaultRange = 3; // 最近 24 小时:够覆盖「昨晚出了点事」的常见诉求
constexpr int kQueryLimit = 2000;

QString hourTitle(const QDateTime& local)
{
    const QDate d = local.date();
    const QDate today = QDate::currentDate();
    const QString hh = local.toString(QStringLiteral("HH:00"));
    if (d == today)
        return u("今天 ") + hh;
    if (d == today.addDays(-1))
        return u("昨天 ") + hh;
    if (d.year() == today.year())
        return local.toString(QStringLiteral("MM-dd ")) + hh;
    return local.toString(QStringLiteral("yyyy-MM-dd ")) + hh;
}

// ── density bar ─────────────────────────────────────────────────────────────────
// Event counts across the queried window, one bar per slice, coloured by the
// most serious thing in it (a real block, a question, or just activity). Drag
// (or click) to look at one stretch of time only; click the selection again to
// clear it.
class DensityBar : public QWidget
{
public:
    struct Sample {
        qint64 ms;
        int severity; // 0 activity · 1 asked · 2 blocked
    };
    std::function<void(const QDateTime& from, const QDateTime& to)> onSelect; // invalid = cleared
    QColor hue; // plain activity is drawn in the page's identity hue; blocks / questions keep their status

    DensityBar()
    {
        setMouseTracking(true);
        setMinimumHeight(66);
        setCursor(Qt::CrossCursor);
        setAccessibleName(u("事件密度,拖动选择时间段"));
    }

    void setData(const QDateTime& from, const QDateTime& to, const QList<Sample>& samples)
    {
        m_from = from.toMSecsSinceEpoch();
        m_to = std::max(to.toMSecsSinceEpoch(), m_from + 60 * 1000);
        m_count.fill(0, kBuckets);
        m_sev.fill(0, kBuckets);
        for (const Sample& s : samples) {
            const int b = bucketOf(s.ms);
            if (b < 0)
                continue;
            ++m_count[b];
            m_sev[b] = std::max(m_sev[b], s.severity);
        }
        m_max = 0;
        for (int c : std::as_const(m_count))
            m_max = std::max(m_max, c);
        m_selA = m_selB = -1;
        update();
    }

    void clearSelection()
    {
        m_selA = m_selB = -1;
        update();
    }

    QSize sizeHint() const override { return {480, 66}; }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF plot = plotRect();
        const qreal bw = plot.width() / kBuckets;
        if (m_selA >= 0) {
            const int a = std::min(m_selA, m_selB);
            const int b = std::max(m_selA, m_selB);
            const QRectF sel(plot.left() + a * bw, plot.top() - 3, (b - a + 1) * bw, plot.height() + 6);
            p.setPen(QPen(theme::blend(theme::accent(), theme::surface(), 0.65), 1.0));
            p.setBrush(theme::blend(theme::accent(), theme::surface(), 0.16));
            p.drawRoundedRect(sel, 4, 4);
        }
        for (int i = 0; i < m_count.size(); ++i) {
            const qreal x = plot.left() + i * bw;
            if (m_count[i] == 0 || m_max == 0) {
                p.setPen(Qt::NoPen);
                p.setBrush(theme::border());
                p.drawRect(QRectF(x + 1, plot.bottom() - 1, std::max(1.0, bw - 2), 1));
                continue;
            }
            const qreal h = std::max(3.0, std::sqrt(qreal(m_count[i]) / m_max) * plot.height());
            QColor c = m_sev[i] >= 2 ? theme::danger()
                       : m_sev[i] == 1 ? theme::warning()
                                       : theme::blend(hue.isValid() ? hue : theme::accent(), theme::surface(), 0.62);
            if (i == m_hover)
                c = c.lighter(130);
            p.setPen(Qt::NoPen);
            p.setBrush(c);
            p.drawRoundedRect(QRectF(x + 1, plot.bottom() - h, std::max(1.0, bw - 2), h), 1.5, 1.5);
        }
        // time axis: start · middle · end
        QFont f = font();
        f.setPointSizeF(8.0);
        p.setFont(f);
        p.setPen(theme::textMuted());
        const QRectF axis(plot.left(), plot.bottom() + 3, plot.width(), 14);
        p.drawText(axis, Qt::AlignLeft | Qt::AlignVCenter, label(m_from));
        p.drawText(axis, Qt::AlignHCenter | Qt::AlignVCenter, label(m_from + (m_to - m_from) / 2));
        p.drawText(axis, Qt::AlignRight | Qt::AlignVCenter, label(m_to));
    }

    void mousePressEvent(QMouseEvent* e) override
    {
        if (e->button() != Qt::LeftButton)
            return;
        m_prevA = m_selA;
        m_prevB = m_selB;
        m_selA = m_selB = bucketAtX(e->position().x());
        update();
    }

    void mouseMoveEvent(QMouseEvent* e) override
    {
        const int b = bucketAtX(e->position().x());
        if (e->buttons() & Qt::LeftButton) {
            if (b != m_selB) {
                m_selB = b;
                update();
            }
        }
        if (b != m_hover) {
            m_hover = b;
            update();
        }
        if (b >= 0 && b < m_count.size())
            QToolTip::showText(e->globalPosition().toPoint(), tip(b), this);
    }

    void mouseReleaseEvent(QMouseEvent* e) override
    {
        if (e->button() != Qt::LeftButton || m_selA < 0)
            return;
        int a = std::min(m_selA, m_selB);
        int b = std::max(m_selA, m_selB);
        const int pa = std::min(m_prevA, m_prevB);
        const int pb = std::max(m_prevA, m_prevB);
        if (a == b && a == pa && b == pb) // clicked the (single-slice) selection again: clear
            a = b = -1;
        m_selA = a;
        m_selB = b;
        update();
        if (onSelect) {
            if (a < 0)
                onSelect(QDateTime(), QDateTime());
            else
                onSelect(QDateTime::fromMSecsSinceEpoch(bucketStart(a), QTimeZone::UTC),
                         QDateTime::fromMSecsSinceEpoch(bucketStart(b + 1), QTimeZone::UTC));
        }
    }

    void leaveEvent(QEvent*) override
    {
        m_hover = -1;
        update();
    }

private:
    static constexpr int kBuckets = 60;

    QRectF plotRect() const { return QRectF(rect()).adjusted(6, 8, -6, -20); }

    qint64 bucketStart(int i) const { return m_from + (m_to - m_from) * i / kBuckets; }

    int bucketOf(qint64 ms) const
    {
        if (ms < m_from || ms > m_to || m_to <= m_from)
            return -1;
        return std::clamp(int((ms - m_from) * kBuckets / (m_to - m_from)), 0, kBuckets - 1);
    }

    int bucketAtX(qreal x) const
    {
        const QRectF plot = plotRect();
        return std::clamp(int((x - plot.left()) / (plot.width() / kBuckets)), 0, kBuckets - 1);
    }

    QString label(qint64 ms) const
    {
        const QDateTime t = QDateTime::fromMSecsSinceEpoch(ms).toLocalTime();
        return (m_to - m_from) <= qint64(36) * 3600 * 1000 ? t.toString(QStringLiteral("HH:mm"))
                                                          : t.toString(QStringLiteral("MM-dd HH:mm"));
    }

    QString tip(int b) const
    {
        const QString span = u("%1 – %2").arg(label(bucketStart(b)), label(bucketStart(b + 1)));
        if (m_count.value(b) == 0)
            return span + u(" · 没有事件");
        return span + u(" · %1 条").arg(m_count.value(b))
             + (m_sev.value(b) >= 2 ? u(",含拦截") : (m_sev.value(b) == 1 ? u(",含询问") : QString()));
    }

    qint64 m_from = 0;
    qint64 m_to = 1;
    QVector<int> m_count = QVector<int>(kBuckets, 0);
    QVector<int> m_sev = QVector<int>(kBuckets, 0);
    int m_max = 0;
    int m_selA = -1;
    int m_selB = -1;
    int m_prevA = -1;
    int m_prevB = -1;
    int m_hover = -1;
};

} // namespace

QWidget* pages::timeline(IpcClient* ipc)
{
    auto* page = new RecordBrowser;
    page->setIdentity(identity::page(nav::Timeline));
    page->setGrouped(true, /*collapsible*/ true, /*rail*/ true);
    page->searchBox()->setPlaceholderText(u("过滤结果 · 回车在全部历史里检索"));
    page->searchBox()->setToolTip(u("输入即在已载入的结果里过滤(多个关键词用空格分隔);"
                                    "按回车按关键字(路径 / 目标 / 命令行 / 发布者)在服务端全部历史里查询"));
    page->setNoDataContent(QStringLiteral("clock"), u("这段时间里没有事件"),
                           u("换一个更长的时间范围,或清除进程 / 关键字条件后重新查询。"));
    auto store = std::make_shared<RecordStore<EventLogPayload>>(page->model(), &evtview::recordView);
    const QString trustSource = u("从时间线信任");

    // ---- query row: time range · process ---------------------------------------------------------
    auto* query = new QWidget;
    auto* qh = new QHBoxLayout(query);
    qh->setContentsMargins(0, 0, 0, 0);
    qh->setSpacing(10);
    auto* range = new Segmented;
    range->setCompact(true);
    range->setIdentity(page->identity());
    range->setAccessibleName(u("时间范围"));
    for (const RangeOption& r : kRanges)
        range->addSegment(u(r.label), r.seconds);
    range->setCurrentIndex(kDefaultRange);
    qh->addWidget(ui::label(u("时间范围"), "caption"));
    qh->addWidget(range);
    qh->addSpacing(12);
    qh->addWidget(ui::label(u("进程"), "caption"));
    auto* pidEdit = new QLineEdit;
    pidEdit->setPlaceholderText(QStringLiteral("PID"));
    pidEdit->setValidator(new QIntValidator(1, 0x7fffffff, pidEdit));
    pidEdit->setClearButtonEnabled(true);
    pidEdit->setFixedWidth(104);
    pidEdit->setAccessibleName(u("只看某个进程(PID)"));
    pidEdit->setToolTip(u("只看这个进程的事件;回车查询"));
    auto* treeBox = new QCheckBox(u("含子进程"));
    treeBox->setChecked(true);
    treeBox->setToolTip(u("按 PID 查询时,把该进程派生出来的整棵进程树的事件一并纳入。"));
    qh->addWidget(pidEdit);
    qh->addWidget(treeBox);
    auto* summary = ui::elided(QString(), "muted");
    summary->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    qh->addWidget(summary, 1);
    page->addTop(query);

    // ---- density bar -------------------------------------------------------------------------------
    auto* density = new DensityBar;
    density->hue = page->identity();
    auto* densityCard = new GlowCard;
    densityCard->setObjectName(QStringLiteral("Card"));
    densityCard->setRadius(14);
    densityCard->setGlow(page->identity(), QPointF(0.0, 0.0), 0.6, 0.06);
    auto* dl = new QVBoxLayout(densityCard);
    dl->setContentsMargins(10, 4, 10, 2);
    dl->addWidget(density);
    page->addAboveList(densityCard);

    // ---- local filters: verdict segments · type · risk · selected time slice ------------------------
    Segmented* seg = page->segments();
    seg->addSegment(u("全部"));
    seg->addSegment(u("拦截"));
    seg->addSegment(u("询问"));
    seg->addSegment(u("放行"));
    seg->setAccent(SegBlock, theme::danger());
    seg->setAccent(SegAsk, theme::warning());
    FilterChip* typeChip = page->addChip(u("类型"));
    typeChip->addOption(u("全部"));
    for (int i = 0; i <= int(bulwark::EventType::DnsQuery); ++i)
        typeChip->addOption(evtfmt::typeShort(bulwark::EventType(i)), i);
    FilterChip* riskChip = page->addChip(u("风险"));
    riskChip->addOption(u("全部"), 0);
    riskChip->addOption(u("可疑及以上"), 50);
    riskChip->addOption(u("仅高危"), 80);
    auto* sliceChip = ui::button(QString(), "ghost", QStringLiteral("close"), true);
    sliceChip->setToolTip(u("清除时间段选择"));
    sliceChip->hide();
    page->addFilterWidget(sliceChip);

    auto slice = std::make_shared<QPair<QDateTime, QDateTime>>();
    page->setPredicate([store, seg, typeChip, riskChip, slice](int row) {
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
        if (slice->first.isValid()
            && (p->event.timestampUtc < slice->first || p->event.timestampUtc >= slice->second))
            return false;
        return true;
    });
    const auto setSlice = [page, slice, sliceChip](const QDateTime& from, const QDateTime& to) {
        *slice = qMakePair(from, to);
        if (from.isValid()) {
            const bool sameDay = from.toLocalTime().date() == to.toLocalTime().date();
            const QString fmtStr = sameDay ? QStringLiteral("HH:mm") : QStringLiteral("MM-dd HH:mm");
            sliceChip->setText(u("%1 – %2").arg(from.toLocalTime().toString(QStringLiteral("MM-dd HH:mm")),
                                                to.toLocalTime().toString(fmtStr)));
        }
        sliceChip->setVisible(from.isValid());
        page->refilter();
    };
    density->onSelect = setSlice;
    QObject::connect(sliceChip, &QPushButton::clicked, page, [density, setSlice] {
        density->clearSelection();
        setSlice(QDateTime(), QDateTime());
    });
    page->setClearFilters([seg, typeChip, riskChip, density, slice, sliceChip] {
        seg->setCurrentIndex(SegAll);
        typeChip->reset();
        riskChip->reset();
        density->clearSelection();
        *slice = {};
        sliceChip->hide();
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
    QObject::connect(seg, &Segmented::currentChanged, page, [page] { page->refilter(); });
    for (FilterChip* c : {typeChip, riskChip})
        QObject::connect(c, &FilterChip::currentChanged, page, [page] { page->refilter(); });

    // ---- record -> inspector / window / menu ------------------------------------------------------
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

    // ---- the query (server side: time window · PID / tree · keyword on Enter) ---------------------
    auto lastId = std::make_shared<QUuid>();
    auto serverText = std::make_shared<QString>();
    auto window = std::make_shared<QPair<QDateTime, QDateTime>>();
    auto lastPid = std::make_shared<int>(0);
    const auto runQuery = [ipc, page, range, pidEdit, treeBox, summary, lastId, serverText, window, lastPid] {
        if (!ipc->isConnected())
            return; // the list shows 「未连接」
        bulwark::ipc::TimelineRequestPayload req;
        const int secs = range->currentData().toInt();
        const QDateTime now = QDateTime::currentDateTimeUtc();
        if (secs > 0)
            req.fromUtc = now.addSecs(-secs);
        req.pid = pidEdit->text().trimmed().toInt();
        req.includeProcessTree = treeBox->isChecked();
        req.text = *serverText;
        req.limit = kQueryLimit;
        *lastPid = req.pid;
        *lastId = req.requestId;
        *window = qMakePair(req.fromUtc, now);
        page->setLoading(true);
        summary->setText(u("查询中…"));
        ipc->requestTimeline(req);
    };

    QObject::connect(ipc, &IpcClient::timelineReceived, page,
                     [page, store, density, summary, lastId, serverText, window, updateCounts, slice,
                      sliceChip](const bulwark::ipc::TimelineResponsePayload& p) {
        if (p.requestId != *lastId)
            return; // 仪表盘等别处发起的查询,与本页无关
        QList<EventLogPayload> items(p.events.crbegin(), p.events.crend()); // 服务端升序 -> 最新在上
        store->resetGrouped(
            items,
            [](const EventLogPayload& e) {
                return e.event.timestampUtc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH"));
            },
            [](const QString&, const QList<const EventLogPayload*>& members) {
                RecordView h;
                const QDateTime t = members.isEmpty() ? QDateTime() : members.first()->event.timestampUtc.toLocalTime();
                h.title = hourTitle(t);
                int blocks = 0;
                int asks = 0;
                int maxRisk = 0;
                for (const EventLogPayload* m : members) {
                    if (evtfmt::isRealBlock(m->action, m->enforcement))
                        ++blocks;
                    else if (m->action == bulwark::VerdictAction::Ask)
                        ++asks;
                    maxRisk = std::max(maxRisk, m->event.riskScore);
                }
                QStringList note;
                if (blocks) note << u("拦截 %1").arg(blocks);
                if (asks) note << u("询问 %1").arg(asks);
                if (maxRisk >= 50) note << u("最高风险 %1").arg(maxRisk);
                h.groupNote = note.join(u(" · "));
                h.groupColor = blocks ? theme::danger() : (maxRisk >= 50 ? theme::warning() : QColor());
                return h;
            });
        page->setLoading(false);
        updateCounts();

        // Density over what was actually loaded: when the result was truncated,
        // older events weren't loaded, so the bar must not show that stretch as empty.
        const QDateTime to = window->second.isValid() ? window->second : QDateTime::currentDateTimeUtc();
        QDateTime from = window->first;
        if (!from.isValid() || p.truncated)
            from = p.events.isEmpty() ? (p.earliestUtc.isValid() ? p.earliestUtc : to.addSecs(-3600))
                                      : p.events.first().event.timestampUtc;
        QList<DensityBar::Sample> samples;
        samples.reserve(p.events.size());
        for (const EventLogPayload& e : p.events) {
            const int sev = evtfmt::isRealBlock(e.action, e.enforcement) ? 2
                            : e.action == bulwark::VerdictAction::Ask     ? 1
                                                                          : 0;
            samples.append(DensityBar::Sample{e.event.timestampUtc.toMSecsSinceEpoch(), sev});
        }
        density->setData(from, to, samples);
        *slice = {};
        sliceChip->hide();
        page->refilter();

        QStringList parts;
        if (p.events.isEmpty())
            parts << (p.message.isEmpty() ? u("没有符合条件的事件") : p.message);
        else
            parts << u("载入 %1 条").arg(p.events.size());
        if (!serverText->isEmpty())
            parts << u("关键字「%1」").arg(*serverText);
        if (p.earliestUtc.isValid())
            parts << u("历史可回溯至 %1").arg(p.earliestUtc.toLocalTime().toString(QStringLiteral("MM-dd HH:mm")));
        summary->setText(parts.join(u(" · ")));
        if (p.truncated)
            ui::notify(page, ui::Tone::Warning,
                       u("命中 %1 条,只载入了最近的 %2 条。缩小时间范围或按 PID 查询,才能看到更早的事件。")
                           .arg(p.matched)
                           .arg(p.events.size()));
    });

    QObject::connect(range, &Segmented::currentChanged, page, [runQuery] { runQuery(); });
    QObject::connect(pidEdit, &QLineEdit::returnPressed, page, [runQuery] { runQuery(); });
    QObject::connect(pidEdit, &QLineEdit::textChanged, page, [runQuery, lastPid](const QString& t) {
        if (t.trimmed().isEmpty() && *lastPid != 0)
            runQuery(); // cleared with ✕: back to every process
    });
    QObject::connect(treeBox, &QCheckBox::toggled, page, [runQuery, pidEdit] {
        if (!pidEdit->text().trimmed().isEmpty())
            runQuery();
    });
    QObject::connect(page->searchBox(), &QLineEdit::returnPressed, page, [page, serverText, runQuery] {
        *serverText = page->searchBox()->text().trimmed();
        runQuery();
    });
    QObject::connect(page->searchBox(), &QLineEdit::textChanged, page, [serverText, runQuery](const QString& t) {
        if (t.trimmed().isEmpty() && !serverText->isEmpty()) {
            serverText->clear();
            runQuery();
        }
    });

    QHBoxLayout* actions = pagekit::headerActions(page);
    QObject::connect(pagekit::headerButton(actions, QStringLiteral("refresh"), u("重新查询")), &QPushButton::clicked,
                     page, [runQuery] { runQuery(); });

    // 首次进入自动查一次最近 24 小时,页面不至于是空的。延后一点,避开启动峰值。
    pagekit::onConnected(page, ipc, page, 1200, runQuery);

    // ---- navigation: nav::go("timeline", {pid, tree, range, text}) ------------------------------------
    nav::onArrive(page, QString::fromLatin1(nav::Timeline),
                  [page, range, pidEdit, treeBox, serverText, runQuery](const QVariantMap& args) {
        {
            const QSignalBlocker b1(range);
            const QSignalBlocker b2(pidEdit);
            const QSignalBlocker b3(treeBox);
            if (args.contains(QStringLiteral("range"))) {
                const QString key = args.value(QStringLiteral("range")).toString();
                for (int i = 0; i < int(std::size(kRanges)); ++i)
                    if (key == QLatin1String(kRanges[i].key))
                        range->setCurrentIndex(i);
            }
            if (args.contains(QStringLiteral("pid"))) {
                const int pid = args.value(QStringLiteral("pid")).toInt();
                pidEdit->setText(pid > 0 ? QString::number(pid) : QString());
                treeBox->setChecked(args.value(QStringLiteral("tree"), true).toBool());
            }
        }
        if (args.contains(QStringLiteral("text"))) {
            // Not signal-blocked: the browser's own local filter listens to the box too.
            *serverText = args.value(QStringLiteral("text")).toString().trimmed();
            page->searchBox()->setText(*serverText);
        }
        runQuery();
    });
    updateCounts();
    return page;
}
