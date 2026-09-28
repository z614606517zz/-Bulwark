#include "pages/DashboardPage.h"
#include "dialogs/EventFormat.h"
#include "dialogs/EventViews.h"
#include "design/Backdrop.h"
#include "design/Components.h"
#include "design/Format.h"
#include "design/GlowCard.h"
#include "design/IconTile.h"
#include "design/Icons.h"
#include "design/Inspector.h"
#include "design/ShieldEmblem.h"
#include "design/Theme.h"
#include "ipc/IpcClient.h"
#include "Nav.h"

#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/models/SecurityEvent.h"

#include <QDateTime>
#include <QEnterEvent>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLocale>
#include <QLinearGradient>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QResizeEvent>
#include <QScrollArea>
#include <QShowEvent>
#include <QTimer>
#include <QToolTip>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <cmath>
#include <functional>
#include <utility>

using evtfmt::u;

namespace {

void go(const char* key, const QVariantMap& args = {})
{
    nav::go(QString::fromLatin1(key), args);
}

// A card that is also a button: click / Enter / Space open what it summarises.
class ClickCard : public GlowCard
{
public:
    std::function<void()> onClick;
    QColor tone;

    ClickCard()
    {
        setCursor(Qt::PointingHandCursor);
        setFocusPolicy(Qt::TabFocus);
    }

protected:
    void paintEvent(QPaintEvent* e) override
    {
        GlowCard::paintEvent(e);
        if (!hasFocus() && !m_hover)
            return;
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(QPen(hasFocus() ? theme::accent() : theme::blend(tone, theme::surface(), 0.55), hasFocus() ? 1.6 : 1.1));
        p.setBrush(Qt::NoBrush);
        p.drawRoundedRect(QRectF(rect()).adjusted(0.8, 0.8, -0.8, -0.8), 15, 15);
    }
    void mouseReleaseEvent(QMouseEvent* e) override
    {
        if (e->button() == Qt::LeftButton && rect().contains(e->position().toPoint()) && onClick)
            onClick();
    }
    void keyPressEvent(QKeyEvent* e) override
    {
        if ((e->key() == Qt::Key_Return || e->key() == Qt::Key_Enter || e->key() == Qt::Key_Space) && onClick) {
            onClick();
            return;
        }
        GlowCard::keyPressEvent(e);
    }
    void enterEvent(QEnterEvent* e) override
    {
        m_hover = true;
        update();
        GlowCard::enterEvent(e);
    }
    void leaveEvent(QEvent* e) override
    {
        m_hover = false;
        update();
        GlowCard::leaveEvent(e);
    }
    void focusInEvent(QFocusEvent* e) override
    {
        update();
        GlowCard::focusInEvent(e);
    }
    void focusOutEvent(QFocusEvent* e) override
    {
        update();
        GlowCard::focusOutEvent(e);
    }

private:
    bool m_hover = false;
};

// The hero card: a wall of stone courses (the 垒 of 磐垒) rises from its right edge
// and fades out before the status text. The mortar takes the colour of the *real*
// protection state — grey while it is unknown — so the texture can never look
// "safe" when the page doesn't know that it is.
class HeroCard : public GlowCard
{
public:
    void setMortar(const QColor& c, qreal strength)
    {
        m_mortar = c;
        m_strength = strength;
        update();
    }

protected:
    void paintEvent(QPaintEvent* e) override
    {
        GlowCard::paintEvent(e);
        if (!m_mortar.isValid() || m_strength <= 0.0 || width() < 80)
            return;
        QPainter p(this);
        const QRectF r = QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5);
        QPainterPath shape;
        shape.addRoundedRect(r, 17.0, 17.0);
        p.setClipPath(shape);
        QLinearGradient fade(r.topRight(), QPointF(r.left() + r.width() * 0.30, r.top()));
        fade.setColorAt(0.0, theme::tint(m_mortar, m_strength));
        fade.setColorAt(1.0, theme::tint(m_mortar, 0.0));
        Backdrop::paintCourses(p, r, QBrush(fade), 16.0);
    }

private:
    QColor m_mortar;
    qreal m_strength = 0.0;
};

// A row inside a card that opens something (activity item).
class ClickRow : public QWidget
{
public:
    std::function<void()> onClick;
    ClickRow()
    {
        setCursor(Qt::PointingHandCursor);
        setAttribute(Qt::WA_Hover);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        if (!underMouse())
            return;
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(Qt::NoPen);
        p.setBrush(theme::surfaceAlt());
        p.drawRoundedRect(QRectF(rect()).adjusted(-6, 0, 6, 0), 10, 10);
    }
    void mouseReleaseEvent(QMouseEvent* e) override
    {
        if (e->button() == Qt::LeftButton && onClick)
            onClick();
    }
    void enterEvent(QEnterEvent*) override { update(); }
    void leaveEvent(QEvent*) override { update(); }
};

// Hourly event counts for the last 24 h, stacked by what was done (放行 / 询问 / 拦截).
class HourChart : public QWidget
{
public:
    std::function<void()> onClick;

    HourChart()
    {
        setMinimumHeight(150);
        setMouseTracking(true);
        setCursor(Qt::PointingHandCursor);
        setAccessibleName(u("过去 24 小时的事件分布,点击在事件时间线中查看"));
    }

    void reset()
    {
        m_counts.clear();
        update();
    }
    // severity: 0 放行 · 1 询问 · 2 拦截
    void add(const QDateTime& utc, int severity)
    {
        m_counts[hourKey(utc.toMSecsSinceEpoch())][std::clamp(severity, 0, 2)]++;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF plot = QRectF(rect()).adjusted(4, 10, -4, -22);
        const qint64 nowHour = hourKey(QDateTime::currentMSecsSinceEpoch());
        int maxTotal = 0;
        std::array<std::array<int, 3>, 24> bars{};
        for (int i = 0; i < 24; ++i) {
            const auto it = m_counts.constFind(nowHour - qint64(23 - i) * 3600000);
            if (it != m_counts.constEnd())
                bars[size_t(i)] = *it;
            maxTotal = std::max(maxTotal, bars[size_t(i)][0] + bars[size_t(i)][1] + bars[size_t(i)][2]);
        }
        const qreal bw = plot.width() / 24.0;
        // baseline
        p.setPen(QPen(theme::border(), 1.0));
        p.drawLine(QPointF(plot.left(), plot.bottom() + 0.5), QPointF(plot.right(), plot.bottom() + 0.5));
        if (maxTotal == 0) {
            p.setPen(theme::textMuted());
            p.drawText(plot, Qt::AlignCenter, u("过去 24 小时没有事件"));
        }
        const QColor colors[3] = {theme::blend(theme::accent(), theme::surface(), 0.6), theme::warning(), theme::danger()};
        for (int i = 0; i < 24 && maxTotal > 0; ++i) {
            const auto& b = bars[size_t(i)];
            const int total = b[0] + b[1] + b[2];
            if (total == 0)
                continue;
            const qreal fullH = std::max(3.0, std::sqrt(qreal(total) / maxTotal) * plot.height());
            qreal y = plot.bottom();
            for (int s = 0; s < 3; ++s) {
                if (b[size_t(s)] == 0)
                    continue;
                const qreal h = fullH * b[size_t(s)] / total;
                QColor c = colors[s];
                if (i == m_hover)
                    c = c.lighter(125);
                p.setPen(Qt::NoPen);
                p.setBrush(c);
                p.drawRoundedRect(QRectF(plot.left() + i * bw + 2, y - h, std::max(2.0, bw - 4), h), 1.5, 1.5);
                y -= h;
            }
        }
        QFont f = font();
        f.setPointSizeF(8.0);
        p.setFont(f);
        p.setPen(theme::textMuted());
        for (int i : {0, 6, 12, 18, 23}) {
            const QDateTime t = QDateTime::fromMSecsSinceEpoch(nowHour - qint64(23 - i) * 3600000).toLocalTime();
            const QRectF cell(plot.left() + i * bw - 20, plot.bottom() + 4, bw + 40, 14);
            p.drawText(cell, Qt::AlignHCenter | Qt::AlignVCenter, i == 23 ? u("现在") : t.toString(QStringLiteral("HH:00")));
        }
    }
    void mouseMoveEvent(QMouseEvent* e) override
    {
        const QRectF plot = QRectF(rect()).adjusted(4, 10, -4, -22);
        const int i = std::clamp(int((e->position().x() - plot.left()) / (plot.width() / 24.0)), 0, 23);
        if (i != m_hover) {
            m_hover = i;
            update();
        }
        const qint64 hour = hourKey(QDateTime::currentMSecsSinceEpoch()) - qint64(23 - i) * 3600000;
        const std::array<int, 3> b = m_counts.value(hour, std::array<int, 3>{});
        const QDateTime t = QDateTime::fromMSecsSinceEpoch(hour).toLocalTime();
        QString text = u("%1 – %2 · %3 条").arg(t.toString(QStringLiteral("HH:00")), t.addSecs(3600).toString(QStringLiteral("HH:00")))
                           .arg(b[0] + b[1] + b[2]);
        if (b[2] || b[1])
            text += u("(拦截 %1 · 询问 %2)").arg(b[2]).arg(b[1]);
        QToolTip::showText(e->globalPosition().toPoint(), text, this);
    }
    void leaveEvent(QEvent*) override
    {
        m_hover = -1;
        update();
    }
    void mouseReleaseEvent(QMouseEvent* e) override
    {
        if (e->button() == Qt::LeftButton && onClick)
            onClick();
    }

private:
    static qint64 hourKey(qint64 ms) { return ms - ms % 3600000; }
    QHash<qint64, std::array<int, 3>> m_counts;
    int m_hover = -1;
};

int severityOf(const bulwark::ipc::EventLogPayload& p)
{
    if (evtfmt::isRealBlock(p.action, p.enforcement))
        return 2;
    return p.action == bulwark::VerdictAction::Ask ? 1 : 0;
}

// A stat tile whose value (and optionally caption) label is handed back for live updates.
ClickCard* makeStat(const QString& icon, const QColor& color, const QString& name, const QString& caption,
                    QLabel*& valueOut, std::function<void()> onClick, QLabel** captionOut = nullptr)
{
    auto* c = new ClickCard;
    c->setObjectName(QStringLiteral("Card"));
    c->setGlow(color, QPointF(1.0, 0.0), 0.75, 0.13);
    c->tone = color;
    c->onClick = std::move(onClick);
    c->setMinimumHeight(118);
    c->setAccessibleName(name);
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(18, 16, 18, 16);
    v->setSpacing(4);
    auto* top = new QHBoxLayout;
    top->setContentsMargins(0, 0, 0, 0);
    top->addWidget(ui::label(name, "secondary"), 1, Qt::AlignVCenter);
    top->addWidget(new IconTile(icon, color, 34, 18), 0, Qt::AlignTop);
    v->addLayout(top);
    valueOut = ui::label(QStringLiteral("0"), "stat");
    v->addWidget(valueOut);
    auto* cap = ui::label(caption, "muted");
    v->addWidget(cap);
    if (captionOut)
        *captionOut = cap;
    return c;
}

// Section header used by the lower cards: title + optional trailing widget.
QHBoxLayout* cardHead(const QString& title, QWidget* trailing = nullptr)
{
    auto* head = new QHBoxLayout;
    head->setContentsMargins(0, 0, 0, 0);
    head->addWidget(ui::label(title, "h2"));
    head->addStretch();
    if (trailing)
        head->addWidget(trailing, 0, Qt::AlignVCenter);
    return head;
}

QWidget* attentionRow(const QString& icon, const QColor& color, const QString& title, const QString& desc,
                      const QString& actionText, std::function<void()> fn)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 8, 0, 8);
    h->setSpacing(12);
    h->addWidget(new IconTile(icon, color, 34, 17), 0, Qt::AlignTop);
    auto* col = new QVBoxLayout;
    col->setSpacing(2);
    col->addWidget(ui::label(title, "title"));
    if (!desc.isEmpty()) {
        auto* d = ui::label(desc, "muted");
        d->setWordWrap(true);
        col->addWidget(d);
    }
    h->addLayout(col, 1);
    if (!actionText.isEmpty() && fn) {
        auto* b = ui::button(actionText, "ghost", QString(), true);
        QObject::connect(b, &QPushButton::clicked, w, [fn = std::move(fn)] { fn(); });
        h->addWidget(b, 0, Qt::AlignVCenter);
    }
    return w;
}

} // namespace

DashboardPage::DashboardPage(IpcClient* ipc, QWidget* parent) : QWidget(parent), m_ipc(ipc)
{
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->viewport()->setAutoFillBackground(false);
    outer->addWidget(scroll);
    auto* content = new QWidget;
    auto* v = new QVBoxLayout(content);
    v->setContentsMargins(theme::metric::pagePad, 16, theme::metric::pagePad, theme::metric::pagePad);
    v->setSpacing(18);

    v->addWidget(buildHero());
    v->addWidget(buildStats());
    auto* mid = new QHBoxLayout;
    mid->setSpacing(18);
    mid->addWidget(buildChart(), 3);
    mid->addWidget(buildAttention(), 2);
    v->addLayout(mid);
    auto* low = new QHBoxLayout;
    low->setSpacing(18);
    low->addWidget(buildActivity(), 3);
    low->addWidget(buildDimensions(), 2);
    v->addLayout(low);
    v->addStretch();
    scroll->setWidget(content);
    content->setAutoFillBackground(false); // setWidget() turns it on; the page canvas shows through
    refreshHero();
    refreshAttention();

    // ---- live wiring ----
    connect(ipc, &IpcClient::eventLogReceived, this, [this](const bulwark::ipc::EventLogPayload& p) {
        m_statEvents->setText(QString::number(++m_eventCount));
        // 「本次拦截」只统计【真实拦截】(内核前拦 / 已结束进程 / 已禁止加载);仅告警、拦截失败
        // 不计入,避免拦截数虚高造成"看起来拦了很多、其实没拦"的假象 —— 它们进「需要关注」。
        if (evtfmt::isRealBlock(p.action, p.enforcement))
            m_statBlocked->setText(QString::number(++m_blockedCount));
        else if (p.action == bulwark::VerdictAction::Block) {
            ++m_unenforced;
            refreshAttention();
        }
        if (m_chartFetched.isValid())
            static_cast<HourChart*>(m_chart)->add(p.event.timestampUtc, severityOf(p));

        // Prepend a compact activity row (cap at 6). 处置按【真实执行结果】显示,杜绝假拦截。
        const bulwark::SecurityEvent& e = p.event;
        const evtfmt::Badge d = evtfmt::disposition(p.action, p.enforcement);
        auto* row = new ClickRow;
        auto* h = new QHBoxLayout(row);
        h->setContentsMargins(0, 7, 0, 7);
        h->setSpacing(12);
        h->addWidget(new IconTile(evtfmt::typeGlyph(e.type), d.color, 34, 17), 0, Qt::AlignVCenter);
        auto* col = new QVBoxLayout;
        col->setSpacing(1);
        col->addWidget(ui::elided(evtfmt::actorName(e.actorPath) + u(" · ") + evtfmt::action(e.type), "title"));
        auto* meta = ui::elided((e.target.isEmpty() ? evtfmt::nativePath(e.actorPath) : e.target) + u("  ·  ")
                                    + e.timestampUtc.toLocalTime().toString(QStringLiteral("HH:mm:ss")),
                                "muted");
        meta->setElideMode(Qt::ElideMiddle);
        col->addWidget(meta);
        h->addLayout(col, 1);
        h->addWidget(ui::pill(d.text, d.color), 0, Qt::AlignVCenter);
        const QString key = evtview::keyOf(e);
        row->onClick = [key] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("all")}, {QStringLiteral("select"), key}}); };
        row->setToolTip(u("在事件记录中查看"));
        // 有内容了就不能再说"暂无活动"(隐藏而非删除:淘汰最旧行的逻辑依赖它占着最后一个位置)。
        m_activityEmpty->hide();
        m_activityBox->insertWidget(0, row);
        if (++m_activityRows > 6) {
            if (QLayoutItem* item = m_activityBox->takeAt(m_activityBox->count() - 2)) {
                // 先隐藏:出了布局的行在延迟删除前仍会按旧几何绘制,和新行叠在一起。
                if (QWidget* w = item->widget()) {
                    w->hide();
                    w->deleteLater();
                }
                delete item;
            }
            --m_activityRows;
        }
    });
    connect(ipc, &IpcClient::attackChainHit, this, [this](const bulwark::ipc::AttackChainHitPayload& hit) {
        if (hit.grade == QLatin1String("hard")) {
            ++m_hardChains;
            refreshAttention();
        }
    });
    connect(ipc, &IpcClient::rulesReceived, this, [this](const QList<bulwark::DefenseRule>& rules) {
        const auto n = std::count_if(rules.cbegin(), rules.cend(), [](const bulwark::DefenseRule& r) { return !r.isTrustEntry(); });
        m_statRules->setText(QString::number(n));
    });
    connect(ipc, &IpcClient::quarantineReceived, this, [this](const QList<bulwark::ipc::QuarantineItemPayload>& items) {
        m_statQuarantine->setText(QString::number(items.size()));
    });
    connect(ipc, &IpcClient::aiScanRecord, this, [this](const AiScanResult& r) {
        m_aiTokens += r.tokens;
        m_statAi->setText(QString::number(++m_aiCount));
        m_statAiCaption->setText(u("累计 Token ") + QLocale().toString(m_aiTokens));
    });
    connect(ipc, &IpcClient::timelineReceived, this, [this](const bulwark::ipc::TimelineResponsePayload& p) {
        if (p.requestId != m_chartRequest)
            return; // 时间线页等别处发起的查询,与仪表盘无关(服务端广播给所有界面)
        auto* chart = static_cast<HourChart*>(m_chart);
        chart->reset();
        for (const bulwark::ipc::EventLogPayload& e : p.events)
            chart->add(e.event.timestampUtc, severityOf(e));
        m_chartFetched = QDateTime::currentDateTimeUtc();
        m_chartNote->setText(p.truncated ? u("只统计了最近 %1 条").arg(p.events.size())
                                         : u("共 %1 条 · 点击在时间线中查看").arg(p.events.size()));
    });
    connect(ipc, &IpcClient::settingsReceived, this, [this](const bulwark::RuntimeSettings& s) {
        m_haveSettings = true;
        m_protectionEnabled = s.protectionEnabled;
        m_kernelConnected = s.kernelConnected;
        m_kernelStatus = s.kernelStatus;
        setDimension(QStringLiteral("proc"), s.processProtection ? 1 : 0);
        setDimension(QStringLiteral("file"), s.fileProtection ? 1 : 0);
        setDimension(QStringLiteral("reg"), s.registryProtection ? 1 : 0);
        setDimension(QStringLiteral("self"), s.selfProtection ? 1 : 0);
        setDimension(QStringLiteral("net"), s.networkProtection ? 1 : 0);
        setDimension(QStringLiteral("mem"), s.memoryProtectionEnabled ? 1 : 0);
        refreshHero();
        refreshAttention();
    });
    connect(ipc, &IpcClient::connectionChanged, this, [this](bool c) {
        m_connected = c;
        if (c) {
            m_ipc->requestSettings();
            m_ipc->requestRules();
            m_ipc->requestQuarantine();
            QTimer::singleShot(2000, this, [this] { requestChart(true); }); // 错开启动峰值
        } else {
            // 断链后旧设置快照不再可信:退回"未知",而不是继续显示上次的状态。
            m_haveSettings = false;
            for (auto it = m_dims.begin(); it != m_dims.end(); ++it)
                setDimension(it.key(), -1);
        }
        refreshHero();
        refreshAttention();
    });
    if (ipc->isConnected()) {
        m_connected = true;
        ipc->requestSettings();
        ipc->requestRules();
        ipc->requestQuarantine();
        QTimer::singleShot(2000, this, [this] { requestChart(true); });
        refreshHero();
        refreshAttention();
    }
}

void DashboardPage::showEvent(QShowEvent* e)
{
    QWidget::showEvent(e);
    requestChart(false); // 10 分钟内不重复查询
}

void DashboardPage::requestChart(bool force)
{
    if (!m_ipc || !m_ipc->isConnected())
        return;
    if (!force && m_chartFetched.isValid() && m_chartFetched.secsTo(QDateTime::currentDateTimeUtc()) < 600)
        return;
    bulwark::ipc::TimelineRequestPayload req;
    req.fromUtc = QDateTime::currentDateTimeUtc().addSecs(-24 * 3600);
    req.limit = 2000;
    m_chartRequest = req.requestId;
    m_ipc->requestTimeline(req);
}

QWidget* DashboardPage::buildHero()
{
    m_hero = new HeroCard;
    m_hero->setObjectName(QStringLiteral("Card"));
    m_hero->setRadius(18);
    m_hero->setMinimumHeight(178);
    auto* h = new QHBoxLayout(m_hero);
    h->setContentsMargins(18, 14, 24, 14);
    h->setSpacing(20);

    m_emblem = new ShieldEmblem;
    h->addWidget(m_emblem, 0, Qt::AlignVCenter);

    auto* col = new QVBoxLayout;
    col->setSpacing(4);
    col->addStretch();
    col->addWidget(ui::eyebrow(u("实时防护")));
    m_heroTitle = ui::coloredText(QString(), 20, 700, theme::textMuted());
    col->addWidget(m_heroTitle);
    m_heroSub = ui::label(QString(), "secondary");
    m_heroSub->setWordWrap(true); // long kernel-status text wraps instead of overflowing
    col->addWidget(m_heroSub);
    col->addSpacing(8);
    auto* chips = new QHBoxLayout;
    chips->setSpacing(8);
    m_kernelPill = ui::pill(QString(), theme::textMuted());
    m_dimsPill = ui::pill(QString(), theme::textMuted());
    chips->addWidget(m_kernelPill);
    chips->addWidget(m_dimsPill);
    chips->addStretch();
    col->addLayout(chips);
    col->addStretch();
    h->addLayout(col, 1);

    // Quick actions: the three things people come to the overview to do next.
    auto* quick = new QVBoxLayout;
    quick->setSpacing(8);
    quick->addStretch();
    const auto action = [quick](const QString& icon, const QString& text, std::function<void()> fn) {
        // Solid (not ghost) so the stone courses behind them never run through the labels.
        auto* b = ui::button(text, nullptr, icon);
        b->setMinimumWidth(150);
        QObject::connect(b, &QPushButton::clicked, b, [fn = std::move(fn)] { fn(); });
        quick->addWidget(b);
    };
    action(QStringLiteral("activity"), u("查看拦截记录"), [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("block")}}); });
    action(QStringLiteral("power"), u("扫描自启动项"), [] { go(nav::Persistence, {{QStringLiteral("scan"), true}}); });
    action(QStringLiteral("cloud"), u("查询云信誉"), [] { go(nav::Reputation); });
    quick->addStretch();
    h->addLayout(quick);
    return m_hero;
}

// 四种状态如实区分,与侧栏防护状态卡(MainWindow::refreshProtectionPill)同一判据,
// 任何一种"说不清"都不显示为绿色:
//   未连接 / 未收到设置 -> 灰。界面此刻对防护状态一无所知,不能替它作保。
//   总开关关闭          -> 红。
//   开启但内核未连      -> 橙。用户态仍在拦,但缺少动作发生前阻断,不该和"完全开启"共用绿色。
//   开启且内核已连      -> 绿。
// 盾牌只在后两种状态下转动 —— 动效本身就是"正在防护"的表态。
void DashboardPage::refreshHero()
{
    using S = ShieldEmblem::State;
    S state = S::Unknown;
    QString title, sub;
    if (!m_connected) {
        title = u("等待服务连接…");
        sub = u("连接后台服务后显示实时防护状态。");
    } else if (!m_haveSettings) {
        title = u("正在读取防护状态…");
        sub = u("已连接后台服务,正在同步防护配置。");
    } else if (!m_protectionEnabled) {
        state = S::Off;
        title = u("防护已关闭");
        sub = u("防护总开关处于关闭状态,系统当前不受保护。可在「设置」中重新开启。");
    } else if (!m_kernelConnected) {
        state = S::Partial;
        title = u("防护已开启 · 无内核");
        sub = !m_kernelStatus.isEmpty() ? m_kernelStatus
                                        : u("内核驱动未连接:仅有用户态观测与补偿处置,缺少「动作发生前阻断」能力。");
    } else {
        state = S::Protected;
        title = u("系统受保护中");
        sub = !m_kernelStatus.isEmpty() ? m_kernelStatus : u("内核驱动已连接,敏感行为可在发生前被拦截。");
    }

    const QColor c = ShieldEmblem::colorFor(state);
    m_emblem->setState(state);
    m_hero->setGlow(c, QPointF(0.07, 0.5), 0.6, state == S::Unknown ? 0.07 : 0.17);
    static_cast<HeroCard*>(m_hero)->setMortar(theme::blend(c, theme::textPrimary(), state == S::Unknown ? 0.0 : 0.55),
                                              state == S::Unknown ? 0.06 : 0.10);
    m_heroTitle->setText(title);
    m_heroTitle->setStyleSheet(QStringLiteral("font-size:20pt; font-weight:700; color:%1;").arg(c.name()));
    m_heroSub->setText(sub);
    m_emblem->setAccessibleDescription(title + QStringLiteral(". ") + sub);

    const bool known = m_connected && m_haveSettings;
    if (!known)
        ui::stylePill(m_kernelPill, u("内核驱动 · 未知"), theme::textMuted());
    else if (m_kernelConnected)
        ui::stylePill(m_kernelPill, u("内核驱动 · 已连接"), theme::success());
    else
        ui::stylePill(m_kernelPill, u("内核驱动 · 未连接"), theme::warning());
    m_kernelPill->setToolTip(m_kernelStatus);

    int on = 0, total = 0;
    for (const Dimension& d : std::as_const(m_dims)) {
        ++total;
        if (d.on == 1)
            ++on;
    }
    if (!known || total == 0)
        ui::stylePill(m_dimsPill, u("防护维度 · —"), theme::textMuted());
    else
        ui::stylePill(m_dimsPill, u("防护维度 %1/%2").arg(on).arg(total),
                      on == total ? theme::success() : (on == 0 ? theme::danger() : theme::warning()));
}

QWidget* DashboardPage::buildStats()
{
    // 5 张指标卡放进【会换行的网格】:一行排不下时按可用宽度折行,任何窗口尺寸下都完整可见。
    // 每张卡都是入口:点开就是它计数的那一页。
    auto* w = new QWidget;
    m_statsGrid = new QGridLayout(w);
    m_statsGrid->setContentsMargins(0, 0, 0, 0);
    m_statsGrid->setHorizontalSpacing(16);
    m_statsGrid->setVerticalSpacing(16);

    m_statCards = {
        makeStat(QStringLiteral("shield-x"), theme::danger(), u("本次拦截"), u("仅计真实拦截"), m_statBlocked,
                 [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("block")}}); }),
        makeStat(QStringLiteral("activity"), theme::accent(), u("本次事件"), u("本次运行累计"), m_statEvents,
                 [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("all")}}); }),
        makeStat(QStringLiteral("lock"), theme::warning(), u("隔离文件"), u("隔离区现存"), m_statQuarantine,
                 [] { go(nav::Quarantine); }),
        makeStat(QStringLiteral("sliders"), theme::info(), u("防护规则"), u("当前规则集"), m_statRules,
                 [] { go(nav::Rules); }),
        makeStat(QStringLiteral("sparkles"), theme::accentAlt(), u("AI 研判"), u("累计 Token 0"), m_statAi,
                 [] { go(nav::Ai); }, &m_statAiCaption),
    };
    for (QWidget* c : m_statCards)
        c->setMinimumWidth(kStatCardMinWidth);

    relayoutStats();
    return w;
}

// 按当前可用宽度决定指标卡的列数并重排。列数没变就直接返回(resizeEvent 触发很频繁,
// 每次都拆装网格会造成可见的闪烁)。
void DashboardPage::relayoutStats()
{
    if (!m_statsGrid || m_statCards.isEmpty())
        return;

    const int total = int(m_statCards.size());
    const int avail = width() - 2 * theme::metric::pagePad;
    const int perCard = kStatCardMinWidth + 16; // 卡片最小宽 + 间距
    int cols = (avail > 0 && perCard > 0) ? avail / perCard : total;
    cols = std::clamp(cols, 1, total);
    if (cols == m_statCols)
        return;
    m_statCols = cols;

    for (QWidget* c : m_statCards)
        m_statsGrid->removeWidget(c);
    for (int i = 0; i < total; ++i)
        m_statsGrid->addWidget(m_statCards.at(i), i / cols, i % cols);
    // 只让在用的列参与等分,否则空列也会分到宽度,卡片被挤窄。
    for (int c = 0; c < total; ++c)
        m_statsGrid->setColumnStretch(c, c < cols ? 1 : 0);
}

void DashboardPage::resizeEvent(QResizeEvent* e)
{
    QWidget::resizeEvent(e);
    relayoutStats();
}

QWidget* DashboardPage::buildChart()
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(20, 18, 20, 14);
    v->setSpacing(8);
    m_chartNote = ui::label(u("连接后台服务后显示"), "muted");
    v->addLayout(cardHead(u("过去 24 小时"), m_chartNote));
    auto* legend = new QHBoxLayout;
    legend->setSpacing(14);
    const auto key = [legend](const QColor& color, const QString& text) {
        auto* dot = ui::statusDot(color);
        auto* row = new QHBoxLayout;
        row->setSpacing(6);
        row->addWidget(dot, 0, Qt::AlignVCenter);
        row->addWidget(ui::label(text, "caption"), 0, Qt::AlignVCenter);
        legend->addLayout(row);
    };
    key(theme::danger(), u("拦截"));
    key(theme::warning(), u("询问"));
    key(theme::blend(theme::accent(), theme::surface(), 0.6), u("放行"));
    legend->addStretch();
    v->addLayout(legend);
    auto* chart = new HourChart;
    chart->onClick = [] { go(nav::Timeline, {{QStringLiteral("range"), QStringLiteral("24h")}}); };
    m_chart = chart;
    v->addWidget(chart, 1);
    return c;
}

QWidget* DashboardPage::buildAttention()
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(20, 18, 20, 14);
    v->setSpacing(6);
    v->addLayout(cardHead(u("需要关注")));
    v->addWidget(ui::hDivider());
    m_attentionBox = new QVBoxLayout;
    m_attentionBox->setSpacing(0);
    v->addLayout(m_attentionBox);
    v->addStretch();
    return c;
}

// 只列真正需要用户处理的事(产品原则:少打扰)。状态未知时不说「一切正常」。
void DashboardPage::refreshAttention()
{
    Inspector::clearLayout(m_attentionBox);
    int n = 0;
    const auto add = [this, &n](const QString& icon, const QColor& color, const QString& title, const QString& desc,
                                const QString& action, std::function<void()> fn) {
        m_attentionBox->addWidget(attentionRow(icon, color, title, desc, action, std::move(fn)));
        ++n;
    };
    const bool known = m_connected && m_haveSettings;
    if (known && !m_protectionEnabled)
        add(QStringLiteral("shield-x"), theme::danger(), u("实时防护已关闭"), u("系统此刻不受本软件保护。"), u("去开启"),
            [] { go(nav::Settings, {{QStringLiteral("section"), QStringLiteral("protection")}}); });
    else if (known && !m_kernelConnected)
        add(QStringLiteral("shield-alert"), theme::warning(), u("内核驱动未连接"),
            u("只有用户态观测与事后处置,缺少动作发生前的阻断。"), u("查看设置"),
            [] { go(nav::Settings, {{QStringLiteral("section"), QStringLiteral("decision")}}); });
    if (m_unenforced > 0)
        add(QStringLiteral("alert"), theme::warning(), u("%1 次拦截没有真正执行").arg(m_unenforced),
            u("判为拦截,但只告警或处置失败 —— 需要确认它们造成了什么影响。"), u("查看"),
            [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("block")}}); });
    if (m_hardChains > 0)
        add(QStringLiteral("link"), theme::danger(), u("攻击链命中 %1 次(确定恶意)").arg(m_hardChains),
            u("同一进程上凑齐了与真实恶意样本一致的动作组合。"), u("查看"), [] { go(nav::Chain); });
    if (n > 0)
        return;
    if (!known)
        m_attentionBox->addWidget(attentionRow(QStringLiteral("server"), theme::textMuted(), u("防护状态未知"),
                                               u("连接后台服务并读到防护配置后,需要你处理的事会列在这里。"), QString(), {}));
    else
        m_attentionBox->addWidget(attentionRow(QStringLiteral("check-circle"), theme::success(), u("目前没有需要你处理的事"),
                                               u("出现没能真正执行的拦截、确定恶意的攻击链命中或防护被关闭时,会列在这里。"),
                                               QString(), {}));
}

QWidget* DashboardPage::buildActivity()
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(20, 18, 20, 14);
    v->setSpacing(8);
    auto* all = ui::button(u("全部事件"), "ghost", QStringLiteral("chevron-right"), true);
    QObject::connect(all, &QPushButton::clicked, all, [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("all")}}); });
    v->addLayout(cardHead(u("最近活动"), all));
    v->addWidget(ui::hDivider());
    m_activityBox = new QVBoxLayout;
    m_activityBox->setSpacing(0);
    v->addLayout(m_activityBox);
    // 空状态提示。第一条事件到达时隐藏(淘汰最旧行的逻辑按 count()-2 定位,依赖它始终占着最后一个位置)。
    m_activityEmpty = ui::label(u("暂无活动 · 事件将在此实时滚动"), "muted");
    m_activityEmpty->setContentsMargins(0, 10, 0, 10);
    m_activityBox->addWidget(m_activityEmpty);
    v->addStretch();
    return c;
}

QWidget* DashboardPage::buildDimensions()
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(20, 18, 20, 14);
    v->setSpacing(8);
    auto* edit = ui::button(u("调整"), "ghost", QStringLiteral("settings"), true);
    QObject::connect(edit, &QPushButton::clicked, edit,
                     [] { go(nav::Settings, {{QStringLiteral("section"), QStringLiteral("dims")}}); });
    v->addLayout(cardHead(u("防护维度"), edit));
    v->addWidget(ui::hDivider());

    auto* rows = new QVBoxLayout;
    rows->setSpacing(0);
    auto add = [&](const QString& key, const QString& icon, const QString& name) {
        auto* w = new QWidget;
        auto* h = new QHBoxLayout(w);
        h->setContentsMargins(0, 7, 0, 7);
        h->setSpacing(12);
        h->addWidget(new IconTile(icon, theme::textSecondary(), 30, 16));
        h->addWidget(ui::label(name, "title"), 0, Qt::AlignVCenter);
        h->addStretch();
        Dimension d;
        d.dot = ui::statusDot(theme::textMuted());
        d.state = ui::coloredText(u("—"), 9, 600, theme::textMuted());
        h->addWidget(d.dot, 0, Qt::AlignVCenter);
        h->addWidget(d.state, 0, Qt::AlignVCenter);
        m_dims.insert(key, d);
        rows->addWidget(w);
    };
    add(QStringLiteral("proc"), QStringLiteral("activity"), u("进程防护"));
    add(QStringLiteral("file"), QStringLiteral("file"), u("文件防护"));
    add(QStringLiteral("reg"), QStringLiteral("sliders"), u("注册表防护"));
    add(QStringLiteral("self"), QStringLiteral("shield"), u("自我保护"));
    add(QStringLiteral("net"), QStringLiteral("globe"), u("网络防护"));
    add(QStringLiteral("mem"), QStringLiteral("cpu"), u("内存防护"));
    v->addLayout(rows);
    v->addStretch();
    return c;
}

// on: 1 = 开启, 0 = 关闭, -1 = 未知(还没收到设置 / 已断链)。未知时不说开也不说关。
void DashboardPage::setDimension(const QString& key, int on)
{
    auto it = m_dims.find(key);
    if (it == m_dims.end())
        return;
    it->on = on;
    const QColor c = on == 1 ? theme::success() : (on == 0 ? theme::warning() : theme::textMuted());
    const QString text = on == 1 ? u("开启") : (on == 0 ? u("关闭") : u("—"));
    it->dot->setStyleSheet(QStringLiteral("background:%1; border-radius:4px;").arg(c.name()));
    it->state->setText(text);
    it->state->setStyleSheet(QStringLiteral("font-size:9pt; font-weight:600; color:%1;").arg(c.name()));
}
