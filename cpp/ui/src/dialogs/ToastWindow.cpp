#include "dialogs/ToastWindow.h"
#include "design/Components.h"
#include "design/CountdownBar.h"
#include "design/FlowLayout.h"
#include "design/IconTile.h"
#include "design/Motion.h"
#include "design/Theme.h"
#include "widgets/WrapLabel.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

// Per-kind visuals: accent colour + glyph.
struct Look {
    QColor color;
    QString icon;
};

Look lookFor(ToastWindow::Kind k)
{
    switch (k) {
    case ToastWindow::Kind::Block:  return {theme::danger(), QStringLiteral("shield-x")};
    // 裁决拦截但实际没拦下:降到琥珀,并换掉那面「拦住了」的盾。
    // shield-alert = 拦截根本没发生(仅告警);x-circle = 动手了但没成(拦截失败)。
    case ToastWindow::Kind::BlockAlertedOnly: return {theme::warning(), QStringLiteral("shield-alert")};
    case ToastWindow::Kind::BlockFailed:      return {theme::warning(), QStringLiteral("x-circle")};
    case ToastWindow::Kind::Info:   return {theme::info(), QStringLiteral("info")};
    // 攻击链用琥珀而不是拦截的红:它表达「若干动作凑成了已知恶意组合」,处置可能是拦截、
    // 询问、也可能是放行(静默模式降级)。用红色会在放行的情况下让人误以为已经拦下了。
    case ToastWindow::Kind::AttackChain: return {theme::warning(), QStringLiteral("link")};
    // 足迹清理:与清理报告卡片(RemediationReportDialog 的抬头)同一个图标与配色口径。
    case ToastWindow::Kind::Cleanup:           return {theme::success(), QStringLiteral("trash")};
    case ToastWindow::Kind::CleanupIncomplete: return {theme::warning(), QStringLiteral("trash")};
    }
    return {theme::info(), QStringLiteral("info")};
}

// The status strip down the toast's left edge.
class Strip : public QWidget
{
public:
    Strip(const QColor& c, QWidget* parent = nullptr) : QWidget(parent), m_color(c)
    {
        setFixedWidth(4);
        setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(Qt::NoPen);
        p.setBrush(m_color);
        p.drawRoundedRect(QRectF(rect()), 2, 2);
    }

private:
    QColor m_color;
};

} // namespace

ToastWindow::ToastWindow(Kind kind, const QString& heading, const QString& sentence,
                         const QString& meta, const QStringList& tags, int lifetimeMs,
                         const QString& badgeText, const QString& actionText, QWidget* parent)
    : QWidget(parent), m_lifetimeMs(lifetimeMs)
{
    // Frameless, on-top, and — crucially for a security notification — never
    // activates, so it can't steal keyboard focus from what the user is doing.
    setWindowFlags(Qt::FramelessWindowHint | Qt::Tool | Qt::WindowStaysOnTopHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_ShowWithoutActivating);
    setFixedWidth(412);

    const Look look = lookFor(kind);
    m_accent = look.color;

    auto* shell = new QVBoxLayout(this);
    shell->setContentsMargins(16, 12, 16, 16); // room for the drop shadow

    auto* cardW = ui::floatingCard(look.color);
    ui::elevate(cardW, 16, 6, 130); // sized to the 16/12/16/16 shell above
    shell->addWidget(cardW);

    auto* v = new QVBoxLayout(cardW);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(0);

    auto* row = new QHBoxLayout;
    row->setContentsMargins(12, 14, 8, 10);
    row->setSpacing(12);
    row->addWidget(new Strip(look.color));
    m_tile = new IconTile(look.icon, look.color, 36, 18);
    row->addWidget(m_tile, 0, Qt::AlignTop);

    auto* col = new QVBoxLayout;
    col->setSpacing(4);

    auto* head = new QHBoxLayout;
    head->setSpacing(8);
    head->addWidget(ui::coloredText(heading, 10, 700, theme::textSecondary()), 1, Qt::AlignVCenter);
    //
    // 处置 pill 只显示调用方【明确给出】的那个词,不再对 Kind::Block 兜底成「已拦截」。
    //
    // 那个兜底正是假拦截的根源:裁决为 Block 不代表真的拦住了,而兜底让「仅告警·未拦截」
    // 和「拦截失败」在界面上与真拦下完全一样 —— 偏偏这两种才是用户必须自己动手的。
    // 现在措辞一律由 ToastNotifier 按真实 EnforcementOutcome 经 evtfmt::disposition() 得出;
    // 万一漏传就【不显示】pill:不说,也好过说假话。
    if (!badgeText.isEmpty())
        head->addWidget(ui::pill(badgeText, look.color), 0, Qt::AlignVCenter);
    auto* close = ui::iconButton(QStringLiteral("close"), u("关闭通知"), theme::textMuted(), 14);
    close->setFocusPolicy(Qt::NoFocus);
    connect(close, &QToolButton::clicked, this, &ToastWindow::beginClose);
    head->addWidget(close, 0, Qt::AlignVCenter);
    col->addLayout(head);

    // 这两行用 WrapLabel,不用「QLabel + setWordWrap」。
    //
    // 它们要显示的是路径 / 注册表键 / 目标地址 —— 里面【没有空格】,而 QLabel 的 wordWrap 只在空格
    // 处断行,断不开就两头落空:既把布局撑得比卡片还宽(右侧文字被裁:「…搜索顺序劫」),又因为
    // 高度按一行算而把第二行挤到卡片外。WrapLabel 在任意位置断行,minimumSizeHint 只要 24px
    // (不会把固定宽度的卡片撑开),并且如实上报 heightForWidth(卡片高度靠它,见 refitHeight)。
    if (!sentence.isEmpty()) {
        auto* s = new WrapLabel(sentence);
        s->setProperty("role", "title");
        col->addWidget(s);
    }
    // 威胁类型(setThreat() 填充;之前隐藏、不占位)。放在「谁做了什么」之后、依据之前:
    // 先说拦下的是什么,再说凭什么 —— 原来这张卡只有「已拦截」,说不出拦的是什么威胁。
    m_threatRow = new QWidget;
    auto* threatRow = new QHBoxLayout(m_threatRow);
    threatRow->setContentsMargins(0, 2, 0, 2);
    threatRow->setSpacing(8);
    threatRow->addWidget(ui::label(u("威胁类型"), "caption"), 0, Qt::AlignVCenter);
    m_threatPill = ui::pill(QString(), look.color);
    threatRow->addWidget(m_threatPill, 0, Qt::AlignVCenter);
    m_threatName = ui::elided(QString(), "secondary");
    m_threatName->hide();
    threatRow->addWidget(m_threatName, 1, Qt::AlignVCenter);
    threatRow->addStretch(); // 没有具名威胁时由它吃掉余量,pill 保持胶囊而不是被拉成长条
    m_threatRow->hide();
    col->addWidget(m_threatRow);
    if (!meta.isEmpty()) {
        auto* m = new WrapLabel(meta);
        m->setProperty("role", "muted");
        col->addWidget(m);
    }
    if (!tags.isEmpty()) {
        auto* tw = new QWidget;
        auto* flow = new FlowLayout(tw, 6, 6);
        flow->setContentsMargins(0, 2, 0, 0);
        int shown = 0;
        for (const QString& t : tags) {
            if (shown++ >= 4)
                break;
            flow->addWidget(ui::pill(t, theme::info()));
        }
        if (tags.size() > 4)
            flow->addWidget(ui::pill(QStringLiteral("+%1").arg(tags.size() - 4), theme::textSecondary()));
        col->addWidget(tw);
    }
    // 附加内容(拦截通知的「AI 解读」)的位置:setInsight() 之前隐藏、不占位。
    m_insightSlot = new QWidget;
    auto* insight = new QVBoxLayout(m_insightSlot);
    insight->setContentsMargins(0, 4, 0, 0);
    insight->setSpacing(0);
    m_insightSlot->hide();
    col->addWidget(m_insightSlot);
    if (!actionText.isEmpty()) {
        auto* act = ui::button(actionText, "ghost", QString(), true);
        act->setFocusPolicy(Qt::NoFocus);
        connect(act, &QPushButton::clicked, this, [this] {
            emit clicked(this);
            beginClose();
        });
        col->addSpacing(2);
        col->addWidget(act, 0, Qt::AlignLeft);
    }
    row->addLayout(col, 1);
    v->addLayout(row);

    m_bar = new CountdownBar;
    m_bar->setColor(look.color);
    // 悬停暂停交给倒计时条自己按指针真实位置判定(不再用 enter/leave —— 那会让一条弹在静止指针
    // 底下的通知永远关不掉,详见 CountdownBar::syncHoverPause)。范围取这张卡片,不含阴影留白。
    m_bar->setHoverPause(cardW);
    auto* barRow = new QHBoxLayout;
    barRow->setContentsMargins(16, 0, 16, 10);
    barRow->addWidget(m_bar);
    v->addLayout(barRow);
    connect(m_bar, &CountdownBar::finished, this, &ToastWindow::onCountdownFinished);

    setAccessibleName(heading);
    m_description = sentence + (meta.isEmpty() ? QString() : u("。") + meta);
    setAccessibleDescription(m_description);
    refitHeight(); // 换行文案必须按固定宽度算高,adjustSize() 会算少(见其说明)

    m_fade = new QPropertyAnimation(this, "windowOpacity", this);
    m_slide = new QPropertyAnimation(this, "pos", this);
    m_slide->setDuration(motion::duration(220));
    m_slide->setEasingCurve(QEasingCurve::OutCubic);
}

void ToastWindow::setThreat(const QString& category, const QString& name)
{
    const QString cat = category.trimmed();
    const QString nm = name.trimmed();
    if (!cat.isEmpty()) {
        ui::stylePill(m_threatPill, cat, m_accent);
        m_threatName->setText(nm); // ElidingLabel:过长省略,全文进 tooltip
        m_threatName->setVisible(!nm.isEmpty());
        setAccessibleDescription(u("威胁类型:") + cat + (nm.isEmpty() ? QString() : u("(") + nm + u(")"))
                                 + u("。") + m_description);
    } else {
        setAccessibleDescription(m_description);
    }
    m_threatRow->setVisible(!cat.isEmpty());
    // 先让布局吃进这一行的显隐,再按固定宽度重算高度(ToastNotifier 摆放时要读 height())。
    if (QLayout* l = layout())
        l->invalidate();
    refitHeight();
}

void ToastWindow::refitHeight()
{
    QLayout* l = layout();
    if (!l)
        return;
    // 先 polish 再量:字号来自样式表(role="title" 是 10.5pt),polish 之前读到的是默认字体。
    //
    // 【仅凭这一步还不够】显示之前,换行标签拿不到真实的分配宽度,行数照样可能算少 ——
    // 实测同一条通知构造期量得 261、显示后量得 293。所以 showEvent 里还会再量一次,
    // 那一次才是权威的;这里算的是个尽量接近的初值(让首次摆放不至于偏太多)。
    const int h = fittedHeight();
    if (h > 0 && h != height())
        resize(width(), h);
}

int ToastWindow::fittedHeight()
{
    QLayout* l = layout();
    if (!l)
        return height();
    ensurePolished();
    l->activate(); // 再把换行结果算进布局,然后问高度
    int h = l->hasHeightForWidth() ? l->totalHeightForWidth(width()) : -1;
    if (h <= 0)
        h = sizeHint().height();
    return h;
}

void ToastWindow::setInsight(QWidget* panel)
{
    if (!panel || !m_insightSlot)
        return;
    m_insightSlot->layout()->addWidget(panel);
    m_insightSlot->show();
    m_insightPending = true;
    if (QLayout* l = layout())
        l->invalidate();
    refitHeight();
}

void ToastWindow::settleInsight(int minRemainingMs)
{
    m_insightPending = false;
    if (QLayout* l = layout())
        l->invalidate();
    if (!m_shown) {
        // 还没显示(命中已存的解读 / 立即失败时是同步回调):首次摆放量的就是最终内容,只把存活期补够。
        refitHeight();
        m_lifetimeMs = qMax(m_lifetimeMs, minRemainingMs);
        return;
    }
    if (m_closing)
        return;
    // 在屏上:向上长、底边不动,一次 setGeometry 到位。先往下长、再等 ToastNotifier 重排把它滑回来的话,
    // 那 220ms 里它会压住下面那条通知(或伸出屏幕底边)。
    const int h = fittedHeight();
    if (h > 0 && h != height()) {
        m_slide->stop();
        const int bottom = y() + height();
        setGeometry(x(), bottom - h, width(), h);
        emit resized(this); // 上面那几条跟着让位
    }
    if (m_expired) {
        m_expired = false;
        if (minRemainingMs > 0)
            m_bar->start(minRemainingMs);
        else
            beginClose();
        return;
    }
    if (minRemainingMs > 0)
        m_bar->ensureRemaining(minRemainingMs);
}

void ToastWindow::onCountdownFinished()
{
    if (m_insightPending && !m_closing) {
        // 时间到了而解读还在路上:先不关(见 setInsight)。
        m_expired = true;
        QTimer::singleShot(kMaxInsightHoldMs, this, [this] {
            if (m_expired && !m_closing)
                beginClose();
        });
        return;
    }
    beginClose();
}

void ToastWindow::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    //
    // 真实高度只有【显示之后】才算得准,所以这里必须再定一次高。
    //
    // 换行标签的 heightForWidth 依赖样式表给的字号与真实分配宽度,而这两样都要到 widget 被
    // 显示(polish 完成)才落定:实测同一条通知,构造期算出 261,显示后算出 293 —— 少的那 32px
    // 正是路径那一行的第二行,于是它被裁在卡片外、和下面的「威胁类型」行叠在一起。
    //
    // 这一步发生在首次绘制之前(place() 是以 opacity 0 开始淡入的),所以用户看不到高度跳变;
    // 位置由 ToastNotifier 收到 resized 后重新摆放(淡入期间不滑动,直接到位,见 place())。
    const int before = height();
    refitHeight();
    if (height() != before)
        emit resized(this);
}

void ToastWindow::place(const QPoint& topLeft)
{
    if (!m_shown) {
        m_shown = true;
        move(topLeft);
        setWindowOpacity(0.0);
        show();
        m_fade->stop();
        m_fade->setDuration(qMax(1, motion::duration(200)));
        m_fade->setStartValue(0.0);
        m_fade->setEndValue(1.0);
        m_fade->start();
        m_bar->start(m_lifetimeMs);
        m_tile->pop(); // the glyph springs in with the card
        return;
    }
    if (m_closing)
        return;
    // Re-flow: slide to the new resting position.
    if (pos() == topLeft)
        return;
    // 还在淡入:这次移动是 showEvent 里那次高度修正带来的「补正到位」,不是重新排队。
    // 直接 move,别滑 —— 否则每条长文案通知刚出现就先往上挪一下,像抖了一下。
    if (m_fade && m_fade->state() == QAbstractAnimation::Running) {
        move(topLeft);
        return;
    }
    m_slide->stop();
    if (m_slide->duration() <= 0) {
        move(topLeft);
        return;
    }
    m_slide->setStartValue(pos());
    m_slide->setEndValue(topLeft);
    m_slide->start();
}

void ToastWindow::beginClose()
{
    if (m_closing)
        return;
    m_closing = true;
    m_bar->stop();
    m_fade->stop();
    m_fade->setDuration(qMax(1, motion::duration(200)));
    m_fade->setStartValue(windowOpacity());
    m_fade->setEndValue(0.0);
    connect(m_fade, &QPropertyAnimation::finished, this, [this] {
        emit closed(this);
        deleteLater();
    });
    m_fade->start();
}
