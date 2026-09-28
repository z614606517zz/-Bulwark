#include "dialogs/ToastWindow.h"
#include "design/Components.h"
#include "design/CountdownBar.h"
#include "design/FlowLayout.h"
#include "design/IconTile.h"
#include "design/Motion.h"
#include "design/Theme.h"

#include <QEnterEvent>
#include <QEvent>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPropertyAnimation>
#include <QPushButton>
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
    case ToastWindow::Kind::AiScan: return {theme::accentAlt(), QStringLiteral("sparkles")};
    case ToastWindow::Kind::Info:   return {theme::info(), QStringLiteral("info")};
    // 攻击链用琥珀而不是拦截的红:它表达「若干动作凑成了已知恶意组合」,处置可能是拦截、
    // 询问、也可能是放行(静默模式降级)。用红色会在放行的情况下让人误以为已经拦下了。
    case ToastWindow::Kind::AttackChain: return {theme::warning(), QStringLiteral("link")};
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
    row->addWidget(new IconTile(look.icon, look.color, 36, 18), 0, Qt::AlignTop);

    auto* col = new QVBoxLayout;
    col->setSpacing(4);

    auto* head = new QHBoxLayout;
    head->setSpacing(8);
    head->addWidget(ui::coloredText(heading, 10, 700, theme::textSecondary()), 1, Qt::AlignVCenter);
    const QString badge = !badgeText.isEmpty() ? badgeText : (kind == Kind::Block ? u("已拦截") : QString());
    if (!badge.isEmpty())
        head->addWidget(ui::pill(badge, look.color), 0, Qt::AlignVCenter);
    auto* close = ui::iconButton(QStringLiteral("close"), u("关闭通知"), theme::textMuted(), 14);
    close->setFocusPolicy(Qt::NoFocus);
    connect(close, &QToolButton::clicked, this, &ToastWindow::beginClose);
    head->addWidget(close, 0, Qt::AlignVCenter);
    col->addLayout(head);

    if (!sentence.isEmpty()) {
        auto* s = ui::label(sentence, "title");
        s->setWordWrap(true);
        col->addWidget(s);
    }
    if (!meta.isEmpty()) {
        auto* m = ui::label(meta, "muted");
        m->setWordWrap(true);
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
    auto* barRow = new QHBoxLayout;
    barRow->setContentsMargins(16, 0, 16, 10);
    barRow->addWidget(m_bar);
    v->addLayout(barRow);
    connect(m_bar, &CountdownBar::finished, this, &ToastWindow::beginClose);

    setAccessibleName(heading);
    setAccessibleDescription(sentence + (meta.isEmpty() ? QString() : u("。") + meta));
    adjustSize();

    m_fade = new QPropertyAnimation(this, "windowOpacity", this);
    m_slide = new QPropertyAnimation(this, "pos", this);
    m_slide->setDuration(motion::duration(220));
    m_slide->setEasingCurve(QEasingCurve::OutCubic);
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
        return;
    }
    if (m_closing)
        return;
    // Re-flow: slide to the new resting position.
    if (pos() == topLeft)
        return;
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

void ToastWindow::enterEvent(QEnterEvent* e)
{
    // Hovering pauses the countdown so the user can read (and click).
    if (!m_closing)
        m_bar->pause();
    QWidget::enterEvent(e);
}

void ToastWindow::leaveEvent(QEvent* e)
{
    if (!m_closing)
        m_bar->resume();
    QWidget::leaveEvent(e);
}
