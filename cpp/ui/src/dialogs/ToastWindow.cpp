#include "dialogs/ToastWindow.h"
#include "widgets/Cards.h"
#include "widgets/Ui.h"
#include "Theme.h"

#include <QEnterEvent>
#include <QEvent>
#include <QGraphicsDropShadowEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QPropertyAnimation>
#include <QTimer>
#include <QVBoxLayout>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

// Per-kind visuals: accent colour + icon glyph + heading fallback.
struct Look {
    QColor color;
    QString icon;
};

Look lookFor(ToastWindow::Kind k)
{
    switch (k) {
    case ToastWindow::Kind::Block:  return {theme::danger(),  QStringLiteral("shield-x")};
    case ToastWindow::Kind::AiScan: return {theme::accent(),  QStringLiteral("sparkles")};
    case ToastWindow::Kind::Info:   return {theme::info(),    QStringLiteral("alert")};
    }
    return {theme::info(), QStringLiteral("alert")};
}

} // namespace

ToastWindow::ToastWindow(Kind kind, const QString& heading, const QString& subtitle,
                         const QString& detail, const QList<ToastField>& fields,
                         const QStringList& tags, int lifetimeMs, QWidget* parent)
    : QWidget(parent), m_lifetimeMs(lifetimeMs)
{
    // Frameless, on-top, and — crucially for a security notification — never
    // activates, so it can't steal keyboard focus from what the user is doing.
    setWindowFlags(Qt::FramelessWindowHint | Qt::Tool | Qt::WindowStaysOnTopHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_ShowWithoutActivating);
    // The block toast carries structured detail (来源/程序/行为/目标), so it's a
    // touch wider; the lighter info / AI toasts stay compact.
    setFixedWidth(kind == Kind::Block ? 430 : 392);

    const Look look = lookFor(kind);

    auto* shell = new QVBoxLayout(this);
    shell->setContentsMargins(16, 12, 16, 16); // room for the drop shadow

    auto* cardW = ui::card();
    auto* shadow = new QGraphicsDropShadowEffect(cardW);
    shadow->setBlurRadius(40);
    shadow->setOffset(0, 10);
    shadow->setColor(QColor(15, 23, 42, 90));
    cardW->setGraphicsEffect(shadow);
    shell->addWidget(cardW);

    auto* row = new QHBoxLayout(cardW);
    row->setContentsMargins(16, 15, 16, 15);
    row->setSpacing(14);

    row->addWidget(ui::iconBadge(look.icon, look.color, 42, 22), 0, Qt::AlignTop);

    auto* col = new QVBoxLayout;
    col->setSpacing(3);

    auto* head = new QHBoxLayout;
    head->setSpacing(8);
    head->addWidget(ui::coloredText(heading, 12, 700, theme::textPrimary()));
    head->addStretch();
    head->addWidget(ui::pill(kind == Kind::Block ? u("已拦截") : u("处理中"), look.color),
                    0, Qt::AlignVCenter);
    col->addLayout(head);

    if (!subtitle.isEmpty())
        col->addWidget(ui::label(subtitle, "muted"));

    if (!detail.isEmpty()) {
        auto* d = ui::label(detail, "secondary");
        d->setWordWrap(true);
        col->addWidget(d);
    }

    // Structured 标签:值 rows (block toast). A fixed-width caption lines the
    // values up into a tidy column; long paths elide rather than widen the toast.
    if (!fields.isEmpty()) {
        auto* grid = new QVBoxLayout;
        grid->setContentsMargins(0, 3, 0, 0);
        grid->setSpacing(4);
        for (const ToastField& f : fields) {
            if (f.second.trimmed().isEmpty())
                continue;
            auto* fr = new QHBoxLayout;
            fr->setSpacing(8);
            auto* cap = ui::coloredText(f.first, 9, 700, theme::textMuted());
            cap->setFixedWidth(34);
            fr->addWidget(cap, 0, Qt::AlignTop);
            fr->addWidget(ui::elided(f.second, "secondary"), 1);
            grid->addLayout(fr);
        }
        col->addLayout(grid);
    }

    if (!tags.isEmpty()) {
        auto* tagRow = new QHBoxLayout;
        tagRow->setContentsMargins(0, 2, 0, 0);
        tagRow->setSpacing(6);
        int shown = 0;
        for (const QString& t : tags) {
            if (shown++ >= 4)
                break;
            tagRow->addWidget(ui::pill(t, theme::info()));
        }
        tagRow->addStretch();
        auto* tagW = new QWidget;
        tagW->setLayout(tagRow);
        col->addWidget(tagW);
    }

    row->addLayout(col, 1);

    setCursor(Qt::PointingHandCursor);
    adjustSize();

    m_life = new QTimer(this);
    m_life->setSingleShot(true);
    m_life->setInterval(m_lifetimeMs);
    connect(m_life, &QTimer::timeout, this, &ToastWindow::beginClose);

    m_fade = new QPropertyAnimation(this, "windowOpacity", this);
    m_slide = new QPropertyAnimation(this, "pos", this);
    m_slide->setDuration(220);
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
        m_fade->setDuration(200);
        m_fade->setStartValue(0.0);
        m_fade->setEndValue(1.0);
        m_fade->start();
        m_life->start();
        return;
    }
    if (m_closing)
        return;
    // Re-flow: slide to the new resting position.
    if (pos() == topLeft)
        return;
    m_slide->stop();
    m_slide->setStartValue(pos());
    m_slide->setEndValue(topLeft);
    m_slide->start();
}

void ToastWindow::beginClose()
{
    if (m_closing)
        return;
    m_closing = true;
    m_life->stop();
    m_fade->stop();
    m_fade->setDuration(200);
    m_fade->setStartValue(windowOpacity());
    m_fade->setEndValue(0.0);
    connect(m_fade, &QPropertyAnimation::finished, this, [this] {
        emit closed(this);
        deleteLater();
    });
    m_fade->start();
}

void ToastWindow::enterEvent(QEnterEvent*)
{
    // Hovering pauses the countdown so the user can read (and click).
    if (!m_closing)
        m_life->stop();
}

void ToastWindow::leaveEvent(QEvent*)
{
    if (!m_closing)
        m_life->start(2500); // short grace after the pointer leaves
}

void ToastWindow::mousePressEvent(QMouseEvent* e)
{
    if (e->button() == Qt::LeftButton) {
        emit clicked(this);
        beginClose();
    }
}
