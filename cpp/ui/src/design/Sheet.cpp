#include "design/Sheet.h"
#include "design/Banner.h"
#include "design/Components.h"
#include "design/GlowCard.h"
#include "design/IconTile.h"
#include "design/Motion.h"
#include "design/Theme.h"

#include <QCoreApplication>
#include <QCursor>
#include <QEvent>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QScreen>
#include <QTimer>
#include <QToolButton>
#include <QVariantAnimation>
#include <QVBoxLayout>
#include <QtMath>

#include <cmath>

namespace {
constexpr int kShell = 24; // transparent margin around the card (room for its shadow)
// Gap between a BottomRight sheet's window edge and the screen's work area. Chosen
// so the card's right and bottom edges line up with the toast cards stacked in the
// same corner (ToastNotifier: 22 px margin; ToastWindow: 16 px shadow room).
constexpr int kCornerInset = 15;

constexpr int kEnterMs = 180;
constexpr int kExitMs = 140; // leaving is quicker than arriving: nothing left to read
constexpr int kRise = 14;    // how far below its place a centred sheet starts (px)
// A corner sheet comes in from the right instead. Less than kCornerInset + kShell,
// so the window never starts outside the work area.
constexpr int kSlide = 32;

// The picture of a sheet that has just closed, sliding and fading out from where
// it stood, then deleting itself.
//
// The exit is played by this stand-in rather than by holding the dialog open,
// because a QDialog that lingers past done() changes things that callers rely on:
// exec() would return late (every caller reads its state on the next line), and a
// window that is still open when the application asks it to close cancels the
// quit — QGuiApplication::quit() closes every window and gives up if one of them
// stays. Closing first and animating after keeps the dialog's semantics exactly as
// they were, and there is nothing left on screen to click.
class Ghost final : public QWidget
{
public:
    Ghost(const QPixmap& shot, const QPoint& at, const QPoint& travel, int ms)
        : QWidget(nullptr, Qt::FramelessWindowHint | Qt::Tool | Qt::WindowStaysOnTopHint), m_shot(shot)
    {
        setAttribute(Qt::WA_TranslucentBackground);
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_ShowWithoutActivating);
        setAttribute(Qt::WA_DeleteOnClose);
        setFocusPolicy(Qt::NoFocus);
        setFixedSize(shot.deviceIndependentSize().toSize());
        move(at);
        show();

        auto* fade = new QPropertyAnimation(this, "windowOpacity", this);
        fade->setDuration(ms);
        fade->setStartValue(1.0);
        fade->setEndValue(0.0);
        auto* slide = new QPropertyAnimation(this, "pos", this);
        slide->setDuration(ms);
        slide->setEasingCurve(QEasingCurve::InCubic);
        slide->setStartValue(at);
        slide->setEndValue(at + travel);
        connect(fade, &QPropertyAnimation::finished, this, &QObject::deleteLater);
        fade->start();
        slide->start();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.drawPixmap(0, 0, m_shot);
    }

private:
    QPixmap m_shot;
};

class Strip : public QWidget
{
public:
    explicit Strip(QWidget* parent = nullptr) : QWidget(parent) { setFixedSize(4, 14); }
    QColor color = theme::accent();
    qreal glow = 0.0; // 0 = the plain tone, 1 = its pale highlight (Sheet::setPulse)

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(Qt::NoPen);
        p.setBrush(glow > 0.0 ? theme::blend(theme::soft(color), color, glow) : color);
        p.drawRoundedRect(QRectF(rect()), 2, 2);
    }
};
} // namespace

Sheet::Sheet(QWidget* parent) : QDialog(parent)
{
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setModal(true);

    auto* shell = new QVBoxLayout(this);
    shell->setContentsMargins(kShell, kShell, kShell, kShell);
    m_card = ui::floatingCard();
    shell->addWidget(m_card);

    auto* v = new QVBoxLayout(m_card);
    v->setContentsMargins(24, 20, 24, 20);
    v->setSpacing(14);

    // eyebrow (hidden until used)
    m_eyebrowRow = new QWidget;
    auto* er = new QHBoxLayout(m_eyebrowRow);
    er->setContentsMargins(0, 0, 0, 0);
    er->setSpacing(8);
    auto* strip = new Strip;
    m_strip = strip;
    er->addWidget(strip, 0, Qt::AlignVCenter);
    m_eyebrow = ui::eyebrow(QString());
    er->addWidget(m_eyebrow, 1, Qt::AlignVCenter);
    m_eyebrowRow->hide();
    v->addWidget(m_eyebrowRow);

    // header
    auto* head = new QHBoxLayout;
    head->setContentsMargins(0, 0, 0, 0);
    head->setSpacing(14);
    m_tile = new IconTile(QStringLiteral("info"), theme::accent(), 42, 21);
    m_tile->hide();
    head->addWidget(m_tile, 0, Qt::AlignTop);
    auto* tc = new QVBoxLayout;
    tc->setSpacing(3);
    m_title = ui::label(QString(), "h2");
    m_title->setWordWrap(true);
    m_title->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_subtitle = ui::label(QString(), "secondary");
    m_subtitle->setWordWrap(true);
    m_subtitle->hide();
    tc->addWidget(m_title);
    tc->addWidget(m_subtitle);
    head->addLayout(tc, 1);
    m_close = ui::iconButton(QStringLiteral("close"), QString::fromUtf8("关闭 (Esc)"), theme::textMuted(), 16);
    m_close->setFocusPolicy(Qt::NoFocus); // Esc does the same; keep the first Tab stop on the content
    connect(m_close, &QToolButton::clicked, this, &QDialog::reject);
    head->addWidget(m_close, 0, Qt::AlignTop);
    v->addLayout(head);

    m_banners = new BannerHost;
    v->addWidget(m_banners);

    m_body = new QVBoxLayout;
    m_body->setContentsMargins(0, 0, 0, 0);
    m_body->setSpacing(12);
    v->addLayout(m_body, 1);

    m_footerHost = new QWidget;
    m_footer = new QHBoxLayout(m_footerHost);
    m_footer->setContentsMargins(0, 4, 0, 0);
    m_footer->setSpacing(10);
    m_footer->addStretch(1);
    v->addWidget(m_footerHost);

    // Enter / exit: opacity and position move together (see done(), startEnter()).
    m_fade = new QPropertyAnimation(this, "windowOpacity", this);
    m_move = new QPropertyAnimation(this, "pos", this);
    m_move->setEasingCurve(QEasingCurve::OutCubic);

    setSheetWidth(520);
}

void Sheet::setHeader(const QString& icon, const QColor& tone, const QString& title, const QString& subtitle)
{
    if (!icon.isEmpty()) {
        m_tile->set(icon, tone);
        m_tile->show();
    } else {
        m_tile->hide();
    }
    setTitle(title);
    setSubtitle(subtitle);
    if (tone.isValid())
        setGlow(tone);
}

void Sheet::setEyebrow(const QString& text, const QColor& color)
{
    m_eyebrow->setText(text);
    m_eyebrow->setStyleSheet(QStringLiteral("color:%1;").arg(color.name()));
    static_cast<Strip*>(m_strip)->color = color;
    m_strip->update();
    m_eyebrowRow->setVisible(!text.isEmpty());
}

void Sheet::setPulse(bool on)
{
    m_pulseWanted = on;
    if (on && !m_pulse) {
        // One slow breath, shaped by a cosine so the loop has no seam.
        m_pulse = new QVariantAnimation(this);
        m_pulse->setStartValue(0.0);
        m_pulse->setEndValue(1.0);
        m_pulse->setDuration(1600);
        m_pulse->setLoopCount(-1);
        connect(m_pulse, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
            static_cast<Strip*>(m_strip)->glow = 0.5 - 0.5 * std::cos(v.toReal() * 2.0 * M_PI);
            m_strip->update();
        });
    }
    syncPulse();
}

void Sheet::syncPulse()
{
    if (!m_pulse)
        return;
    // Parked whenever nobody can see it (behind, minimised, on its way out) —
    // a repaint inside the card re-renders its shadow, and that is not free.
    const bool run = m_pulseWanted && motion::enabled() && motion::onScreen(this);
    if (run == (m_pulse->state() == QAbstractAnimation::Running))
        return;
    if (run) {
        m_pulse->start();
        return;
    }
    m_pulse->stop();
    static_cast<Strip*>(m_strip)->glow = 0.0;
    m_strip->update();
}

void Sheet::setTitle(const QString& title)
{
    m_title->setText(title);
    setWindowTitle(title);
    setAccessibleName(title);
}

void Sheet::setSubtitle(const QString& subtitle)
{
    m_subtitle->setText(subtitle);
    m_subtitle->setVisible(!subtitle.isEmpty());
}

void Sheet::setGlow(const QColor& color)
{
    if (color.isValid())
        m_card->setGlow(color, QPointF(0.0, 0.0), 0.85, 0.13);
    else
        m_card->clearGlow();
}

void Sheet::setSheetWidth(int width)
{
    setFixedWidth(width + 2 * kShell);
}

void Sheet::setClosable(bool closable)
{
    m_closable = closable;
    m_close->setVisible(closable);
}

void Sheet::setCloseButtonVisible(bool visible)
{
    m_close->setVisible(visible);
}

void Sheet::refit()
{
    // Not while the sheet is still arriving: the anchor below has to be read off
    // its resting place, not off a spot it is passing through.
    settleEnter();
    // A corner sheet is anchored by its bottom edge (wherever it sits now, the user
    // may have dragged it). Read it here, before the pending relayout gets a chance
    // to resize the window; only meaningful once the sheet has been placed.
    const bool anchorBottom = m_placed && m_placement == Placement::BottomRight;
    const int bottom = frameGeometry().bottom();
    QTimer::singleShot(0, this, [this, anchorBottom, bottom] {
        // Let every pending relayout (shown/hidden sections, scroll areas that
        // re-measured their content) propagate up to this window first —
        // otherwise adjustSize() measures the previous layout.
        for (int i = 0; i < 3; ++i)
            QCoreApplication::sendPostedEvents(nullptr, QEvent::LayoutRequest);
        if (QLayout* l = layout())
            l->invalidate();
        fitHeight();
        const QScreen* scr = screen();
        if (!scr)
            return;
        const QRect avail = scr->availableGeometry();
        QRect g = frameGeometry();
        if (anchorBottom)
            g.moveBottom(bottom); // grow / shrink upward
        if (g.bottom() > avail.bottom())
            g.moveBottom(avail.bottom());
        if (g.top() < avail.top())
            g.moveTop(avail.top());
        move(g.topLeft());
        m_restPos = pos();
    });
}

// Not adjustSize(): for a top-level window Qt measures the height at the
// layout's *hint* width — narrower than the sheet's fixed width whenever
// nothing wide is visible — so every wrapped label is measured a line too
// tall and the surplus shows up as gaps between rows. It also silently caps
// windows at 2/3 of the screen. Measure at the width the sheet really has,
// and cap at the screen instead (the footer must stay reachable).
void Sheet::fitHeight()
{
    QLayout* l = layout();
    if (!l) {
        adjustSize();
        return;
    }
    l->activate();
    const int w = width();
    int h = l->hasHeightForWidth() ? l->totalHeightForWidth(w) : l->totalSizeHint().height();
    h = qMax(h, l->totalMinimumSize().height());
    const QScreen* scr = screen();
    if (!scr)
        scr = QGuiApplication::primaryScreen();
    if (scr)
        h = qMin(h, scr->availableGeometry().height());
    resize(w, h);
}

void Sheet::addFooterLeft(QWidget* w)
{
    m_footer->insertWidget(m_footerLeft++, w);
}

QPushButton* Sheet::addButton(const QString& text, const char* variant, std::function<void()> fn)
{
    auto* b = ui::button(text, variant);
    b->setMinimumWidth(96);
    if (fn)
        connect(b, &QPushButton::clicked, this, [fn = std::move(fn)] { fn(); });
    m_footer->addWidget(b);
    return b;
}

int Sheet::screenHeightFor(const QWidget* anchor, qreal fraction)
{
    const QScreen* scr = anchor ? anchor->screen() : nullptr;
    if (!scr)
        scr = QGuiApplication::screenAt(QCursor::pos());
    if (!scr)
        scr = QGuiApplication::primaryScreen();
    const int h = scr ? scr->availableGeometry().height() : 900;
    return int(h * fraction);
}

void Sheet::placeOnScreen()
{
    fitHeight();
    if (m_placement == Placement::BottomRight) {
        // Same screen as the toast stack (ToastNotifier uses the primary screen too),
        // so the prompt and the notifications share one corner.
        const QScreen* scr = QGuiApplication::primaryScreen();
        if (!scr)
            return;
        const QRect avail = scr->availableGeometry();
        // Never taller than the screen: the footer (the answer buttons) must stay reachable.
        if (height() > avail.height())
            resize(width(), avail.height());
        QRect g(QPoint(0, 0), size());
        g.moveBottomRight(QPoint(avail.right() - kCornerInset, avail.bottom() - kCornerInset));
        g.moveLeft(qMax(avail.left(), g.left()));
        g.moveTop(qMax(avail.top(), g.top()));
        move(g.topLeft());
        return;
    }
    const QWidget* anchor = parentWidget() ? parentWidget()->window() : nullptr;
    QScreen* scr = nullptr;
    QRect target;
    if (anchor && anchor->isVisible() && !anchor->isMinimized()) {
        target = anchor->frameGeometry();
        scr = anchor->screen();
    } else {
        scr = QGuiApplication::screenAt(QCursor::pos());
        if (!scr)
            scr = QGuiApplication::primaryScreen();
        if (scr)
            target = scr->availableGeometry();
    }
    if (!scr)
        return;
    const QRect avail = scr->availableGeometry();
    // Never taller than the screen: the footer (the answer buttons) must stay reachable.
    if (height() > avail.height())
        resize(width(), avail.height());
    QRect g(QPoint(0, 0), size());
    g.moveCenter(target.center());
    g.moveLeft(qBound(avail.left(), g.left(), avail.right() - g.width() + 1));
    g.moveTop(qBound(avail.top(), g.top(), avail.bottom() - g.height() + 1));
    move(g.topLeft());
}

void Sheet::showEvent(QShowEvent* e)
{
    if (!m_placed) {
        m_placed = true;
        // Initial focus: the caller's choice, else the default button, else the
        // right-most footer button that can take it (the primary one may still
        // be disabled) — never a stray ✕, link or the first card in the body.
        if (!focusWidget()) {
            const auto usable = [this](QPushButton* b) {
                return b && b->isEnabled() && b->isVisibleTo(this);
            };
            QPushButton* target = nullptr;
            for (QPushButton* b : findChildren<QPushButton*>())
                if (b->isDefault() && usable(b))
                    target = b;
            for (int i = m_footer->count() - 1; !target && i >= 0; --i)
                if (auto* b = qobject_cast<QPushButton*>(m_footer->itemAt(i)->widget()); usable(b))
                    target = b;
            if (target)
                target->setFocus(Qt::OtherFocusReason);
        }
        placeOnScreen();
        startEnter();
    }
    QDialog::showEvent(e);
    syncPulse();
}

void Sheet::hideEvent(QHideEvent* e)
{
    QDialog::hideEvent(e);
    syncPulse();
}

QPoint Sheet::travel() const
{
    // A corner sheet slides in from the right — the corner it is parked in is also
    // the toast stack's, and sliding up into it would cross them. Anything centred
    // rises into place.
    return m_placement == Placement::BottomRight ? QPoint(kSlide, 0) : QPoint(0, kRise);
}

void Sheet::startEnter()
{
    m_restPos = pos();
    const int ms = motion::duration(kEnterMs);
    if (ms <= 0)
        return;
    m_entering = true;
    setWindowOpacity(0.0);
    move(m_restPos + travel());
    m_fade->stop();
    m_fade->setDuration(ms);
    m_fade->setStartValue(0.0);
    m_fade->setEndValue(1.0);
    m_fade->start();
    m_move->stop();
    m_move->setDuration(ms);
    m_move->setStartValue(pos());
    m_move->setEndValue(m_restPos);
    m_move->start();
}

void Sheet::settleEnter()
{
    if (!m_entering)
        return;
    m_entering = false;
    m_fade->stop();
    m_move->stop();
    setWindowOpacity(1.0);
    move(m_restPos);
}

void Sheet::done(int result)
{
    playExit();
    QDialog::done(result);
}

void Sheet::playExit()
{
    settleEnter();
    const int ms = motion::duration(kExitMs);
    if (ms <= 0 || !isVisible() || !motion::onScreen(this))
        return;
    // Everything the sheet shows right now, over a transparent background (the
    // window is translucent: the card and its shadow are the only pixels).
    const qreal dpr = devicePixelRatioF();
    QPixmap shot(int(std::ceil(width() * dpr)), int(std::ceil(height() * dpr)));
    shot.setDevicePixelRatio(dpr);
    shot.fill(Qt::transparent);
    render(&shot, QPoint(), QRegion(), QWidget::DrawChildren);
    new Ghost(shot, pos(), travel(), ms); // owns itself; gone when it has faded
}

void Sheet::keyPressEvent(QKeyEvent* e)
{
    if (e->key() == Qt::Key_Escape && !m_closable) {
        e->accept();
        return;
    }
    QDialog::keyPressEvent(e);
}

void Sheet::mousePressEvent(QMouseEvent* e)
{
    if (e->button() == Qt::LeftButton) {
        settleEnter(); // a drag takes over from the entry animation
        m_dragging = true;
        m_dragOffset = e->globalPosition().toPoint() - frameGeometry().topLeft();
        e->accept();
        return;
    }
    QDialog::mousePressEvent(e);
}

void Sheet::mouseMoveEvent(QMouseEvent* e)
{
    if (m_dragging && (e->buttons() & Qt::LeftButton)) {
        move(e->globalPosition().toPoint() - m_dragOffset);
        m_restPos = pos(); // dragged: this is where it sits now (refit, exit)
        e->accept();
        return;
    }
    QDialog::mouseMoveEvent(e);
}

void Sheet::mouseReleaseEvent(QMouseEvent* e)
{
    m_dragging = false;
    QDialog::mouseReleaseEvent(e);
}
