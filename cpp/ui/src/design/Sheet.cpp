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
#include <QVBoxLayout>

namespace {
constexpr int kShell = 24; // transparent margin around the card (room for its shadow)

class Strip : public QWidget
{
public:
    explicit Strip(QWidget* parent = nullptr) : QWidget(parent) { setFixedSize(4, 14); }
    QColor color = theme::accent();

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(Qt::NoPen);
        p.setBrush(color);
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
    QTimer::singleShot(0, this, [this] {
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
        if (g.bottom() > avail.bottom())
            g.moveBottom(avail.bottom());
        if (g.top() < avail.top())
            g.moveTop(avail.top());
        move(g.topLeft());
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
        if (const int ms = motion::duration(150); ms > 0) {
            setWindowOpacity(0.0);
            auto* a = new QPropertyAnimation(this, "windowOpacity", this);
            a->setDuration(ms);
            a->setStartValue(0.0);
            a->setEndValue(1.0);
            a->start(QAbstractAnimation::DeleteWhenStopped);
        }
    }
    QDialog::showEvent(e);
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
