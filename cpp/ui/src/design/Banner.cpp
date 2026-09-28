#include "design/Banner.h"
#include "design/Components.h"
#include "design/Icons.h"
#include "design/Motion.h"
#include "design/Theme.h"

#include <QEnterEvent>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QTimer>
#include <QToolTip>
#include <QVBoxLayout>

namespace {

int defaultTimeout(ui::Tone t)
{
    switch (t) {
    case ui::Tone::Success: return 4500;
    case ui::Tone::Info:    return 5000;
    case ui::Tone::Warning: return 9000;
    case ui::Tone::Danger:  return 0;
    }
    return 5000;
}

// Leading glyph, painted in the tone colour.
class ToneGlyph : public QWidget
{
public:
    ToneGlyph(ui::Tone tone, QWidget* parent = nullptr) : QWidget(parent), m_tone(tone)
    {
        setFixedSize(20, 20);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        AppIcon::draw(p, ui::toneIcon(m_tone), QRectF(1, 1, 18, 18), ui::toneColor(m_tone), 1.7);
    }

private:
    ui::Tone m_tone;
};

} // namespace

Banner::Banner(ui::Tone tone, const QString& text, QWidget* parent)
    : QFrame(parent), m_tone(tone)
{
    setAttribute(Qt::WA_StyledBackground, false);
    auto* h = new QHBoxLayout(this);
    h->setContentsMargins(16, 10, 8, 10);
    h->setSpacing(10);
    h->addWidget(new ToneGlyph(tone), 0, Qt::AlignTop);

    m_text = ui::label(text);
    m_text->setWordWrap(true);
    m_text->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_text->setStyleSheet(QStringLiteral("color:%1;").arg(theme::textPrimary().name()));
    h->addWidget(m_text, 1, Qt::AlignVCenter);

    m_action = ui::button(QString(), "ghost", QString(), true);
    m_action->hide();
    connect(m_action, &QPushButton::clicked, this, [this] {
        if (m_fn)
            m_fn();
        dismiss();
    });
    h->addWidget(m_action, 0, Qt::AlignVCenter);

    auto* close = ui::iconButton(QStringLiteral("close"), QString::fromUtf8("关闭提示"),
                                 theme::textMuted(), 14);
    connect(close, &QToolButton::clicked, this, &Banner::dismiss);
    h->addWidget(close, 0, Qt::AlignTop);

    m_timer = new QTimer(this);
    m_timer->setSingleShot(true);
    connect(m_timer, &QTimer::timeout, this, &Banner::dismiss);

    setAccessibleName(QString::fromUtf8("提示"));
    setAccessibleDescription(text);
}

QString Banner::text() const { return m_text->text(); }

void Banner::setText(const QString& text)
{
    m_text->setText(text);
    setAccessibleDescription(text);
}

void Banner::setAction(const QString& text, std::function<void()> fn)
{
    m_fn = std::move(fn);
    m_action->setText(text);
    m_action->setVisible(!text.isEmpty());
}

void Banner::setTimeout(int ms)
{
    m_remaining = ms;
    m_timer->stop();
    if (ms > 0) {
        m_since.start();
        m_timer->start(ms);
    }
}

void Banner::enterEvent(QEnterEvent* e)
{
    // Hover pauses the countdown: the user is reading it.
    if (m_timer->isActive()) {
        m_remaining = qMax(800, m_remaining - int(m_since.elapsed()));
        m_timer->stop();
    }
    QFrame::enterEvent(e);
}

void Banner::leaveEvent(QEvent* e)
{
    if (m_remaining > 0 && !m_closing && !m_timer->isActive()) {
        m_since.start();
        m_timer->start(m_remaining);
    }
    QFrame::leaveEvent(e);
}

void Banner::dismiss()
{
    if (m_closing)
        return;
    m_closing = true;
    m_timer->stop();
    const int ms = motion::duration(160);
    if (ms <= 0) {
        emit dismissed();
        deleteLater();
        return;
    }
    auto* fx = new QGraphicsOpacityEffect(this);
    fx->setOpacity(1.0);
    setGraphicsEffect(fx);
    auto* anim = new QPropertyAnimation(fx, "opacity", this);
    anim->setDuration(ms);
    anim->setStartValue(1.0);
    anim->setEndValue(0.0);
    connect(anim, &QPropertyAnimation::finished, this, [this] {
        emit dismissed();
        deleteLater();
    });
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void Banner::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const QColor c = ui::toneColor(m_tone);
    const QRectF r = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
    QPainterPath shape;
    shape.addRoundedRect(r, 12, 12);
    p.fillPath(shape, theme::blend(c, theme::surface(), 0.12));
    p.setPen(QPen(theme::blend(c, theme::surface(), 0.34), 1.0));
    p.drawPath(shape);
    // Left strip, clipped to the rounded shape.
    p.save();
    p.setClipPath(shape);
    p.fillRect(QRectF(r.left(), r.top(), 3.5, r.height()), c);
    p.restore();
}

// ---- BannerHost ---------------------------------------------------------------

BannerHost::BannerHost(QWidget* parent) : QWidget(parent)
{
    setObjectName(QStringLiteral("BannerHost"));
    m_stack = new QVBoxLayout(this);
    m_stack->setContentsMargins(0, 0, 0, 0);
    m_stack->setSpacing(8);
    hide();
}

Banner* BannerHost::post(ui::Tone tone, const QString& text, int timeoutMs)
{
    const int timeout = timeoutMs < 0 ? defaultTimeout(tone) : timeoutMs;

    // Same message again: refresh instead of stacking a duplicate.
    for (const QPointer<Banner>& b : std::as_const(m_banners)) {
        if (b && b->tone() == tone && b->text() == text) {
            b->setTimeout(timeout);
            return b;
        }
    }

    m_banners.removeAll(QPointer<Banner>());
    while (m_banners.size() >= 3) {
        if (Banner* old = m_banners.takeFirst())
            old->dismiss();
    }

    auto* b = new Banner(tone, text, this);
    m_stack->addWidget(b);
    m_banners.append(b);
    connect(b, &Banner::dismissed, this, [this, b] {
        m_banners.removeAll(QPointer<Banner>(b));
        m_banners.removeAll(QPointer<Banner>());
        if (m_banners.isEmpty())
            hide();
    });
    show();

    if (const int ms = motion::duration(160); ms > 0) {
        auto* fx = new QGraphicsOpacityEffect(b);
        fx->setOpacity(0.0);
        b->setGraphicsEffect(fx);
        auto* anim = new QPropertyAnimation(fx, "opacity", b);
        anim->setDuration(ms);
        anim->setStartValue(0.0);
        anim->setEndValue(1.0);
        // Drop the effect once visible: an opacity effect renders the banner
        // through an offscreen pixmap, which blurs text on fractional scales.
        QObject::connect(anim, &QPropertyAnimation::finished, b, [b] { b->setGraphicsEffect(nullptr); });
        anim->start(QAbstractAnimation::DeleteWhenStopped);
    }
    b->setTimeout(timeout);
    return b;
}

void BannerHost::clear()
{
    for (const QPointer<Banner>& b : std::as_const(m_banners))
        if (b)
            b->dismiss();
}

BannerHost* BannerHost::find(QWidget* from)
{
    for (QWidget* w = from; w; w = w->parentWidget()) {
        if (auto* self = dynamic_cast<BannerHost*>(w))
            return self;
        if (auto* h = w->findChild<BannerHost*>(QString(), Qt::FindDirectChildrenOnly))
            return h;
        if (w->isWindow())
            break;
    }
    return nullptr;
}

Banner* ui::notify(QWidget* context, Tone tone, const QString& text, int timeoutMs)
{
    if (BannerHost* host = BannerHost::find(context))
        return host->post(tone, text, timeoutMs);
    if (context)
        QToolTip::showText(context->mapToGlobal(context->rect().center()), text, context, QRect(),
                           tone == Tone::Danger ? 10000 : 5000);
    return nullptr;
}
