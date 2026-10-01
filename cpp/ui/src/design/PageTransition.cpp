#include "design/PageTransition.h"
#include "design/Backdrop.h"
#include "design/Motion.h"

#include <QCoreApplication>
#include <QEvent>
#include <QPainter>
#include <QPixmap>
#include <QTimer>
#include <QVariantAnimation>
#include <QWidget>
#include <QtMath>

#include <cmath>
#include <utility>

namespace {

constexpr int kDurationMs = 260;
constexpr int kResizeQuietMs = 250; // a resize this recent: the window is still being resized
constexpr qreal kRise = 12.0;       // how far below its place the incoming page starts (px)

// One state of the covered area, as transparent layers over the plane.
struct Frame {
    QPixmap head; // the page header, drawn at headAt
    QPixmap body; // everything below it (banners, page), drawn at bodyAt
    QPoint headAt;
    QPoint bodyAt;
};

QPixmap blankLayer(const QSize& size, qreal dpr)
{
    QPixmap pm(qMax(1, qCeil(size.width() * dpr)), qMax(1, qCeil(size.height() * dpr)));
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    return pm;
}

// Renders the header and the body widgets without any background of their own
// (DrawChildren only), so the layers can be composited over the plane.
Frame capture(QWidget* host, QWidget* header, const QList<QPointer<QWidget>>& body)
{
    Frame f;
    const qreal dpr = host->devicePixelRatioF();
    f.headAt = header->mapTo(host, QPoint(0, 0));
    f.head = blankLayer(header->size(), dpr);
    header->render(&f.head, QPoint(), QRegion(), QWidget::DrawChildren);

    f.bodyAt = QPoint(0, f.headAt.y() + header->height());
    f.body = blankLayer(QSize(host->width(), host->height() - f.bodyAt.y()), dpr);
    for (const QPointer<QWidget>& w : body)
        if (w && w->isVisible())
            w->render(&f.body, w->mapTo(host, QPoint(0, 0)) - f.bodyAt, QRegion(), QWidget::DrawChildren);
    return f;
}

// The picture over the content area while a page change plays. Opaque — it
// paints the plane first — so the live page underneath (already the new one)
// never shows through; input passes straight to it.
class Cover final : public QWidget
{
public:
    Cover(QWidget* host, const QPixmap& plane, Frame from)
        : QWidget(host), m_plane(plane), m_from(std::move(from))
    {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_OpaquePaintEvent);
        setFocusPolicy(Qt::NoFocus);
        setGeometry(host->rect());
    }

    bool revealed() const { return m_revealed; }
    void reveal(Frame to)
    {
        m_to = std::move(to);
        m_revealed = true;
        update();
    }
    void setProgress(qreal t)
    {
        m_t = t;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.drawPixmap(0, 0, m_plane);
        if (!m_revealed) { // waiting for the incoming state: hold the outgoing one
            p.drawPixmap(m_from.headAt, m_from.head);
            p.drawPixmap(m_from.bodyAt, m_from.body);
            return;
        }
        // One clock, three staggered curves: the header cross-fades over most of
        // it, the old page is gone by a little under half, the new one starts a
        // beat later and settles at the end.
        const qreal head = motion::outCubic(motion::slice(m_t, 0.0, 0.8));
        const qreal out = 1.0 - motion::outCubic(motion::slice(m_t, 0.0, 0.45));
        const qreal in = motion::outCubic(motion::slice(m_t, 0.12, 1.0));
        if (head < 1.0) {
            p.setOpacity(1.0 - head);
            p.drawPixmap(m_from.headAt, m_from.head);
        }
        if (head > 0.0) {
            p.setOpacity(head);
            p.drawPixmap(m_to.headAt, m_to.head);
        }
        if (out > 0.0) {
            p.setOpacity(out);
            p.drawPixmap(m_from.bodyAt, m_from.body);
        }
        if (in > 0.0) {
            // Whole device pixels only, so text in the moving layer stays crisp.
            const qreal dpr = devicePixelRatioF();
            const qreal rise = std::round(kRise * (1.0 - in) * dpr) / dpr;
            p.setOpacity(in);
            p.drawPixmap(QPointF(m_to.bodyAt.x(), m_to.bodyAt.y() + rise), m_to.body);
        }
    }

private:
    QPixmap m_plane;
    Frame m_from;
    Frame m_to;
    bool m_revealed = false;
    qreal m_t = 0.0;
};

} // namespace

PageTransition::PageTransition(Backdrop* host, QWidget* header, const QList<QWidget*>& body)
    : QObject(host), m_host(host), m_header(header)
{
    for (QWidget* w : body)
        m_body << QPointer<QWidget>(w);
    m_anim = new QVariantAnimation(this);
    m_anim->setStartValue(0.0);
    m_anim->setEndValue(1.0);
    connect(m_anim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
        if (auto* cover = static_cast<Cover*>(m_cover.data()))
            cover->setProgress(v.toReal());
    });
    connect(m_anim, &QVariantAnimation::finished, this, [this] { finish(); });
    host->installEventFilter(this);
}

PageTransition::~PageTransition() = default;

bool PageTransition::isRunning() const
{
    return !m_cover.isNull();
}

bool PageTransition::start()
{
    if (isRunning()) {
        finish(); // rapid clicks: cut the change that is playing, switch instantly
        return false;
    }
    if (!m_header || motion::duration(kDurationMs) <= 0 || !motion::onScreen(m_host))
        return false;
    if (m_host->width() < 2 || m_host->height() <= m_header->height())
        return false;
    if (m_lastResize.isValid() && m_lastResize.elapsed() < kResizeQuietMs)
        return false;

    auto* cover = new Cover(m_host, m_host->canvas(), capture(m_host, m_header, m_body));
    cover->show();
    cover->raise();
    m_cover = cover;
    // After the caller's switch and everything it posted (navigation arguments,
    // relayouts): snapshot the incoming state and play.
    QTimer::singleShot(0, this, [this] { reveal(); });
    return true;
}

void PageTransition::reveal()
{
    auto* cover = static_cast<Cover*>(m_cover.data());
    if (!cover || cover->revealed())
        return;
    // Let the switch settle: the new page, the header's actions and the banners
    // that left with the old page propagate their relayouts first.
    for (int i = 0; i < 3; ++i)
        QCoreApplication::sendPostedEvents(nullptr, QEvent::LayoutRequest);
    const int ms = motion::duration(kDurationMs);
    if (!m_header || ms <= 0 || !motion::onScreen(m_host) || cover->size() != m_host->size()) {
        finish();
        return;
    }
    cover->reveal(capture(m_host, m_header, m_body));
    m_anim->stop();
    m_anim->setDuration(ms);
    m_anim->start();
}

void PageTransition::finish()
{
    m_anim->stop();
    if (QWidget* cover = m_cover.data()) {
        m_cover.clear();
        cover->hide(); // the live page, exactly as an instant switch left it
        cover->deleteLater();
    }
}

bool PageTransition::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == m_host) {
        switch (event->type()) {
        case QEvent::Resize:
            m_lastResize.start();
            if (isRunning())
                finish();
            break;
        case QEvent::Hide:
#if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
        case QEvent::DevicePixelRatioChange:
#endif
            if (isRunning())
                finish();
            break;
        default:
            break;
        }
    }
    return QObject::eventFilter(watched, event);
}
