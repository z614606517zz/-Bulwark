#pragma once
#include <QFrame>
#include <QPixmap>
#include <QSize>

class QBrush;
class QPainter;

// The two planes behind everything (design system "Bedrock", see Theme.h):
//
//  • Kind::Content — the work area: warm graphite, a little lighter at the top,
//    a cool spill of jade light where it meets the rail and a warm wash from the
//    far corner, all under a fine grain. Page containers are transparent, so the
//    material shows between cards.
//  • Kind::Sidebar — the navigation rail: jade-ink laid in courses of stone
//    (the 垒 of 磐垒), strongest behind the brand mark and fading down the rail,
//    with a brass inlay along the edge that meets the work area.
//
// Rendered once per size into a cached pixmap; repaints of small regions (a
// ticking counter, a hover) just blit from the cache.
class Backdrop : public QFrame
{
public:
    enum class Kind { Content, Sidebar };
    explicit Backdrop(Kind kind, QWidget* parent = nullptr);

    // Ashlar courses (stone blocks of varying width, staggered row to row) drawn
    // as crisp 1px joints with `joints` (usually a gradient, so the wall fades
    // out). Clipped to `r`. Fixed seed: the same wall on every rebuild.
    static void paintCourses(QPainter& p, const QRectF& r, const QBrush& joints, qreal courseHeight = 18.0);

    // The plane rendered at `size` (logical px) for `dpr`.
    static QPixmap render(Kind kind, const QSize& size, qreal dpr);

    // This widget's plane exactly as it paints it (its size, its DPR) — for an
    // overlay that stands in for the live content (design/PageTransition).
    QPixmap canvas();

    // Gives a framed top-level window (detail dialogs, graph / timeline windows)
    // the same work-area material as the main window without restructuring its
    // layout: an event filter paints the cached canvas at the start of the
    // window's own paint event, and children paint over it as usual.
    static void install(QWidget* window);

protected:
    void paintEvent(QPaintEvent*) override;
    void resizeEvent(QResizeEvent*) override;

private:
    Kind m_kind;
    QPixmap m_cache;
};
