#pragma once
#include <QElapsedTimer>
#include <QList>
#include <QObject>
#include <QPointer>

class Backdrop;
class QEvent;
class QVariantAnimation;
class QWidget;

// The main window's page change, played on snapshots of its content area so no
// live widget is ever faded, offset or given a graphics effect (text inside an
// effect renders through an offscreen pixmap and blurs on fractional scales):
//
//   header   the outgoing and the incoming page header cross-fade in place
//   body     the outgoing page fades out; the incoming one fades in while
//            rising a few pixels into place
//
// Call start() right before switching pages. It snapshots what is on screen and
// covers the area with that picture; on the next turn of the event loop — once
// the caller has switched pages, delivered navigation arguments and whatever
// that set off has laid out — it snapshots the incoming state and plays the
// change, after which the cover removes itself and the live page is exactly
// what an instant switch would have shown.
//
// start() returns false, and the switch is simply instant, when the change
// couldn't be seen or could only go wrong: the area isn't on screen (window
// hidden or minimised), animations are off, the area was resized a moment ago
// (window being resized, rail collapsing), or a change is still playing (rapid
// clicks: that one is cut to its end first). A resize, hide or DPI change while
// one plays also cuts it to its end.
class PageTransition : public QObject
{
public:
    // `host` is the covered area (the content plane); `header` sits at its top
    // and `body` are the widgets below it (banners, page stack) — all children
    // of `host`, which also owns this object.
    PageTransition(Backdrop* host, QWidget* header, const QList<QWidget*>& body);
    ~PageTransition() override;

    bool start();
    void finish();
    bool isRunning() const;

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    void reveal();

    Backdrop* m_host;
    QPointer<QWidget> m_header;
    QList<QPointer<QWidget>> m_body;
    QPointer<QWidget> m_cover; // the picture over the area while a change is on screen
    QVariantAnimation* m_anim = nullptr;
    QElapsedTimer m_lastResize;
};
