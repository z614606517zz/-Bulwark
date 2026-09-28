#pragma once
#include <QEvent>
#include <QFrame>
#include <QScrollArea>
#include <QScrollBar>

// A scroll area that is exactly as tall as its content — up to a cap — and only
// scrolls beyond that. For dialogs whose middle section varies wildly in length
// (a prompt with two risk reasons vs. twelve, a report with 3 vs. 300 items):
// short content leaves no dead space, long content can't push the dialog's
// buttons off the screen.
//
// Height is computed height-for-width, so wrapped text is measured at the real
// width. `fallbackWidth` is used before the area has been laid out.
class FitScrollArea : public QScrollArea
{
public:
    FitScrollArea(int maxHeight, int fallbackWidth, QWidget* parent = nullptr)
        : QScrollArea(parent), m_max(maxHeight), m_fallbackW(fallbackWidth)
    {
        setWidgetResizable(true);
        setFrameShape(QFrame::NoFrame);
        setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        viewport()->setAutoFillBackground(false);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    }

    void setContent(QWidget* w)
    {
        setWidget(w);
        // QScrollArea::setWidget() turns autoFillBackground on, which would paint
        // the palette's window colour over the card behind it.
        w->setAutoFillBackground(false);
        w->installEventFilter(this);
        updateGeometry();
    }

    void setMaxHeight(int h)
    {
        m_max = h;
        updateGeometry();
    }

    QSize sizeHint() const override
    {
        const QWidget* w = widget();
        if (!w)
            return QScrollArea::sizeHint();
        const int vw = viewport()->width() > 60 ? viewport()->width() : m_fallbackW;
        int h = w->hasHeightForWidth() ? w->heightForWidth(vw) : w->sizeHint().height();
        if (h > m_max)
            h = m_max;
        return {vw, qMax(0, h)};
    }

    QSize minimumSizeHint() const override
    {
        return {60, qMin(sizeHint().height(), 96)};
    }

protected:
    bool eventFilter(QObject* obj, QEvent* e) override
    {
        if (obj == widget() && e->type() == QEvent::LayoutRequest)
            updateGeometry();
        return QScrollArea::eventFilter(obj, e);
    }

    void resizeEvent(QResizeEvent* e) override
    {
        QScrollArea::resizeEvent(e);
        if (viewport()->width() != m_lastW) { // height depends on width
            m_lastW = viewport()->width();
            updateGeometry();
        }
    }

private:
    int m_max;
    int m_fallbackW;
    int m_lastW = -1;
};
