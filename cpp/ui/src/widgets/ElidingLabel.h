#pragma once
#include <QFontMetrics>
#include <QLabel>
#include <QResizeEvent>
#include <QSize>

// A single-line label that elides its text with "…" to fit the width it is
// given, and reports a tiny horizontal minimum so a long path / URL can never
// force its parent layout wider than the viewport. This is what keeps content
// from overflowing and visually overlapping neighbours when the window is not
// maximized. The full text stays available as a tooltip.
//
// It remains a normal QLabel (painted by Qt), so the app's QSS role styling
// ([role="muted"] etc.) still applies. Callers that update the text at runtime
// must hold an ElidingLabel* (not a QLabel*) so setText() routes here.
class ElidingLabel : public QLabel
{
public:
    explicit ElidingLabel(const QString& text = QString(), QWidget* parent = nullptr)
        : QLabel(parent), m_full(text)
    {
        QLabel::setText(text);
        if (!text.isEmpty())
            setToolTip(text);
        setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    }

    void setElideMode(Qt::TextElideMode mode)
    {
        m_mode = mode;
        reElide();
    }

    // Hides QLabel::setText — updates the stored full text, then re-elides.
    void setText(const QString& text)
    {
        m_full = text;
        setToolTip(text);
        reElide();
    }

    QString fullText() const { return m_full; }

    // Allow the label to shrink well below its natural text width; it will
    // elide to fit instead of forcing the layout wide.
    QSize minimumSizeHint() const override
    {
        QSize s = QLabel::minimumSizeHint();
        s.setWidth(qMin(s.width(), 24));
        return s;
    }

protected:
    void resizeEvent(QResizeEvent* e) override
    {
        QLabel::resizeEvent(e);
        reElide();
    }

private:
    void reElide()
    {
        if (m_inElide)
            return;
        m_inElide = true;
        const int w = width();
        const QString shown = (w > 4) ? fontMetrics().elidedText(m_full, m_mode, w) : m_full;
        QLabel::setText(shown);
        m_inElide = false;
    }

    QString m_full;
    Qt::TextElideMode m_mode = Qt::ElideRight;
    bool m_inElide = false;
};
