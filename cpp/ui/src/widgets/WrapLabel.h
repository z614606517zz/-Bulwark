#pragma once
#include <QFontMetrics>
#include <QLabel>
#include <QPainter>
#include <QPaintEvent>
#include <QSizePolicy>

// A label that wraps ANYWHERE, not just at spaces — for the long unbroken
// strings a security tool has to show in full: file paths, command lines,
// SHA-256 hashes, registry keys, URLs. QLabel's word wrap cannot break those
// (there are no spaces), so they either overflow their card or get elided
// away, and a path the user can't read in full is a path they can't verify.
//
// Height-for-width aware, so it grows to as many lines as the value needs.
// Colour and font still come from the style sheet role (it paints with the
// polished palette / font). Callers updating the text must hold a WrapLabel*.
class WrapLabel : public QLabel
{
public:
    explicit WrapLabel(const QString& text = QString(), QWidget* parent = nullptr)
        : QLabel(parent)
    {
        QSizePolicy sp(QSizePolicy::Preferred, QSizePolicy::Preferred);
        sp.setHeightForWidth(true);
        setSizePolicy(sp);
        setText(text);
    }

    // Hides QLabel::setText (keeps QLabel's copy for accessibility).
    void setText(const QString& text)
    {
        m_text = text;
        QLabel::setText(text);
        updateGeometry();
        update();
    }
    QString fullText() const { return m_text; }

    bool hasHeightForWidth() const override { return true; }

    int heightForWidth(int w) const override
    {
        const QMargins m = contentsMargins();
        const int avail = qMax(1, w - m.left() - m.right());
        const QRect br = fontMetrics().boundingRect(QRect(0, 0, avail, 1 << 20),
                                                    kFlags, m_text.isEmpty() ? QStringLiteral(" ") : m_text);
        return br.height() + m.top() + m.bottom();
    }

    QSize sizeHint() const override
    {
        const int w = qMin(fontMetrics().horizontalAdvance(m_text) + 4, 460);
        return {w, heightForWidth(w)};
    }

    QSize minimumSizeHint() const override
    {
        return {24, fontMetrics().height()};
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setFont(font());
        p.setPen(palette().color(isEnabled() ? QPalette::Active : QPalette::Disabled, foregroundRole()));
        p.drawText(contentsRect(), kFlags, m_text);
    }

private:
    static constexpr int kFlags = int(Qt::TextWrapAnywhere) | int(Qt::AlignLeft) | int(Qt::AlignTop);
    QString m_text;
};
