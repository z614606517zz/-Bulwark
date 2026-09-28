#pragma once
#include <QColor>
#include <QFrame>
#include <QPointF>

// The design's card surface. Painted directly (not through the style sheet) so
// every card in the product shares one exact recipe:
//
//   • a faint vertical light falloff (lit from above),
//   • a 1px rim that is brighter along the top edge — the depth cue that
//     replaces drop shadows on a dark canvas,
//   • optionally a soft ambient light ("glow") in a status colour, anchored at a
//     point of the card. The dashboard hero, the stat tiles and the floating
//     prompts use it to carry state without shouting.
//
// Tones:
//   Flat      in-window content card (default)
//   Inset     recessed panel inside a card
//   Floating  the only opaque surface of a frameless top-level window (behavior
//             prompt, toasts, scan progress): raised fill + brighter rim.
//   Rail      recessed panel on the jade-ink navigation rail (status card)
class GlowCard : public QFrame
{
public:
    enum class Tone { Flat, Inset, Floating, Rail };

    explicit GlowCard(QWidget* parent = nullptr);

    void setTone(Tone tone);
    Tone tone() const { return m_tone; }

    void setRadius(qreal radius);

    // `anchor` is in card-relative units (0,0 = top-left, 1,1 = bottom-right);
    // `reach` is the glow radius as a fraction of the card's longer side;
    // `strength` is the peak alpha at the anchor.
    void setGlow(const QColor& color, QPointF anchor = QPointF(0.0, 0.0),
                 qreal reach = 0.75, qreal strength = 0.20);
    void clearGlow();
    QColor glowColor() const { return m_glow; }

protected:
    void paintEvent(QPaintEvent*) override;

private:
    Tone m_tone = Tone::Flat;
    qreal m_radius = 16.0;
    QColor m_glow;
    QPointF m_anchor{0.0, 0.0};
    qreal m_reach = 0.75;
    qreal m_strength = 0.20;
};
