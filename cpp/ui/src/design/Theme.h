#pragma once
#include <QBrush>
#include <QColor>
#include <QLinearGradient>
#include <QRectF>
#include <QString>

class QApplication;

// ═════════════════════════════════════════════════════════════════════════════
//  Bulwark design system — "Bedrock" (磐石)
// ═════════════════════════════════════════════════════════════════════════════
//
//  A dark console built from the product's own metaphor — 磐垒, a rampart of
//  stacked stone — instead of the usual navy + neon gradient:
//
//  • Two planes of different material, not one flat fill. The navigation rail
//    is patinated jade-ink laid in courses of stone; the work area is warm
//    graphite with a fine grain (design/Backdrop). Cards are smooth stone on
//    top, separated by hairline rims lit along the top edge; only true
//    top-level floating windows (prompts, toasts) cast a shadow.
//  • One brand hue — jade (玉青) — for interaction and focus. Brass (黄铜) is an
//    inlay only (brand mark, active-nav bar, the rail's edge) and never carries
//    state, so it can't be mistaken for a warning.
//  • Status colours are earthy and reserved for state: green safe, amber
//    caution, cinnabar threat, azurite info.
//  • Every page has an identity hue (design/Identity.h) for wayfinding — its
//    header tile, rail glyph, list-card light, segment thumb, empty states —
//    and records carry the hue of their kind (event type, autostart point,
//    launch origin). Both come only from the categorical set below, never
//    from a status colour, and a record's status always wins its glyph.
//
//  Contrast: every token that carries text clears WCAG AA (4.5:1) on surface(),
//  bg() and the rail; the measured ratio on surface() is noted next to each
//  value. textMuted() in particular renders suspect-program paths, command
//  lines and prompt field captions — content the user must read to make a
//  security decision — so it may not be "tuned down" below AA for looks.
//
//  Colours are functions so QPainter code and computed per-widget styles share
//  one source of truth; styleSheet()/apply() bake the same values into the
//  global Qt Style Sheet.
namespace theme {

// ---- planes, back to front -------------------------------------------------
inline QColor bg()           { return QColor(0x15, 0x14, 0x13); } // work-area canvas (warm graphite) + title bar
inline QColor bgSidebar()    { return QColor(0x0E, 0x1B, 0x18); } // navigation rail (jade-ink)
inline QColor railInset()    { return QColor(0x0A, 0x14, 0x12); } // recessed panel on the rail (status card)
inline QColor railBorder()   { return QColor(0x22, 0x37, 0x32); } // hairlines on the rail
inline QColor railMuted()    { return QColor(0x8C, 0xA8, 0xA0); } // muted text on the rail (6.9:1 on the rail)
inline QColor surface()      { return QColor(0x1D, 0x1C, 0x1A); } // cards / panels / tables
inline QColor surfaceTop()   { return QColor(0x22, 0x21, 0x1E); } // top of a card's vertical light falloff
inline QColor surfaceAlt()   { return QColor(0x26, 0x25, 0x22); } // hover / secondary fill
inline QColor surfaceHi()    { return QColor(0x31, 0x2F, 0x2B); } // pressed / selected
inline QColor raised()       { return QColor(0x24, 0x23, 0x20); } // floating: menus, popups, prompts
inline QColor field()        { return QColor(0x13, 0x12, 0x11); } // inset inputs
inline QColor border()       { return QColor(0x2D, 0x2B, 0x28); } // hairlines
inline QColor borderStrong() { return QColor(0x41, 0x3E, 0x39); } // control outlines
inline QColor borderLit()    { return QColor(0x47, 0x43, 0x3D); } // top rim of a card (catches the light)

// ---- text ------------------------------------------------------------------
inline QColor textPrimary()   { return QColor(0xEF, 0xEA, 0xE2); } // 14.2:1 on surface
inline QColor textSecondary() { return QColor(0xBD, 0xB7, 0xAD); } //  8.6:1
inline QColor textMuted()     { return QColor(0x9B, 0x94, 0x8A); } //  5.7:1, 5.1:1 on surfaceAlt (see header note)
inline QColor textDisabled()  { return QColor(0x62, 0x5D, 0x56); } // disabled controls only

// ---- brand -----------------------------------------------------------------
inline QColor accent()       { return QColor(0x3D, 0xC4, 0xA5); } // jade: icons, focus, links (7.8:1)
inline QColor accentSoft()   { return QColor(0x8E, 0xDF, 0xC9); } // pale jade highlight (active nav glyph)
inline QColor accentStrong() { return QColor(0x13, 0x82, 0x70); } // fills carrying light text (4.6:1 w/ ink)
inline QColor accentDeep()   { return QColor(0x0E, 0x6A, 0x5C); } // low end of a fill's same-hue falloff (6.3:1 w/ ink)
inline QColor accentAlt()    { return QColor(0xB3, 0x9A, 0xE6); } // amethyst: AI / intelligence (7.0:1)
inline QColor accentInk()    { return QColor(0xFF, 0xFC, 0xF5); } // text / knob on accent fills
inline QColor brass()        { return QColor(0xC9, 0xA0, 0x63); } // inlay only — never state (7.1:1)
inline QColor brassDeep()    { return QColor(0x8E, 0x6B, 0x3B); } // brass in shadow

// ---- status ----------------------------------------------------------------
inline QColor success() { return QColor(0x4C, 0xC9, 0x8F); } // 8.2:1
inline QColor warning() { return QColor(0xE9, 0xA9, 0x3F); } // 8.3:1
inline QColor danger()  { return QColor(0xEC, 0x65, 0x53); } // 5.3:1 (cinnabar)
inline QColor info()    { return QColor(0x62, 0xA8, 0xDB); } // 6.6:1 (azurite)

// ---- categorical (graph entity kinds, charts) — all >= 5.5:1 on surface -----
// Spread around the wheel so the eight graph node kinds stay tellable apart.
//
// Three of them sit on top of a reserved hue and must never stand in for
// anything else: sky IS info, amber reads as warning (CIEDE2000 3.7), teal
// reads as jade (3.0). Page identities and record kinds (design/Identity.h)
// therefore use violet, purple, cyan, pink, olive and periwinkle only.
inline QColor violet()     { return QColor(0xA5, 0x8F, 0xE0); } // 6.2:1
inline QColor purple()     { return QColor(0xC9, 0x8B, 0xD0); } // orchid, 6.6:1
inline QColor sky()        { return QColor(0x62, 0xA8, 0xDB); }
inline QColor cyan()       { return QColor(0x4E, 0xC3, 0xCF); } // 8.1:1
inline QColor teal()       { return QColor(0x4D, 0xBF, 0xA9); }
inline QColor amber()      { return QColor(0xE2, 0xB0, 0x4E); }
inline QColor pink()       { return QColor(0xE2, 0x7D, 0x9E); } // rose, 6.2:1
inline QColor olive()      { return QColor(0xA8, 0xC2, 0x5B); } // 8.5:1
inline QColor periwinkle() { return QColor(0x8E, 0x9C, 0xF2); } // 6.6:1; between info and accentAlt, 10+ from both

// Translucent copy of a colour (glows, soft fills in QPainter code).
inline QColor tint(const QColor& c, qreal alpha)
{
    QColor r = c;
    r.setAlphaF(qBound<qreal>(0.0, alpha, 1.0));
    return r;
}

// Opaque blend of `fg` over `bg` at `a` (0..1). Soft badge / pill fills use this
// so they stay opaque (style sheets get no rgba() alpha ambiguity).
inline QColor blend(const QColor& fg, const QColor& bg, qreal a)
{
    return QColor(int(fg.red()   * a + bg.red()   * (1 - a)),
                  int(fg.green() * a + bg.green() * (1 - a)),
                  int(fg.blue()  * a + bg.blue()  * (1 - a)));
}

// The pale highlight of a hue (active nav glyph, lit segment thumb): roughly
// what accentSoft() is to accent().
inline QColor soft(const QColor& c)
{
    return blend(accentInk(), c, 0.40);
}

// The brand fill laid diagonally across `r`: one hue (jade) falling off into its
// own shadow — deliberately not a hue-shifting gradient.
inline QLinearGradient brandGradient(const QRectF& r)
{
    QLinearGradient g(r.topLeft(), r.bottomRight());
    g.setColorAt(0.0, accentStrong());
    g.setColorAt(1.0, accentDeep());
    return g;
}

namespace metric {
inline constexpr int sidebarW   = 244;
inline constexpr int topbarH    = 70;
inline constexpr int radiusCard = 16;
inline constexpr int radiusCtl  = 10;
inline constexpr int pagePad    = 28;
} // namespace metric

// Canvas for graph views: the base colour with a faint dot grid (a tiled brush;
// fill before applying any zoom so the grid pitch stays constant).
QBrush canvasBrush();

// Fine monochrome grain on a transparent tile (fixed seed, so it is identical on
// every rebuild and never shimmers). Filled over a plane it gives the dark
// surfaces a material instead of a flat digital fill.
QBrush grainBrush();

// The global application style sheet (all tokens above, baked in).
QString styleSheet();

// Applies the complete look to the application: Fusion as the base style (it
// honours the palette everywhere the style sheet doesn't reach), a matching dark
// QPalette, the UI font, the style sheet, and native window chrome (dark title
// bars / rounded popups on Windows). Call once in main(), before any window.
void apply(QApplication& app);

} // namespace theme
