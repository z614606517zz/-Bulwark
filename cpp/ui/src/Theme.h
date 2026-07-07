#pragma once
#include <QColor>
#include <QString>

// Bulwark UI design system (Qt Widgets edition).
//
// A clean, light "security console" palette. White cards/panels float on a soft
// cool-gray canvas (depth via layering + a subtle shadow rather than a flat
// white expanse), with a teal brand accent and semantic status colours tuned
// for reading on white. Colours are exposed as QColor helpers (for QPainter
// custom widgets) and baked into the global Qt Style Sheet returned by
// styleSheet(). Plain container widgets are made transparent (see the .QWidget
// rule) so only cards carry a fill — no gray strips inside panels.
namespace theme {

inline QColor bg()            { return QColor("#EDF0F5"); } // app canvas (soft gray — cards float on it)
inline QColor bgSidebar()     { return QColor("#FFFFFF"); } // navigation rail (white)
inline QColor surface()       { return QColor("#FFFFFF"); } // cards / panels (white)
inline QColor surfaceAlt()    { return QColor("#EEF2F8"); } // secondary / hover
inline QColor surfaceHi()     { return QColor("#E4EAF3"); } // pressed / selected
inline QColor border()        { return QColor("#E2E7EF"); }
inline QColor borderStrong()  { return QColor("#CAD4E1"); }

inline QColor textPrimary()   { return QColor("#141C29"); } // near-black navy ink
inline QColor textSecondary() { return QColor("#586576"); }
inline QColor textMuted()     { return QColor("#93A0B2"); }

inline QColor accent()        { return QColor("#0E9E8C"); } // brand teal / interactive
inline QColor accentAlt()     { return QColor("#2E86DE"); } // secondary blue
inline QColor accentInk()     { return QColor("#FFFFFF"); } // text / knob on accent

inline QColor success()       { return QColor("#0E8F4E"); }
inline QColor warning()       { return QColor("#B87400"); }
inline QColor danger()        { return QColor("#DC3545"); }
inline QColor info()          { return QColor("#2563EB"); }

// Translucent tint of a colour (soft badges, glows, chart fills).
inline QColor tint(const QColor& c, qreal alpha) {
    QColor r = c;
    r.setAlphaF(alpha);
    return r;
}

// Opaque blend of `fg` over `bg` at `a` (0..1). Handy for soft badge fills that
// must stay opaque (avoids QSS rgba() alpha ambiguity). On the light theme this
// yields pale tints of the semantic colours over white.
inline QColor blend(const QColor& fg, const QColor& bg, qreal a) {
    return QColor(int(fg.red()   * a + bg.red()   * (1 - a)),
                  int(fg.green() * a + bg.green() * (1 - a)),
                  int(fg.blue()  * a + bg.blue()  * (1 - a)));
}

namespace metric {
inline constexpr int sidebarW   = 238;
inline constexpr int topbarH    = 68;
inline constexpr int radiusCard = 14;
inline constexpr int radiusCtl  = 10;
inline constexpr int pagePad     = 28;
} // namespace metric

// The global application stylesheet (applied once in main()).
QString styleSheet();

} // namespace theme
