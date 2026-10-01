#pragma once
#include <QtGlobal>

#include <functional>

class QLabel;
class QString;
class QWidget;

// Motion policy shared by every animated control (page transitions, sidebar
// collapse and rail selection, inspector slide, sheet enter/exit, toasts,
// segmented thumb, countdown bars, press ripples, count-ups).
//
// Windows' "Show animations in Windows" accessibility setting is honoured: when
// it is off, animations jump straight to their end value. Nothing in the design
// depends on motion to convey meaning — every animated state also has a static
// look — so turning it off loses nothing but the transition itself.
namespace motion {

// True when the system allows client-area animations. Read once and cached for
// the session (the setting is rarely toggled while an app is running).
bool enabled();

// Duration to use for a transition: `ms` when motion is on, 0 when it is off.
int duration(int ms);

// ---- easing for hand-driven animations (input and output 0..1) ------------
qreal outCubic(qreal t);
qreal inCubic(qreal t);
// Overshoots a little past 1 before settling: a "pop".
qreal outBack(qreal t);
// The slice [from, to] of a 0..1 progress, stretched back to 0..1 (clamped) —
// several things staggered off one clock.
qreal slice(qreal t, qreal from, qreal to);

// True when `w` can actually be seen: shown, and its window neither hidden nor
// minimised. Animations nobody can see are skipped (or parked) on this.
bool onScreen(const QWidget* w);

// Shows `value` in `label`, rolling the number from the one it shows now in a
// short decelerating count. `format` renders a value (default: the plain
// number). Steps of one, and labels that are not on screen, just jump: a
// counter going up by one should read as a tick, not a roll. Calling again
// mid-roll retargets from wherever the count is.
void countTo(QLabel* label, qint64 value, std::function<QString(qint64)> format = {});

} // namespace motion
