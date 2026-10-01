#pragma once

class QApplication;

namespace ui {

// Press feedback for the app's ordinary buttons: a soft circle spreads from
// where the button was pressed and fades out (~400 ms), painted by a throwaway
// overlay child so the button itself — and its style-sheet look — is untouched.
//
// Installed once from theme::apply() as an application-wide filter on
// QMouseEvent, because "every button" is exactly the point: nothing has to opt
// in, and a control that paints its own press state is simply left out.
//
// Only QPushButton and QToolButton get it: the design's custom-painted buttons
// (ToggleSwitch's knob, NavButton, the segmented control, filter chips, count
// tiles) each animate their own press or selection, and a circle spreading
// under them would fight it. Check boxes and radio buttons are out for the same
// reason. Nothing happens while motion is off.
void installRipples(QApplication& app);

} // namespace ui
