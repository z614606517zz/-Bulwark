#pragma once

// Motion policy shared by every animated control (sidebar collapse, inspector
// slide, sheet fade-in, segmented thumb, countdown bars).
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

} // namespace motion
