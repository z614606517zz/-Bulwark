#pragma once
#include "Nav.h"
#include "design/Theme.h"

#include <QColor>
#include <QString>

// ═════════════════════════════════════════════════════════════════════════════
//  Identity hues — where am I, and what kind of thing is this?
// ═════════════════════════════════════════════════════════════════════════════
//
// Status colours answer "is this safe?". Identity hues answer two other
// questions, so pages stop looking alike without borrowing a status colour:
//
//   page   every page wears one hue for wayfinding: its rail glyph and active
//          wash, the tile beside its title, the light in its list card, its
//          segment thumb, neutral group headers and its empty states;
//   kind   a record shows the hue of what it is — event type, autostart point,
//          launch origin — so a list can be read by colour as well as by shape.
//
// Both are drawn only from the categorical hues in Theme.h that stay clear of
// every reserved one (violet, purple, cyan, pink, olive, periwinkle), plus
// accentAlt, which already means "AI", and — for page chrome only — accent for
// the product's own pages (仪表盘 · 进程管理 · 设置).
//
// Rules that keep them from being read as state:
//   • A record's status always wins its glyph: a risky row is danger / warning
//     whatever its kind; only unremarkable rows show their kind.
//   • Interaction stays jade: selection, focus rings, primary buttons, toggles,
//     the "new records" pill.
//   • Brass stays an inlay (the rail's active bar), whatever the page hue.
namespace identity {

// ---- pages -------------------------------------------------------------------
//
// Neighbours in the rail never share a hue family (the closest adjacent pair,
// jade 仪表盘 beside cyan 事件记录, is CIEDE2000 15). A hue returns only in
// another section, where the group title separates the two.
inline QColor page(const QString& key)
{
    const auto is = [&key](const char* k) { return key == QLatin1String(k); };
    if (is(nav::Events) || is(nav::Reputation))       return theme::cyan();       // live signal · cloud
    if (is(nav::Timeline) || is(nav::Persistence))    return theme::periwinkle(); // history · what survives a reboot
    if (is(nav::Chain) || is(nav::Quarantine))        return theme::purple();     // combined / contained threats
    if (is(nav::Rules))                               return theme::violet();     // policy
    if (is(nav::Trust))                               return theme::olive();      // allow list, not "safe" green
    return theme::accent(); // 仪表盘 · 进程管理 (the attack graph's process colour) · 设置 — the product itself
}

inline QColor page(const char* key) { return page(QString::fromLatin1(key)); }

// 设置 is one page with seven sections; each is titled in the hue of what it
// configures, so 「威胁情报源」 matches 云信誉, 「云查杀与 AI」 wears the AI colour, and
// the category column reads like a small rail of its own. Keys are the section
// keys nav::go("settings", {section}) takes.
inline QColor settingsSection(const QString& key)
{
    const auto is = [&key](const char* k) { return key == QLatin1String(k); };
    if (is("dims"))     return theme::olive();       // the six dimensions carry their own kinds
    if (is("decision")) return page(nav::Rules);     // policy
    if (is("intel"))    return page(nav::Reputation);
    if (is("ai"))       return theme::accentAlt();   // the AI colour (大模型接口 lives here)
    if (is("share"))    return theme::pink();
    if (is("about"))    return theme::periwinkle();
    return theme::accent();                          // 防护总控: the product's own switchboard
}

// ---- record kinds --------------------------------------------------------------
//
// The same vocabulary as the attack graph's node kinds (AttackGraphWindow),
// except where the graph uses a hue that is reserved next to a status pill:
// networks there are sky (= info), modules amber (≈ warning) and processes
// jade (≈ success); in lists they are cyan, periwinkle and neutral.
enum class Kind {
    Neutral,    // nothing to say (unknown origin, "other")
    Process,    // process start / end, interactive launch, IFEO hijack
    Injection,  // remote thread; the process dimension (it watches injection)
    Module,     // image / driver load, AppInit_DLLs; the memory dimension
    File,       // file write / delete, startup folder
    Registry,   // registry write, Run / RunOnce, Winlogon, logon autostart
    Network,    // connections, DNS, WMI
    Protection, // the 自我保护 dimension — never a record (see below)
    Service,    // Windows services
    Task,       // scheduled tasks
};

inline QColor kind(Kind k)
{
    switch (k) {
    // Records never wear jade. The graph's process colour sits CIEDE2000 7 from
    // success green, so a jade glyph beside a 「已放行」 pill reads as "allowed" —
    // and on a low-risk row that was blocked it would contradict the row. Processes,
    // the most common kind, stay neutral; lists read fine with the others in colour.
    case Kind::Process:    return theme::textSecondary();
    case Kind::Protection: return theme::accent(); // the product's own shield, on the settings tile only
    case Kind::Injection:  return theme::purple();
    case Kind::Service:    return theme::purple(); // shares orchid with Injection: one is a launch origin, the other an event type
    case Kind::Module:     return theme::periwinkle();
    case Kind::File:       return theme::olive();
    case Kind::Registry:   return theme::violet();
    case Kind::Network:    return theme::cyan();
    case Kind::Task:       return theme::pink();
    case Kind::Neutral:    break;
    }
    return theme::textSecondary();
}

// A fixed walk through the identity hues for peers that have no kind of their
// own (the threat-intel sources in 设置): consecutive entries never share a
// family, and the walk is stable, so a source keeps its hue across launches.
inline QColor sequence(int i)
{
    const QColor hues[] = {theme::cyan(),   theme::purple(), theme::olive(),
                           theme::periwinkle(), theme::pink(), theme::violet()};
    constexpr int n = int(sizeof(hues) / sizeof(hues[0]));
    return hues[((i % n) + n) % n];
}

} // namespace identity
