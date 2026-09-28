#pragma once
#include "design/GlowCard.h"
#include "design/Icons.h"
#include "design/Theme.h"
#include "widgets/ElidingLabel.h"

#include <QClipboard>
#include <QFont>
#include <QFrame>
#include <QGraphicsDropShadowEffect>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QString>
#include <QStyle>
#include <QTimer>
#include <QToolButton>
#include <QVariant>
#include <QVBoxLayout>

#include <functional>
#include <utility>

// Building blocks for composing pages in the "Bedrock" design. Everything a
// page needs to look native to the design lives here — pages never pick raw
// colours or fonts themselves (they use theme:: tokens through these helpers
// and the style sheet roles: role = display | h1 | h2 | title | secondary |
// muted | caption | eyebrow | stat | mono | link).
namespace ui {

// ---- surfaces ---------------------------------------------------------------

// A content card (layered surface + top-lit rim; see GlowCard). Returned as the
// GlowCard it is, so a page can light it in an identity hue (setGlow).
inline GlowCard* card(QWidget* parent = nullptr)
{
    auto* c = new GlowCard(parent);
    c->setObjectName(QStringLiteral("Card"));
    return c;
}

// A recessed secondary panel inside a card.
inline GlowCard* cardAlt(QWidget* parent = nullptr)
{
    auto* c = new GlowCard(parent);
    c->setObjectName(QStringLiteral("CardAlt"));
    c->setTone(GlowCard::Tone::Inset);
    c->setRadius(12);
    return c;
}

// Ambient shadow for a frameless top-level card. On a dark desktop the shadow
// all but disappears, which is why floating cards also get a brighter rim
// (GlowCard::Tone::Floating) — the rim, not the shadow, separates them from
// whatever is behind.
//
// The shadow can only paint inside the translucent window, i.e. within the
// shell margins around the card. `blur + dy` must stay close to the bottom
// margin (and `blur` to the side margins), or the shadow is cut off where the
// window ends and shows up as a faint hard-edged box on light desktops. The
// defaults fit the 24px shells of the prompt / update / report dialogs.
inline void elevate(QWidget* w, int blur = 24, int dy = 8, int alpha = 140)
{
    auto* sh = new QGraphicsDropShadowEffect(w);
    sh->setBlurRadius(blur);
    sh->setOffset(0, dy);
    sh->setColor(QColor(0, 0, 0, alpha));
    w->setGraphicsEffect(sh);
}

// The single opaque surface of a frameless, translucent top-level window
// (behavior prompt, toasts, scan progress, reports). `glow` tints the card with
// an ambient light in the window's state colour (risk, verdict…).
inline GlowCard* floatingCard(const QColor& glow = QColor(), QWidget* parent = nullptr)
{
    auto* c = new GlowCard(parent);
    c->setObjectName(QStringLiteral("Card"));
    c->setTone(GlowCard::Tone::Floating);
    c->setRadius(18);
    if (glow.isValid())
        c->setGlow(glow, QPointF(0.0, 0.0), 0.85, 0.13);
    elevate(c);
    return c;
}

// ---- text -------------------------------------------------------------------

inline QLabel* label(const QString& text, const char* role = nullptr, QWidget* parent = nullptr)
{
    auto* l = new QLabel(text, parent);
    if (role)
        l->setProperty("role", role);
    return l;
}

// Like label(), but for long single-line values (paths / URLs): elides with
// "…" to fit and never forces the layout wider than the viewport. Keep the
// returned ElidingLabel* if you update the text later (setText re-elides).
inline ElidingLabel* elided(const QString& text, const char* role = nullptr, QWidget* parent = nullptr)
{
    auto* l = new ElidingLabel(text, parent);
    if (role)
        l->setProperty("role", role);
    return l;
}

// A small, letter-spaced group heading ("威胁响应", "实时防护").
inline QLabel* eyebrow(const QString& text, QWidget* parent = nullptr)
{
    auto* l = label(text, "eyebrow", parent);
    QFont f = l->font();
    f.setLetterSpacing(QFont::AbsoluteSpacing, 1.4);
    l->setFont(f);
    return l;
}

// A label with explicit size / weight / colour (bypasses role styling).
inline QLabel* coloredText(const QString& text, int pt, int weight, const QColor& c)
{
    auto* l = new QLabel(text);
    l->setStyleSheet(QStringLiteral("font-size:%1pt; font-weight:%2; color:%3;")
                         .arg(pt).arg(weight).arg(c.name()));
    return l;
}

inline QFrame* hDivider(QWidget* parent = nullptr)
{
    auto* f = new QFrame(parent);
    f->setObjectName(QStringLiteral("Divider"));
    f->setFixedHeight(1);
    return f;
}

// ---- status -----------------------------------------------------------------

// A soft status capsule: tinted opaque fill, hairline rim, coloured text.
inline void stylePill(QLabel* l, const QString& text, const QColor& c)
{
    l->setText(text);
    // A concrete radius: Qt's style sheet engine drops the rounding entirely when
    // the radius exceeds half the box (the old 999px rendered square capsules).
    l->setStyleSheet(QStringLiteral(
        "background:%1; color:%2; border:1px solid %3; border-radius:11px;"
        "padding:3px 10px; font-size:9pt; font-weight:600;")
        .arg(theme::blend(c, theme::surface(), 0.14).name(),
             c.name(),
             theme::blend(c, theme::surface(), 0.34).name()));
    l->setAlignment(Qt::AlignCenter);
}

inline QLabel* pill(const QString& text, const QColor& c, QWidget* parent = nullptr)
{
    auto* l = new QLabel(parent);
    stylePill(l, text, c);
    return l;
}

inline QLabel* statusDot(const QColor& c)
{
    auto* d = new QLabel;
    d->setFixedSize(8, 8);
    d->setStyleSheet(QStringLiteral("background:%1; border-radius:4px;").arg(c.name()));
    return d;
}

// A rounded tile holding a centred glyph: diagonal tint of `color` with a
// matching rim. The tile radius scales with its size (~30%).
inline QFrame* iconBadge(const QString& name, const QColor& color, int box, int iconPx)
{
    auto* f = new QFrame;
    f->setFixedSize(box, box);
    f->setStyleSheet(QStringLiteral(
        "QFrame{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 %1,stop:1 %2);"
        "border:1px solid %3; border-radius:%4px;}")
        .arg(theme::blend(color, theme::surface(), 0.26).name(),
             theme::blend(color, theme::surface(), 0.10).name(),
             theme::blend(color, theme::surface(), 0.34).name())
        .arg(qRound(box * 0.3)));
    auto* lay = new QVBoxLayout(f);
    lay->setContentsMargins(0, 0, 0, 0);
    auto* ic = new AppIcon(name);
    ic->setColor(color);
    ic->setPx(iconPx);
    lay->addWidget(ic);
    return f;
}

// A metric tile: label + icon badge, big value, optional caption. The tile
// carries a faint corner light in its colour.
inline QFrame* statCard(const QString& icon, const QColor& color, const QString& value,
                        const QString& name, const QString& caption = QString())
{
    auto* c = new GlowCard;
    c->setObjectName(QStringLiteral("Card"));
    c->setGlow(color, QPointF(1.0, 0.0), 0.7, 0.12);
    c->setMinimumHeight(118);
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(18, 16, 18, 16);
    v->setSpacing(6);
    auto* top = new QHBoxLayout;
    top->setContentsMargins(0, 0, 0, 0);
    top->addWidget(label(name, "secondary"), 1, Qt::AlignVCenter);
    top->addWidget(iconBadge(icon, color, 34, 18), 0, Qt::AlignTop);
    v->addLayout(top);
    auto* val = label(value, "stat");
    v->addWidget(val);
    if (!caption.isEmpty())
        v->addWidget(label(caption, "muted"));
    v->addStretch();
    return c;
}

// ---- dynamic-property styling ------------------------------------------------
//
// The style sheet keys on dynamic properties (role / variant / size), and Qt
// only re-evaluates those when a widget is polished. Changing one at runtime
// with a bare setProperty() silently keeps the old look — that is how the
// process-detail status line kept showing its first colour. Change them through
// these helpers, which re-polish.
inline void repolish(QWidget* w)
{
    if (!w)
        return;
    w->style()->unpolish(w);
    w->style()->polish(w);
    w->update();
}

inline void setRole(QWidget* w, const char* role)
{
    if (!w)
        return;
    w->setProperty("role", role);
    repolish(w);
}

inline void setVariant(QWidget* w, const char* variant)
{
    if (!w)
        return;
    w->setProperty("variant", variant);
    repolish(w);
}

// ---- buttons -------------------------------------------------------------------

// A push button in one of the style-sheet variants (primary / ghost / danger;
// nullptr = default), optionally small and with a leading glyph tinted to match.
inline QPushButton* button(const QString& text, const char* variant = nullptr,
                           const QString& icon = QString(), bool small = false)
{
    auto* b = new QPushButton(text);
    if (variant)
        b->setProperty("variant", variant);
    if (small)
        b->setProperty("size", "sm");
    b->setCursor(Qt::PointingHandCursor);
    if (!icon.isEmpty()) {
        const bool primary = variant && qstrcmp(variant, "primary") == 0;
        const bool danger = variant && qstrcmp(variant, "danger") == 0;
        b->setIcon(AppIcon::icon(icon, primary ? theme::accentInk()
                                       : danger ? theme::danger()
                                                : theme::textSecondary(), 16));
    }
    return b;
}

// A borderless glyph-only button (close, copy, overflow…). `tip` doubles as the
// accessible name: a glyph on its own tells a screen reader nothing.
inline QToolButton* iconButton(const QString& icon, const QString& tip,
                               const QColor& color = theme::textSecondary(), int px = 16)
{
    auto* b = new QToolButton;
    b->setIcon(AppIcon::icon(icon, color, px));
    b->setIconSize(QSize(px, px));
    b->setToolTip(tip);
    b->setAccessibleName(tip);
    b->setCursor(Qt::PointingHandCursor);
    b->setAutoRaise(true);
    b->setFocusPolicy(Qt::TabFocus);
    return b;
}

// The "⋯" overflow button that opens `menu` (secondary page actions).
inline QToolButton* moreButton(QMenu* menu, const QString& tip = QString::fromUtf8("更多操作"))
{
    auto* b = iconButton(QStringLiteral("more"), tip, theme::textSecondary(), 18);
    b->setObjectName(QStringLiteral("MoreButton"));
    b->setMenu(menu);
    b->setPopupMode(QToolButton::InstantPopup);
    return b;
}

// Copy-to-clipboard glyph. Turns into a green check for a moment so the user can
// see the copy happened (the clipboard itself gives no feedback).
inline QToolButton* copyButton(std::function<QString()> text,
                               const QString& what = QString::fromUtf8("复制"))
{
    auto* b = iconButton(QStringLiteral("copy"), what, theme::textMuted(), 14);
    QObject::connect(b, &QToolButton::clicked, b, [b, what, text = std::move(text)] {
        if (QClipboard* cb = QGuiApplication::clipboard())
            cb->setText(text());
        b->setIcon(AppIcon::icon(QStringLiteral("check"), theme::success(), 14));
        b->setToolTip(QString::fromUtf8("已复制"));
        QTimer::singleShot(1400, b, [b, what] {
            b->setIcon(AppIcon::icon(QStringLiteral("copy"), theme::textMuted(), 14));
            b->setToolTip(what);
        });
    });
    return b;
}

// ---- page header actions ----------------------------------------------------------
//
// A page's primary actions (新增规则, 重新扫描, 信任文件…) live in the shell's page
// header, right-aligned, instead of in a toolbar row inside the page. A page
// hands its action row to the shell by attaching it here; MainWindow picks it up
// when the page is added and shows it while the page is current.
inline void setPageActions(QWidget* page, QWidget* actions)
{
    if (page)
        page->setProperty("bw.pageActions", QVariant::fromValue(static_cast<QObject*>(actions)));
}

inline QWidget* pageActions(const QWidget* page)
{
    if (!page)
        return nullptr;
    return qobject_cast<QWidget*>(page->property("bw.pageActions").value<QObject*>());
}

// A right-aligned row to fill with header actions (buttons, a ⋯ menu).
inline QWidget* actionRow(QHBoxLayout** layoutOut)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(8);
    if (layoutOut)
        *layoutOut = h;
    return w;
}

} // namespace ui
