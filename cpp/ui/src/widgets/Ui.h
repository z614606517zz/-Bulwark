#pragma once
#include "Theme.h"
#include "widgets/ElidingLabel.h"

#include <QFrame>
#include <QGraphicsDropShadowEffect>
#include <QLabel>
#include <QString>

// Small header-only factory helpers to cut boilerplate when composing pages.
namespace ui {

inline QFrame* card(QWidget* parent = nullptr)
{
    auto* f = new QFrame(parent);
    f->setObjectName(QStringLiteral("Card"));
    // Soft cool shadow so white cards lift off the gray canvas (a "floating"
    // depth cue — the antidote to a flat all-white expanse).
    auto* sh = new QGraphicsDropShadowEffect(f);
    sh->setBlurRadius(22);
    sh->setColor(QColor(23, 42, 71, 34));
    sh->setOffset(0, 3);
    f->setGraphicsEffect(sh);
    return f;
}

inline QFrame* cardAlt(QWidget* parent = nullptr)
{
    auto* f = new QFrame(parent);
    f->setObjectName(QStringLiteral("CardAlt"));
    return f;
}

inline QLabel* label(const QString& text, const char* role = nullptr, QWidget* parent = nullptr)
{
    auto* l = new QLabel(text, parent);
    if (role)
        l->setProperty("role", role);
    return l;
}

// Like label(), but for long single-line values (paths / URLs): elides with
// "…" to fit and never forces the layout wider than the viewport. Keep the
// returned ElidingLabel* type if you update the text later (setText re-elides).
inline ElidingLabel* elided(const QString& text, const char* role = nullptr, QWidget* parent = nullptr)
{
    auto* l = new ElidingLabel(text, parent);
    if (role)
        l->setProperty("role", role);
    return l;
}

inline QFrame* hDivider(QWidget* parent = nullptr)
{
    auto* f = new QFrame(parent);
    f->setObjectName(QStringLiteral("Divider"));
    f->setFixedHeight(1);
    return f;
}

// A soft rounded status badge: tinted opaque fill + coloured text/outline.
inline void stylePill(QLabel* l, const QString& text, const QColor& c)
{
    l->setText(text);
    l->setStyleSheet(QStringLiteral(
        "background:%1; color:%2; border:1px solid %3; border-radius:999px;"
        "padding:3px 10px; font-size:9pt; font-weight:600;")
        .arg(theme::blend(c, theme::surface(), 0.16).name(),
             c.name(),
             theme::blend(c, theme::surface(), 0.40).name()));
    l->setAlignment(Qt::AlignCenter);
}

inline QLabel* pill(const QString& text, const QColor& c, QWidget* parent = nullptr)
{
    auto* l = new QLabel(parent);
    stylePill(l, text, c);
    return l;
}

} // namespace ui
