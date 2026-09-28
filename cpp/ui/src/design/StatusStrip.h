#pragma once
#include "design/Components.h"
#include "design/GlowCard.h"
#include "design/IconTile.h"
#include "design/Theme.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QVBoxLayout>

// The standing state of whatever feeds a page, shown above its list — "只记录不拦截 ·
// 组合表 0.3 · 128 条组合". Unlike a banner it is not a message and never goes
// away: it is the context every record on the page has to be read in (a list of
// attack-chain hits means something different while the engine only records).
class StatusStrip : public GlowCard
{
public:
    explicit StatusStrip(QWidget* parent = nullptr) : GlowCard(parent)
    {
        setObjectName(QStringLiteral("Card"));
        setRadius(14);
        auto* h = new QHBoxLayout(this);
        h->setContentsMargins(14, 11, 16, 11);
        h->setSpacing(12);
        m_tile = new IconTile(QStringLiteral("info"), theme::textMuted(), 32, 16);
        h->addWidget(m_tile, 0, Qt::AlignTop);
        auto* col = new QVBoxLayout;
        col->setContentsMargins(0, 0, 0, 0);
        col->setSpacing(2);
        m_title = ui::label(QString(), "title");
        m_text = ui::label(QString(), "secondary");
        m_text->setWordWrap(true);
        m_text->hide();
        col->addWidget(m_title);
        col->addWidget(m_text);
        h->addLayout(col, 1);
        m_meta = ui::label(QString(), "muted");
        m_meta->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        m_meta->hide();
        h->addWidget(m_meta, 0, Qt::AlignVCenter);
        m_row = h;
    }

    // A control at the right end ("去设置").
    void addTrailing(QWidget* w) { m_row->addWidget(w, 0, Qt::AlignVCenter); }

    // `title` is coloured with the state colour; the glyph says it too, so the
    // state never rides on colour alone.
    void setState(const QString& icon, const QColor& color, const QString& title,
                  const QString& text = QString(), const QString& meta = QString())
    {
        m_tile->set(icon, color);
        m_title->setText(title);
        m_title->setStyleSheet(QStringLiteral("color:%1;").arg(color.name()));
        m_text->setText(text);
        m_text->setVisible(!text.isEmpty());
        m_meta->setText(meta);
        m_meta->setVisible(!meta.isEmpty());
        setGlow(color, QPointF(0.0, 0.5), 0.6, 0.08);
        setAccessibleName(title + (text.isEmpty() ? QString() : QStringLiteral("。") + text));
    }

private:
    IconTile* m_tile = nullptr;
    QLabel* m_title = nullptr;
    QLabel* m_text = nullptr;
    QLabel* m_meta = nullptr;
    QHBoxLayout* m_row = nullptr;
};
