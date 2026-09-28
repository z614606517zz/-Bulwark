#include "design/Inspector.h"
#include "design/Components.h"
#include "design/FlowLayout.h"
#include "design/IconTile.h"
#include "design/Theme.h"
#include "widgets/ElidingLabel.h"
#include "widgets/WrapLabel.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QLayout>
#include <QMenu>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QToolButton>
#include <QVBoxLayout>

Inspector::Inspector(QWidget* parent) : GlowCard(parent)
{
    setObjectName(QStringLiteral("Inspector"));
    setRadius(16);
    setAccessibleName(QString::fromUtf8("详情"));

    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(0);

    // header
    auto* head = new QWidget;
    auto* hh = new QHBoxLayout(head);
    hh->setContentsMargins(18, 16, 10, 12);
    hh->setSpacing(12);
    m_tile = new IconTile(QStringLiteral("info"), theme::textMuted(), 38, 19);
    hh->addWidget(m_tile, 0, Qt::AlignTop);
    auto* tc = new QVBoxLayout;
    tc->setSpacing(2);
    m_title = ui::elided(QString(), "h2");
    m_subtitle = ui::elided(QString(), "muted");
    m_subtitle->setElideMode(Qt::ElideMiddle);
    tc->addWidget(m_title);
    tc->addWidget(m_subtitle);
    hh->addLayout(tc, 1);
    auto* close = ui::iconButton(QStringLiteral("close"), QString::fromUtf8("关闭详情 (Esc)"),
                                 theme::textMuted(), 16);
    connect(close, &QToolButton::clicked, this, &Inspector::closeRequested);
    hh->addWidget(close, 0, Qt::AlignTop);
    v->addWidget(head);
    v->addWidget(ui::hDivider());

    // body
    m_scroll = new QScrollArea;
    m_scroll->setWidgetResizable(true);
    m_scroll->setFrameShape(QFrame::NoFrame);
    m_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_scroll->viewport()->setAutoFillBackground(false);
    auto* host = new QWidget;
    host->setObjectName(QStringLiteral("InspectorBody"));
    m_body = new QVBoxLayout(host);
    m_body->setContentsMargins(18, 14, 16, 16);
    m_body->setSpacing(8);
    m_body->setAlignment(Qt::AlignTop); // pack content at the top; never spread it over the panel
    m_scroll->setWidget(host);
    host->setAutoFillBackground(false); // setWidget() turns it on; the card shows through
    v->addWidget(m_scroll, 1);

    // footer
    m_footerRule = ui::hDivider();
    v->addWidget(m_footerRule);
    m_footer = new QWidget;
    auto* fv = new QVBoxLayout(m_footer);
    fv->setContentsMargins(16, 12, 16, 14);
    fv->setSpacing(8);
    m_actions = new QHBoxLayout;
    m_actions->setSpacing(8);
    fv->addLayout(m_actions);
    m_note = ui::label(QString(), "muted");
    m_note->setWordWrap(true);
    m_note->hide();
    fv->addWidget(m_note);
    v->addWidget(m_footer);
    syncFooter();
}

void Inspector::clearLayout(QLayout* layout)
{
    if (!layout)
        return;
    while (QLayoutItem* item = layout->takeAt(0)) {
        if (QWidget* w = item->widget()) {
            w->hide();
            w->deleteLater();
        } else if (QLayout* sub = item->layout()) {
            clearLayout(sub);
        }
        delete item;
    }
}

void Inspector::clear()
{
    clearLayout(m_body);
    clearLayout(m_actions);
    m_note->clear();
    m_note->hide();
    m_sections = 0;
    m_scroll->verticalScrollBar()->setValue(0);
    syncFooter();
}

void Inspector::setHeader(const QString& icon, const QColor& color, const QString& title,
                          const QString& subtitle)
{
    m_tile->set(icon, color);
    m_title->setText(title);
    m_subtitle->setText(subtitle);
    m_subtitle->setVisible(!subtitle.isEmpty());
    setGlow(color, QPointF(0.0, 0.0), 0.55, 0.07);
    setAccessibleDescription(title);
}

QLabel* Inspector::addLead(const QString& text)
{
    auto* l = ui::label(text, "lead");
    l->setWordWrap(true);
    l->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_body->addWidget(l);
    return l;
}

QVBoxLayout* Inspector::addSection(const QString& title, QWidget* trailing)
{
    if (m_body->count() > 0)
        m_body->addSpacing(10);
    auto* head = new QHBoxLayout;
    head->setContentsMargins(0, 0, 0, 0);
    head->addWidget(ui::eyebrow(title), 0, Qt::AlignVCenter);
    head->addStretch();
    if (trailing)
        head->addWidget(trailing, 0, Qt::AlignVCenter);
    m_body->addLayout(head);
    auto* sec = new QVBoxLayout;
    sec->setContentsMargins(0, 2, 0, 0);
    sec->setSpacing(7);
    m_body->addLayout(sec);
    ++m_sections;
    return sec;
}

QWidget* Inspector::makeField(const QString& name, const QString& value, FieldFlags flags, int keyWidth)
{
    auto* row = new QWidget;
    auto* h = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(10);
    auto* k = ui::label(name, "caption");
    k->setFixedWidth(keyWidth);
    k->setWordWrap(true);
    k->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    h->addWidget(k, 0, Qt::AlignTop);

    const bool empty = value.trimmed().isEmpty();
    auto* val = new WrapLabel(empty ? QString::fromUtf8("—") : value);
    if (flags.testFlag(Mono) && !empty)
        val->setProperty("role", "mono");
    else if (flags.testFlag(Muted) || empty)
        val->setProperty("role", "secondary");
    val->setAccessibleName(name);
    val->setAccessibleDescription(value);
    h->addWidget(val, 1);
    if (flags.testFlag(Copy) && !empty)
        h->addWidget(ui::copyButton([value] { return value; }, QString::fromUtf8("复制") + name), 0,
                     Qt::AlignTop);
    return row;
}

QWidget* Inspector::makeChips(const QList<QPair<QString, QColor>>& chips)
{
    auto* w = new QWidget;
    auto* flow = new FlowLayout(w, 6, 6);
    for (const auto& [text, color] : chips)
        flow->addWidget(ui::pill(text, color.isValid() ? color : theme::textSecondary()));
    return w;
}

QWidget* Inspector::addField(QVBoxLayout* section, const QString& name, const QString& value,
                             FieldFlags flags)
{
    QWidget* row = makeField(name, value, flags);
    (section ? section : m_body)->addWidget(row);
    return row;
}

QWidget* Inspector::addChips(QVBoxLayout* section, const QList<QPair<QString, QColor>>& chips)
{
    QWidget* w = makeChips(chips);
    (section ? section : m_body)->addWidget(w);
    return w;
}

QLabel* Inspector::addText(QVBoxLayout* section, const QString& text, const char* role)
{
    auto* l = ui::label(text, role);
    l->setWordWrap(true);
    l->setTextInteractionFlags(Qt::TextSelectableByMouse);
    (section ? section : m_body)->addWidget(l);
    return l;
}

void Inspector::addWidget(QWidget* w)
{
    m_body->addWidget(w);
}

QPushButton* Inspector::addAction(const QString& icon, const QString& text, const char* variant,
                                  std::function<void()> fn)
{
    auto* b = ui::button(text, variant, icon, true);
    connect(b, &QPushButton::clicked, this, [fn = std::move(fn)] {
        if (fn)
            fn();
    });
    m_actions->addWidget(b);
    syncFooter();
    return b;
}

QToolButton* Inspector::addMenu(QMenu* menu)
{
    m_actions->addStretch();
    auto* b = ui::moreButton(menu);
    menu->setParent(b, menu->windowFlags()); // owned by the button, cleared with the footer
    m_actions->addWidget(b);
    syncFooter();
    return b;
}

void Inspector::setNote(const QString& text, const QColor& color)
{
    m_note->setText(text);
    m_note->setStyleSheet(color.isValid() ? QStringLiteral("color:%1;").arg(color.name()) : QString());
    m_note->setVisible(!text.isEmpty());
    syncFooter();
}

void Inspector::syncFooter()
{
    const bool any = m_actions->count() > 0 || !m_note->text().isEmpty();
    m_footer->setVisible(any);
    m_footerRule->setVisible(any);
}
