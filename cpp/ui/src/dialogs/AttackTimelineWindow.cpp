#include "dialogs/AttackTimelineWindow.h"
#include "dialogs/EventFormat.h"
#include "dialogs/EventViews.h"
#include "design/Backdrop.h"
#include "design/Components.h"
#include "design/Format.h"
#include "design/IconTile.h"
#include "design/Inspector.h"
#include "design/Theme.h"

#include <QBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QResizeEvent>
#include <QScrollArea>
#include <QVBoxLayout>

using evtfmt::u;

namespace {

constexpr int kStackBelow = 900; // narrower than this, the two columns stack

// A titled card in a column; returns the layout to fill.
QVBoxLayout* cardSection(QVBoxLayout* column, const QString& title)
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(18, 15, 18, 16);
    v->setSpacing(9);
    v->addWidget(ui::eyebrow(title));
    column->addWidget(c);
    return v;
}

} // namespace

AttackTimelineWindow::AttackTimelineWindow(const bulwark::SecurityEvent& e, QWidget* parent, IpcClient* ipc,
                                           std::optional<evtview::Outcome> outcome)
    : QDialog(parent)
{
    const QString name = evtfmt::actorName(e.actorPath);
    setWindowTitle(u("攻击时间线 · %1").arg(name));
    setAccessibleName(windowTitle());
    Backdrop::install(this); // same work-area material as the main window
    resize(1080, 740);
    setMinimumSize(700, 480);
    setSizeGripEnabled(true);

    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(24, 20, 24, 18);
    outer->setSpacing(14);

    // ---- header: who · what · when, and the two verdict facts --------------------
    const QColor tone = e.riskScore >= 50 ? evtfmt::riskColor(e.riskScore) : theme::info();
    auto* head = new QHBoxLayout;
    head->setSpacing(14);
    head->addWidget(new IconTile(evtfmt::typeGlyph(e.type), tone, 46, 23), 0, Qt::AlignTop);
    auto* hc = new QVBoxLayout;
    hc->setSpacing(3);
    auto* title = ui::label(name, "h1");
    title->setTextInteractionFlags(Qt::TextSelectableByMouse);
    hc->addWidget(title);
    hc->addWidget(ui::label(QStringLiteral("%1  ·  PID %2  ·  %3")
                                .arg(evtfmt::typeLabel(e.type))
                                .arg(e.actorPid)
                                .arg(fmt::absoluteTime(e.timestampUtc)),
                            "secondary"));
    head->addLayout(hc, 1);
    QList<QPair<QString, QColor>> top;
    if (outcome) {
        const evtfmt::Badge d = evtfmt::disposition(outcome->action, outcome->enforcement);
        top << qMakePair(d.text, d.color);
    }
    if (e.riskScore > 0)
        top << qMakePair(QStringLiteral("%1 %2").arg(evtfmt::riskLevel(e.riskScore)).arg(e.riskScore),
                         evtfmt::riskColor(e.riskScore));
    for (const auto& [text, color] : top)
        head->addWidget(ui::pill(text, color), 0, Qt::AlignTop);
    outer->addLayout(head);

    auto* lead = ui::label(evtfmt::sentence(e, !outcome.has_value()), "lead");
    lead->setWordWrap(true);
    lead->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outer->addWidget(lead);
    if (const auto facts = evtview::factChips(e); !facts.isEmpty())
        outer->addWidget(Inspector::makeChips(facts));

    // ---- two columns: the story | the facts ---------------------------------------
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->viewport()->setAutoFillBackground(false);
    auto* content = new QWidget;
    m_columns = new QBoxLayout(QBoxLayout::LeftToRight, content);
    m_columns->setContentsMargins(0, 0, 4, 0);
    m_columns->setSpacing(16);
    auto* left = new QVBoxLayout;
    left->setSpacing(14);
    auto* right = new QVBoxLayout;
    right->setSpacing(14);
    m_columns->addLayout(left, 3);
    m_columns->addLayout(right, 2);

    QVBoxLayout* s = cardSection(left, u("判定依据 · 证据链"));
    s->addWidget(evtview::evidenceList(e));
    if (!e.techniques.isEmpty()) {
        QList<QPair<QString, QColor>> tech;
        for (const QString& t : e.techniques)
            tech << qMakePair(t, theme::info());
        s->addSpacing(4);
        s->addWidget(ui::label(u("命中 ATT&CK 技战术"), "caption"));
        s->addWidget(Inspector::makeChips(tech));
    }
    s = cardSection(left, u("进程溯源"));
    s->addWidget(evtview::processChain(e));
    left->addStretch(1);

    s = cardSection(right, u("处置"));
    auto* disp = ui::label(outcome ? evtfmt::dispositionDetail(outcome->action, outcome->enforcement)
                                   : u("这条行为正在等待你的裁决。"),
                           "secondary");
    disp->setWordWrap(true);
    s->addWidget(disp);
    if (!e.matchedRuleNote.trimmed().isEmpty())
        s->addWidget(Inspector::makeField(u("命中规则"), e.matchedRuleNote));
    s = cardSection(right, u("取证"));
    evtview::addForensicFields(s, e);
    right->addStretch(1);

    scroll->setWidget(content);
    content->setAutoFillBackground(false); // setWidget() turns it on; the window shows through
    outer->addWidget(scroll, 1);

    // ---- footer ----------------------------------------------------------------------
    auto* bar = new QHBoxLayout;
    bar->setSpacing(10);
    bar->addStretch(1);
    if (ipc) {
        auto* graph = ui::button(u("查看攻击关系图"), "ghost", QStringLiteral("link"));
        const QUuid seed = e.id;
        const int pid = e.actorPid;
        connect(graph, &QPushButton::clicked, this,
                [this, ipc, seed, pid, name] { evtview::openGraph(this, ipc, seed, pid, name); });
        bar->addWidget(graph);
    }
    auto* close = ui::button(u("关闭"), "primary");
    close->setMinimumWidth(96);
    close->setDefault(true);
    connect(close, &QPushButton::clicked, this, &QDialog::accept);
    bar->addWidget(close);
    outer->addLayout(bar);
}

void AttackTimelineWindow::resizeEvent(QResizeEvent* e)
{
    QDialog::resizeEvent(e);
    if (m_columns)
        m_columns->setDirection(width() < kStackBelow ? QBoxLayout::TopToBottom : QBoxLayout::LeftToRight);
}
