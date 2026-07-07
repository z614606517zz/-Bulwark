#include "dialogs/AttackTimelineWindow.h"
#include "dialogs/EventFormat.h"
#include "widgets/AppIcon.h"
#include "widgets/Cards.h"
#include "widgets/Ui.h"
#include "Theme.h"

#include <QDialogButtonBox>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

using evtfmt::u;

namespace {

// A titled card returning its inner content layout.
QVBoxLayout* sectionCard(QVBoxLayout* parent, const QString& title)
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(18, 15, 18, 15);
    v->setSpacing(9);
    v->addWidget(ui::label(title, "h2"));
    v->addWidget(ui::hDivider());
    parent->addWidget(c);
    return v;
}

QWidget* detailRow(const QString& caption, const QString& value, bool mono = false)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 2, 0, 2);
    h->setSpacing(12);
    auto* cap = ui::label(caption, "caption");
    cap->setFixedWidth(96);
    h->addWidget(cap, 0, Qt::AlignTop);
    auto* val = ui::label(value.isEmpty() ? u("—") : value, mono ? "mono" : "secondary");
    val->setWordWrap(true);
    val->setTextInteractionFlags(Qt::TextSelectableByMouse);
    h->addWidget(val, 1);
    return w;
}

} // namespace

AttackTimelineWindow::AttackTimelineWindow(const bulwark::SecurityEvent& e, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(u("攻击时间线"));
    setModal(true);
    resize(680, 720);

    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);

    // Header banner.
    auto* head = new QFrame;
    head->setObjectName(QStringLiteral("Topbar"));
    auto* hh = new QHBoxLayout(head);
    hh->setContentsMargins(20, 16, 20, 16);
    hh->setSpacing(14);
    hh->addWidget(ui::iconBadge("activity", evtfmt::riskColor(e.riskScore), 46, 24));
    auto* hcol = new QVBoxLayout;
    hcol->setSpacing(2);
    const QString name = QFileInfo(e.actorPath).fileName();
    hcol->addWidget(ui::coloredText(name.isEmpty() ? u("未知程序") : name, 15, 700, theme::textPrimary()));
    hcol->addWidget(ui::label(evtfmt::verb(e.type) + u("  ·  ")
                              + e.timestampUtc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")),
                              "secondary"));
    hh->addLayout(hcol);
    hh->addStretch();
    hh->addWidget(ui::pill(evtfmt::riskLevel(e.riskScore) + QStringLiteral("  ·  %1").arg(e.riskScore),
                           evtfmt::riskColor(e.riskScore)), 0, Qt::AlignTop);
    outer->addWidget(head);

    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    outer->addWidget(scroll, 1);
    auto* content = new QWidget;
    scroll->setWidget(content);
    auto* v = new QVBoxLayout(content);
    v->setContentsMargins(20, 18, 20, 18);
    v->setSpacing(14);

    // ---- 进程溯源链 ----
    {
        auto* box = sectionCard(v, u("进程溯源链"));
        if (e.chainContext.isEmpty()) {
            // 无链上下文:用父进程 -> 主体两步兜底展示。
            if (!e.parentPath.isEmpty())
                box->addWidget(detailRow(u("父进程"),
                                         QStringLiteral("%1 (PID %2)").arg(e.parentPath).arg(e.parentPid), true));
            box->addWidget(detailRow(u("主体"),
                                     QStringLiteral("%1 (PID %2)").arg(e.actorPath).arg(e.actorPid), true));
        } else {
            int step = 1;
            for (const bulwark::ChainEventInfo& c : e.chainContext) {
                auto* row = new QHBoxLayout;
                row->setSpacing(10);
                row->addWidget(ui::pill(QString::number(step++), theme::info()), 0, Qt::AlignTop);
                auto* col = new QVBoxLayout;
                col->setSpacing(1);
                col->addWidget(ui::label(QStringLiteral("%1  ·  %2 (PID %3)")
                                             .arg(evtfmt::typeLabel(c.type),
                                                  QFileInfo(c.actorPath).fileName().isEmpty()
                                                      ? c.actorPath : QFileInfo(c.actorPath).fileName())
                                             .arg(c.actorPid), "title"));
                if (!c.target.isEmpty())
                    col->addWidget(ui::label(u("→ ") + c.target, "muted"));
                auto* rw = new QWidget; rw->setLayout(col);
                row->addWidget(rw, 1);
                box->addLayout(row);
            }
        }
    }

    // ---- 证据链时间线 ----
    if (!e.evidenceChain.isEmpty()) {
        auto* box = sectionCard(v, u("判定依据 · 证据链时间线"));
        for (const bulwark::Evidence& ev : e.evidenceChain) {
            auto* row = new QHBoxLayout;
            row->setSpacing(10);
            row->addWidget(ui::pill(evtfmt::evidenceKindLabel(ev.kind), evtfmt::evidenceKindColor(ev.kind)),
                           0, Qt::AlignTop);
            auto* col = new QVBoxLayout;
            col->setSpacing(1);
            auto* desc = ui::label(ev.description, "secondary");
            desc->setWordWrap(true);
            col->addWidget(desc);
            QStringList meta;
            if (!ev.source.isEmpty()) meta << ev.source;
            if (ev.scoreDelta != 0) meta << QStringLiteral("%1%2").arg(ev.scoreDelta > 0 ? u("+") : QString()).arg(ev.scoreDelta);
            if (!ev.technique.isEmpty())
                meta << (ev.techniqueName.isEmpty() ? ev.technique : QStringLiteral("%1 %2").arg(ev.technique, ev.techniqueName));
            if (!meta.isEmpty())
                col->addWidget(ui::label(meta.join(QStringLiteral("  ·  ")), "muted"));
            auto* rw = new QWidget; rw->setLayout(col);
            row->addWidget(rw, 1);
            box->addLayout(row);
        }
    } else if (!e.riskReasons.isEmpty()) {
        auto* box = sectionCard(v, u("风险因素"));
        for (const QString& r : e.riskReasons) {
            auto* rl = ui::label(QStringLiteral("· ") + r, "secondary");
            rl->setWordWrap(true);
            box->addWidget(rl);
        }
    }

    // ---- 命中规则(这条裁决是哪条规则做出的;此前只在弹窗一闪而过,详情里看不到)----
    if (!e.matchedRuleNote.trimmed().isEmpty()) {
        auto* box = sectionCard(v, u("命中规则"));
        auto* rl = ui::label(QStringLiteral("· ") + e.matchedRuleNote, "secondary");
        rl->setWordWrap(true);
        box->addWidget(rl);
    }

    // ---- 命中技战术 ----
    if (!e.techniques.isEmpty()) {
        auto* box = sectionCard(v, u("命中 ATT&CK 技战术"));
        auto* flow = new QHBoxLayout;
        flow->setSpacing(8);
        for (const QString& t : e.techniques)
            flow->addWidget(ui::pill(t, theme::info()));
        flow->addStretch();
        box->addLayout(flow);
    }

    // ---- 详情 ----
    {
        auto* box = sectionCard(v, u("取证详情"));
        box->addWidget(detailRow(u("主体路径"), e.actorPath, true));
        box->addWidget(detailRow(u("数字签名"),
                                 e.actorSigned ? (e.actorPublisher.isEmpty() ? u("有效") : u("有效 · ") + e.actorPublisher)
                                               : (e.signatureMismatch ? u("签名失配(内嵌但校验失败)") : u("无 / 无效"))));
        if (!e.commandLine.isEmpty()) box->addWidget(detailRow(u("命令行"), e.commandLine, true));
        if (!e.target.isEmpty())      box->addWidget(detailRow(u("操作目标"), e.target, true));
        if (!e.actorHash.isEmpty())   box->addWidget(detailRow(u("SHA-256"), e.actorHash, true));
        if (e.originatorPid > 0)
            box->addWidget(detailRow(u("真凶溯源"),
                                     QStringLiteral("%1 (PID %2)").arg(e.originatorPath).arg(e.originatorPid), true));
        if (!e.detail.isEmpty())      box->addWidget(detailRow(u("说明"), e.detail));
    }

    v->addStretch();

    auto* bar = new QHBoxLayout;
    bar->setContentsMargins(20, 0, 20, 16);
    bar->addStretch();
    auto* close = new QPushButton(u("关闭"));
    close->setProperty("variant", "primary");
    close->setCursor(Qt::PointingHandCursor);
    connect(close, &QPushButton::clicked, this, &QDialog::accept);
    bar->addWidget(close);
    outer->addLayout(bar);
}
