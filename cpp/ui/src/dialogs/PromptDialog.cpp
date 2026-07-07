#include "dialogs/PromptDialog.h"
#include "dialogs/AttackTimelineWindow.h"
#include "dialogs/EventFormat.h"
#include "widgets/AppIcon.h"
#include "widgets/Cards.h"
#include "widgets/Ui.h"
#include "Theme.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFileInfo>
#include <QGraphicsDropShadowEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

using evtfmt::u;

namespace {

QWidget* field(const QString& caption, QWidget* value)
{
    auto* w = new QWidget;
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(3);
    v->addWidget(ui::label(caption, "caption"));
    v->addWidget(value);
    return w;
}

QWidget* metaChip(const QString& text, const QColor& color)
{
    return ui::pill(text, color);
}

} // namespace

PromptDialog::PromptDialog(const bulwark::SecurityEvent& event, QWidget* parent,
                           int timeoutSeconds, bool defaultAllow)
    : QDialog(parent), m_event(event),
      m_timeoutSeconds(timeoutSeconds), m_defaultAllow(defaultAllow)
{
    const bulwark::SecurityEvent& e = m_event;
    const QColor risk = evtfmt::riskColor(e.riskScore);

    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setModal(true);
    setFixedWidth(560);

    auto* shell = new QVBoxLayout(this);
    shell->setContentsMargins(24, 24, 24, 24);

    auto* cardW = ui::card();
    auto* shadow = new QGraphicsDropShadowEffect(cardW);
    shadow->setBlurRadius(54);
    shadow->setOffset(0, 14);
    shadow->setColor(QColor(15, 23, 42, 110));
    cardW->setGraphicsEffect(shadow);
    shell->addWidget(cardW);

    auto* v = new QVBoxLayout(cardW);
    v->setContentsMargins(24, 22, 24, 22);
    v->setSpacing(14);

    // Header.
    auto* head = new QHBoxLayout;
    head->setSpacing(14);
    head->addWidget(ui::iconBadge("shield-x", risk, 46, 24));
    auto* hcol = new QVBoxLayout;
    hcol->setSpacing(2);
    hcol->addWidget(ui::coloredText(u("行为防护提示"), 15, 700, theme::textPrimary()));
    hcol->addWidget(ui::label(u("检测到需要裁决的敏感行为"), "secondary"));
    head->addLayout(hcol);
    head->addStretch();
    head->addWidget(ui::pill(QStringLiteral("%1  ·  %2").arg(evtfmt::riskLevel(e.riskScore)).arg(e.riskScore),
                             risk), 0, Qt::AlignTop);
    v->addLayout(head);
    v->addWidget(ui::hDivider());

    // Actor + signature / first-seen chips.
    QString actorName = QFileInfo(e.actorPath).fileName();
    if (actorName.isEmpty()) actorName = u("未知程序");
    auto* actorCol = new QVBoxLayout;
    actorCol->setSpacing(3);
    actorCol->addWidget(ui::coloredText(actorName, 12, 700, theme::textPrimary()));
    auto* path = ui::label(e.actorPath, "mono");
    path->setProperty("role", "muted");
    actorCol->addWidget(path);
    auto* chips = new QHBoxLayout;
    chips->setSpacing(6);
    if (e.actorSigned)
        chips->addWidget(metaChip(e.actorPublisher.isEmpty() ? u("已签名") : u("已签名 · ") + e.actorPublisher,
                                  theme::success()));
    else
        chips->addWidget(metaChip(e.signatureMismatch ? u("签名失配") : u("无签名"), theme::danger()));
    if (e.isFirstSeen) chips->addWidget(metaChip(u("本机首见"), theme::warning()));
    if (e.reputation.has_value() && e.reputation->malicious > 0)
        chips->addWidget(metaChip(QStringLiteral("VT %1/%2").arg(e.reputation->malicious).arg(e.reputation->totalEngines),
                                  theme::danger()));
    chips->addStretch();
    actorCol->addLayout(chips);
    auto* actorW = new QWidget; actorW->setLayout(actorCol);
    v->addWidget(field(u("发起程序"), actorW));

    // Behavior + target.
    auto* beh = ui::label(e.target.isEmpty() ? evtfmt::verb(e.type)
                                             : QStringLiteral("%1  ·  %2").arg(evtfmt::verb(e.type), e.target),
                          "title");
    beh->setWordWrap(true);
    v->addWidget(field(u("行为"), beh));

    if (!e.commandLine.isEmpty()) {
        auto* cl = ui::label(e.commandLine, "mono");
        cl->setProperty("role", "muted");
        cl->setWordWrap(true);
        v->addWidget(field(u("命令行"), cl));
    }

    // Risk factors (prefer scored evidence-chain highlights, capped).
    QStringList reasons = e.riskReasons;
    if (!reasons.isEmpty()) {
        auto* rc = new QVBoxLayout;
        rc->setSpacing(4);
        int shown = 0;
        for (const QString& r : reasons) {
            if (shown++ >= 5) break;
            auto* row = new QHBoxLayout;
            row->setSpacing(8);
            row->addWidget(ui::statusDot(risk), 0, Qt::AlignVCenter);
            auto* rl = ui::label(r, "secondary");
            rl->setWordWrap(true);
            row->addWidget(rl, 1);
            rc->addLayout(row);
        }
        if (reasons.size() > 5)
            rc->addWidget(ui::label(QStringLiteral("… 另有 %1 条").arg(reasons.size() - 5), "muted"));
        auto* rw = new QWidget; rw->setLayout(rc);
        v->addWidget(field(u("风险因素"), rw));
    }

    if (!e.techniques.isEmpty()) {
        auto* tw = new QWidget;
        auto* th = new QHBoxLayout(tw);
        th->setContentsMargins(0, 0, 0, 0);
        th->setSpacing(8);
        for (const QString& t : e.techniques)
            th->addWidget(ui::pill(t, theme::info()));
        th->addStretch();
        v->addWidget(field(u("ATT&CK 技战术"), tw));
    }

    // "View full attack timeline" link.
    {
        auto* more = new QPushButton(u("查看攻击时间线 →"));
        more->setProperty("variant", "ghost");
        more->setProperty("size", "sm");
        more->setCursor(Qt::PointingHandCursor);
        connect(more, &QPushButton::clicked, this, [this] {
            AttackTimelineWindow dlg(m_event, this);
            dlg.exec();
        });
        auto* mrow = new QHBoxLayout;
        mrow->addWidget(more);
        mrow->addStretch();
        v->addLayout(mrow);
    }

    v->addWidget(ui::hDivider());

    auto* rememberRow = new QHBoxLayout;
    rememberRow->setSpacing(10);
    m_remember = new QCheckBox(u("记住我的选择"));
    rememberRow->addWidget(m_remember);
    m_scope = new QComboBox;
    m_scope->addItems({u("永久"), u("本次会话"), u("1 小时"), u("1 天")});
    m_scope->setFixedWidth(120);
    rememberRow->addWidget(m_scope);
    rememberRow->addStretch();
    v->addLayout(rememberRow);

    auto* btns = new QHBoxLayout;
    btns->setSpacing(10);
    btns->addStretch();
    m_allowBtn = new QPushButton(u("放行"));
    m_allowBtn->setProperty("variant", "ghost");
    m_allowBtn->setCursor(Qt::PointingHandCursor);
    m_allowBtn->setMinimumWidth(120);
    m_blockBtn = new QPushButton(u("拦截"));
    m_blockBtn->setProperty("variant", "primary");
    m_blockBtn->setCursor(Qt::PointingHandCursor);
    m_blockBtn->setMinimumWidth(120);
    btns->addWidget(m_allowBtn);
    btns->addWidget(m_blockBtn);
    v->addLayout(btns);

    connect(m_allowBtn, &QPushButton::clicked, this, [this] {
        if (m_countdown) m_countdown->stop();
        m_allowed = true;
        accept();
    });
    connect(m_blockBtn, &QPushButton::clicked, this, [this] {
        if (m_countdown) m_countdown->stop();
        m_allowed = false;
        accept();
    });

    // Auto-decision countdown: on timeout, apply the default policy and close —
    // this is what makes the prompt honour PromptTimeoutSeconds instead of
    // waiting forever. The default-action button shows the remaining seconds so
    // the user can see what will happen and when.
    if (m_timeoutSeconds > 0) {
        m_remaining = m_timeoutSeconds;
        m_countdown = new QTimer(this);
        m_countdown->setInterval(1000);
        connect(m_countdown, &QTimer::timeout, this, [this] {
            if (--m_remaining <= 0) {
                m_countdown->stop();
                m_allowed = m_defaultAllow;
                accept();
            } else {
                updateCountdown();
            }
        });
        updateCountdown();
        m_countdown->start();
    }
}

void PromptDialog::updateCountdown()
{
    QPushButton* def = m_defaultAllow ? m_allowBtn : m_blockBtn;
    if (!def)
        return;
    def->setText(QStringLiteral("%1 (%2s)").arg(m_defaultAllow ? u("放行") : u("拦截")).arg(m_remaining));
}

bool PromptDialog::remember() const { return m_remember && m_remember->isChecked(); }
int PromptDialog::scopeIndex() const { return m_scope ? m_scope->currentIndex() : 0; }

void PromptDialog::mousePressEvent(QMouseEvent* e)
{
    if (e->button() == Qt::LeftButton)
        m_dragOffset = e->globalPosition().toPoint() - frameGeometry().topLeft();
    QDialog::mousePressEvent(e);
}

void PromptDialog::mouseMoveEvent(QMouseEvent* e)
{
    if (e->buttons() & Qt::LeftButton)
        move(e->globalPosition().toPoint() - m_dragOffset);
    QDialog::mouseMoveEvent(e);
}
