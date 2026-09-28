#include "dialogs/PromptDialog.h"
#include "dialogs/AttackTimelineWindow.h"
#include "dialogs/EventFormat.h"
#include "design/Components.h"
#include "design/CountdownBar.h"
#include "design/FitScroll.h"
#include "design/FlowLayout.h"
#include "design/Icons.h"
#include "design/Segmented.h"
#include "design/Theme.h"
#include "widgets/WrapLabel.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollBar>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

using evtfmt::u;

namespace {

constexpr int kCardW = 580;              // sheet (card) width
constexpr int kContentW = kCardW - 48;   // minus the card's side padding

// "● reason" row: the dot sits on the first line's centre.
QWidget* reasonRow(const QString& text, const QColor& color)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(10);
    auto* dotBox = new QWidget;
    auto* db = new QVBoxLayout(dotBox);
    db->setContentsMargins(0, 7, 0, 0);
    db->addWidget(ui::statusDot(color));
    h->addWidget(dotBox, 0, Qt::AlignTop);
    auto* l = ui::label(text);
    l->setWordWrap(true);
    l->setTextInteractionFlags(Qt::TextSelectableByMouse);
    h->addWidget(l, 1);
    return w;
}

// Caption + value (+ copy) for the expandable details block.
QWidget* detailRow(const QString& name, const QString& value, bool mono, bool copy)
{
    auto* row = new QWidget;
    auto* h = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(10);
    auto* k = ui::label(name, "caption");
    k->setFixedWidth(64);
    k->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    h->addWidget(k, 0, Qt::AlignTop);
    const bool empty = value.trimmed().isEmpty();
    auto* v = new WrapLabel(empty ? u("—") : value);
    if (mono && !empty)
        v->setProperty("role", "mono");
    else
        v->setProperty("role", "secondary");
    v->setAccessibleName(name);
    h->addWidget(v, 1);
    if (copy && !empty)
        h->addWidget(ui::copyButton([value] { return value; }, u("复制") + name), 0, Qt::AlignTop);
    return row;
}

QWidget* chipCloud(const QList<QPair<QString, QColor>>& chips)
{
    auto* w = new QWidget;
    auto* flow = new FlowLayout(w, 6, 6);
    for (const auto& [text, color] : chips)
        flow->addWidget(ui::pill(text, color));
    return w;
}

} // namespace

PromptDialog::PromptDialog(const bulwark::SecurityEvent& event, QWidget* parent,
                           int timeoutSeconds, bool defaultAllow)
    : Sheet(parent), m_event(event), m_timeoutSeconds(timeoutSeconds), m_defaultAllow(defaultAllow)
{
    const bulwark::SecurityEvent& e = m_event;
    const QColor risk = evtfmt::riskColor(e.riskScore);

    // A security question must not end up behind other windows while its
    // countdown runs (the main window may be hidden in the tray).
    setWindowFlag(Qt::WindowStaysOnTopHint, true);
    setSheetWidth(kCardW);
    setCloseButtonVisible(false); // Esc / Alt+F4 still close — as 拦截, see reject()
    setGlow(risk);
    setEyebrow(u("%1 %2 · 行为防护").arg(evtfmt::riskLevel(e.riskScore)).arg(e.riskScore), risk);
    setTitle(evtfmt::sentence(e, /*present*/ true));
    titleLabel()->setStyleSheet(QStringLiteral("font-size:13pt; font-weight:600; color:%1;")
                                    .arg(theme::textPrimary().name()));
    setWindowTitle(u("行为防护提示"));

    QVBoxLayout* body = this->body();
    body->setSpacing(10);

    // ── who: full image path + signature / reputation facts ─────────────────
    auto* path = new WrapLabel(e.actorPath.isEmpty() ? u("(未取得程序路径)")
                                                     : evtfmt::nativePath(e.actorPath));
    path->setProperty("role", "mono");
    path->setAccessibleName(u("发起程序路径"));
    body->addWidget(path);

    QList<QPair<QString, QColor>> facts;
    if (e.actorSigned && !e.signatureMismatch)
        facts << qMakePair(e.actorPublisher.isEmpty() ? u("已签名") : u("已签名 · ") + e.actorPublisher,
                           theme::success());
    else if (e.signatureMismatch)
        facts << qMakePair(u("签名失配"), theme::danger());
    else
        facts << qMakePair(u("无签名"), theme::warning());
    if (e.certRevoked)
        facts << qMakePair(u("证书已吊销"), theme::danger());
    if (e.signedAfterCertExpiry)
        facts << qMakePair(u("证书过期后签名"), theme::danger());
    if (e.isFirstSeen)
        facts << qMakePair(u("本机首见"), theme::warning());
    if (e.reputation.has_value() && e.reputation->totalEngines > 0)
        facts << qMakePair(QStringLiteral("VT %1/%2").arg(e.reputation->malicious).arg(e.reputation->totalEngines),
                           e.reputation->malicious > 0 ? theme::danger() : theme::success());
    body->addWidget(chipCloud(facts));

    // ── why: evidence (scrolls; capped so the decision stays on screen) ──────
    auto* scroll = new FitScrollArea(Sheet::screenHeightFor(parent, 0.34), kContentW);
    auto* ev = new QWidget;
    auto* evl = new QVBoxLayout(ev);
    evl->setContentsMargins(0, 4, 4, 0);
    evl->setSpacing(8);
    evl->setAlignment(Qt::AlignTop);
    evl->addWidget(ui::eyebrow(u("为什么提示")));
    constexpr int kMaxReasons = 6;
    int shown = 0;
    for (const QString& r : e.riskReasons) {
        if (shown++ >= kMaxReasons)
            break;
        evl->addWidget(reasonRow(r, risk));
    }
    if (e.riskReasons.size() > kMaxReasons)
        evl->addWidget(ui::label(u("… 另有 %1 条,见「查看攻击时间线」")
                                     .arg(e.riskReasons.size() - kMaxReasons), "muted"));
    if (e.riskReasons.isEmpty())
        evl->addWidget(ui::label(u("引擎评分 %1,未列出具体原因。").arg(e.riskScore), "muted"));
    if (!e.techniques.isEmpty()) {
        QList<QPair<QString, QColor>> tags;
        for (const QString& t : e.techniques)
            tags << qMakePair(t, theme::info());
        auto* cloud = chipCloud(tags);
        cloud->setToolTip(u("ATT&CK 技战术:") + e.techniques.join(QStringLiteral(", ")));
        evl->addWidget(cloud);
    }

    // Expandable details: command line · parent · origin · SHA-256.
    auto* toggle = new QToolButton;
    toggle->setCheckable(true);
    toggle->setCursor(Qt::PointingHandCursor);
    toggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    toggle->setIconSize(QSize(14, 14));
    toggle->setIcon(AppIcon::icon(QStringLiteral("chevron-right"), theme::textSecondary(), 14));
    toggle->setText(u("展开详情:命令行 · 父进程 · 启动来源 · SHA-256"));
    toggle->setAccessibleName(u("展开详情"));
    evl->addWidget(toggle, 0, Qt::AlignLeft);

    auto* details = ui::cardAlt();
    auto* dl = new QVBoxLayout(details);
    dl->setContentsMargins(14, 12, 14, 12);
    dl->setSpacing(8);
    dl->addWidget(detailRow(u("命令行"), e.commandLine, true, true));
    const QString parentText =
        e.parentPath.isEmpty()
            ? (e.parentPid > 0 ? QStringLiteral("PID %1").arg(e.parentPid) : QString())
            : evtfmt::nativePath(e.parentPath)
                  + (e.parentPid > 0 ? QStringLiteral("  (PID %1)").arg(e.parentPid) : QString());
    dl->addWidget(detailRow(u("父进程"), parentText, true, true));
    const QString origin = e.originLabel();
    dl->addWidget(detailRow(u("启动来源"), origin.isEmpty() ? u("未能判定") : origin, false, false));
    dl->addWidget(detailRow(QStringLiteral("SHA-256"), e.actorHash, true, true));
    if (e.actorPid > 0)
        dl->addWidget(detailRow(QStringLiteral("PID"), QString::number(e.actorPid), true, false));
    details->hide();
    evl->addWidget(details);

    connect(toggle, &QToolButton::toggled, this, [this, toggle, details, scroll](bool on) {
        details->setVisible(on);
        toggle->setIcon(AppIcon::icon(on ? QStringLiteral("chevron-down") : QStringLiteral("chevron-right"),
                                      theme::textSecondary(), 14));
        toggle->setText(on ? u("收起详情") : u("展开详情:命令行 · 父进程 · 启动来源 · SHA-256"));
        refit();
        // The evidence area is capped, so the details usually open below the
        // fold: bring them up (runs after refit's own deferred resize).
        if (on)
            QTimer::singleShot(0, scroll, [scroll, toggle] {
                scroll->verticalScrollBar()->setValue(toggle->y() - 2);
            });
    });

    scroll->setContent(ev);
    body->addWidget(scroll, 1);
    body->addWidget(ui::hDivider());

    // ── the decision ──────────────────────────────────────────────────────────
    auto* rememberRow = new QHBoxLayout;
    rememberRow->setSpacing(12);
    rememberRow->addWidget(ui::label(u("记住选择"), "caption"), 0, Qt::AlignVCenter);
    m_scope = new Segmented;
    m_scope->setAccessibleName(u("记住选择的范围"));
    for (const char* s : {"仅本次", "本次会话", "1 小时", "1 天", "永久"})
        m_scope->addSegment(u(s));
    m_scope->setToolTip(u("选「仅本次」之外的范围,会把这次裁决保存为规则"));
    rememberRow->addWidget(m_scope, 0, Qt::AlignVCenter);
    rememberRow->addStretch();
    body->addLayout(rememberRow);

    if (m_timeoutSeconds > 0) {
        m_countdown = new CountdownBar;
        m_countdown->setColor(m_defaultAllow ? theme::success() : theme::danger());
        const bool allowByDefault = m_defaultAllow;
        m_countdown->setFormatter([allowByDefault](int s) {
            return allowByDefault ? u("%1 秒后自动放行").arg(s) : u("%1 秒后自动拦截").arg(s);
        });
        body->addWidget(m_countdown);
    }

    // ── footer: timeline link · 拦截 · 放行 ───────────────────────────────────
    auto* timeline = ui::button(u("查看攻击时间线"), "ghost", QStringLiteral("clock"), true);
    timeline->setAutoDefault(false);
    connect(timeline, &QPushButton::clicked, this, [this] {
        AttackTimelineWindow dlg(m_event, this);
        dlg.exec();
    });
    addFooterLeft(timeline);

    m_blockBtn = addButton(u("拦截"), "ghost", [this] { decide(false); });
    m_allowBtn = addButton(u("放行"), "ghost", [this] { decide(true); });
    m_blockBtn->setMinimumWidth(112);
    m_allowBtn->setMinimumWidth(112);

    // 视觉重点必须落在【真正会发生的那个动作】上:有倒计时时强调项 = 超时后的默认动作,
    // 与倒计时条的说明文字、回车键三者一致;没有倒计时(timeoutSeconds<=0)时不会自动裁决,
    // 关窗 / Esc 走的是"拦截"这条保守路径,所以强调项是拦截。
    QPushButton* primaryBtn = (m_timeoutSeconds > 0 && m_defaultAllow) ? m_allowBtn : m_blockBtn;
    QPushButton* secondaryBtn = primaryBtn == m_allowBtn ? m_blockBtn : m_allowBtn;
    ui::setVariant(primaryBtn, "primary");
    ui::setVariant(secondaryBtn, "ghost");
    primaryBtn->setDefault(true);
    primaryBtn->setAutoDefault(true);
    secondaryBtn->setAutoDefault(false);
    primaryBtn->setFocus();

    m_allowBtn->setAccessibleName(u("放行"));
    m_allowBtn->setAccessibleDescription(u("允许本次行为继续执行"));
    m_blockBtn->setAccessibleName(u("拦截"));
    m_blockBtn->setAccessibleDescription(u("阻止本次行为"));

    // Auto-decision: on timeout, close any window opened from here (the attack
    // timeline) first — otherwise the verdict would wait for it — then apply the
    // default policy. This is what makes the prompt honour PromptTimeoutSeconds.
    if (m_countdown) {
        connect(m_countdown, &CountdownBar::finished, this, [this] {
            for (QDialog* d : findChildren<QDialog*>())
                if (d->isVisible())
                    d->reject();
            decide(m_defaultAllow);
        });
        m_countdown->start(m_timeoutSeconds * 1000);
    }
}

void PromptDialog::decide(bool allow)
{
    if (m_countdown)
        m_countdown->stop();
    m_allowed = allow;
    accept();
}

bool PromptDialog::remember() const { return m_scope && m_scope->currentIndex() > 0; }

int PromptDialog::scopeIndex() const
{
    // Segments: 0 仅本次 · 1 本次会话 · 2 1 小时 · 3 1 天 · 4 永久
    // RememberScope: 0 Permanent · 1 Session · 2 OneHour · 3 OneDay
    switch (m_scope ? m_scope->currentIndex() : 0) {
    case 1: return 1;
    case 2: return 2;
    case 3: return 3;
    default: return 0;
    }
}
