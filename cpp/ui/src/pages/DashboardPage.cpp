#include "pages/DashboardPage.h"
#include "ipc/IpcClient.h"
#include "widgets/AppIcon.h"
#include "widgets/Cards.h"
#include "widgets/Ui.h"
#include "Theme.h"

#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/models/SecurityEvent.h"

#include <QDateTime>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QScrollArea>
#include <QVBoxLayout>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

QString eventTypeLabel(bulwark::EventType t)
{
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return u("进程创建");
    case E::ProcessTerminate: return u("结束进程");
    case E::RemoteThread:     return u("远程线程注入");
    case E::ImageLoad:        return u("映像加载");
    case E::FileWrite:        return u("文件写入");
    case E::FileDelete:       return u("文件删除");
    case E::RegistryWrite:    return u("注册表写入");
    case E::NetworkConnect:   return u("网络外联");
    case E::SelfProtect:      return u("自我保护");
    case E::DnsQuery:         return u("DNS 解析");
    }
    return u("事件");
}

// A stat card whose big value label is handed back for live updates.
QFrame* makeStat(const QString& icon, const QColor& color, const QString& name, QLabel*& valueOut)
{
    auto* c = ui::card();
    c->setMinimumHeight(112);
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(18, 16, 18, 16);
    v->setSpacing(10);
    auto* top = new QHBoxLayout;
    top->setContentsMargins(0, 0, 0, 0);
    top->addWidget(ui::iconBadge(icon, color, 38, 20));
    top->addStretch();
    v->addLayout(top);
    valueOut = ui::coloredText(QStringLiteral("0"), 24, 800, theme::textPrimary());
    v->addWidget(valueOut);
    v->addWidget(ui::label(name, "secondary"));
    return c;
}

// A protection-dimension row with a trailing status dot + on/off text.
QWidget* dimensionRow(const QString& icon, const QString& name, bool on)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 5, 0, 5);
    h->setSpacing(12);
    auto* ic = new AppIcon(icon);
    ic->setColor(theme::textSecondary());
    ic->setPx(18);
    ic->setFixedSize(20, 20);
    h->addWidget(ic);
    h->addWidget(ui::label(name, "title"));
    h->addStretch();
    h->addWidget(ui::statusDot(on ? theme::success() : theme::textMuted()));
    h->addWidget(ui::coloredText(on ? u("开启") : u("关闭"), 9, 600,
                                 on ? theme::success() : theme::textMuted()));
    return w;
}

// Set a dimension row's trailing dot + text from a bool (widgets at fixed tail positions).
void setDimension(QWidget* row, bool on)
{
    if (!row) return;
    auto* h = qobject_cast<QHBoxLayout*>(row->layout());
    if (!h || h->count() < 2) return;
    auto* dot = qobject_cast<QLabel*>(h->itemAt(h->count() - 2)->widget());
    auto* txt = qobject_cast<QLabel*>(h->itemAt(h->count() - 1)->widget());
    if (dot)
        dot->setStyleSheet(QStringLiteral("background:%1; border-radius:4px;")
                               .arg((on ? theme::success() : theme::textMuted()).name()));
    if (txt) {
        txt->setText(on ? u("开启") : u("关闭"));
        txt->setStyleSheet(QStringLiteral("font-size:9pt; font-weight:600; color:%1;")
                               .arg((on ? theme::success() : theme::textMuted()).name()));
    }
}

QWidget* activityRow(const QString& icon, const QColor& color, const QString& title,
                     const QString& meta, const QString& risk, const QColor& riskColor)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 6, 0, 6);
    h->setSpacing(12);
    h->addWidget(ui::iconBadge(icon, color, 34, 18));
    auto* col = new QVBoxLayout;
    col->setSpacing(1);
    col->addWidget(ui::elided(title, "title"));
    col->addWidget(ui::elided(meta, "muted"));
    h->addLayout(col, 1);
    h->addWidget(ui::pill(risk, riskColor));
    return w;
}

} // namespace

DashboardPage::DashboardPage(IpcClient* ipc, QWidget* parent) : QWidget(parent), m_ipc(ipc)
{
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    outer->addWidget(scroll);
    auto* content = new QWidget;
    scroll->setWidget(content);
    auto* v = new QVBoxLayout(content);
    v->setContentsMargins(theme::metric::pagePad, 22, theme::metric::pagePad, theme::metric::pagePad);
    v->setSpacing(18);

    v->addWidget(buildHero());
    v->addWidget(buildStats());
    auto* row = new QHBoxLayout;
    row->setSpacing(18);
    row->addWidget(buildActivity(), 2);
    row->addWidget(buildDimensions(), 1);
    v->addLayout(row);
    v->addStretch();

    // ---- live wiring ----
    connect(ipc, &IpcClient::eventLogReceived, this,
            [this](const bulwark::ipc::EventLogPayload& p) {
        m_statEvents->setText(QString::number(++m_eventCount));
        // 「本次拦截」只统计【真实拦截】(内核前拦 / 已结束进程 / 已禁止加载);仅告警、拦截失败
        // 不计入,避免拦截数虚高造成"看起来拦了很多、其实没拦"的假象。
        using EO = bulwark::EnforcementOutcome;
        const bool realBlock = p.action == bulwark::VerdictAction::Block
            && (p.enforcement == EO::KernelBlocked || p.enforcement == EO::Terminated
                || p.enforcement == EO::ModuleBlacklisted || p.enforcement == EO::NotApplicable);
        if (realBlock)
            m_statBlocked->setText(QString::number(++m_blockedCount));
        // Prepend a compact activity row (cap at 6). 处置按【真实执行结果】显示,杜绝假拦截。
        const bulwark::SecurityEvent& e = p.event;
        QString risk; QColor rc;
        if (p.action != bulwark::VerdictAction::Block) {
            if (p.action == bulwark::VerdictAction::Ask) { risk = u("已询问"); rc = theme::warning(); }
            else                                         { risk = u("已放行"); rc = theme::success(); }
        } else {
            switch (p.enforcement) {
            case EO::KernelBlocked:     risk = u("已拦截");        rc = theme::danger();  break;
            case EO::Terminated:        risk = u("已结束进程");    rc = theme::danger();  break;
            case EO::ModuleBlacklisted: risk = u("已禁止加载");    rc = theme::danger();  break;
            case EO::AlertedOnly:       risk = u("仅告警·未拦截"); rc = theme::warning(); break;
            case EO::Failed:            risk = u("拦截失败");      rc = theme::warning(); break;
            default:                    risk = u("已拦截");        rc = theme::danger();  break;
            }
        }
        const QString name = QFileInfo(e.actorPath).fileName();
        auto* r = activityRow("activity", rc, eventTypeLabel(e.type) + u(" · ") + name,
                              (e.target.isEmpty() ? name : e.target) + u("  ·  ")
                                  + QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")),
                              risk, rc);
        m_activityBox->insertWidget(0, r);
        if (++m_activityRows > 6) {
            if (auto* item = m_activityBox->takeAt(m_activityBox->count() - 2)) {
                if (item->widget()) item->widget()->deleteLater();
                delete item;
            }
            --m_activityRows;
        }
    });
    connect(ipc, &IpcClient::rulesReceived, this,
            [this](const QList<bulwark::DefenseRule>& rules) {
        m_statRules->setText(QString::number(rules.size()));
    });
    connect(ipc, &IpcClient::quarantineReceived, this,
            [this](const QList<bulwark::ipc::QuarantineItemPayload>& items) {
        m_statQuarantine->setText(QString::number(items.size()));
    });
    connect(ipc, &IpcClient::aiScanRecord, this, [this](const AiScanResult& r) {
        m_aiTokens += r.tokens;
        m_statAi->setText(QString::number(++m_aiCount));
        m_statAi->setToolTip(QStringLiteral("累计消耗 Token:%1").arg(m_aiTokens));
    });
    connect(ipc, &IpcClient::settingsReceived, this, [this](const bulwark::RuntimeSettings& s) {
        m_heroTitle->setText(s.protectionEnabled ? u("系统受保护中") : u("防护已关闭"));
        m_heroTitle->setStyleSheet(QStringLiteral("font-size:20pt; font-weight:800; color:%1;")
                                       .arg((s.protectionEnabled ? theme::success() : theme::danger()).name()));
        const QString kernel = s.kernelStatus.isEmpty()
            ? (s.kernelConnected ? u("内核驱动已连接") : u("内核驱动未连接"))
            : s.kernelStatus;
        m_heroSub->setText(u("已启用防护维度  ·  ") + kernel);
        setDimension(m_dimRows.value(QStringLiteral("proc")), s.processProtection);
        setDimension(m_dimRows.value(QStringLiteral("file")), s.fileProtection);
        setDimension(m_dimRows.value(QStringLiteral("reg")), s.registryProtection);
        setDimension(m_dimRows.value(QStringLiteral("self")), s.selfProtection);
        setDimension(m_dimRows.value(QStringLiteral("net")), s.networkProtection);
        setDimension(m_dimRows.value(QStringLiteral("mem")), s.memoryProtectionEnabled);
    });
    connect(ipc, &IpcClient::connectionChanged, this, [this](bool c) {
        if (c) { m_ipc->requestSettings(); m_ipc->requestRules(); m_ipc->requestQuarantine(); }
    });
    if (ipc->isConnected()) { ipc->requestSettings(); ipc->requestRules(); ipc->requestQuarantine(); }
}

QWidget* DashboardPage::buildHero()
{
    auto* c = ui::card();
    c->setMinimumHeight(128);
    auto* h = new QHBoxLayout(c);
    h->setContentsMargins(24, 20, 24, 20);
    h->setSpacing(20);
    h->addWidget(ui::iconBadge("shield", theme::accent(), 68, 36));
    auto* col = new QVBoxLayout;
    col->setSpacing(3);
    col->addWidget(ui::label(u("实时防护"), "caption"));
    m_heroTitle = ui::coloredText(u("等待服务连接…"), 20, 800, theme::textMuted());
    col->addWidget(m_heroTitle);
    m_heroSub = ui::label(u("连接服务后显示防护状态"), "secondary");
    m_heroSub->setWordWrap(true); // long kernel-status text wraps instead of overflowing
    col->addWidget(m_heroSub);
    h->addLayout(col, 1);
    return c;
}

QWidget* DashboardPage::buildStats()
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(16);
    h->addWidget(makeStat("shield-x", theme::danger(), u("本次拦截"), m_statBlocked));
    h->addWidget(makeStat("activity", theme::accent(), u("本次事件"), m_statEvents));
    h->addWidget(makeStat("lock", theme::warning(), u("隔离文件"), m_statQuarantine));
    h->addWidget(makeStat("sliders", theme::info(), u("生效规则"), m_statRules));
    h->addWidget(makeStat("sparkles", theme::accentAlt(), u("AI 研判"), m_statAi));
    return w;
}

QWidget* DashboardPage::buildActivity()
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(20, 18, 20, 18);
    v->setSpacing(8);
    auto* head = new QHBoxLayout;
    head->addWidget(ui::label(u("最近活动"), "h2"));
    head->addStretch();
    v->addLayout(head);
    v->addWidget(ui::hDivider());
    v->addSpacing(2);
    m_activityBox = new QVBoxLayout;
    m_activityBox->setSpacing(2);
    v->addLayout(m_activityBox);
    auto* hint = ui::label(u("暂无活动 · 事件将在此实时滚动"), "muted");
    m_activityBox->addWidget(hint);
    v->addStretch();
    return c;
}

QWidget* DashboardPage::buildDimensions()
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(20, 18, 20, 18);
    v->setSpacing(6);
    v->addWidget(ui::label(u("防护维度"), "h2"));
    v->addWidget(ui::hDivider());
    v->addSpacing(2);
    auto add = [&](const QString& key, const QString& icon, const QString& name) {
        auto* r = dimensionRow(icon, name, true);
        m_dimRows.insert(key, r);
        v->addWidget(r);
    };
    add(QStringLiteral("proc"), QStringLiteral("activity"), u("进程防护"));
    add(QStringLiteral("file"), QStringLiteral("file"), u("文件防护"));
    add(QStringLiteral("reg"), QStringLiteral("sliders"), u("注册表防护"));
    add(QStringLiteral("self"), QStringLiteral("shield"), u("自我保护"));
    add(QStringLiteral("net"), QStringLiteral("globe"), u("网络防护"));
    add(QStringLiteral("mem"), QStringLiteral("cpu"), u("内存防护"));
    v->addStretch();
    return c;
}
