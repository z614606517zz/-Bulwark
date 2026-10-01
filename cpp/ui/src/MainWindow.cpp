#include "MainWindow.h"
#include "Bootstrap.h"
#include "Nav.h"
#include "design/Backdrop.h"
#include "design/Banner.h"
#include "design/Components.h"
#include "design/Confirm.h"
#include "design/GlowCard.h"
#include "design/IconTile.h"
#include "design/Icons.h"
#include "design/Identity.h"
#include "design/Motion.h"
#include "design/NavButton.h"
#include "design/PageTransition.h"
#include "design/Theme.h"
#include "dialogs/PromptDialog.h"
#include "dialogs/RemediationReportDialog.h"
#include "dialogs/ScanProgressWindow.h"
#include "dialogs/ToastNotifier.h"
#include "dialogs/UpdateDialog.h"
#include "ipc/IpcClient.h"
#include "pages/CardPages.h"
#include "pages/TablePages.h"
#include "pages/DashboardPage.h"
#include "voice/VoiceAnnouncer.h"
#include "widgets/ElidingLabel.h"

#include "bulwark/Version.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <QApplication>
#include <QButtonGroup>
#include <QCloseEvent>
#include <QDateTime>
#include <QDialog>
#include <QFrame>
#include <QHash>
#include <QHBoxLayout>
#include <QIcon>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QScreen>
#include <QScrollArea>
#include <QSet>
#include <QSettings>
#include <QShortcut>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QTimer>
#include <QToolButton>
#include <QUuid>
#include <QVariantAnimation>
#include <QVBoxLayout>

#include <algorithm>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr int kRailW = 72;          // collapsed rail width
constexpr int kAutoCollapseW = 1100; // window width below which the rail collapses by itself

// The tray icon is the shared brand mark (jade badge + ivory shield),
// baked at multiple sizes so the tray/taskbar/title bar each pick a crisp
// variant. Defined once in AppIcon::appBadge().
QIcon buildTrayIcon()
{
    return AppIcon::appBadge();
}

// The brand mark as a standalone widget (sidebar header).
class BrandMark : public QWidget
{
public:
    explicit BrandMark(int px, QWidget* parent = nullptr) : QWidget(parent)
    {
        setFixedSize(px, px);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        AppIcon::drawBadge(p, QRectF(rect()));
    }
};

// A tiny coloured dot + label + value row for the status card.
struct StatusLine {
    QLabel* dot = nullptr;
    QLabel* name = nullptr;
    QLabel* value = nullptr;
};

StatusLine makeStatusLine(QVBoxLayout* into, const QString& name)
{
    StatusLine s;
    auto* row = new QHBoxLayout;
    row->setContentsMargins(0, 0, 0, 0);
    row->setSpacing(8);
    s.dot = ui::statusDot(theme::textMuted());
    s.name = ui::label(name, "muted");
    s.value = ui::label(u("未知"), "muted");
    s.value->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    row->addWidget(s.dot, 0, Qt::AlignVCenter);
    row->addWidget(s.name, 0, Qt::AlignVCenter);
    row->addStretch();
    row->addWidget(s.value, 0, Qt::AlignVCenter);
    into->addLayout(row);
    return s;
}

void paintStatusLine(StatusLine& s, const QString& value, const QColor& color)
{
    s.dot->setStyleSheet(QStringLiteral("background:%1; border-radius:4px;").arg(color.name()));
    s.value->setText(value);
    s.value->setStyleSheet(QStringLiteral("color:%1; font-size:9pt; font-weight:600;").arg(color.name()));
}

// A painted shield glyph in the protection-state colour (card header / rail tile).
class StateGlyph : public QWidget
{
public:
    StateGlyph(int px, QWidget* parent = nullptr) : QWidget(parent), m_px(px)
    {
        setFixedSize(px, px);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }
    void set(const QString& glyph, const QColor& c)
    {
        m_glyph = glyph;
        m_color = c;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        AppIcon::draw(p, m_glyph, QRectF(0, 0, m_px, m_px), m_color, m_px >= 20 ? 1.9 : 1.7);
    }

private:
    int m_px;
    QString m_glyph = QStringLiteral("shield");
    QColor m_color = theme::textMuted();
};

} // namespace

// 侧栏底部的「防护状态」卡:把原先分散在右上角(防护状态灯)与侧栏(服务连接、信誉服务)
// 的三盏灯合成一处。展开时逐行写清;折叠成图标栏时只剩一枚按防护状态着色的盾牌,
// 完整信息在悬停提示里。它只负责呈现 —— 四态判定仍在 MainWindow::refreshProtectionPill()。
class StatusCard : public GlowCard
{
public:
    StatusCard()
    {
        setObjectName(QStringLiteral("CardAlt"));
        setTone(GlowCard::Tone::Rail); // recessed into the jade-ink rail, not a warm card floating on it
        setRadius(12);
        setAccessibleName(u("防护状态"));

        auto* outer = new QVBoxLayout(this);
        outer->setContentsMargins(0, 0, 0, 0);

        m_full = new QWidget;
        auto* v = new QVBoxLayout(m_full);
        v->setContentsMargins(12, 11, 12, 10);
        v->setSpacing(6);
        auto* head = new QHBoxLayout;
        head->setSpacing(8);
        m_glyph = new StateGlyph(18);
        head->addWidget(m_glyph, 0, Qt::AlignVCenter);
        m_state = ui::elided(u("状态未知"), "title");
        head->addWidget(m_state, 1, Qt::AlignVCenter);
        v->addLayout(head);
        m_detail = ui::elided(QString(), "muted");
        v->addWidget(m_detail);
        v->addSpacing(2);
        v->addWidget(ui::hDivider());
        v->addSpacing(2);
        m_service = makeStatusLine(v, u("后台服务"));
        m_rep = makeStatusLine(v, u("信誉服务"));
        outer->addWidget(m_full);

        m_mini = new QWidget;
        auto* mv = new QVBoxLayout(m_mini);
        mv->setContentsMargins(0, 10, 0, 10);
        m_miniGlyph = new StateGlyph(22);
        mv->addWidget(m_miniGlyph, 0, Qt::AlignHCenter);
        m_mini->hide();
        outer->addWidget(m_mini);

        paintStatusLine(m_service, u("未连接"), theme::textMuted());
        paintStatusLine(m_rep, u("未知"), theme::textMuted());
    }

    void setCompact(bool compact)
    {
        m_full->setVisible(!compact);
        m_mini->setVisible(compact);
    }

    void setProtection(const QString& text, const QColor& color, const QString& glyph,
                       const QString& detail, const QString& tip)
    {
        m_state->setText(text);
        m_state->setStyleSheet(QStringLiteral("color:%1; font-size:10.5pt; font-weight:600;").arg(color.name()));
        m_detail->setText(detail);
        m_glyph->set(glyph, color);
        m_miniGlyph->set(glyph, color);
        m_protTip = tip;
        m_protText = text;
        syncTip();
    }

    void setService(bool connected)
    {
        paintStatusLine(m_service, connected ? u("已连接") : u("未连接"),
                        connected ? theme::success() : theme::textMuted());
        m_svcText = connected ? u("后台服务已连接") : u("后台服务未连接");
        syncTip();
    }

    void setReputation(const QString& value, const QColor& color, const QString& tip)
    {
        paintStatusLine(m_rep, value, color);
        m_rep.value->setToolTip(tip);
        m_rep.name->setToolTip(tip);
        m_repText = u("信誉服务:") + value + (tip.isEmpty() ? QString() : u("(") + tip + u(")"));
        syncTip();
    }

private:
    void syncTip()
    {
        const QString all = QStringList{m_protText + u(" — ") + m_protTip, m_svcText, m_repText}
                                .join(QLatin1Char('\n'));
        setToolTip(all);
        setAccessibleDescription(all);
    }

    QWidget* m_full = nullptr;
    QWidget* m_mini = nullptr;
    StateGlyph* m_glyph = nullptr;
    StateGlyph* m_miniGlyph = nullptr;
    ElidingLabel* m_state = nullptr;
    ElidingLabel* m_detail = nullptr;
    StatusLine m_service;
    StatusLine m_rep;
    QString m_protText, m_protTip, m_svcText, m_repText;
};

MainWindow::MainWindow(QWidget* parent) : QWidget(parent)
{
    setObjectName(QStringLiteral("Root"));
    setWindowTitle(u("磐垒主动防御"));
    setWindowIcon(AppIcon::appBadge()); // title bar / taskbar / Alt-Tab icon
    setMinimumSize(940, 620);
    // 默认 1240x800,但不超过所在屏幕可用区域的 92%:1366x768 这类屏上整窗放不下时,
    // 底部的状态区和按钮会落到屏幕外。最小尺寸仍然优先。
    {
        QSize want(1240, 800);
        if (const QScreen* scr = screen())
            want = want.boundedTo(scr->availableGeometry().size() * 0.92);
        resize(want.expandedTo(minimumSize()));
    }
    m_prefCollapsed = QSettings().value(QStringLiteral("ui/sidebarCollapsed"), false).toBool();

    auto* root = new QHBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);
    root->addWidget(buildSidebar());
    root->addWidget(buildContent(), 1);

    // Create the IPC client up-front so each page can bind to its signals during
    // construction; start() is deferred to the end of the ctor (after wiring).
    m_ipc = new IpcClient(this);

    // 导航按用途分三组:监控(看发生了什么)/ 管控(决定允许什么)/ 情报(判断它是什么)。
    // 页面键是稳定标识(见 Nav.h),与导航文字、图标、分组、顺序都无关。
    addPage(nav::Dashboard, u("监控"), "dashboard", u("仪表盘"), u("仪表盘"), u("系统防护总览"),
            new DashboardPage(m_ipc));
    // 事件记录 = 原「拦截记录」+「活动日志」(同一份历史,用分段切换视角;分段会被记住)。
    addPage(nav::Events, QString(), "activity", u("事件记录"), u("事件记录"), u("拦截 · 询问 · 放行的全部安全事件"),
            pages::interceptions(m_ipc));
    addPage(nav::Timeline, QString(), "clock", u("事件时间线"), u("事件时间线"), u("按时间回溯 · 攻击关系图"),
            pages::timeline(m_ipc));
    addPage(nav::Chain, QString(), "link", u("攻击链"), u("攻击链"), u("动作组合定性 · 命中记录"),
            pages::attackChain(m_ipc));
    addPage(nav::Processes, u("管控"), "target", u("进程管理"), u("进程管理"), u("在跑进程 · 服务与计划任务溯源"),
            pages::processes(m_ipc));
    addPage(nav::Rules, QString(), "sliders", u("防护规则"), u("防护规则"), u("自定义放行 / 拦截策略"),
            pages::rules(m_ipc));
    addPage(nav::Trust, QString(), "trust", u("信任名单"), u("信任名单"), u("受信任的程序与目录"),
            pages::trust(m_ipc));
    addPage(nav::Quarantine, QString(), "lock", u("隔离区"), u("隔离区"), u("已隔离的威胁文件"),
            pages::quarantine(m_ipc));
    addPage(nav::Persistence, QString(), "power", u("自启动项"), u("自启动项"), u("开机持久化审计"),
            pages::persistence(m_ipc));
    addPage(nav::Reputation, u("情报"), "cloud", u("云信誉"), u("云信誉"), u("多引擎哈希信誉查询"),
            pages::reputation(m_ipc));
    addPage(nav::Settings, QString(), "settings", u("设置"), u("设置"), u("防护与情报配置"),
            pages::settings(m_ipc), /*pinned*/ true);

    if (auto* b = m_navGroup->button(0))
        b->setChecked(true);
    onNavClicked(0);

    // In-app navigation requests (dashboard tiles, "查询云信誉", "去设置"…).
    connect(NavHub::instance(), &NavHub::requested, this,
            [this](const QString& key, const QVariantMap& args) { navigateTo(key, args); });

    // Ctrl+F: jump to the current page's search box.
    auto* find = new QShortcut(QKeySequence::Find, this);
    connect(find, &QShortcut::activated, this, &MainWindow::focusPageSearch);

    // Corner toast notifications (block / attack chain) + the system tray presence.
    m_toasts = new ToastNotifier(this);
    // 拦截通知里的「AI 解读」与行为询问共用同一个大模型客户端(同一份缓存、同一个限速闸)。
    m_toasts->setAiScanner(m_ipc->aiScanner());
    connect(m_toasts, &ToastNotifier::blockToastClicked, this, [this] {
        showFromTray();
        navigateTo(nav::Events, {{QStringLiteral("segment"), QStringLiteral("block")}});
    });
    // 点攻击链 toast -> 跳到「攻击链」页面看完整命中记录。
    connect(m_toasts, &ToastNotifier::attackChainToastClicked, this, [this] {
        showFromTray();
        navigateTo(nav::Chain);
    });
    // 语音播报拦截结果(设置页开关,默认关)。只接拦截通知真正弹出的这两处,询问 / 放行 / 攻击链 /
    // 云查杀一概不接 —— 念的与右下角看到的逐条对应,开关关着时播报器自己什么都不做。
    connect(m_toasts, &ToastNotifier::blockPresented, VoiceAnnouncer::instance(), &VoiceAnnouncer::announceBlock);
    connect(m_toasts, &ToastNotifier::blockBatchPresented, VoiceAnnouncer::instance(),
            &VoiceAnnouncer::announceBatch);
    setupTray();

    // Live named-pipe link to the service. Drives the status card, pops the
    // behavior prompt when a verdict is needed, and raises toast notifications
    // for outright blocks and attack-chain hits. (m_ipc was created above so the
    // pages could bind to it; we connect the window-level slots and start here.)
    connect(m_ipc, &IpcClient::connectionChanged, this, &MainWindow::setConnected);
    connect(m_ipc, &IpcClient::promptReceived, this, &MainWindow::onPromptReceived);
    connect(m_ipc, &IpcClient::blockNotification, this, &MainWindow::onBlockNotification);
    connect(m_ipc, &IpcClient::attackChainHit, this, &MainWindow::onAttackChainHit);
    connect(m_ipc, &IpcClient::remediationReport, this, &MainWindow::onRemediationReport);
    // 未读角标:新拦截(事件记录)。只数真正进入「拦截」分段的记录(裁决为拦截)。
    connect(m_ipc, &IpcClient::eventLogReceived, this, [this](const bulwark::ipc::EventLogPayload& p) {
        if (p.action == bulwark::VerdictAction::Block)
            bumpBadge(nav::Events);
    });
    // Keep the prompt-timeout + default verdict in sync with the service so the
    // behavior prompt can auto-decide on timeout (honours PromptTimeoutSeconds).
    connect(m_ipc, &IpcClient::settingsReceived, this,
            [this](const bulwark::RuntimeSettings& s) {
                m_promptTimeoutSeconds = s.promptTimeoutSeconds;
                m_defaultBlock = s.defaultBlock;
                // 防护状态卡的真实数据来源(原先右上角那个标签是写死的绿色"防护开启")。
                m_protectionEnabled = s.protectionEnabled;
                m_protectionFollowsUi = s.protectionFollowsUi;
                //
                // 【K2 内核防护降级/恢复的角落通知】
                //
                // 这一条此前一直被挂着,理由写的是「需要新增 IPC 消息类型」—— 那个判断是错的。
                // 服务侧在每次内核状态迁移时就已经 sendSettings()(见 main.cpp 的
                // recordKernelState),而这个 lambda 正好收到它。所以 K2 只需要在这里认出
                // 【状态发生了变化】,零新增 IPC 表面、零新增消息号、不碰 IpcMessageType.h。
                //
                // 三点必须做对:
                //   ① 只在【迁移】时提示,不是每次 settings 推送都提示。服务会因为很多原因
                //      推设置(用户改配置、周期性刷新),不比较前值的话,无内核的机器每次推送
                //      都弹一次,几分钟后用户就学会无视它 —— 那等于把这条通知作废。
                //   ② 首次收到设置【不提示】。那是启动时的既有状态,不是刚刚发生的变化;
                //      不然每次开 UI 都会在无内核机器上弹一个「刚刚降级」的假消息。
                //   ③ 文案带上 kernelStatus。它现在装的是 2.5 的能力矩阵摘要
                //      (「生效 7/13 个维度:…;未生效:…」),所以用户看到的不是干巴巴一句
                //      「驱动掉了」,而是【还剩什么、少了什么】—— 这才是这条通知的价值所在。
                //
                // 刻意不看静默模式:静默模式的语义是「不要为决策打扰我」,而这是告知防护能力
                // 变化,不是向用户提问(与服务侧 recordKernelState 里同一条理由)。
                const bool hadSettings = m_haveSettings;
                const bool wasConnected = m_kernelConnected;
                m_kernelConnected = s.kernelConnected;
                m_kernelStatus = s.kernelStatus;
                m_haveSettings = true;
                if (hadSettings && wasConnected != m_kernelConnected && m_toasts) {
                    const QString detail = m_kernelStatus.isEmpty()
                        ? u("请在「设置」里查看当前防护档位。")
                        : m_kernelStatus;
                    if (!m_kernelConnected) {
                        // 降级那一侧给更长的停留时间:它是用户真正需要读完的那一条。
                        m_toasts->showInfo(u("内核驱动已断开 · 防护已降级"), detail, 12000);
                    } else {
                        m_toasts->showInfo(u("内核驱动已连接 · 行为前拦截恢复"), detail, 6000);
                    }
                }
                refreshProtectionPill();
                refreshQuitAction();   // 托盘「退出」项的文案取决于 protectionFollowsUi
            });
    // Centered "cloud scan in progress" card (ports the .NET AiScanToastWindow):
    // VT double-click/dropped-payload scans push live progress + verdict here.
    connect(m_ipc, &IpcClient::vtScanUpdate, this,
            [this](const bulwark::VtScanRecord& r) {
                ScanProgressWindow::vtUpdate(r);
                // 双击/释放载荷查毒完成且命中(恶意/可疑)-> 自动弹出行为关系图详情窗口,30 秒后自动关闭。
                static QSet<QUuid> shownDetail;
                if (r.isTerminal()
                    && (r.outcome == bulwark::VtScanOutcome::Malicious
                        || r.outcome == bulwark::VtScanOutcome::Suspicious)
                    && !shownDetail.contains(r.id)) {
                    shownDetail.insert(r.id);
                    pages::showVtDetailWindow(this, r, m_ipc, 30000);
                }
            });
    // 重试隔离的回执走右下角 toast,不走托盘气泡(原因见 ToastNotifier::showQuarantineRetry 的声明处)。
    connect(m_ipc, &IpcClient::manualQuarantineResult, this,
            [this](const bulwark::ipc::ManualQuarantineResultPayload& r) {
                if (m_toasts)
                    m_toasts->showQuarantineRetry(r);
            });

    // 「启动后自动检查」的结果落在这里。刻意只弹一次右下角通知,不自动打开弹窗、更不自动下载:
    // 更新会替换内核驱动,那必须由用户按下按钮才发生。
    //
    // 三道抑制,针对的都是「变成骚扰」这一个失败形态:
    //   查失败 / 没有新版本 -> 什么都不说。用户没主动问,就不该被告知「检查失败了」。
    //   弹窗正开着          -> 那是用户自己点的检查,结论已经写在弹窗里,再弹通知是噪音。
    //   本会话已经弹过      -> 服务端每个生命周期只自动查一次,但界面可能重连,不设闸门
    //                          就会每次重连都弹一遍。
    connect(m_ipc, &IpcClient::updateCheckReceived, this,
            [this](const bulwark::ipc::UpdateCheckResponsePayload& p) {
                if (!p.ok || !p.available) return;
                if (UpdateDialog::isAnyOpen()) return;
                if (m_updateNoticeShown) return;
                if (!m_toasts) return;
                m_updateNoticeShown = true;
                // 右下角 toast 而不是托盘气泡:气泡由 Windows 按系统主题绘制,浅色主题下是一张
                // 白卡,和本程序的深色通知混在同一个角落(见 ToastNotifier::showRemediation)。
                m_toasts->showInfo(
                    u("有新版本 ") + p.version,
                    u("当前 ") + p.currentVersion
                        + u("。在「设置 > 关于与更新」里查看更新说明并安装。"),
                    6000);
            });

    // 中央信誉服务在线状态:连接后 + 每 30s 探测一次(source=ReputationProxy 定向探测代理
    // /health,服务端非阻塞返回),按 requestId 回填侧栏状态卡。离线仅提示,本地直连情报源照常兜底。
    m_repTimer = new QTimer(this);
    m_repTimer->setInterval(30000);
    connect(m_repTimer, &QTimer::timeout, this, &MainWindow::pingReputation);
    connect(m_ipc, &IpcClient::vtResponse, this,
            [this](const bulwark::ipc::VtResponsePayload& resp) {
                if (m_repPingId.isNull() || resp.requestId != m_repPingId)
                    return; // 只认本窗口发起的健康探测;各页自身的查询 / 测试连接自动忽略
                m_repPingId = QUuid();
                const bool online = resp.success;
                const bool checking = !online && resp.message.contains(u("检测中"));
                // 「限流中」是在线的一种:链路好着,只是服务端对本出口 IP 的配额暂时用满,
                // 本地直连情报照常兜底。单独画成警示色,别再和「离线」混为一谈 —— 以前服务端
                // 一回 429 就报离线,而不受限流管辖的 /health 仍是 200,状态灯于是来回跳。
                const bool throttled = online && resp.message.contains(u("限流"));
                const QString value = throttled ? u("限流中")
                                      : online  ? u("在线")
                                      : checking ? u("检测中")
                                                 : u("离线");
                const QColor color = throttled ? theme::warning()
                                     : online  ? theme::success()
                                     : checking ? theme::textMuted()
                                                : theme::danger();
                const QString tip = resp.message.isEmpty()
                                        ? (online ? u("中央信誉服务连接正常")
                                                  : u("中央信誉服务不可达,已回退本地直连"))
                                        : resp.message;
                m_status->setReputation(value, color, tip);
                if (checking) // 尚无结论(缓存预热中),稍后再探一次尽快收敛
                    QTimer::singleShot(4000, this, &MainWindow::pingReputation);
            });
    m_status->setReputation(u("未知"), theme::textMuted(),
                            u("中央信誉服务(云端共享缓存 + 多引擎)连接状态。离线时本地直连情报源自动兜底,"
                              "实时防护不受影响。"));
    refreshProtectionPill();
    m_ipc->start();
}

QWidget* MainWindow::buildSidebar()
{
    m_sidebar = new Backdrop(Backdrop::Kind::Sidebar);
    m_sidebar->setObjectName(QStringLiteral("Sidebar"));
    m_sidebar->setFixedWidth(theme::metric::sidebarW);

    auto* v = new QVBoxLayout(m_sidebar);
    m_sidebarLayout = v;
    v->setContentsMargins(14, 18, 14, 12);
    v->setSpacing(0);

    // brand
    m_brandRow = new QHBoxLayout;
    m_brandRow->setContentsMargins(6, 0, 0, 0);
    m_brandRow->setSpacing(12);
    m_brandRow->addWidget(new BrandMark(36), 0, Qt::AlignVCenter);
    m_brandText = new QWidget;
    auto* bt = new QVBoxLayout(m_brandText);
    bt->setContentsMargins(0, 0, 0, 0);
    bt->setSpacing(0);
    bt->addWidget(ui::coloredText(u("磐垒"), 13, 700, theme::textPrimary()));
    bt->addWidget(ui::label(u("主动防御 · HIPS"), "muted"));
    m_brandRow->addWidget(m_brandText, 1);
    v->addLayout(m_brandRow);
    v->addSpacing(18);

    // 导航项放进一个无边框透明滚动区:13 项加三个分组标题在最小窗口高度(620)下放不下,
    // 窗口够高时看不出区别,不够高时这一段可滚动,而不是把底部的设置与状态区挤掉。
    auto* navHost = new QWidget;
    m_navLayout = new QVBoxLayout(navHost);
    m_navLayout->setContentsMargins(0, 0, 0, 0);
    m_navLayout->setSpacing(1);
    m_navLayout->addStretch(); // 末尾留一个弹簧,导航项始终顶部对齐(addPage 插在它之前)

    m_navScroll = new QScrollArea;
    m_navScroll->setWidgetResizable(true);
    m_navScroll->setFrameShape(QFrame::NoFrame);
    m_navScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_navScroll->setWidget(navHost);
    navHost->setAutoFillBackground(false); // let the rail's canvas light show through
    v->addWidget(m_navScroll, 1);

    // 固定在底部:设置入口 + 防护状态卡 + 折叠按钮。
    m_navFooter = new QVBoxLayout;
    m_navFooter->setContentsMargins(0, 8, 0, 0);
    m_navFooter->setSpacing(2);
    v->addLayout(m_navFooter);
    v->addSpacing(10);

    m_status = new StatusCard;
    v->addWidget(m_status);
    v->addSpacing(6);

    // Bottom row: collapse toggle + version. 版本串来自 bulwark/Version.h —— 与 exe 的
    // VERSIONINFO、更新清单比较用的是同一个数字。
    auto* bottom = new QHBoxLayout;
    m_bottomRow = bottom;
    bottom->setContentsMargins(0, 0, 4, 0);
    bottom->setSpacing(6);
    m_toggle = new QToolButton;
    m_toggle->setObjectName(QStringLiteral("SidebarToggle"));
    m_toggle->setCursor(Qt::PointingHandCursor);
    m_toggle->setAutoRaise(true);
    m_toggle->setIconSize(QSize(16, 16));
    connect(m_toggle, &QToolButton::clicked, this, &MainWindow::toggleSidebar);
    bottom->addWidget(m_toggle, 0, Qt::AlignVCenter);
    bottom->addStretch();
    m_version = ui::label(bulwark::version::displayString(), "muted");
    m_version->setToolTip(bulwark::version::displayString());
    bottom->addWidget(m_version, 0, Qt::AlignVCenter);
    v->addLayout(bottom);

    m_navGroup = new QButtonGroup(this);
    m_navGroup->setExclusive(true);
    connect(m_navGroup, &QButtonGroup::idClicked, this, &MainWindow::onNavClicked);

    m_sideAnim = new QVariantAnimation(this);
    m_sideAnim->setEasingCurve(QEasingCurve::OutCubic);
    connect(m_sideAnim, &QVariantAnimation::valueChanged, this, [this](const QVariant& val) {
        const int w = val.toInt();
        m_sidebar->setFixedWidth(w);
        // Expanding: switch to the full content once there is room for it.
        if (!m_collapsed && m_compactContent && w > 170)
            setSidebarCompact(false);
    });
    connect(m_sideAnim, &QVariantAnimation::finished, this, [this] {
        if (!m_collapsed && m_compactContent)
            setSidebarCompact(false);
    });
    return m_sidebar;
}

QWidget* MainWindow::buildContent()
{
    auto* content = new Backdrop(Backdrop::Kind::Content);
    content->setObjectName(QStringLiteral("Content"));
    auto* v = new QVBoxLayout(content);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(0);

    // page header: floats on the canvas, no bar or rule of its own; the page's
    // own primary actions sit at its right end.
    auto* top = new QFrame;
    top->setObjectName(QStringLiteral("PageHeader"));
    top->setFixedHeight(theme::metric::topbarH);
    auto* h = new QHBoxLayout(top);
    h->setContentsMargins(theme::metric::pagePad, 14, theme::metric::pagePad, 0);
    h->setSpacing(16);

    // The page's glyph in its identity hue, beside the title — the same tile the
    // page's rail item, list card and empty states are keyed to.
    auto* titleRow = new QHBoxLayout;
    titleRow->setSpacing(14);
    m_titleTile = new IconTile(QStringLiteral("dashboard"), theme::accent(), 40, 20);
    titleRow->addWidget(m_titleTile, 0, Qt::AlignVCenter);
    auto* tcol = new QVBoxLayout;
    tcol->setSpacing(2);
    m_title = ui::label(QString(), "h1");
    m_subtitle = ui::label(QString(), "secondary");
    tcol->addWidget(m_title);
    tcol->addWidget(m_subtitle);
    titleRow->addLayout(tcol);
    h->addLayout(titleRow);
    h->addStretch();

    auto* actions = new QWidget;
    m_headerActions = new QHBoxLayout(actions);
    m_headerActions->setContentsMargins(0, 0, 0, 0);
    m_headerActions->setSpacing(8);
    h->addWidget(actions, 0, Qt::AlignVCenter);
    v->addWidget(top);

    // In-page message strip for every page (operation results, failures with
    // their reason). A direct child of the content area, so BannerHost::find()
    // reaches it from any page.
    m_banners = new BannerHost(content);
    if (QLayout* bl = m_banners->layout())
        bl->setContentsMargins(theme::metric::pagePad, 8, theme::metric::pagePad, 0);
    v->addWidget(m_banners);

    m_stack = new QStackedWidget;
    v->addWidget(m_stack, 1);

    // Page changes cross-fade on snapshots of this area (design/PageTransition):
    // the header cross-fades, the old page fades out, the new one fades in rising.
    m_pageFx = new PageTransition(content, top, {m_banners, m_stack});
    return content;
}

void MainWindow::addPage(const QString& key, const QString& section, const QString& icon, const QString& nav,
                         const QString& title, const QString& subtitle, QWidget* page, bool pinned)
{
    const int idx = m_stack->count();
    const QColor hue = identity::page(key);
    auto* btn = new NavButton(icon, nav);
    btn->setIdentity(hue);
    if (pinned) {
        m_navFooter->addWidget(btn);
    } else {
        // 插在末尾弹簧之前,保持导航项顶部对齐。第一个分组紧贴品牌区,其后的分组留出间隔。
        if (!section.isEmpty()) {
            const bool first = m_navLayout->count() <= 1;
            auto* head = ui::eyebrow(section);
            head->setContentsMargins(14, first ? 0 : 12, 0, 3);
            m_navLayout->insertWidget(std::max(0, m_navLayout->count() - 1), head);
            m_sectionHeads << head;
            // Collapsed rail: a short hairline stands in for the group title.
            auto* rule = new QWidget;
            auto* rl = new QVBoxLayout(rule);
            rl->setContentsMargins(10, first ? 0 : 10, 10, 6);
            rl->addWidget(ui::hDivider());
            rule->hide();
            m_navLayout->insertWidget(std::max(0, m_navLayout->count() - 1), rule);
            m_sectionRules << rule;
        }
        m_navLayout->insertWidget(std::max(0, m_navLayout->count() - 1), btn);
    }
    m_navGroup->addButton(btn, idx);
    m_navButtons << btn;
    m_stack->addWidget(page);
    m_titles << title;
    m_subtitles << subtitle;
    m_pageKeys << key;
    m_pageIcons << icon;
    m_pageHues << hue;

    QWidget* actions = ui::pageActions(page);
    if (actions) {
        m_headerActions->addWidget(actions);
        actions->hide();
    }
    m_pageActions << actions;
}

QString MainWindow::currentKey() const
{
    return m_pageKeys.value(m_stack ? m_stack->currentIndex() : -1);
}

void MainWindow::navigateTo(const QString& pageKey, const QVariantMap& args)
{
    const int idx = m_pageKeys.indexOf(pageKey);
    if (idx < 0)
        return;
    if (auto* b = m_navGroup->button(idx))
        b->setChecked(true);
    onNavClicked(idx);
    NavHub::instance()->deliver(pageKey, args);
}

void MainWindow::onNavClicked(int index)
{
    if (index < 0 || index >= m_stack->count())
        return;
    const bool changing = index != m_stack->currentIndex();
    // Cross-fade the content area over a snapshot of the page being left. Started
    // before anything changes; it degrades to an instant switch on its own when the
    // change couldn't be seen (see PageTransition).
    const bool fading = changing && m_pageFx && m_pageFx->start();
    // Banners report on what was just done on the page being left (and failures
    // are sticky): carried over they would sit, out of context, on top of the next
    // page — "无法添加规则" above the dashboard. While fading they are already on
    // the outgoing snapshot, so they go at once instead of fading twice.
    if (changing && m_banners)
        m_banners->clear(/*animated*/ !fading);
    m_stack->setCurrentIndex(index);
    m_titleTile->set(m_pageIcons.value(index), m_pageHues.value(index, theme::accent()));
    m_title->setText(m_titles.value(index));
    m_subtitle->setText(m_subtitles.value(index));
    for (int i = 0; i < m_pageActions.size(); ++i)
        if (QWidget* a = m_pageActions[i])
            a->setVisible(i == index);
    clearBadge(m_pageKeys.value(index));
}

void MainWindow::focusPageSearch()
{
    QWidget* page = m_stack ? m_stack->currentWidget() : nullptr;
    if (!page)
        return;
    const auto boxes = page->findChildren<QLineEdit*>(QStringLiteral("PageSearch"));
    for (QLineEdit* e : boxes) {
        if (e->isVisible() && e->isEnabled()) {
            e->setFocus(Qt::ShortcutFocusReason);
            e->selectAll();
            return;
        }
    }
}

// ---- rail collapse ------------------------------------------------------------

void MainWindow::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    const bool narrow = width() < kAutoCollapseW;
    if (narrow != m_narrow || !m_sidebarReady) {
        m_narrow = narrow;
        m_narrowExpand = false; // a temporary expand doesn't survive crossing the threshold
        applySidebar(m_sidebarReady);
    }
}

void MainWindow::toggleSidebar()
{
    if (m_narrow) {
        m_narrowExpand = !m_narrowExpand;
    } else {
        m_prefCollapsed = !m_prefCollapsed;
        QSettings().setValue(QStringLiteral("ui/sidebarCollapsed"), m_prefCollapsed);
    }
    applySidebar(true);
}

void MainWindow::applySidebar(bool animate)
{
    const bool collapse = m_narrow ? !m_narrowExpand : m_prefCollapsed;
    if (m_sidebarReady && collapse == m_collapsed)
        return;
    m_sidebarReady = true;
    m_collapsed = collapse;
    const int target = collapse ? kRailW : theme::metric::sidebarW;

    // Collapsing: switch to glyph-only content first, so labels aren't squeezed.
    if (collapse)
        setSidebarCompact(true);

    m_toggle->setIcon(AppIcon::icon(collapse ? QStringLiteral("chevrons-right") : QStringLiteral("chevrons-left"),
                                    theme::textMuted(), 16));
    m_toggle->setText(collapse ? QString() : u("收起侧栏"));
    m_toggle->setToolButtonStyle(collapse ? Qt::ToolButtonIconOnly : Qt::ToolButtonTextBesideIcon);
    const QString tip = collapse ? u("展开侧栏") : u("收起侧栏");
    m_toggle->setToolTip(tip);
    m_toggle->setAccessibleName(tip);

    m_sideAnim->stop();
    const int ms = animate ? motion::duration(180) : 0;
    if (ms <= 0) {
        m_sidebar->setFixedWidth(target);
        if (!collapse)
            setSidebarCompact(false);
        return;
    }
    m_sideAnim->setDuration(ms);
    m_sideAnim->setStartValue(m_sidebar->width());
    m_sideAnim->setEndValue(target);
    m_sideAnim->start();
}

void MainWindow::setSidebarCompact(bool compact)
{
    m_compactContent = compact;
    for (NavButton* b : std::as_const(m_navButtons))
        b->setCompact(compact);
    m_brandText->setVisible(!compact);
    m_brandRow->setContentsMargins(compact ? 4 : 6, 0, 0, 0);
    for (QWidget* w : std::as_const(m_sectionHeads))
        w->setVisible(!compact);
    for (QWidget* w : std::as_const(m_sectionRules))
        w->setVisible(compact);
    m_status->setCompact(compact);
    m_version->setVisible(!compact);
    if (m_bottomRow) // centre the lone toggle on the 44 px rail
        m_bottomRow->setContentsMargins(compact ? 7 : 0, 0, 4, 0);
    // The 44 px rail has no room for a scrollbar next to the glyphs; it still
    // scrolls with the wheel when the window is very short.
    m_navScroll->setVerticalScrollBarPolicy(compact ? Qt::ScrollBarAlwaysOff : Qt::ScrollBarAsNeeded);
}

// ---- unread badges ---------------------------------------------------------------

bool MainWindow::isViewing(const QString& key) const
{
    return isVisible() && !isMinimized() && currentKey() == key;
}

void MainWindow::bumpBadge(const QString& key)
{
    if (isViewing(key))
        return;
    const int idx = m_pageKeys.indexOf(key);
    if (idx < 0 || idx >= m_navButtons.size())
        return;
    const int n = ++m_unread[key];
    const QColor c = key == QLatin1String(nav::Chain) ? theme::warning() : theme::danger();
    m_navButtons[idx]->setBadge(n, c);
}

void MainWindow::clearBadge(const QString& key)
{
    if (!m_unread.value(key))
        return;
    m_unread.remove(key);
    const int idx = m_pageKeys.indexOf(key);
    if (idx >= 0 && idx < m_navButtons.size())
        m_navButtons[idx]->setBadge(0);
}

void MainWindow::clearViewedBadge()
{
    if (isVisible() && !isMinimized())
        clearBadge(currentKey());
}

void MainWindow::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::WindowStateChange || event->type() == QEvent::ActivationChange)
        clearViewedBadge();
}

void MainWindow::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    clearViewedBadge();
}

void MainWindow::onPromptReceived(const bulwark::SecurityEvent& event)
{
    // Arm the auto-decision countdown from the live settings: if the user doesn't
    // respond within PromptTimeoutSeconds, close with the default policy
    // (defaultBlock ? 拦截 : 放行) so a prompt never lingers forever.
    // AI 解读(配置了大模型且没关掉时)由弹窗自己异步去取,只给人看,不影响这里拿回的裁决。
    PromptDialog dlg(event, this, m_promptTimeoutSeconds, !m_defaultBlock, m_ipc->aiScanner());
    // The prompt sits in the bottom-right corner, the toasts' corner: have them
    // stack above it so a block toast never covers the 拦截 / 放行 buttons.
    if (m_toasts)
        m_toasts->reserveCorner(&dlg);
    dlg.exec();
    if (m_toasts)
        m_toasts->releaseCorner(&dlg);
    const auto action = dlg.allowed() ? bulwark::VerdictAction::Allow
                                      : bulwark::VerdictAction::Block;
    m_ipc->sendVerdict(event.id, action, dlg.remember(),
                       static_cast<bulwark::RememberScope>(dlg.scopeIndex()));
}

// 防护状态(侧栏「防护状态」卡 + 托盘提示)。四种状态如实区分,任何一种"说不清"都不显示为绿色:
//   未连接服务      -> 灰。界面此刻对防护状态一无所知,不能替它作保。
//   总开关关闭      -> 红。用户主动关了防护,必须显眼。
//   开启但内核未连  -> 橙。用户态仍在拦,但少了内核前置拦截(真正的动作前阻断),
//                      这是能力差异,不该和"完全开启"共用一个绿灯。
//   开启且内核已连  -> 绿。
void MainWindow::refreshProtectionPill()
{
    if (!m_status)
        return;

    QString text;
    QColor color;
    QString tip;
    QString glyph;
    QString detail;

    if (!m_svcConnected || !m_haveSettings) {
        text   = u("○ 状态未知");
        color  = theme::textMuted();
        tip    = u("尚未与后台服务建立连接,无法确认防护状态。");
        glyph  = QStringLiteral("shield");
        detail = m_svcConnected ? u("正在读取防护配置…") : u("等待后台服务连接");
    } else if (!m_protectionEnabled) {
        text   = u("● 防护已关闭");
        color  = theme::danger();
        tip    = u("防护总开关处于关闭状态,系统当前不受保护。可在「设置」中重新开启。");
        glyph  = QStringLiteral("shield-x");
        detail = u("总开关已关闭");
    } else if (!m_kernelConnected) {
        text   = u("◐ 防护开启 · 无内核");
        color  = theme::warning();
        tip    = m_kernelStatus.isEmpty()
                     ? u("防护已开启,但内核驱动未连接:仅有用户态观测与补偿处置,"
                         "缺少「动作发生前阻断」能力。")
                     : m_kernelStatus;
        glyph  = QStringLiteral("shield-alert");
        detail = u("内核驱动未连接");
    } else {
        text   = u("● 防护开启");
        color  = theme::success();
        tip    = m_kernelStatus.isEmpty() ? u("防护已开启,内核驱动已连接。") : m_kernelStatus;
        glyph  = QStringLiteral("trust");
        detail = u("内核驱动已连接");
    }

    // text 前两个字符是状态符号 + 空格:卡片上有按状态着色的盾牌,文字只保留纯文案。
    m_status->setProtection(text.mid(2), color, glyph, detail, tip);
    m_status->setService(m_svcConnected);

    // 托盘提示同步。它原先也是一句写死的「防护运行中」—— 主界面关掉后托盘是用户唯一能看到
    // 的状态入口,那里更不能谎报。
    if (m_tray)
        m_tray->setToolTip(u("磐垒主动防御 — ") + text.mid(2));
}

void MainWindow::setConnected(bool connected)
{
    m_svcConnected = connected;
    if (!connected)
        m_haveSettings = false;   // 断链后旧设置快照不再可信,退回"未知"而不是继续显示上次的状态
    refreshProtectionPill();
    // Refresh prompt-timeout / default-action the moment the link comes up, so a
    // prompt arriving right after connect already has the correct countdown.
    if (connected && m_ipc) {
        m_ipc->requestSettings();
        pingReputation();                    // 立即探一次中央信誉服务
        if (m_repTimer) m_repTimer->start();  // 之后每 30s 复探
    } else {
        if (m_repTimer) m_repTimer->stop();
        m_repPingId = QUuid();
        // 与服务断链时无从得知代理状态,置灰。
        m_status->setReputation(u("未知"), theme::textMuted(), u("与后台服务断开,无法得知中央信誉服务状态。"));
    }
}

void MainWindow::pingReputation()
{
    if (!m_ipc || !m_ipc->isConnected())
        return;
    bulwark::ipc::VtRequestPayload p;
    p.kind = bulwark::VtRequestKind::TestConnection;
    p.source = QStringLiteral("ReputationProxy"); // 定向探测中央代理(ProxyReputationService::name())
    m_repPingId = p.requestId;                    // 记住本次 requestId,回填时只认自己的响应
    m_ipc->vtQuery(p);
}

void MainWindow::onBlockNotification(const bulwark::SecurityEvent& event,
                                     bulwark::EnforcementOutcome enforcement)
{
    // 真实处置结果直接透给 toast —— 它据此决定说「已拦截」还是「仅告警·未拦截 / 拦截失败」。
    if (m_toasts)
        m_toasts->showBlock(event, enforcement);
    // 同一个文件如果正开着云查卡片(双击查毒 / 释放载荷),把处置结果补进那张卡:
    // 卡片此前只会写「检测到威胁,已处置」,而处置成没成它根本不知道。
    ScanProgressWindow::applyDisposition(event.actorPath, enforcement);
}

void MainWindow::onAttackChainHit(const bulwark::ipc::AttackChainHitPayload& hit)
{
    // 这条通知【不看静默模式】—— 服务端已按 attackChainToast 开关决定要不要发,
    // UI 收到就显示。理由见 RuntimeSettings::attackChainToast 处的说明:
    // 静默模式把询问降级成放行,恰好造出「命中了但用户毫不知情」的盲区。
    if (m_toasts)
        m_toasts->showAttackChain(hit);
    bumpBadge(nav::Chain);
}

void MainWindow::onRemediationReport(const bulwark::ipc::RemediationReportPayload& report)
{
    // 去重(B):同一主体的处置报告在窗口期(30s)内只弹一张卡片,避免高频处置时叠出大量报告窗口
    // ——既是重复提示,海量建窗也会拖卡 UI。完整报告仍在事件 / 审计日志中,不丢信息。
    static QHash<QString, qint64> recentReports;
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    const QString rkey = report.actorPath.isEmpty() ? report.reason : report.actorPath;
    const auto rit = recentReports.find(rkey);
    if (rit != recentReports.end() && nowMs - rit.value() < 30000) {
        rit.value() = nowMs;
        return;
    }
    recentReports.insert(rkey, nowMs);
    if (recentReports.size() > 512) {
        for (auto i = recentReports.begin(); i != recentReports.end(); ) {
            if (nowMs - i.value() > 30000) i = recentReports.erase(i);
            else ++i;
        }
    }

    // Surface the "footprint cleanup" transparently: what was quarantined/removed,
    // and how many items couldn't be cleaned (the report detail also rides the
    // event/audit log on the service side). A corner toast, not a tray balloon:
    // Windows draws balloons itself in the *system* theme — a white card in light
    // mode, wedged between our dark toasts in the same corner. Wording (已清理 /
    // 部分清理 / 未能清理, by what was really cleaned) lives in ToastNotifier.
    if (m_toasts)
        m_toasts->showRemediation(report);

    // 完整报告卡片:主体 / 判定 / 已隔离项 / 未能清理项(文件可一键重试强制隔离)。
    // 非模态,不打断用户;自身带滚动区与关闭按钮。
    (new RemediationReportDialog(report, m_ipc, m_ipc->aiScanner(), this))->show();
}

// ---- System tray + close-to-tray -------------------------------------------

void MainWindow::setupTray()
{
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        // The notification area isn't always ready the instant we start — the app
        // can launch before/while Explorer initialises its tray, notably when
        // elevated or at logon. Giving up permanently would strand the app with
        // no way back after close-to-tray, so retry for a while before conceding.
        if (m_trayRetries++ < 30) {
            QTimer::singleShot(1000, this, &MainWindow::setupTray);
            return;
        }
        return; // genuinely headless — closeEvent then falls back to a real quit
    }
    if (m_tray)
        return; // already created (a retry raced a now-ready tray)

    m_tray = new QSystemTrayIcon(this);
    m_tray->setIcon(buildTrayIcon());
    m_tray->setToolTip(u("磐垒主动防御"));   // 真实状态随后由 refreshProtectionPill() 补上

    auto* menu = new QMenu(this);
    auto* actShow = menu->addAction(u("显示主界面"));
    auto* actScan = menu->addAction(u("立即扫描"));
    menu->addSeparator();
    // 措辞必须与实际行为一致。原来叫「退出磐垒防护」,而它真的会去停服务 + 卸驱动;
    // 后来退出只关界面、防护继续常驻,所以改成了如实说明。
    // 现在这句话【取决于设置】(「退出界面即停止防护」),所以文案也必须随之变 ——
    // 一个固定写着「防护继续运行」的菜单项,在那个开关打开之后就是谎报。见 refreshQuitAction。
    m_actQuit = menu->addAction(QString());
    connect(actShow, &QAction::triggered, this, &MainWindow::showFromTray);
    // 「立即扫描」落到云信誉页:那里可以选择 / 拖入文件做云端查毒。
    connect(actScan, &QAction::triggered, this, [this] {
        showFromTray();
        navigateTo(nav::Reputation);
    });
    connect(m_actQuit, &QAction::triggered, this, &MainWindow::quitApp);
    refreshQuitAction();
    m_tray->setContextMenu(menu);

    connect(m_tray, &QSystemTrayIcon::activated, this,
            [this](QSystemTrayIcon::ActivationReason reason) {
                if (reason == QSystemTrayIcon::Trigger
                    || reason == QSystemTrayIcon::DoubleClick)
                    showFromTray();
            });

    m_tray->show();
    refreshProtectionPill(); // 托盘刚建好:把当前已知状态写进它的提示文字

    // First appearance: point the user at the tray. Windows usually folds a new
    // app's icon into the overflow ("^") flyout, so a one-time notice helps them
    // locate it (and learn the window minimises here instead of quitting). A corner
    // toast, not a tray balloon: Windows draws balloons in the *system* theme.
    if (!m_trayIntroShown && m_toasts) {
        m_trayIntroShown = true;
        m_toasts->showInfo(
            u("磐垒主动防御 · 防护运行中"),
            u("图标已在系统托盘。若未看到,请点任务栏通知区的 ‘^’ 展开;双击图标可打开主界面。"),
            6000);
    }
}

void MainWindow::showFromTray()
{
    show();
    setWindowState((windowState() & ~Qt::WindowMinimized) | Qt::WindowActive);
    raise();
    activateWindow();
    clearViewedBadge();
}

// 托盘「退出」项的文案 + 提示。它说的话必须与【当前设置下真会发生的事】一致,所以每次
// 收到服务推来的设置都要重算一次(见 settingsReceived 里的调用)。
//
// 这不是措辞洁癖:这一项是用户唯一的退出入口,而两种模式的后果差别极大(防护继续 / 防护全停)。
// 固定文案在其中一种模式下必然是错的,而用户恰恰是照着它做决定的。
void MainWindow::refreshQuitAction()
{
    if (!m_actQuit)
        return;
    // 设置还没回来时按「未知」说话:不替防护作保,也不吓用户。与防护状态卡同一条原则。
    if (!m_haveSettings) {
        m_actQuit->setText(u("退出界面"));
        m_actQuit->setToolTip(u("尚未连上后台服务,无法确认退出后防护是否继续运行。"));
        return;
    }
    if (m_protectionFollowsUi) {
        m_actQuit->setText(u("退出(防护同时停止)"));
        m_actQuit->setToolTip(u("已开启「退出界面即停止防护」:退出后事件监控与处置全部停止,"
                               "内核驱动也会被卸载。要让防护常驻,请在「设置 → 防护总控」里关掉该项。"));
    } else {
        m_actQuit->setText(u("退出界面(防护继续运行)"));
        m_actQuit->setToolTip(u("仅关闭界面,后台防护保持运行。"
                               "想让防护随界面一起停,可在「设置 → 防护总控」里开启"
                               "「退出界面即停止防护」。"));
    }
}

void MainWindow::quitApp()
{
    // 【退出界面是否等于关闭防护,由设置决定】
    //
    // 更早的实现在这里调 bootstrap::shutdownBackend():用户从托盘点一下"退出",整台机器的防护
    // 就没了,而这是除"关到托盘"以外唯一的退出路径 —— 界面是前台程序,用户关它是常事,防护
    // 不该跟着前台程序一起死。所以那条路被去掉了,退出只关界面。
    //
    // 现在这件事变成【用户可选】的(设置 → 防护总控 →「退出界面即停止防护」,默认关)。
    // 实现上界面【什么都不做】:它是 asInvoker,既停不了 LocalSystem 的服务也卸不了驱动,
    // 硬要做就得每次退出弹一次 UAC。真正的动作由服务侧做 —— 它把管道断开当作「界面已退出」
    // 的事实来源(见 main.cpp 的 applyProtectionLifetime)。所以这里只需要:选了那个模式时,
    // 把后果当面说清再退,而不是让用户点完才发现防护没了。
    if (m_protectionFollowsUi && m_haveSettings) {
        ui::ConfirmSpec c;
        c.risk = ui::Risk::Caution;
        c.title = u("退出并停止防护");
        c.summary = u("你开启了「退出界面即停止防护」,所以退出后本软件不再提供任何防护。");
        c.consequences << u("事件监控与处置停止,内核驱动会被卸载")
                       << u("重新打开本程序即恢复全部防护")
                       << u("只想收起窗口的话,点右上角关闭即最小化到托盘,防护照常运行");
        c.confirmText = u("退出并停止防护");
        if (!ui::confirm(this, c))
            return;
    }
    m_forceQuit = true;
    qApp->quit();
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    // With a tray present, closing the window just hides it — protection keeps
    // running headless in the background. Real exit goes through the tray menu.
    if (!m_forceQuit && m_tray && QSystemTrayIcon::isSystemTrayAvailable()) {
        hide();
        event->ignore();
        if (!m_trayHintShown && m_toasts) {
            m_trayHintShown = true;
            // 「最小化到托盘 = 防护照常」在两种模式下都成立(托盘里管道还连着,服务不会待机),
            // 所以这句话本身没问题;但开了「退出界面即停止防护」时,用户最需要知道的是
            // 「收起 ≠ 退出」这个区别 —— 否则他会以为点了关闭就已经停掉防护了。
            m_toasts->showInfo(
                u("磐垒仍在后台防护"),
                m_protectionFollowsUi && m_haveSettings
                    ? u("已最小化到系统托盘,防护持续运行 —— 收起窗口不算退出。"
                        "要连防护一起停,请右键托盘图标选「退出」。")
                    : u("已最小化到系统托盘,防护持续运行。右键托盘图标可退出。"),
                4000);
        }
        return;
    }
    // No tray (or a real quit): accept the close and make sure the app exits,
    // since we disabled quit-on-last-window-closed for the tray lifecycle.
    event->accept();
    qApp->quit();
}
