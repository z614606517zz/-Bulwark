#include "MainWindow.h"
#include "Bootstrap.h"
#include "Theme.h"
#include "dialogs/PromptDialog.h"
#include "dialogs/RemediationReportDialog.h"
#include "dialogs/ScanProgressWindow.h"
#include "dialogs/ToastNotifier.h"
#include "dialogs/UpdateDialog.h"
#include "ipc/IpcClient.h"
#include "pages/CardPages.h"
#include "pages/CleanupPage.h"
#include "pages/DashboardPage.h"
#include "pages/TablePages.h"
#include "widgets/AppIcon.h"
#include "widgets/NavButton.h"
#include "widgets/Ui.h"

#include "bulwark/Version.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <QApplication>
#include <QButtonGroup>
#include <QCloseEvent>
#include <QDialog>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMenu>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QScrollArea>
#include <QDateTime>
#include <QHash>
#include <QSet>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>

#include <algorithm>

namespace {

// The tray icon is the shared app brand badge (teal rounded-square + white
// shield), baked at multiple sizes so the tray/taskbar/title bar each pick a
// crisp variant. Defined once in AppIcon::appBadge().
QIcon buildTrayIcon()
{
    return AppIcon::appBadge();
}

} // namespace

MainWindow::MainWindow(QWidget* parent) : QWidget(parent)
{
    setObjectName(QStringLiteral("Root"));
    setWindowTitle(QString::fromUtf8("磐垒主动防御"));
    setWindowIcon(AppIcon::appBadge()); // title bar / taskbar / Alt-Tab icon
    resize(1240, 800);
    setMinimumSize(940, 620);

    auto* root = new QHBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);
    root->addWidget(buildSidebar());
    root->addWidget(buildContent(), 1);

    auto u = [](const char* s) { return QString::fromUtf8(s); };

    // Create the IPC client up-front so each page can bind to its signals during
    // construction; start() is deferred to the end of the ctor (after wiring).
    m_ipc = new IpcClient(this);

    addPage("dashboard", u("仪表盘"), u("仪表盘"), u("系统防护总览"), new DashboardPage(m_ipc));
    addPage("shield-x", u("拦截记录"), u("拦截记录"), u("已阻止的恶意行为"), pages::interceptions(m_ipc));
    addPage("activity", u("活动日志"), u("活动日志"), u("全部安全事件"), pages::activity(m_ipc));
    addPage("clock", u("事件时间线"), u("事件时间线"), u("按时间回溯 · 攻击关系图"), pages::timeline(m_ipc));
    addPage("target", u("进程管理"), u("进程管理"), u("在跑进程 · 服务与计划任务溯源"), pages::processes(m_ipc));
    addPage("sliders", u("防护规则"), u("防护规则"), u("自定义放行 / 拦截策略"), pages::rules(m_ipc));
    addPage("trust", u("信任名单"), u("信任名单"), u("受信任的程序与目录"), pages::trust(m_ipc));
    addPage("lock", u("隔离区"), u("隔离区"), u("已隔离的威胁文件"), pages::quarantine(m_ipc));
    addPage("power", u("自启动项"), u("自启动项"), u("开机持久化审计"), pages::persistence(m_ipc));
    addPage("trash", u("垃圾清理"), u("垃圾清理"), u("按类别扫描 · 勾选后清理"), new CleanupPage(m_ipc));
    addPage("cloud", u("云信誉"), u("云信誉"), u("多引擎哈希信誉查询"), pages::reputation(m_ipc));
    addPage("link", u("攻击链"), u("攻击链"), u("动作组合定性 · 命中记录"), pages::attackChain(m_ipc));
    addPage("sparkles", u("AI 研判"), u("AI 研判"), u("大模型行为研判"), pages::aiScan(m_ipc));
    addPage("settings", u("设置"), u("设置"), u("防护与情报配置"), pages::settings(m_ipc));

    if (auto* b = m_navGroup->button(0))
        b->setChecked(true);
    onNavClicked(0);

    // Corner toast notifications (block / AI-scan) + the system tray presence.
    m_toasts = new ToastNotifier(this);
    connect(m_toasts, &ToastNotifier::blockToastClicked, this,
            [this] { showFromTray(); navigateTo(QStringLiteral("shield-x")); });
    // 点攻击链 toast -> 跳到「攻击链」页面看完整命中记录("link" 即该页的导航图标)。
    connect(m_toasts, &ToastNotifier::attackChainToastClicked, this,
            [this] { showFromTray(); navigateTo(QStringLiteral("link")); });
    setupTray();

    // Live named-pipe link to the service. Drives the connection pill, pops the
    // behavior prompt when a verdict is needed, and raises toast notifications
    // for outright blocks and AI-scan research. (m_ipc was created above so the
    // pages could bind to it; we connect the window-level slots and start here.)
    connect(m_ipc, &IpcClient::connectionChanged, this, &MainWindow::setConnected);
    connect(m_ipc, &IpcClient::promptReceived, this, &MainWindow::onPromptReceived);
    connect(m_ipc, &IpcClient::blockNotification, this, &MainWindow::onBlockNotification);
    connect(m_ipc, &IpcClient::attackChainHit, this, &MainWindow::onAttackChainHit);
    connect(m_ipc, &IpcClient::aiScanStarted, this, &MainWindow::onAiScanStarted);
    connect(m_ipc, &IpcClient::remediationReport, this, &MainWindow::onRemediationReport);
    // Keep the prompt-timeout + default verdict in sync with the service so the
    // behavior prompt can auto-decide on timeout (honours PromptTimeoutSeconds).
    connect(m_ipc, &IpcClient::settingsReceived, this,
            [this](const bulwark::RuntimeSettings& s) {
                m_promptTimeoutSeconds = s.promptTimeoutSeconds;
                m_defaultBlock = s.defaultBlock;
            });
    // Centered "cloud scan in progress" card (ports the .NET AiScanToastWindow):
    // VT double-click/dropped-payload scans push live progress + verdict here, and
    // the AI research result finalizes the same card.
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
    connect(m_ipc, &IpcClient::aiScanRecord, this,
            [](const AiScanResult& r) { ScanProgressWindow::aiResult(r); });
    connect(m_ipc, &IpcClient::manualQuarantineResult, this,
            [this](const bulwark::ipc::ManualQuarantineResultPayload& r) {
                if (m_tray && QSystemTrayIcon::isSystemTrayAvailable())
                    m_tray->showMessage(QString::fromUtf8("重试隔离"), r.message,
                                        r.success ? QSystemTrayIcon::Information : QSystemTrayIcon::Warning, 4000);
            });

    // 「启动后自动检查」的结果落在这里。刻意只弹一次托盘气泡,不自动打开弹窗、更不自动下载:
    // 更新会替换内核驱动,那必须由用户按下按钮才发生。
    //
    // 三道抑制,针对的都是「变成骚扰」这一个失败形态:
    //   查失败 / 没有新版本 -> 什么都不说。用户没主动问,就不该被告知「检查失败了」。
    //   弹窗正开着          -> 那是用户自己点的检查,结论已经写在弹窗里,再弹气泡是噪音。
    //   本会话已经弹过      -> 服务端每个生命周期只自动查一次,但界面可能重连,不设闸门
    //                          就会每次重连都弹一遍。
    connect(m_ipc, &IpcClient::updateCheckReceived, this,
            [this](const bulwark::ipc::UpdateCheckResponsePayload& p) {
                if (!p.ok || !p.available) return;
                if (UpdateDialog::isAnyOpen()) return;
                if (m_updateBalloonShown) return;
                if (!m_tray || !QSystemTrayIcon::isSystemTrayAvailable()) return;
                m_updateBalloonShown = true;
                m_tray->showMessage(
                    QString::fromUtf8("有新版本 ") + p.version,
                    QString::fromUtf8("当前 ") + p.currentVersion
                        + QString::fromUtf8("。在「设置 > 关于与更新」里查看更新说明并安装。"),
                    QSystemTrayIcon::Information, 6000);
            });

    // 中央信誉服务在线状态灯:连接后 + 每 30s 探测一次(source=ReputationProxy 定向探测代理
    // /health,服务端非阻塞返回),按 requestId 回填侧栏状态。离线仅提示,本地直连情报源照常兜底。
    m_repTimer = new QTimer(this);
    m_repTimer->setInterval(30000);
    connect(m_repTimer, &QTimer::timeout, this, &MainWindow::pingReputation);
    connect(m_ipc, &IpcClient::vtResponse, this,
            [this](const bulwark::ipc::VtResponsePayload& resp) {
                if (m_repPingId.isNull() || resp.requestId != m_repPingId)
                    return; // 只认本窗口发起的健康探测;各页自身的查询 / 测试连接自动忽略
                m_repPingId = QUuid();
                const bool online = resp.success;
                const bool checking = !online && resp.message.contains(QString::fromUtf8("检测中"));
                // 「限流中」是在线的一种:链路好着,只是服务端对本出口 IP 的配额暂时用满,
                // 本地直连情报照常兜底。单独画成警示色,别再和「离线」混为一谈 —— 以前服务端
                // 一回 429 就报离线,而不受限流管辖的 /health 仍是 200,状态灯于是来回跳。
                const bool throttled = online && resp.message.contains(QString::fromUtf8("限流"));
                ui::stylePill(m_repPill,
                              throttled ? QString::fromUtf8("◐ 信誉服务限流中")
                                        : (online ? QString::fromUtf8("● 信誉服务在线")
                                                  : (checking ? QString::fromUtf8("○ 信誉服务检测中")
                                                              : QString::fromUtf8("○ 信誉服务离线"))),
                              throttled ? theme::warning()
                                        : (online ? theme::success()
                                                  : (checking ? theme::textMuted() : theme::danger())));
                m_repPill->setToolTip(resp.message.isEmpty()
                                          ? (online ? QString::fromUtf8("中央信誉服务连接正常")
                                                    : QString::fromUtf8("中央信誉服务不可达,已回退本地直连"))
                                          : resp.message);
                if (checking) // 尚无结论(缓存预热中),稍后再探一次尽快收敛
                    QTimer::singleShot(4000, this, &MainWindow::pingReputation);
            });
    m_ipc->start();
}

QWidget* MainWindow::buildSidebar()
{
    auto* bar = new QFrame;
    bar->setObjectName(QStringLiteral("Sidebar"));
    bar->setFixedWidth(theme::metric::sidebarW);

    auto* v = new QVBoxLayout(bar);
    v->setContentsMargins(16, 20, 16, 16);
    v->setSpacing(0);

    // brand
    auto* brand = new QHBoxLayout;
    brand->setSpacing(11);
    auto* logo = new AppIcon(QStringLiteral("shield"));
    logo->setColor(theme::accent());
    logo->setPx(28);
    logo->setFixedSize(30, 30);
    brand->addWidget(logo);
    auto* bt = new QVBoxLayout;
    bt->setSpacing(0);
    bt->addWidget(ui::label(QString::fromUtf8("磐垒"), "title"));
    bt->addWidget(ui::label(QString::fromUtf8("主动防御"), "caption"));
    brand->addLayout(bt);
    brand->addStretch();
    v->addLayout(brand);
    v->addSpacing(22);

    // nav items host。导航项已有 13 项(仪表盘 / 拦截记录 / 活动日志 / 事件时间线 / 进程管理 /
    // 防护规则 / 信任名单 / 隔离区 / 自启动项 / 云信誉 / 攻击链 / AI 研判 / 设置),在最小窗口
    // 高度(620)下会挤不下,故放进一个无边框透明滚动区:窗口够高时看不出区别,不够高时可滚动,
    // 而不是把底部的连接状态条挤掉。
    auto* navHost = new QWidget;
    navHost->setStyleSheet(QStringLiteral("background:transparent;"));
    m_navLayout = new QVBoxLayout(navHost);
    m_navLayout->setContentsMargins(0, 0, 0, 0);
    m_navLayout->setSpacing(3);
    m_navLayout->addStretch(); // 末尾留一个弹簧,导航项始终顶部对齐(addPage 插在它之前)

    auto* navScroll = new QScrollArea;
    navScroll->setWidgetResizable(true);
    navScroll->setFrameShape(QFrame::NoFrame);
    navScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    navScroll->setStyleSheet(QStringLiteral("QScrollArea{background:transparent;}"));
    navScroll->viewport()->setStyleSheet(QStringLiteral("background:transparent;"));
    navScroll->setWidget(navHost);
    v->addWidget(navScroll, 1);

    v->addWidget(ui::hDivider());
    v->addSpacing(12);
    m_connPill = ui::pill(QString::fromUtf8("○ 未连接服务"), theme::textMuted());
    v->addWidget(m_connPill, 0, Qt::AlignLeft);
    v->addSpacing(6);
    m_repPill = ui::pill(QString::fromUtf8("○ 信誉服务未知"), theme::textMuted());
    m_repPill->setToolTip(QString::fromUtf8(
        "中央信誉服务(云端共享缓存 + 多引擎)连接状态。离线时本地直连情报源自动兜底,实时防护不受影响。"));
    v->addWidget(m_repPill, 0, Qt::AlignLeft);
    v->addSpacing(8);
    // 版本串来自 bulwark/Version.h —— 与 exe 的 VERSIONINFO、更新清单比较用的是
    // 同一个数字。以前这里是硬编字面量,是全产品唯一的版本来源。
    v->addWidget(ui::label(bulwark::version::displayString(), "muted"));

    m_navGroup = new QButtonGroup(this);
    m_navGroup->setExclusive(true);
    connect(m_navGroup, &QButtonGroup::idClicked, this, &MainWindow::onNavClicked);
    return bar;
}

QWidget* MainWindow::buildContent()
{
    auto* content = new QFrame;
    content->setObjectName(QStringLiteral("Content"));
    auto* v = new QVBoxLayout(content);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(0);

    // topbar
    auto* top = new QFrame;
    top->setObjectName(QStringLiteral("Topbar"));
    top->setFixedHeight(theme::metric::topbarH);
    auto* h = new QHBoxLayout(top);
    h->setContentsMargins(theme::metric::pagePad, 0, theme::metric::pagePad, 0);

    auto* tcol = new QVBoxLayout;
    tcol->setSpacing(1);
    m_title = ui::label(QString(), "h1");
    m_subtitle = ui::label(QString(), "secondary");
    tcol->addWidget(m_title);
    tcol->addWidget(m_subtitle);
    h->addLayout(tcol);
    h->addStretch();

    h->addWidget(ui::pill(QString::fromUtf8("● 防护开启"), theme::success()));
    v->addWidget(top);

    m_stack = new QStackedWidget;
    v->addWidget(m_stack, 1);
    return content;
}

void MainWindow::addPage(const QString& icon, const QString& nav,
                         const QString& title, const QString& subtitle, QWidget* page)
{
    const int idx = m_stack->count();
    auto* btn = new NavButton(icon, nav);
    // 插在末尾弹簧之前,保持导航项顶部对齐。
    m_navLayout->insertWidget(std::max(0, m_navLayout->count() - 1), btn);
    m_navGroup->addButton(btn, idx);
    m_stack->addWidget(page);
    m_titles << title;
    m_subtitles << subtitle;
    m_pageKeys << icon; // the icon name doubles as a stable page key
}

void MainWindow::navigateTo(const QString& pageKey)
{
    const int idx = m_pageKeys.indexOf(pageKey);
    if (idx < 0)
        return;
    if (auto* b = m_navGroup->button(idx))
        b->setChecked(true);
    onNavClicked(idx);
}

void MainWindow::onNavClicked(int index)
{
    if (index < 0 || index >= m_stack->count())
        return;
    m_stack->setCurrentIndex(index);
    m_title->setText(m_titles.value(index));
    m_subtitle->setText(m_subtitles.value(index));
}

void MainWindow::onPromptReceived(const bulwark::SecurityEvent& event)
{
    // Arm the auto-decision countdown from the live settings: if the user doesn't
    // respond within PromptTimeoutSeconds, close with the default policy
    // (defaultBlock ? 拦截 : 放行) so a prompt never lingers forever.
    PromptDialog dlg(event, this, m_promptTimeoutSeconds, !m_defaultBlock);
    dlg.exec();
    const auto action = dlg.allowed() ? bulwark::VerdictAction::Allow
                                      : bulwark::VerdictAction::Block;
    m_ipc->sendVerdict(event.id, action, dlg.remember(),
                       static_cast<bulwark::RememberScope>(dlg.scopeIndex()));
}

void MainWindow::setConnected(bool connected)
{
    ui::stylePill(m_connPill,
                  connected ? QString::fromUtf8("● 已连接服务")
                            : QString::fromUtf8("○ 未连接服务"),
                  connected ? theme::success() : theme::textMuted());
    // Refresh prompt-timeout / default-action the moment the link comes up, so a
    // prompt arriving right after connect already has the correct countdown.
    if (connected && m_ipc) {
        m_ipc->requestSettings();
        pingReputation();                    // 立即探一次中央信誉服务
        if (m_repTimer) m_repTimer->start();  // 之后每 30s 复探
    } else {
        if (m_repTimer) m_repTimer->stop();
        m_repPingId = QUuid();
        if (m_repPill) // 与服务断链时无从得知代理状态,置灰
            ui::stylePill(m_repPill, QString::fromUtf8("○ 信誉服务未知"), theme::textMuted());
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

void MainWindow::onBlockNotification(const bulwark::SecurityEvent& event)
{
    if (m_toasts)
        m_toasts->showBlock(event);
}

void MainWindow::onAttackChainHit(const bulwark::ipc::AttackChainHitPayload& hit)
{
    // 这条通知【不看静默模式】—— 服务端已按 attackChainToast 开关决定要不要发,
    // UI 收到就显示。理由见 RuntimeSettings::attackChainToast 处的说明:
    // 静默模式把询问降级成放行,恰好造出「命中了但用户毫不知情」的盲区。
    if (m_toasts)
        m_toasts->showAttackChain(hit);
}

void MainWindow::onAiScanStarted(const bulwark::SecurityEvent& event)
{
    // Centered progress card (with countdown) instead of the old one-shot corner
    // toast — matches the .NET experience and pairs with the VT scan updates.
    ScanProgressWindow::aiStart(event);
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
    // and how many items couldn't be cleaned. Shown as a tray balloon (the report
    // detail also rides the event/audit log on the service side).
    const QString name = QFileInfo(report.actorPath).fileName();
    QString body = QString::fromUtf8("%1:隔离 %2 文件 · 移除 %3 持久化")
                       .arg(name.isEmpty() ? report.reason : name)
                       .arg(report.quarantinedFiles.size())
                       .arg(report.removedRegistryValues.size());
    if (!report.skipped.isEmpty())
        body += QString::fromUtf8(" · %1 项未清理").arg(report.skipped.size());
    if (m_tray && QSystemTrayIcon::isSystemTrayAvailable())
        m_tray->showMessage(QString::fromUtf8("已清理恶意足迹"), body,
                            QSystemTrayIcon::Information, 5000);

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

    auto u = [](const char* s) { return QString::fromUtf8(s); };

    m_tray = new QSystemTrayIcon(this);
    m_tray->setIcon(buildTrayIcon());
    m_tray->setToolTip(u("磐垒主动防御 — 防护运行中"));

    auto* menu = new QMenu(this);
    auto* actShow = menu->addAction(u("显示主界面"));
    auto* actScan = menu->addAction(u("立即扫描"));
    menu->addSeparator();
    auto* actQuit = menu->addAction(u("退出磐垒防护"));
    connect(actShow, &QAction::triggered, this, &MainWindow::showFromTray);
    connect(actScan, &QAction::triggered, this, [this] {
        showFromTray();
        navigateTo(QStringLiteral("sparkles"));
    });
    connect(actQuit, &QAction::triggered, this, &MainWindow::quitApp);
    m_tray->setContextMenu(menu);

    connect(m_tray, &QSystemTrayIcon::activated, this,
            [this](QSystemTrayIcon::ActivationReason reason) {
                if (reason == QSystemTrayIcon::Trigger
                    || reason == QSystemTrayIcon::DoubleClick)
                    showFromTray();
            });

    m_tray->show();

    // First appearance: point the user at the tray. Windows usually folds a new
    // app's icon into the overflow ("^") flyout, so a one-time balloon helps them
    // locate it (and learn the window minimises here instead of quitting).
    if (!m_trayBalloonShown) {
        m_trayBalloonShown = true;
        m_tray->showMessage(
            u("磐垒主动防御 · 防护运行中"),
            u("图标已在系统托盘。若未看到,请点任务栏通知区的 ‘^’ 展开;双击图标可打开主界面。"),
            QSystemTrayIcon::Information, 6000);
    }
}

void MainWindow::showFromTray()
{
    show();
    setWindowState((windowState() & ~Qt::WindowMinimized) | Qt::WindowActive);
    raise();
    activateWindow();
}

void MainWindow::quitApp()
{
    // UI 关闭时自动停止服务和卸载驱动
    if (!qEnvironmentVariableIsEmpty("BULWARK_UI_SMOKE")) {
        // 冒烟测试模式不执行关闭清理
    } else {
        bulwark::ui::bootstrap::shutdownBackend();
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
        if (!m_trayHintShown) {
            m_trayHintShown = true;
            m_tray->showMessage(
                QString::fromUtf8("磐垒仍在后台防护"),
                QString::fromUtf8("已最小化到系统托盘,防护持续运行。右键托盘图标可退出。"),
                QSystemTrayIcon::Information, 4000);
        }
        return;
    }
    // No tray (or a real quit): accept the close and make sure the app exits,
    // since we disabled quit-on-last-window-closed for the tray lifecycle.
    event->accept();
    qApp->quit();
}
