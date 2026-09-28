#pragma once
#include <QColor>
#include <QHash>
#include <QList>
#include <QStringList>
#include <QUuid>
#include <QVariantMap>
#include <QWidget>

class Backdrop;
class BannerHost;
class IconTile;
class NavButton;
class QButtonGroup;
class QCloseEvent;
class QHBoxLayout;
class QLabel;
class QScrollArea;
class QStackedWidget;
class QSystemTrayIcon;
class QTimer;
class QToolButton;
class QVariantAnimation;
class QVBoxLayout;
class IpcClient;
class StatusCard;
class ToastNotifier;

namespace bulwark {
struct SecurityEvent;
namespace ipc {
struct RemediationReportPayload;
struct AttackChainHitPayload;
}
}

// Top-level application window: a navigation rail on the left (brand, grouped
// page list with unread badges, settings, the live 「防护状态」 card and a
// collapse toggle) and the content area (page header with the page's own
// actions, an in-page banner host, the page stack) on the right, both drawn on
// the design's canvas (design/Backdrop).
//
// The rail collapses to a 72 px glyph strip — on request (remembered) and
// automatically while the window is narrower than 1100 px.
//
// Lives in the system tray — closing the window hides it and protection keeps
// running in the background; the tray menu restores it or quits for real.
class MainWindow : public QWidget
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void changeEvent(QEvent* event) override;
    void showEvent(QShowEvent* event) override;

private slots:
    void onNavClicked(int index);
    void onPromptReceived(const bulwark::SecurityEvent& event);
    void onBlockNotification(const bulwark::SecurityEvent& event);
    void onAttackChainHit(const bulwark::ipc::AttackChainHitPayload& hit);
    void onAiScanStarted(const bulwark::SecurityEvent& event);
    void onRemediationReport(const bulwark::ipc::RemediationReportPayload& report);
    void setConnected(bool connected);
    void showFromTray();
    void quitApp();

private:
    QWidget* buildSidebar();
    QWidget* buildContent();
    // `key` is the stable page key (see Nav.h). `section` starts a new labelled
    // group in the rail (empty = continue the current group); `pinned` puts the
    // item in the rail's footer instead.
    void addPage(const QString& key, const QString& section, const QString& icon, const QString& nav,
                 const QString& title, const QString& subtitle, QWidget* page, bool pinned = false);
    void setupTray();
    void navigateTo(const QString& pageKey, const QVariantMap& args = QVariantMap());
    void pingReputation(); // 探测中央信誉服务是否在线,回填侧栏「防护状态」卡
    // 防护状态(侧栏卡片 + 托盘提示):按「已连接 + 总开关 + 内核」如实显示四态。
    void refreshProtectionPill();

    // ---- rail collapse ----
    void applySidebar(bool animate);
    void setSidebarCompact(bool compact);
    void toggleSidebar();

    // ---- unread badges ----
    QString currentKey() const;
    bool isViewing(const QString& key) const;
    void bumpBadge(const QString& key);
    void clearBadge(const QString& key);
    void clearViewedBadge();

    void focusPageSearch();

    QStackedWidget* m_stack = nullptr;
    QButtonGroup* m_navGroup = nullptr;
    QVBoxLayout* m_navLayout = nullptr;  // scrollable page list
    QVBoxLayout* m_navFooter = nullptr;  // pinned items (settings)
    IconTile* m_titleTile = nullptr;      // the page's glyph in its identity hue (design/Identity.h)
    QLabel* m_title = nullptr;
    QLabel* m_subtitle = nullptr;
    QHBoxLayout* m_headerActions = nullptr;
    QList<QWidget*> m_pageActions;        // per page index (nullptr = none)
    BannerHost* m_banners = nullptr;

    // rail
    Backdrop* m_sidebar = nullptr;
    QVBoxLayout* m_sidebarLayout = nullptr;
    QWidget* m_brandText = nullptr;
    QHBoxLayout* m_brandRow = nullptr;
    QList<QWidget*> m_sectionHeads;       // expanded: eyebrow labels
    QList<QWidget*> m_sectionRules;       // compact: hairlines in their place
    QList<NavButton*> m_navButtons;
    StatusCard* m_status = nullptr;
    QScrollArea* m_navScroll = nullptr;
    QToolButton* m_toggle = nullptr;
    QLabel* m_version = nullptr;
    QHBoxLayout* m_bottomRow = nullptr;
    QVariantAnimation* m_sideAnim = nullptr;
    bool m_prefCollapsed = false;  // the user's choice (persisted)
    bool m_narrow = false;         // window < 1100 px
    bool m_narrowExpand = false;   // user expanded the rail while narrow (not persisted)
    bool m_collapsed = false;      // effective state
    bool m_compactContent = false;
    bool m_sidebarReady = false;

    QHash<QString, int> m_unread;

    // 防护状态所依赖的真实状态。默认按「未知」呈现,绝不默认说"已开启"。
    bool m_svcConnected = false;
    bool m_protectionEnabled = false;
    bool m_kernelConnected = false;
    bool m_haveSettings = false;   // 是否已收到过一次真实设置(没收到就只能说"未知")
    QString m_kernelStatus;
    QTimer* m_repTimer = nullptr;  // 周期性健康探测
    QUuid m_repPingId;             // 当前在途健康探测的 requestId(只认自己发起的响应)
    IpcClient* m_ipc = nullptr;
    QSystemTrayIcon* m_tray = nullptr;
    ToastNotifier* m_toasts = nullptr;
    QStringList m_titles;
    QStringList m_subtitles;
    QStringList m_pageKeys;
    QStringList m_pageIcons;
    QList<QColor> m_pageHues;
    bool m_forceQuit = false;
    bool m_trayHintShown = false;    // close-to-tray hint (shown once on first close)
    bool m_trayBalloonShown = false; // startup "here's the tray icon" balloon (once)
    bool m_updateBalloonShown = false; // "new version available" balloon (once per session)
    int m_trayRetries = 0;           // setupTray() retry budget while the tray warms up

    // Live copies of the service's prompt policy, used to arm the behavior
    // prompt's auto-decision countdown (PromptTimeoutSeconds / default verdict).
    int m_promptTimeoutSeconds = 30;
    bool m_defaultBlock = false;
};
