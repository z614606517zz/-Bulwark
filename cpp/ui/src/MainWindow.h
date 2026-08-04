#pragma once
#include <QStringList>
#include <QUuid>
#include <QWidget>

class QStackedWidget;
class QButtonGroup;
class QLabel;
class QVBoxLayout;
class QCloseEvent;
class QSystemTrayIcon;
class QTimer;
class IpcClient;
class ToastNotifier;

namespace bulwark {
struct SecurityEvent;
namespace ipc {
struct RemediationReportPayload;
struct AttackChainHitPayload;
}
}

// Top-level application window: a fixed navigation rail on the left and a
// stacked content area (topbar + page stack) on the right. Lives in the system
// tray — closing the window hides it and protection keeps running in the
// background; the tray menu restores it or quits for real.
class MainWindow : public QWidget
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;

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
    void addPage(const QString& icon, const QString& nav,
                 const QString& title, const QString& subtitle, QWidget* page);
    void setupTray();
    void navigateTo(const QString& pageKey);
    void pingReputation(); // 探测中央信誉服务是否在线,回填侧栏状态灯

    QStackedWidget* m_stack = nullptr;
    QButtonGroup* m_navGroup = nullptr;
    QVBoxLayout* m_navLayout = nullptr;
    QLabel* m_title = nullptr;
    QLabel* m_subtitle = nullptr;
    QLabel* m_connPill = nullptr;
    QLabel* m_repPill = nullptr;   // 中央信誉服务在线/离线状态灯
    QTimer* m_repTimer = nullptr;  // 周期性健康探测
    QUuid m_repPingId;             // 当前在途健康探测的 requestId(只认自己发起的响应)
    IpcClient* m_ipc = nullptr;
    QSystemTrayIcon* m_tray = nullptr;
    ToastNotifier* m_toasts = nullptr;
    QStringList m_titles;
    QStringList m_subtitles;
    QStringList m_pageKeys;
    bool m_forceQuit = false;
    bool m_trayHintShown = false;    // close-to-tray hint (shown once on first close)
    bool m_trayBalloonShown = false; // startup "here's the tray icon" balloon (once)
    int m_trayRetries = 0;           // setupTray() retry budget while the tray warms up

    // Live copies of the service's prompt policy, used to arm the behavior
    // prompt's auto-decision countdown (PromptTimeoutSeconds / default verdict).
    int m_promptTimeoutSeconds = 30;
    bool m_defaultBlock = false;
};
