// Bulwark UI (磐垒主动防御) — Qt Widgets front-end entry point.
//
// A single desktop app that connects to the headless service over a named pipe
// and renders the dashboard / prompts / management pages. Pure Widgets =>
// QApplication. The global dark theme is applied once via a Qt Style Sheet.
#include "MainWindow.h"
#include "Theme.h"
#include "dialogs/PromptDialog.h"
#include "widgets/AppIcon.h"

#include <QApplication>
#include <QFont>
#include <QLocalServer>
#include <QLocalSocket>
#include <QTimer>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Bulwark"));
    app.setOrganizationName(QStringLiteral("Bulwark"));
    app.setWindowIcon(AppIcon::appBadge()); // default icon for all windows/dialogs + taskbar

    // The app lives in the system tray: closing the main window hides it rather
    // than quitting, so protection notifications (and the pipe link) keep
    // running. Exit is explicit via the tray menu.
    app.setQuitOnLastWindowClosed(false);

    // ── 单实例:软件只允许一个 UI 在跑。若已有实例,通知它把窗口拉到前台(从托盘/最小化恢复),
    //    本进程随即退出,避免叠出多份 UI 与多个托盘图标。用本地套接字(命名管道)做实例间通信,
    //    键名带用户名以隔离多用户会话(RDP / 快速用户切换)。──────────────────────────────
    const QString kInstanceKey =
        QStringLiteral("BulwarkUI-Instance-") + qEnvironmentVariable("USERNAME", QStringLiteral("default"));
    {
        QLocalSocket probe;
        probe.connectToServer(kInstanceKey);
        if (probe.waitForConnected(250)) {
            // 已有实例在运行:发「显示」指令让它前置窗口,然后本进程退出(不再建第二套 UI/托盘)。
            probe.write("SHOW");
            probe.flush();
            probe.waitForBytesWritten(250);
            probe.disconnectFromServer();
            return 0;
        }
    }
    // 本进程是首个实例:清理可能残留的陈旧套接字(上次异常退出遗留)后开始监听。
    QLocalServer::removeServer(kInstanceKey);
    QLocalServer instanceServer;
    instanceServer.listen(kInstanceKey);

    QFont f(QStringLiteral("Segoe UI"), 10);
    f.setStyleStrategy(QFont::PreferAntialias);
    app.setFont(f);

    app.setStyleSheet(theme::styleSheet());

    MainWindow w;
    w.show();

    // 后续被拉起的实例会连进来:把主窗口从托盘/最小化恢复并抢到前台,让用户「再点一次」有反馈。
    QObject::connect(&instanceServer, &QLocalServer::newConnection, &w, [&instanceServer, &w] {
        while (QLocalSocket* conn = instanceServer.nextPendingConnection()) {
            QObject::connect(conn, &QLocalSocket::disconnected, conn, &QLocalSocket::deleteLater);
            w.showNormal();       // 从最小化/隐藏(托盘)恢复
            w.raise();            // 提到窗口栈顶
            w.activateWindow();   // 抢焦点
        }
    });

    // Headless smoke test: BULWARK_UI_SMOKE=1 auto-quits after a moment so the
    // build machine can confirm the app starts and paints without a human. Also
    // pops the behavior prompt so its construction/paint is exercised.
    if (!qEnvironmentVariableIsEmpty("BULWARK_UI_SMOKE")) {
        bulwark::SecurityEvent ev;
        ev.type = bulwark::EventType::RemoteThread;
        ev.actorPath = QStringLiteral("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        ev.target = QString::fromUtf8("explorer.exe (PID 2204)");
        ev.riskScore = 82;
        ev.actorSigned = true;
        ev.actorPublisher = QStringLiteral("Microsoft Windows");
        ev.commandLine = QStringLiteral("powershell -enc SQBFAFgA...");
        ev.riskReasons = {QString::fromUtf8("向系统进程注入远程线程"),
                          QString::fromUtf8("命令行经过编码混淆")};
        ev.techniques = {QStringLiteral("T1055"), QStringLiteral("T1059.001")};
        auto* dlg = new PromptDialog(ev, &w);
        dlg->show();
        QTimer::singleShot(1500, &app, &QApplication::quit);
    }

    return app.exec();
}
