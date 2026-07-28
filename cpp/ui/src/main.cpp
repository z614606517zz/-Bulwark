// Bulwark UI (磐垒主动防御) — Qt Widgets front-end entry point.
//
// A single desktop app that connects to the headless service over a named pipe
// and renders the dashboard / prompts / management pages. Pure Widgets =>
// QApplication. The global dark theme is applied once via a Qt Style Sheet.
#include "Bootstrap.h"
#include "MainWindow.h"
#include "Theme.h"
#include "dialogs/PromptDialog.h"
#include "widgets/AppIcon.h"

#include <QApplication>
#include <QBuffer>
#include <QByteArray>
#include <QDataStream>
#include <QFile>
#include <QFont>
#include <QImage>
#include <QList>
#include <QLocalServer>
#include <QLocalSocket>
#include <QPixmap>
#include <QTimer>

// Write the brand badge (teal shield) to a multi-size Windows .ico file so the
// build can embed it as the application icon (Explorer / taskbar / shortcuts).
// Each frame is stored PNG-compressed (Vista+ .ico supports this), so no image
// plugin beyond Qt's built-in PNG writer is needed. Hidden CLI: --export-icon.
static bool exportAppIco(const QString& path)
{
    const int sizes[] = {16, 20, 24, 32, 48, 64, 128, 256};
    const QIcon badge = AppIcon::appBadge();
    QList<QByteArray> frames;
    QList<int> dims;
    for (int s : sizes) {
        QPixmap pm = badge.pixmap(QSize(s, s));
        if (pm.isNull())
            continue;
        QImage img = pm.toImage().convertToFormat(QImage::Format_ARGB32);
        if (img.width() != s || img.height() != s)
            img = img.scaled(s, s, Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
        QByteArray png;
        QBuffer buf(&png);
        buf.open(QIODevice::WriteOnly);
        if (!img.save(&buf, "PNG"))
            continue;
        buf.close();
        frames.append(png);
        dims.append(s);
    }
    if (frames.isEmpty())
        return false;

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly))
        return false;
    QDataStream ds(&f);
    ds.setByteOrder(QDataStream::LittleEndian);
    const quint16 count = quint16(frames.size());
    ds << quint16(0) << quint16(1) << count;         // ICONDIR: reserved, type=icon, count
    quint32 offset = 6u + 16u * count;               // data starts after all dir entries
    for (int i = 0; i < frames.size(); ++i) {
        const int d = dims[i];
        ds << quint8(d >= 256 ? 0 : d);              // width  (0 => 256)
        ds << quint8(d >= 256 ? 0 : d);              // height (0 => 256)
        ds << quint8(0) << quint8(0);                // color count, reserved
        ds << quint16(1) << quint16(32);             // planes, bit depth
        ds << quint32(frames[i].size()) << offset;   // bytes in res, offset
        offset += quint32(frames[i].size());
    }
    for (const QByteArray& png : frames)
        f.write(png);
    f.close();
    return true;
}

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Bulwark"));
    app.setOrganizationName(QStringLiteral("Bulwark"));
    app.setWindowIcon(AppIcon::appBadge()); // default icon for all windows/dialogs + taskbar

    // Hidden build helper: `--export-icon <path>` renders the brand badge to a
    // multi-size .ico and exits (used to regenerate the embedded exe icon).
    {
        const QStringList args = app.arguments();
        const int idx = args.indexOf(QStringLiteral("--export-icon"));
        if (idx >= 0 && idx + 1 < args.size())
            return exportAppIco(args[idx + 1]) ? 0 : 1;
    }

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

    // ── 双击即用:把后台服务 + 内核驱动带起来,不用再手工 sc start / fltmc load。
    //    服务已在跑(开机自启)时这里立即返回,零 UAC、零等待;只有没跑起来才提权一次。
    //    失败/用户拒绝提权也不阻塞 —— 界面照常打开,只显示「未连接」。
    //    冒烟测试(BULWARK_UI_SMOKE)跳过,免得在构建机上弹 UAC 卡住。
    if (qEnvironmentVariableIsEmpty("BULWARK_UI_SMOKE"))
        bulwark::ui::bootstrap::ensureBackendRunning();

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
