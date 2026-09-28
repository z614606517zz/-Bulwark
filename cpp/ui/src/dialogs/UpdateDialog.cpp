#include "dialogs/UpdateDialog.h"

#include "ipc/IpcClient.h"
#include "design/Components.h"
#include "design/Icons.h"
#include "design/Inspector.h"
#include "design/Stepper.h"
#include "design/Theme.h"
#include "bulwark/Version.h"

#include <QDesktopServices>
#include <QDir>
#include <QHBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QTextBrowser>
#include <QUrl>
#include <QVBoxLayout>

// 这里刻意【不】包含 windows.h / shellapi.h:自从安装改由服务就地完成,本弹窗不再调用
// 任何 Win32 API。windows.h 会 #define 掉一堆常见标识符(min/max/near…),留一个用不到的
// 平台头在这里,只会在将来某次改动里突然撞上 Qt 的名字。

namespace {
QString u(const char* s) { return QString::fromUtf8(s); }

enum Step { StepCheck = 0, StepDownload = 1, StepInstall = 2, StepDone = 3 };

// 更新说明是 markdown 风格的纯文本。QTextBrowser 认 markdown,直接交给它 ——
// 自己写一个 markdown 渲染器不值得,而把 markdown 当纯文本显示会让 '##' 和 '-' 露在界面上。
QString friendlySize(qint64 bytes)
{
    if (bytes <= 0) return QString();
    const double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
    return QStringLiteral("%1 MB").arg(mb, 0, 'f', 1);
}

// "✓ 大小一致" style verified row.
QWidget* checkRow(const QString& text, const QColor& color, const QString& glyph)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(10);
    auto* g = new QLabel;
    g->setPixmap(AppIcon::pixmap(glyph, color, 16));
    g->setFixedSize(16, 16);
    h->addWidget(g, 0, Qt::AlignVCenter);
    auto* l = ui::label(text);
    l->setWordWrap(true);
    h->addWidget(l, 1);
    return w;
}
} // namespace

// 计数而不是布尔:弹窗可以嵌套出现(比如设置页里点开一个、托盘入口又开一个),
// 布尔会被先关掉的那个错误地置成 false。
int UpdateDialog::s_openCount = 0;

UpdateDialog::~UpdateDialog() { --s_openCount; }

UpdateDialog::UpdateDialog(IpcClient* ipc, QWidget* parent)
    : Sheet(parent), m_ipc(ipc), m_current(bulwark::version::current())
{
    ++s_openCount;
    setSheetWidth(580);
    setHeader(QStringLiteral("refresh-cw"), theme::info(), u("检查更新"),
              u("当前版本 ") + m_current);

    QVBoxLayout* v = body();
    v->setSpacing(12);

    m_steps = new Stepper({u("检查"), u("下载校验"), u("安装"), u("完成")});
    m_steps->setProgress(StepCheck);
    v->addWidget(m_steps);

    // Version compare, big: the one fact the user decides on first.
    m_version = ui::coloredText(QString(), 17, 700, theme::textPrimary());
    m_version->setTextFormat(Qt::RichText);
    m_version->hide();
    v->addWidget(m_version);
    m_meta = ui::label(QString(), "muted");
    m_meta->hide();
    v->addWidget(m_meta);

    m_status = ui::label(u("正在向服务器查询…"), "secondary");
    m_status->setWordWrap(true);
    m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    v->addWidget(m_status);

    m_notes = new QTextBrowser;
    m_notes->setOpenExternalLinks(true);
    m_notes->setMinimumHeight(200);
    m_notes->setVisible(false);
    m_notes->setAccessibleName(u("更新说明"));
    v->addWidget(m_notes);

    m_checklist = ui::cardAlt();
    m_checkRows = new QVBoxLayout(m_checklist);
    m_checkRows->setContentsMargins(14, 12, 14, 12);
    m_checkRows->setSpacing(8);
    m_checklist->hide();
    v->addWidget(m_checklist);

    // 细进度条不画字:「已完成 / 总数」写进上面的状态行(见 onProgress)。
    m_bar = new QProgressBar;
    m_bar->setRange(0, 100);
    m_bar->setTextVisible(false);
    m_bar->setVisible(false);
    v->addWidget(m_bar);

    m_cancel = addButton(u("取消"), "ghost");
    m_primary = addButton(u("下载"), "primary");
    m_primary->setMinimumWidth(120);
    m_primary->setEnabled(false);   // 直到确认真有新版本才可点

    connect(m_cancel, &QPushButton::clicked, this, &QDialog::reject);
    // 只连这一次,且连到成员函数。见头文件里关于 Qt::UniqueConnection + lambda 的说明。
    connect(m_primary, &QPushButton::clicked, this, &UpdateDialog::onPrimaryClicked);

    if (m_ipc) {
        connect(m_ipc, &IpcClient::updateCheckReceived, this, &UpdateDialog::onCheckResult);
        connect(m_ipc, &IpcClient::updateProgress, this, &UpdateDialog::onProgress);
        connect(m_ipc, &IpcClient::updateDownloadFinished, this, &UpdateDialog::onDownloadFinished);
        connect(m_ipc, &IpcClient::updateApplyFinished, this, &UpdateDialog::onApplyFinished);
        if (!m_ipc->isConnected()) {
            // 服务没连上时不要让弹窗停在「正在查询…」—— 那会让用户以为网络慢,
            // 实际是本地服务没起来,两件事的处置完全不同。
            m_steps->setState(StepCheck, Stepper::State::Error);
            m_status->setText(u("未连接后台服务 —— 无法检查更新。请确认 bulwark_service.exe 正在运行。"));
            m_primary->setVisible(false);
            m_cancel->setText(u("关闭"));
        } else {
            m_ipc->checkForUpdate();
        }
    }
}

void UpdateDialog::setBusy(const QString& text)
{
    m_status->setText(text);
    m_primary->setEnabled(false);
}

void UpdateDialog::onCheckResult(const bulwark::ipc::UpdateCheckResponsePayload& p)
{
    if (!p.currentVersion.isEmpty())
        m_current = p.currentVersion;
    setSubtitle(u("当前版本 ") + m_current
                + (p.endpointMasked.isEmpty() ? QString() : u("  ·  ") + p.endpointMasked));

    if (!p.ok) {
        // 服务端把「配置里关了」「端点没配」「网络不通」「HTTP 非 200」区分开了,
        // 这里直接把它给的原因显示出来,而不是笼统一句「检查更新失败」。
        m_stage = Stage::Failed;
        m_steps->setState(StepCheck, Stepper::State::Error);
        setTitle(u("检查更新失败"));
        m_status->setText(p.error.isEmpty() ? u("未知原因。") : p.error);
        m_primary->setVisible(false);
        m_cancel->setText(u("关闭"));
        refit();
        return;
    }
    if (!p.available) {
        m_stage = Stage::Failed;   // 没有可执行的下一步,主按钮隐藏
        m_steps->setState(StepCheck, Stepper::State::Done);
        for (int s = StepDownload; s <= StepDone; ++s)
            m_steps->setState(s, Stepper::State::Skipped);
        setTitle(u("已是最新版本"));
        m_status->setText(u("服务器上没有比当前版本更新的发布。"));
        m_primary->setVisible(false);
        m_cancel->setText(u("关闭"));
        refit();
        return;
    }

    setTitle(p.label.isEmpty() ? u("有新版本 ") + p.version : p.label);
    m_version->setText(QStringLiteral("<span style='color:%1'>%2</span>"
                                      "&nbsp;&nbsp;<span style='color:%3'>→</span>&nbsp;&nbsp;"
                                      "<span style='color:%4'>%5</span>")
                           .arg(theme::textSecondary().name(), m_current.toHtmlEscaped(),
                                theme::textMuted().name(), theme::accentSoft().name(),
                                p.version.toHtmlEscaped()));
    m_version->setAccessibleName(u("从 %1 更新到 %2").arg(m_current, p.version));
    m_version->show();
    QStringList meta;
    if (p.totalBytes > 0) meta << friendlySize(p.totalBytes);
    if (!p.files.isEmpty()) meta << u("%1 个文件").arg(p.files.size());
    if (!p.publishedUtc.isEmpty()) meta << u("发布于 ") + p.publishedUtc;
    m_meta->setText(meta.join(u("  ·  ")));
    m_meta->setVisible(!meta.isEmpty());
    m_status->setText(u("先读更新说明,再决定是否下载。下载后会逐个校验大小、SHA-256 与数字签名,"
                        "签名者不符一律拒绝安装。"));

    if (!p.notes.trimmed().isEmpty()) {
        m_notes->setMarkdown(p.notes);
        m_notes->setVisible(true);
    }
    m_stage = Stage::Available;
    m_steps->setProgress(StepDownload);
    m_primary->setText(u("下载"));
    m_primary->setVisible(true); // may have been hidden by an earlier "not connected" state
    m_primary->setEnabled(true);
    m_primary->setDefault(true);
    m_primary->setFocus();
    m_cancel->setText(u("取消"));
    refit();
}

void UpdateDialog::onPrimaryClicked()
{
    switch (m_stage) {
    case Stage::Available:
        if (!m_ipc)
            return;
        m_stage = Stage::Downloading;
        m_steps->setProgress(StepDownload);
        m_bar->setVisible(true);
        m_bar->setRange(0, 0);        // 服务端还没报进度前先走不确定态,而不是停在 0%
        setBusy(u("正在下载并校验…"));
        m_ipc->downloadUpdate();
        refit();
        break;
    case Stage::Downloaded: {
        // 替换由【服务自身】就地完成:UI 不提权、不启动脚本、不碰安装目录。
        //
        // 曾经的做法是 UI 拉起一个提权脚本去换文件。那条路走不通,而原因不是某个 bug,
        // 是方向错了:脚本是外部进程,而本产品会自我保护,于是它每一步都被自己挡下 ——
        //   · 写安装目录        -> 内核 SelfGuard 只放行本产品自身进程;
        //   · 结束本产品进程    -> 同样被拒,而 Stop-Process 的失败是静默的,脚本以为成功了;
        //   · 跑脚本的 powershell -> 被攻击链检测判成勒索软件并内核封禁。
        // 服务自身正是 SelfGuard 放行的那个主体,而「旧映像改名让位」不需要结束任何进程。
        //
        // 那条提权分支已经整段删除,不留作兜底:留着它意味着这个按钮有两种可能的行为,
        // 而界面上只能写一种文案 —— 这正是上一版「说要提权、实际没有提权框」的来源。
        //
        // 删掉的代码里有两条值得留下的教训,都是「上层报成功、实际什么都没跑」:
        //   1) QProcess + cmd.exe /c —— cmd 会把 /c 之后整段的首尾两个引号去掉,路径含
        //      空格就在空格处断开;而 cmd.exe 自身启动成功,于是调用方看到「成功」。
        //   2) ShellExecuteEx 打 .bat —— 看着绕过了 cmd,其实没有:.bat 的 runas 关联
        //      (HKCR\batfile\shell\runas\command)本身就是 cmd.exe /C "%1" %*,又回到第 1 条。
        // 结论:凡是「点了没反应」,先怀疑中间层吞掉了失败,别信上层的返回值。
        if (!m_ipc) {
            // 理论上到不了这里:没有 IPC 就下载不了,也就不会进入 Downloaded。
            // 真到了也别摆一个点下去没反应的按钮。
            if (!m_stagingDir.isEmpty())
                QDesktopServices::openUrl(QUrl::fromLocalFile(m_stagingDir));
            break;
        }
        m_stage = Stage::Downloading;   // 复用忙态:按钮禁用 + 状态文字
        m_steps->setProgress(StepInstall);
        setBusy(u("正在安装…"));
        m_bar->setVisible(true);
        m_bar->setRange(0, 0);
        m_ipc->applyUpdate();
        refit();
        break;
    }
    default:
        break;   // 检查中 / 下载中 / 已失败:按钮此时是禁用的,不该走到这里
    }
}

void UpdateDialog::onProgress(const bulwark::ipc::UpdateProgressPayload& p)
{
    m_bar->setVisible(true);
    QString count;
    if (p.total > 0) {
        m_bar->setRange(0, p.total);
        m_bar->setValue(p.done);
        count = QStringLiteral("  (%1 / %2)").arg(p.done).arg(p.total);
    }
    m_status->setText(p.stage + (p.fileName.isEmpty() ? QString() : u("  ") + p.fileName) + count);
}

void UpdateDialog::showChecklist(int files)
{
    Inspector::clearLayout(m_checkRows);
    // 只有服务端判定四道校验全部通过(ok=true)时才会走到这里,所以每一项都是「已通过」。
    m_checkRows->addWidget(checkRow(u("大小与清单一致"), theme::success(), QStringLiteral("check-circle")));
    m_checkRows->addWidget(checkRow(QStringLiteral("SHA-256 与清单一致"), theme::success(), QStringLiteral("check-circle")));
    m_checkRows->addWidget(checkRow(u("数字签名有效,签名者在钉死名单内"), theme::success(), QStringLiteral("check-circle")));
    m_checkRows->addWidget(checkRow(u("共 %1 个文件通过校验").arg(files), theme::info(), QStringLiteral("file")));
    m_checklist->show();
}

void UpdateDialog::onDownloadFinished(const bulwark::ipc::UpdateDownloadResponsePayload& p)
{
    m_bar->setVisible(false);
    if (!p.ok) {
        m_stage = Stage::Failed;
        m_steps->setState(StepDownload, Stepper::State::Error);
        setTitle(u("更新未能完成"));
        // 校验失败的原因必须原样显示。「签名者不在钉死名单内」和「网络中断」是两件
        // 性质完全不同的事:后者重试即可,前者意味着拿到的文件不是我们发的。
        m_status->setText(p.error.isEmpty() ? u("下载或校验失败。") : p.error);
        m_primary->setVisible(false);
        m_cancel->setText(u("关闭"));
        refit();
        return;
    }

    m_stagingDir = p.stagingDir;
    m_stage = Stage::Downloaded;
    m_steps->setProgress(StepInstall);
    m_notes->setVisible(false);
    setTitle(u("已下载并校验通过"));
    showChecklist(p.verified);

    // 这里【不再】去找包内的「更新.bat」。安装由服务就地完成,和包里有没有那个脚本
    // 毫无关系 —— 而上一版会在找不到它时把主按钮改成「打开文件夹」,于是用户明明能装,
    // 界面上却根本没有「立即安装」这个选项(用户报的「点不了自动安装」就是这个)。
    //
    // 文案也必须与实际发生的事一致:不会弹提权框、不会停防护。上一版写着「会请求管理员
    // 权限,然后停止防护」,而实际两件都不发生 —— 用户等不到 UAC,只会认为按钮坏了。
    m_status->setText(u("点「立即安装」由后台服务就地替换程序文件:")
                      + u("不需要管理员授权,不会弹出授权框,防护全程不中断。")
                      + u("\n新版本在下次启动时生效;任一步失败都会回退,当前版本不受影响。"));
    m_primary->setText(u("立即安装"));
    m_primary->setEnabled(true);
    m_primary->setFocus();
    m_cancel->setText(u("关闭"));
    refit();
}

void UpdateDialog::onApplyFinished(const bulwark::ipc::UpdateApplyResponsePayload& p)
{
    m_bar->setVisible(false);
    m_notes->setVisible(false);

    if (!p.ok) {
        // 失败原因原样显示。「安装失败」这四个字曾经把排查带偏过一整轮 —— 真实原因是
        // 服务没被杀掉导致 exe 被锁,而从那句话上完全看不出来。
        setTitle(u("更新未能完成"));
        m_steps->setState(StepInstall, Stepper::State::Error);
        QString s = p.error.isEmpty() ? u("安装失败。") : p.error;
        if (p.rolledBack)
            s += u("\n\n安装目录已还原,当前版本一个字节都没有改动。");
        m_status->setText(s);
        // 允许重试:失败后把按钮藏掉等于逼用户重开界面。
        m_stage = Stage::Downloaded;
        m_primary->setText(u("重试安装"));
        m_primary->setEnabled(true);
        m_cancel->setText(u("关闭"));
        refit();
        return;
    }

    m_stage = Stage::Failed;   // 终态:不留可重复点击的按钮
    m_steps->setProgress(StepDone + 1);
    m_primary->setVisible(false);
    m_cancel->setText(u("关闭"));
    setTitle(u("更新已安装"));

    // needsRestart 恒为真,而且【不代表出了问题】。替换用的是「旧映像改名让位、新文件
    // 放到原名」,正在跑的进程仍从改名后的文件执行 —— 所以必须如实说明新版本要下次启动
    // 才生效,否则用户会以为点完就已经在跑新版了,下次看到版本号还是旧的会更困惑。
    QString s = u("已替换 ") + QString::number(p.replaced) + u(" 个文件");
    if (!p.version.isEmpty()) s += u("(") + p.version + u(")");
    s += u("。\n\n");
    if (p.needsRestart) {
        s += u("新版本将在下次启动时生效 —— 现在运行的仍是旧版本,防护没有中断过。\n")
             + u("重启防护:关闭界面后重新双击 启动Bulwark.bat;或者重启一次机器。");
    }
    m_status->setText(s);
    refit();
}
