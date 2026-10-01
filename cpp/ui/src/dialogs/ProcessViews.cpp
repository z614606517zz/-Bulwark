#include "dialogs/ProcessViews.h"
#include "dialogs/EventFormat.h"
#include "dialogs/EventViews.h"
#include "dialogs/ProcessDetailDialog.h"
#include "design/Banner.h"
#include "design/Components.h"
#include "design/Confirm.h"
#include "design/Format.h"
#include "design/Icons.h"
#include "design/Inspector.h"
#include "design/Theme.h"
#include "ipc/IpcClient.h"
#include "widgets/WrapLabel.h"
#include "Nav.h"

#include <QDesktopServices>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QUrl>
#include <QVBoxLayout>

using evtfmt::u;
using Kind = bulwark::ipc::ProcessActionKind;

namespace {

QString who(const bulwark::ProcessEntry& e)
{
    return QStringLiteral("%1 (PID %2)\n%3").arg(e.name).arg(e.pid).arg(evtfmt::nativePath(e.imagePath));
}

void copyText(const QString& text)
{
    if (QClipboard* cb = QGuiApplication::clipboard())
        cb->setText(text);
}

// SHA-256 row with its on-demand 「计算」: hashing hundreds of processes for the
// list would be pointless, so only the one being looked at is hashed, on request.
QWidget* hashRow(const bulwark::ProcessEntry& e, IpcClient* ipc)
{
    auto* row = new QWidget;
    auto* h = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(10);
    auto* k = ui::label(QStringLiteral("SHA-256"), "caption");
    k->setFixedWidth(74);
    h->addWidget(k, 0, Qt::AlignTop);
    auto* val = new WrapLabel(e.sha256.isEmpty() ? u("未计算") : e.sha256);
    val->setProperty("role", e.sha256.isEmpty() ? "secondary" : "mono");
    h->addWidget(val, 1);
    auto* calc = ui::button(u("计算"), "ghost", QString(), true);
    calc->setEnabled(ipc && !e.imagePath.isEmpty() && e.sha256.isEmpty());
    if (e.imagePath.isEmpty())
        calc->setToolTip(u("取不到映像路径,无法计算"));
    h->addWidget(calc, 0, Qt::AlignTop);
    const int pid = e.pid;
    const QString image = e.imagePath;
    QObject::connect(calc, &QPushButton::clicked, row, [row, val, calc, ipc, pid, image] {
        if (!ipc || !ipc->isConnected()) {
            val->setText(u("未连接后台服务,无法计算"));
            return;
        }
        calc->setEnabled(false);
        val->setText(u("计算中…"));
        bulwark::ipc::ProcessActionRequestPayload p;
        p.kind = Kind::ComputeHash;
        p.pid = pid;
        p.imagePath = image;
        const QUuid rid = p.requestId;
        QObject::connect(ipc, &IpcClient::processActionResult, row,
                         [val, calc, rid](const bulwark::ipc::ProcessActionResultPayload& r) {
            if (r.requestId != rid)
                return;
            ui::setRole(val, r.success ? "mono" : "secondary");
            val->setText(r.success ? r.sha256 : (r.message.isEmpty() ? u("计算失败") : r.message));
            calc->setEnabled(!r.success);
        });
        ipc->processAction(p);
    });
    return row;
}

// "由服务 Schedule(Task Scheduler)启动,以 SYSTEM 身份运行。" — only when the
// launcher is known; the user alone isn't worth a headline.
QString launchSentence(const bulwark::ProcessEntry& e)
{
    using O = bulwark::ProcessOriginKind;
    QString s;
    if (e.originKind == O::Service && !e.originService.isEmpty())
        s = u("由服务 %1 启动").arg(e.originServiceDisplay.isEmpty()
                                         ? e.originService
                                         : QStringLiteral("%1(%2)").arg(e.originService, e.originServiceDisplay));
    else if (e.originKind == O::ScheduledTask && !e.originTask.isEmpty())
        s = u("由计划任务 %1 启动").arg(e.originTask);
    else if (e.parentPid > 0)
        s = u("由 %1 (PID %2) 启动").arg(e.parentName.isEmpty() ? u("进程") : e.parentName).arg(e.parentPid);
    if (s.isEmpty())
        return QString();
    if (!e.userName.isEmpty())
        s += u(",以 %1 身份运行").arg(e.userName);
    return s + u("。");
}

} // namespace

namespace procview {

Hint hint(const bulwark::ProcessEntry& e)
{
    if (e.isProtectedSelf)
        return {u("本软件组件"), theme::info(), -3};
    if (e.isTrusted)
        return {u("已信任"), theme::success(), -2};
    if (e.isCritical)
        return {u("关键进程"), theme::info(), -1};
    if (e.riskScore >= 50)
        return {u("留意 %1").arg(e.riskScore), evtfmt::riskColor(e.riskScore), e.riskScore};
    if (e.riskScore > 0)
        return {u("提示 %1").arg(e.riskScore), theme::warning(), e.riskScore};
    return {u("正常"), theme::textMuted(), 0};
}

QColor tone(const bulwark::ProcessEntry& e)
{
    const Hint h = hint(e);
    if (h.rank > 0)
        return h.color;
    if (e.isTrusted)
        return theme::success();
    if (e.isProtectedSelf || e.isCritical)
        return theme::info();
    return evtfmt::originColor(e.originKind);
}

QString signatureText(const bulwark::ProcessEntry& e)
{
    if (e.signatureMismatch)
        return u("签名失配");
    return e.isSigned ? u("已签名") : u("无签名");
}

QColor signatureColor(const bulwark::ProcessEntry& e)
{
    if (e.signatureMismatch)
        return theme::danger();
    return e.isSigned ? theme::success() : theme::textMuted();
}

QString lockReason(const bulwark::ProcessEntry& e)
{
    if (e.isProtectedSelf)
        return u("本软件组件受自我保护,不能在这里结束、挂起或隔离。");
    if (e.isCritical)
        return u("关键系统进程:结束或挂起会导致系统崩溃(蓝屏),已禁用。");
    return QString();
}

QString searchText(const bulwark::ProcessEntry& e)
{
    return QStringList{e.name, e.imagePath, e.commandLine, e.fileDescription, e.publisher, e.userName,
                       e.originLabel(), e.originService, e.originTask, e.parentName, QString::number(e.pid),
                       e.riskReasons.join(QLatin1Char(' '))}
        .join(QLatin1Char(' '));
}

void fill(Inspector* in, const bulwark::ProcessEntry& e, IpcClient* ipc, bool actions)
{
    const Hint h = hint(e);
    in->setHeader(evtfmt::originGlyph(e.originKind), tone(e), e.name.isEmpty() ? u("未知进程") : e.name,
                  e.fileDescription.isEmpty() ? QStringLiteral("PID %1").arg(e.pid)
                                              : QStringLiteral("PID %1 · %2").arg(e.pid).arg(e.fileDescription));
    if (const QString lead = launchSentence(e); !lead.isEmpty())
        in->addLead(lead);
    QList<QPair<QString, QColor>> chips;
    chips << qMakePair(h.text, h.color);
    chips << qMakePair(e.isSigned && !e.publisher.isEmpty() ? u("已签名 · ") + e.publisher : signatureText(e),
                       signatureColor(e));
    if (e.elevated)
        chips << qMakePair(u("已提权"), theme::warning());
    chips << qMakePair(e.is64Bit ? u("64 位") : u("32 位"), theme::textMuted());
    in->addChips(nullptr, chips);

    const Inspector::FieldFlags monoCopy = Inspector::Mono | Inspector::Copy;
    QVBoxLayout* s = in->addSection(u("启动来源"));
    in->addField(s, u("判定"), e.originLabel().isEmpty() ? u("未能判定(父进程为普通进程)") : e.originLabel());
    if (!e.originService.isEmpty())
        in->addField(s, u("服务名"), e.originService, Inspector::Mono);
    if (!e.originServiceDisplay.isEmpty())
        in->addField(s, u("服务显示名"), e.originServiceDisplay);
    if (!e.originTask.isEmpty())
        in->addField(s, u("计划任务"), e.originTask, monoCopy);
    if (!e.originDetail.isEmpty())
        in->addField(s, u("依据"), e.originDetail);
    in->addField(s, u("父进程"),
                 e.parentPid > 0 ? QStringLiteral("%1 (PID %2)").arg(e.parentName.isEmpty() ? u("未知") : e.parentName)
                                       .arg(e.parentPid)
                                 : QString());

    s = in->addSection(u("身份与签名"));
    in->addField(s, u("映像路径"), evtfmt::nativePath(e.imagePath), monoCopy);
    in->addField(s, u("数字签名"),
                 e.isSigned ? (e.publisher.isEmpty() ? u("有效") : u("有效 · ") + e.publisher)
                            : (e.signatureMismatch ? u("签名失配(内嵌签名但校验失败)") : u("无 / 无效")));
    if (!e.fileDescription.isEmpty())
        in->addField(s, u("文件描述"), e.fileDescription);
    if (!e.commandLine.isEmpty())
        in->addField(s, u("命令行"), e.commandLine, monoCopy);
    s->addWidget(hashRow(e, ipc));

    s = in->addSection(u("运行状态"));
    in->addField(s, u("启动时间"), fmt::absoluteTime(e.startTimeUtc));
    in->addField(s, u("运行用户"), e.userName);
    in->addField(s, u("内存占用"), e.workingSetBytes > 0 ? fmt::bytes(e.workingSetBytes) : QString());
    in->addField(s, u("线程数"), e.threadCount > 0 ? QString::number(e.threadCount) : QString());
    in->addField(s, u("会话"), QString::number(e.sessionId));
    in->addField(s, u("完整性"), e.elevated ? u("高(已提权)") : u("普通"));

    if (!e.riskReasons.isEmpty()) {
        s = in->addSection(u("静态提示 · 非判定结论"));
        for (const QString& r : e.riskReasons)
            in->addText(s, QStringLiteral("· ") + r);
        in->addText(s,
                    u("这些是静态特征提示,单独出现不构成恶意判定,也不会触发任何自动处置。"
                      "真正的裁决只由行为规则与威胁检测在事件发生时给出。"),
                    "muted");
    }

    if (!actions)
        return;
    const QString locked = lockReason(e);
    const bulwark::ProcessEntry ent = e;
    auto* kill = in->addAction(QStringLiteral("close"), u("结束进程"), "danger",
                               [in, ipc, ent] { run(in, ipc, ent, Kind::Terminate); });
    auto* tree = in->addAction(QStringLiteral("tree"), u("结束进程树"), "ghost",
                               [in, ipc, ent] { run(in, ipc, ent, Kind::TerminateTree); });
    kill->setEnabled(locked.isEmpty());
    tree->setEnabled(locked.isEmpty());
    auto* menu = new QMenu;
    fillMenu(menu, in, e, ipc, true);
    in->addMenu(menu);
    if (!locked.isEmpty())
        in->setNote(locked, theme::textSecondary());
}

void fillMenu(QMenu* menu, QWidget* context, const bulwark::ProcessEntry& e, IpcClient* ipc, bool withDetailWindow)
{
    const bulwark::ProcessEntry ent = e;
    const QString locked = lockReason(e);
    const auto add = [menu, context](const QString& icon, const QString& text, std::function<void()> fn) {
        QAction* a = menu->addAction(icon.isEmpty() ? QIcon() : AppIcon::icon(icon, theme::textSecondary(), 16), text);
        QObject::connect(a, &QAction::triggered, context, [fn = std::move(fn)] { fn(); });
        return a;
    };

    if (withDetailWindow)
        add(QStringLiteral("maximize"), u("在独立窗口中查看"), [context, ent, ipc] { openDetail(context, ent, ipc); });
    add(QStringLiteral("link"), u("查看攻击关系图(该进程近期行为)"),
        [context, ent, ipc] { evtview::openGraph(context, ipc, QUuid(), ent.pid, ent.name); });
    add(QStringLiteral("activity"), u("在事件时间线中查看"), [pid = e.pid] {
        nav::go(QString::fromLatin1(nav::Timeline),
                {{QStringLiteral("pid"), pid}, {QStringLiteral("range"), QStringLiteral("24h")}});
    });
    menu->addSeparator();
    QAction* suspend = add(QStringLiteral("pause"), u("挂起"), [context, ipc, ent] { run(context, ipc, ent, Kind::Suspend); });
    add(QStringLiteral("play"), u("恢复"), [context, ipc, ent] { run(context, ipc, ent, Kind::Resume); });
    QAction* quarantine = add(QStringLiteral("lock"), u("结束并隔离映像…"),
                              [context, ipc, ent] { run(context, ipc, ent, Kind::QuarantineImage); });
    QAction* trustAct = add(QStringLiteral("trust"), u("加入信任名单…"),
                            [context, ipc, ent] { run(context, ipc, ent, Kind::TrustImage); });
    if (!locked.isEmpty()) {
        for (QAction* a : {suspend, quarantine}) {
            a->setEnabled(false);
            a->setToolTip(locked);
        }
    }
    if (e.imagePath.isEmpty()) {
        quarantine->setEnabled(false);
        trustAct->setEnabled(false);
        trustAct->setText(u("加入信任名单(取不到映像路径)"));
    }
    menu->setToolTipsVisible(true);
    menu->addSeparator();
    if (!e.imagePath.isEmpty()) {
        const QString path = evtfmt::nativePath(e.imagePath);
        add(QStringLiteral("copy"), u("复制映像路径"), [path] { copyText(path); });
        add(QStringLiteral("folder"), u("打开所在文件夹"), [path] {
            QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(path).absolutePath()));
        });
    }
    if (!e.commandLine.isEmpty())
        add(QStringLiteral("copy"), u("复制命令行"), [cl = e.commandLine] { copyText(cl); });
}

void run(QWidget* context, IpcClient* ipc, const bulwark::ProcessEntry& e, Kind kind)
{
    if (!ipc || !ipc->isConnected()) {
        ui::notify(context, ui::Tone::Danger, u("未连接后台服务,无法执行操作。"));
        return;
    }
    ui::ConfirmSpec s;
    s.subjectLabel = u("进程");
    s.subject = who(e);
    switch (kind) {
    case Kind::Terminate:
        s.title = u("结束进程");
        s.summary = u("将强制结束该进程,它未保存的数据会丢失。");
        s.confirmText = u("结束进程");
        break;
    case Kind::TerminateTree:
        s.risk = ui::Risk::Danger;
        s.title = u("结束进程树");
        s.summary = u("将强制结束该进程及其全部子孙进程。");
        s.consequences << u("每一个被结束的进程,未保存的数据都会丢失");
        s.confirmText = u("结束进程树");
        break;
    case Kind::Suspend:
        s.title = u("挂起进程");
        s.summary = u("将冻结该进程的所有线程,它会停止响应,直到你恢复它。");
        s.confirmText = u("挂起");
        break;
    case Kind::Resume:
        s.risk = ui::Risk::Info;
        s.title = u("恢复进程");
        s.summary = u("将恢复该进程的所有线程。");
        s.confirmText = u("恢复");
        break;
    case Kind::QuarantineImage:
        s.risk = ui::Risk::Danger;
        s.title = u("结束并隔离映像");
        s.summary = u("将先结束该进程及其子孙进程,再把它的可执行文件移入隔离区。");
        s.consequences << u("隔离可以撤销:判断有误时可在「隔离区」页还原")
                       << u("被结束的进程未保存的数据会丢失");
        s.confirmText = u("结束并隔离");
        break;
    case Kind::TrustImage:
        s.title = u("信任此程序");
        s.summary = u("信任后,该程序的所有行为都将直接放行,并跳过全部检测与后台云查毒。");
        s.consequences << u("请只信任你确认安全的程序,并核对下面的完整路径");
        s.subjectLabel = u("程序");
        s.subject = evtfmt::nativePath(e.imagePath);
        s.confirmText = u("信任此程序");
        break;
    case Kind::ComputeHash:
        return; // not a user-confirmed action (see the SHA-256 row)
    }
    if (!ui::confirm(context, s))
        return;
    bulwark::ipc::ProcessActionRequestPayload p;
    p.kind = kind;
    p.pid = e.pid;
    p.imagePath = e.imagePath;
    ipc->processAction(p);
}

void openDetail(QWidget* parent, const bulwark::ProcessEntry& e, IpcClient* ipc)
{
    auto* dlg = new ProcessDetailDialog(e, ipc, parent ? parent->window() : nullptr);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->show();
}

} // namespace procview
