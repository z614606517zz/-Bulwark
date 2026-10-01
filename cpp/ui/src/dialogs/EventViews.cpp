#include "dialogs/EventViews.h"
#include "dialogs/AttackGraphWindow.h"
#include "dialogs/AttackTimelineWindow.h"
#include "dialogs/EventFormat.h"
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

#include <QDir>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPainter>
#include <QRegularExpression>
#include <QTimer>
#include <QVBoxLayout>

using evtfmt::u;

namespace {

// A dot on a vertical rail: the steps of a chain read as one thread.
class RailDot : public QWidget
{
public:
    RailDot(const QColor& color, bool first, bool last, bool strong)
        : m_color(color), m_first(first), m_last(last), m_strong(strong)
    {
        setFixedWidth(14);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const qreal cx = width() / 2.0;
        const qreal cy = 9.0;
        p.setPen(QPen(theme::borderStrong(), 1.4));
        if (!m_first)
            p.drawLine(QPointF(cx, 0.0), QPointF(cx, cy - 5.0));
        if (!m_last)
            p.drawLine(QPointF(cx, cy + 5.0), QPointF(cx, qreal(height())));
        p.setPen(QPen(m_color, 1.6));
        p.setBrush(m_strong ? m_color : theme::surface());
        p.drawEllipse(QPointF(cx, cy), 4.0, 4.0);
    }

private:
    QColor m_color;
    bool m_first;
    bool m_last;
    bool m_strong;
};

struct Step {
    QString title;
    QStringList lines;
    QColor color;
    bool strong = false;
};

QWidget* stepList(const QList<Step>& steps)
{
    auto* w = new QWidget;
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(0);
    for (int i = 0; i < steps.size(); ++i) {
        const Step& s = steps[i];
        const bool last = i + 1 == steps.size();
        auto* row = new QWidget;
        auto* h = new QHBoxLayout(row);
        h->setContentsMargins(0, 0, 0, last ? 0 : 12);
        h->setSpacing(10);
        h->addWidget(new RailDot(s.color.isValid() ? s.color : theme::textMuted(), i == 0, last, s.strong));
        auto* col = new QVBoxLayout;
        col->setContentsMargins(0, 0, 0, 0);
        col->setSpacing(2);
        auto* t = new WrapLabel(s.title);
        if (s.strong)
            t->setProperty("role", "title");
        col->addWidget(t);
        for (const QString& line : s.lines) {
            auto* l = new WrapLabel(line);
            l->setProperty("role", "muted");
            col->addWidget(l);
        }
        h->addLayout(col, 1);
        v->addWidget(row);
    }
    return w;
}

QWidget* bullet(const QString& text, const QColor& color)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(10);
    auto* dotBox = new QWidget;
    auto* db = new QVBoxLayout(dotBox);
    db->setContentsMargins(0, 6, 0, 0);
    db->addWidget(ui::statusDot(color));
    h->addWidget(dotBox, 0, Qt::AlignTop);
    h->addWidget(new WrapLabel(text), 1);
    return w;
}

QString signatureText(const bulwark::SecurityEvent& e)
{
    QString s;
    if (e.signatureMismatch)
        s = u("签名失配(内嵌签名但校验失败)");
    else if (e.actorSigned)
        s = e.actorPublisher.isEmpty() ? u("有效") : u("有效 · ") + e.actorPublisher;
    else
        s = u("无 / 无效");
    if (e.certRevoked)
        s += u(" · 证书已吊销");
    if (e.signedAfterCertExpiry)
        s += u(" · 在证书过期后签名");
    return s;
}

// Short origin tag for a list row ("服务 Schedule" / "计划任务 GoogleUpdate").
QString originChip(const bulwark::SecurityEvent& e)
{
    using O = bulwark::ProcessOriginKind;
    if (e.originKind == O::Service && !e.originService.isEmpty())
        return u("服务 ") + e.originService.section(QStringLiteral(", "), 0, 0);
    if (e.originKind == O::ScheduledTask && !e.originTask.isEmpty())
        return u("计划任务 ") + e.originTask.section(QLatin1Char('\\'), -1);
    return QString();
}

// Folders whose trust would switch protection off for (almost) everything.
bool isBroadFolder(const QString& path)
{
    QString p = QDir::toNativeSeparators(QDir::cleanPath(path));
    while (p.endsWith(QLatin1Char('\\')) && p.size() > 3)
        p.chop(1);
    static const QRegularExpression drive(QStringLiteral("^[A-Za-z]:\\\\?$"));
    if (drive.match(p).hasMatch())
        return true;
    for (const char* var : {"SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "USERPROFILE"}) {
        const QString v = QDir::toNativeSeparators(QDir::cleanPath(qEnvironmentVariable(var)));
        if (!v.isEmpty() && v.compare(p, Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

bool trustMatches(const bulwark::DefenseRule& r, const QString& path, bool isDir)
{
    const QString want = QDir::toNativeSeparators(QDir::cleanPath(path));
    if (isDir) {
        QString pat = QDir::toNativeSeparators(r.actorPattern);
        if (pat.endsWith(QStringLiteral("\\*")))
            pat.chop(2);
        return !pat.isEmpty() && QDir::cleanPath(pat).compare(QDir::cleanPath(want), Qt::CaseInsensitive) == 0;
    }
    return !r.actorPath.isEmpty()
        && QDir::toNativeSeparators(QDir::cleanPath(r.actorPath)).compare(want, Qt::CaseInsensitive) == 0;
}

// Waits for the service to echo a trust list that contains `path`, then says so.
// A list without it isn't conclusive (it may answer an earlier request), so only
// the timeout reports a missing confirmation.
void watchTrust(QWidget* context, IpcClient* ipc, const QString& path, bool isDir)
{
    auto* guard = new QObject(context);
    const QString name = isDir ? path : QFileInfo(path).fileName();
    QObject::connect(ipc, &IpcClient::trustReceived, guard,
                     [guard, context, path, isDir, name](const QList<bulwark::DefenseRule>& list) {
        for (const bulwark::DefenseRule& r : list) {
            if (!trustMatches(r, path, isDir))
                continue;
            if (Banner* b = ui::notify(context, ui::Tone::Success,
                                       isDir ? u("已信任文件夹 %1,其中运行的程序将跳过检测。").arg(name)
                                             : u("已信任 %1,之后的行为将直接放行。").arg(name)))
                b->setAction(u("查看信任名单"), [] { nav::go(QString::fromLatin1(nav::Trust)); });
            guard->deleteLater();
            return;
        }
    });
    QTimer::singleShot(8000, guard, [guard, context, name] {
        ui::notify(context, ui::Tone::Warning,
                   u("没有收到服务对「%1」的信任确认。请稍后在「信任名单」里核对是否已添加。").arg(name));
        guard->deleteLater();
    });
}

} // namespace

namespace evtview {

// ---- list rows ------------------------------------------------------------------

QString searchText(const bulwark::SecurityEvent& e)
{
    QStringList s;
    s << e.actorPath << e.target << e.commandLine << e.parentPath << e.actorPublisher << e.originLabel()
      << evtfmt::typeLabel(e.type) << evtfmt::action(e.type) << QString::number(e.actorPid) << e.actorHash
      << e.techniques.join(QLatin1Char(' ')) << e.riskReasons.join(QLatin1Char(' ')) << e.matchedRuleNote;
    return s.join(QLatin1Char(' '));
}

RecordView recordView(const bulwark::ipc::EventLogPayload& p)
{
    const bulwark::SecurityEvent& e = p.event;
    RecordView v;
    v.icon = evtfmt::typeGlyph(e.type);
    v.iconColor = evtfmt::glyphColor(e); // risk when it matters, the behaviour family otherwise
    v.title = evtfmt::actorName(e.actorPath) + u(" · ") + evtfmt::action(e.type);
    v.subtitle = e.target.trimmed().isEmpty() ? evtfmt::nativePath(e.actorPath) : e.target;
    v.subtitleMono = true;
    if (e.riskScore > 0) {
        v.score = QString::number(e.riskScore);
        v.scoreColor = evtfmt::riskColor(e.riskScore);
    }
    const evtfmt::Badge d = evtfmt::disposition(p.action, p.enforcement);
    v.pill = d.text;
    v.pillColor = d.color;
    v.time = e.timestampUtc;
    if (const QString oc = originChip(e); !oc.isEmpty()) {
        v.chips << oc;
        v.chipColors << evtfmt::originColor(e.originKind); // 服务 orchid · 计划任务 rose
    }
    if (p.action == bulwark::VerdictAction::Block)
        v.accent = d.color;
    v.tooltip = evtfmt::nativePath(e.actorPath) + u("\n") + fmt::absoluteTime(e.timestampUtc);
    v.haystack = searchText(e) + QLatin1Char(' ') + d.text;
    v.key = keyOf(e);
    return v;
}

// ---- building blocks ------------------------------------------------------------------

QList<QPair<QString, QColor>> factChips(const bulwark::SecurityEvent& e)
{
    QList<QPair<QString, QColor>> c;
    if (e.signatureMismatch)
        c << qMakePair(u("签名失配"), theme::danger());
    else if (e.actorSigned)
        c << qMakePair(e.actorPublisher.isEmpty() ? u("已签名") : u("已签名 · ") + e.actorPublisher, theme::success());
    else if (!e.actorPath.isEmpty())
        c << qMakePair(u("无签名"), theme::warning());
    if (e.certRevoked)
        c << qMakePair(u("证书已吊销"), theme::danger());
    if (e.signedAfterCertExpiry)
        c << qMakePair(u("证书过期后签名"), theme::danger());
    if (e.isFirstSeen)
        c << qMakePair(u("本机首见"), theme::warning());
    if (e.reputation.has_value() && e.reputation->totalEngines > 0)
        c << qMakePair(QStringLiteral("VT %1/%2").arg(e.reputation->malicious).arg(e.reputation->totalEngines),
                       e.reputation->malicious > 0 ? theme::danger() : theme::success());
    if (e.memoryInjection)
        c << qMakePair(u("内存防护命中"), theme::danger());
    return c;
}

QWidget* evidenceList(const bulwark::SecurityEvent& e)
{
    auto* w = new QWidget;
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(10);
    if (!e.evidenceChain.isEmpty()) {
        for (const bulwark::Evidence& ev : e.evidenceChain) {
            auto* row = new QWidget;
            auto* h = new QHBoxLayout(row);
            h->setContentsMargins(0, 0, 0, 0);
            h->setSpacing(10);
            h->addWidget(ui::pill(evtfmt::evidenceKindLabel(ev.kind), evtfmt::evidenceKindColor(ev.kind)), 0,
                         Qt::AlignTop);
            auto* col = new QVBoxLayout;
            col->setContentsMargins(0, 1, 0, 0);
            col->setSpacing(2);
            col->addWidget(new WrapLabel(ev.description));
            QStringList meta;
            if (!ev.source.isEmpty())
                meta << ev.source;
            if (ev.scoreDelta != 0)
                meta << QStringLiteral("%1%2").arg(ev.scoreDelta > 0 ? QStringLiteral("+") : QString()).arg(ev.scoreDelta);
            if (!ev.technique.isEmpty())
                meta << (ev.techniqueName.isEmpty() ? ev.technique : ev.technique + u(" ") + ev.techniqueName);
            if (!meta.isEmpty()) {
                auto* m = ui::label(meta.join(u(" · ")), "muted");
                m->setWordWrap(true);
                col->addWidget(m);
            }
            h->addLayout(col, 1);
            v->addWidget(row);
        }
    } else if (!e.riskReasons.isEmpty()) {
        for (const QString& r : e.riskReasons)
            v->addWidget(bullet(r, evtfmt::riskColor(e.riskScore)));
    } else {
        v->addWidget(ui::label(e.riskScore > 0 ? u("引擎评分 %1,没有列出具体原因。").arg(e.riskScore)
                                               : u("没有触发任何风险信号。"),
                               "muted"));
    }
    return w;
}

QWidget* processChain(const bulwark::SecurityEvent& e)
{
    QList<Step> steps;
    const QString origin = e.originLabel();
    if (e.originKind != bulwark::ProcessOriginKind::Unknown && !origin.isEmpty()) {
        Step s;
        s.title = origin;
        if (!e.originDetail.isEmpty())
            s.lines << e.originDetail;
        s.color = evtfmt::originColor(e.originKind);
        steps << s;
    }
    if (e.chainContext.isEmpty()) {
        if (e.parentPid > 0 || !e.parentPath.isEmpty()) {
            Step s;
            s.title = QStringLiteral("%1 (PID %2)").arg(evtfmt::actorName(e.parentPath)).arg(e.parentPid);
            if (!e.parentPath.isEmpty())
                s.lines << evtfmt::nativePath(e.parentPath);
            steps << s;
        }
        Step a;
        a.title = QStringLiteral("%1 (PID %2)").arg(evtfmt::actorName(e.actorPath)).arg(e.actorPid);
        a.lines << evtfmt::action(e.type) + (e.target.isEmpty() ? QString() : u(" → ") + e.target);
        a.color = evtfmt::riskColor(e.riskScore);
        a.strong = true;
        steps << a;
    } else {
        for (int i = 0; i < e.chainContext.size(); ++i) {
            const bulwark::ChainEventInfo& c = e.chainContext[i];
            const bool last = i + 1 == e.chainContext.size();
            Step s;
            s.title = QStringLiteral("%1 (PID %2)").arg(evtfmt::actorName(c.actorPath)).arg(c.actorPid);
            s.lines << evtfmt::typeLabel(c.type) + (c.target.isEmpty() ? QString() : u(" → ") + c.target);
            if (!c.originLabel.isEmpty())
                s.lines << u("启动来源:") + c.originLabel;
            s.color = c.riskScore >= 50 ? evtfmt::riskColor(c.riskScore) : QColor();
            if (last) {
                s.strong = true;
                if (!s.color.isValid())
                    s.color = evtfmt::riskColor(e.riskScore);
            }
            steps << s;
        }
    }
    return stepList(steps);
}

void addForensicFields(QVBoxLayout* s, const bulwark::SecurityEvent& e)
{
    const Inspector::FieldFlags mono = Inspector::Mono;
    const Inspector::FieldFlags monoCopy = Inspector::Mono | Inspector::Copy;
    s->addWidget(Inspector::makeField(u("主体路径"), evtfmt::nativePath(e.actorPath), monoCopy));
    s->addWidget(Inspector::makeField(u("数字签名"), signatureText(e)));
    if (!e.commandLine.isEmpty())
        s->addWidget(Inspector::makeField(u("命令行"), e.commandLine, monoCopy));
    if (!e.target.isEmpty())
        s->addWidget(Inspector::makeField(u("操作目标"), e.target, monoCopy));
    if (!e.detail.isEmpty())
        s->addWidget(Inspector::makeField(u("附加信息"), e.detail));
    if (e.parentPid > 0 || !e.parentPath.isEmpty())
        s->addWidget(Inspector::makeField(
            u("父进程"),
            QStringLiteral("%1  (PID %2)").arg(evtfmt::nativePath(e.parentPath)).arg(e.parentPid).trimmed(), mono));
    if (e.originatorPid > 0)
        s->addWidget(Inspector::makeField(
            u("实际发起者"),
            QStringLiteral("%1  (PID %2)").arg(evtfmt::nativePath(e.originatorPath)).arg(e.originatorPid).trimmed(),
            mono));
    if (!e.actorHash.isEmpty())
        s->addWidget(Inspector::makeField(QStringLiteral("SHA-256"), e.actorHash, monoCopy));
    if (e.actorFileSize > 0)
        s->addWidget(Inspector::makeField(u("文件大小"), fmt::bytes(e.actorFileSize)));
    if (!e.actorCertThumbprint.isEmpty())
        s->addWidget(Inspector::makeField(u("证书指纹"), e.actorCertThumbprint, monoCopy));
    if (e.certNotAfterUtc.has_value())
        s->addWidget(Inspector::makeField(u("证书有效期至"), fmt::absoluteTime(*e.certNotAfterUtc)));
    s->addWidget(Inspector::makeField(u("发生时间"), fmt::absoluteTime(e.timestampUtc)));
    s->addWidget(Inspector::makeField(u("事件 ID"), keyOf(e), monoCopy));
}

// ---- inspector + actions ------------------------------------------------------------------

void fillInspector(Inspector* in, const bulwark::ipc::EventLogPayload& p, IpcClient* ipc,
                   const QString& trustSource)
{
    const bulwark::SecurityEvent& e = p.event;
    const evtfmt::Badge disp = evtfmt::disposition(p.action, p.enforcement);
    const QString name = evtfmt::actorName(e.actorPath);
    in->setHeader(evtfmt::typeGlyph(e.type), evtfmt::glyphColor(e), name,
                  QStringLiteral("PID %1 · %2").arg(e.actorPid).arg(fmt::absoluteTime(e.timestampUtc)));
    in->addLead(evtfmt::sentence(e, false));
    QList<QPair<QString, QColor>> chips;
    chips << qMakePair(disp.text, disp.color);
    if (e.riskScore > 0)
        chips << qMakePair(QStringLiteral("%1 %2").arg(evtfmt::riskLevel(e.riskScore)).arg(e.riskScore),
                           evtfmt::riskColor(e.riskScore));
    chips += factChips(e);
    in->addChips(nullptr, chips);

    QVBoxLayout* s = in->addSection(u("处置"));
    in->addText(s, evtfmt::dispositionDetail(p.action, p.enforcement));
    // 与拦截通知同一来源(evtfmt::threatOf):从通知上点「查看详情」进来,看到的是同一个定性。
    // 放行的记录不写 —— 没拦它,就不该给它贴一个威胁标签。
    if (p.action != bulwark::VerdictAction::Allow) {
        const evtfmt::Threat threat = evtfmt::threatOf(e);
        if (!threat.isEmpty())
            in->addField(s, u("威胁类型"), threat.text());
    }
    in->addField(s, u("裁决来源"), evtfmt::verdictSourceLabel(p.source));
    if (!e.matchedRuleNote.trimmed().isEmpty())
        in->addField(s, u("命中规则"), e.matchedRuleNote);

    s = in->addSection(u("判定依据"));
    s->addWidget(evidenceList(e));
    if (!e.techniques.isEmpty()) {
        QList<QPair<QString, QColor>> tech;
        for (const QString& t : e.techniques)
            tech << qMakePair(t, theme::info());
        in->addChips(s, tech)->setToolTip(u("命中的 ATT&CK 技战术"));
    }

    s = in->addSection(u("进程溯源"));
    s->addWidget(processChain(e));

    s = in->addSection(u("取证"));
    addForensicFields(s, e);

    const bulwark::SecurityEvent ev = e;
    const Outcome oc = outcomeOf(p);
    in->addAction(QStringLiteral("clock"), u("攻击时间线"), "ghost",
                  [in, ev, ipc, oc] { openTimeline(in, ev, ipc, oc); });
    if (ipc)
        in->addAction(QStringLiteral("link"), u("关系图"), "ghost",
                      [in, ev, ipc, name] { openGraph(in, ipc, ev.id, ev.actorPid, name); });
    auto* menu = new QMenu;
    fillContextMenu(menu, in, p, ipc, trustSource);
    in->addMenu(menu);
    if (p.action == bulwark::VerdictAction::Block && evtfmt::needsManualAction(p.enforcement))
        in->setNote(u("这条行为没有被实际阻断,需要人工确认它造成了什么影响。"), theme::warning());
}

void fillContextMenu(QMenu* menu, QWidget* context, const bulwark::ipc::EventLogPayload& p, IpcClient* ipc,
                     const QString& trustSource)
{
    const bulwark::SecurityEvent e = p.event;
    const Outcome oc = outcomeOf(p);
    const QString path = evtfmt::nativePath(e.actorPath);
    const QString name = evtfmt::actorName(e.actorPath);
    const QColor ic = theme::textSecondary();

    QObject::connect(menu->addAction(AppIcon::icon(QStringLiteral("clock"), ic, 16), u("查看攻击时间线")),
                     &QAction::triggered, context, [context, e, ipc, oc] { openTimeline(context, e, ipc, oc); });
    if (ipc)
        QObject::connect(menu->addAction(AppIcon::icon(QStringLiteral("link"), ic, 16), u("查看攻击关系图")),
                         &QAction::triggered, context,
                         [context, e, ipc, name] { openGraph(context, ipc, e.id, e.actorPid, name); });
    if (e.actorPid > 0)
        QObject::connect(menu->addAction(AppIcon::icon(QStringLiteral("activity"), ic, 16), u("在事件时间线中查看此进程")),
                         &QAction::triggered, context, [pid = e.actorPid] {
                             nav::go(QString::fromLatin1(nav::Timeline),
                                     {{QStringLiteral("pid"), pid}, {QStringLiteral("range"), QStringLiteral("24h")}});
                         });
    menu->addSeparator();
    if (!path.isEmpty())
        QObject::connect(menu->addAction(AppIcon::icon(QStringLiteral("copy"), ic, 16), u("复制程序路径")),
                         &QAction::triggered, context, [path] {
                             if (QClipboard* cb = QGuiApplication::clipboard())
                                 cb->setText(path);
                         });
    if (!e.target.isEmpty())
        QObject::connect(menu->addAction(AppIcon::icon(QStringLiteral("copy"), ic, 16), u("复制操作目标")),
                         &QAction::triggered, context, [t = e.target] {
                             if (QClipboard* cb = QGuiApplication::clipboard())
                                 cb->setText(t);
                         });
    menu->addSeparator();
    if (path.isEmpty()) {
        menu->addAction(u("该事件没有程序路径,无法信任"))->setEnabled(false);
    } else {
        QObject::connect(menu->addAction(AppIcon::icon(QStringLiteral("trust"), ic, 16), u("信任此程序…")),
                         &QAction::triggered, context,
                         [context, ipc, path, trustSource] { trust(context, ipc, path, false, trustSource); });
    }
}

void openTimeline(QWidget* parent, const bulwark::SecurityEvent& e, IpcClient* ipc, std::optional<Outcome> outcome)
{
    auto* w = new AttackTimelineWindow(e, parent ? parent->window() : nullptr, ipc, outcome);
    w->setAttribute(Qt::WA_DeleteOnClose);
    w->show();
}

void openGraph(QWidget* context, IpcClient* ipc, const QUuid& seedEventId, int pid, const QString& title)
{
    if (!ipc || !ipc->isConnected()) {
        ui::notify(context, ui::Tone::Danger, u("未连接后台服务,无法构建攻击关系图。"));
        return;
    }
    auto* w = new AttackGraphWindow(ipc, seedEventId, pid, title, context ? context->window() : nullptr);
    w->setAttribute(Qt::WA_DeleteOnClose);
    w->show();
}

void trust(QWidget* context, IpcClient* ipc, const QString& rawPath, bool isDirectory, const QString& source)
{
    const QString path = QDir::toNativeSeparators(rawPath.trimmed());
    if (path.isEmpty())
        return;
    if (!ipc || !ipc->isConnected()) {
        ui::notify(context, ui::Tone::Danger, u("未连接后台服务,无法添加信任项。"));
        return;
    }
    ui::ConfirmSpec s;
    if (isDirectory) {
        s.risk = ui::Risk::Danger;
        s.title = u("信任文件夹");
        s.summary = u("信任后,这个文件夹及其子目录中运行的所有程序都将完全跳过检测,直接放行。");
        if (isBroadFolder(path))
            s.consequences << u("这是磁盘根目录或系统 / 程序 / 用户主目录:信任它几乎等于关闭防护");
        s.consequences << u("今后放进这个文件夹的新程序同样不受检测")
                       << u("请只信任你完全确信安全的文件夹");
        s.subjectLabel = u("文件夹");
        s.confirmText = u("信任文件夹");
    } else {
        s.risk = ui::Risk::Caution;
        s.title = u("信任此程序");
        s.summary = u("信任后,该程序的所有行为都将直接放行,并跳过全部检测与后台云查毒。");
        s.consequences << u("同名程序很多(如 svchost.exe),请核对下面的完整路径")
                       << u("已经发生的拦截不会撤销,信任只对之后的行为生效");
        s.subjectLabel = u("程序");
        s.confirmText = u("信任此程序");
    }
    s.subject = path;
    if (!ui::confirm(context, s))
        return;
    watchTrust(context, ipc, path, isDirectory);
    ipc->addTrust(path, source, isDirectory);
}

} // namespace evtview
