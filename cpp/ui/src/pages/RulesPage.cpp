// 防护规则 —— 查看 / 新增 / 删除,以及从威胁情报(ThreatFox)与 AI 建议里挑选采纳。
//
// 每条规则读成一句话(「拦截 mimikatz.exe 的所有行为」),附加条件作为胶囊跟在后面。
// 规则的增删由服务端回推最新列表确认 —— 界面只在看到列表真的变了之后才说「已添加 / 已删除」,
// 没等到就如实说没等到。
//
// 一条要让用户知道的事实(见产品说明的裁决流水线):规则在第 7 步才生效。本软件组件、用户信任、
// 已安装的安全软件,以及已知即时通讯软件的网络 / DNS 行为会先行放行 —— 写一条拦截规则并不能
// 覆盖它们。新建规则时与检查器里都写明这一点。
#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "design/Banner.h"
#include "design/Confirm.h"
#include "design/DropZone.h"
#include "design/FilterChip.h"
#include "design/FitScroll.h"
#include "design/FlowLayout.h"
#include "design/Format.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Segmented.h"
#include "design/Sheet.h"
#include "ipc/IpcClient.h"
#include "widgets/WrapLabel.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <functional>
#include <memory>

using evtfmt::u;
using bulwark::DefenseRule;

namespace {

enum Seg { SegAll = 0, SegBlock, SegAllow, SegTemp, SegOff };

QString verbOf(bulwark::VerdictAction a)
{
    return evtfmt::verdict(a).text;
}

QString actorSpec(const DefenseRule& r)
{
    if (!r.actorPath.isEmpty())
        return evtfmt::nativePath(r.actorPath);
    return r.actorPattern.isEmpty() ? u("任意程序") : r.actorPattern;
}

// "mimikatz.exe" for an exact path, the pattern as written otherwise.
QString actorShort(const QString& spec)
{
    const QString s = spec.trimmed();
    if (s.isEmpty() || s == QLatin1String("*"))
        return u("任意程序");
    if (s.contains(QLatin1Char('*')) || s.contains(QLatin1Char('?')))
        return s;
    const QString name = QFileInfo(s).fileName();
    return name.isEmpty() ? s : name;
}

QString sentence(bulwark::VerdictAction action, const QString& actor, const std::optional<bulwark::EventType>& type,
                 const QString& target)
{
    QString s = u("%1 %2 的%3").arg(verbOf(action), actorShort(actor),
                                    type ? evtfmt::typeShort(*type) : u("所有行为"));
    if (!target.trimmed().isEmpty())
        s += u("(目标 %1)").arg(target.trimmed());
    return s;
}

QString ruleSentence(const DefenseRule& r)
{
    return sentence(r.action, !r.actorPath.isEmpty() ? r.actorPath : r.actorPattern, r.type, r.targetPattern);
}

bool isTemporary(const DefenseRule& r) { return r.sessionOnly || r.expiresUtc.has_value(); }
bool isOff(const DefenseRule& r) { return !r.enabled || r.isExpired(QDateTime::currentDateTimeUtc()); }

QStringList conditionChips(const DefenseRule& r)
{
    QStringList c;
    if (!r.commandLinePattern.isEmpty()) c << u("命令行 ") + r.commandLinePattern;
    if (!r.parentPattern.isEmpty())      c << u("父进程 ") + r.parentPattern;
    if (r.requireUnsigned)               c << u("仅无签名");
    if (r.requireSigned)                 c << u("需有效签名");
    if (r.requireTargetUnsigned)         c << u("目标无签名");
    if (r.requireTargetSigned)           c << u("目标需有效签名");
    if (!r.actorHashes.isEmpty())        c << u("哈希 ×%1").arg(r.actorHashes.size());
    if (r.hardOverride)                  c << u("硬拦截");
    if (r.exemptTrustedOsComponent)      c << u("系统组件可豁免");
    return c;
}

evtfmt::Badge statusOf(const DefenseRule& r)
{
    if (!r.enabled)
        return {u("停用"), theme::textMuted()};
    if (r.isExpired(QDateTime::currentDateTimeUtc()))
        return {u("已过期"), theme::textMuted()};
    if (r.sessionOnly)
        return {u("本次会话"), theme::info()};
    if (r.expiresUtc)
        return {u("至 ") + r.expiresUtc->toLocalTime().toString(QStringLiteral("MM-dd HH:mm")), theme::warning()};
    return {u("启用"), theme::success()};
}

QString glyphOf(bulwark::VerdictAction a)
{
    switch (a) {
    case bulwark::VerdictAction::Block: return QStringLiteral("shield-x");
    case bulwark::VerdictAction::Ask:   return QStringLiteral("alert");
    case bulwark::VerdictAction::Allow: break;
    }
    return QStringLiteral("check-circle");
}

// A bare file name in an Allow rule lets anything renamed to that name through.
bool bareNameAllow(bulwark::VerdictAction action, const QString& actor)
{
    const QString a = actor.trimmed();
    return action == bulwark::VerdictAction::Allow && !a.isEmpty() && !a.contains(QLatin1Char('\\'))
        && !a.contains(QLatin1Char('/')) && !a.contains(QLatin1Char('*'));
}

QString precedenceNote()
{
    return u("规则在裁决流水线第 7 步生效:本软件组件、信任名单、已安装的安全软件,以及已知即时通讯软件的"
             "网络 / DNS 行为会先行放行,不受规则约束。");
}

RecordView ruleView(const DefenseRule& r)
{
    RecordView v;
    const evtfmt::Badge b = evtfmt::verdict(r.action);
    const evtfmt::Badge st = statusOf(r);
    v.icon = glyphOf(r.action);
    v.iconColor = isOff(r) ? theme::textMuted() : b.color;
    v.title = ruleSentence(r);
    v.subtitle = actorSpec(r);
    v.subtitleMono = true;
    v.chips = conditionChips(r);
    for (const QString& c : std::as_const(v.chips)) // 「硬拦截」 is a status; the other conditions are plain facts
        v.chipColors << (c == u("硬拦截") ? theme::danger() : QColor());
    if (st.text != u("启用")) {
        v.pill = st.text;
        v.pillColor = st.color;
    }
    v.dim = isOff(r);
    v.time = r.createdUtc;
    v.accent = r.hardOverride ? theme::danger() : QColor();
    v.tooltip = r.note;
    v.haystack = QStringList{actorSpec(r), r.type ? evtfmt::typeLabel(*r.type) : u("所有行为"), r.targetPattern,
                             r.commandLinePattern, r.parentPattern, r.note, b.text, st.text}
                     .join(QLatin1Char(' '));
    v.key = r.id.toString(QUuid::WithoutBraces);
    return v;
}

// Waits (up to 8 s) for a rules snapshot for which `done` holds, then reports.
// A snapshot that doesn't satisfy it isn't conclusive (it may answer an earlier
// request), so only the timeout reports a missing confirmation.
void awaitRules(QWidget* page, IpcClient* ipc, std::function<bool(const QList<DefenseRule>&)> done,
                const QString& okText, const QString& timeoutText)
{
    auto* guard = new QObject(page);
    QObject::connect(ipc, &IpcClient::rulesReceived, guard,
                     [guard, page, done = std::move(done), okText](const QList<DefenseRule>& list) {
        if (!done(list))
            return;
        ui::notify(page, ui::Tone::Success, okText);
        guard->deleteLater();
    });
    QTimer::singleShot(8000, guard, [guard, page, timeoutText] {
        ui::notify(page, ui::Tone::Warning, timeoutText);
        guard->deleteLater();
    });
}

// ── rule builder ────────────────────────────────────────────────────────────────
class RuleBuilder : public Sheet
{
public:
    explicit RuleBuilder(QWidget* parent) : Sheet(parent)
    {
        setSheetWidth(560);
        setHeader(QStringLiteral("sliders"), identity::page(nav::Rules), u("新增防护规则"),
                  u("主体、行为类型、目标全部满足时生效;未填写的条件视为「任意」。"));
        QVBoxLayout* b = body();
        b->setSpacing(8);

        b->addWidget(ui::label(u("动作"), "caption"));
        m_action = new Segmented;
        m_action->setAccessibleName(u("动作"));
        m_action->addSegment(u("拦截"), int(bulwark::VerdictAction::Block));
        m_action->addSegment(u("放行"), int(bulwark::VerdictAction::Allow));
        m_action->setCurrentIndex(0);
        b->addWidget(m_action, 0, Qt::AlignLeft);

        b->addSpacing(4);
        b->addWidget(ui::label(u("主体程序"), "caption"));
        auto* actorRow = new QHBoxLayout;
        actorRow->setSpacing(8);
        m_actor = new QLineEdit;
        m_actor->setPlaceholderText(u("完整路径、通配(如 *\\mimikatz.exe)或裸文件名"));
        m_actor->setAccessibleName(u("主体程序"));
        actorRow->addWidget(m_actor, 1);
        auto* browse = ui::button(u("选择文件…"), "ghost", QStringLiteral("folder"));
        actorRow->addWidget(browse);
        b->addLayout(actorRow);

        b->addSpacing(4);
        b->addWidget(ui::label(u("行为类型"), "caption"));
        m_type = new QComboBox;
        m_type->setAccessibleName(u("行为类型"));
        m_type->addItem(u("所有行为"), -1);
        for (int i = 0; i <= int(bulwark::EventType::DnsQuery); ++i)
            m_type->addItem(evtfmt::typeLabel(bulwark::EventType(i)), i);
        b->addWidget(m_type);

        b->addSpacing(4);
        b->addWidget(ui::label(u("目标(可选)"), "caption"));
        m_target = new QLineEdit;
        m_target->setPlaceholderText(u("目标通配,留空 = 任意(如 *\\CurrentVersion\\Run\\*、*.onion)"));
        m_target->setAccessibleName(u("目标"));
        b->addWidget(m_target);

        b->addSpacing(6);
        auto* prev = ui::cardAlt();
        auto* pv = new QVBoxLayout(prev);
        pv->setContentsMargins(14, 12, 14, 12);
        pv->setSpacing(6);
        pv->addWidget(ui::eyebrow(u("规则预览")));
        m_preview = new WrapLabel;
        m_preview->setProperty("role", "lead");
        pv->addWidget(m_preview);
        m_warn = ui::label(QString(), "secondary");
        m_warn->setWordWrap(true);
        pv->addWidget(m_warn);
        b->addWidget(prev);

        addButton(u("取消"), "ghost", [this] { reject(); });
        m_ok = addButton(u("添加规则"), "primary", [this] { accept(); });
        m_ok->setDefault(true);

        connect(browse, &QPushButton::clicked, this, [this] {
            const QString f = QFileDialog::getOpenFileName(this, u("选择规则的主体程序"), QString(),
                                                           u("可执行文件 (*.exe *.dll *.sys);;所有文件 (*.*)"));
            if (!f.isEmpty())
                m_actor->setText(evtfmt::nativePath(f));
        });
        ui::acceptFileDrops(card(), u("松开以填入主体程序"), [this](const QStringList& paths) {
            if (!paths.isEmpty())
                m_actor->setText(evtfmt::nativePath(paths.first()));
        });
        connect(m_actor, &QLineEdit::textChanged, this, [this] { sync(); });
        connect(m_target, &QLineEdit::textChanged, this, [this] { sync(); });
        connect(m_type, &QComboBox::currentIndexChanged, this, [this] { sync(); });
        connect(m_action, &Segmented::currentChanged, this, [this] { sync(); });
        m_actor->setFocus();
        sync();
    }

    bulwark::ipc::AddRulePayload payload() const
    {
        bulwark::ipc::AddRulePayload p;
        p.actorPath = m_actor->text().trimmed();
        const int t = m_type->currentData().toInt();
        if (t >= 0)
            p.type = bulwark::EventType(t);
        p.targetPattern = m_target->text().trimmed();
        p.action = bulwark::VerdictAction(m_action->currentData().toInt());
        return p;
    }

private:
    void sync()
    {
        const bulwark::ipc::AddRulePayload p = payload();
        m_ok->setEnabled(!p.actorPath.isEmpty());
        m_preview->setText(p.actorPath.isEmpty() ? u("先填写主体程序。")
                                                 : sentence(p.action, p.actorPath, p.type, p.targetPattern));
        if (bareNameAllow(p.action, p.actorPath)) {
            m_warn->setText(u("只写文件名的放行规则,会放过任何改成这个名字的程序 —— 建议填写完整路径。"));
            m_warn->setStyleSheet(QStringLiteral("color:%1;").arg(theme::warning().name()));
        } else if (p.action == bulwark::VerdictAction::Allow && p.actorPath == QLatin1String("*")) {
            m_warn->setText(u("这条规则会放行所有程序的这类行为。"));
            m_warn->setStyleSheet(QStringLiteral("color:%1;").arg(theme::warning().name()));
        } else {
            m_warn->setText(precedenceNote());
            m_warn->setStyleSheet(QString());
        }
        refit();
    }

    Segmented* m_action = nullptr;
    QLineEdit* m_actor = nullptr;
    QComboBox* m_type = nullptr;
    QLineEdit* m_target = nullptr;
    WrapLabel* m_preview = nullptr;
    QLabel* m_warn = nullptr;
    QPushButton* m_ok = nullptr;
};

// ── adoption list (intel preview / AI suggestions) ─────────────────────────────────
struct AdoptRow {
    QString title;
    QString detail;
};

// A row that toggles its check box when clicked anywhere.
class CheckRow : public QWidget
{
public:
    CheckRow(const AdoptRow& r, QCheckBox* box) : m_box(box)
    {
        auto* h = new QHBoxLayout(this);
        h->setContentsMargins(6, 6, 6, 6);
        h->setSpacing(10);
        h->addWidget(box, 0, Qt::AlignTop);
        auto* col = new QVBoxLayout;
        col->setSpacing(2);
        col->addWidget(new WrapLabel(r.title));
        if (!r.detail.isEmpty()) {
            auto* d = new WrapLabel(r.detail);
            d->setProperty("role", "muted");
            col->addWidget(d);
        }
        h->addLayout(col, 1);
        setCursor(Qt::PointingHandCursor);
    }

protected:
    void mousePressEvent(QMouseEvent* e) override
    {
        if (e->button() == Qt::LeftButton)
            m_box->toggle();
        QWidget::mousePressEvent(e);
    }

private:
    QCheckBox* m_box;
};

// Returns the indices the user chose to adopt (empty = cancelled / none).
QList<int> adopt(QWidget* parent, const QString& icon, const QColor& tone, const QString& title, const QString& intro,
                 const QList<AdoptRow>& rows)
{
    Sheet s(parent);
    s.setSheetWidth(640);
    s.setHeader(icon, tone, title, intro);
    auto* tools = new QHBoxLayout;
    tools->setSpacing(6);
    auto* all = ui::button(u("全选"), "ghost", QString(), true);
    auto* invert = ui::button(u("反选"), "ghost", QString(), true);
    auto* count = ui::label(QString(), "muted");
    tools->addWidget(all);
    tools->addWidget(invert);
    tools->addStretch(1);
    tools->addWidget(count);
    s.body()->addLayout(tools);

    auto* scroll = new FitScrollArea(Sheet::screenHeightFor(parent, 0.5), 592);
    auto* content = new QWidget;
    auto* list = new QVBoxLayout(content);
    list->setContentsMargins(0, 0, 6, 0);
    list->setSpacing(2);
    QList<QCheckBox*> boxes;
    for (const AdoptRow& r : rows) {
        auto* box = new QCheckBox;
        box->setChecked(true);
        box->setAccessibleName(r.title);
        boxes << box;
        list->addWidget(new CheckRow(r, box));
    }
    list->addStretch(1);
    scroll->setContent(content);
    s.body()->addWidget(scroll, 1);

    s.addButton(u("取消"), "ghost", [&s] { s.reject(); });
    QPushButton* ok = s.addButton(QString(), "primary", [&s] { s.accept(); });
    const auto sync = [&boxes, count, ok] {
        const auto n = std::count_if(boxes.cbegin(), boxes.cend(), [](const QCheckBox* b) { return b->isChecked(); });
        count->setText(u("已选 %1 / %2").arg(n).arg(boxes.size()));
        ok->setText(u("采纳 %1 条").arg(n));
        ok->setEnabled(n > 0);
    };
    for (QCheckBox* b : boxes)
        QObject::connect(b, &QCheckBox::toggled, &s, sync);
    QObject::connect(all, &QPushButton::clicked, &s, [&boxes] {
        for (QCheckBox* b : boxes)
            b->setChecked(true);
    });
    QObject::connect(invert, &QPushButton::clicked, &s, [&boxes] {
        for (QCheckBox* b : boxes)
            b->setChecked(!b->isChecked());
    });
    sync();

    QList<int> chosen;
    if (s.exec() != QDialog::Accepted)
        return chosen;
    for (int i = 0; i < boxes.size(); ++i)
        if (boxes[i]->isChecked())
            chosen << i;
    return chosen;
}

// ── AI request ───────────────────────────────────────────────────────────────────
QString askAi(QWidget* parent)
{
    Sheet s(parent);
    s.setSheetWidth(560);
    s.setHeader(QStringLiteral("sparkles"), theme::accentAlt(), u("AI 生成规则"),
                u("用一句话描述你想防住什么,AI 会给出 1~5 条建议规则,由你逐条勾选采纳。"));
    auto* edit = new QPlainTextEdit;
    edit->setPlaceholderText(u("例如:禁止 wscript.exe 创建子进程"));
    edit->setFixedHeight(96);
    edit->setAccessibleName(u("防护需求描述"));
    s.body()->addWidget(edit);
    s.body()->addWidget(ui::label(u("试试这些"), "caption"));
    auto* ex = new QWidget;
    auto* flow = new FlowLayout(ex, 6, 6);
    for (const char* t : {"禁止 Office 程序启动 PowerShell", "禁止任何程序写入启动文件夹", "拦截 mshta.exe 的网络外联",
                          "禁止 wscript.exe 创建子进程"}) {
        auto* b = ui::button(u(t), "ghost", QString(), true);
        QObject::connect(b, &QPushButton::clicked, &s, [edit, text = u(t)] { edit->setPlainText(text); });
        flow->addWidget(b);
    }
    s.body()->addWidget(ex);
    auto* note = ui::label(u("需要先在「设置 → 云查杀与 AI」里配置大模型。生成的规则不会自动生效,要你勾选采纳。"), "muted");
    note->setWordWrap(true);
    s.body()->addWidget(note);
    s.addButton(u("取消"), "ghost", [&s] { s.reject(); });
    QPushButton* go = s.addButton(u("生成"), "primary", [&s] { s.accept(); });
    go->setEnabled(false);
    QObject::connect(edit, &QPlainTextEdit::textChanged, &s,
                     [edit, go] { go->setEnabled(!edit->toPlainText().trimmed().isEmpty()); });
    edit->setFocus();
    return s.exec() == QDialog::Accepted ? edit->toPlainText().trimmed() : QString();
}

void fillRuleInspector(Inspector* in, const DefenseRule& r, IpcClient* ipc, QWidget* page)
{
    const evtfmt::Badge b = evtfmt::verdict(r.action);
    const evtfmt::Badge st = statusOf(r);
    in->setHeader(glyphOf(r.action), isOff(r) ? theme::textMuted() : b.color, ruleSentence(r),
                  u("创建于 ") + fmt::absoluteTime(r.createdUtc));
    QList<QPair<QString, QColor>> chips;
    chips << qMakePair(b.text, b.color) << qMakePair(st.text, st.color);
    for (const QString& c : conditionChips(r))
        chips << qMakePair(c, c == u("硬拦截") ? theme::danger() : theme::textSecondary());
    in->addChips(nullptr, chips);

    const Inspector::FieldFlags monoCopy = Inspector::Mono | Inspector::Copy;
    QVBoxLayout* s = in->addSection(u("条件"));
    in->addField(s, u("主体"), actorSpec(r), monoCopy);
    in->addField(s, u("匹配方式"), !r.actorPath.isEmpty() ? u("精确路径(不区分大小写)")
                                   : r.actorPattern.isEmpty() ? u("任意程序") : u("通配符(* 与 ?)"));
    in->addField(s, u("行为类型"), r.type ? evtfmt::typeLabel(*r.type) : u("所有行为"));
    in->addField(s, u("目标"), r.targetPattern.isEmpty() ? u("任意") : r.targetPattern, Inspector::Mono);
    if (!r.commandLinePattern.isEmpty())
        in->addField(s, u("命令行"), r.commandLinePattern, monoCopy);
    if (!r.parentPattern.isEmpty())
        in->addField(s, u("父进程"), r.parentPattern, Inspector::Mono);
    if (r.requireUnsigned || r.requireSigned)
        in->addField(s, u("签名条件"), r.requireUnsigned ? u("仅当主体没有可信签名") : u("仅当主体持有健康签名"));
    // 目标文件自身的签名条件(目前只有「模块加载」类规则会用到,见 DefenseRule 的声明)。
    if (r.requireTargetUnsigned || r.requireTargetSigned)
        in->addField(s, u("目标签名条件"), r.requireTargetUnsigned ? u("仅当被加载的模块没有可信签名")
                                                                  : u("仅当被加载的模块持有可信签名"));
    int shownHashes = 0;
    for (const QString& h : r.actorHashes) {
        if (shownHashes++ >= 5)
            break;
        in->addField(s, QStringLiteral("SHA-256"), h, monoCopy);
    }
    if (r.actorHashes.size() > 5)
        in->addText(s, u("… 另有 %1 个哈希").arg(r.actorHashes.size() - 5), "muted");

    s = in->addSection(u("生效"));
    in->addField(s, u("状态"), st.text);
    in->addField(s, u("有效期"), r.sessionOnly ? u("仅本次会话(不落盘)")
                                 : r.expiresUtc ? fmt::absoluteTime(*r.expiresUtc) : u("永久"));
    if (r.hardOverride)
        in->addField(s, u("优先级"), u("确定性恶意硬拦截(排序最高)"));
    if (r.exemptTrustedOsComponent)
        in->addField(s, u("豁免"), u("命中后仍可被强可信的系统组件豁免"));

    s = in->addSection(u("来源"));
    in->addField(s, u("备注"), r.note);
    in->addField(s, u("规则 ID"), r.id.toString(QUuid::WithoutBraces), monoCopy);

    const DefenseRule rule = r;
    in->addAction(QStringLiteral("trash"), u("删除规则"), "danger", [page, ipc, rule] {
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法删除规则。"));
            return;
        }
        ui::ConfirmSpec c;
        c.title = u("删除规则");
        c.summary = u("删除后立即生效:之后同样的行为会重新按默认流程判定。");
        c.subjectLabel = u("规则");
        c.subject = ruleSentence(rule) + u("\n") + actorSpec(rule);
        c.confirmText = u("删除");
        if (!ui::confirm(page, c))
            return;
        const QUuid id = rule.id;
        awaitRules(page, ipc,
                   [id](const QList<DefenseRule>& list) {
                       return std::none_of(list.cbegin(), list.cend(), [id](const DefenseRule& x) { return x.id == id; });
                   },
                   u("已删除规则:%1").arg(ruleSentence(rule)),
                   u("规则「%1」仍在列表里,删除没有生效。").arg(ruleSentence(rule)));
        ipc->deleteRule(id);
    });
    if (bareNameAllow(r.action, r.actorPath.isEmpty() ? r.actorPattern : r.actorPath))
        in->setNote(u("这条放行规则只按文件名匹配:任何改成这个名字的程序都会被放过。"), theme::warning());
    else if (r.action == bulwark::VerdictAction::Block)
        in->setNote(precedenceNote());
}

} // namespace

QWidget* pages::rules(IpcClient* ipc)
{
    auto* page = new RecordBrowser;
    page->setIdentity(identity::page(nav::Rules));
    page->searchBox()->setPlaceholderText(u("搜索主体 / 目标 / 备注…"));
    auto store = std::make_shared<RecordStore<DefenseRule>>(page->model(), &ruleView);

    const auto openBuilder = [page, ipc] {
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法添加规则。"));
            return;
        }
        RuleBuilder b(page);
        if (b.exec() != QDialog::Accepted)
            return;
        const bulwark::ipc::AddRulePayload p = b.payload();
        const QString want = p.actorPath;
        const QString text = sentence(p.action, p.actorPath, p.type, p.targetPattern);
        awaitRules(page, ipc,
                   [want, action = p.action](const QList<DefenseRule>& list) {
                       return std::any_of(list.cbegin(), list.cend(), [&](const DefenseRule& r) {
                           return r.action == action
                               && (r.actorPath.compare(want, Qt::CaseInsensitive) == 0
                                   || r.actorPattern.endsWith(want, Qt::CaseInsensitive)
                                   || r.actorPath.endsWith(want, Qt::CaseInsensitive));
                       });
                   },
                   u("已添加规则:%1").arg(text), u("没有在规则列表里看到新规则「%1」,请刷新核对。").arg(text));
        ipc->addRule(p);
    };
    page->setNoDataContent(QStringLiteral("sliders"), u("还没有规则"),
                           u("规则可以让某个程序的某类行为总是放行或总是拦截。信任的程序在「信任名单」页管理。"),
                           u("新增规则"), openBuilder);

    // ---- filters ---------------------------------------------------------------------------------------
    Segmented* seg = page->segments();
    seg->addSegment(u("全部"));
    seg->addSegment(u("拦截"));
    seg->addSegment(u("放行"));
    seg->addSegment(u("临时"));
    seg->addSegment(u("停用"));
    seg->setAccent(SegBlock, theme::danger());
    FilterChip* typeChip = page->addChip(u("类型"));
    typeChip->addOption(u("全部"));
    for (int i = 0; i <= int(bulwark::EventType::DnsQuery); ++i)
        typeChip->addOption(evtfmt::typeShort(bulwark::EventType(i)), i);
    page->setPredicate([store, seg, typeChip](int row) {
        const DefenseRule* r = store->itemAt(row);
        if (!r)
            return true;
        switch (seg->currentIndex()) {
        case SegBlock: if (r->action != bulwark::VerdictAction::Block) return false; break;
        case SegAllow: if (r->action != bulwark::VerdictAction::Allow) return false; break;
        case SegTemp:  if (!isTemporary(*r)) return false; break;
        case SegOff:   if (!isOff(*r)) return false; break;
        default: break;
        }
        // 「所有行为」的规则也作用于被筛选的类型,一并保留。
        if (typeChip->isActive() && r->type && int(*r->type) != typeChip->currentData().toInt())
            return false;
        return true;
    });
    page->setClearFilters([seg, typeChip] {
        seg->setCurrentIndex(SegAll);
        typeChip->reset();
    });
    QObject::connect(seg, &Segmented::currentChanged, page, [page] { page->refilter(); });
    QObject::connect(typeChip, &FilterChip::currentChanged, page, [page] { page->refilter(); });
    const auto updateCounts = [store, seg] {
        int n[5] = {0, 0, 0, 0, 0};
        for (const DefenseRule& r : store->items()) {
            ++n[SegAll];
            if (r.action == bulwark::VerdictAction::Block) ++n[SegBlock];
            if (r.action == bulwark::VerdictAction::Allow) ++n[SegAllow];
            if (isTemporary(r)) ++n[SegTemp];
            if (isOff(r)) ++n[SegOff];
        }
        for (int i = 0; i < 5; ++i)
            seg->setCount(i, n[i]);
    };

    page->setInspectorBuilder([store, ipc, page](Inspector* in, int row) {
        if (const DefenseRule* r = store->itemAt(row))
            fillRuleInspector(in, *r, ipc, page);
    });
    page->setContextMenuBuilder([page, store](QMenu* m, const QList<int>& rows) {
        if (rows.size() != 1)
            return;
        const DefenseRule* r = store->itemAt(rows.first());
        if (!r)
            return;
        const QString spec = actorSpec(*r);
        pagekit::menuAction(m, QStringLiteral("eye"), u("查看详情"), page, [page, key = r->id.toString(QUuid::WithoutBraces)] {
            page->selectKey(key, true);
        });
        pagekit::menuAction(m, QStringLiteral("copy"), u("复制主体"), page, [spec] {
            if (QClipboard* cb = QGuiApplication::clipboard())
                cb->setText(spec);
        });
    });

    // ---- header: AI · intel · new rule · ⋯ refresh ------------------------------------------------------
    QHBoxLayout* actions = pagekit::headerActions(page);
    auto* aiBtn = pagekit::headerButton(actions, QStringLiteral("sparkles"), u("AI 生成"));
    auto* intelBtn = pagekit::headerButton(actions, QStringLiteral("cloud"), u("情报刷新"));
    auto* addBtn = pagekit::headerButton(actions, QStringLiteral("plus"), u("新增规则"), "primary");
    QMenu* more = pagekit::headerMenu(actions);
    const auto reload = [page, ipc] {
        if (!ipc->isConnected())
            return;
        page->setLoading(true);
        ipc->requestRules();
    };
    pagekit::menuAction(more, QStringLiteral("refresh"), u("刷新列表"), page, reload);
    QObject::connect(addBtn, &QPushButton::clicked, page, openBuilder);

    // 情报刷新(ThreatFox):先预览拉取到的候选规则,用户勾选后再采纳(低误报 · 用户可控)。
    enum class Intel { Idle, Preview, Apply };
    auto intel = std::make_shared<Intel>(Intel::Idle);
    QObject::connect(intelBtn, &QPushButton::clicked, page, [page, ipc, intel] {
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法刷新威胁情报。"));
            return;
        }
        *intel = Intel::Preview;
        ui::notify(page, ui::Tone::Info, u("正在从 ThreatFox 拉取最新 IOC,生成候选规则…"));
        ipc->intelRefresh(/*previewOnly=*/true);
    });
    QObject::connect(ipc, &IpcClient::intelResult, page, [page, ipc, intel](const bulwark::ipc::IntelRefreshResultPayload& r) {
        if (*intel == Intel::Idle)
            return; // 别处(设置页)发起的
        if (*intel == Intel::Preview && !r.generatedRules.isEmpty()) {
            *intel = Intel::Idle;
            QList<AdoptRow> rows;
            for (const DefenseRule& dr : r.generatedRules)
                rows << AdoptRow{ruleSentence(dr), actorSpec(dr) + (dr.note.isEmpty() ? QString() : u(" · ") + dr.note)};
            // Threat intel wears the hue of the intel pages (云信誉 / 情报源), not azurite:
            // nothing here is an "info" state.
            const QList<int> sel = adopt(page, QStringLiteral("cloud"), identity::page(nav::Reputation), u("采纳情报规则"),
                                         u("从 ThreatFox 拉取 %1 条 IOC,生成 %2 条候选规则。勾选要采纳的:")
                                             .arg(r.iocCount)
                                             .arg(r.generatedRules.size()),
                                         rows);
            if (sel.isEmpty())
                return;
            QList<DefenseRule> chosen;
            for (int i : sel)
                chosen << r.generatedRules[i];
            *intel = Intel::Apply;
            ipc->intelApply(chosen);
            return;
        }
        const bool apply = *intel == Intel::Apply;
        *intel = Intel::Idle;
        const QString msg = !r.message.isEmpty() ? r.message
                            : apply              ? u("已采纳 %1 条情报规则。").arg(r.rulesApplied)
                                                 : u("没有新的候选规则。");
        ui::notify(page, !r.success ? ui::Tone::Danger : (apply ? ui::Tone::Success : ui::Tone::Info), msg);
    });

    // AI 生成:自然语言 -> 大模型给出 1~5 条建议规则,勾选后逐条加入。
    auto aiPending = std::make_shared<bool>(false);
    QObject::connect(aiBtn, &QPushButton::clicked, page, [page, ipc, aiPending] {
        const QString text = askAi(page);
        if (text.isEmpty())
            return;
        *aiPending = true;
        ui::notify(page, ui::Tone::Info, u("AI 正在根据描述生成规则…"));
        ipc->aiGenerateRules(text);
    });
    QObject::connect(ipc, &IpcClient::aiRulesSuggested, page, [page, ipc, store, aiPending](const QList<AiSuggestedRule>& rules) {
        if (!*aiPending)
            return;
        *aiPending = false;
        if (rules.isEmpty()) {
            ui::notify(page, ui::Tone::Warning, u("AI 没有给出可用的规则(可能没有配置大模型,或没能理解这段描述)。"));
            return;
        }
        QList<AdoptRow> rows;
        for (const AiSuggestedRule& s : rules)
            rows << AdoptRow{sentence(s.payload.action, s.payload.actorPath, s.payload.type, s.payload.targetPattern),
                             evtfmt::nativePath(s.payload.actorPath) + (s.note.isEmpty() ? QString() : u(" · ") + s.note)};
        const QList<int> sel = adopt(page, QStringLiteral("sparkles"), theme::accentAlt(), u("采纳 AI 建议的规则"),
                                     u("AI 建议以下 %1 条规则。勾选要采纳的:").arg(rules.size()), rows);
        if (sel.isEmpty())
            return;
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法添加规则。"));
            return;
        }
        const int before = store->size();
        const int n = int(sel.size());
        awaitRules(page, ipc,
                   [before, n](const QList<DefenseRule>& list) {
                       const auto count = std::count_if(list.cbegin(), list.cend(),
                                                        [](const DefenseRule& r) { return !r.isTrustEntry(); });
                       return count >= before + n;
                   },
                   u("已添加 %1 条 AI 建议的规则。").arg(n),
                   u("提交了 %1 条规则,服务没有全部确认(重复的规则可能被合并),请核对列表。").arg(n));
        for (int i : sel)
            ipc->addRule(rules[i].payload);
    });

    // ---- data ---------------------------------------------------------------------------------------------
    QObject::connect(ipc, &IpcClient::rulesReceived, page, [page, store, updateCounts](const QList<DefenseRule>& rules) {
        QList<DefenseRule> list;
        list.reserve(rules.size());
        for (const DefenseRule& r : rules)
            if (!r.isTrustEntry()) // 信任项在「信任名单」页展示
                list << r;
        std::stable_sort(list.begin(), list.end(),
                         [](const DefenseRule& a, const DefenseRule& b) { return a.createdUtc > b.createdUtc; });
        store->reset(list);
        page->setLoading(false);
        updateCounts();
    });
    // 启动不卡:规则列表可能较大(海量情报规则),回填延后到窗口可交互之后,略晚于事件历史。
    pagekit::onConnected(page, ipc, page, 800, reload);
    updateCounts();
    return page;
}
