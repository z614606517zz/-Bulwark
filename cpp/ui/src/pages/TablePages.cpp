#include "pages/TablePages.h"
#include "dialogs/AttackTimelineWindow.h"
#include "ipc/IpcClient.h"
#include "widgets/TableKit.h"
#include "widgets/Ui.h"
#include "Theme.h"

#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/PersistenceEntry.h"
#include "bulwark/models/SecurityEvent.h"

#include <QJsonDocument>

#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

struct Built {
    QWidget* page = nullptr;
    QHBoxLayout* toolbar = nullptr;
    QTableWidget* table = nullptr;
};

// Standard page scaffold: padded column with a toolbar row above a table.
Built buildPage(const QStringList& headers)
{
    auto* page = new QWidget;
    auto* v = new QVBoxLayout(page);
    v->setContentsMargins(theme::metric::pagePad, 22, theme::metric::pagePad,
                          theme::metric::pagePad);
    v->setSpacing(16);

    auto* tb = new QHBoxLayout;
    tb->setSpacing(10);
    v->addLayout(tb);

    auto* t = ui::table(headers);
    v->addWidget(t, 1);
    return {page, tb, t};
}

int addRow(QTableWidget* t)
{
    const int r = t->rowCount();
    t->insertRow(r);
    return r;
}

void put(QTableWidget* t, int r, int c, const QString& text, bool secondary = false, bool mono = false)
{
    t->setItem(r, c, ui::textItem(text, secondary, mono));
}

QPushButton* smallBtn(const QString& text, const char* variant)
{
    auto* b = new QPushButton(text);
    b->setProperty("variant", variant);
    b->setProperty("size", "sm");
    b->setCursor(Qt::PointingHandCursor);
    return b;
}

void actionCell(QTableWidget* t, int r, int c, QPushButton* b1, QPushButton* b2 = nullptr)
{
    auto* w = new QWidget;
    w->setStyleSheet(QStringLiteral("background:transparent;"));
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(8, 0, 8, 0);
    h->setSpacing(6);
    h->addWidget(b1);
    if (b2)
        h->addWidget(b2);
    h->addStretch();
    t->setCellWidget(r, c, w);
}

// A small empty-state placeholder shown above/below the table when it has no rows.
QLabel* emptyHint(const QString& text)
{
    auto* l = ui::label(text, "muted");
    l->setAlignment(Qt::AlignCenter);
    return l;
}

// Stash the full SecurityEvent (as compact JSON) on the row's first cell so a
// double-click can reconstruct the attack timeline.
void stashEvent(QTableWidget* t, int row, const bulwark::SecurityEvent& e)
{
    if (auto* c0 = t->item(row, 0))
        c0->setData(Qt::UserRole, QString::fromUtf8(QJsonDocument(e.toJson()).toJson(QJsonDocument::Compact)));
}

// Double-click a row -> open the attack-timeline window for its stashed event.
void wireAttackTimeline(QTableWidget* t, QWidget* page)
{
    QObject::connect(t, &QTableWidget::cellDoubleClicked, page, [t](int row, int) {
        auto* c0 = t->item(row, 0);
        if (!c0) return;
        const QString js = c0->data(Qt::UserRole).toString();
        if (js.isEmpty()) return;
        AttackTimelineWindow dlg(
            bulwark::SecurityEvent::fromJson(QJsonDocument::fromJson(js.toUtf8()).object()), t->window());
        dlg.exec();
    });
}

// ---- shared formatting -----------------------------------------------------

QString eventTypeLabel(bulwark::EventType t)
{
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return u("进程创建");
    case E::ProcessTerminate: return u("结束进程");
    case E::RemoteThread:     return u("远程线程");
    case E::ImageLoad:        return u("映像加载");
    case E::FileWrite:        return u("文件写入");
    case E::FileDelete:       return u("文件删除");
    case E::RegistryWrite:    return u("注册表写入");
    case E::NetworkConnect:   return u("网络外联");
    case E::SelfProtect:      return u("自我保护");
    case E::DnsQuery:         return u("DNS 解析");
    }
    return u("事件");
}

QColor riskColor(int score)
{
    if (score >= 80) return theme::danger();
    if (score >= 50) return theme::warning();
    return theme::success();
}

QString riskLabel(int score)
{
    if (score >= 80) return u("高危");
    if (score >= 50) return u("可疑");
    return u("正常");
}

void verdictPill(bulwark::VerdictAction a, QString& text, QColor& color)
{
    switch (a) {
    case bulwark::VerdictAction::Block: text = u("拦截"); color = theme::danger(); break;
    case bulwark::VerdictAction::Ask:   text = u("询问"); color = theme::warning(); break;
    default:                            text = u("放行"); color = theme::success(); break;
    }
}

// 处置文案:action==Block 时按【真实执行结果】(enforcement)显示,杜绝「判了 Block 就显示已拦截、
// 实则毫无动作」的假拦截。只有真前拦 / 已结束进程 / 已加黑名单才算真拦;未能处置如实标注。
void dispositionPill(bulwark::VerdictAction action, bulwark::EnforcementOutcome enf,
                     QString& text, QColor& color)
{
    if (action != bulwark::VerdictAction::Block) {
        if (action == bulwark::VerdictAction::Ask) { text = u("已询问"); color = theme::warning(); }
        else                                       { text = u("已放行"); color = theme::success(); }
        return;
    }
    using EO = bulwark::EnforcementOutcome;
    switch (enf) {
    case EO::KernelBlocked:     text = u("已拦截");        color = theme::danger();  break; // 内核前拦
    case EO::Terminated:        text = u("已结束进程");    color = theme::danger();  break; // 事后杀成功
    case EO::ModuleBlacklisted: text = u("已禁止加载");    color = theme::danger();  break; // 下次前拦
    case EO::AlertedOnly:       text = u("仅告警·未拦截"); color = theme::warning(); break; // 未实际拦截
    case EO::Failed:            text = u("拦截失败");      color = theme::warning(); break;
    case EO::NotApplicable:
    default:                    text = u("已拦截");        color = theme::danger();  break; // 历史记录兜底
    }
}



constexpr int kMaxLogRows = 200; // cap the live-fed log tables to bound memory

} // namespace

// ── 拦截记录:被「直接拦截」的确定性高危行为(event-log 里 action==Block)────────
// 打开时向服务请求事件历史回填(重启后仍保留),之后实时追加。
QWidget* pages::interceptions(IpcClient* ipc)
{
    auto b = buildPage({u("时间"), u("类型"), u("程序"), u("目标"), u("风险"), u("处置")});
    b.toolbar->addWidget(ui::searchBox(u("搜索程序 / 目标…")));
    b.toolbar->addStretch();
    auto* count = ui::label(u("等待事件…"), "secondary");
    b.toolbar->addWidget(count);
    auto* clearBtn = ui::toolButton("trash", u("清空"), "ghost", theme::danger());
    b.toolbar->addWidget(clearBtn);
    QObject::connect(clearBtn, &QPushButton::clicked, b.page, [ipc, page = b.page] {
        if (QMessageBox::question(page, u("清空拦截记录"),
                u("确定清空全部事件历史吗?\n拦截记录与活动日志共享同一份历史,清空后两者都会被清空,且不可恢复。"))
            == QMessageBox::Yes)
            ipc->clearEventHistory();
    });

    auto* t = b.table;
    t->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    t->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    wireAttackTimeline(t, b.page); // 双击回溯攻击时间线

    // Insert a Block row at the top (newest first), using the event's own timestamp.
    // 处置列按【真实执行结果】显示(内核前拦/已结束进程/已禁止加载/仅告警未拦截),而非一律"已拦截"。
    auto addRowTop = [t](const bulwark::SecurityEvent& e, bulwark::EnforcementOutcome enf) {
        t->insertRow(0);
        put(t, 0, 0, e.timestampUtc.toLocalTime().toString(QStringLiteral("MM-dd HH:mm:ss")), true, true);
        put(t, 0, 1, eventTypeLabel(e.type));
        put(t, 0, 2, QFileInfo(e.actorPath).fileName());
        put(t, 0, 3, e.target, true, true);
        ui::pillCell(t, 0, 4, riskLabel(e.riskScore), riskColor(e.riskScore));
        QString dt; QColor dc; dispositionPill(bulwark::VerdictAction::Block, enf, dt, dc);
        ui::pillCell(t, 0, 5, dt, dc);
        stashEvent(t, 0, e);
        while (t->rowCount() > kMaxLogRows) t->removeRow(t->rowCount() - 1);
    };
    auto refreshCount = [t, count] {
        count->setText(t->rowCount() == 0 ? u("暂无拦截记录") : u("共 %1 条").arg(t->rowCount()));
    };
    QObject::connect(ipc, &IpcClient::eventLogReceived, b.page,
                     [addRowTop, refreshCount](const bulwark::ipc::EventLogPayload& p) {
                         if (p.action != bulwark::VerdictAction::Block) return;
                         addRowTop(p.event, p.enforcement);
                         refreshCount();
                     });
    QObject::connect(ipc, &IpcClient::eventHistoryReceived, b.page,
                     [t, addRowTop, refreshCount](const QList<bulwark::ipc::EventLogPayload>& events) {
                         t->setRowCount(0);
                         for (const auto& p : events) // oldest->newest, insert-at-top => newest on top
                             if (p.action == bulwark::VerdictAction::Block) addRowTop(p.event, p.enforcement);
                         refreshCount();
                     });
    QObject::connect(ipc, &IpcClient::connectionChanged, b.page,
                     [ipc](bool c) { if (c) ipc->requestEventHistory(); });
    if (ipc->isConnected()) ipc->requestEventHistory();
    return b.page;
}

// ── 活动日志:更全的事件流(放行 / 询问 / 拦截)。打开时回填历史,之后实时追加。────────
QWidget* pages::activity(IpcClient* ipc)
{
    auto b = buildPage({u("时间"), u("事件"), u("程序"), u("PID"), u("风险分"), u("裁决")});
    b.toolbar->addWidget(ui::searchBox(u("搜索事件…")));
    b.toolbar->addStretch();
    auto* count = ui::label(u("等待事件…"), "secondary");
    b.toolbar->addWidget(count);
    auto* clearBtn = ui::toolButton("trash", u("清空"), "ghost", theme::danger());
    b.toolbar->addWidget(clearBtn);
    QObject::connect(clearBtn, &QPushButton::clicked, b.page, [ipc, page = b.page] {
        if (QMessageBox::question(page, u("清空活动日志"),
                u("确定清空全部事件历史吗?\n拦截记录与活动日志共享同一份历史,清空后两者都会被清空,且不可恢复。"))
            == QMessageBox::Yes)
            ipc->clearEventHistory();
    });

    auto* t = b.table;
    t->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    wireAttackTimeline(t, b.page); // 双击回溯攻击时间线

    auto addRowTop = [t](const bulwark::ipc::EventLogPayload& p) {
        const bulwark::SecurityEvent& e = p.event;
        t->insertRow(0);
        put(t, 0, 0, e.timestampUtc.toLocalTime().toString(QStringLiteral("MM-dd HH:mm:ss")), true, true);
        put(t, 0, 1, eventTypeLabel(e.type));
        put(t, 0, 2, QFileInfo(e.actorPath).fileName());
        put(t, 0, 3, QString::number(e.actorPid), true, true);
        put(t, 0, 4, QString::number(e.riskScore), true);
        QString vt; QColor vc; verdictPill(p.action, vt, vc);
        ui::pillCell(t, 0, 5, vt, vc);
        stashEvent(t, 0, e);
        while (t->rowCount() > kMaxLogRows) t->removeRow(t->rowCount() - 1);
    };
    auto refreshCount = [t, count] {
        count->setText(t->rowCount() == 0 ? u("暂无事件") : u("最近 %1 条").arg(t->rowCount()));
    };
    QObject::connect(ipc, &IpcClient::eventLogReceived, b.page,
                     [addRowTop, refreshCount](const bulwark::ipc::EventLogPayload& p) {
                         addRowTop(p);
                         refreshCount();
                     });
    QObject::connect(ipc, &IpcClient::eventHistoryReceived, b.page,
                     [t, addRowTop, refreshCount](const QList<bulwark::ipc::EventLogPayload>& events) {
                         t->setRowCount(0);
                         for (const auto& p : events) addRowTop(p); // oldest->newest => newest on top
                         refreshCount();
                     });
    QObject::connect(ipc, &IpcClient::connectionChanged, b.page,
                     [ipc](bool c) { if (c) ipc->requestEventHistory(); });
    if (ipc->isConnected()) ipc->requestEventHistory();
    return b.page;
}

namespace {

// Compact modal to compose a new rule (actor + optional type/target + action).
bool promptAddRule(QWidget* parent, bulwark::ipc::AddRulePayload& out)
{
    QDialog dlg(parent);
    dlg.setWindowTitle(u("新增防护规则"));
    dlg.setMinimumWidth(460);
    auto* form = new QFormLayout(&dlg);

    auto* actor = new QLineEdit;
    actor->setPlaceholderText(u("完整路径、通配(*\\mimikatz.exe)或裸文件名"));
    auto* type = new QComboBox;
    type->addItem(u("所有行为"), -1);
    for (int i = 0; i <= static_cast<int>(bulwark::EventType::DnsQuery); ++i)
        type->addItem(eventTypeLabel(static_cast<bulwark::EventType>(i)), i);
    auto* target = new QLineEdit;
    target->setPlaceholderText(u("目标通配,留空=任意"));
    auto* action = new QComboBox;
    action->addItem(u("放行"), static_cast<int>(bulwark::VerdictAction::Allow));
    action->addItem(u("拦截"), static_cast<int>(bulwark::VerdictAction::Block));

    form->addRow(u("主体"), actor);
    form->addRow(u("行为类型"), type);
    form->addRow(u("目标"), target);
    form->addRow(u("处置"), action);

    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    bb->button(QDialogButtonBox::Ok)->setText(u("添加"));
    bb->button(QDialogButtonBox::Cancel)->setText(u("取消"));
    form->addRow(bb);
    QObject::connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() != QDialog::Accepted || actor->text().trimmed().isEmpty())
        return false;
    out.actorPath = actor->text().trimmed();
    const int tv = type->currentData().toInt();
    out.type = tv < 0 ? std::optional<bulwark::EventType>()
                      : std::optional<bulwark::EventType>(static_cast<bulwark::EventType>(tv));
    out.targetPattern = target->text().trimmed();
    out.action = static_cast<bulwark::VerdictAction>(action->currentData().toInt());
    return true;
}

// One-line label for a defense rule (used in the intel/AI adopt dialogs).
QString ruleLabel(const bulwark::DefenseRule& r)
{
    const QString actor = !r.actorPath.isEmpty() ? r.actorPath
                          : (r.actorPattern.isEmpty() ? u("*") : r.actorPattern);
    QString s = actor + u("  →  ") + (r.action == bulwark::VerdictAction::Block ? u("拦截") : u("放行"));
    if (r.type.has_value()) s += u(" · ") + eventTypeLabel(*r.type);
    if (!r.note.isEmpty())  s += QStringLiteral("  (") + r.note + QLatin1Char(')');
    return s;
}

QString suggestionLabel(const AiSuggestedRule& r)
{
    QString s = r.payload.actorPath
        + u("  →  ") + (r.payload.action == bulwark::VerdictAction::Block ? u("拦截") : u("放行"));
    if (r.payload.type.has_value()) s += u(" · ") + eventTypeLabel(*r.payload.type);
    if (!r.note.isEmpty())          s += QStringLiteral("  (") + r.note + QLatin1Char(')');
    return s;
}

// A checklist dialog: rows pre-checked, returns the indices the user kept.
QList<int> selectFromList(QWidget* parent, const QString& title, const QString& header,
                          const QStringList& rows)
{
    QList<int> selected;
    QDialog dlg(parent);
    dlg.setWindowTitle(title);
    dlg.setMinimumWidth(600);
    auto* v = new QVBoxLayout(&dlg);
    auto* h = new QLabel(header);
    h->setWordWrap(true);
    v->addWidget(h);
    auto* list = new QListWidget;
    for (const QString& r : rows) {
        auto* it = new QListWidgetItem(r, list);
        it->setFlags(it->flags() | Qt::ItemIsUserCheckable);
        it->setCheckState(Qt::Checked);
    }
    v->addWidget(list, 1);
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    bb->button(QDialogButtonBox::Ok)->setText(u("采纳选中"));
    bb->button(QDialogButtonBox::Cancel)->setText(u("取消"));
    v->addWidget(bb);
    QObject::connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    if (dlg.exec() != QDialog::Accepted)
        return selected;
    for (int i = 0; i < list->count(); ++i)
        if (list->item(i)->checkState() == Qt::Checked)
            selected.append(i);
    return selected;
}

} // namespace

// ── 防护规则:查看 / 新增 / 删除。服务在增删后自动回推最新规则列表。────────────────
QWidget* pages::rules(IpcClient* ipc)
{
    auto b = buildPage({u("状态"), u("主体"), u("类型"), u("目标"), u("动作"), u("备注"), u("操作")});
    b.toolbar->addWidget(ui::searchBox(u("搜索规则…")));
    b.toolbar->addStretch();
    auto* refresh = ui::toolButton("refresh", u("刷新"), "ghost", theme::textSecondary());
    auto* intel = ui::toolButton("cloud", u("情报刷新"), "ghost", theme::textSecondary());
    auto* aiGen = ui::toolButton("sparkles", u("AI 生成"), "ghost", theme::accentAlt());
    auto* add = ui::toolButton("plus", u("新增规则"), "primary", theme::accentInk());
    b.toolbar->addWidget(refresh);
    b.toolbar->addWidget(intel);
    b.toolbar->addWidget(aiGen);
    b.toolbar->addWidget(add);

    auto* t = b.table;
    t->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    t->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);

    QObject::connect(ipc, &IpcClient::rulesReceived, b.page,
                     [t, ipc](const QList<bulwark::DefenseRule>& rules) {
        t->setRowCount(0);
        const QString trustTag = bulwark::DefenseRule::trustNoteTag();
        for (const bulwark::DefenseRule& r : rules) {
            if (r.isTrustEntry()) continue; // 信任项在「信任名单」页展示
            const int i = addRow(t);
            QString st; QColor sc;
            if (!r.enabled)            { st = u("停用"); sc = theme::textMuted(); }
            else if (r.sessionOnly)    { st = u("会话"); sc = theme::info(); }
            else if (r.expiresUtc.has_value()) { st = u("限时"); sc = theme::warning(); }
            else                       { st = u("启用"); sc = theme::success(); }
            ui::pillCell(t, i, 0, st, sc);
            const QString actor = !r.actorPath.isEmpty() ? r.actorPath
                                  : (r.actorPattern.isEmpty() ? u("*") : r.actorPattern);
            put(t, i, 1, actor, false, true);
            put(t, i, 2, r.type.has_value() ? eventTypeLabel(*r.type) : u("所有"));
            put(t, i, 3, r.targetPattern.isEmpty() ? u("*") : r.targetPattern, true, true);
            QString at; QColor ac; verdictPill(r.action, at, ac);
            ui::pillCell(t, i, 4, at, ac);
            put(t, i, 5, r.note, true);
            auto* del = smallBtn(u("删除"), "danger");
            const QUuid id = r.id;
            QObject::connect(del, &QPushButton::clicked, t, [ipc, id] { ipc->deleteRule(id); });
            actionCell(t, i, 6, del);
        }
    });

    QObject::connect(refresh, &QPushButton::clicked, b.page, [ipc] { ipc->requestRules(); });
    QObject::connect(add, &QPushButton::clicked, b.page, [ipc, page = b.page] {
        bulwark::ipc::AddRulePayload p;
        if (promptAddRule(page, p)) ipc->addRule(p);
    });

    // 情报刷新(ThreatFox):先预览拉取到的候选规则,用户勾选后再采纳(低误报 · 用户可控)。
    QObject::connect(intel, &QPushButton::clicked, b.page, [ipc] { ipc->intelRefresh(/*previewOnly=*/true); });
    QObject::connect(ipc, &IpcClient::intelResult, b.page,
                     [ipc, page = b.page](const bulwark::ipc::IntelRefreshResultPayload& r) {
        if (!r.generatedRules.isEmpty()) { // 预览结果:交用户勾选采纳
            QStringList rows;
            for (const bulwark::DefenseRule& dr : r.generatedRules) rows << ruleLabel(dr);
            const QList<int> sel = selectFromList(
                page, u("情报刷新 · 采纳规则"),
                u("从 ThreatFox 拉取 %1 条 IOC,生成 %2 条候选规则,勾选后采纳:")
                    .arg(r.iocCount).arg(r.generatedRules.size()),
                rows);
            if (!sel.isEmpty()) {
                QList<bulwark::DefenseRule> chosen;
                for (int i : sel) chosen << r.generatedRules[i];
                ipc->intelApply(chosen);
            }
        } else { // 采纳/刷新回执(无候选规则):提示结果
            QMessageBox::information(page, u("威胁情报"),
                                     r.message.isEmpty() ? u("已完成") : r.message);
        }
    });

    // AI 生成:自然语言 -> 大模型给出 1~5 条建议规则,勾选后逐条加入。
    QObject::connect(aiGen, &QPushButton::clicked, b.page, [ipc, page = b.page] {
        bool ok = false;
        const QString text = QInputDialog::getMultiLineText(
            page, u("AI 生成规则"),
            u("用自然语言描述防护需求(例如:禁止 wscript 创建子进程):"), QString(), &ok);
        if (ok && !text.trimmed().isEmpty()) ipc->aiGenerateRules(text.trimmed());
    });
    QObject::connect(ipc, &IpcClient::aiRulesSuggested, b.page,
                     [ipc, page = b.page](const QList<AiSuggestedRule>& rules) {
        if (rules.isEmpty()) {
            QMessageBox::information(page, u("AI 生成规则"),
                                     u("AI 未给出可用规则(未配置模型 / 未能理解需求)。"));
            return;
        }
        QStringList rows;
        for (const AiSuggestedRule& s : rules) rows << suggestionLabel(s);
        const QList<int> sel = selectFromList(page, u("AI 生成规则 · 采纳"),
                                              u("AI 建议以下 %1 条规则,勾选后采纳:").arg(rules.size()), rows);
        for (int i : sel) ipc->addRule(rules[i].payload);
    });

    QObject::connect(ipc, &IpcClient::connectionChanged, b.page,
                     [ipc](bool c) { if (c) ipc->requestRules(); });
    if (ipc->isConnected()) ipc->requestRules();
    return b.page;
}

// ── 信任名单:受信任程序/目录直接放行。服务在增删后自动回推最新列表。────────────────
QWidget* pages::trust(IpcClient* ipc)
{
    auto b = buildPage({u("程序 / 目录"), u("类型"), u("备注"), u("添加时间"), u("操作")});
    b.toolbar->addWidget(ui::searchBox(u("搜索信任项…")));
    b.toolbar->addStretch();
    auto* refresh = ui::toolButton("refresh", u("刷新"), "ghost", theme::textSecondary());
    auto* add = ui::toolButton("plus", u("信任文件"), "primary", theme::accentInk());
    auto* addDir = ui::toolButton("plus", u("信任文件夹"), "ghost", theme::accentInk());
    b.toolbar->addWidget(refresh);
    b.toolbar->addWidget(addDir);
    b.toolbar->addWidget(add);

    auto* t = b.table;
    t->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    t->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    QObject::connect(ipc, &IpcClient::trustReceived, b.page,
                     [t, ipc](const QList<bulwark::DefenseRule>& entries) {
        t->setRowCount(0);
        const QString tag = bulwark::DefenseRule::trustNoteTag();
        for (const bulwark::DefenseRule& r : entries) {
            const int i = addRow(t);
            const bool isDir = r.actorPath.isEmpty() && !r.actorPattern.isEmpty();
            const QString path = isDir ? r.actorPattern : r.actorPath;
            put(t, i, 0, path, false, true);
            ui::pillCell(t, i, 1, isDir ? u("目录") : u("文件"), theme::info());
            QString note = r.note;
            if (note.startsWith(tag)) note = note.mid(tag.size()).trimmed();
            put(t, i, 2, note, true);
            put(t, i, 3, r.createdUtc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd")), true, true);
            auto* rm = smallBtn(u("移除"), "ghost");
            const QUuid id = r.id;
            QObject::connect(rm, &QPushButton::clicked, t, [ipc, id] { ipc->removeTrust(id); });
            actionCell(t, i, 4, rm);
        }
    });

    QObject::connect(refresh, &QPushButton::clicked, b.page, [ipc] { ipc->requestTrust(); });
    QObject::connect(add, &QPushButton::clicked, b.page, [ipc, page = b.page] {
        const QString file = QFileDialog::getOpenFileName(
            page, u("选择要信任的程序"), QString(), u("可执行文件 (*.exe *.dll);;所有文件 (*.*)"));
        if (!file.isEmpty()) ipc->addTrust(QDir::toNativeSeparators(file), u("用户手动信任"));
    });
    // 信任文件夹:该目录及子目录下运行的所有程序「完全跳过检测」直接放行。此举关闭了对整个
    // 目录的防护,故先弹二次确认,避免误信任(如误选 C:\ 或系统盘导致防护形同虚设)。
    QObject::connect(addDir, &QPushButton::clicked, b.page, [ipc, page = b.page] {
        const QString dir = QFileDialog::getExistingDirectory(
            page, u("选择要信任的文件夹(该文件夹内运行的所有程序将不再检测)"));
        if (dir.isEmpty()) return;
        const auto ret = QMessageBox::question(
            page, u("信任文件夹"),
            u("信任后,该文件夹及其子目录中运行的所有程序都将【完全跳过检测】并直接放行。\n"
              "请仅信任你完全确信安全的文件夹。\n\n确定信任吗?\n%1")
                .arg(QDir::toNativeSeparators(dir)),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (ret == QMessageBox::Yes)
            ipc->addTrust(QDir::toNativeSeparators(dir), u("用户手动信任文件夹"), true);
    });
    QObject::connect(ipc, &IpcClient::connectionChanged, b.page,
                     [ipc](bool c) { if (c) ipc->requestTrust(); });
    if (ipc->isConnected()) ipc->requestTrust();
    return b.page;
}

namespace {

QString fmtSize(qint64 bytes)
{
    if (bytes >= 1024 * 1024) return QString::number(bytes / (1024.0 * 1024.0), 'f', 1) + u(" MB");
    if (bytes >= 1024)        return QString::number(bytes / 1024.0, 'f', 0) + u(" KB");
    return QString::number(bytes) + u(" B");
}

QString persistenceCategoryLabel(bulwark::PersistenceCategory c)
{
    using C = bulwark::PersistenceCategory;
    switch (c) {
    case C::RegistryRun:     return u("注册表 Run");
    case C::RegistryRunOnce: return u("注册表 RunOnce");
    case C::StartupFolder:   return u("启动文件夹");
    case C::ScheduledTask:   return u("计划任务");
    case C::Service:         return u("服务");
    case C::WmiSubscription: return u("WMI 订阅");
    case C::IfeoDebugger:    return u("映像劫持");
    case C::Winlogon:        return u("Winlogon");
    case C::AppInitDll:      return u("AppInit_DLLs");
    default:                 return u("其它");
    }
}

} // namespace

// ── 隔离区:还原 / 永久删除。服务在操作后自动回推最新列表。────────────────────────
QWidget* pages::quarantine(IpcClient* ipc)
{
    auto b = buildPage({u("文件"), u("原始路径"), u("原因"), u("大小"), u("隔离时间"), u("操作")});
    b.toolbar->addWidget(ui::searchBox(u("搜索隔离项…")));
    b.toolbar->addStretch();
    auto* refresh = ui::toolButton("refresh", u("刷新"), "ghost", theme::textSecondary());
    auto* count = ui::label(QString(), "secondary");
    b.toolbar->addWidget(count);
    b.toolbar->addWidget(refresh);

    auto* t = b.table;
    t->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    t->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    QObject::connect(ipc, &IpcClient::quarantineReceived, b.page,
                     [t, count, ipc](const QList<bulwark::ipc::QuarantineItemPayload>& items) {
        t->setRowCount(0);
        qint64 totalBytes = 0;
        for (const auto& it : items) {
            const int i = addRow(t);
            put(t, i, 0, it.fileName, false, true);
            put(t, i, 1, it.originalPath, true, true);
            put(t, i, 2, it.reason, true);
            put(t, i, 3, fmtSize(it.size), true);
            put(t, i, 4, it.quarantinedUtc.toLocalTime().toString(QStringLiteral("MM-dd HH:mm")), true, true);
            auto* restore = smallBtn(u("还原"), "ghost");
            auto* del = smallBtn(u("删除"), "danger");
            const QUuid id = it.id;
            QObject::connect(restore, &QPushButton::clicked, t, [ipc, id] { ipc->quarantineRestore(id); });
            QObject::connect(del, &QPushButton::clicked, t, [ipc, id] { ipc->quarantineDelete(id); });
            actionCell(t, i, 5, restore, del);
            totalBytes += it.size;
        }
        count->setText(items.isEmpty() ? u("隔离区为空")
                                       : u("共 %1 项 · %2").arg(items.size()).arg(fmtSize(totalBytes)));
    });

    QObject::connect(refresh, &QPushButton::clicked, b.page, [ipc] { ipc->requestQuarantine(); });
    QObject::connect(ipc, &IpcClient::connectionChanged, b.page,
                     [ipc](bool c) { if (c) ipc->requestQuarantine(); });
    if (ipc->isConnected()) ipc->requestQuarantine();
    return b.page;
}

// ── 自启动项:只读枚举 7 类持久化点,按风险着色。绝不修改任何自启动项。──────────────
QWidget* pages::persistence(IpcClient* ipc)
{
    auto b = buildPage({u("名称"), u("类别"), u("路径 / 命令"), u("ATT&CK"), u("风险"), u("状态")});
    auto* scan = ui::toolButton("refresh", u("重新扫描"), "ghost", theme::textSecondary());
    b.toolbar->addWidget(scan);
    b.toolbar->addStretch();
    auto* count = ui::label(u("点「重新扫描」枚举自启动项"), "secondary");
    b.toolbar->addWidget(count);

    auto* t = b.table;
    t->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    auto* scanning = new bool(false);
    QObject::connect(ipc, &IpcClient::persistenceReceived, b.page,
                     [t, count, scanning](const bulwark::ipc::PersistenceListResponsePayload& p) {
        *scanning = false;
        t->setRowCount(0);
        for (const bulwark::PersistenceEntry& e : p.entries) {
            const int i = addRow(t);
            put(t, i, 0, e.name);
            put(t, i, 1, persistenceCategoryLabel(e.category), true);
            put(t, i, 2, e.command.isEmpty() ? e.imagePath : e.command, true, true);
            put(t, i, 3, e.techniques.join(QStringLiteral(", ")), true, true);
            ui::pillCell(t, i, 4, riskLabel(e.riskScore) + QStringLiteral(" %1").arg(e.riskScore),
                         riskColor(e.riskScore));
            const QString sig = e.isSigned.has_value()
                ? (*e.isSigned ? u("已签名") : u("无签名"))
                : u("—");
            put(t, i, 5, sig, true);
        }
        count->setText(p.message.isEmpty() ? u("共 %1 项").arg(p.entries.size()) : p.message);
    });

    auto doScan = [ipc, count, scanning] {
        if (!ipc->isConnected()) { count->setText(u("未连接服务")); return; }
        *scanning = true;
        count->setText(u("扫描中…"));
        ipc->requestPersistence();
    };
    QObject::connect(scan, &QPushButton::clicked, b.page, doScan);
    QObject::connect(b.page, &QObject::destroyed, [scanning] { delete scanning; });
    return b.page;
}
