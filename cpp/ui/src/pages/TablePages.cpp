#include "pages/TablePages.h"
#include "dialogs/AttackChainDetailDialog.h"
#include "dialogs/AttackGraphWindow.h"
#include "dialogs/AttackTimelineWindow.h"
#include "dialogs/ProcessDetailDialog.h"
#include "ipc/IpcClient.h"
#include "widgets/TableKit.h"
#include "widgets/Ui.h"
#include "Theme.h"

#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/PersistenceEntry.h"
#include "bulwark/models/ProcessEntry.h"
#include "bulwark/models/SecurityEvent.h"

#include <QCheckBox>
#include <QJsonDocument>
#include <QLocale>

#include <QAction>
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QTimer>
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
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <optional>

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

// Read back the SecurityEvent stashed on a row by stashEvent(). Shared by the
// double-click timeline and the right-click menu.
std::optional<bulwark::SecurityEvent> stashedEvent(QTableWidget* t, int row)
{
    auto* c0 = t->item(row, 0);
    if (!c0) return std::nullopt;
    const QString js = c0->data(Qt::UserRole).toString();
    if (js.isEmpty()) return std::nullopt;
    return bulwark::SecurityEvent::fromJson(QJsonDocument::fromJson(js.toUtf8()).object());
}

// Double-click a row -> open the attack-timeline window for its stashed event.
// ipc 透传给时间线窗口,让它能进一步打开攻击关系图(需要向服务请求关联)。
void wireAttackTimeline(QTableWidget* t, QWidget* page, IpcClient* ipc)
{
    QObject::connect(t, &QTableWidget::cellDoubleClicked, page, [t, ipc](int row, int) {
        if (const std::optional<bulwark::SecurityEvent> e = stashedEvent(t, row)) {
            AttackTimelineWindow dlg(*e, t->window(), ipc);
            dlg.exec();
        }
    });
}

// 右键一行 -> 把该行的主体程序加入信任名单(事件日志类表格通用:拦截记录 / 活动日志)。
//
// 信任在 `RuleEngine::evaluateInternal` 里是第 1 步的【无条件放行通道】,并且会置
// `e.userTrusted` 让 Worker 跳过全部后台扫描(VT / 微步 IP 情报 / AI 研判)。所以这不是
// 「少弹一次窗」,而是「对该程序彻底停止检测」——必须让用户在确认时看清代价。因此:
//   · 表格只显示文件名,确认框里给出【完整路径】:不然 svchost.exe 这类同名程序极易误信任;
//   · 明确说明本次拦截已经发生、信任只对之后的行为生效,避免用户以为能把已结束的进程救回来。
// 服务收到 AddTrust 后会回推最新信任列表,「信任名单」页自动刷新;当前行属于历史记录,保留不动。
void wireTrustContextMenu(QTableWidget* t, QWidget* page, IpcClient* ipc, const QString& source)
{
    t->setContextMenuPolicy(Qt::CustomContextMenu);
    QObject::connect(t, &QTableWidget::customContextMenuRequested, page,
                     [t, page, ipc, source](const QPoint& pos) {
        const int row = t->indexAt(pos).row();
        if (row < 0) return; // 右击空白处:不弹菜单
        const std::optional<bulwark::SecurityEvent> ev = stashedEvent(t, row);
        if (!ev) return;
        t->selectRow(row); // 高亮命中行,让用户确认操作对象

        const QPoint global = t->viewport()->mapToGlobal(pos);
        const QString actorPath = QDir::toNativeSeparators(ev->actorPath);

        QMenu menu(t);
        // 内核遥测等少数事件可能拿不到主体路径,此时给出禁用项说明原因,而不是弹一个空菜单。
        if (actorPath.isEmpty()) {
            menu.addAction(u("该事件无程序路径,无法信任"))->setEnabled(false);
            menu.exec(global);
            return;
        }

        // 「查看攻击关系图」放在第一项:排查时最先想做的是把这条孤立记录还原成一次入侵的形状,
        // 而不是先决定要不要信任。
        QAction* graphAct = menu.addAction(u("查看攻击关系图"));
        menu.addSeparator();
        QAction* trustAct = menu.addAction(u("信任此程序:") + QFileInfo(actorPath).fileName());
        QAction* chosen = menu.exec(global);
        if (chosen == graphAct) {
            if (!ipc->isConnected()) {
                QMessageBox::warning(page, u("攻击关系图"), u("未连接服务,无法构建攻击图。"));
                return;
            }
            AttackGraphWindow dlg(ipc, ev->id, ev->actorPid,
                                  QFileInfo(actorPath).fileName(), t->window());
            dlg.exec();
            return;
        }
        if (chosen != trustAct) return;

        if (!ipc->isConnected()) {
            QMessageBox::warning(page, u("信任此程序"), u("未连接服务,无法添加信任项。"));
            return;
        }
        const auto ret = QMessageBox::question(
            page, u("信任此程序"),
            u("信任后,该程序的【所有行为】都将直接放行,并跳过全部检测与后台云查毒 / AI 研判。\n"
              "请仅信任你确认安全的程序。\n\n"
              "程序:%1\n\n"
              "注:本次拦截已经发生,信任只对之后的行为生效。\n\n"
              "确定信任吗?").arg(actorPath),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (ret == QMessageBox::Yes)
            ipc->addTrust(actorPath, source);
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

// 数值列排序用的表项:显示仍是格式化文本(如 "12.3 MB"),排序按真实数值。
// 不这么做的话点一下「内存」表头就得到 "9 MB > 120 MB" 这种按字符串排的荒唐结果。
class NumericItem : public QTableWidgetItem
{
public:
    NumericItem(const QString& text, qint64 v) : QTableWidgetItem(text), value(v) {}
    bool operator<(const QTableWidgetItem& other) const override
    {
        if (const auto* o = dynamic_cast<const NumericItem*>(&other))
            return value < o->value;
        return QTableWidgetItem::operator<(other);
    }
    qint64 value = 0;
};

void putNum(QTableWidget* t, int r, int c, const QString& text, qint64 value,
            bool secondary = false, bool mono = false)
{
    auto* it = new NumericItem(text, value);
    if (secondary) it->setForeground(theme::textSecondary());
    if (mono)      it->setFont(QFont(QStringLiteral("Cascadia Mono")));
    t->setItem(r, c, it);
}

QString humanBytes(qint64 bytes)
{
    if (bytes <= 0)
        return u("—");
    return QLocale().formattedDataSize(bytes, 1, QLocale::DataSizeTraditionalFormat);
}

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
    wireAttackTimeline(t, b.page, ipc); // 双击回溯攻击时间线(内含攻击关系图入口)
    wireTrustContextMenu(t, b.page, ipc, u("从拦截记录信任")); // 右键:攻击关系图 / 加入信任名单

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
    // 启动不卡:事件历史回填(最多 500 条 + 同步重建表格)延后到窗口首帧绘制/可交互之后再拉,
    // 避免一连接就在 GUI 线程同步重建大表造成「打开软件卡一会儿」。ipc 作上下文,断开自动取消。
    QObject::connect(ipc, &IpcClient::connectionChanged, b.page,
                     [ipc](bool c) { if (c) QTimer::singleShot(500, ipc, [ipc] { ipc->requestEventHistory(); }); });
    if (ipc->isConnected()) QTimer::singleShot(500, ipc, [ipc] { ipc->requestEventHistory(); });
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
    wireAttackTimeline(t, b.page, ipc); // 双击回溯攻击时间线(内含攻击关系图入口)
    wireTrustContextMenu(t, b.page, ipc, u("从活动日志信任")); // 右键:攻击关系图 / 加入信任名单

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
    // 启动不卡:事件历史回填(最多 500 条 + 同步重建表格)延后到窗口首帧绘制/可交互之后再拉,
    // 避免一连接就在 GUI 线程同步重建大表造成「打开软件卡一会儿」。ipc 作上下文,断开自动取消。
    QObject::connect(ipc, &IpcClient::connectionChanged, b.page,
                     [ipc](bool c) { if (c) QTimer::singleShot(500, ipc, [ipc] { ipc->requestEventHistory(); }); });
    if (ipc->isConnected()) QTimer::singleShot(500, ipc, [ipc] { ipc->requestEventHistory(); });
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

    // 启动不卡:规则列表可能较大(海量情报规则),回填延后到窗口可交互之后,避免启动即在 GUI
    // 线程反序列化 + 重建大表;略晚于事件历史,错开启动峰值。刷新按钮仍即时可用。
    QObject::connect(ipc, &IpcClient::connectionChanged, b.page,
                     [ipc](bool c) { if (c) QTimer::singleShot(800, ipc, [ipc] { ipc->requestRules(); }); });
    if (ipc->isConnected()) QTimer::singleShot(800, ipc, [ipc] { ipc->requestRules(); });
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
    // 清理按钮:此前本页是纯只读的 —— 服务端 ThreatRemediator 把 8 类持久化点的清理动作全实现了、
    // IPC 也留了消息号,但没有任何入口,那些代码一行都到不了。这里补上唯一的用户入口。
    auto* clean = ui::toolButton("shield-x", u("清理选中项"), "ghost", theme::danger());
    clean->setEnabled(false);   // 选中一行才可用
    b.toolbar->addWidget(scan);
    b.toolbar->addWidget(clean);
    b.toolbar->addStretch();
    auto* count = ui::label(u("点「重新扫描」枚举自启动项"), "secondary");
    b.toolbar->addWidget(count);

    auto* t = b.table;
    t->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    auto* scanning = new bool(false);
    // 保留本次扫描的完整条目:清理请求要把整条 PersistenceEntry 回传(服务端按 category 分派、
    // 用 location/name/imagePath 定位目标,且扫描是无状态的按需枚举,服务端不留上次结果)。
    auto* rows = new QList<bulwark::PersistenceEntry>();

    QObject::connect(ipc, &IpcClient::persistenceReceived, b.page,
                     [t, count, scanning, rows](const bulwark::ipc::PersistenceListResponsePayload& p) {
        *scanning = false;
        *rows = p.entries;
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

    // 选中行才允许清理(避免空点或误点到表头)。
    QObject::connect(t, &QTableWidget::itemSelectionChanged, b.page, [t, clean] {
        clean->setEnabled(t->currentRow() >= 0);
    });

    QObject::connect(clean, &QPushButton::clicked, b.page, [ipc, t, rows, count] {
        const int row = t->currentRow();
        if (row < 0 || row >= rows->size())
            return;
        if (!ipc->isConnected()) {
            QMessageBox::warning(t, u("清理自启动项"), u("未连接服务,无法执行清理。"));
            return;
        }
        const bulwark::PersistenceEntry e = rows->at(row);
        // 清理是不可逆动作(改注册表 / 删计划任务 / 停服务),必须显式二次确认并说清后果。
        // 文件类载荷会进隔离区(可还原),注册表/任务/服务的移除【不可撤销】—— 这点必须写明。
        const QString detail =
            u("将清理以下自启动项:\n\n名称:%1\n类别:%2\n位置:%3\n命令:%4\n\n")
                .arg(e.name, persistenceCategoryLabel(e.category), e.location,
                     e.command.isEmpty() ? e.imagePath : e.command)
            + u("• 指向的可执行文件会被移入隔离区(可还原)\n")
            + u("• 注册表项 / 计划任务 / 服务的移除【不可撤销】\n")
            + u("• 清理后该项会被加入内核注册表硬拦,阻止被立刻重建\n\n")
            + u("如果这是你自己安装的正常软件,请改用「信任名单」而不是清理。确定继续吗?");
        if (QMessageBox::warning(t, u("清理自启动项(高危)"), detail,
                                 QMessageBox::Yes | QMessageBox::Cancel,
                                 QMessageBox::Cancel) != QMessageBox::Yes)
            return;
        count->setText(u("清理中…"));
        ipc->requestPersistenceCleanup(e);
    });

    QObject::connect(ipc, &IpcClient::persistenceCleanupDone, b.page,
                     [t, count, doScan](const bulwark::ipc::PersistenceCleanupResultPayload& r) {
        count->setText(r.message);
        if (r.success) {
            QString extra;
            if (!r.quarantinedFiles.isEmpty())
                extra += u("\n\n已隔离(可在「隔离区」还原):\n") + r.quarantinedFiles.join(QLatin1Char('\n'));
            if (!r.removedRegistryValues.isEmpty())
                extra += u("\n\n已移除持久化:\n") + r.removedRegistryValues.join(QLatin1Char('\n'));
            QMessageBox::information(t, u("清理自启动项"), r.message + extra);
            doScan();   // 清完立刻重扫,让列表反映真实现状(而不是留一条已消失的行)
        } else {
            // 服务端的护栏拒绝(已加白 / 本产品自身 / 目标已不存在)也走这里,如实展示原因。
            QMessageBox::warning(t, u("清理自启动项"), r.message);
        }
    });

    QObject::connect(b.page, &QObject::destroyed, [scanning, rows] { delete scanning; delete rows; });
    return b.page;
}

// ═══════════════════════════════════════════════════════════════════════════
// 事件时间线 —— 按条件回溯历史事件,并从任一条展开攻击关系图。
//
// 与「活动日志」的分工:活动日志是实时流水(最近 N 条,一直往上追加),回答「刚刚发生了什么」;
// 时间线是查询视图,回答「昨天下午三点前后那台机器上发生了什么」。查询走服务端落盘的
// events.jsonl(比内存缓冲深得多),所以能回看远超 500 条的历史。
// ═══════════════════════════════════════════════════════════════════════════
namespace {

struct RangeOption { const char* label; int seconds; };
const RangeOption kRanges[] = {
    { "最近 15 分钟", 15 * 60 },
    { "最近 1 小时",  60 * 60 },
    { "最近 6 小时",  6 * 3600 },
    { "最近 24 小时", 24 * 3600 },
    { "最近 7 天",    7 * 24 * 3600 },
    { "全部历史",     0 },
};

} // namespace

QWidget* pages::timeline(IpcClient* ipc)
{
    auto b = buildPage({u("时间"), u("事件"), u("程序"), u("PID"), u("启动来源"), u("目标"),
                        u("风险"), u("处置")});

    auto* range = new QComboBox;
    for (const RangeOption& r : kRanges)
        range->addItem(u(r.label), r.seconds);
    range->setCurrentIndex(3); // 默认最近 24 小时:够覆盖「昨晚出了点事」的常见诉求
    range->setFixedWidth(126);

    auto* typeBox = new QComboBox;
    typeBox->addItem(u("所有行为"), -1);
    for (int i = 0; i <= static_cast<int>(bulwark::EventType::DnsQuery); ++i)
        typeBox->addItem(eventTypeLabel(static_cast<bulwark::EventType>(i)), i);
    typeBox->setFixedWidth(126);

    auto* verdictBox = new QComboBox;
    verdictBox->addItem(u("所有裁决"), -1);
    verdictBox->addItem(u("仅拦截"), static_cast<int>(bulwark::VerdictAction::Block));
    verdictBox->addItem(u("仅询问"), static_cast<int>(bulwark::VerdictAction::Ask));
    verdictBox->addItem(u("仅放行"), static_cast<int>(bulwark::VerdictAction::Allow));
    verdictBox->setFixedWidth(110);

    auto* riskBox = new QComboBox;
    riskBox->addItem(u("全部风险"), 0);
    riskBox->addItem(u("可疑及以上"), 50);
    riskBox->addItem(u("仅高危"), 80);
    riskBox->setFixedWidth(110);

    auto* pidEdit = new QLineEdit;
    pidEdit->setPlaceholderText(u("PID(可空)"));
    pidEdit->setFixedWidth(96);
    auto* treeBox = new QCheckBox(u("含子进程"));
    treeBox->setChecked(true);
    treeBox->setToolTip(u("按 PID 过滤时,把该进程派生出来的整棵进程树的事件一并纳入。"));

    auto* search = ui::searchBox(u("路径 / 目标 / 命令行 / 服务名…"), 240);
    auto* queryBtn = ui::toolButton("search", u("查询"), "primary", theme::accentInk());

    b.toolbar->addWidget(range);
    b.toolbar->addWidget(typeBox);
    b.toolbar->addWidget(verdictBox);
    b.toolbar->addWidget(riskBox);
    b.toolbar->addWidget(pidEdit);
    b.toolbar->addWidget(treeBox);
    b.toolbar->addWidget(search);
    b.toolbar->addWidget(queryBtn);
    b.toolbar->addStretch();
    auto* count = ui::label(u("点「查询」检索事件历史"), "secondary");
    b.toolbar->addWidget(count);

    auto* t = b.table;
    t->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    t->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    wireAttackTimeline(t, b.page, ipc);                         // 双击看单条事件的证据链
    wireTrustContextMenu(t, b.page, ipc, u("从时间线信任"));      // 右键:攻击关系图 / 信任

    auto runQuery = [ipc, range, typeBox, verdictBox, riskBox, pidEdit, treeBox, search, count] {
        if (!ipc->isConnected()) { count->setText(u("未连接服务")); return; }
        bulwark::ipc::TimelineRequestPayload req;
        const int secs = range->currentData().toInt();
        if (secs > 0)
            req.fromUtc = QDateTime::currentDateTimeUtc().addSecs(-secs);
        const int type = typeBox->currentData().toInt();
        if (type >= 0) req.types = { type };
        const int verdict = verdictBox->currentData().toInt();
        if (verdict >= 0) req.actions = { verdict };
        req.minRiskScore = riskBox->currentData().toInt();
        req.pid = pidEdit->text().trimmed().toInt();
        req.includeProcessTree = treeBox->isChecked();
        req.text = search->text().trimmed();
        req.limit = 1000;
        count->setText(u("查询中…"));
        ipc->requestTimeline(req);
    };

    QObject::connect(queryBtn, &QPushButton::clicked, b.page, runQuery);
    QObject::connect(search, &QLineEdit::returnPressed, b.page, runQuery);
    QObject::connect(range, &QComboBox::currentIndexChanged, b.page, [runQuery](int) { runQuery(); });
    QObject::connect(typeBox, &QComboBox::currentIndexChanged, b.page, [runQuery](int) { runQuery(); });
    QObject::connect(verdictBox, &QComboBox::currentIndexChanged, b.page, [runQuery](int) { runQuery(); });
    QObject::connect(riskBox, &QComboBox::currentIndexChanged, b.page, [runQuery](int) { runQuery(); });

    QObject::connect(ipc, &IpcClient::timelineReceived, b.page,
                     [t, count](const bulwark::ipc::TimelineResponsePayload& p) {
        t->setRowCount(0);
        // 服务端按时间升序给,倒序插入 -> 最新在最上面。
        for (const bulwark::ipc::EventLogPayload& lp : p.events) {
            const bulwark::SecurityEvent& e = lp.event;
            t->insertRow(0);
            put(t, 0, 0, e.timestampUtc.toLocalTime().toString(QStringLiteral("MM-dd HH:mm:ss")),
                true, true);
            put(t, 0, 1, eventTypeLabel(e.type));
            put(t, 0, 2, QFileInfo(e.actorPath).fileName());
            putNum(t, 0, 3, QString::number(e.actorPid), e.actorPid, true, true);
            // 这一列是整个溯源改造的落点:svchost.exe 那一行会显示成「服务:Schedule」,
            // 计划任务拉起的进程会显示成「计划任务:\Microsoft\Windows\...」。
            put(t, 0, 4, e.originLabel(), true);
            put(t, 0, 5, e.target, true, true);
            putNum(t, 0, 6, QString::number(e.riskScore), e.riskScore, true);
            QString dt; QColor dc;
            dispositionPill(lp.action, lp.enforcement, dt, dc);
            ui::pillCell(t, 0, 7, dt, dc);
            stashEvent(t, 0, e);
        }
        // 刻意不开表头排序:时间线的语义就是「按时间倒序读」,一旦被按别的列重排,
        // 「这一步之后紧接着发生了什么」这条最有用的信息就没了。
        QStringList parts;
        parts << (p.events.isEmpty() ? u("没有符合条件的事件")
                                     : u("命中 %1 条").arg(p.events.size()));
        if (p.truncated) parts << u("已按上限截断");
        if (p.earliestUtc.isValid())
            parts << u("可回溯至 %1").arg(
                p.earliestUtc.toLocalTime().toString(QStringLiteral("MM-dd HH:mm")));
        count->setText(parts.join(u("  ·  ")));
    });

    // 首次进入自动查一次最近 24 小时,页面不至于是空的。延后一点,避开启动峰值。
    // 定时器一律以页面为上下文:页面销毁即取消,免得回调打在已析构的控件上。
    QObject::connect(ipc, &IpcClient::connectionChanged, b.page,
                     [runQuery, page = b.page](bool c) {
                         if (c) QTimer::singleShot(1200, page, [runQuery] { runQuery(); });
                     });
    if (ipc->isConnected()) QTimer::singleShot(1200, b.page, [runQuery] { runQuery(); });
    return b.page;
}

// ═══════════════════════════════════════════════════════════════════════════
// 进程管理 —— 在跑进程快照 + 用户主动处置。
//
// 定位:这不是任务管理器的复刻,而是「带取证与溯源的进程视图」。三件事是别处看不到的:
//   ① 启动来源列:svchost.exe 显示成具体服务名,任务宿主派生的进程显示成具体计划任务名;
//   ② 签名与提示分:未签名 / 签名失配 / 跑在用户可写目录 / 伪装系统进程名,一眼可见;
//   ③ 处置就在手边:结束 / 结束进程树 / 挂起 / 隔离映像 / 加信任。
//
// 三条红线:所有处置都要用户显式点击(页面本身不做任何自动动作)、关键系统进程与本软件
// 自身组件由服务端拒绝(这里也置灰),提示分只做着色排序、绝不当成判定结论。
// ═══════════════════════════════════════════════════════════════════════════
QWidget* pages::processes(IpcClient* ipc)
{
    auto b = buildPage({u("PID"), u("进程"), u("启动来源"), u("用户"), u("签名"), u("内存"),
                        u("提示"), u("路径")});

    auto* search = ui::searchBox(u("进程名 / 路径 / 服务 / 任务…"), 250);
    auto* refresh = ui::toolButton("refresh", u("刷新"), "ghost", theme::textSecondary());
    auto* autoBox = new QCheckBox(u("每 5 秒自动刷新"));
    auto* killBtn = ui::toolButton("close", u("结束进程"), "ghost", theme::danger());
    auto* detailBtn = ui::toolButton("eye", u("详情"), "ghost", theme::textSecondary());
    b.toolbar->addWidget(search);
    b.toolbar->addWidget(refresh);
    b.toolbar->addWidget(autoBox);
    b.toolbar->addStretch();
    auto* count = ui::label(u("加载进程列表…"), "secondary");
    b.toolbar->addWidget(count);
    b.toolbar->addWidget(detailBtn);
    b.toolbar->addWidget(killBtn);

    auto* t = b.table;
    t->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    t->horizontalHeader()->setSectionResizeMode(7, QHeaderView::Stretch);
    // 默认按「提示」列降序:打开页面第一眼就落在最值得看的进程上(未签名 / 签名失配 /
    // 跑在用户可写目录 / 伪装系统进程名)。表头可点,按 PID / 内存 / 名称重排都是数值排序。
    t->horizontalHeader()->setSortIndicator(6, Qt::DescendingOrder);
    t->setSortingEnabled(true);

    // 当前快照:表格行 -> ProcessEntry。处置和详情都从这里取,而不是回读表格文本。
    auto entries = std::make_shared<QList<bulwark::ProcessEntry>>();

    auto rowEntry = [t, entries](int row) -> std::optional<bulwark::ProcessEntry> {
        if (row < 0 || row >= t->rowCount()) return std::nullopt;
        auto* c0 = t->item(row, 0);
        if (!c0) return std::nullopt;
        const int idx = c0->data(Qt::UserRole).toInt();
        if (idx < 0 || idx >= entries->size()) return std::nullopt;
        return entries->at(idx);
    };
    auto selectedEntry = [t, rowEntry]() -> std::optional<bulwark::ProcessEntry> {
        return rowEntry(t->currentRow());
    };

    auto applyFilter = [t, search, count, entries] {
        const QString q = search->text().trimmed();
        int shown = 0;
        for (int r = 0; r < t->rowCount(); ++r) {
            bool match = q.isEmpty();
            if (!match) {
                for (int c = 0; c < t->columnCount() && !match; ++c)
                    if (auto* it = t->item(r, c))
                        match = it->text().contains(q, Qt::CaseInsensitive);
            }
            t->setRowHidden(r, !match);
            if (match) ++shown;
        }
        count->setText(q.isEmpty() ? u("共 %1 个进程").arg(entries->size())
                                   : u("匹配 %1 / %2 个进程").arg(shown).arg(entries->size()));
    };
    QObject::connect(search, &QLineEdit::textChanged, b.page, [applyFilter](const QString&) { applyFilter(); });

    QObject::connect(ipc, &IpcClient::processListReceived, b.page,
                     [t, entries, applyFilter](const bulwark::ipc::ProcessListResponsePayload& p) {
        // 刷新时尽量保住用户当前选中的那个进程,不然自动刷新会把选择弹掉。
        int keepPid = 0;
        if (auto* c0 = t->item(t->currentRow(), 0))
            keepPid = c0->text().toInt();

        *entries = p.processes;
        t->setSortingEnabled(false);
        t->setRowCount(0);
        int restoreRow = -1;
        for (int i = 0; i < entries->size(); ++i) {
            const bulwark::ProcessEntry& e = entries->at(i);
            const int r = addRow(t);
            putNum(t, r, 0, QString::number(e.pid), e.pid, false, true);
            if (auto* c0 = t->item(r, 0))
                c0->setData(Qt::UserRole, i); // 行 -> 快照下标
            put(t, r, 1, e.fileDescription.isEmpty()
                             ? e.name
                             : QStringLiteral("%1  (%2)").arg(e.name, e.fileDescription));
            put(t, r, 2, e.originLabel(), true);
            put(t, r, 3, e.userName, true);
            if (e.isSigned)
                ui::pillCell(t, r, 4, e.publisher.isEmpty() ? u("已签名") : u("已签名"),
                             theme::success());
            else if (e.signatureMismatch)
                ui::pillCell(t, r, 4, u("签名失配"), theme::danger());
            else
                ui::pillCell(t, r, 4, u("无签名"), theme::textMuted());
            putNum(t, r, 5, humanBytes(e.workingSetBytes), e.workingSetBytes, true);

            // 「提示」列刻意不叫「风险」:它是静态特征汇总,不是判定结论。
            // 用可排序的文本项而不是胶囊,才能作为默认排序键把可疑的顶到最上面。
            QString tip;
            QColor tipColor = theme::textMuted();
            qint64 tipRank = e.riskScore;
            if (e.isProtectedSelf)      { tip = u("本软件组件"); tipColor = theme::info();    tipRank = -3; }
            else if (e.isTrusted)       { tip = u("已信任");     tipColor = theme::success(); tipRank = -2; }
            else if (e.isCritical)      { tip = u("关键进程");   tipColor = theme::info();    tipRank = -1; }
            else if (e.riskScore >= 50) { tip = u("留意 %1").arg(e.riskScore); tipColor = riskColor(e.riskScore); }
            else if (e.riskScore > 0)   { tip = u("提示 %1").arg(e.riskScore); tipColor = theme::warning(); }
            else                        { tip = u("正常");       tipColor = theme::success(); }
            putNum(t, r, 6, tip, tipRank);
            if (auto* tipItem = t->item(r, 6))
                tipItem->setForeground(tipColor);
            put(t, r, 7, QDir::toNativeSeparators(e.imagePath), true, true);
            if (keepPid > 0 && e.pid == keepPid)
                restoreRow = r;
        }
        t->setSortingEnabled(true);
        if (restoreRow >= 0)
            t->selectRow(restoreRow);
        applyFilter();
    });

    // ---- 处置:统一走一个带确认的执行器,措辞把「会发生什么、能不能撤」讲清楚 ----
    auto runAction = [ipc, page = b.page](const bulwark::ProcessEntry& e,
                                          bulwark::ipc::ProcessActionKind kind) {
        using Kind = bulwark::ipc::ProcessActionKind;
        if (!ipc->isConnected()) {
            QMessageBox::warning(page, u("进程管理"), u("未连接服务,无法执行操作。"));
            return;
        }
        const QString who = QStringLiteral("%1 (PID %2)\n%3")
                                .arg(e.name).arg(e.pid)
                                .arg(QDir::toNativeSeparators(e.imagePath));
        QString title, body;
        switch (kind) {
        case Kind::Terminate:
            title = u("结束进程");
            body = u("将强制结束该进程,未保存的数据会丢失。\n\n%1\n\n确定继续吗?").arg(who);
            break;
        case Kind::TerminateTree:
            title = u("结束进程树");
            body = u("将强制结束该进程【及其全部子孙进程】,未保存的数据会丢失。\n\n%1\n\n确定继续吗?")
                       .arg(who);
            break;
        case Kind::Suspend:
            title = u("挂起进程");
            body = u("将冻结该进程的所有线程,进程会停止响应直到你恢复它。\n\n%1\n\n确定继续吗?").arg(who);
            break;
        case Kind::Resume:
            title = u("恢复进程");
            body = u("将恢复该进程的所有线程。\n\n%1\n\n确定继续吗?").arg(who);
            break;
        case Kind::QuarantineImage:
            title = u("隔离映像");
            body = u("将先结束该进程及其子孙进程,再把它的可执行文件移入隔离区。\n"
                     "隔离是可逆的 —— 判断有误可在「隔离区」页还原。\n\n%1\n\n确定继续吗?").arg(who);
            break;
        case Kind::TrustImage:
            title = u("信任此程序");
            body = u("信任后,该程序的【所有行为】都将直接放行,并跳过全部检测与后台云查毒 / AI 研判。\n"
                     "请仅信任你确认安全的程序。\n\n%1\n\n确定信任吗?").arg(who);
            break;
        default:
            return;
        }
        if (QMessageBox::question(page, title, body, QMessageBox::Yes | QMessageBox::No,
                                  QMessageBox::No)
            != QMessageBox::Yes)
            return;
        bulwark::ipc::ProcessActionRequestPayload p;
        p.kind = kind;
        p.pid = e.pid;
        p.imagePath = e.imagePath;
        ipc->processAction(p);
    };

    // 处置结果一律弹出回执:成功要说明做了什么,失败必须说明为什么没做成
    //(关键进程 / 自我保护 / 权限不足 / 进程已退出),绝不让用户以为「点了就生效了」。
    QObject::connect(ipc, &IpcClient::processActionResult, b.page,
                     [ipc, page = b.page](const bulwark::ipc::ProcessActionResultPayload& r) {
        if (r.kind == bulwark::ipc::ProcessActionKind::ComputeHash)
            return; // 详情窗口自己处理
        if (r.success)
            QMessageBox::information(page, u("进程管理"), r.message);
        else
            QMessageBox::warning(page, u("进程管理"),
                                 r.message.isEmpty() ? u("操作未成功") : r.message);
        if (ipc->isConnected())
            ipc->requestProcesses();
    });

    // 右键菜单:全部处置动作 + 详情。按进程状态置灰不该做的项,并把原因写在菜单项上。
    t->setContextMenuPolicy(Qt::CustomContextMenu);
    QObject::connect(t, &QTableWidget::customContextMenuRequested, b.page,
                     [t, ipc, rowEntry, runAction](const QPoint& pos) {
        using Kind = bulwark::ipc::ProcessActionKind;
        const int row = t->indexAt(pos).row();
        if (row < 0) return;
        t->selectRow(row);
        const auto opt = rowEntry(row);
        if (!opt) return;
        const bulwark::ProcessEntry e = *opt;

        QMenu menu(t);
        QAction* detail = menu.addAction(u("查看详情"));
        QAction* graph = menu.addAction(u("查看攻击关系图(该进程近期行为)"));
        menu.addSeparator();
        QAction* kill = menu.addAction(u("结束进程"));
        QAction* killTree = menu.addAction(u("结束进程树"));
        QAction* suspend = menu.addAction(u("挂起"));
        QAction* resume = menu.addAction(u("恢复"));
        menu.addSeparator();
        QAction* quarantine = menu.addAction(u("结束并隔离映像…"));
        QAction* trust = menu.addAction(u("加入信任名单"));

        const bool locked = e.isProtectedSelf || e.isCritical;
        const QString why = e.isProtectedSelf ? u("(本软件组件,受自我保护)")
                                              : u("(关键系统进程,结束会蓝屏)");
        for (QAction* a : { kill, killTree, suspend, quarantine }) {
            a->setEnabled(!locked);
            if (locked) a->setText(a->text() + QLatin1Char(' ') + why);
        }
        if (e.imagePath.isEmpty()) {
            quarantine->setEnabled(false);
            trust->setEnabled(false);
            trust->setText(trust->text() + u("(无映像路径)"));
        }

        QAction* chosen = menu.exec(t->viewport()->mapToGlobal(pos));
        if (!chosen) return;
        if (chosen == detail) {
            ProcessDetailDialog dlg(e, ipc, t->window());
            dlg.exec();
        } else if (chosen == graph) {
            AttackGraphWindow dlg(ipc, QUuid(), e.pid, e.name, t->window());
            dlg.exec();
        } else if (chosen == kill)          runAction(e, Kind::Terminate);
        else if (chosen == killTree)        runAction(e, Kind::TerminateTree);
        else if (chosen == suspend)         runAction(e, Kind::Suspend);
        else if (chosen == resume)          runAction(e, Kind::Resume);
        else if (chosen == quarantine)      runAction(e, Kind::QuarantineImage);
        else if (chosen == trust)           runAction(e, Kind::TrustImage);
    });

    QObject::connect(t, &QTableWidget::cellDoubleClicked, b.page,
                     [t, ipc, rowEntry](int row, int) {
        if (const auto e = rowEntry(row)) {
            ProcessDetailDialog dlg(*e, ipc, t->window());
            dlg.exec();
        }
    });

    QObject::connect(detailBtn, &QPushButton::clicked, b.page, [t, ipc, selectedEntry, page = b.page] {
        const auto e = selectedEntry();
        if (!e) { QMessageBox::information(page, u("进程详情"), u("请先选中一个进程。")); return; }
        ProcessDetailDialog dlg(*e, ipc, t->window());
        dlg.exec();
    });
    QObject::connect(killBtn, &QPushButton::clicked, b.page, [selectedEntry, runAction, page = b.page] {
        const auto e = selectedEntry();
        if (!e) { QMessageBox::information(page, u("结束进程"), u("请先选中一个进程。")); return; }
        runAction(*e, bulwark::ipc::ProcessActionKind::Terminate);
    });

    auto reload = [ipc, count] {
        if (!ipc->isConnected()) { count->setText(u("未连接服务")); return; }
        ipc->requestProcesses();
    };
    QObject::connect(refresh, &QPushButton::clicked, b.page, reload);

    // 自动刷新默认关:一次快照要枚举几百个进程并验签,没必要一直跑。需要盯着看时再打开。
    auto* timer = new QTimer(b.page);
    timer->setInterval(5000);
    QObject::connect(timer, &QTimer::timeout, b.page, reload);
    QObject::connect(autoBox, &QCheckBox::toggled, b.page, [timer](bool on) {
        if (on) timer->start();
        else    timer->stop();
    });

    QObject::connect(ipc, &IpcClient::connectionChanged, b.page,
                     [reload, page = b.page](bool c) {
                         if (c) QTimer::singleShot(1500, page, [reload] { reload(); });
                     });
    if (ipc->isConnected()) QTimer::singleShot(1500, b.page, [reload] { reload(); });
    return b.page;
}

// ═══════════════════════════════════════════════════════════════════════════
// 攻击链 —— 组合表状态 + 命中记录。
//
// 这页回答两个问题:
//   1) 「我这台机器上装的是哪一版组合表、还灵不灵」——版本 / 组合条数 / 标记数 / 更新计划;
//   2) 「它到底逮到过什么」——每次凑齐组合的记录:谁、凑齐了哪几个动作、多少样本作证、最终怎么处置的。
//
// 为什么不并进「拦截记录」页:一次攻击链命中横跨【多条】事件(凑齐组合的那几个动作分散在不同
// 事件里),挂到任何单条事件上都看不到全貌,所以服务端单独存了一份记录,这页单独读它。
//
// dry-run 的显示要诚实:默认「只记录不拦截」,此时命中【不影响裁决】。若不明说,用户会误以为
// 这些记录都已被拦下 —— 故顶部横幅与每行的「最终裁决」都如实标注真实处置。
// ═══════════════════════════════════════════════════════════════════════════
namespace {

// 组合强度配色:hard 是「仅此一条就足以定性」,ask 只是「值得问一句」。
QColor chainGradeColor(const QString& grade)
{
    if (grade == QLatin1String("hard"))   return theme::danger();
    if (grade == QLatin1String("strong")) return theme::warning();
    return theme::info();
}

QString chainGradeLabel(const QString& grade)
{
    if (grade == QLatin1String("hard"))   return u("确定恶意");
    if (grade == QLatin1String("strong")) return u("高度可疑");
    if (grade == QLatin1String("ask"))    return u("需询问");
    return grade.isEmpty() ? u("—") : grade;
}

QColor chainLevelColor(const QString& level)
{
    if (level == QLatin1String("critical")) return theme::danger();
    if (level == QLatin1String("high"))     return theme::warning();
    return theme::info();
}

} // namespace

QWidget* pages::attackChain(IpcClient* ipc)
{
    auto b = buildPage({u("时间"), u("主体"), u("PID"), u("凑齐的动作"),
                        u("强度"), u("严重度"), u("样本数"), u("家族"), u("最终裁决")});

    // ---- 工具栏:引擎状态 + 组合表汇总 ----
    //
    // 这里【刻意不放卡片】。全部列表页的结构都是「工具栏 -> 表格」,汇总数字一律是工具栏里的
    // 一行 muted 文字(隔离区「共 11 项 · 100.2 MB」、进程管理「共 N 个进程」),状态一律是
    // ui::pill(侧栏「● 已连接服务」、右上「● 防护开启」)。此前这页在表格上方加了一张带
    // 大号数字的状态卡 —— 那是整个界面里唯一的一张,自成一套写法,所以看着格格不入。
    // 现在改回既有词汇表:状态用 pill,数字用 muted 汇总,细节挂 tooltip。
    auto* statePill = ui::pill(u("● 读取中…"), theme::textMuted());
    b.toolbar->addWidget(statePill);
    auto* summary = ui::label(QString(), "muted");
    b.toolbar->addWidget(summary);
    b.toolbar->addStretch();
    auto* search = ui::searchBox(u("搜索主体 / 动作 / 家族"), 240);
    b.toolbar->addWidget(search);
    auto* count = ui::label(QString(), "secondary");
    b.toolbar->addWidget(count);
    auto* refresh = ui::toolButton("refresh", u("刷新"), "ghost", theme::textSecondary());
    auto* clear = ui::toolButton("trash", u("清空记录"), "ghost", theme::danger());
    b.toolbar->addWidget(refresh);
    b.toolbar->addWidget(clear);

    auto* t = b.table;
    // ui::table() 默认把所有列设为 Stretch。9 列平分后每列只有 ~104px,连时间戳
    // 「08-01 04:11:12」都会被截成「08-01 04:11:…」。故给内容宽度固定的列钉死宽度,
    // 把省下来的空间全留给三个真正长的文本列(主体 / 凑齐的动作 / 家族)。
    auto* hh = t->horizontalHeader();
    const auto fixWidth = [hh](int col, int px) {
        hh->setSectionResizeMode(col, QHeaderView::Fixed);
        hh->resizeSection(col, px);
    };
    fixWidth(0, 118);                                        // 时间(MM-dd HH:mm:ss)
    hh->setSectionResizeMode(1, QHeaderView::Stretch);       // 主体(长路径)
    fixWidth(2, 74);                                         // PID
    hh->setSectionResizeMode(3, QHeaderView::Stretch);       // 凑齐的动作(长规则名)
    // 强度要装得下最长的 4 字标签(确定恶意 / 高度可疑),留够余量,否则胶囊里的字会被挤扁。
    fixWidth(4, 108);                                        // 强度
    fixWidth(5, 84);                                         // 严重度
    fixWidth(6, 76);                                         // 样本数
    hh->setSectionResizeMode(7, QHeaderView::Stretch);       // 家族
    fixWidth(8, 92);                                         // 最终裁决

    // 保留整份记录用于本地过滤 —— 搜索不该每次都往服务端跑一趟。
    auto* rows = new QList<bulwark::ipc::AttackChainHitPayload>();

    auto repaint = [t, rows, count, search] {
        const QString q = search->text().trimmed();
        t->setRowCount(0);
        int shown = 0;
        for (int src = 0; src < rows->size(); ++src) {
            const bulwark::ipc::AttackChainHitPayload& h = rows->at(src);
            if (!q.isEmpty()) {
                const bool hit = h.actorPath.contains(q, Qt::CaseInsensitive)
                              || h.families.contains(q, Qt::CaseInsensitive)
                              || h.titles.join(QLatin1Char(' ')).contains(q, Qt::CaseInsensitive);
                if (!hit)
                    continue;
            }
            const int i = addRow(t);
            put(t, i, 0, h.whenUtc.toLocalTime().toString(QStringLiteral("MM-dd HH:mm:ss")), true);
            // 行 -> 记录下标。表格带过滤,显示行号不等于记录下标,双击要靠这个回查
            //(与进程管理页同一约定:下标暗存在第 0 列的 UserRole)。
            if (auto* c0 = t->item(i, 0))
                c0->setData(Qt::UserRole, src);
            put(t, i, 1, h.actorPath, false, true);
            put(t, i, 2, h.actorPid > 0 ? QString::number(h.actorPid) : u("—"), true, true);
            // 凑齐的动作是这页的重点:哪几个行为叠在一起才定性,一行摊开给人看。
            put(t, i, 3, h.titles.join(u(" + ")));
            // 9 列挤在一屏,主体路径与组合动作名(原 Sigma 规则名,很长)必然被截断。
            // 悬停提示供扫读时快速确认,要看全量字段(可选中复制)则双击开详情。
            if (auto* cell = t->item(i, 1))
                cell->setToolTip(h.actorPath);
            if (auto* cell = t->item(i, 3))
                cell->setToolTip(h.titles.join(QStringLiteral("\n+ ")));
            ui::pillCell(t, i, 4, chainGradeLabel(h.grade), chainGradeColor(h.grade));
            ui::pillCell(t, i, 5, h.maxLevel.isEmpty() ? u("—") : h.maxLevel,
                         chainLevelColor(h.maxLevel));
            put(t, i, 6, h.support > 0 ? QString::number(h.support) : u("—"), true, true);
            put(t, i, 7, h.families.isEmpty() ? u("—") : h.families, true);
            if (auto* cell = t->item(i, 7); cell && !h.families.isEmpty())
                cell->setToolTip(h.families);
            // 最终裁决:dry-run 下这里显示的是【本次事件的真实处置】,与命中强度无关。
            QString vt = h.action;
            QColor vc = theme::textMuted();
            if (h.action == QLatin1String("Block"))      { vt = u("已拦截"); vc = theme::danger(); }
            else if (h.action == QLatin1String("Ask"))   { vt = u("已询问"); vc = theme::warning(); }
            else if (h.action == QLatin1String("Allow")) { vt = u("已放行"); vc = theme::success(); }
            else if (vt.isEmpty())                       { vt = u("—"); }
            ui::pillCell(t, i, 8, vt, vc);
            ++shown;
        }
        count->setText(q.isEmpty() ? u("共 %1 条").arg(rows->size())
                                   : u("匹配 %1 / %2 条").arg(shown).arg(rows->size()));
    };

    QObject::connect(ipc, &IpcClient::attackChainReceived, b.page,
                     [=](const bulwark::ipc::AttackChainResponsePayload& p) {
        *rows = p.hits;

        // 引擎状态 -> pill。三种状态各自把话说明白,别让用户对着一张空表猜。
        // 「只记录不拦截」这条最要紧的前提由 pill 的橙色 + tooltip 承担:表里所有记录都
        // 没影响过裁决,不说清楚会被误读成「这些都已经拦下了」。
        QString stateText;
        QColor stateColor;
        QString tip;
        if (!p.enabled) {
            stateColor = theme::textMuted();
            stateText = u("引擎未启用");
            tip = u("在 appsettings.json 里把 AttackChainEngine.Enabled 设为 true 后生效。");
        } else if (p.version <= 0) {
            stateColor = theme::warning();
            stateText = u("等待组合表");
            tip = u("引擎已启用,但还没装载到组合表,正在等首次同步。");
        } else if (p.dryRun) {
            stateColor = theme::warning();
            stateText = u("只记录不拦截");
            tip = u("下表记录均未参与过拦截判定。要让攻击链真正生效,"
                    "把 appsettings.json 里的 AttackChainEngine.DryRun 改为 false。");
        } else {
            stateColor = theme::success();
            stateText = u("参与拦截判定");
            tip = u("组合凑齐即作为硬指标进入裁决流水线,按强度判为拦截或弹窗询问。");
        }
        ui::stylePill(statePill, u("● ") + stateText, stateColor);

        // 组合表汇总 -> 一行 muted 文字(与隔离区「共 11 项 · 100.2 MB」同一写法)。
        QStringList parts;
        if (p.version > 0) {
            // 展示服务器给的可读版本号(0.1 起、每次内容变化 +0.1);老服务端不下发时
            // 回退到内部整数版本号,别把版本位置留空。内部号挂 tooltip,排查时还用得上。
            const QString ver = p.versionLabel.isEmpty()
                                    ? QStringLiteral("v%1").arg(p.version)
                                    : p.versionLabel;
            parts << ver << u("%1 条组合").arg(p.patterns) << u("%1 标记").arg(p.markers);
        }
        parts << u("记账 %1 进程").arg(p.trackedProcesses);
        summary->setText(parts.join(u(" · ")));

        // 更新计划与来源是元数据,不占版面,挂 tooltip。
        QStringList meta{tip};
        if (p.version > 0 && !p.versionLabel.isEmpty())
            meta << u("内部版本号 v%1(客户端据此判断是否需要重新下载)").arg(p.version);
        if (!p.updateSchedule.isEmpty())
            meta << p.updateSchedule;
        if (!p.endpoint.isEmpty())
            meta << u("组合表来源 %1").arg(p.endpoint);
        const QString fullTip = meta.join(QStringLiteral("\n"));
        statePill->setToolTip(fullTip);
        summary->setToolTip(fullTip);
        repaint();
    });

    auto reload = [ipc, count] {
        if (!ipc->isConnected()) { count->setText(u("未连接服务")); return; }
        ipc->requestAttackChain();
    };
    QObject::connect(refresh, &QPushButton::clicked, b.page, reload);
    QObject::connect(search, &QLineEdit::textChanged, b.page, [repaint] { repaint(); });

    // 双击一行 -> 命中详情(与拦截记录双击开攻击时间线、进程管理双击开进程详情同一约定)。
    QObject::connect(t, &QTableWidget::cellDoubleClicked, b.page, [t, rows](int row, int) {
        if (auto* c0 = t->item(row, 0)) {
            const int src = c0->data(Qt::UserRole).toInt();
            if (src >= 0 && src < rows->size()) {
                AttackChainDetailDialog dlg(rows->at(src), t->window());
                dlg.exec();
            }
        }
    });

    QObject::connect(clear, &QPushButton::clicked, b.page, [ipc, t] {
        if (!ipc->isConnected()) {
            QMessageBox::warning(t, u("清空命中记录"), u("未连接服务,无法清空。"));
            return;
        }
        if (QMessageBox::question(t, u("清空命中记录"),
                                  u("将清空全部攻击链命中记录(含落盘文件),此操作不可撤销。\n\n"
                                    "这只影响这页的历史展示,不会改变组合表或防护策略。确定继续吗?"),
                                  QMessageBox::Yes | QMessageBox::Cancel,
                                  QMessageBox::Cancel) != QMessageBox::Yes)
            return;
        ipc->clearAttackChainHits();   // 服务端清完会主动回推空列表,无需再请求
    });

    QObject::connect(ipc, &IpcClient::connectionChanged, b.page, [reload](bool c) {
        if (c) reload();
    });
    if (ipc->isConnected())
        reload();

    QObject::connect(b.page, &QObject::destroyed, [rows] { delete rows; });
    return b.page;
}
