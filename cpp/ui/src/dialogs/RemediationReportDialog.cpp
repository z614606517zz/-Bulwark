#include "dialogs/RemediationReportDialog.h"
#include "Nav.h"
#include "ai/AiScanner.h"
#include "dialogs/AiCleanupDialog.h"
#include "ipc/IpcClient.h"
#include "design/Banner.h"
#include "design/Components.h"
#include "design/CountTile.h"
#include "design/CountdownBar.h"
#include "design/FitScroll.h"
#include "design/Icons.h"
#include "design/Theme.h"
#include "widgets/WrapLabel.h"

#include <QClipboard>
#include <QFileInfo>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollBar>
#include <QVBoxLayout>

#include <utility>

using bulwark::ipc::RemediationReportPayload;
using bulwark::ipc::RemediationSkippedItem;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr int kCardW = 600;
constexpr int kAutoCloseMs = 30000;

// "• path" row; the path wraps anywhere so it is readable in full.
QWidget* pathRow(const QString& path, const QString& note = QString())
{
    auto* w = new QWidget;
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(18, 0, 0, 0);
    v->setSpacing(1);
    auto* p = new WrapLabel(path);
    p->setProperty("role", "mono");
    v->addWidget(p);
    if (!note.isEmpty()) {
        auto* n = ui::label(note, "muted");
        n->setWordWrap(true);
        v->addWidget(n);
    }
    return w;
}

} // namespace

RemediationReportDialog::RemediationReportDialog(const RemediationReportPayload& report,
                                                 IpcClient* ipc, AiScanner* ai, QWidget* parent)
    : Sheet(parent), m_report(report), m_ipc(ipc), m_ai(ai)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setModal(false); // informational — never blocks the user's work
    setSheetWidth(kCardW);

    // quarantinedFiles 已经包含主体本身(服务端的 actorQuarantined 正是据此判定的),不能再 +1:
    // 以前这里把主体数了两遍,「已隔离」比实际多 1,和右下角通知的数字也对不上。
    const int quarantined = int(report.quarantinedFiles.size());
    const int removed = int(report.removedRegistryValues.size());
    const int failed = int(report.skipped.size());
    const QString when = report.timestampUtc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    QString actorName = QFileInfo(report.actorPath).fileName();
    if (actorName.isEmpty())
        actorName = report.actorPath.isEmpty() ? u("未知程序") : report.actorPath;

    const QColor tone = failed > 0 ? theme::warning() : theme::success();
    setHeader(QStringLiteral("trash"), tone, u("恶意足迹清理报告"),
              actorName + (report.actorPid > 0 ? u(" · PID %1").arg(report.actorPid) : QString()) + u(" · ") + when);

    QVBoxLayout* body = this->body();
    body->setSpacing(12);

    if (!report.actorPath.isEmpty()) {
        auto* p = new WrapLabel(report.actorPath);
        p->setProperty("role", "mono");
        p->setAccessibleName(u("主体路径"));
        body->addWidget(p);
    }
    if (!report.reason.isEmpty()) {
        auto* r = ui::label(u("判定:") + report.reason, "secondary");
        r->setWordWrap(true);
        r->setTextInteractionFlags(Qt::TextSelectableByMouse);
        body->addWidget(r);
    }

    // ── summary tiles ──────────────────────────────────────────────────────────
    auto* tiles = new QHBoxLayout;
    tiles->setSpacing(10);
    struct TileSpec { const char* key; QString label; int count; QColor color; };
    const TileSpec specs[] = {
        {"quarantined", u("已隔离"), quarantined, theme::success()},
        {"removed", u("已移除自启动"), removed, theme::info()},
        {"skipped", u("未能清理"), failed, theme::warning()},
        {"intel", u("新增拦截规则"), report.intelRulesInjected, theme::accentAlt()},
    };
    for (const TileSpec& s : specs) {
        auto* t = new CountTile(s.label, s.count, s.color);
        const QString key = QString::fromLatin1(s.key);
        connect(t, &QAbstractButton::clicked, this, [this, key] { scrollToGroup(key); });
        tiles->addWidget(t);
    }
    body->addLayout(tiles);

    // ── groups (scroll inside a capped area) ────────────────────────────────────
    m_scroll = new FitScrollArea(Sheet::screenHeightFor(parent, 0.40), kCardW - 48);
    auto* content = new QWidget;
    auto* list = new QVBoxLayout(content);
    list->setContentsMargins(0, 0, 6, 0);
    list->setSpacing(6);
    list->setAlignment(Qt::AlignTop);

    if (quarantined > 0) {
        group(list, QStringLiteral("quarantined"), u("已隔离(可在隔离区还原)"), theme::success(), quarantined);
        // 主体排最前并标注「主体载荷」;它本身也在 quarantinedFiles 里,下面跳过,免得列两遍。
        // 比较口径与服务端判定 actorQuarantined 时一致(不区分大小写)。
        if (report.actorQuarantined)
            list->addWidget(pathRow(report.actorPath, u("主体载荷")));
        for (const QString& f : report.quarantinedFiles) {
            if (report.actorQuarantined && f.compare(report.actorPath, Qt::CaseInsensitive) == 0)
                continue;
            list->addWidget(pathRow(f));
        }
    }
    if (removed > 0) {
        group(list, QStringLiteral("removed"), u("已移除自启动 / 注册表项"), theme::info(), removed);
        for (const QString& r : report.removedRegistryValues)
            list->addWidget(pathRow(r));
    }
    if (failed > 0) {
        group(list, QStringLiteral("skipped"), u("未能自动清理"), theme::warning(), failed);
        for (const RemediationSkippedItem& s : report.skipped) {
            auto* rowW = new QWidget;
            auto* h = new QHBoxLayout(rowW);
            h->setContentsMargins(0, 0, 0, 0);
            h->setSpacing(10);
            h->addWidget(pathRow(s.target, s.reason), 1);
            if (s.isFile) {
                auto* retry = ui::button(u("重试隔离"), "ghost", QStringLiteral("refresh"), true);
                const QString target = s.target;
                connect(retry, &QPushButton::clicked, this, [this, retry, target] {
                    if (!m_ipc || !m_ipc->isConnected()) {
                        banners()->post(ui::Tone::Danger, u("未连接后台服务,无法重试隔离。"));
                        return;
                    }
                    m_ipc->manualQuarantine(target);
                    retry->setEnabled(false);
                    retry->setText(u("已请求"));
                    setPinned(true); // the user is acting on it: keep the report open
                });
                h->addWidget(retry, 0, Qt::AlignTop);
                m_retry << qMakePair(target, retry);
            }
            list->addWidget(rowW);
        }
    }

    // 情报补充:该样本(据 VT 等沙箱行为画像)已知会释放 / 外联什么。既解释了上面为何清理
    // 这些项,也说明了据此生成的主动拦截规则覆盖了哪些 IOC。
    const bool hasIntel = !report.intelDroppedFiles.isEmpty() || !report.intelContactedIps.isEmpty()
                       || !report.intelContactedDomains.isEmpty() || !report.intelRegistryKeys.isEmpty();
    if (hasIntel || report.intelRulesInjected > 0) {
        const QString src = report.intelSource.trimmed().isEmpty() ? u("威胁情报") : report.intelSource;
        group(list, QStringLiteral("intel"), u("情报补充 · ") + src, theme::accentAlt(), 0);
        if (report.intelRulesInjected > 0) {
            auto* l = ui::label(u("已据行为画像生成 %1 条主动拦截规则,阻断该样本家族再次入侵。")
                                    .arg(report.intelRulesInjected), "secondary");
            l->setWordWrap(true);
            l->setContentsMargins(18, 0, 0, 0);
            list->addWidget(l);
        }
        auto addCapped = [&](const QString& title, const QStringList& items) {
            if (items.isEmpty())
                return;
            auto* t = ui::label(u("%1(%2 项)").arg(title).arg(items.size()), "caption");
            t->setContentsMargins(18, 4, 0, 0);
            list->addWidget(t);
            constexpr int cap = 10;
            for (int i = 0; i < items.size() && i < cap; ++i)
                list->addWidget(pathRow(items[i]));
            if (items.size() > cap) {
                auto* more = ui::label(u("…… 还有 %1 项").arg(items.size() - cap), "muted");
                more->setContentsMargins(18, 0, 0, 0);
                list->addWidget(more);
            }
        };
        addCapped(u("已知释放文件"), report.intelDroppedFiles);
        addCapped(u("已知外联 IP"), report.intelContactedIps);
        addCapped(u("已知外联域名"), report.intelContactedDomains);
        addCapped(u("已知写入注册表"), report.intelRegistryKeys);
    }

    // AI 清理:交给 AiCleanupDialog(同一套提权 + UTF-8 BOM 的执行流程)。
    if (hasIntel) {
        group(list, QStringLiteral("ai"), u("AI 清理方案"), theme::accent(), 0);
        auto* rowW = new QWidget;
        auto* h = new QHBoxLayout(rowW);
        h->setContentsMargins(18, 0, 0, 0);
        h->setSpacing(10);
        const bool configured = m_ai && m_ai->isConfigured();
        auto* l = ui::label(configured ? u("让大模型根据上面的行为画像写一份 PowerShell 清理脚本;你复核后再以管理员身份执行。")
                                       : u("配置大模型后,可让 AI 根据行为画像生成清理脚本。"),
                            "secondary");
        l->setWordWrap(true);
        h->addWidget(l, 1);
        if (configured) {
            auto* b = ui::button(u("生成清理方案…"), "ghost", QStringLiteral("sparkles"), true);
            connect(b, &QPushButton::clicked, this, [this] {
                bulwark::VtScanRecord rec;
                rec.filePath = m_report.actorPath;
                rec.fileName = QFileInfo(m_report.actorPath).fileName();
                rec.outcome = bulwark::VtScanOutcome::Malicious; // the report exists because it was confirmed
                rec.stage = bulwark::VtScanStage::Completed;
                // Parent to the main window, not to this report: the report may
                // auto-close, the cleanup wizard must not go with it.
                (new AiCleanupDialog(rec, m_report, m_ipc, m_ai, parentWidget()))->show();
                setPinned(true);
            });
            h->addWidget(b, 0, Qt::AlignTop);
        } else {
            auto* b = ui::button(u("去设置"), "ghost", QString(), true);
            connect(b, &QPushButton::clicked, this, [] {
                nav::go(nav::Settings, {{QStringLiteral("section"), QStringLiteral("ai")}});
            });
            h->addWidget(b, 0, Qt::AlignTop);
        }
        list->addWidget(rowW);
    }
    if (list->count() == 0)
        list->addWidget(ui::label(u("本次没有需要列出的清理项。"), "muted"));

    m_scroll->setContent(content);
    body->addWidget(m_scroll, 1);

    // ── footer ──────────────────────────────────────────────────────────────────
    if (failed == 0) {
        m_autoClose = new CountdownBar;
        m_autoClose->setColor(theme::textMuted());
        m_autoClose->setFormatter([](int s) { return u("%1 秒后自动关闭").arg(s); });
        m_autoClose->setToolTip(u("鼠标停在报告上时暂停"));
        // 「停在报告上暂停」由倒计时条按指针真实位置判定。这张卡片是居中弹出的,很容易正好落在
        // 静止的指针底下 —— 换成 enter/leave 那一套的话,它会当场把倒计时冻住再也不自动关闭
        //(详见 CountdownBar::syncHoverPause)。
        m_autoClose->setHoverPause(card());
        connect(m_autoClose, &CountdownBar::finished, this, &QDialog::accept);
        addFooterLeft(m_autoClose);
        m_pin = ui::button(QString(), "ghost", QStringLiteral("pin"), true);
        m_pin->setToolTip(u("固定:保持报告打开,不自动关闭"));
        m_pin->setAccessibleName(u("固定报告"));
        m_pin->setAutoDefault(false);
        connect(m_pin, &QPushButton::clicked, this, [this] { setPinned(true); });
        addFooterLeft(m_pin);
        m_autoClose->start(kAutoCloseMs);
    } else {
        // Said in the body, not squeezed into the footer next to the buttons.
        auto* note = ui::label(u("有未能清理的项,这份报告不会自动关闭。"), "muted");
        body->addWidget(note);
    }

    auto* copy = ui::button(u("复制报告"), "ghost", QStringLiteral("copy"), true);
    copy->setAutoDefault(false);
    connect(copy, &QPushButton::clicked, this, [this, copy] {
        if (QClipboard* cb = QGuiApplication::clipboard())
            cb->setText(reportText());
        copy->setText(u("已复制"));
    });
    footer()->addWidget(copy);
    auto* openQ = ui::button(u("打开隔离区"), "ghost", QStringLiteral("lock"), true);
    openQ->setAutoDefault(false);
    connect(openQ, &QPushButton::clicked, this, &RemediationReportDialog::openQuarantine);
    footer()->addWidget(openQ);
    if (!m_retry.isEmpty()) {
        auto* all = ui::button(u("全部重试"), "ghost", QStringLiteral("refresh"), true);
        all->setAutoDefault(false);
        connect(all, &QPushButton::clicked, this, &RemediationReportDialog::retryAll);
        footer()->addWidget(all);
    }
    QPushButton* close = addButton(u("关闭"), "primary", [this] { accept(); });
    close->setMinimumWidth(84);

    // Retry results land here too (the tray balloon alone is easy to miss).
    if (m_ipc)
        connect(m_ipc, &IpcClient::manualQuarantineResult, this,
                [this](const bulwark::ipc::ManualQuarantineResultPayload& r) {
                    banners()->post(r.success ? ui::Tone::Success : ui::Tone::Danger,
                                    u("重试隔离:") + (r.message.isEmpty() ? (r.success ? u("已隔离") : u("未成功"))
                                                                         : r.message));
                    refit();
                });
}

QWidget* RemediationReportDialog::group(QVBoxLayout* into, const QString& key, const QString& title,
                                        const QColor& color, int count)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, into->count() > 0 ? 10 : 0, 0, 2);
    h->setSpacing(8);
    h->addWidget(ui::statusDot(color), 0, Qt::AlignVCenter);
    h->addWidget(ui::coloredText(title, 10, 700, theme::textPrimary()), 0, Qt::AlignVCenter);
    if (count > 0)
        h->addWidget(ui::pill(QString::number(count), color), 0, Qt::AlignVCenter);
    h->addStretch();
    into->addWidget(w);
    m_groups.insert(key, w);
    return w;
}

void RemediationReportDialog::scrollToGroup(const QString& key)
{
    if (QWidget* w = m_groups.value(key))
        m_scroll->ensureWidgetVisible(w, 0, 8);
    if (QWidget* w = m_groups.value(key)) // put the group title at the top when possible
        m_scroll->verticalScrollBar()->setValue(w->y());
}

void RemediationReportDialog::retryAll()
{
    if (!m_ipc || !m_ipc->isConnected()) {
        banners()->post(ui::Tone::Danger, u("未连接后台服务,无法重试隔离。"));
        refit();
        return;
    }
    int n = 0;
    for (const auto& [path, btn] : std::as_const(m_retry)) {
        if (!btn->isEnabled())
            continue;
        m_ipc->manualQuarantine(path);
        btn->setEnabled(false);
        btn->setText(u("已请求"));
        ++n;
    }
    setPinned(true);
    banners()->post(ui::Tone::Info, n > 0 ? u("已请求重试隔离 %1 个文件,结果会逐条显示在这里。").arg(n)
                                          : u("没有待重试的文件。"));
    refit();
}

void RemediationReportDialog::openQuarantine()
{
    if (QWidget* w = parentWidget() ? parentWidget()->window() : nullptr) {
        w->show();
        w->setWindowState((w->windowState() & ~Qt::WindowMinimized) | Qt::WindowActive);
        w->raise();
        w->activateWindow();
    }
    nav::go(nav::Quarantine);
}

QString RemediationReportDialog::reportText() const
{
    const RemediationReportPayload& r = m_report;
    QStringList out;
    out << u("磐垒 · 恶意足迹清理报告");
    out << u("时间:") + r.timestampUtc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    out << u("主体:") + r.actorPath + (r.actorPid > 0 ? u(" (PID %1)").arg(r.actorPid) : QString());
    if (!r.reason.isEmpty())
        out << u("判定:") + r.reason;
    if (r.actorQuarantined)
        out << u("主体载荷已隔离");
    if (!r.quarantinedFiles.isEmpty())
        out << u("已隔离文件:") << r.quarantinedFiles;
    if (!r.removedRegistryValues.isEmpty())
        out << u("已移除自启动 / 注册表项:") << r.removedRegistryValues;
    if (!r.skipped.isEmpty()) {
        out << u("未能自动清理:");
        for (const RemediationSkippedItem& s : r.skipped)
            out << s.target + u(" —— ") + s.reason;
    }
    if (r.intelRulesInjected > 0)
        out << u("据威胁情报新增拦截规则:%1 条").arg(r.intelRulesInjected);
    return out.join(QLatin1Char('\n'));
}

void RemediationReportDialog::setPinned(bool pinned)
{
    if (pinned == m_pinned)
        return;
    m_pinned = pinned;
    if (!m_autoClose)
        return;
    if (pinned) {
        m_autoClose->stop();
        m_autoClose->hide();
        if (m_pin) {
            m_pin->setEnabled(false);
            m_pin->setText(u("已固定"));
            m_pin->setIcon(QIcon());
        }
    }
}
