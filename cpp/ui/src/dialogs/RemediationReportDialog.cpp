#include "dialogs/RemediationReportDialog.h"
#include "ai/AiScanner.h"
#include "ipc/IpcClient.h"
#include "widgets/AppIcon.h"
#include "widgets/Cards.h"
#include "widgets/Ui.h"
#include "Theme.h"

#include <QApplication>
#include <QClipboard>
#include <QDir>
#include <QFileInfo>
#include <QGraphicsDropShadowEffect>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QScreen>
#include <QScrollArea>
#include <QShowEvent>
#include <QTemporaryFile>
#include <QToolButton>
#include <QVBoxLayout>

using bulwark::ipc::RemediationReportPayload;
using bulwark::ipc::RemediationSkippedItem;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

// Caption above a value widget (mirrors the behavior prompt's field()).
QWidget* field(const QString& caption, QWidget* value)
{
    auto* w = new QWidget;
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(3);
    v->addWidget(ui::label(caption, "caption"));
    v->addWidget(value);
    return w;
}

// Section heading: a small coloured dot + bold title + count pill.
QWidget* sectionHead(const QString& title, const QColor& color, int count)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 6, 0, 0);
    h->setSpacing(8);
    h->addWidget(ui::statusDot(color), 0, Qt::AlignVCenter);
    h->addWidget(ui::coloredText(title, 11, 700, theme::textPrimary()));
    if (count > 0)
        h->addWidget(ui::pill(QString::number(count), color), 0, Qt::AlignVCenter);
    h->addStretch();
    return w;
}

// A single "• path" list row (path elides, so long paths never widen the card).
QWidget* pathRow(const QString& path, const QString& note = QString())
{
    auto* w = new QWidget;
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(17, 0, 0, 0); // indent under the section dot
    v->setSpacing(1);
    auto* p = ui::elided(path, "mono");
    p->setProperty("role", "muted");
    v->addWidget(p);
    if (!note.isEmpty())
        v->addWidget(ui::label(note, "muted"));
    return w;
}

} // namespace

RemediationReportDialog::RemediationReportDialog(const RemediationReportPayload& report,
                                                 IpcClient* ipc, AiScanner* ai, QWidget* parent)
    : QDialog(parent), m_ipc(ipc), m_ai(ai), m_actorName(QFileInfo(report.actorPath).fileName())
{
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_DeleteOnClose);
    setModal(false); // informational — never blocks the user's work
    setFixedWidth(560);

    const int cleaned = report.quarantinedFiles.size() + report.removedRegistryValues.size()
                        + (report.actorQuarantined ? 1 : 0);
    const int failed = report.skipped.size();
    const QString when = report.timestampUtc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    const QString actorName = QFileInfo(report.actorPath).fileName();

    auto* shell = new QVBoxLayout(this);
    shell->setContentsMargins(24, 24, 24, 24);

    auto* cardW = ui::card();
    auto* shadow = new QGraphicsDropShadowEffect(cardW);
    shadow->setBlurRadius(54);
    shadow->setOffset(0, 14);
    shadow->setColor(QColor(15, 23, 42, 110));
    cardW->setGraphicsEffect(shadow);
    shell->addWidget(cardW);

    auto* v = new QVBoxLayout(cardW);
    v->setContentsMargins(24, 22, 24, 22);
    v->setSpacing(14);

    // ── Header ──────────────────────────────────────────────────────────
    auto* head = new QHBoxLayout;
    head->setSpacing(14);
    head->addWidget(ui::iconBadge(QStringLiteral("trash"), theme::accent(), 46, 24), 0, Qt::AlignTop);
    auto* hcol = new QVBoxLayout;
    hcol->setSpacing(2);
    hcol->addWidget(ui::coloredText(u("恶意足迹清理报告"), 15, 700, theme::textPrimary()));
    hcol->addWidget(ui::label(u("MALICIOUS FOOTPRINT REMEDIATION REPORT"), "caption"));
    head->addLayout(hcol);
    head->addStretch();
    auto* closeX = new QToolButton;
    closeX->setIcon(AppIcon::icon(QStringLiteral("close"), theme::textMuted(), 16));
    closeX->setCursor(Qt::PointingHandCursor);
    closeX->setAutoRaise(true);
    closeX->setStyleSheet(QStringLiteral(
        "QToolButton{border:none;background:transparent;padding:2px;}"
        "QToolButton:hover{background:%1;border-radius:6px;}").arg(theme::surfaceAlt().name()));
    connect(closeX, &QToolButton::clicked, this, &QDialog::accept);
    head->addWidget(closeX, 0, Qt::AlignTop);
    v->addLayout(head);
    v->addWidget(ui::hDivider());

    // ── Subject (name + PID) ────────────────────────────────────────────
    auto* subjCol = new QVBoxLayout;
    subjCol->setSpacing(3);
    auto* nameRow = new QHBoxLayout;
    nameRow->setSpacing(8);
    nameRow->addWidget(ui::coloredText(actorName.isEmpty() ? u("未知程序") : actorName,
                                       12, 700, theme::textPrimary()));
    if (report.actorPid > 0)
        nameRow->addWidget(ui::pill(QStringLiteral("PID %1").arg(report.actorPid), theme::textMuted()),
                           0, Qt::AlignVCenter);
    nameRow->addStretch();
    auto* nameW = new QWidget; nameW->setLayout(nameRow);
    subjCol->addWidget(nameW);
    auto* subjPath = ui::elided(report.actorPath, "mono");
    subjPath->setProperty("role", "muted");
    subjCol->addWidget(subjPath);
    auto* subjW = new QWidget; subjW->setLayout(subjCol);
    v->addWidget(field(u("主体"), subjW));

    // ── Verdict / reason ────────────────────────────────────────────────
    if (!report.reason.isEmpty()) {
        auto* rl = ui::label(report.reason, "secondary");
        rl->setWordWrap(true);
        v->addWidget(field(u("判定"), rl));
    }

    // ── Tally line ──────────────────────────────────────────────────────
    const QColor tallyColor = failed > 0 ? theme::warning() : theme::success();
    auto* tally = ui::coloredText(
        u("成功清理 ") + QString::number(cleaned) + u(" 项  ·  未能清理 ")
            + QString::number(failed) + u(" 项  ·  ") + when,
        10, 600, tallyColor);
    v->addWidget(tally);
    // 主动防护提示:据威胁情报行为画像生成的拦截规则数(让「不仅报毒,还免疫再感染」直观可见)。
    if (report.intelRulesInjected > 0)
        v->addWidget(ui::coloredText(
            u("已据威胁情报行为画像生成 ") + QString::number(report.intelRulesInjected)
                + u(" 条主动拦截规则,阻断该样本家族再次入侵"),
            10, 600, theme::accentAlt()));
    v->addWidget(ui::hDivider());

    // ── Result sections (scrollable so long lists never overgrow the card) ─
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setMaximumHeight(300);
    auto* content = new QWidget;
    scroll->setWidget(content);
    auto* list = new QVBoxLayout(content);
    list->setContentsMargins(0, 0, 4, 0);
    list->setSpacing(6);

    if (report.actorQuarantined) {
        list->addWidget(sectionHead(u("主体载荷已隔离"), theme::success(), 0));
        list->addWidget(pathRow(report.actorPath));
    }
    if (!report.quarantinedFiles.isEmpty()) {
        list->addWidget(sectionHead(u("已隔离文件"), theme::success(), report.quarantinedFiles.size()));
        for (const QString& f : report.quarantinedFiles)
            list->addWidget(pathRow(f));
    }
    if (!report.removedRegistryValues.isEmpty()) {
        list->addWidget(sectionHead(u("已移除自启动 / 注册表项"), theme::info(),
                                    report.removedRegistryValues.size()));
        for (const QString& r : report.removedRegistryValues)
            list->addWidget(pathRow(r));
    }
    if (!report.skipped.isEmpty()) {
        list->addWidget(sectionHead(u("未能自动清理"), theme::warning(), report.skipped.size()));
        for (const RemediationSkippedItem& s : report.skipped) {
            auto* rowW = new QWidget;
            auto* h = new QHBoxLayout(rowW);
            h->setContentsMargins(17, 0, 0, 0);
            h->setSpacing(10);
            h->addWidget(pathRow(s.target, s.reason), 1);
            if (s.isFile) {
                auto* retry = new QPushButton(u("重试隔离"));
                retry->setProperty("variant", "primary");
                retry->setProperty("size", "sm");
                retry->setCursor(Qt::PointingHandCursor);
                const QString target = s.target;
                connect(retry, &QPushButton::clicked, this, [this, retry, target] {
                    if (m_ipc) m_ipc->manualQuarantine(target);
                    retry->setEnabled(false);
                    retry->setText(u("已请求"));
                });
                h->addWidget(retry, 0, Qt::AlignVCenter);
            }
            list->addWidget(rowW);
        }
    }

    // ── 情报补充:该样本(据 VT 等沙箱行为画像)已知会释放 / 外联什么。既解释了上面为何清理
    //    这些项,也说明了据此生成的主动拦截规则覆盖了哪些 IOC。────────────────────────
    const bool hasIntel = !report.intelDroppedFiles.isEmpty()
                       || !report.intelContactedIps.isEmpty()
                       || !report.intelContactedDomains.isEmpty()
                       || !report.intelRegistryKeys.isEmpty();
    if (hasIntel) {
        const QString src = report.intelSource.trimmed().isEmpty() ? u("威胁情报")
                                                                   : report.intelSource;
        list->addWidget(sectionHead(u("情报补充 · ") + src, theme::accentAlt(), 0));
        auto addCapped = [&](const QString& title, const QStringList& items) {
            if (items.isEmpty()) return;
            list->addWidget(pathRow(title + u("(") + QString::number(items.size()) + u(" 项)")));
            const int cap = 10;
            for (int i = 0; i < items.size() && i < cap; ++i)
                list->addWidget(pathRow(QStringLiteral("· ") + items[i]));
            if (items.size() > cap)
                list->addWidget(pathRow(u("…… 还有 ") + QString::number(items.size() - cap) + u(" 项")));
        };
        addCapped(u("已知释放文件"), report.intelDroppedFiles);
        addCapped(u("已知外联 IP"), report.intelContactedIps);
        addCapped(u("已知外联域名"), report.intelContactedDomains);
        addCapped(u("已知写入注册表"), report.intelRegistryKeys);
    }

    // ── AI 清理脚本:基于 VT 行为画像由 AI 生成 PowerShell 清理脚本───────────────
    if (m_ai && m_ai->isConfigured() && hasIntel) {
        list->addWidget(ui::hDivider());
        list->addWidget(sectionHead(u("AI 清理脚本"), theme::accent(), 0));
        m_genBtn = new QPushButton(u("🤖 生成清理脚本"));
        m_genBtn->setProperty("variant", "primary");
        m_genBtn->setCursor(Qt::PointingHandCursor);
        connect(m_genBtn, &QPushButton::clicked, this, [this, report] {
            m_genBtn->setEnabled(false);
            m_genBtn->setText(u("AI 生成中…"));
            m_ai->generateCleanupScript(report);
        });
        list->addWidget(m_genBtn);

        m_scriptView = new QPlainTextEdit;
        m_scriptView->setReadOnly(true);
        m_scriptView->setFont(QFont(QStringLiteral("Consolas"), 9));
        m_scriptView->setMaximumHeight(250);
        m_scriptView->setPlaceholderText(u("点击上方按钮,AI 将基于威胁情报生成清理脚本…"));
        m_scriptView->hide();
        list->addWidget(m_scriptView);

        auto* actionRow = new QHBoxLayout;
        actionRow->setSpacing(8);
        m_copyBtn = new QPushButton(u("📋 复制脚本"));
        m_copyBtn->setProperty("variant", "ghost");
        m_copyBtn->setCursor(Qt::PointingHandCursor);
        m_copyBtn->hide();
        connect(m_copyBtn, &QPushButton::clicked, this, [this] {
            QApplication::clipboard()->setText(m_scriptView->toPlainText());
            m_copyBtn->setText(u("✅ 已复制"));
        });
        actionRow->addWidget(m_copyBtn);

        m_runBtn = new QPushButton(u("▶ 一键执行(需确认)"));
        m_runBtn->setProperty("variant", "primary");
        m_runBtn->setCursor(Qt::PointingHandCursor);
        m_runBtn->hide();
        connect(m_runBtn, &QPushButton::clicked, this, [this] {
            const QString title = u("确认执行清理脚本");
            const QString msg = u("即将执行 AI 生成的 PowerShell 清理脚本,该脚本会:\n"
                                  "1. 尝试终止相关进程\n"
                                  "2. 删除释放的文件\n"
                                  "3. 清理注册表项\n"
                                  "4. 添加防火墙/hosts 阻断规则\n\n"
                                  "请确认脚本内容后再执行。要继续吗?");
            if (QMessageBox::warning(this, title, msg,
                                     QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
                return;
            QTemporaryFile tmp(QDir::tempPath() + QStringLiteral("/bulwark_cleanup_XXXXXX.ps1"));
            if (tmp.open()) {
                tmp.write(m_scriptView->toPlainText().toUtf8());
                tmp.flush();
                const QString scriptPath = tmp.fileName();
                tmp.setAutoRemove(false);
                tmp.close();
                QProcess::startDetached(QStringLiteral("powershell"),
                    { QStringLiteral("-NoProfile"), QStringLiteral("-ExecutionPolicy"),
                      QStringLiteral("Bypass"), QStringLiteral("-File"), scriptPath });
            }
        });
        actionRow->addWidget(m_runBtn);
        actionRow->addStretch();
        auto* actionW = new QWidget;
        actionW->setLayout(actionRow);
        actionW->hide();
        list->addWidget(actionW);

        // Store action widgets for show/hide on completion.
        struct Scope {
            QPushButton* copy;
            QPushButton* run;
            QPlainTextEdit* view;
            QWidget* row;
        };
        auto* scope = new Scope{ m_copyBtn, m_runBtn, m_scriptView, actionW };
        connect(m_ai, &AiScanner::cleanupScriptGenerated, this,
                [this, scope](const QString& script) {
            m_genBtn->setText(u("🤖 重新生成"));
            m_genBtn->setEnabled(true);
            if (script.isEmpty()) {
                m_scriptView->setPlainText(u("AI 生成失败(网络/模型不可用)"));
                m_scriptView->show();
                return;
            }
            m_scriptView->setPlainText(script);
            m_scriptView->show();
            scope->copy->show();
            scope->run->show();
            scope->row->show();
        });
    }

    list->addStretch();
    v->addWidget(scroll);

    // ── Footer ──────────────────────────────────────────────────────────
    auto* footer = new QHBoxLayout;
    footer->addWidget(ui::label(u("报告时间: ") + when, "muted"));
    footer->addStretch();
    auto* closeBtn = new QPushButton(u("关闭"));
    closeBtn->setProperty("variant", "primary");
    closeBtn->setCursor(Qt::PointingHandCursor);
    closeBtn->setMinimumWidth(96);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    footer->addWidget(closeBtn);
    v->addLayout(footer);
}

void RemediationReportDialog::showEvent(QShowEvent* e)
{
    QDialog::showEvent(e);
    if (m_centered)
        return;
    m_centered = true;
    adjustSize();
    QScreen* scr = QGuiApplication::primaryScreen();
    const QRect area = scr ? scr->availableGeometry() : QRect(0, 0, 1920, 1080);
    move(area.center().x() - width() / 2, area.center().y() - height() / 2);
}

void RemediationReportDialog::mousePressEvent(QMouseEvent* e)
{
    if (e->button() == Qt::LeftButton)
        m_dragOffset = e->globalPosition().toPoint() - frameGeometry().topLeft();
    QDialog::mousePressEvent(e);
}

void RemediationReportDialog::mouseMoveEvent(QMouseEvent* e)
{
    if (e->buttons() & Qt::LeftButton)
        move(e->globalPosition().toPoint() - m_dragOffset);
    QDialog::mouseMoveEvent(e);
}
