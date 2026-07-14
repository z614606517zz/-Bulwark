#include "dialogs/AiCleanupDialog.h"
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
#include <QFont>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QTemporaryFile>
#include <QVBoxLayout>

using bulwark::ipc::RemediationReportPayload;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

// 结论 -> 展示文案 + 颜色(与云信誉页保持一致的语义配色)。
QString outcomeText(bulwark::VtScanOutcome o, QColor& color)
{
    switch (o) {
        case bulwark::VtScanOutcome::Clean:      color = theme::success(); return u("安全");
        case bulwark::VtScanOutcome::Suspicious: color = theme::warning(); return u("可疑");
        case bulwark::VtScanOutcome::Malicious:  color = theme::danger();  return u("恶意");
        case bulwark::VtScanOutcome::Error:      color = theme::danger();  return u("错误");
        case bulwark::VtScanOutcome::Unknown:    color = theme::textMuted(); return u("未知");
        default:                                 color = theme::textMuted(); return u("待定");
    }
}

// 把 AI 生成的清理脚本落到临时 .ps1,再以提权(UAC)方式在可见窗口中执行——清理需触及
// HKLM/防火墙/hosts,必须管理员;-NoExit 让用户看到 Write-Host 输出,便于核对清理过程。
// 用外层普通 powershell 调 Start-Process -Verb RunAs 触发 UAC,无需额外链接 shell32。
bool runElevatedScript(const QString& script)
{
    QTemporaryFile tmp(QDir::tempPath() + QStringLiteral("/bulwark_ai_cleanup_XXXXXX.ps1"));
    if (!tmp.open())
        return false;
    tmp.write("\xEF\xBB\xBF", 3); // UTF-8 BOM,确保中文 Write-Host 输出不乱码
    tmp.write(script.toUtf8());
    tmp.flush();
    const QString scriptPath = QDir::toNativeSeparators(tmp.fileName());
    tmp.setAutoRemove(false); // 交给提权子进程读取,不随本对象销毁而删除
    tmp.close();

    // 单引号内的路径按 PowerShell 规则转义(单引号翻倍);反斜杠在单引号串中为字面量。
    QString safePath = scriptPath;
    safePath.replace(QLatin1Char('\''), QStringLiteral("''"));
    const QString inner =
        QStringLiteral("Start-Process -FilePath 'powershell' -Verb RunAs -ArgumentList "
                       "@('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','%1')")
            .arg(safePath);
    return QProcess::startDetached(
        QStringLiteral("powershell"),
        { QStringLiteral("-NoProfile"), QStringLiteral("-ExecutionPolicy"),
          QStringLiteral("Bypass"), QStringLiteral("-Command"), inner });
}

} // namespace

AiCleanupDialog::AiCleanupDialog(const bulwark::VtScanRecord& record,
                                 const RemediationReportPayload& report,
                                 IpcClient* ipc, AiScanner* ai, QWidget* parent)
    : QDialog(parent), m_ipc(ipc), m_ai(ai), m_report(report),
      m_fileName(!record.fileName.isEmpty() ? record.fileName : QFileInfo(record.filePath).fileName()),
      m_filePath(record.filePath)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setModal(false);
    setWindowTitle(u("AI 智能清理 · ") + (m_fileName.isEmpty() ? u("未知文件") : m_fileName));
    setMinimumWidth(560);
    setStyleSheet(QStringLiteral("QDialog{background:%1;}").arg(theme::surface().name()));

    auto* shell = new QVBoxLayout(this);
    shell->setContentsMargins(22, 20, 22, 20);
    shell->setSpacing(13);

    // ── 顶部:图标 + 文件名 + 路径 + 结论 pill ──────────────────────────────
    auto* head = new QHBoxLayout;
    head->setSpacing(12);
    head->addWidget(ui::iconBadge(QStringLiteral("sparkles"), theme::accent(), 40, 20), 0, Qt::AlignVCenter);
    auto* hcol = new QVBoxLayout;
    hcol->setSpacing(2);
    hcol->addWidget(ui::coloredText(m_fileName.isEmpty() ? u("未知文件") : m_fileName,
                                    14, 700, theme::textPrimary()));
    auto* subPath = ui::elided(m_filePath.isEmpty() ? record.sha256 : m_filePath, "mono");
    subPath->setProperty("role", "muted");
    hcol->addWidget(subPath);
    head->addLayout(hcol, 1);
    QColor oc;
    const QString ot = outcomeText(record.outcome, oc);
    head->addWidget(ui::pill(ot, oc), 0, Qt::AlignVCenter);
    shell->addLayout(head);
    shell->addWidget(ui::hDivider());

    // ── 说明 + IOC 摘要 ────────────────────────────────────────────────────
    auto* intro = ui::label(
        u("AI 将根据该文件的行为画像(释放文件 / 外联地址 / 注册表)生成 PowerShell 清理方案。"
          "脚本会在你复核并确认后,以管理员权限执行。"), "secondary");
    intro->setWordWrap(true);
    shell->addWidget(intro);

    QStringList iocParts;
    if (!m_report.intelDroppedFiles.isEmpty())
        iocParts << u("释放文件 ") + QString::number(m_report.intelDroppedFiles.size());
    if (!m_report.intelContactedIps.isEmpty())
        iocParts << u("外联 IP ") + QString::number(m_report.intelContactedIps.size());
    if (!m_report.intelContactedDomains.isEmpty())
        iocParts << u("外联域名 ") + QString::number(m_report.intelContactedDomains.size());
    if (!m_report.intelRegistryKeys.isEmpty())
        iocParts << u("注册表 ") + QString::number(m_report.intelRegistryKeys.size());
    auto* iocLine = ui::label(
        iocParts.isEmpty() ? u("行为画像:暂无额外 IOC,将针对该文件主体进行清理")
                           : (u("行为画像:") + iocParts.join(QStringLiteral(" · "))), "muted");
    iocLine->setWordWrap(true);
    shell->addWidget(iocLine);

    // ── 生成按钮 + 状态 ────────────────────────────────────────────────────
    auto* genRow = new QHBoxLayout;
    genRow->setSpacing(10);
    m_genBtn = new QPushButton(u("🤖 开始 AI 清理"));
    m_genBtn->setProperty("variant", "primary");
    m_genBtn->setCursor(Qt::PointingHandCursor);
    genRow->addWidget(m_genBtn);
    m_status = ui::label(QString(), "muted");
    m_status->setWordWrap(true);
    genRow->addWidget(m_status, 1);
    shell->addLayout(genRow);

    // ── 脚本预览(生成后显示)─────────────────────────────────────────────
    m_scriptView = new QPlainTextEdit;
    m_scriptView->setReadOnly(true);
    m_scriptView->setFont(QFont(QStringLiteral("Consolas"), 9));
    m_scriptView->setPlaceholderText(u("点击「开始 AI 清理」,AI 将基于行为画像生成清理脚本…"));
    m_scriptView->setMinimumHeight(220);
    m_scriptView->hide();
    shell->addWidget(m_scriptView, 1);

    // ── 复制 / 执行(生成后显示)+ 关闭 ───────────────────────────────────
    auto* footer = new QHBoxLayout;
    footer->setSpacing(8);
    m_copyBtn = new QPushButton(u("📋 复制脚本"));
    m_copyBtn->setProperty("variant", "ghost");
    m_copyBtn->setCursor(Qt::PointingHandCursor);
    m_copyBtn->hide();
    footer->addWidget(m_copyBtn);
    m_runBtn = new QPushButton(u("▶ 执行清理(需确认)"));
    m_runBtn->setProperty("variant", "danger");
    m_runBtn->setCursor(Qt::PointingHandCursor);
    m_runBtn->hide();
    footer->addWidget(m_runBtn);
    footer->addStretch();
    auto* closeBtn = new QPushButton(u("关闭"));
    closeBtn->setProperty("variant", "ghost");
    closeBtn->setCursor(Qt::PointingHandCursor);
    closeBtn->setMinimumWidth(84);
    footer->addWidget(closeBtn);
    shell->addLayout(footer);

    connect(closeBtn, &QPushButton::clicked, this, &QDialog::reject);
    connect(m_genBtn, &QPushButton::clicked, this, &AiCleanupDialog::startGeneration);
    connect(m_copyBtn, &QPushButton::clicked, this, [this] {
        QApplication::clipboard()->setText(m_scriptView->toPlainText());
        m_copyBtn->setText(u("✅ 已复制"));
    });
    connect(m_runBtn, &QPushButton::clicked, this, &AiCleanupDialog::executeScript);

    // AI 客户端未配置:禁用生成,提示到「设置」里填接口地址/API Key。
    if (!m_ai || !m_ai->isConfigured()) {
        m_genBtn->setEnabled(false);
        m_status->setStyleSheet(QStringLiteral("color:%1;").arg(theme::warning().name()));
        m_status->setText(u("未配置大模型:请到「设置 → AI」填写接口地址与 API Key 后再试。"));
    } else {
        connect(m_ai, &AiScanner::cleanupScriptGenerated, this, &AiCleanupDialog::onScriptReady);
    }

    resize(680, 560);
}

void AiCleanupDialog::startGeneration()
{
    if (!m_ai || !m_ai->isConfigured())
        return;
    m_awaiting = true;
    m_genBtn->setEnabled(false);
    m_genBtn->setText(u("AI 生成中…"));
    m_status->setStyleSheet(QStringLiteral("color:%1;").arg(theme::textMuted().name()));
    m_status->setText(u("正在把行为画像发送给大模型并生成清理方案…"));
    m_ai->generateCleanupScript(m_report);
}

void AiCleanupDialog::onScriptReady(const QString& script)
{
    if (!m_awaiting) // 忽略由其它对话框触发的同名信号(共享同一个 AiScanner)
        return;
    m_awaiting = false;
    m_genBtn->setEnabled(true);
    m_genBtn->setText(u("🤖 重新生成"));

    if (script.isEmpty()) {
        m_status->setStyleSheet(QStringLiteral("color:%1;").arg(theme::danger().name()));
        m_status->setText(u("AI 生成失败(网络 / 模型不可用或返回为空),请稍后重试。"));
        return;
    }

    m_status->setStyleSheet(QStringLiteral("color:%1;").arg(theme::success().name()));
    m_status->setText(u("清理方案已生成,请复核脚本内容后再执行。"));
    m_scriptView->setPlainText(script);
    m_scriptView->show();
    m_copyBtn->show();
    m_copyBtn->setText(u("📋 复制脚本"));
    m_runBtn->show();
}

void AiCleanupDialog::executeScript()
{
    const QString script = m_scriptView->toPlainText().trimmed();
    if (script.isEmpty())
        return;

    const QString msg = u("即将以管理员权限执行 AI 生成的 PowerShell 清理脚本,该脚本可能会:\n"
                          "  1. 终止相关进程\n"
                          "  2. 删除释放的恶意文件\n"
                          "  3. 清理注册表自启动项\n"
                          "  4. 添加防火墙 / hosts 阻断规则\n\n"
                          "请务必先复核脚本内容。执行会触发 UAC 提权,确定继续吗?");
    if (QMessageBox::warning(this, u("确认执行 AI 清理"), msg,
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;

    if (runElevatedScript(script)) {
        m_status->setStyleSheet(QStringLiteral("color:%1;").arg(theme::success().name()));
        m_status->setText(u("已启动清理(请在弹出的 UAC 与 PowerShell 窗口中确认并查看结果)。"));
        m_runBtn->setEnabled(false);
        m_runBtn->setText(u("清理已启动"));
    } else {
        m_status->setStyleSheet(QStringLiteral("color:%1;").arg(theme::danger().name()));
        m_status->setText(u("无法启动清理进程(PowerShell 不可用或被拦截)。可复制脚本手动执行。"));
    }
}
