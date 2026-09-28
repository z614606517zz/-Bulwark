#include "dialogs/AiCleanupDialog.h"
#include "Nav.h"
#include "ai/AiScanner.h"
#include "ipc/IpcClient.h"
#include "design/Components.h"
#include "design/CountTile.h"
#include "design/Icons.h"
#include "design/Stepper.h"
#include "design/Theme.h"
#include "widgets/WrapLabel.h"

#include <QButtonGroup>
#include <QCheckBox>
#include <QClipboard>
#include <QDir>
#include <QFileInfo>
#include <QFont>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QStackedWidget>
#include <QTemporaryFile>
#include <QVBoxLayout>

using bulwark::ipc::RemediationReportPayload;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

enum Page { PageProfile = 0, PageScript = 1, PageRun = 2 };

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
    : Sheet(parent), m_ipc(ipc), m_ai(ai), m_report(report),
      m_fileName(!record.fileName.isEmpty() ? record.fileName : QFileInfo(record.filePath).fileName()),
      m_filePath(record.filePath)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setModal(false);
    setSheetWidth(640);
    setHeader(QStringLiteral("sparkles"), theme::accentAlt(),
              u("AI 智能清理 · ") + (m_fileName.isEmpty() ? u("未知文件") : m_fileName),
              u("看画像 → 生成方案 → 复核后执行,每一步都由你确认"));

    QVBoxLayout* body = this->body();
    m_steps = new Stepper({u("行为画像"), u("生成方案"), u("执行")});
    body->addWidget(m_steps);

    m_pages = new QStackedWidget;
    m_pages->addWidget(buildProfile(record));
    m_pages->addWidget(buildScript());
    m_pages->addWidget(buildRun());
    body->addWidget(m_pages, 1);

    m_back = ui::button(u("上一步"), "ghost", QStringLiteral("chevron-left"), false);
    m_back->setAutoDefault(false);
    connect(m_back, &QPushButton::clicked, this, [this] { goTo(m_step - 1); });
    addFooterLeft(m_back);
    addButton(u("关闭"), "ghost", [this] { reject(); });
    m_next = addButton(QString(), "primary", [this] {
        if (m_step == PageRun)
            executeScript();
        else
            goTo(m_step + 1);
    });

    if (m_ai)
        connect(m_ai, &AiScanner::cleanupScriptGenerated, this, &AiCleanupDialog::onScriptReady);
    goTo(PageProfile);
}

QWidget* AiCleanupDialog::buildProfile(const bulwark::VtScanRecord& record)
{
    auto* w = new QWidget;
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(0, 4, 0, 0);
    v->setSpacing(12);

    // subject
    auto* subj = new QHBoxLayout;
    subj->setSpacing(10);
    auto* path = new WrapLabel(m_filePath.isEmpty() ? record.sha256 : m_filePath);
    path->setProperty("role", "mono");
    subj->addWidget(path, 1);
    QColor oc;
    const QString ot = outcomeText(record.outcome, oc);
    subj->addWidget(ui::pill(ot, oc), 0, Qt::AlignTop);
    v->addLayout(subj);

    auto* intro = ui::label(
        u("AI 会根据该文件的行为画像(释放文件 / 外联地址 / 注册表)生成 PowerShell 清理方案。"
          "发给模型的只有这些画像信息,不含文件本身。"), "secondary");
    intro->setWordWrap(true);
    v->addWidget(intro);

    // IOC tiles; a tile toggles its item list.
    struct Cat { QString name; QStringList items; QColor color; };
    const QList<Cat> cats = {
        {u("释放文件"), m_report.intelDroppedFiles, theme::warning()},
        {u("外联 IP"), m_report.intelContactedIps, theme::cyan()},
        {u("外联域名"), m_report.intelContactedDomains, theme::sky()},
        {u("注册表"), m_report.intelRegistryKeys, theme::violet()},
    };
    auto* tiles = new QHBoxLayout;
    tiles->setSpacing(10);
    auto* detail = ui::cardAlt();
    auto* dl = new QVBoxLayout(detail);
    dl->setContentsMargins(14, 10, 14, 12);
    dl->setSpacing(4);
    auto* detailTitle = ui::label(QString(), "caption");
    auto* detailText = new WrapLabel;
    detailText->setProperty("role", "mono");
    dl->addWidget(detailTitle);
    dl->addWidget(detailText);
    detail->hide();
    auto* group = new QButtonGroup(w);
    group->setExclusive(false);
    int total = 0;
    for (const Cat& c : cats) {
        auto* t = new CountTile(c.name, int(c.items.size()), c.color);
        t->setCheckable(true);
        total += int(c.items.size());
        group->addButton(t);
        const QString name = c.name;
        const QStringList items = c.items;
        connect(t, &QAbstractButton::toggled, this, [this, group, t, detail, detailTitle, detailText, name, items](bool on) {
            if (on) {
                for (QAbstractButton* other : group->buttons())
                    if (other != t)
                        other->setChecked(false);
                constexpr int cap = 30;
                QStringList shown = items.mid(0, cap);
                if (items.size() > cap)
                    shown << u("…… 还有 %1 项").arg(items.size() - cap);
                detailTitle->setText(u("%1(%2 项)").arg(name).arg(items.size()));
                detailText->setText(shown.join(QLatin1Char('\n')));
                detail->show();
            } else {
                bool any = false;
                for (QAbstractButton* other : group->buttons())
                    any = any || other->isChecked();
                if (!any)
                    detail->hide();
            }
            refit();
        });
        tiles->addWidget(t);
    }
    v->addLayout(tiles);
    v->addWidget(detail);
    if (total == 0)
        v->addWidget(ui::label(u("行为画像:暂无额外 IOC,将只针对该文件主体生成清理步骤。"), "muted"));

    if (!m_ai || !m_ai->isConfigured()) {
        auto* row = new QHBoxLayout;
        auto* warn = ui::label(u("未配置大模型:在「设置 → 云查杀与 AI」填写接口地址与 API Key 后才能生成方案。"),
                               "secondary");
        warn->setWordWrap(true);
        warn->setStyleSheet(QStringLiteral("color:%1;").arg(theme::warning().name()));
        row->addWidget(warn, 1);
        auto* go = ui::button(u("去设置"), "ghost", QString(), true);
        connect(go, &QPushButton::clicked, this, [] {
            nav::go(nav::Settings, {{QStringLiteral("section"), QStringLiteral("ai")}});
        });
        row->addWidget(go, 0, Qt::AlignTop);
        v->addLayout(row);
    }
    v->addStretch();
    return w;
}

QWidget* AiCleanupDialog::buildScript()
{
    auto* w = new QWidget;
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(0, 4, 0, 0);
    v->setSpacing(10);
    auto* top = new QHBoxLayout;
    m_genStatus = ui::label(QString(), "secondary");
    m_genStatus->setWordWrap(true);
    top->addWidget(m_genStatus, 1);
    m_regen = ui::button(u("重新生成"), "ghost", QStringLiteral("refresh"), true);
    m_regen->setAutoDefault(false);
    connect(m_regen, &QPushButton::clicked, this, &AiCleanupDialog::startGeneration);
    top->addWidget(m_regen, 0, Qt::AlignTop);
    m_copy = ui::button(u("复制脚本"), "ghost", QStringLiteral("copy"), true);
    m_copy->setAutoDefault(false);
    connect(m_copy, &QPushButton::clicked, this, [this] {
        if (QClipboard* cb = QGuiApplication::clipboard())
            cb->setText(m_scriptView->toPlainText());
        m_copy->setText(u("已复制"));
    });
    top->addWidget(m_copy, 0, Qt::AlignTop);
    v->addLayout(top);

    m_scriptView = new QPlainTextEdit;
    m_scriptView->setReadOnly(true);
    QFont mono;
    mono.setFamilies({QStringLiteral("Cascadia Mono"), QStringLiteral("Consolas")});
    mono.setPointSizeF(9.0);
    m_scriptView->setFont(mono);
    m_scriptView->setLineWrapMode(QPlainTextEdit::NoWrap);
    m_scriptView->setPlaceholderText(u("方案生成后显示在这里…"));
    m_scriptView->setMinimumHeight(260);
    m_scriptView->setAccessibleName(u("清理脚本"));
    v->addWidget(m_scriptView, 1);
    return w;
}

QWidget* AiCleanupDialog::buildRun()
{
    auto* w = new QWidget;
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(0, 4, 0, 0);
    v->setSpacing(10);
    v->addWidget(ui::label(u("执行前请确认:这份脚本可能会"), "title"));
    for (const char* s : {"终止相关进程", "删除释放的恶意文件", "清理注册表自启动项",
                          "添加防火墙 / hosts 阻断规则"}) {
        auto* row = new QHBoxLayout;
        row->setSpacing(10);
        auto* dotBox = new QWidget;
        auto* db = new QVBoxLayout(dotBox);
        db->setContentsMargins(0, 7, 0, 0);
        db->addWidget(ui::statusDot(theme::danger()));
        row->addWidget(dotBox, 0, Qt::AlignTop);
        auto* l = ui::label(u(s));
        l->setWordWrap(true);
        row->addWidget(l, 1);
        v->addLayout(row);
    }
    auto* how = ui::label(u("执行会弹出 Windows 的管理员授权(UAC),脚本在可见的 PowerShell 窗口里运行,"
                            "窗口保持打开,方便你核对每一步输出。删除操作可能无法撤销。"), "secondary");
    how->setWordWrap(true);
    v->addWidget(how);
    m_ack = new QCheckBox(u("我已复核脚本内容"));
    m_ack->setCursor(Qt::PointingHandCursor);
    connect(m_ack, &QCheckBox::toggled, this, [this] { syncNav(); });
    v->addWidget(m_ack);
    m_runStatus = ui::label(QString(), "secondary");
    m_runStatus->setWordWrap(true);
    v->addWidget(m_runStatus);
    v->addStretch();
    return w;
}

void AiCleanupDialog::goTo(int step)
{
    step = qBound(0, step, int(PageRun));
    m_step = step;
    m_pages->setCurrentIndex(step);
    m_steps->setProgress(step);
    if (step == PageScript && !m_hasScript && !m_awaiting)
        startGeneration();
    syncNav();
    refit();
}

void AiCleanupDialog::syncNav()
{
    m_back->setVisible(m_step > PageProfile);
    const bool configured = m_ai && m_ai->isConfigured();
    switch (m_step) {
    case PageProfile:
        m_next->setText(u("生成方案"));
        ui::setVariant(m_next, "primary");
        m_next->setEnabled(configured);
        m_next->setToolTip(configured ? QString() : u("需要先配置大模型"));
        break;
    case PageScript:
        m_next->setText(u("下一步"));
        ui::setVariant(m_next, "primary");
        m_next->setEnabled(m_hasScript && !m_awaiting);
        m_next->setToolTip(m_hasScript ? QString() : u("等待方案生成"));
        break;
    case PageRun:
        m_next->setText(m_launched ? u("清理已启动") : u("以管理员身份执行"));
        ui::setVariant(m_next, "danger");
        m_next->setEnabled(!m_launched && m_hasScript && m_ack && m_ack->isChecked());
        m_next->setToolTip(m_ack && !m_ack->isChecked() ? u("先勾选「我已复核脚本内容」") : QString());
        break;
    default:
        break;
    }
    m_regen->setEnabled(configured && !m_awaiting);
    m_copy->setEnabled(m_hasScript);
}

void AiCleanupDialog::startGeneration()
{
    if (!m_ai || !m_ai->isConfigured())
        return;
    m_awaiting = true;
    m_hasScript = false;
    if (m_ack)
        m_ack->setChecked(false); // a new script must be reviewed again
    m_scriptView->clear();
    m_genStatus->setStyleSheet(QString());
    m_genStatus->setText(u("正在把行为画像发送给大模型并生成清理方案…"));
    m_ai->generateCleanupScript(m_report);
    syncNav();
}

void AiCleanupDialog::onScriptReady(const QString& script)
{
    if (!m_awaiting) // 忽略由其它对话框触发的同名信号(共享同一个 AiScanner)
        return;
    m_awaiting = false;

    if (script.isEmpty()) {
        m_genStatus->setStyleSheet(QStringLiteral("color:%1;").arg(theme::danger().name()));
        m_genStatus->setText(u("AI 生成失败(网络 / 模型不可用或返回为空),请稍后点「重新生成」。"));
        syncNav();
        return;
    }
    m_hasScript = true;
    m_genStatus->setStyleSheet(QStringLiteral("color:%1;").arg(theme::success().name()));
    m_genStatus->setText(u("方案已生成。请逐行复核,确认无误后进入下一步执行。"));
    m_scriptView->setPlainText(script);
    m_copy->setText(u("复制脚本"));
    syncNav();
}

void AiCleanupDialog::executeScript()
{
    const QString script = m_scriptView->toPlainText().trimmed();
    if (script.isEmpty() || !m_ack || !m_ack->isChecked())
        return;
    if (runElevatedScript(script)) {
        m_launched = true;
        m_runStatus->setStyleSheet(QStringLiteral("color:%1;").arg(theme::success().name()));
        m_runStatus->setText(u("已启动清理:请在弹出的 UAC 中确认,然后在 PowerShell 窗口里查看每一步结果。"));
    } else {
        m_runStatus->setStyleSheet(QStringLiteral("color:%1;").arg(theme::danger().name()));
        m_runStatus->setText(u("无法启动清理进程(PowerShell 不可用或被拦截)。可回到上一步复制脚本手动执行。"));
    }
    syncNav();
    refit();
}
