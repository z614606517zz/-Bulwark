#include "dialogs/ProcessDetailDialog.h"
#include "dialogs/EventFormat.h"
#include "ipc/IpcClient.h"
#include "widgets/AppIcon.h"
#include "widgets/Cards.h"
#include "widgets/Ui.h"
#include "Theme.h"

#include <QDir>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLocale>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

using evtfmt::u;

namespace {

QVBoxLayout* sectionCard(QVBoxLayout* parent, const QString& title)
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(18, 15, 18, 15);
    v->setSpacing(8);
    v->addWidget(ui::label(title, "h2"));
    v->addWidget(ui::hDivider());
    parent->addWidget(c);
    return v;
}

QWidget* row(const QString& caption, const QString& value, bool mono = false)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 2, 0, 2);
    h->setSpacing(12);
    auto* cap = ui::label(caption, "caption");
    cap->setFixedWidth(96);
    h->addWidget(cap, 0, Qt::AlignTop);
    auto* val = ui::label(value.isEmpty() ? u("—") : value, mono ? "mono" : "secondary");
    val->setWordWrap(true);
    val->setTextInteractionFlags(Qt::TextSelectableByMouse);
    h->addWidget(val, 1);
    return w;
}

QString humanBytes(qint64 bytes)
{
    if (bytes <= 0)
        return QString();
    return QLocale().formattedDataSize(bytes, 1, QLocale::DataSizeTraditionalFormat);
}

} // namespace

ProcessDetailDialog::ProcessDetailDialog(const bulwark::ProcessEntry& e, IpcClient* ipc,
                                        QWidget* parent)
    : QDialog(parent), m_ipc(ipc), m_pid(e.pid)
{
    setWindowTitle(u("进程详情 · %1").arg(e.name));
    setModal(true);
    resize(660, 700);

    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);

    // ---- 头部 ----
    auto* head = new QFrame;
    head->setObjectName(QStringLiteral("Topbar"));
    auto* hh = new QHBoxLayout(head);
    hh->setContentsMargins(20, 16, 20, 16);
    hh->setSpacing(14);
    const QColor accent = e.isTrusted ? theme::success() : evtfmt::riskColor(e.riskScore);
    hh->addWidget(ui::iconBadge("target", accent, 46, 24));
    auto* hcol = new QVBoxLayout;
    hcol->setSpacing(2);
    hcol->addWidget(ui::coloredText(e.name.isEmpty() ? u("未知进程") : e.name, 15, 700,
                                    theme::textPrimary()));
    QStringList sub;
    sub << QStringLiteral("PID %1").arg(e.pid);
    if (!e.fileDescription.isEmpty()) sub << e.fileDescription;
    if (!e.originLabel().isEmpty()) sub << e.originLabel();
    hcol->addWidget(ui::label(sub.join(u("  ·  ")), "secondary"));
    hh->addLayout(hcol);
    hh->addStretch();
    auto* pills = new QHBoxLayout;
    pills->setSpacing(6);
    if (e.isTrusted)        pills->addWidget(ui::pill(u("已信任"), theme::success()));
    if (e.isProtectedSelf)  pills->addWidget(ui::pill(u("本软件组件"), theme::info()));
    if (e.isCritical)       pills->addWidget(ui::pill(u("关键系统进程"), theme::info()));
    if (!e.isTrusted && e.riskScore > 0)
        pills->addWidget(ui::pill(u("提示分 %1").arg(e.riskScore), accent));
    auto* pw = new QWidget;
    pw->setLayout(pills);
    hh->addWidget(pw, 0, Qt::AlignTop);
    outer->addWidget(head);

    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    outer->addWidget(scroll, 1);
    auto* content = new QWidget;
    scroll->setWidget(content);
    auto* v = new QVBoxLayout(content);
    v->setContentsMargins(20, 18, 20, 18);
    v->setSpacing(14);

    // ---- 启动来源(本页最有价值的一块:把 svchost / 任务宿主还原成具体实体)----
    {
        auto* box = sectionCard(v, u("启动来源溯源"));
        box->addWidget(row(u("判定"), e.originLabel().isEmpty()
                                          ? u("未能判定(父进程为普通进程)")
                                          : e.originLabel()));
        if (!e.originService.isEmpty())
            box->addWidget(row(u("服务名"), e.originService, true));
        if (!e.originServiceDisplay.isEmpty())
            box->addWidget(row(u("服务显示名"), e.originServiceDisplay));
        if (!e.originTask.isEmpty())
            box->addWidget(row(u("计划任务"), e.originTask, true));
        box->addWidget(row(u("依据"), e.originDetail));
        box->addWidget(row(u("父进程"),
                           e.parentPid > 0
                               ? QStringLiteral("%1 (PID %2)")
                                     .arg(e.parentName.isEmpty() ? u("未知") : e.parentName)
                                     .arg(e.parentPid)
                               : QString()));
    }

    // ---- 身份 ----
    {
        auto* box = sectionCard(v, u("身份与签名"));
        box->addWidget(row(u("映像路径"), QDir::toNativeSeparators(e.imagePath), true));
        box->addWidget(row(u("文件描述"), e.fileDescription));
        box->addWidget(row(u("数字签名"),
                           e.isSigned
                               ? (e.publisher.isEmpty() ? u("有效") : u("有效 · ") + e.publisher)
                               : (e.signatureMismatch ? u("签名失配(内嵌但校验失败)")
                                                      : u("无 / 无效"))));
        if (!e.commandLine.isEmpty())
            box->addWidget(row(u("命令行"), e.commandLine, true));

        auto* hashRow = new QWidget;
        auto* hl = new QHBoxLayout(hashRow);
        hl->setContentsMargins(0, 2, 0, 2);
        hl->setSpacing(12);
        auto* cap = ui::label(u("SHA-256"), "caption");
        cap->setFixedWidth(96);
        hl->addWidget(cap, 0, Qt::AlignTop);
        m_hashValue = ui::label(e.sha256.isEmpty() ? u("未计算") : e.sha256,
                                e.sha256.isEmpty() ? "muted" : "mono");
        m_hashValue->setWordWrap(true);
        m_hashValue->setTextInteractionFlags(Qt::TextSelectableByMouse);
        hl->addWidget(m_hashValue, 1);
        auto* calc = new QPushButton(u("计算"));
        calc->setProperty("variant", "ghost");
        calc->setProperty("size", "sm");
        calc->setCursor(Qt::PointingHandCursor);
        calc->setEnabled(m_ipc && !e.imagePath.isEmpty());
        hl->addWidget(calc, 0, Qt::AlignTop);
        box->addWidget(hashRow);

        const QString imagePath = e.imagePath;
        connect(calc, &QPushButton::clicked, this, [this, calc, imagePath] {
            if (!m_ipc || !m_ipc->isConnected()) {
                m_hashValue->setText(u("未连接服务,无法计算"));
                return;
            }
            calc->setEnabled(false);
            m_hashValue->setText(u("计算中…"));
            bulwark::ipc::ProcessActionRequestPayload p;
            p.kind = bulwark::ipc::ProcessActionKind::ComputeHash;
            p.pid = m_pid;
            p.imagePath = imagePath;
            m_ipc->processAction(p);
        });
        if (m_ipc) {
            connect(m_ipc, &IpcClient::processActionResult, this,
                    [this](const bulwark::ipc::ProcessActionResultPayload& r) {
                        if (r.kind != bulwark::ipc::ProcessActionKind::ComputeHash || r.pid != m_pid)
                            return;
                        m_hashValue->setProperty("role", r.success ? "mono" : "muted");
                        m_hashValue->setText(r.success ? r.sha256 : r.message);
                    });
        }
    }

    // ---- 运行态 ----
    {
        auto* box = sectionCard(v, u("运行状态"));
        box->addWidget(row(u("启动时间"),
                           e.startTimeUtc.isValid()
                               ? e.startTimeUtc.toLocalTime().toString(
                                     QStringLiteral("yyyy-MM-dd HH:mm:ss"))
                               : QString()));
        box->addWidget(row(u("运行用户"), e.userName));
        box->addWidget(row(u("内存占用"), humanBytes(e.workingSetBytes)));
        box->addWidget(row(u("线程数"), e.threadCount > 0 ? QString::number(e.threadCount) : QString()));
        box->addWidget(row(u("会话 / 位数"),
                           QStringLiteral("%1  ·  %2")
                               .arg(e.sessionId)
                               .arg(e.is64Bit ? QStringLiteral("64 位") : QStringLiteral("32 位"))));
        box->addWidget(row(u("完整性"), e.elevated ? u("高(已提权)") : u("普通")));
    }

    // ---- 静态提示(只读,不代表判定)----
    if (!e.riskReasons.isEmpty()) {
        auto* box = sectionCard(v, u("静态提示(仅供参考,非判定结论)"));
        for (const QString& r : e.riskReasons) {
            auto* l = ui::label(QStringLiteral("· ") + r, "secondary");
            l->setWordWrap(true);
            box->addWidget(l);
        }
        auto* note = ui::label(
            u("这些是静态特征提示,单独出现【不构成】恶意判定,也不会触发任何自动处置。"
              "真正的裁决只由行为规则与威胁检测在事件发生时给出。"),
            "muted");
        note->setWordWrap(true);
        box->addWidget(note);
    }

    v->addStretch();

    auto* bar = new QHBoxLayout;
    bar->setContentsMargins(20, 0, 20, 16);
    bar->addStretch();
    auto* close = new QPushButton(u("关闭"));
    close->setProperty("variant", "primary");
    close->setCursor(Qt::PointingHandCursor);
    connect(close, &QPushButton::clicked, this, &QDialog::accept);
    bar->addWidget(close);
    outer->addLayout(bar);
}
