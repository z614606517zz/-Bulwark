#include "dialogs/AttackChainDetailDialog.h"
#include "dialogs/EventFormat.h"
#include "widgets/AppIcon.h"
#include "widgets/Cards.h"
#include "widgets/Ui.h"
#include "Theme.h"

#include <QDir>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QHash>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

using evtfmt::u;

namespace {

// 与 ProcessDetailDialog 同名同形的两个版式助手 —— 刻意逐字沿用,保证两个详情弹窗
// 的分组卡与行距完全一致。
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

// 服务端回的是 eventTypeToString() 的英文枚举名;转成 evtfmt::typeLabel 的同一套中文,
// 免得同一个事件类型在弹窗里和别处叫法不同。
QString eventLabel(const QString& raw)
{
    using E = bulwark::EventType;
    static const QHash<QString, E> map = {
        {QStringLiteral("ProcessCreate"),    E::ProcessCreate},
        {QStringLiteral("ProcessTerminate"), E::ProcessTerminate},
        {QStringLiteral("RemoteThread"),     E::RemoteThread},
        {QStringLiteral("ImageLoad"),        E::ImageLoad},
        {QStringLiteral("FileWrite"),        E::FileWrite},
        {QStringLiteral("FileDelete"),       E::FileDelete},
        {QStringLiteral("RegistryWrite"),    E::RegistryWrite},
        {QStringLiteral("NetworkConnect"),   E::NetworkConnect},
        {QStringLiteral("SelfProtect"),      E::SelfProtect},
        {QStringLiteral("DnsQuery"),         E::DnsQuery},
    };
    const auto it = map.constFind(raw);
    return it == map.constEnd() ? raw : evtfmt::typeLabel(*it);
}

// 组合强度:hard 是「仅此一条即可定性」,ask 只是「值得问一句」。
QColor gradeColor(const QString& g)
{
    if (g == QLatin1String("hard"))   return theme::danger();
    if (g == QLatin1String("strong")) return theme::warning();
    return theme::info();
}

QString gradeLabel(const QString& g)
{
    if (g == QLatin1String("hard"))   return u("确定恶意");
    if (g == QLatin1String("strong")) return u("高度可疑");
    if (g == QLatin1String("ask"))    return u("需询问");
    return g;
}

QColor levelColor(const QString& lv)
{
    if (lv == QLatin1String("critical")) return theme::danger();
    if (lv == QLatin1String("high"))     return theme::warning();
    return theme::info();
}

} // namespace

AttackChainDetailDialog::AttackChainDetailDialog(const bulwark::ipc::AttackChainHitPayload& hit,
                                                 QWidget* parent)
    : QDialog(parent)
{
    const QString nativePath = QDir::toNativeSeparators(hit.actorPath);
    const QString fileName = QFileInfo(nativePath).fileName();
    setWindowTitle(u("攻击链命中 · %1").arg(fileName.isEmpty() ? u("未知主体") : fileName));
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
    const QColor accent = gradeColor(hit.grade);
    hh->addWidget(ui::iconBadge("link", accent, 46, 24));
    auto* hcol = new QVBoxLayout;
    hcol->setSpacing(2);
    hcol->addWidget(ui::coloredText(fileName.isEmpty() ? u("未知主体") : fileName, 15, 700,
                                    theme::textPrimary()));
    QStringList sub;
    if (hit.actorPid > 0)
        sub << QStringLiteral("PID %1").arg(hit.actorPid);
    if (!hit.eventType.isEmpty())
        sub << eventLabel(hit.eventType);
    if (hit.whenUtc.isValid())
        sub << hit.whenUtc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    hcol->addWidget(ui::label(sub.join(u("  ·  ")), "secondary"));
    hh->addLayout(hcol);
    hh->addStretch();
    auto* pills = new QHBoxLayout;
    pills->setSpacing(6);
    if (!hit.grade.isEmpty())
        pills->addWidget(ui::pill(gradeLabel(hit.grade), accent));
    if (!hit.maxLevel.isEmpty())
        pills->addWidget(ui::pill(hit.maxLevel, levelColor(hit.maxLevel)));
    if (hit.dryRun)
        pills->addWidget(ui::pill(u("只记录不拦截"), theme::warning()));
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

    // ---- 凑齐的动作(本页最有价值的一块:说清「为什么这堆行为放一起才算恶意」)----
    {
        auto* box = sectionCard(v, u("凑齐的动作(%1 个)").arg(hit.titles.size()));
        for (int i = 0; i < hit.titles.size(); ++i) {
            auto* line = new QWidget;
            auto* lh = new QHBoxLayout(line);
            lh->setContentsMargins(0, 2, 0, 2);
            lh->setSpacing(10);
            auto* idx = ui::coloredText(QString::number(i + 1), 10, 700, accent);
            idx->setFixedWidth(16);
            lh->addWidget(idx, 0, Qt::AlignTop);
            auto* t = ui::label(hit.titles.at(i), "secondary");
            t->setWordWrap(true);
            t->setTextInteractionFlags(Qt::TextSelectableByMouse);
            lh->addWidget(t, 1);
            box->addWidget(line);
        }
        auto* note = ui::label(
            u("这些动作出现在【同一个进程】上才算凑齐。单独任何一个都只是软信号,"
              "不构成判定 —— 组合本身就是互证。"),
            "muted");
        note->setWordWrap(true);
        box->addWidget(note);
    }

    // ---- 判定依据 ----
    {
        auto* box = sectionCard(v, u("判定依据"));
        box->addWidget(row(u("强度"), hit.grade.isEmpty()
                                         ? QString()
                                         : u("%1(%2)").arg(gradeLabel(hit.grade), hit.grade)));
        box->addWidget(row(u("严重度"), hit.maxLevel));
        box->addWidget(row(u("样本作证"),
                           hit.support > 0
                               ? u("%1 个真实恶意样本同时具备上述动作组合").arg(hit.support)
                               : QString()));
        box->addWidget(row(u("常见家族"), hit.families));
        auto* note = ui::label(
            u("组合表由服务器从每日采集的真实样本沙箱记录里挖出,样本数越多说明该组合越可靠。"),
            "muted");
        note->setWordWrap(true);
        box->addWidget(note);
    }

    // ---- 主体 ----
    {
        auto* box = sectionCard(v, u("主体"));
        box->addWidget(row(u("映像路径"), nativePath, true));
        box->addWidget(row(u("PID"), hit.actorPid > 0 ? QString::number(hit.actorPid) : QString(),
                           true));
        box->addWidget(row(u("触发事件"), eventLabel(hit.eventType)));
        box->addWidget(row(u("命中时间"),
                           hit.whenUtc.isValid()
                               ? hit.whenUtc.toLocalTime().toString(
                                     QStringLiteral("yyyy-MM-dd HH:mm:ss"))
                               : QString()));
    }

    // ---- 最终裁决 ----
    {
        auto* box = sectionCard(v, u("最终裁决"));
        QString verdict = hit.action;
        if (hit.action == QLatin1String("Block"))      verdict = u("已拦截");
        else if (hit.action == QLatin1String("Ask"))   verdict = u("已询问");
        else if (hit.action == QLatin1String("Allow")) verdict = u("已放行");
        box->addWidget(row(u("处置"), verdict));
        // dry-run 必须说清:命中不参与裁决,上面的处置来自流水线其他环节。不讲明白会被
        // 误读成「这条组合把它放过了」。
        auto* note = ui::label(
            hit.dryRun
                ? u("命中时引擎为「只记录不拦截」,本次命中【未参与】裁决 —— 上面的处置由其他"
                    "检测环节得出,与这条组合无关。")
                : u("命中已作为硬指标进入裁决流水线。但用户信任 / 本软件自身组件 / 已装第三方"
                    "杀软这几条放行通道位于本引擎之前,命中它们时仍会放行。"),
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
