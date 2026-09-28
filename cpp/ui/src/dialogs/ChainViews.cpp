#include "dialogs/ChainViews.h"
#include "dialogs/AttackChainDetailDialog.h"
#include "dialogs/EventViews.h"
#include "design/Components.h"
#include "design/Format.h"
#include "design/Icons.h"
#include "design/Inspector.h"
#include "design/Theme.h"
#include "widgets/WrapLabel.h"
#include "Nav.h"

#include <QHash>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPainter>
#include <QRegularExpression>
#include <QVBoxLayout>

using evtfmt::u;

namespace {

// "①"-style step number in the grade colour.
class StepNumber : public QWidget
{
public:
    StepNumber(int n, const QColor& color) : m_n(n), m_color(color) { setFixedSize(22, 22); }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(QPen(theme::blend(m_color, theme::surface(), 0.55), 1.2));
        p.setBrush(theme::blend(m_color, theme::surface(), 0.16));
        p.drawEllipse(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5));
        QFont f = font();
        f.setPointSizeF(8.5);
        f.setBold(true);
        p.setFont(f);
        p.setPen(m_color);
        p.drawText(rect(), Qt::AlignCenter, QString::number(m_n));
    }

private:
    int m_n;
    QColor m_color;
};

// The actions that together made the combination, as numbered steps joined by "+".
QWidget* stepCards(const bulwark::ipc::AttackChainHitPayload& h)
{
    auto* panel = ui::cardAlt();
    auto* v = new QVBoxLayout(panel);
    v->setContentsMargins(12, 10, 12, 10);
    v->setSpacing(4);
    const QColor c = chainview::gradeColor(h.grade);
    for (int i = 0; i < h.titles.size(); ++i) {
        if (i > 0) {
            auto* plus = ui::label(QStringLiteral("+"), "muted");
            plus->setContentsMargins(6, 0, 0, 0);
            v->addWidget(plus);
        }
        auto* row = new QHBoxLayout;
        row->setSpacing(10);
        row->addWidget(new StepNumber(i + 1, c), 0, Qt::AlignTop);
        row->addWidget(new WrapLabel(h.titles.at(i)), 1);
        v->addLayout(row);
    }
    if (h.titles.isEmpty())
        v->addWidget(ui::label(u("服务端没有给出组合里的动作名。"), "muted"));
    return panel;
}

QString actorName(const bulwark::ipc::AttackChainHitPayload& h)
{
    return evtfmt::actorName(h.actorPath);
}

} // namespace

namespace chainview {

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
    return g.isEmpty() ? u("未分级") : g;
}

QColor levelColor(const QString& lv)
{
    if (lv == QLatin1String("critical")) return theme::danger();
    if (lv == QLatin1String("high"))     return theme::warning();
    return theme::info();
}

QString levelLabel(const QString& lv)
{
    if (lv == QLatin1String("critical")) return u("严重");
    if (lv == QLatin1String("high"))     return u("高");
    if (lv == QLatin1String("medium"))   return u("中");
    return lv;
}

evtfmt::Badge verdict(const QString& action)
{
    if (action == QLatin1String("Block")) return {u("判为拦截"), theme::danger()};
    if (action == QLatin1String("Ask"))   return {u("已询问"), theme::warning()};
    if (action == QLatin1String("Allow")) return {u("已放行"), theme::success()};
    return {action.isEmpty() ? u("—") : action, theme::textMuted()};
}

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

QString keyOf(const bulwark::ipc::AttackChainHitPayload& h)
{
    return QStringLiteral("%1|%2|%3").arg(h.whenUtc.toMSecsSinceEpoch()).arg(h.actorPid).arg(h.titles.join(QLatin1Char('+')));
}

RecordView recordView(const bulwark::ipc::AttackChainHitPayload& h)
{
    RecordView v;
    const QColor c = gradeColor(h.grade);
    v.icon = QStringLiteral("link");
    v.iconColor = c;
    v.title = actorName(h) + u(" · ") + (h.titles.isEmpty() ? gradeLabel(h.grade) : u("凑齐 %1 个动作").arg(h.titles.size()));
    v.subtitle = h.titles.join(u(" + "));
    // The grade chip states the row's status and wears it. The malware families
    // are plain facts, and "只记录" is already said once, in the warning colour, by
    // the page's status strip — repeated in amber on every row it would only shout.
    v.chips << gradeLabel(h.grade);
    v.chipColors << c;
    static const QRegularExpression sep(u("[,,、;]\\s*"));
    const QStringList fam = h.families.split(sep, Qt::SkipEmptyParts);
    for (int i = 0; i < fam.size() && i < 2; ++i) {
        v.chips << fam.at(i).trimmed();
        v.chipColors << QColor();
    }
    if (h.dryRun)
        v.chips << u("只记录");
    const evtfmt::Badge b = verdict(h.action);
    v.pill = b.text;
    v.pillColor = b.color;
    v.time = h.whenUtc;
    v.accent = h.grade == QLatin1String("hard") ? c : QColor();
    v.tooltip = evtfmt::nativePath(h.actorPath) + u("\n") + fmt::absoluteTime(h.whenUtc);
    v.haystack = QStringList{h.actorPath, h.titles.join(QLatin1Char(' ')), h.families, gradeLabel(h.grade),
                             levelLabel(h.maxLevel), QString::number(h.actorPid), eventLabel(h.eventType), b.text}
                     .join(QLatin1Char(' '));
    v.key = keyOf(h);
    return v;
}

void fill(Inspector* in, const bulwark::ipc::AttackChainHitPayload& h, IpcClient* ipc, bool withWindow)
{
    const QColor c = gradeColor(h.grade);
    QStringList sub;
    if (h.actorPid > 0)
        sub << QStringLiteral("PID %1").arg(h.actorPid);
    if (!h.eventType.isEmpty())
        sub << eventLabel(h.eventType);
    sub << fmt::absoluteTime(h.whenUtc);
    in->setHeader(QStringLiteral("link"), c, actorName(h), sub.join(u(" · ")));
    QString lead = u("%1 在同一个进程上凑齐了 %2 个动作").arg(actorName(h)).arg(h.titles.size());
    lead += h.support > 0 ? u(",与 %1 个真实恶意样本的行为组合一致。").arg(h.support) : u("。");
    in->addLead(lead);
    QList<QPair<QString, QColor>> chips;
    chips << qMakePair(gradeLabel(h.grade), c);
    if (!h.maxLevel.isEmpty())
        chips << qMakePair(u("严重度 ") + levelLabel(h.maxLevel), levelColor(h.maxLevel));
    if (h.dryRun)
        chips << qMakePair(u("只记录不拦截"), theme::warning());
    const evtfmt::Badge b = verdict(h.action);
    chips << qMakePair(b.text, b.color);
    in->addChips(nullptr, chips);

    QVBoxLayout* s = in->addSection(u("凑齐的动作"));
    s->addWidget(stepCards(h));
    in->addText(s,
                u("这些动作出现在同一个进程上才算凑齐。单独任何一个都只是软信号,不构成判定 —— 组合本身就是互证。"),
                "muted");

    s = in->addSection(u("判定依据"));
    in->addField(s, u("强度"), h.grade.isEmpty() ? QString() : u("%1(%2)").arg(gradeLabel(h.grade), h.grade));
    in->addField(s, u("严重度"), levelLabel(h.maxLevel));
    in->addField(s, u("样本作证"), h.support > 0 ? u("%1 个真实恶意样本同时具备这组动作").arg(h.support) : QString());
    in->addField(s, u("常见家族"), h.families);
    in->addText(s, u("组合表由服务器从每日采集的真实样本沙箱记录里挖出,作证的样本越多,组合越可靠。"), "muted");

    s = in->addSection(u("主体"));
    in->addField(s, u("映像路径"), evtfmt::nativePath(h.actorPath), Inspector::Mono | Inspector::Copy);
    in->addField(s, QStringLiteral("PID"), h.actorPid > 0 ? QString::number(h.actorPid) : QString(), Inspector::Mono);
    in->addField(s, u("触发事件"), eventLabel(h.eventType));
    in->addField(s, u("命中时间"), fmt::absoluteTime(h.whenUtc));

    s = in->addSection(u("最终裁决"));
    in->addField(s, u("裁决"), b.text);
    in->addText(s,
                h.dryRun ? u("命中时引擎为「只记录不拦截」,这次命中没有参与裁决 —— 上面的裁决由其他检测环节得出,"
                             "与这条组合无关。")
                         : u("命中已作为硬指标进入裁决流水线。但本软件组件、用户信任与已安装的安全软件这几条放行通道"
                             "位于本引擎之前,命中它们时仍会放行。"),
                "muted");
    in->addText(s, u("这里是裁决;是否真的拦住,以该事件在「事件记录」里的处置结果为准。"), "muted");

    if (h.actorPid > 0) {
        const bulwark::ipc::AttackChainHitPayload hit = h;
        in->addAction(QStringLiteral("link"), u("关系图"), "ghost",
                      [in, ipc, hit] { evtview::openGraph(in, ipc, QUuid(), hit.actorPid, actorName(hit)); });
        in->addAction(QStringLiteral("activity"), u("时间线"), "ghost", [pid = h.actorPid] {
            nav::go(QString::fromLatin1(nav::Timeline),
                    {{QStringLiteral("pid"), pid}, {QStringLiteral("range"), QStringLiteral("24h")}});
        });
    }
    auto* menu = new QMenu;
    fillMenu(menu, in, h, ipc, withWindow);
    in->addMenu(menu);
}

void fillMenu(QMenu* menu, QWidget* context, const bulwark::ipc::AttackChainHitPayload& h, IpcClient* ipc,
              bool withWindow)
{
    const QColor ic = theme::textSecondary();
    const bulwark::ipc::AttackChainHitPayload hit = h;
    if (withWindow)
        QObject::connect(menu->addAction(AppIcon::icon(QStringLiteral("maximize"), ic, 16), u("在独立窗口中查看")),
                         &QAction::triggered, context, [context, hit, ipc] { openDetail(context, hit, ipc); });
    if (h.actorPid > 0)
        QObject::connect(menu->addAction(AppIcon::icon(QStringLiteral("link"), ic, 16), u("查看攻击关系图")),
                         &QAction::triggered, context, [context, hit, ipc] {
                             evtview::openGraph(context, ipc, QUuid(), hit.actorPid, actorName(hit));
                         });
    if (!h.actorPath.isEmpty())
        QObject::connect(menu->addAction(AppIcon::icon(QStringLiteral("copy"), ic, 16), u("复制主体路径")),
                         &QAction::triggered, context, [p = evtfmt::nativePath(h.actorPath)] {
                             if (QClipboard* cb = QGuiApplication::clipboard())
                                 cb->setText(p);
                         });
}

void openDetail(QWidget* parent, const bulwark::ipc::AttackChainHitPayload& h, IpcClient* ipc)
{
    auto* dlg = new AttackChainDetailDialog(h, parent ? parent->window() : nullptr, ipc);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->show();
}

} // namespace chainview
