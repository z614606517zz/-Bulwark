#include "dialogs/ToastNotifier.h"
#include "dialogs/ToastWindow.h"

#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <QFileInfo>
#include <QGuiApplication>
#include <QScreen>

using bulwark::SecurityEvent;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

// Short human verb for an event type — mirrors the phrasing used by the
// behavior prompt so the toast reads consistently with the rest of the UI.
QString actionVerb(bulwark::EventType t)
{
    using bulwark::EventType;
    switch (t) {
    case EventType::ProcessCreate:    return u("创建进程");
    case EventType::ProcessTerminate: return u("结束进程");
    case EventType::RemoteThread:     return u("注入远程线程");
    case EventType::ImageLoad:        return u("加载模块 / 驱动");
    case EventType::FileWrite:        return u("写入 / 修改文件");
    case EventType::FileDelete:       return u("删除文件");
    case EventType::RegistryWrite:    return u("写入注册表");
    case EventType::NetworkConnect:   return u("网络外联");
    case EventType::SelfProtect:      return u("触发自我保护");
    case EventType::DnsQuery:         return u("发起 DNS 解析");
    }
    return u("敏感行为");
}

QString actorName(const SecurityEvent& e)
{
    const QString name = QFileInfo(e.actorPath).fileName();
    return name.isEmpty() ? u("未知程序") : name;
}

} // namespace

ToastNotifier::ToastNotifier(QObject* parent) : QObject(parent) {}

void ToastNotifier::showBlock(const SecurityEvent& e)
{
    QString program = actorName(e);
    if (e.actorPid > 0)
        program += QStringLiteral(" (PID %1)").arg(e.actorPid);

    // 来源 = why it was blocked: the matched rule note, else the top risk reason.
    QString source = e.matchedRuleNote.trimmed();
    if (source.isEmpty() && !e.riskReasons.isEmpty())
        source = e.riskReasons.first();
    if (source.isEmpty())
        source = u("命中高危行为规则");

    const QString target = e.target.isEmpty() ? e.actorPath : e.target;

    const QList<ToastField> fields = {
        {u("来源"), source},
        {u("程序"), program},
        {u("行为"), actionVerb(e.type)},
        {u("目标"), target},
    };
    auto* t = new ToastWindow(ToastWindow::Kind::Block,
                              u("已拦截危险行为"),
                              u("磐垒已自动处置,无需手动操作"),
                              QString(), // structured fields carry the detail
                              fields,
                              e.techniques,
                              8000);
    present(t, /*isBlock=*/true);
}

void ToastNotifier::showAiScan(const SecurityEvent& e)
{
    auto* t = new ToastWindow(ToastWindow::Kind::AiScan,
                              u("AI 安全研判中"),
                              actorName(e),                          // subtitle = program name
                              u("正在对该程序进行大模型行为研判…"),   // detail line
                              {},                                     // no structured fields
                              e.techniques,
                              5000);
    present(t, /*isBlock=*/false);
}

void ToastNotifier::showInfo(const QString& heading, const QString& detail)
{
    auto* t = new ToastWindow(ToastWindow::Kind::Info, heading, QString(), detail,
                              {}, {}, 5000);
    present(t, /*isBlock=*/false);
}

void ToastNotifier::present(ToastWindow* toast, bool isBlock)
{
    connect(toast, &ToastWindow::closed, this, &ToastNotifier::remove);
    if (isBlock)
        connect(toast, &ToastWindow::clicked, this,
                [this](ToastWindow*) { emit blockToastClicked(); });

    m_stack.prepend(toast);

    // Cap the visible stack; retire the oldest surplus toasts immediately.
    while (m_stack.size() > kMaxVisible)
        m_stack.takeLast()->deleteLater();

    reflow();
}

void ToastNotifier::reflow()
{
    QScreen* screen = QGuiApplication::primaryScreen();
    if (!screen)
        return;
    const QRect area = screen->availableGeometry();
    const int margin = 22;
    const int gap = 12;

    int baselineBottom = area.bottom() - margin;
    for (ToastWindow* t : m_stack) {
        const int x = area.right() - margin - t->width();
        const int top = baselineBottom - t->height();
        t->place(QPoint(x, top));
        baselineBottom = top - gap;
    }
}

void ToastNotifier::remove(ToastWindow* toast)
{
    m_stack.removeAll(toast);
    reflow();
}
