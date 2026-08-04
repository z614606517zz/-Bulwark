#include "dialogs/ToastNotifier.h"
#include "dialogs/ToastWindow.h"

#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <QDateTime>
#include <QFileInfo>
#include <QGuiApplication>
#include <QScreen>
#include <QTimer>

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

ToastNotifier::ToastNotifier(QObject* parent) : QObject(parent)
{
    // 合并定时器:高频拦截被限流后,每秒汇成一条「又拦截 N 项」摘要 toast(而非逐条建窗)。
    m_coalesceTimer = new QTimer(this);
    m_coalesceTimer->setInterval(1000);
    m_coalesceTimer->setSingleShot(true);
    connect(m_coalesceTimer, &QTimer::timeout, this, [this] {
        flushSuppressed();
        if (m_suppressedBlocks > 0) // 期间又有积压:继续下一轮合并
            m_coalesceTimer->start();
    });
}

void ToastNotifier::showAttackChain(const bulwark::ipc::AttackChainHitPayload& hit)
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();

    // 去重键 = 主体路径 + 组合内容。同一程序反复命中【同一组合】在窗口期内只提示一次 ——
    // 实测 kiro-account-manager\svchost.exe 三分钟内命中两次,逐条弹是纯噪音。
    // 但换了组合(说明是新的行为链)仍会提示,不会被压掉。
    // 与拦截那套键分开:拦截按「程序+行为+目标」,攻击链的目标每次可能不同、组合才是身份。
    const QString key = QStringLiteral("chain|") + hit.actorPath + QLatin1Char('|')
                      + hit.titles.join(QLatin1Char('+'));
    auto it = m_recentBlockKeys.find(key);
    if (it != m_recentBlockKeys.end() && now - it.value() < kChainDedupWindowMs) {
        it.value() = now;
        return;
    }
    m_recentBlockKeys.insert(key, now);
    pruneRecentKeys(now);

    QString program = QFileInfo(hit.actorPath).fileName();
    if (program.isEmpty())
        program = hit.actorPath.isEmpty() ? u("未知程序") : hit.actorPath;
    if (hit.actorPid > 0)
        program += QStringLiteral(" (PID %1)").arg(hit.actorPid);

    // 处置如实写。dry-run 时明确标出「仅记录」,否则用户会以为已经处理了。
    const QString act = hit.dryRun
        ? u("仅记录")
        : (hit.action == QLatin1String("Block") ? u("已拦截")
         : hit.action == QLatin1String("Ask")   ? u("已询问")
                                                : u("已放行"));

    const QString gradeCn = hit.grade == QLatin1String("hard")   ? u("可直接拦断")
                          : hit.grade == QLatin1String("strong") ? u("阻断或强提示")
                                                                : u("弹窗询问");

    QList<ToastField> fields;
    fields << ToastField{u("程序"), program};
    // 动作链是这条通知的主体信息 —— 它回答「凭什么定性」,而不只是「拦了谁」。
    fields << ToastField{u("动作链"), hit.titles.join(u(" ＋ "))};
    if (!hit.families.trimmed().isEmpty())
        fields << ToastField{u("常见家族"), hit.families};

    const QString subtitle = u("%1 个恶意样本作证 · 强度「%2」")
                                 .arg(hit.support).arg(gradeCn);

    // 存活期比拦截 toast 更长:动作链常有两三个动作名要读完。悬停会暂停倒计时(ToastWindow 已有)。
    auto* t = new ToastWindow(ToastWindow::Kind::AttackChain, u("攻击链组合命中"), subtitle,
                              QString(), fields, QStringList(), kChainLifetimeMs, nullptr, act);
    connect(t, &ToastWindow::clicked, this, [this](ToastWindow*) {
        emit attackChainToastClicked();
    });
    present(t, /*isBlock=*/false);
}

void ToastNotifier::showBlock(const SecurityEvent& e)
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();

    // 去重(B):同一威胁 = 同程序 + 同行为 + 同目标。窗口期内只弹一次,重试/循环触发不再刷屏。
    const QString key = e.actorPath + QLatin1Char('|')
                      + QString::number(static_cast<int>(e.type)) + QLatin1Char('|') + e.target;
    auto it = m_recentBlockKeys.find(key);
    if (it != m_recentBlockKeys.end() && now - it.value() < kDedupWindowMs) {
        it.value() = now;   // 刷新时间戳,持续压制重复提示
        return;
    }
    m_recentBlockKeys.insert(key, now);
    pruneRecentKeys(now);

    // 限流合并(C):不同威胁短时间大量涌入(拦截风暴)时不逐条建窗(会卡死 UI)——超过最小间隔的
    // 拦截只累加计数,由合并定时器每秒汇成一条摘要 toast。完整记录仍进拦截表 / 日志,不丢信息。
    if (now - m_lastBlockToastMs < kMinBlockGapMs) {
        ++m_suppressedBlocks;
        if (m_coalesceTimer && !m_coalesceTimer->isActive())
            m_coalesceTimer->start();
        return;
    }
    m_lastBlockToastMs = now;

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

// 把被限流压制掉的拦截汇成一条摘要 toast(点击可跳到拦截记录)。
void ToastNotifier::flushSuppressed()
{
    if (m_suppressedBlocks <= 0)
        return;
    const int n = m_suppressedBlocks;
    m_suppressedBlocks = 0;
    m_lastBlockToastMs = QDateTime::currentMSecsSinceEpoch();
    auto* t = new ToastWindow(ToastWindow::Kind::Block,
                              u("已批量拦截危险行为"),
                              u("磐垒已自动处置,无需手动操作"),
                              u("短时间内共拦截 ") + QString::number(n) + u(" 项(点击查看拦截记录)"),
                              {}, {}, 6000);
    present(t, /*isBlock=*/true);
}

// 去重键集合的有界维护:平时不清(省开销),超阈值才清过期键;极端风暴再兜底整体清空。
void ToastNotifier::pruneRecentKeys(qint64 nowMs)
{
    if (m_recentBlockKeys.size() <= 512)
        return;
    for (auto it = m_recentBlockKeys.begin(); it != m_recentBlockKeys.end(); ) {
        if (nowMs - it.value() > kDedupWindowMs)
            it = m_recentBlockKeys.erase(it);
        else
            ++it;
    }
    if (m_recentBlockKeys.size() > 4096)
        m_recentBlockKeys.clear();
}
