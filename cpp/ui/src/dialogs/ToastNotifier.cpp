#include "dialogs/ToastNotifier.h"
#include "ai/AiScanner.h"
#include "dialogs/AiInsightPanel.h"
#include "dialogs/EventFormat.h"
#include "dialogs/ToastWindow.h"

#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <QDateTime>
#include <QEvent>
#include <QFileInfo>
#include <QGuiApplication>
#include <QPointer>
#include <QRect>
#include <QScreen>
#include <QTimer>
#include <QWidget>

#include <utility>

using bulwark::SecurityEvent;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

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

    // 一句话:谁凑齐了哪几个动作。动作链是这条通知的主体 —— 它回答「凭什么定性」,
    // 而不只是「拦了谁」。
    const QString sentence = u("%1 凑齐 %2").arg(program, hit.titles.join(u(" → ")));
    QString meta = u("%1 个恶意样本作证 · 强度「%2」").arg(hit.support).arg(gradeCn);
    if (!hit.families.trimmed().isEmpty())
        meta += u(" · 常见家族 ") + hit.families.trimmed();
    if (hit.dryRun)
        meta += u(" · 只记录不拦截,未参与裁决");

    // 存活期比拦截 toast 更长:动作链常有两三个动作名要读完。悬停会暂停倒计时。
    auto* t = new ToastWindow(ToastWindow::Kind::AttackChain, u("攻击链组合命中"), sentence, meta,
                              QStringList(), kChainLifetimeMs, act, u("查看详情 ›"));
    connect(t, &ToastWindow::clicked, this, [this](ToastWindow*) {
        emit attackChainToastClicked();
    });
    present(t, /*isBlock=*/false);
}

void ToastNotifier::showBlock(const SecurityEvent& e, bulwark::EnforcementOutcome enforcement)
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();

    // 去重(B):同一威胁 = 同程序 + 同行为 + 同目标。窗口期内只弹一次,重试/循环触发不再刷屏。
    //
    // 键里【必须带上真实处置结果】。否则同一个威胁先被成功拦下(弹了「已拦截」)、几秒后再次
    // 触发却没拦下(AlertedOnly / Failed),第二条会被当成重复压掉 —— 用户只看见那条绿灯,
    // 完全不知道后来有一次漏了。处置结果变了就是新消息,必须放它过去。
    const QString key = e.actorPath + QLatin1Char('|')
                      + QString::number(static_cast<int>(e.type)) + QLatin1Char('|') + e.target
                      + QLatin1Char('|') + QString::number(static_cast<int>(enforcement));
    auto it = m_recentBlockKeys.find(key);
    if (it != m_recentBlockKeys.end() && now - it.value() < kDedupWindowMs) {
        it.value() = now;   // 刷新时间戳,持续压制重复提示
        return;
    }
    m_recentBlockKeys.insert(key, now);
    pruneRecentKeys(now);

    // 限流合并(C):不同威胁短时间大量涌入(拦截风暴)时不逐条建窗(会卡死 UI)——超过最小间隔的
    // 拦截只累加计数,由合并定时器每秒汇成一条摘要 toast。完整记录仍进拦截表 / 日志,不丢信息。
    //
    // 但【真拦下的】和【没拦下的】必须分开计数:摘要那句「已自动处置,无需手动操作」只有在全部
    // 真拦下时才成立。把 AlertedOnly / Failed 混进同一个计数,等于用一条绿灯把一批需要人工处理
    // 的事情盖掉 —— 风暴场景下这恰恰是最危险的一种谎报。
    if (now - m_lastBlockToastMs < kMinBlockGapMs) {
        if (evtfmt::needsManualAction(enforcement))
            ++m_suppressedUnenforced;
        else
            ++m_suppressedBlocks;
        if (m_coalesceTimer && !m_coalesceTimer->isActive())
            m_coalesceTimer->start();
        return;
    }
    m_lastBlockToastMs = now;

    //
    // 威胁类型 + 依据,出自【同一条】证据(evtfmt::threatOf;拦截记录检查器用的也是它):
    // 云端点名的威胁 > 命中规则的分类 > 分值最高的硬指标 > ……,读起来是「它是 X,因为 Y」。
    //
    // 依据原来是「规则备注,否则 riskReasons.first()」。而 ThreatDetector 最先登记的恰恰是
    // 「无可信数字签名」这条 Info 级上下文,于是没命中规则的启发式拦截(实测占多数)通知上只有
    // 一句「依据:无可信数字签名」—— 既不是拦它的理由,也说不出拦下的是什么威胁。
    // 说不清类别时不显示威胁类型(不编),依据退回证据链里最强的那条判据。
    const evtfmt::Threat threat = evtfmt::threatOf(e);
    QString source = threat.basis;
    if (source.isEmpty())
        source = evtfmt::strongestReason(e);
    if (source.isEmpty())
        source = u("命中高危行为规则");

    //
    // 措辞 / 配色 / 图标全部由【真实执行结果】决定,不再一律写「已拦截」。
    //
    // evtfmt::disposition() 是全产品唯一的处置措辞来源(拦截记录页、时间线、审计都用它),
    // 这里复用它,右下角通知才不会和记录页说两套话 —— 此前正是这条通知在单独谎报:
    // 服务端早就算出了 EnforcementOutcome,只有它不看。
    //
    //   KernelBlocked     已拦截        动作发生【前】被内核阻断,真的没发生
    //   Terminated        已结束进程    动作已发生,但作恶进程树已被真实结束
    //   ModuleBlacklisted 已禁止加载    这次没拦下,下次加载会被内核前拦
    //   ExecDenied        已禁止启动    这次没有可结束的进程,但它再也启动不起来
    //   ActorAlreadyGone  主体已结束    发起进程已被【此前那次处置】结束,本条是它生前排队的动作
    //   AlertedOnly       仅告警·未拦截 什么实际阻断都没做 —— 必须让用户知道
    //   Failed            拦截失败      动手了没成
    //
    // 后两个是「请你自己动手」,前五个不是。这个界线由 evtfmt::needsManualAction 统一给出:
    // 此前这里手写了一份「算不算拦下了」的名单,而 ExecDenied / ActorAlreadyGone 这类
    // 「做成了、只是没杀到进程」的结果一旦漏进未拦下那一侧,就会弹出一条假的「未能拦截」。
    //
    using EO = bulwark::EnforcementOutcome;
    const evtfmt::Badge disp = evtfmt::disposition(bulwark::VerdictAction::Block, enforcement);
    const bool enforced = !evtfmt::needsManualAction(enforcement);

    const ToastWindow::Kind kind = enforcement == EO::AlertedOnly ? ToastWindow::Kind::BlockAlertedOnly
                                 : enforcement == EO::Failed      ? ToastWindow::Kind::BlockFailed
                                                                  : ToastWindow::Kind::Block;
    // 抬头也跟着变:没拦下时绝不出现「已拦截」三个字,否则一眼扫过去又被误读成处理完了。
    // 反过来同样要准:主体是被上一次处置杀掉的,就不能写成「已拦截」——那会把一次处置
    // 说成好几次;它该说的是「这条动作发生在它被结束之前」。
    const QString heading = enforcement == EO::AlertedOnly ? u("检测到危险行为,未能拦截")
                          : enforcement == EO::Failed      ? u("检测到危险行为,处置未成功")
                          : enforcement == EO::ExecDenied  ? u("已拦下危险行为,并禁止其再次启动")
                          : enforcement == EO::ActorAlreadyGone
                                                           ? u("危险行为已处置(主体此前已被结束)")
                                                           : u("已拦截危险行为");
    // 未拦下时把「为什么没拦下 / 该怎么办」说清楚(dispositionDetail 同样来自 EventFormat),
    // 而不是只丢一句判定依据 —— 这条通知此刻承担的是「请你自己动手」。
    QString meta = u("依据:") + source;
    if (!enforced)
        meta = evtfmt::dispositionDetail(bulwark::VerdictAction::Block, enforcement)
             + u("(") + meta + u(")");

    // 一句话代替原来四行「标签:值」:谁、做了什么、对谁。
    auto* t = new ToastWindow(kind, heading, evtfmt::arrowLine(e), meta, e.techniques,
                              // 没拦下的多给 4 秒:这条要读的字更多,而且用户得决定下一步。
                              enforced ? 8000 : 12000,
                              disp.text,
                              u("查看详情 ›"));
    t->setThreat(threat.category, threat.name); // 先定高度,再交给 present() 摆放

    // 「AI 解读」(配置了大模型、且没在设置里关掉时):先以「正在解读」占位进卡片,高度在摆放前就定好;
    // 结论异步到达后原地换上。只给人看:不回传服务,不改变已经做出的处置。
    // 被去重压掉、被限流合并成摘要的拦截走不到这里 —— 它们本来就不单独弹卡,也就不单独花 token。
    if (m_ai && m_ai->isConfigured() && m_ai->blockExplainEnabled()) {
        auto* panel = new AiInsightPanel(AiExplainContext::Blocked, /*compact*/ true);
        panel->setLoading();
        t->setInsight(panel);
        const bool hardIndicator = e.hasThreatIndicator;
        const QPointer<ToastWindow> toast(t);
        // receiver = panel:通知已关 / 已被挤出(随之销毁)后才回来的结论直接丢弃。命中已存的解读、
        // 或立即失败(限速 / 额度)时是同步回调,那时卡片还没摆放,settleInsight 只补存活期。
        m_ai->explainEvent(e, panel, [panel, toast, hardIndicator](const AiExplanation& r) {
            panel->setResult(r, hardIndicator);
            if (toast)
                toast->settleInsight(r.ok ? kAiReadMs : kAiFailReadMs);
        }, AiExplainContext::Blocked);
    }
    present(t, /*isBlock=*/true);
    emit blockPresented(e.actorPath, enforcement);
}

void ToastNotifier::setAiScanner(AiScanner* ai)
{
    m_ai = ai;
}

void ToastNotifier::showInfo(const QString& heading, const QString& detail, int lifetimeMs)
{
    auto* t = new ToastWindow(ToastWindow::Kind::Info, heading, detail, QString(), {}, lifetimeMs);
    present(t, /*isBlock=*/false);
}

// 足迹清理结果。去重(同一主体 30s 内只报一次)由 MainWindow::onRemediationReport 在弹报告卡片前
// 统一做,这里不再重复。完整清单在同时弹出的清理报告卡片里,这条只说结论。
void ToastNotifier::showRemediation(const bulwark::ipc::RemediationReportPayload& report)
{
    // quarantinedFiles 已经包含主体本身(服务端的 actorQuarantined 正是据此判定的),不要再 +1。
    const int quarantined = int(report.quarantinedFiles.size());
    const int removed = int(report.removedRegistryValues.size());
    const int failed = int(report.skipped.size());
    const int done = quarantined + removed;

    //
    // 抬头按【实际清掉了什么】写,不一律是「已清理恶意足迹」。
    //
    // ThreatRemediator 把每一个失败项都如实放进 skipped(受 ACL 保护、被占用、夺取所有权失败…),
    // 完全可能「一个都没清掉、全在 skipped 里」—— 那时顶一个绿色「已清理」,等于告诉用户事情
    // 办完了,而恶意文件还在盘上。三种情形分开说,配色也跟着分:只有全部清掉才是绿。
    const QString heading = failed == 0 ? u("已清理恶意足迹")
                          : done == 0   ? u("恶意足迹未能清理")
                                        : u("恶意足迹部分清理");
    const QString badge = failed == 0 ? u("已清理") : done == 0 ? u("未能清理") : u("部分清理");

    QString subject = QFileInfo(report.actorPath).fileName();
    if (subject.isEmpty())
        subject = report.reason.isEmpty() ? u("未知程序") : report.reason;
    const QString sentence = u("%1:隔离 %2 文件 · 移除 %3 持久化").arg(subject).arg(quarantined).arg(removed);
    const QString meta = failed > 0 ? u("%1 项未能清理,需手动处理").arg(failed) : QString();

    auto* t = new ToastWindow(failed == 0 ? ToastWindow::Kind::Cleanup : ToastWindow::Kind::CleanupIncomplete,
                              heading, sentence, meta, {},
                              // 有没清掉的多给几秒:要读的字更多,而且用户得决定下一步。
                              failed == 0 ? 5000 : 9000, badge);
    present(t, /*isBlock=*/false);
}

// 清理报告里「重试隔离」的回执。报告卡片自己也会在横幅里写一遍结果;这条保证卡片被挡住 /
// 已关掉时用户仍然看得到。
void ToastNotifier::showQuarantineRetry(const bulwark::ipc::ManualQuarantineResultPayload& result)
{
    const QString detail = result.message.trimmed().isEmpty()
                               ? (result.success ? u("已隔离") : u("未成功"))
                               : result.message.trimmed();
    auto* t = new ToastWindow(result.success ? ToastWindow::Kind::Cleanup : ToastWindow::Kind::CleanupIncomplete,
                              u("重试隔离"), detail, QString(), {},
                              result.success ? 4000 : 8000,
                              result.success ? u("已隔离") : u("未成功"));
    present(t, /*isBlock=*/false);
}

void ToastNotifier::present(ToastWindow* toast, bool isBlock)
{
    connect(toast, &ToastWindow::closed, this, &ToastNotifier::remove);
    // 通知显示后自己修正了高度(换行文案的真实行数要等 polish 完才知道,见 ToastWindow::showEvent):
    // 重新摆一遍这一叠,否则它会比预定位置低出修正的那几十像素、压到下面那条。
    connect(toast, &ToastWindow::resized, this, [this](ToastWindow*) { scheduleReflow(); });
    if (isBlock)
        connect(toast, &ToastWindow::clicked, this,
                [this](ToastWindow*) { emit blockToastClicked(); });

    m_stack.prepend(toast);

    // Cap the visible stack; retire the oldest surplus toasts immediately.
    while (m_stack.size() > kMaxVisible) {
        ToastWindow* old = m_stack.takeLast();
        old->hide(); // deleteLater alone would leave it on screen until the event loop runs
        old->deleteLater();
    }

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

    // 同在这个角上的窗口(行为询问弹窗):toast 一律让开,不许落在它身上。
    QList<QRect> obstacles;
    for (const QPointer<QWidget>& w : std::as_const(m_cornerWindows))
        if (w && w->isVisible())
            obstacles << w->frameGeometry();

    int baselineBottom = area.bottom() - margin;
    int placed = 0;
    for (; placed < m_stack.size(); ++placed) {
        ToastWindow* t = m_stack.at(placed);
        QRect slot(area.right() - margin - t->width(), baselineBottom - t->height(),
                   t->width(), t->height());
        // 压到障碍就跳到它上方。每跳一次只会往上走、并且从此越过那个障碍,
        // 所以最多每个障碍跳一次就停。紧贴即可:两边的阴影留白已经构成了间距。
        for (bool hopped = true; hopped;) {
            hopped = false;
            for (const QRect& o : std::as_const(obstacles)) {
                if (slot.intersects(o)) {
                    slot.moveBottom(o.top() - 1);
                    hopped = true;
                }
            }
        }
        if (slot.top() < area.top())
            break; // 上方放不下了
        t->place(slot.topLeft());
        baselineBottom = slot.top() - gap;
    }
    // 放不下的按最旧优先退场 —— 与 present() 里 kMaxVisible 的封顶同一口径(完整记录仍在拦截表 / 日志里)。
    while (m_stack.size() > placed) {
        ToastWindow* old = m_stack.takeLast();
        old->hide(); // deleteLater alone would leave it on screen until the event loop runs
        old->deleteLater();
    }
}

void ToastNotifier::scheduleReflow()
{
    // 合并到下一轮事件循环:弹窗显示 / 定位 / 被拖动时会连发一串 Move / Resize,
    // 而且它的最终位置要等它自己的 showEvent 跑完才确定。
    if (m_reflowPending)
        return;
    m_reflowPending = true;
    QTimer::singleShot(0, this, [this] {
        m_reflowPending = false;
        reflow();
    });
}

void ToastNotifier::reserveCorner(QWidget* window)
{
    m_cornerWindows.removeIf([](const QPointer<QWidget>& p) { return p.isNull(); });
    if (!window || m_cornerWindows.contains(window))
        return;
    m_cornerWindows.append(window);
    window->installEventFilter(this);
    scheduleReflow();
}

void ToastNotifier::releaseCorner(QWidget* window)
{
    if (!window)
        return;
    window->removeEventFilter(this);
    m_cornerWindows.removeAll(window);
    scheduleReflow();
}

bool ToastNotifier::eventFilter(QObject* watched, QEvent* event)
{
    switch (event->type()) {
    case QEvent::Show:
    case QEvent::Hide:
    case QEvent::Move:
    case QEvent::Resize:
        if (auto* w = qobject_cast<QWidget*>(watched); w && m_cornerWindows.contains(w))
            scheduleReflow();
        break;
    default:
        break;
    }
    return QObject::eventFilter(watched, event);
}

void ToastNotifier::remove(ToastWindow* toast)
{
    m_stack.removeAll(toast);
    reflow();
}

// 把被限流压制掉的拦截汇成一条摘要 toast(点击可跳到拦截记录)。
//
// 摘要必须如实分开两类计数:真拦下的、以及【裁决了拦截但实际没拦下的】。只要后者不为零,
// 整条摘要就降成琥珀,并且绝不出现「无需手动操作」那句话 —— 那句话在有未拦下项时是假的。
void ToastNotifier::flushSuppressed()
{
    const int blocked = m_suppressedBlocks;
    const int unenforced = m_suppressedUnenforced;
    if (blocked <= 0 && unenforced <= 0)
        return;
    m_suppressedBlocks = 0;
    m_suppressedUnenforced = 0;
    m_lastBlockToastMs = QDateTime::currentMSecsSinceEpoch();

    const int total = blocked + unenforced;
    if (unenforced <= 0) {
        // 全部真拦下:可以说「已自动处置」。
        auto* t = new ToastWindow(ToastWindow::Kind::Block,
                                  u("已批量拦截危险行为"),
                                  u("短时间内共拦截 %1 项").arg(blocked),
                                  u("磐垒已自动处置,无需手动操作"),
                                  {}, 6000, u("已拦截"), u("查看拦截记录 ›"));
        present(t, /*isBlock=*/true);
        emit blockBatchPresented(blocked, 0);
        return;
    }
    // 有没拦下的:琥珀 + 明确写出各是多少 + 提示需要人工处理。
    auto* t = new ToastWindow(
        ToastWindow::Kind::BlockAlertedOnly,
        u("批量处置:有未能拦截的项"),
        blocked > 0 ? u("短时间内共 %1 项,其中 %2 项已拦下、%3 项未能拦截")
                          .arg(total).arg(blocked).arg(unenforced)
                    : u("短时间内共 %1 项危险行为未能拦截").arg(unenforced),
        u("未能拦截的动作已经发生,需要你手动处理"),
        {}, 12000, u("需人工处理"), u("查看拦截记录 ›"));
    present(t, /*isBlock=*/true);
    emit blockBatchPresented(blocked, unenforced);
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
