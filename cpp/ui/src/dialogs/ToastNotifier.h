#pragma once
#include <QHash>
#include <QList>
#include <QObject>
#include <QPointer>
#include <QString>

#include "bulwark/models/Enums.h"   // EnforcementOutcome(按值传参,不能只前置声明)

namespace bulwark { struct SecurityEvent; }
namespace bulwark::ipc {
struct AttackChainHitPayload;
struct ManualQuarantineResultPayload;
struct RemediationReportPayload;
}

class AiScanner;
class ToastWindow;
class QTimer;
class QWidget;

// Owns and lays out the corner toast stack (bottom-right of the primary
// screen). Toasts float above every app and never steal focus, so protection
// notifications reach the user even while the main window is hidden in the
// tray. Newest sits at the bottom; older toasts slide upward. Emits a signal
// when a block toast is clicked so the shell can surface the intercept log.
//
// The behavior prompt lives in the same corner: while one is registered with
// reserveCorner() and visible, toasts stack above it instead of over it.
class ToastNotifier : public QObject
{
    Q_OBJECT
public:
    explicit ToastNotifier(QObject* parent = nullptr);

    // A window parked in the toast corner (the behavior prompt). Toasts are raised
    // above everything, so one landing on the prompt would cover its 拦截 / 放行
    // buttons — while the window is visible they stack above it, and the oldest
    // ones that no longer fit are retired. Follows the window's moves, resizes and
    // visibility; releaseCorner() (or the window's destruction) gives the corner back.
    void reserveCorner(QWidget* window);
    void releaseCorner(QWidget* window);

    // 拦截通知的「AI 解读」用哪个大模型客户端(与行为询问共用同一个 AiScanner:同一份缓存、同一个限速闸)。
    // 不设 / 没配置大模型 / 设置里关掉 = 通知里就没有这一块。
    void setAiScanner(AiScanner* ai);

    // 拦截通知。`enforcement` 是服务端【处置执行完之后】的真实结果,这条通知的配色、图标、
    // 抬头与处置 pill 全部由它决定(经 evtfmt::disposition / dispositionDetail):
    // 真拦下 -> 朱砂「已拦截 / 已结束进程 / 已禁止加载 / 已禁止启动 / 主体已结束」;
    // 没拦下 -> 琥珀「仅告警·未拦截 / 拦截失败」+ 说明为什么没拦下 + 更长的存活期
    // (用户得自己处理)。两侧的界线只由 evtfmt::needsManualAction 给出,这里不再手写名单 ——
    // 手写的那份曾把「已禁止启动」「主体已结束」漏到没拦下那一侧,于是弹出假的「未能拦截」。
    // 缺省 NotApplicable 只在「新界面 + 老服务」混跑期出现,沿用 EventFormat 的历史兜底,
    // 与拦截记录页对同一条事件的显示一致(见 BlockNotificationPayload 处的说明)。
    // 「威胁类型」一行与「依据」出自 evtfmt::threatOf(同一条证据),与拦截记录检查器一致。
    // 配置了大模型时再附一块「AI 解读」(见 setAiScanner / ToastWindow::setInsight)。
    void showBlock(const bulwark::SecurityEvent& event,
                   bulwark::EnforcementOutcome enforcement =
                       bulwark::EnforcementOutcome::NotApplicable);
    // Generic informational toast — also carries the non-threat notices that used
    // to be tray balloons (托盘首次出现 / 关到托盘 / 有新版本).
    void showInfo(const QString& heading, const QString& detail, int lifetimeMs = 5000);

    // 攻击链组合命中(攻击链通知)。与 showBlock 分开的三个理由:
    //   1. 处置可能是拦截 / 询问 / 放行 —— 用拦截 toast 的红色与"已拦截"措辞会在放行时谎报;
    //   2. 要展示的是【动作链】(凑齐的那几个动作)与作证样本数,拦截 toast 的字段结构装不下;
    //   3. 去重键必须按「主体 + 组合」而不是拦截那套键 —— 同一程序反复命中同一组合应合并
    //      (实测 kiro-account-manager 三分钟内命中两次)。
    void showAttackChain(const bulwark::ipc::AttackChainHitPayload& hit);

    // 恶意足迹清理结果,以及清理报告里「重试隔离」的回执。
    //
    // 这两条原先走 QSystemTrayIcon::showMessage。Windows 10/11 会把托盘气泡转成【系统自己画】
    // 的通知:跟随系统主题(浅色主题下就是一张白卡),本程序的深色主题管不到它;它还和这里的
    // toast 抢同一个右下角、互相压住 —— 用户看到的就是「深色拦截通知里夹着一张白色威胁弹窗」。
    // 所以右下角的通知一律走这里,界面不再调用托盘气泡(非威胁的几条提示走 showInfo)。
    void showRemediation(const bulwark::ipc::RemediationReportPayload& report);
    void showQuarantineRetry(const bulwark::ipc::ManualQuarantineResultPayload& result);

signals:
    void blockToastClicked();
    // 点了攻击链 toast —— 外壳据此切到「攻击链」页面。
    void attackChainToastClicked();

    // 一条拦截结果真正呈现给了用户(已过去重与限流合并)。语音播报只接这两个信号,所以耳朵听到的与
    // 右下角看到的逐条对应:被去重压掉的不会念,被合并成摘要的只念那句摘要。攻击链 / 普通信息 toast 不发。
    void blockPresented(const QString& actorPath, bulwark::EnforcementOutcome enforcement);
    void blockBatchPresented(int blocked, int unenforced);

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    void present(ToastWindow* toast, bool isBlock);
    void reflow();
    void scheduleReflow();             // 合并到下一轮事件循环再 reflow(见实现)
    void remove(ToastWindow* toast);
    void flushSuppressed();            // 把被限流合并的拦截汇成一条摘要 toast
    void pruneRecentKeys(qint64 nowMs);

    QList<ToastWindow*> m_stack; // index 0 = newest (bottom-most)
    QList<QPointer<QWidget>> m_cornerWindows; // reserveCorner():toast 必须让开的窗口
    QPointer<AiScanner> m_ai;                 // setAiScanner()

    // 解读到了之后至少再留多久给人读(倒计时不足就补足;已走完的从这里重新开始)。
    // 失败那一句短,只留够看清原因 —— 「接口拒绝了 API Key」这种得让用户知道。
    static constexpr int kAiReadMs = 10000;
    static constexpr int kAiFailReadMs = 4000;
    bool m_reflowPending = false;

    // 去重 + 限流合并:避免同一威胁重复提示,以及高频拦截风暴下逐条建窗把 UI 卡死。
    QHash<QString, qint64> m_recentBlockKeys; // 去重键 -> 最近弹出时刻(ms since epoch)
    qint64 m_lastBlockToastMs = 0;            // 上次单条拦截 toast 的时刻
    int m_suppressedBlocks = 0;               // 被限流合并掉的【真拦下】数
    // 被限流合并掉的【裁决拦截但实际没拦下】数(AlertedOnly / Failed)。与上面分开计数:
    // 摘要里那句「已自动处置,无需手动操作」只有在这个数为 0 时才是真话。
    int m_suppressedUnenforced = 0;
    QTimer* m_coalesceTimer = nullptr;        // 1s 合并摘要定时器

    static constexpr int kMaxVisible = 4;
    static constexpr int kDedupWindowMs = 10000; // 同一威胁 10s 内只弹一次
    static constexpr int kMinBlockGapMs = 800;   // 单条拦截 toast 最小间隔(超出即合并)

    // 攻击链去重窗口取得比拦截长得多:攻击链是低频事件(一天几次),而同一程序凑齐同一组合
    // 往往在几分钟内反复触发(每次新事件都会再次凑齐)。10s 压不住,5 分钟才压得住。
    static constexpr int kChainDedupWindowMs = 300000;
    // 存活期比拦截 toast(6s)长:动作链有两三个动作名要读完。悬停暂停倒计时。
    static constexpr int kChainLifetimeMs = 9000;
};
