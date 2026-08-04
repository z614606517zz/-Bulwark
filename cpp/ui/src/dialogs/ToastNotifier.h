#pragma once
#include <QHash>
#include <QList>
#include <QObject>
#include <QString>

namespace bulwark { struct SecurityEvent; }
namespace bulwark::ipc { struct AttackChainHitPayload; }

class ToastWindow;
class QTimer;

// Owns and lays out the corner toast stack (bottom-right of the primary
// screen). Toasts float above every app and never steal focus, so protection
// notifications reach the user even while the main window is hidden in the
// tray. Newest sits at the bottom; older toasts slide upward. Emits a signal
// when a block toast is clicked so the shell can surface the intercept log.
class ToastNotifier : public QObject
{
    Q_OBJECT
public:
    explicit ToastNotifier(QObject* parent = nullptr);

    // Block toast (拦截通知) — a deterministic high-risk action was blocked outright.
    void showBlock(const bulwark::SecurityEvent& event);
    // AI-scan toast (AI 扫描提示) — an AI verdict was triggered by launching a program.
    void showAiScan(const bulwark::SecurityEvent& event);
    // Generic informational toast.
    void showInfo(const QString& heading, const QString& detail);

    // 攻击链组合命中(攻击链通知)。与 showBlock 分开的三个理由:
    //   1. 处置可能是拦截 / 询问 / 放行 —— 用拦截 toast 的红色与"已拦截"措辞会在放行时谎报;
    //   2. 要展示的是【动作链】(凑齐的那几个动作)与作证样本数,拦截 toast 的字段结构装不下;
    //   3. 去重键必须按「主体 + 组合」而不是拦截那套键 —— 同一程序反复命中同一组合应合并
    //      (实测 kiro-account-manager 三分钟内命中两次)。
    void showAttackChain(const bulwark::ipc::AttackChainHitPayload& hit);

signals:
    void blockToastClicked();
    // 点了攻击链 toast —— 外壳据此切到「攻击链」页面。
    void attackChainToastClicked();

private:
    void present(ToastWindow* toast, bool isBlock);
    void reflow();
    void remove(ToastWindow* toast);
    void flushSuppressed();            // 把被限流合并的拦截汇成一条摘要 toast
    void pruneRecentKeys(qint64 nowMs);

    QList<ToastWindow*> m_stack; // index 0 = newest (bottom-most)

    // 去重 + 限流合并:避免同一威胁重复提示,以及高频拦截风暴下逐条建窗把 UI 卡死。
    QHash<QString, qint64> m_recentBlockKeys; // 去重键 -> 最近弹出时刻(ms since epoch)
    qint64 m_lastBlockToastMs = 0;            // 上次单条拦截 toast 的时刻
    int m_suppressedBlocks = 0;               // 被限流合并掉的拦截数
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
