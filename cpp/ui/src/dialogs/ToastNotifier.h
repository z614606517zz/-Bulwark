#pragma once
#include <QHash>
#include <QList>
#include <QObject>
#include <QString>

namespace bulwark { struct SecurityEvent; }

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

signals:
    void blockToastClicked();

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
};
