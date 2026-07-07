#pragma once
#include <QList>
#include <QObject>

namespace bulwark { struct SecurityEvent; }

class ToastWindow;

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

    QList<ToastWindow*> m_stack; // index 0 = newest (bottom-most)
    static constexpr int kMaxVisible = 4;
};
