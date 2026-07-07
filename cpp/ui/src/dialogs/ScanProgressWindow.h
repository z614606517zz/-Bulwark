#pragma once
#include <QColor>
#include <QString>
#include <QUuid>
#include <QWidget>

#include "bulwark/models/VtScanRecord.h"

namespace bulwark { struct SecurityEvent; }
struct AiScanResult;

class QLabel;
class QProgressBar;
class QHBoxLayout;
class QTimer;
class QFrame;

// Centered, live-updating "cloud scan in progress" card — the Qt port of the
// .NET AiScanToastWindow. While a double-clicked / dropped payload is checked by
// VirusTotal (query -> upload -> analyze, up to minutes) or the AI model, this
// pops up in the middle of the screen showing a countdown ("预计等待 N 秒") and a
// progress bar; when the verdict lands it flips to a colour-coded result
// (green = safe, red = malicious, amber = unknown) and auto-closes.
//
// One card is visible at a time; further scans queue. Cards are keyed by file
// path so the VT scan and the AI research of the same double-click share one
// card, and repeated events for one file don't stack duplicates. Frameless,
// translucent, always-on-top and never steals focus (WA_ShowWithoutActivating).
class ScanProgressWindow : public QWidget
{
    Q_OBJECT
public:
    // Entry points (call on the UI thread). Each finds-or-creates the card for
    // the file and updates it; terminal states schedule an auto-close.
    static void vtUpdate(const bulwark::VtScanRecord& record); // VT scan progress / result
    static void aiStart(const bulwark::SecurityEvent& event);  // AI research started
    static void aiResult(const AiScanResult& result);          // AI research finished

protected:
    void mousePressEvent(QMouseEvent*) override;

private:
    explicit ScanProgressWindow(const QString& key, const QString& fileName);

    static QString keyFor(const QString& path, const QUuid& id);
    static ScanProgressWindow* obtain(const QString& key, const QString& fileName);
    static void promoteNext(); // show the next queued card when the active one closes

    void showCentered();
    void startCountdown();
    void setBadge(const QString& iconName, const QColor& color);
    void applyVt(const bulwark::VtScanRecord& record);
    void applyResult(const QColor& accent, const QString& iconName, const QString& title,
                     const QString& status, int autoCloseSecs);
    void beginClose();

    QHBoxLayout* m_row = nullptr;   // badge | text column
    QFrame* m_badge = nullptr;      // rebuilt to recolour on the verdict
    QLabel* m_title = nullptr;
    QLabel* m_file = nullptr;       // eliding file-name label
    QProgressBar* m_bar = nullptr;
    QLabel* m_status = nullptr;     // stage message, then conclusion
    QLabel* m_countdown = nullptr;  // "预计等待 N 秒"
    QTimer* m_countdownTimer = nullptr;
    QTimer* m_autoClose = nullptr;
    int m_remaining = 120;
    bool m_resultShown = false;
    bool m_closing = false;
    QString m_key;
};
