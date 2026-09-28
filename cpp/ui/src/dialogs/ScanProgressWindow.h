#pragma once
#include <QColor>
#include <QString>
#include <QUuid>
#include <QWidget>

#include "bulwark/models/VtScanRecord.h"

namespace bulwark { struct SecurityEvent; }
struct AiScanResult;

class ElidingLabel;
class GlowCard;
class IconTile;
class QLabel;
class QPushButton;
class QTimer;
class Stepper;

// Live "cloud scan in progress" card, shown centred while a double-clicked /
// dropped payload is checked (the user just launched it and is waiting):
//
//   [cloud] 正在云端查毒…                         [+2]  ⤓  ✕
//           invoice_2026_09.pdf.exe
//   ①查询 ── ②上传 ── ③分析 ── ④结论                 (VtScanStage)
//   正在查询中央服务器是否已收录…              预计等待 97 秒
//   AI 研判 · 大模型正在基于静态特征研判…               (when AI research runs)
//
// When the verdict lands it flips to a colour-coded result and auto-closes.
// 「转到后台」 folds it into a small capsule at the top-right of the screen; the
// capsule shows the verdict when it arrives and 「查看详情」 unfolds it again.
//
// One card is visible at a time; further scans queue ("+2"). Cards are keyed by
// file path so the VT scan and the AI research of the same double-click share
// one card. Frameless, translucent, always-on-top, never steals focus.
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
    static void syncQueueBadge();

    void showCentered();
    // 文案变化后重算窗口尺寸并保持位置。宽度是固定的,所以长文案只能靠换行消化,
    // 窗口高度必须跟着长 —— 否则多出来的那几行会被裁在卡片外面(结论看不全)。
    // 尺寸未变时不动窗口,避免每次进度更新都抖一下。
    void relayout();
    bool refitHeight(); // 按固定宽度重算高度;返回 true 表示高度确实变了
    void recenter();    // 按当前尺寸重新定位(居中;小胶囊模式在右上角)
    void setMini(bool mini);
    void setQueued(int n);
    void startCountdown();
    void applyVt(const bulwark::VtScanRecord& record);
    void applyAi(const AiScanResult& result);
    void applyResult(const QColor& accent, const QString& iconName, const QString& title,
                     const QString& status, int autoCloseSecs);
    void beginClose();

    GlowCard* m_card = nullptr;     // the floating card; its glow follows the verdict colour
    QWidget* m_full = nullptr;      // full card content
    QWidget* m_mini = nullptr;      // capsule content
    IconTile* m_tile = nullptr;
    QLabel* m_title = nullptr;
    QLabel* m_file = nullptr;
    QLabel* m_queue = nullptr;      // "+N"
    Stepper* m_steps = nullptr;
    QLabel* m_status = nullptr;     // stage message, then conclusion
    QLabel* m_countdown = nullptr;  // "预计等待 N 秒"
    QWidget* m_aiRow = nullptr;
    QLabel* m_aiText = nullptr;
    IconTile* m_miniTile = nullptr;
    ElidingLabel* m_miniText = nullptr; // must stay ElidingLabel*: setText() is not virtual
    QPushButton* m_miniOpen = nullptr;
    QTimer* m_countdownTimer = nullptr;
    QTimer* m_autoClose = nullptr;
    int m_remaining = 120;
    bool m_resultShown = false;
    bool m_closing = false;
    bool m_isMini = false;
    bool m_sawUpload = false;
    QString m_fileName;
    QString m_key;
};
