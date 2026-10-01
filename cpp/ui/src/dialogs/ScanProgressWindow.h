#pragma once
#include <QColor>
#include <QString>
#include <QUuid>
#include <QWidget>

#include "bulwark/models/Enums.h"        // EnforcementOutcome
#include "bulwark/models/VtScanRecord.h"

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
//
// When the verdict lands it flips to a colour-coded result and auto-closes.
// 「转到后台」 folds it into a small capsule at the top-right of the screen; the
// capsule shows the verdict when it arrives and 「查看详情」 unfolds it again.
//
// One card is visible at a time; further scans queue ("+2"). Cards are keyed by
// file path so every update for the same file lands on one card.
// Frameless, translucent, always-on-top, never steals focus.
class ScanProgressWindow : public QWidget
{
    Q_OBJECT
public:
    // Entry points (call on the UI thread). Each finds-or-creates the card for
    // the file and updates it; terminal states schedule an auto-close.
    static void vtUpdate(const bulwark::VtScanRecord& record); // VT scan progress / result

    // 处置结果回填(由 BlockNotification 带回的真实 EnforcementOutcome 驱动)。
    //
    // 检测与处置是两个阶段:云查给出「恶意」结论时,结束进程树 / 隔离载荷还没做,而且可能
    // 失败(进程受保护、文件被占用)。所以结论标题只写「检测到威胁」,真正做成了什么由这里补上:
    //   已拦截 / 已结束进程 / 已禁止加载 -> 「检测到威胁,已处置」(玉髓绿说明行)
    //   仅告警·未拦截 / 拦截失败         -> 「检测到威胁,未能完全处置」(琥珀 + 需人工处理)
    // 找不到对应卡片(已关闭 / 不是双击查毒触发的)时静默忽略。
    static void applyDisposition(const QString& filePath,
                                 bulwark::EnforcementOutcome enforcement);

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
    // 该卡片的结论是「恶意」——只有这种卡片在等处置结果回填(applyDisposition)。
    bool m_maliciousVerdict = false;
    // 恶意结论那一行(含威胁名)。applyDisposition 回填处置时保留它,处置结果另起一行。
    QString m_verdictText;
    bool m_dispositionShown = false;  // 已回填过,忽略后续重复通知(同一威胁可能多条)
    QString m_fileName;
    QString m_key;
};
