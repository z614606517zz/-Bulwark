#pragma once
#include <QColor>
#include <QPoint>
#include <QString>
#include <QStringList>
#include <QWidget>

class CountdownBar;
class ElidingLabel;
class IconTile;
class QLabel;
class QPropertyAnimation;

// A single corner "toast" notification — the building block behind the block
// (拦截通知), attack-chain and info toasts.
//
//   ┃ [glyph] 已拦截危险行为                      [已拦截]  ✕
//   ┃         powershell.exe 注入远程线程 → explorer.exe
//   ┃         威胁类型 [进程注入]                  (block toasts: setThreat)
//   ┃         依据:命中高危行为规则         [T1055] [T1059]
//   ┃         ▌✦ AI 解读 [拦截合理] [置信度 高]    (block toasts: setInsight)
//   ┃         查看详情 ›
//   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  (time left; hover pauses — see below)
//
// One sentence says what happened, instead of four 标签:值 rows. ✕ only closes;
// only 「查看详情」 navigates (clicking the body used to jump to a page with no
// way to just dismiss).
//
// The bar closes the toast when it runs out, and pausing on hover is delegated to
// CountdownBar::setHoverPause() — deliberately not to enterEvent / leaveEvent: a
// toast that pops up (or slides) under a cursor that then never moves gets the
// Enter but no Leave, and used to sit there paused forever. The bar asks where the
// pointer actually is instead, and only counts it as hover once the pointer has
// moved over the card.
//
// Frameless, translucent, always-on-top and non-activating (never steals focus
// from the user's work). Placement/stacking is owned by ToastNotifier; this
// widget only knows how to paint itself and animate to a target position.
class ToastWindow : public QWidget
{
    Q_OBJECT
public:
    // AttackChain 单独一档而不是复用 Block:它表达的是「若干动作凑成了已知恶意组合」,
    // 处置可能是拦截、询问、也可能是放行(静默模式降级)。用 Block 的红色 + "已拦截" 措辞
    // 会在放行的情况下变成谎报。
    //
    // BlockAlertedOnly / BlockFailed 同理单独成档 —— 它们是「裁决了拦截,但实际没拦下」:
    //   AlertedOnly  内核无法前拦、又没有可结束的进程,什么实际阻断都没做;
    //   Failed       尝试结束但没成(进程已退出 / 受保护 / 关键进程)。
    // 注意【只有这两个】走琥珀档。「没有可结束的进程」本身不等于没拦下:同一情形下若已经
    // 留下跨重启的禁止启动、或主体早被上一次处置杀掉(ExecDenied / ActorAlreadyGone),
    // 那是处置到位了,走的是 Block 这一档。
    // 二者都必须用琥珀 + 告警图标,和真拦下的朱砂 shield-x 一眼分开:这两种情况下动作是
    // 【已经发生了】的,用户必须自己处理,把它们画成「已拦截」就是骗人。
    //
    // Cleanup / CleanupIncomplete 是确认恶意后的足迹清理结果(以及清理报告里「重试隔离」的回执):
    // 全部清掉 = 绿;有没清掉的 = 琥珀,剩下的得用户自己处理。与清理报告卡片同一套配色。
    enum class Kind { Block, BlockAlertedOnly, BlockFailed, Info, AttackChain, Cleanup, CleanupIncomplete };

    // `badgeText` is the status capsule and must carry the REAL disposition
    // (evtfmt::disposition(): 已拦截 / 已结束进程 / 已禁止加载 / 已禁止启动 / 主体已结束 /
    //  仅告警·未拦截 / 拦截失败,
    // or the attack chain's 已询问 / 已放行 / 仅记录). Empty = no capsule at all —
    // there is deliberately NO fallback text, because a wrong capsule is worse
    // than none. `actionText` empty = no 「查看详情」 link.
    ToastWindow(Kind kind, const QString& heading, const QString& sentence, const QString& meta,
                const QStringList& tags, int lifetimeMs, const QString& badgeText = QString(),
                const QString& actionText = QString(), QWidget* parent = nullptr);

    // 「威胁类型」一行(拦截通知用,内容来自 evtfmt::threatOf):类别 pill(随本条通知的状态色)
    // + 可选的具名威胁(云端威胁名,过长省略,全文在 tooltip)。category 为空 = 不显示这一行。
    // 必须在交给 ToastNotifier 摆放(place)之前调用:它会改变卡片高度。
    void setThreat(const QString& category, const QString& name = QString());

    // 在「依据 / 技战术」之后、「查看详情」之前插一块附加内容 —— 拦截通知的「AI 解读」。
    // 同样必须在交给 ToastNotifier 摆放之前调用。
    //
    // 解读是异步到的,而这张卡只活 8 秒:慢一点的模型(推理模型动辄十几秒)回话时卡早就关了,
    // 用户永远看不到它。所以内容还在路上时,倒计时走完也先不关(进度条停在空处,面板自己写着
    // 「正在解读… N 秒」),等 settleInsight()。等待有上限(kMaxInsightHoldMs),✕ 随时可关。
    void setInsight(QWidget* panel);
    // 附加内容到了(或失败了):按新内容重算高度 —— 已在屏上时向上长、底边不动;并保证至少还剩
    // minRemainingMs 可读。倒计时已走完的从 minRemainingMs 重新开始(0 = 直接关),还在走的不足就补足。
    void settleInsight(int minRemainingMs);

    // Move to `topLeft`. The first call fades the toast in at that spot; later
    // calls slide it (used when the stack re-flows as toasts come and go).
    void place(const QPoint& topLeft);

signals:
    void closed(ToastWindow* self);
    void clicked(ToastWindow* self); // 「查看详情」
    // 显示后高度被修正了(见 showEvent):ToastNotifier 据此重新摆放这一叠通知。
    void resized(ToastWindow* self);

protected:
    void showEvent(QShowEvent* event) override;

private slots:
    void beginClose();

private:
    // 按固定宽度重算卡片高度(构造时算一次初值,showEvent 里算准)。
    //
    // 【不能用 adjustSize()】它走 sizeHint(),而换行标签在宽度确定前会低报所需高度 ——
    // 本窗口宽度写死 412,长文案只能靠换行消化,多出来的那几行于是被挤在卡片外:实测
    // 「qishui_Music_X6485152.exe 加载模块 → C:\…\InstallOptions.dll」这句要三行,
    // 构造期只算出两行的高度,第三行与下面的「威胁类型」行直接叠在一起。
    // 权威的那次测量在 showEvent(见那里:显示之前连 heightForWidth 都还不准)。
    void refitHeight();
    int fittedHeight();             // 按固定宽度量出来的高度(refitHeight 与 settleInsight 共用)
    void onCountdownFinished();     // 附加内容还在路上就先不关,否则 beginClose()

    // 兜底上限:只防「回调永远不来」。解读请求自己有 25 秒硬超时,正常轮不到它。
    static constexpr int kMaxInsightHoldMs = 30000;

    QWidget* m_insightSlot = nullptr;    // setInsight() 的位置;之前隐藏、不占位
    bool m_insightPending = false;       // 附加内容还在路上
    bool m_expired = false;              // 倒计时已走完,正在等附加内容
    QWidget* m_threatRow = nullptr;      // 「威胁类型」行;setThreat() 之前隐藏、不占位
    QLabel* m_threatPill = nullptr;
    ElidingLabel* m_threatName = nullptr; // must stay ElidingLabel*: setText() is not virtual
    QColor m_accent;                      // 本条通知的状态色(pill 跟着它)
    QString m_description;                // 构造时的无障碍描述(setThreat 在它前面补上威胁类型)
    CountdownBar* m_bar = nullptr;
    IconTile* m_tile = nullptr;
    QPropertyAnimation* m_fade = nullptr;
    QPropertyAnimation* m_slide = nullptr;
    int m_lifetimeMs = 6000;
    bool m_shown = false;
    bool m_closing = false;
};
