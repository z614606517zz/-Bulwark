#pragma once
#include <QColor>
#include <QPoint>
#include <QString>
#include <QStringList>
#include <QWidget>

class CountdownBar;
class QPropertyAnimation;

// A single corner "toast" notification — the building block behind the block
// (拦截通知), attack-chain and AI-scan toasts.
//
//   ┃ [glyph] 已拦截危险行为                      [已拦截]  ✕
//   ┃         powershell.exe 注入远程线程 → explorer.exe
//   ┃         依据:命中高危行为规则         [T1055] [T1059]
//   ┃         查看详情 ›
//   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  (time left; hover pauses)
//
// One sentence says what happened, instead of four 标签:值 rows. ✕ only closes;
// only 「查看详情」 navigates (clicking the body used to jump to a page with no
// way to just dismiss).
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
    enum class Kind { Block, AiScan, Info, AttackChain };

    // `badgeText` is the status capsule (the attack chain passes its REAL
    // disposition: 已拦截 / 已询问 / 已放行 / 仅记录). Empty = no capsule, except
    // Block which defaults to 已拦截. `actionText` empty = no 「查看详情」 link.
    ToastWindow(Kind kind, const QString& heading, const QString& sentence, const QString& meta,
                const QStringList& tags, int lifetimeMs, const QString& badgeText = QString(),
                const QString& actionText = QString(), QWidget* parent = nullptr);

    // Move to `topLeft`. The first call fades the toast in at that spot; later
    // calls slide it (used when the stack re-flows as toasts come and go).
    void place(const QPoint& topLeft);

signals:
    void closed(ToastWindow* self);
    void clicked(ToastWindow* self); // 「查看详情」

protected:
    void enterEvent(QEnterEvent*) override;
    void leaveEvent(QEvent*) override;

private slots:
    void beginClose();

private:
    CountdownBar* m_bar = nullptr;
    QPropertyAnimation* m_fade = nullptr;
    QPropertyAnimation* m_slide = nullptr;
    int m_lifetimeMs = 6000;
    bool m_shown = false;
    bool m_closing = false;
};
