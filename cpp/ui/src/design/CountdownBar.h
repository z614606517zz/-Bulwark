#pragma once
#include <QColor>
#include <QElapsedTimer>
#include <QPoint>
#include <QPointer>
#include <QWidget>

#include <functional>

class QTimer;

// A thin bar that shrinks from full to empty over a time span, with an optional
// caption at its right ("18 秒后自动放行"). It shows *that* something will happen
// on its own and *when*, without borrowing a button's label for the number.
//
// setHoverPause() is how surfaces that should wait while the user reads (toasts,
// the cleanup report) hold the countdown. The behavior prompt deliberately never
// pauses: the service keeps its own timeout, and a UI that stops counting would
// let the user click after the service has already applied the default.
class CountdownBar : public QWidget
{
    Q_OBJECT
public:
    explicit CountdownBar(QWidget* parent = nullptr);

    void start(int ms);
    void stop();
    void pause();
    void resume();
    // 剩余不足 ms 时补到 ms(进度条随之回涨);暂停 / 悬停状态保持不变。已走完(或没开始)= start(ms)。
    // 给内容晚到的浮窗用(拦截通知的「AI 解读」):内容到了,得留够读它的时间。
    void ensureRemaining(int ms);

    // 悬停暂停:倒计时在指针【真的停在 target 上】的时候暂停,离开即继续。target 一般传这条
    // 倒计时所属的那张可见卡片(而不是外面那层带阴影留白的窗口)。
    //
    // 判据是每隔 120ms 直接问指针在哪(QCursor::pos),而【不是】靠 enterEvent / leaveEvent ——
    // 那一套会让通知永远关不掉,原因见 syncHoverPause() 的说明。另外:卡片自己跑到静止指针底下
    // 不算悬停,必须指针在它上面动过才算,否则「弹出时正好压在指针下」会直接把倒计时冻住。
    void setHoverPause(QWidget* target);
    bool isRunning() const { return m_running; }
    bool isPaused() const { return m_paused; }
    int remainingMs() const;
    int totalMs() const { return m_total; }

    void setColor(const QColor& c);
    // Caption for the remaining whole seconds; unset = bar only.
    void setFormatter(std::function<QString(int secondsLeft)> fmt);

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

signals:
    void finished();
    void secondChanged(int secondsLeft);

protected:
    void paintEvent(QPaintEvent*) override;

private:
    void tick();
    QString caption() const;
    void syncHoverPause();                              // 按指针真实位置校正暂停状态
    bool pointerOnTarget(const QPoint& globalPos) const;

    QTimer* m_timer = nullptr;
    QElapsedTimer m_clock;
    int m_total = 0;
    int m_base = 0; // remaining when the clock was (re)started
    bool m_running = false;
    bool m_paused = false;
    int m_lastSecond = -1;
    QColor m_color;
    std::function<QString(int)> m_fmt;

    // setHoverPause()
    QPointer<QWidget> m_hoverTarget;
    QTimer* m_hoverTimer = nullptr;
    QPoint m_lastCursor;
    bool m_hoverArmed = false; // 指针在 target 上动过 —— 这才算「用户在看它」
};
