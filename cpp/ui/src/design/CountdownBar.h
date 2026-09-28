#pragma once
#include <QColor>
#include <QElapsedTimer>
#include <QWidget>

#include <functional>

class QTimer;

// A thin bar that shrinks from full to empty over a time span, with an optional
// caption at its right ("18 秒后自动放行"). It shows *that* something will happen
// on its own and *when*, without borrowing a button's label for the number.
//
// pause()/resume() exist for surfaces that should wait while the user reads
// (toasts, the cleanup report). The behavior prompt deliberately never pauses:
// the service keeps its own timeout, and a UI that stops counting would let the
// user click after the service has already applied the default.
class CountdownBar : public QWidget
{
    Q_OBJECT
public:
    explicit CountdownBar(QWidget* parent = nullptr);

    void start(int ms);
    void stop();
    void pause();
    void resume();
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

    QTimer* m_timer = nullptr;
    QElapsedTimer m_clock;
    int m_total = 0;
    int m_base = 0; // remaining when the clock was (re)started
    bool m_running = false;
    bool m_paused = false;
    int m_lastSecond = -1;
    QColor m_color;
    std::function<QString(int)> m_fmt;
};
