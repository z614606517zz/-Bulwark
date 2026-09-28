#pragma once
#include <QColor>
#include <QElapsedTimer>
#include <QWidget>

class QTimer;

// The dashboard's protection emblem: a shield glyph in a lit disc, a ring of
// instrument ticks and — only while protection is actually running — a slow
// radar sweep with a breathing glow.
//
// Motion here means "actively protecting", so the emblem is perfectly still in
// the Off and Unknown states: an animated shield next to "防护已关闭" would be
// the same lie as a green light that is always green. It also stays still when
// Windows' "show animations" accessibility setting is off, and stops its timer
// whenever it isn't visible (other page, window in the tray).
class ShieldEmblem : public QWidget
{
    Q_OBJECT
public:
    enum class State { Unknown, Protected, Partial, Off };

    explicit ShieldEmblem(QWidget* parent = nullptr);

    void setState(State s);
    State state() const { return m_state; }
    static QColor colorFor(State s);

    QSize sizeHint() const override { return {148, 148}; }
    QSize minimumSizeHint() const override { return {120, 120}; }

protected:
    void paintEvent(QPaintEvent*) override;
    void showEvent(QShowEvent*) override;
    void hideEvent(QHideEvent*) override;

private:
    bool live() const;
    void syncAnimation();

    State m_state = State::Unknown;
    QTimer* m_timer = nullptr;
    QElapsedTimer m_clock;
    bool m_motionAllowed = true;
};
