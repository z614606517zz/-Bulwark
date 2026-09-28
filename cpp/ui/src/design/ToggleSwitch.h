#pragma once
#include <QAbstractButton>

class QVariantAnimation;

// An on/off switch (checkable). The track fills with the jade brand fill when on
// and the knob glides across (~140 ms) when the user flips it. Programmatic
// setChecked() — including under a QSignalBlocker, which is how pages apply
// settings pushed by the service — snaps the knob immediately, so the switch
// can never show a state different from isChecked().
class ToggleSwitch : public QAbstractButton
{
    Q_OBJECT
public:
    explicit ToggleSwitch(bool on = true, QWidget* parent = nullptr);
    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent*) override;
    void checkStateSet() override;
    void nextCheckState() override;
    void enterEvent(QEnterEvent*) override;
    void leaveEvent(QEvent*) override;
    void focusInEvent(QFocusEvent*) override;
    void focusOutEvent(QFocusEvent*) override;

private:
    qreal m_pos = 1.0; // knob position: 0 = off, 1 = on
    bool m_hover = false;
    bool m_keyboardFocus = false;
    QVariantAnimation* m_anim = nullptr;
};
