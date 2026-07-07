#pragma once
#include <QAbstractButton>

// An iOS-style on/off switch (checkable). Track turns accent when on; the knob
// sits right (on) / left (off). Used on the Settings page.
class ToggleSwitch : public QAbstractButton
{
    Q_OBJECT
public:
    explicit ToggleSwitch(bool on = true, QWidget* parent = nullptr);
    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent*) override;
};
