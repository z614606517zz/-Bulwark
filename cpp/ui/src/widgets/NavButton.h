#pragma once
#include <QAbstractButton>

// A sidebar navigation item: icon + label, checkable, with hover/active states
// (active = soft fill + left accent bar + accent icon). Fully custom-painted so
// it needs no child widgets and stays crisp on the dark theme.
class NavButton : public QAbstractButton
{
    Q_OBJECT
public:
    NavButton(const QString& iconName, const QString& text, QWidget* parent = nullptr);
    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent*) override;
    void enterEvent(QEnterEvent*) override;
    void leaveEvent(QEvent*) override;

private:
    QString m_icon;
    bool m_hover = false;
};
