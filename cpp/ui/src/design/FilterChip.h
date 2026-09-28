#pragma once
#include <QAbstractButton>
#include <QList>
#include <QPair>
#include <QVariant>

// A drop-down filter "chip" for a list page's filter bar: "类型 ▾". Clicking opens
// a menu of mutually exclusive options; picking anything other than the first
// ("全部") turns the chip active — tinted, and spelling out the choice
// ("类型 · 文件写入") — so an applied filter can't go unnoticed while the list
// looks emptier than expected.
//
// Keyboard: Space / Enter / ↓ open the menu. Accessible name reads
// "类型:文件写入".
class FilterChip : public QAbstractButton
{
    Q_OBJECT
public:
    explicit FilterChip(const QString& label, QWidget* parent = nullptr);

    // Option 0 is the neutral "no filter" choice.
    void addOption(const QString& text, const QVariant& value = QVariant());
    void clearOptions();
    int optionCount() const { return int(m_options.size()); }

    int currentIndex() const { return m_index; }
    QVariant currentData() const;
    QString currentText() const;
    // Emits currentChanged() when the index actually changes.
    void setCurrentIndex(int index);
    void reset() { setCurrentIndex(0); }
    bool isActive() const { return m_index > 0; }

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override { return sizeHint(); }

signals:
    void currentChanged(int index);

protected:
    void paintEvent(QPaintEvent*) override;
    void enterEvent(QEnterEvent*) override;
    void leaveEvent(QEvent*) override;
    void focusInEvent(QFocusEvent*) override;
    void focusOutEvent(QFocusEvent*) override;
    void keyPressEvent(QKeyEvent*) override;

private:
    QString shownText() const;
    void openMenu();
    void syncAccessible();

    QString m_label;
    QList<QPair<QString, QVariant>> m_options;
    int m_index = 0;
    bool m_hover = false;
    bool m_keyboardFocus = false;
};
