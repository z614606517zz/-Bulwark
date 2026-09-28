#pragma once
#include <QLayout>
#include <QList>
#include <QRect>

// A layout that places items left to right and wraps onto a new line when the
// row is full — for tag / chip clouds whose count isn't known in advance
// (ATT&CK techniques on the behavior prompt, rule conditions, IOC tags). Unlike
// an HBox it never clips an item or forces its parent wider; unlike a fixed
// grid it doesn't leave holes.
//
// Height-for-width aware: a parent layout that honours heightForWidth (every
// QBoxLayout / QGridLayout does) grows the row count as the width shrinks.
class FlowLayout : public QLayout
{
public:
    explicit FlowLayout(QWidget* parent = nullptr, int hSpacing = 6, int vSpacing = 6);
    ~FlowLayout() override;

    void addItem(QLayoutItem* item) override;
    int count() const override;
    QLayoutItem* itemAt(int index) const override;
    QLayoutItem* takeAt(int index) override;

    Qt::Orientations expandingDirections() const override;
    bool hasHeightForWidth() const override;
    int heightForWidth(int width) const override;
    QSize minimumSize() const override;
    QSize sizeHint() const override;
    void setGeometry(const QRect& rect) override;

    // Removes every item and deletes the widgets they held.
    void clear();

private:
    int doLayout(const QRect& rect, bool testOnly) const;

    QList<QLayoutItem*> m_items;
    int m_hSpace;
    int m_vSpace;
};
