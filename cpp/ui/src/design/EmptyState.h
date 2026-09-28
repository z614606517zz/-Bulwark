#pragma once
#include <QColor>
#include <QString>
#include <QWidget>

#include <functional>

class IconTile;
class QLabel;
class QPushButton;

// What a list shows when it has nothing to show — and why. Three situations
// read very differently and must not share one "暂无数据":
//   • not connected to the service  → the data is unknown, not empty;
//   • connected, genuinely nothing  → offer the page's own next step
//                                     (「立即扫描」, 「新增规则」…);
//   • data exists but the filter    → say so, and offer 「清除筛选」.
//     hides all of it
// ListShell picks the situation; this widget only renders it.
class EmptyState : public QWidget
{
public:
    explicit EmptyState(QWidget* parent = nullptr);

    void setContent(const QString& icon, const QColor& color, const QString& title,
                    const QString& body);
    // Empty `text` hides the button.
    void setAction(const QString& text, std::function<void()> fn, const char* variant = "ghost");

private:
    IconTile* m_tile = nullptr;
    QLabel* m_title = nullptr;
    QLabel* m_body = nullptr;
    QPushButton* m_action = nullptr;
    std::function<void()> m_fn;
};
