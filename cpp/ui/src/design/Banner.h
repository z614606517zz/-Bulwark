#pragma once
#include "design/Tone.h"

#include <QElapsedTimer>
#include <QFrame>
#include <QList>
#include <QPoint>
#include <QPointer>
#include <QString>

#include <functional>

class QHBoxLayout;
class QLabel;
class QPushButton;
class QTimer;
class QVBoxLayout;

// An in-page message strip — the replacement for "操作成功" message boxes.
//
//   success / info   dismiss themselves after a few seconds (hover pauses — by
//                    where the pointer really is, see syncHoverPause());
//   warning          stays a little longer;
//   danger           stays until closed: a failure message carries the reason,
//                    and a reason the user never got to read is a silent failure.
//
// Tone is carried by a left strip, a glyph and a soft tint — never by colour
// alone (the glyph and the text say it too).
class Banner : public QFrame
{
    Q_OBJECT
public:
    Banner(ui::Tone tone, const QString& text, QWidget* parent = nullptr);

    ui::Tone tone() const { return m_tone; }
    QString text() const;
    void setText(const QString& text);
    // A single inline action ("撤销", "查看详情"…). Clicking it also dismisses.
    void setAction(const QString& text, std::function<void()> fn);
    // 0 = sticky (until closed). Restarts the countdown.
    void setTimeout(int ms);
    void dismiss();

signals:
    void dismissed();

protected:
    void paintEvent(QPaintEvent*) override;

private:
    void syncHoverPause();

    ui::Tone m_tone;
    QLabel* m_text = nullptr;
    QPushButton* m_action = nullptr;
    std::function<void()> m_fn;
    QTimer* m_timer = nullptr;
    int m_remaining = 0;
    QElapsedTimer m_since;
    bool m_closing = false;

    // 悬停暂停(同 CountdownBar:按指针真实位置判定,不用 enter/leave)
    QTimer* m_hoverWatch = nullptr;
    QPoint m_lastCursor;
    bool m_hoverArmed = false; // 指针在这条提示上动过
    bool m_holding = false;    // 正因悬停而停着
};

// A vertical stack of banners at the top of a page or sheet. At most three are
// kept (the oldest goes first); posting the same text again refreshes the
// existing banner instead of stacking a duplicate.
class BannerHost : public QWidget
{
    Q_OBJECT
public:
    explicit BannerHost(QWidget* parent = nullptr);

    // timeoutMs < 0 = the tone's default (success 4.5 s · info 5 s · warning 9 s ·
    // danger sticky).
    Banner* post(ui::Tone tone, const QString& text, int timeoutMs = -1);
    // Dismisses every banner. `animated` = false removes them at once (a page
    // transition already fades them out with the page they belonged to).
    void clear(bool animated = true);

    // The host responsible for `from`: the nearest one found by walking up the
    // parent chain (checking each ancestor's direct children), stopping at the
    // window. MainWindow keeps one under the page header for every page.
    static BannerHost* find(QWidget* from);

private:
    QVBoxLayout* m_stack = nullptr;
    QList<QPointer<Banner>> m_banners;
};

namespace ui {

// Post a message into the banner host responsible for `context` (see
// BannerHost::find). Falls back to a tooltip-style flash at `context` if no host
// exists, so a message is never dropped on the floor.
Banner* notify(QWidget* context, Tone tone, const QString& text, int timeoutMs = -1);

} // namespace ui
