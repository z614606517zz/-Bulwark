#pragma once
#include <QColor>
#include <QDialog>
#include <QPoint>
#include <QString>

#include <functional>

class BannerHost;
class GlowCard;
class IconTile;
class QHBoxLayout;
class QLabel;
class QPropertyAnimation;
class QVariantAnimation;
class QPushButton;
class QToolButton;
class QVBoxLayout;

// The design's dialog: a frameless floating card — no native title bar, no
// white frame — that can be dragged by any empty area and closed with Esc.
// Behavior prompts, confirmations, the rule builder, adoption lists and the
// update dialog are all Sheets, so every question the product asks looks and
// behaves the same.
//
//   ▌EYEBROW                                   (optional, tinted strip)
//   [tile] Title                           ✕
//          subtitle
//   [banners]
//   body …
//   [left footer items]          [secondary] [primary]
//
// It is still a QDialog: exec() / accept() / reject() work as usual, and
// reject() is what Esc and ✕ trigger (so "closing" a question always takes the
// conservative path the caller assigned to reject()).
//
// It enters and leaves with a short move + fade (see done()): a centred sheet
// rises into place and sinks back out, a corner sheet slides in and out of its
// corner. The answer is decided the moment the caller's button handler runs —
// the exit animation only delays when the dialog closes, never what it returns.
class Sheet : public QDialog
{
    Q_OBJECT
public:
    explicit Sheet(QWidget* parent = nullptr);

    // Closes exactly as QDialog does — immediately, with `result` — and leaves a
    // picture of the sheet behind to play the exit animation (move + fade) where
    // it stood. Nothing about exec()'s return, the signals or their timing
    // changes: holding the dialog open for the animation would delay the state
    // every caller reads on the next line, and a window still open when the
    // application asks it to close cancels the quit.
    void done(int result) override;

    void setHeader(const QString& icon, const QColor& tone, const QString& title,
                   const QString& subtitle = QString());
    void setEyebrow(const QString& text, const QColor& color);
    // Breathes the eyebrow's tone strip — the element that carries the sheet's
    // risk — for as long as the sheet is on screen. Used by the behavior prompt
    // at the top of the risk scale (riskScore >= 80): the strip is cinnabar
    // either way, the pulse only makes it harder to click past. It moves nothing
    // and adds nothing; stopped, the strip is exactly its tone colour again.
    void setPulse(bool on);
    void setTitle(const QString& title);
    void setSubtitle(const QString& subtitle);
    void setGlow(const QColor& color);
    // Width of the card (the window adds the shadow margins).
    void setSheetWidth(int width);
    // ✕ button + Esc. Off for sheets that must be answered with a button.
    void setClosable(bool closable);
    bool isClosable() const { return m_closable; }
    // Hide just the ✕ (Esc still rejects) — for questions whose "close" has a
    // meaning the buttons already spell out.
    void setCloseButtonVisible(bool visible);
    QLabel* titleLabel() const { return m_title; }

    // Where the sheet lands when it is first shown (set before showing).
    //   CenterOnParent — centred over the owning window, else the screen under
    //                    the cursor (the default: confirmations, editors, …).
    //   BottomRight    — parked in the bottom-right corner of the primary screen,
    //                    the corner the toast stack uses (ToastNotifier), with
    //                    the card edges lined up with the toast cards. Grows and
    //                    shrinks upward from there (see refit()).
    enum class Placement { CenterOnParent, BottomRight };
    void setPlacement(Placement placement) { m_placement = placement; }
    Placement placement() const { return m_placement; }

    // Re-fit the height to the content (after expanding a section) and keep
    // the whole sheet on screen, without re-centring it. A BottomRight sheet
    // keeps its bottom edge where it is, so it grows upward instead of off the
    // bottom of the screen.
    void refit();

    QVBoxLayout* body() const { return m_body; }
    QHBoxLayout* footer() const { return m_footer; }
    void addFooterLeft(QWidget* w);
    // Appended right of the footer's stretch, in call order.
    QPushButton* addButton(const QString& text, const char* variant, std::function<void()> fn = {});
    BannerHost* banners() const { return m_banners; }
    GlowCard* card() const { return m_card; }

    // Max body height as a fraction of the screen (content beyond scrolls when
    // the caller put it in a scroll area; see PromptDialog).
    static int screenHeightFor(const QWidget* anchor, qreal fraction);

protected:
    void showEvent(QShowEvent* e) override;
    void hideEvent(QHideEvent* e) override;
    void keyPressEvent(QKeyEvent* e) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseMoveEvent(QMouseEvent* e) override;
    void mouseReleaseEvent(QMouseEvent* e) override;

private:
    void placeOnScreen();
    void fitHeight();
    // Where the sheet comes from / goes to, relative to its resting place.
    QPoint travel() const;
    void startEnter();
    // Cuts a running enter animation to its end (before anything reads or sets
    // the sheet's geometry: a drag, refit()).
    void settleEnter();
    // Runs the pulse only while it can be seen and is still wanted.
    void syncPulse();
    // Leaves a picture of the sheet behind to animate out of the way (done()).
    void playExit();

    GlowCard* m_card = nullptr;
    QWidget* m_eyebrowRow = nullptr;
    QWidget* m_strip = nullptr;
    QLabel* m_eyebrow = nullptr;
    IconTile* m_tile = nullptr;
    QLabel* m_title = nullptr;
    QLabel* m_subtitle = nullptr;
    QToolButton* m_close = nullptr;
    BannerHost* m_banners = nullptr;
    QVBoxLayout* m_body = nullptr;
    QHBoxLayout* m_footer = nullptr;
    QWidget* m_footerHost = nullptr;
    int m_footerLeft = 0;
    Placement m_placement = Placement::CenterOnParent;
    bool m_closable = true;
    bool m_placed = false;
    bool m_dragging = false;
    QPoint m_dragOffset;

    QPropertyAnimation* m_fade = nullptr;
    QPropertyAnimation* m_move = nullptr;
    QVariantAnimation* m_pulse = nullptr;
    QPoint m_restPos;        // where the sheet sits once it has arrived
    bool m_entering = false;
    bool m_pulseWanted = false;
};
