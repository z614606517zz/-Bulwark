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
class Sheet : public QDialog
{
    Q_OBJECT
public:
    explicit Sheet(QWidget* parent = nullptr);

    void setHeader(const QString& icon, const QColor& tone, const QString& title,
                   const QString& subtitle = QString());
    void setEyebrow(const QString& text, const QColor& color);
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
    // Re-fit the height to the content (after expanding a section) and keep
    // the whole sheet on screen, without re-centring it.
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
    void keyPressEvent(QKeyEvent* e) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseMoveEvent(QMouseEvent* e) override;
    void mouseReleaseEvent(QMouseEvent* e) override;

private:
    void placeOnScreen();
    void fitHeight();

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
    bool m_closable = true;
    bool m_placed = false;
    bool m_dragging = false;
    QPoint m_dragOffset;
};
