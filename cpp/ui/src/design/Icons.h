#pragma once
#include <QColor>
#include <QIcon>
#include <QPixmap>
#include <QSize>
#include <QString>
#include <QWidget>

class QPainter;
class QPainterPath;

// The design's icon set: crisp stroke glyphs drawn with QPainter on a 24x24
// grid (Lucide geometry, round caps and joins). No icon font, SVG plugin or
// bitmap assets to ship — everything renders at the exact device pixel size.
//
// Use the widget for a standalone glyph, AppIcon::draw() inside another
// widget's paintEvent, and pixmap()/icon() for QLineEdit actions, button icons
// and the like. Unknown names draw a small ring so a typo is visible, not blank.
//
// Glyphs: dashboard, shield, shield-x, shield-alert, trust (= shield-check),
// activity, clock, target, sliders, lock, power, cloud, link, sparkles,
// settings, search, close, check, alert, info, refresh, refresh-cw, file,
// chevron (= chevron-right), chevron-left, chevron-down, chevron-up,
// chevrons-left, chevrons-right, arrow-right, arrow-left, arrow-up, plus,
// minus, trash, eye, globe, cpu, server, layers, zap, more, copy, folder,
// upload, download, pause, play, filter, external, panel-left, check-circle,
// x-circle, bar-chart, list, tree, hash, terminal, user, key, bell, undo,
// maximize, minimize, pin, calendar.
class AppIcon : public QWidget
{
    Q_OBJECT
public:
    explicit AppIcon(const QString& name = QString(), QWidget* parent = nullptr);

    void setName(const QString& name);
    QString name() const { return m_name; }

    void setColor(const QColor& c);
    QColor color() const { return m_color; }

    void setPx(int px);
    int px() const { return m_px; }

    QSize sizeHint() const override { return {m_px, m_px}; }

    // Paint `name` centred in `rect` in `color`. penWidth is in device-independent
    // pixels at the final size (not grid units).
    static void draw(QPainter& p, const QString& name, const QRectF& rect,
                     const QColor& color, qreal penWidth = 1.7);

    // Render to a transparent, high-DPI pixmap / icon.
    static QPixmap pixmap(const QString& name, const QColor& color, int px,
                          qreal penWidth = 1.7);
    static QIcon icon(const QString& name, const QColor& color, int px);

    // The shield outline on the 24-grid (shared by glyphs, the brand mark and
    // the dashboard emblem so every shield in the product is the same shield).
    static QPainterPath shieldPath();

    // The brand mark: a jade rounded square (brass bezel from 28 px up) with an
    // ivory shield carrying a check. drawBadge() paints it into any rect; appBadge()
    // bakes it at every size Windows asks for (title bar 16 → Alt-Tab 256) and is
    // used for the window, taskbar, tray and exported .ico.
    static void drawBadge(QPainter& p, const QRectF& rect);
    static QIcon appBadge();

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QString m_name;
    QColor m_color;
    int m_px = 20;
};
