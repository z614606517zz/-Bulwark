#pragma once
#include <QColor>
#include <QIcon>
#include <QPixmap>
#include <QSize>
#include <QString>
#include <QWidget>

// A crisp, self-contained stroke-icon widget drawn with QPainter (Feather /
// Lucide style, authored on a 24x24 grid). No icon font or SVG assets to
// bundle. Set `name` to one of the keys handled in paintEvent(); colour and
// pixel size are themeable. Use AppIcon::draw() to paint an icon inside another
// widget's paintEvent (e.g. nav buttons) without a child widget.
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

    // Paint `name` centred in `rect` using `color`. Reusable from any paintEvent.
    static void draw(QPainter& p, const QString& name, const QRectF& rect,
                     const QColor& color, qreal penWidth = 1.8);

    // Render an icon to a (2x, transparent) pixmap / QIcon — for QLineEdit
    // actions, QPushButton icons, etc.
    static QPixmap pixmap(const QString& name, const QColor& color, int px,
                          qreal penWidth = 1.8);
    static QIcon icon(const QString& name, const QColor& color, int px);

    // The application's brand badge: a filled teal rounded-square with a white
    // shield. Returned as a multi-size QIcon so Windows can pick a crisp variant
    // for the title bar (16px), taskbar (32/48px) and Alt-Tab (256px). Used as
    // the window icon, the app-wide icon, and the system-tray icon.
    static QIcon appBadge();

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QString m_name;
    QColor m_color;
    int m_px = 20;
};
