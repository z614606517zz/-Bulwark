#include "design/Theme.h"
#include "design/Icons.h"
#include "design/Motion.h"
#include "design/Ripple.h"

#include <QApplication>
#include <QDir>
#include <QEvent>
#include <QFont>
#include <QGuiApplication>
#include <QImage>
#include <QPainter>
#include <QPalette>
#include <QPixmap>
#include <QRandomGenerator>
#include <QStyle>
#include <QStyleFactory>
#include <QStyleHints>
#include <QTemporaryDir>
#include <QToolTip>
#include <QWidget>

#include <initializer_list>
#include <memory>
#include <utility>

#ifdef Q_OS_WIN
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <dwmapi.h>
#endif

namespace theme {
namespace {

// ---- glyph images for the style sheet ---------------------------------------
//
// A few sub-controls (combo / spin arrows, the check mark, header sort arrows,
// the line-edit clear button) can only be themed through `image: url(...)` in
// a style sheet. Rather than shipping bitmaps, the same AppIcon glyphs used
// everywhere else are rendered once per launch into a private temporary folder
// (random name, per-user temp, removed again at exit) and referenced from there.
// If the folder can't be created the arrows simply don't render — nothing else
// depends on it.
QString glyphDir()
{
    static std::unique_ptr<QTemporaryDir> dir;
    static QString path;
    if (dir)
        return path;

    dir = std::make_unique<QTemporaryDir>(QDir::tempPath() + QStringLiteral("/bulwark-ui-XXXXXX"));
    if (!dir->isValid())
        return path; // empty: urls resolve to nothing, sub-controls stay blank

    path = QDir::fromNativeSeparators(dir->path());

    struct Glyph {
        const char* file;
        const char* icon;
        QColor color;
        int px;      // bitmap size; drawn scaled down, so it stays crisp at 200-300 %
        qreal inset; // empty margin around the glyph inside the bitmap
        qreal pen;   // stroke width in bitmap pixels
    };
    const Glyph glyphs[] = {
        {"chevron-down.png",          "chevron-down", textSecondary(), 36, 2.0, 3.4},
        {"chevron-down-disabled.png", "chevron-down", textDisabled(),  36, 2.0, 3.4},
        {"chevron-up.png",            "chevron-up",   textSecondary(), 36, 2.0, 3.4},
        {"chevron-up-disabled.png",   "chevron-up",   textDisabled(),  36, 2.0, 3.4},
        {"sort-down.png",             "chevron-down", textMuted(),     36, 2.0, 3.6},
        {"sort-up.png",               "chevron-up",   textMuted(),     36, 2.0, 3.6},
        {"check.png",                 "check",        accentInk(),     48, 9.0, 5.0},
        {"clear.png",                 "close",        textMuted(),     32, 8.0, 2.8},
    };
    for (const Glyph& g : glyphs) {
        QImage img(g.px, g.px, QImage::Format_ARGB32_Premultiplied);
        img.fill(Qt::transparent);
        {
            QPainter p(&img);
            AppIcon::draw(p, QString::fromLatin1(g.icon),
                          QRectF(g.inset, g.inset, g.px - 2 * g.inset, g.px - 2 * g.inset),
                          g.color, g.pen);
        }
        img.save(path + QLatin1Char('/') + QLatin1String(g.file), "PNG");
    }
    return path;
}

QPalette makePalette()
{
    QPalette p;
    p.setColor(QPalette::Window, bg());
    p.setColor(QPalette::WindowText, textPrimary());
    p.setColor(QPalette::Base, field());
    p.setColor(QPalette::AlternateBase, surfaceAlt());
    p.setColor(QPalette::ToolTipBase, raised());
    p.setColor(QPalette::ToolTipText, textPrimary());
    p.setColor(QPalette::PlaceholderText, textMuted());
    p.setColor(QPalette::Text, textPrimary());
    p.setColor(QPalette::Button, surfaceAlt());
    p.setColor(QPalette::ButtonText, textPrimary());
    p.setColor(QPalette::BrightText, accentInk());
    p.setColor(QPalette::Light, borderLit());
    p.setColor(QPalette::Midlight, borderStrong());
    p.setColor(QPalette::Mid, border());
    p.setColor(QPalette::Dark, blend(QColor(0, 0, 0), bg(), 0.5));
    p.setColor(QPalette::Shadow, QColor(0, 0, 0));
    p.setColor(QPalette::Highlight, accentStrong());
    p.setColor(QPalette::HighlightedText, accentInk());
    p.setColor(QPalette::Link, accent());
    p.setColor(QPalette::LinkVisited, accentAlt());
#if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
    p.setColor(QPalette::Accent, accent());
#endif
    for (const auto role : {QPalette::WindowText, QPalette::Text, QPalette::ButtonText,
                            QPalette::HighlightedText, QPalette::PlaceholderText})
        p.setColor(QPalette::Disabled, role, textDisabled());
    p.setColor(QPalette::Disabled, QPalette::Highlight, surfaceHi());
    return p;
}

#ifdef Q_OS_WIN
COLORREF colorRef(const QColor& c)
{
    return RGB(c.red(), c.green(), c.blue());
}

// Native window chrome on Windows:
//  • framed windows (main window, detail dialogs, message boxes) get a dark
//    title bar whose caption colour is the canvas colour, so the title bar and
//    the app read as one surface;
//  • popups and tooltips get Windows 11's small rounded corners and a rim in
//    the design's border colour.
// Frameless / translucent windows draw their own card and are left alone. The
// colour attributes need Windows 11; on Windows 10 they fail harmlessly and
// only the dark title bar applies.
void applyNativeChrome(QWidget* w)
{
    if (!w->testAttribute(Qt::WA_WState_Created))
        return; // never force a native handle into existence from here
    const HWND hwnd = reinterpret_cast<HWND>(w->winId());
    if (!hwnd)
        return;

    // DWMWINDOWATTRIBUTE ids, spelled out so the file also builds against SDKs
    // that predate them.
    constexpr DWORD kDarkModeLegacy = 19;  // Windows 10 1809-1909
    constexpr DWORD kDarkMode       = 20;  // DWMWA_USE_IMMERSIVE_DARK_MODE
    constexpr DWORD kCorner         = 33;  // DWMWA_WINDOW_CORNER_PREFERENCE
    constexpr DWORD kBorderColor    = 34;  // DWMWA_BORDER_COLOR
    constexpr DWORD kCaptionColor   = 35;  // DWMWA_CAPTION_COLOR
    constexpr DWORD kTextColor      = 36;  // DWMWA_TEXT_COLOR
    constexpr DWORD kRoundSmall     = 3;   // DWMWCP_ROUNDSMALL

    const Qt::WindowType type = w->windowType();
    const bool translucent = w->testAttribute(Qt::WA_TranslucentBackground);

    if (type == Qt::Popup || type == Qt::ToolTip) {
        if (translucent)
            return;
        const DWORD corner = kRoundSmall;
        DwmSetWindowAttribute(hwnd, kCorner, &corner, sizeof(corner));
        const COLORREF rim = colorRef(borderStrong());
        DwmSetWindowAttribute(hwnd, kBorderColor, &rim, sizeof(rim));
        return;
    }
    if (translucent || w->windowFlags().testFlag(Qt::FramelessWindowHint))
        return;

    const BOOL dark = TRUE;
    if (FAILED(DwmSetWindowAttribute(hwnd, kDarkMode, &dark, sizeof(dark))))
        DwmSetWindowAttribute(hwnd, kDarkModeLegacy, &dark, sizeof(dark));
    const COLORREF caption = colorRef(bg());
    DwmSetWindowAttribute(hwnd, kCaptionColor, &caption, sizeof(caption));
    const COLORREF text = colorRef(textSecondary());
    DwmSetWindowAttribute(hwnd, kTextColor, &text, sizeof(text));
    const COLORREF rim = colorRef(border());
    DwmSetWindowAttribute(hwnd, kBorderColor, &rim, sizeof(rim));
}

// Applies the chrome to every top-level window just before it first appears
// (Show is delivered after the native window exists but before it is mapped, so
// there is no flash of a light title bar), and again if the handle is recreated.
class NativeChromeFilter final : public QObject
{
public:
    using QObject::QObject;

protected:
    bool eventFilter(QObject* obj, QEvent* ev) override
    {
        const QEvent::Type t = ev->type();
        if ((t == QEvent::Show || t == QEvent::WinIdChange) && obj->isWidgetType()) {
            auto* w = static_cast<QWidget*>(obj);
            if (w->isWindow())
                applyNativeChrome(w);
        }
        return QObject::eventFilter(obj, ev);
    }
};
#endif

// Replaces every "@{name}" in `qss` with the matching value.
QString bake(QString qss, std::initializer_list<std::pair<const char*, QString>> vars)
{
    for (const auto& [key, value] : vars)
        qss.replace(QStringLiteral("@{") + QLatin1String(key) + QLatin1Char('}'), value);
    return qss;
}

QString hex(const QColor& c) { return c.name(QColor::HexRgb); }

} // namespace

QBrush canvasBrush()
{
    static QPixmap tile;
    if (tile.isNull()) {
        constexpr int step = 22;
        tile = QPixmap(step, step);
        tile.fill(bg());
        QPainter p(&tile);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(Qt::NoPen);
        p.setBrush(blend(textPrimary(), bg(), 0.11));
        p.drawEllipse(QPointF(step / 2.0, step / 2.0), 1.0, 1.0);
    }
    return QBrush(tile);
}

QBrush grainBrush()
{
    static QImage tile;
    if (tile.isNull()) {
        // 128 px is large enough that the repeat never reads as a pattern. Each grain
        // is either a light or a dark speck at up to ~3 % opacity (premultiplied) —
        // felt as a material, not seen as noise.
        constexpr int n = 128;
        tile = QImage(n, n, QImage::Format_ARGB32_Premultiplied);
        QRandomGenerator gen(0x5EED0B1Du);
        for (int y = 0; y < n; ++y) {
            auto* line = reinterpret_cast<QRgb*>(tile.scanLine(y));
            for (int x = 0; x < n; ++x) {
                const quint32 r = gen.generate();
                const int a = int(r % 9u);
                const int v = (r & 0x100u) ? a : 0; // light speck: premultiplied white; dark speck: black
                line[x] = qRgba(v, v, v, a);
            }
        }
    }
    return QBrush(tile);
}

QString styleSheet()
{
    // Widgets opt into variants through dynamic properties:
    //   label->setProperty("role", "h1");         display | h1 | h2 | title | secondary |
    //                                              muted | caption | eyebrow | stat | mono | link
    //   button->setProperty("variant", "primary"); primary | ghost | danger
    //   button->setProperty("size", "sm");
    //
    // Deliberately no rule on the universal QWidget selector: containers stay
    // transparent so the canvas light (design/Backdrop) shows between cards,
    // text colour comes from the palette, and cards paint themselves
    // (design/GlowCard) — which keeps this sheet small and hard to break.
    static const char* const kSheet = R"QSS(
/* ── base ─────────────────────────────────────────────────────────────── */
QLabel { background: transparent; }
QToolTip {
    background-color: @{raised};
    color: @{text};
    border: 1px solid @{borderStrong};
    padding: 6px 9px;
}

/* ── text roles ───────────────────────────────────────────────────────── */
QLabel[role="display"]   { font-size: 21pt; font-weight: 700; color: @{text}; }
QLabel[role="h1"]        { font-size: 16pt; font-weight: 700; color: @{text}; }
QLabel[role="h2"]        { font-size: 12pt; font-weight: 600; color: @{text}; }
QLabel[role="title"]     { font-size: 10.5pt; font-weight: 600; color: @{text}; }
QLabel[role="secondary"] { color: @{textSecondary}; }
QLabel[role="muted"]     { color: @{textMuted}; font-size: 9pt; }
QLabel[role="caption"]   { color: @{textMuted}; font-size: 9pt; font-weight: 600; }
QLabel[role="eyebrow"]   { color: @{textMuted}; font-size: 9pt; font-weight: 700; }
QLabel[role="stat"]      { font-size: 22pt; font-weight: 700; color: @{text}; }
QLabel[role="mono"]      { font-family: "Cascadia Mono", "Consolas"; color: @{textSecondary}; }
QLabel[role="link"]      { color: @{accent}; }
QLabel[role="lead"]      { font-size: 11pt; font-weight: 600; color: @{text}; }

/* ── containers ───────────────────────────────────────────────────────── */
QFrame#Divider { background-color: @{border}; border: none; }
QFrame#Topbar  { background: transparent; border: none; border-bottom: 1px solid @{border}; }
QScrollArea    { background: transparent; border: none; }
QAbstractScrollArea::corner { background: transparent; border: none; }

/* ── navigation rail: its own jade-ink plane (design/Backdrop) ────────── */
QWidget#Sidebar QFrame#Divider { background-color: @{railBorder}; }
QWidget#Sidebar QLabel[role="muted"], QWidget#Sidebar QLabel[role="eyebrow"] { color: @{railMuted}; }
QWidget#Sidebar QToolButton:hover { background-color: @{railHover}; }
QWidget#Sidebar QToolButton#SidebarToggle { color: @{railMuted}; }
QWidget#Sidebar QToolButton#SidebarToggle:hover { color: @{text}; }

/* ── buttons ──────────────────────────────────────────────────────────── */
QPushButton {
    background-color: @{surfaceAlt};
    color: @{text};
    border: 1px solid @{borderStrong};
    border-radius: 10px;
    padding: 7px 16px;
    font-weight: 600;
    outline: none;
}
QPushButton:hover    { background-color: @{surfaceHi}; border-color: @{borderHover}; }
QPushButton:pressed  { background-color: @{surface}; }
QPushButton:focus    { border-color: @{accent}; }
QPushButton:disabled { color: @{textDisabled}; background-color: @{surface}; border-color: @{border}; }

QPushButton[variant="primary"] {
    color: @{accentInk};
    border: 1px solid @{accentStrong};
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 @{accentStrong}, stop:1 @{accentDeep});
}
QPushButton[variant="primary"]:hover   { border-color: @{accentSoft}; }
QPushButton[variant="primary"]:pressed {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 @{accentStrongDown}, stop:1 @{accentDeepDown});
}
QPushButton[variant="primary"]:focus    { border-color: @{focusOnAccent}; }
QPushButton[variant="primary"]:disabled { color: @{textDisabled}; background-color: @{surfaceAlt}; border-color: @{border}; }

QPushButton[variant="ghost"]          { background-color: transparent; color: @{textSecondary}; border: 1px solid @{borderStrong}; }
QPushButton[variant="ghost"]:hover    { background-color: @{surfaceAlt}; color: @{text}; border-color: @{borderHover}; }
QPushButton[variant="ghost"]:pressed  { background-color: @{surface}; }
QPushButton[variant="ghost"]:focus    { border-color: @{accent}; }
QPushButton[variant="ghost"]:disabled { background-color: transparent; color: @{textDisabled}; border-color: @{border}; }

QPushButton[variant="danger"]          { background-color: @{dangerFill}; color: @{danger}; border: 1px solid @{dangerRim}; }
QPushButton[variant="danger"]:hover    { background-color: @{dangerFillHover}; border-color: @{dangerRimHover}; }
QPushButton[variant="danger"]:pressed  { background-color: @{dangerFill}; }
QPushButton[variant="danger"]:focus    { border-color: @{danger}; }
QPushButton[variant="danger"]:disabled { background-color: @{surface}; color: @{textDisabled}; border-color: @{border}; }

QPushButton[size="sm"] { padding: 4px 11px; font-size: 9pt; border-radius: 8px; }

QToolButton         { background: transparent; border: 1px solid transparent; border-radius: 8px; padding: 4px; color: @{textSecondary}; }
QToolButton:hover   { background-color: @{surfaceAlt}; }
QToolButton:pressed { background-color: @{surfaceHi}; }
QToolButton:focus   { border: 1px solid @{accent}; }
QToolButton#MoreButton::menu-indicator { image: none; width: 0px; }
QToolButton#SidebarToggle { color: @{textMuted}; padding: 6px 8px; font-size: 9pt; }
QToolButton#SidebarToggle:hover { color: @{text}; }

/* ── inputs ───────────────────────────────────────────────────────────── */
QLineEdit, QComboBox, QAbstractSpinBox, QPlainTextEdit, QTextEdit {
    background-color: @{field};
    color: @{text};
    border: 1px solid @{borderStrong};
    border-radius: 10px;
    padding: 6px 10px;
    selection-background-color: @{accentStrong};
    selection-color: @{accentInk};
}
QLineEdit:hover, QComboBox:hover, QAbstractSpinBox:hover, QPlainTextEdit:hover, QTextEdit:hover {
    border-color: @{borderHover};
}
QLineEdit:focus, QComboBox:focus, QAbstractSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {
    border-color: @{accent};
}
QLineEdit:disabled, QComboBox:disabled, QAbstractSpinBox:disabled, QPlainTextEdit:disabled, QTextEdit:disabled {
    color: @{textDisabled}; background-color: @{bg}; border-color: @{border};
}
QPlainTextEdit, QTextEdit { padding: 6px 8px; }
QLineEdit { lineedit-clear-button-icon: url("@{glyphs}/clear.png"); }

/* Drop-down below the field (not the overlaid "menu" popup), so the list
   honours the item rules below. */
QComboBox { combobox-popup: 0; padding: 6px 8px 6px 12px; }
QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: center right;
    width: 24px;
    border: none;
    background: transparent;
}
QComboBox::down-arrow          { image: url("@{glyphs}/chevron-down.png"); width: 12px; height: 12px; }
QComboBox::down-arrow:on       { image: url("@{glyphs}/chevron-up.png"); }
QComboBox::down-arrow:disabled { image: url("@{glyphs}/chevron-down-disabled.png"); }
QComboBox QFrame {
    background-color: @{raised};
    border: 1px solid @{borderStrong};
}
QComboBox QAbstractItemView {
    background-color: @{raised};
    color: @{text};
    border: none;
    border-radius: 0px;
    padding: 4px;
    outline: none;
    selection-background-color: @{surfaceHi};
    selection-color: @{text};
}
QComboBox QAbstractItemView::item          { min-height: 30px; padding: 0px 10px; border-radius: 6px; }
QComboBox QAbstractItemView::item:hover    { background-color: @{surfaceAlt}; }
QComboBox QAbstractItemView::item:selected { background-color: @{surfaceHi}; color: @{text}; }

QAbstractSpinBox { padding-right: 28px; }
QAbstractSpinBox::up-button, QAbstractSpinBox::down-button {
    subcontrol-origin: border;
    width: 22px;
    border: none;
    background: transparent;
}
QAbstractSpinBox::up-button   { subcontrol-position: top right; margin: 4px 4px 0px 0px; border-top-right-radius: 7px; }
QAbstractSpinBox::down-button { subcontrol-position: bottom right; margin: 0px 4px 4px 0px; border-bottom-right-radius: 7px; }
QAbstractSpinBox::up-button:hover, QAbstractSpinBox::down-button:hover { background-color: @{surfaceAlt}; }
QAbstractSpinBox::up-arrow   { image: url("@{glyphs}/chevron-up.png"); width: 10px; height: 10px; }
QAbstractSpinBox::down-arrow { image: url("@{glyphs}/chevron-down.png"); width: 10px; height: 10px; }
QAbstractSpinBox::up-arrow:disabled, QAbstractSpinBox::up-arrow:off {
    image: url("@{glyphs}/chevron-up-disabled.png");
}
QAbstractSpinBox::down-arrow:disabled, QAbstractSpinBox::down-arrow:off {
    image: url("@{glyphs}/chevron-down-disabled.png");
}

/* ── check / radio ────────────────────────────────────────────────────── */
QCheckBox, QRadioButton { spacing: 8px; color: @{text}; background: transparent; outline: none; }
QCheckBox:disabled, QRadioButton:disabled { color: @{textDisabled}; }
QCheckBox::indicator {
    width: 18px; height: 18px; border-radius: 6px;
    border: 1px solid @{borderStrong}; background-color: @{field};
}
QCheckBox::indicator:hover { border-color: @{accent}; }
QCheckBox::indicator:checked {
    border: 1px solid @{accentStrong};
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 @{accentStrong}, stop:1 @{accentDeep});
    image: url("@{glyphs}/check.png");
}
QCheckBox::indicator:focus            { border-color: @{accentSoft}; }
QCheckBox::indicator:disabled         { background-color: @{bg}; border-color: @{border}; }
QCheckBox::indicator:checked:disabled { background-color: @{surfaceHi}; border-color: @{border}; }
QRadioButton::indicator {
    width: 18px; height: 18px; border-radius: 9px;
    border: 1px solid @{borderStrong}; background-color: @{field};
}
QRadioButton::indicator:hover { border-color: @{accent}; }
QRadioButton::indicator:checked {
    border: 1px solid @{accentStrong};
    background-color: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
        stop:0 @{accentInk}, stop:0.30 @{accentInk}, stop:0.40 @{accentStrong}, stop:1 @{accentStrong});
}

/* ── lists & tables ───────────────────────────────────────────────────── */
/* The 4px padding keeps the header and rows clear of the 14px corners, so
   nothing square pokes through the rounded rim. */
QTableView, QListView, QTreeView {
    background-color: @{surface};
    alternate-background-color: @{rowAlt};
    color: @{text};
    border: 1px solid @{border};
    border-radius: 14px;
    padding: 4px;
    gridline-color: @{border};
    outline: none;
    selection-background-color: @{selection};
    selection-color: @{text};
}
QTableView::item, QListView::item, QTreeView::item { border: none; padding: 0px 10px; }
QTableView::item:selected, QListView::item:selected, QTreeView::item:selected {
    background-color: @{selection}; color: @{text};
}
/* Record lists sit inside a card and paint their own rows (design/RecordDelegate). */
QListView#RecordList { background: transparent; border: none; border-radius: 0px; padding: 0px; }
QListView#RecordList::item { padding: 0px; border: none; }
/* The process list / tree sits inside a list card too (pages/ProcessesPage). */
QTreeView#ProcessTree { background: transparent; border: none; border-radius: 0px; padding: 0px 2px; }
QTreeView#ProcessTree::item { padding: 0px 8px; border: none; }
QHeaderView { background: transparent; border: none; }
QHeaderView::section {
    background-color: transparent;
    color: @{textMuted};
    border: none;
    border-bottom: 1px solid @{border};
    border-right: 1px solid @{border};
    padding: 9px 10px;
    font-size: 9pt;
    font-weight: 600;
}
QHeaderView::section:last, QHeaderView::section:only-one { border-right: none; }
QHeaderView::up-arrow {
    image: url("@{glyphs}/sort-up.png"); width: 10px; height: 10px;
    subcontrol-origin: padding; subcontrol-position: center right;
}
QHeaderView::down-arrow {
    image: url("@{glyphs}/sort-down.png"); width: 10px; height: 10px;
    subcontrol-origin: padding; subcontrol-position: center right;
}
QTableCornerButton::section { background: transparent; border: none; }

/* ── menus ────────────────────────────────────────────────────────────── */
QMenu {
    background-color: @{raised};
    color: @{text};
    border: 1px solid @{borderStrong};
    padding: 5px;
}
QMenu::item           { padding: 7px 26px 7px 12px; border-radius: 6px; background: transparent; }
QMenu::item:selected  { background-color: @{surfaceHi}; color: @{text}; }
QMenu::item:disabled  { color: @{textDisabled}; }
QMenu::separator      { height: 1px; background: @{border}; margin: 5px 6px; }

/* ── scroll bars ──────────────────────────────────────────────────────── */
QScrollBar:vertical   { background: transparent; width: 12px; margin: 0px; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 0px; }
QScrollBar::handle:vertical   { background-color: @{scroll}; min-height: 32px; border-radius: 3px; margin: 2px 3px; }
QScrollBar::handle:horizontal { background-color: @{scroll}; min-width: 32px; border-radius: 3px; margin: 3px 2px; }
QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover     { background-color: @{scrollHover}; }
QScrollBar::handle:vertical:pressed, QScrollBar::handle:horizontal:pressed { background-color: @{scrollPressed}; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0px; height: 0px; border: none; background: none; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }

/* ── progress ─────────────────────────────────────────────────────────── */
QProgressBar {
    background-color: @{field};
    border: 1px solid @{border};
    border-radius: 5px;
    min-height: 10px;
    max-height: 10px;
    text-align: center;
}
QProgressBar::chunk {
    border-radius: 4px;
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 @{accentStrong}, stop:1 @{accent});
}

/* ── standard dialogs ─────────────────────────────────────────────────── */
QMessageBox QLabel { color: @{text}; }
QDialogButtonBox QPushButton, QMessageBox QPushButton { min-width: 84px; }
)QSS";

    const QColor white(0xFF, 0xFF, 0xFF);
    return bake(QString::fromUtf8(kSheet), {
        {"bg",               hex(bg())},
        {"surface",          hex(surface())},
        {"surfaceAlt",       hex(surfaceAlt())},
        {"surfaceHi",        hex(surfaceHi())},
        {"raised",           hex(raised())},
        {"field",            hex(field())},
        {"borderStrong",     hex(borderStrong())},
        {"borderHover",      hex(blend(textPrimary(), borderStrong(), 0.14))},
        {"border",           hex(border())},
        {"textSecondary",    hex(textSecondary())},
        {"textMuted",        hex(textMuted())},
        {"textDisabled",     hex(textDisabled())},
        {"text",             hex(textPrimary())},
        {"accentStrongDown", hex(accentStrong().darker(115))},
        {"accentDeepDown",   hex(accentDeep().darker(115))},
        {"accentStrong",     hex(accentStrong())},
        {"accentDeep",       hex(accentDeep())},
        {"accentSoft",       hex(accentSoft())},
        {"accentAlt",        hex(accentAlt())},
        {"accent",           hex(accent())},
        {"focusOnAccent",    hex(blend(white, accentSoft(), 0.55))},
        {"accentInk",        hex(accentInk())},
        {"railBorder",       hex(railBorder())},
        {"railMuted",        hex(railMuted())},
        {"railHover",        hex(blend(white, bgSidebar(), 0.06))},
        {"selection",        hex(blend(accent(), surface(), 0.18))},
        {"rowAlt",           hex(blend(white, surface(), 0.016))},
        {"dangerFillHover",  hex(blend(danger(), surface(), 0.20))},
        {"dangerFill",       hex(blend(danger(), surface(), 0.12))},
        {"dangerRimHover",   hex(blend(danger(), surface(), 0.50))},
        {"dangerRim",        hex(blend(danger(), surface(), 0.32))},
        {"danger",           hex(danger())},
        {"scrollPressed",    hex(blend(textPrimary(), surface(), 0.32))},
        {"scrollHover",      hex(blend(textPrimary(), surface(), 0.24))},
        {"scroll",           hex(blend(textPrimary(), surface(), 0.14))},
        {"glyphs",           glyphDir()},
    });
}

void apply(QApplication& app)
{
    // Fusion is the base style: it takes its colours from the palette, so the few
    // things the style sheet doesn't cover (size grips, focus frames, message-box
    // icons' surroundings) still come out dark instead of in native light grey.
    if (QStyle* fusion = QStyleFactory::create(QStringLiteral("Fusion")))
        app.setStyle(fusion);
#if QT_VERSION >= QT_VERSION_CHECK(6, 8, 0)
    QGuiApplication::styleHints()->setColorScheme(Qt::ColorScheme::Dark);
#endif

    const QPalette pal = makePalette();
    app.setPalette(pal);
    QToolTip::setPalette(pal);

    // Segoe UI for Latin text and numerals, Microsoft YaHei UI for CJK.
    QFont f;
    f.setFamilies({QStringLiteral("Segoe UI"), QStringLiteral("Microsoft YaHei UI")});
    f.setPointSizeF(10.0);
    f.setStyleStrategy(QFont::PreferAntialias);
    app.setFont(f);

    app.setStyleSheet(styleSheet());

    // Qt's own transitions for the layers it owns: menus, the combo box list and
    // tooltips fade/slide in instead of appearing hard. Qt 6 leaves these off
    // unless asked, so the popups were the one part of the UI that never moved.
    // Off when the system asks for no animations (motion::enabled()), like
    // everything else in the design.
    for (const Qt::UIEffect effect : {Qt::UI_AnimateMenu, Qt::UI_FadeMenu, Qt::UI_AnimateCombo,
                                      Qt::UI_AnimateTooltip, Qt::UI_FadeTooltip})
        QApplication::setEffectEnabled(effect, motion::enabled());

    // Press feedback for every ordinary button (design/Ripple.h).
    ui::installRipples(app);

#ifdef Q_OS_WIN
    app.installEventFilter(new NativeChromeFilter(&app));
#endif
}

} // namespace theme
