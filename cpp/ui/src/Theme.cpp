#include "Theme.h"

namespace theme {

QString styleSheet()
{
    // One global sheet. Widgets opt into variants via dynamic properties, e.g.
    //   label->setProperty("role", "h1");
    //   button->setProperty("variant", "primary");
    //
    // Light theme with depth: white cards float on a soft gray canvas. The base
    // canvas colour is set on QWidget (covers windows / pages / stacks), while
    // `.QWidget` (exact-class selector — plain container widgets only, NOT
    // buttons/tables/inputs/dividers) is made transparent so row-containers
    // inside cards show the white card instead of painting a gray strip.
    return QStringLiteral(R"QSS(
/* ---- base ---------------------------------------------------------- */
QWidget {
    background-color: #EDF0F5;
    color: #141C29;
    font-family: "Segoe UI";
    font-size: 10pt;
}
/* Plain QWidget containers (layout hosts / rows) carry no fill of their own. */
.QWidget { background-color: transparent; }
QLabel { background: transparent; }
QToolTip {
    background-color: #1E2836;
    color: #FFFFFF;
    border: 1px solid #1E2836;
    border-radius: 6px;
    padding: 6px 8px;
}

/* ---- text roles ---------------------------------------------------- */
QLabel[role="display"]   { font-size: 22pt; font-weight: 700; color: #141C29; }
QLabel[role="h1"]        { font-size: 16pt; font-weight: 700; color: #141C29; }
QLabel[role="h2"]        { font-size: 13pt; font-weight: 600; color: #141C29; }
QLabel[role="title"]     { font-size: 11pt; font-weight: 600; color: #141C29; }
QLabel[role="secondary"] { color: #586576; }
QLabel[role="muted"]     { color: #93A0B2; font-size: 9pt; }
QLabel[role="caption"]   { color: #93A0B2; font-size: 8.5pt; font-weight: 600; }
QLabel[role="stat"]      { font-size: 26pt; font-weight: 800; color: #141C29; }
QLabel[role="mono"]      { font-family: "Cascadia Mono","Consolas",monospace; color: #586576; }

/* ---- containers ---------------------------------------------------- */
QFrame#Sidebar   { background-color: #FFFFFF; border-right: 1px solid #E2E7EF; }
QFrame#Topbar    { background-color: transparent; border-bottom: 1px solid #E2E7EF; }
QFrame#Card      { background-color: #FFFFFF; border: 1px solid #E2E7EF; border-radius: 14px; }
QFrame#CardAlt   { background-color: #F5F7FB; border: 1px solid #E2E7EF; border-radius: 12px; }
QFrame#Divider   { background-color: #E9EDF3; border: none; }

/* ---- buttons ------------------------------------------------------- */
QPushButton {
    background-color: #FFFFFF;
    color: #141C29;
    border: 1px solid #CAD4E1;
    border-radius: 10px;
    padding: 8px 16px;
    font-size: 10pt;
    font-weight: 600;
}
QPushButton:hover   { background-color: #F1F4F9; border-color: #B4C0D0; }
QPushButton:pressed { background-color: #E4EAF3; }
QPushButton:disabled{ color: #AEB9C7; background-color: #F3F5F9; border-color: #E2E7EF; }

QPushButton[variant="primary"] {
    background-color: #0E9E8C; color: #FFFFFF; border: none;
}
QPushButton[variant="primary"]:hover   { background-color: #12B3A0; }
QPushButton[variant="primary"]:pressed { background-color: #0B8576; }

QPushButton[variant="danger"] {
    background-color: rgba(220,53,69,0.10); color: #DC3545; border: 1px solid rgba(220,53,69,0.35);
}
QPushButton[variant="danger"]:hover { background-color: rgba(220,53,69,0.18); }

QPushButton[variant="ghost"] {
    background-color: transparent; border: 1px solid #E2E7EF; color: #586576;
}
QPushButton[variant="ghost"]:hover { background-color: #F1F4F9; color: #141C29; }

QPushButton[size="sm"] { padding: 4px 11px; font-size: 9pt; border-radius: 8px; }

/* ---- inputs -------------------------------------------------------- */
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit {
    background-color: #FFFFFF;
    border: 1px solid #CAD4E1;
    border-radius: 10px;
    padding: 7px 10px;
    color: #141C29;
    selection-background-color: #0E9E8C;
    selection-color: #FFFFFF;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {
    border-color: #0E9E8C;
}
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView {
    background-color: #FFFFFF; border: 1px solid #CAD4E1; border-radius: 8px;
    selection-background-color: #E4EAF3; color: #141C29; outline: none;
}

/* ---- checkbox ------------------------------------------------------ */
QCheckBox { spacing: 8px; background: transparent; }
QCheckBox::indicator {
    width: 18px; height: 18px; border-radius: 5px;
    border: 1px solid #CAD4E1; background-color: #FFFFFF;
}
QCheckBox::indicator:checked { background-color: #0E9E8C; border-color: #0E9E8C; }

/* ---- tables -------------------------------------------------------- */
QTableView, QTreeView, QListView {
    background-color: #FFFFFF; alternate-background-color: #F6F8FC;
    border: 1px solid #E2E7EF; border-radius: 12px;
    gridline-color: #EDF1F6; outline: none;
    selection-background-color: #E4EAF3; selection-color: #141C29;
}
QTableView::item, QTreeView::item, QListView::item { padding: 6px 8px; border: none; }
/* 表头列之间画一条竖线:列宽是可拖的(见 ui::columns),没有分隔线用户就看不出
   哪里能抓、也想不到能拖。最后一列右侧那条线由 :last 去掉,免得贴着边框重影。 */
QHeaderView::section {
    background-color: #F6F8FC; color: #586576; padding: 8px 10px; border: none;
    border-bottom: 1px solid #E2E7EF; border-right: 1px solid #E2E7EF;
    font-weight: 600; font-size: 9pt;
}
QHeaderView::section:last, QHeaderView::section:only-one { border-right: none; }
QTableCornerButton::section { background-color: #F6F8FC; border: none; }

/* ---- scrollbars ---------------------------------------------------- */
QScrollBar:vertical   { background: transparent; width: 10px; margin: 2px; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:vertical   { background: #CAD4E1; min-height: 30px; border-radius: 5px; }
QScrollBar::handle:horizontal { background: #CAD4E1; min-width: 30px; border-radius: 5px; }
QScrollBar::handle:hover { background: #AEBBCC; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QScrollArea { border: none; background: transparent; }
)QSS");
}

} // namespace theme
