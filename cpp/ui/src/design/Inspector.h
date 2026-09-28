#pragma once
#include "design/GlowCard.h"

#include <QColor>
#include <QFlags>
#include <QList>
#include <QPair>
#include <QString>

#include <functional>

class ElidingLabel;
class IconTile;
class QHBoxLayout;
class QLabel;
class QLayout;
class QMenu;
class QPushButton;
class QScrollArea;
class QToolButton;
class QVBoxLayout;

// The detail panel that slides in beside a list when a record is selected —
// the replacement for "double-click opens a modal". It keeps the list in view,
// follows ↑/↓ as the user walks the records, and puts the record's actions
// where the evidence is.
//
//   header   glyph tile · title · subtitle · ✕
//   body     (scrolls) lead sentence, sections of fields / chips / custom views
//   footer   (pinned) action buttons, ⋯ menu, and a note line that explains
//            anything that is disabled ("关键系统进程,结束会蓝屏")
//
// Pages rebuild it on every selection change: clear(), setHeader(), then add
// content. Values wrap anywhere (paths, hashes, command lines) and can carry a
// copy button, because forensic fields exist to be copied somewhere else.
class Inspector : public GlowCard
{
    Q_OBJECT
public:
    enum FieldFlag { Plain = 0x0, Mono = 0x1, Copy = 0x2, Muted = 0x4 };
    Q_DECLARE_FLAGS(FieldFlags, FieldFlag)

    explicit Inspector(QWidget* parent = nullptr);

    void clear();
    void setHeader(const QString& icon, const QColor& color, const QString& title,
                   const QString& subtitle = QString());

    // ---- body ----
    QVBoxLayout* body() const { return m_body; }
    QLabel* addLead(const QString& text);
    QVBoxLayout* addSection(const QString& title, QWidget* trailing = nullptr);
    QWidget* addField(QVBoxLayout* section, const QString& name, const QString& value,
                      FieldFlags flags = Plain);
    QWidget* addChips(QVBoxLayout* section, const QList<QPair<QString, QColor>>& chips);
    QLabel* addText(QVBoxLayout* section, const QString& text, const char* role = "secondary");
    void addWidget(QWidget* w);

    // ---- footer ----
    QPushButton* addAction(const QString& icon, const QString& text, const char* variant,
                           std::function<void()> fn);
    QToolButton* addMenu(QMenu* menu);
    void setNote(const QString& text, const QColor& color = QColor());

    // Clears every child of `layout` (widgets are hidden and deleted later, so a
    // button whose click triggered the rebuild is not destroyed mid-signal).
    static void clearLayout(QLayout* layout);

    // The same field / chip rows for other layouts (full-size detail windows),
    // so a record reads identically in the side panel and in its own window.
    static QWidget* makeField(const QString& name, const QString& value, FieldFlags flags = Plain,
                              int keyWidth = 74);
    static QWidget* makeChips(const QList<QPair<QString, QColor>>& chips);

signals:
    void closeRequested();

private:
    void syncFooter();

    IconTile* m_tile = nullptr;
    ElidingLabel* m_title = nullptr;
    ElidingLabel* m_subtitle = nullptr;
    QScrollArea* m_scroll = nullptr;
    QVBoxLayout* m_body = nullptr;
    QFrame* m_footerRule = nullptr;
    QWidget* m_footer = nullptr;
    QHBoxLayout* m_actions = nullptr;
    QLabel* m_note = nullptr;
    int m_sections = 0;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(Inspector::FieldFlags)
