#pragma once
#include <QColor>
#include <QList>
#include <QPair>
#include <QPoint>
#include <QString>
#include <QStringList>
#include <QWidget>

class QTimer;
class QPropertyAnimation;

// A labelled detail line for the block toast, e.g. {"来源", "从桌面执行未签名程序"}.
using ToastField = QPair<QString, QString>;

// A single corner "toast" notification — the building block behind the block
// (拦截通知) and AI-scan (AI 扫描提示) toasts described in the README.
//
// Frameless, translucent, always-on-top and non-activating (never steals focus
// from the user's work). A rounded white card with a colour-coded icon badge,
// heading, actor + detail lines and optional ATT&CK tags. Fades in, auto-
// dismisses after `lifetimeMs`, pauses while hovered and closes on click.
// Placement/stacking is owned by ToastNotifier; this widget only knows how to
// paint itself and animate to a target position.
class ToastWindow : public QWidget
{
    Q_OBJECT
public:
    enum class Kind { Block, AiScan, Info };

    // `subtitle` is a small line under the heading ("磐垒已自动处置,无需操作").
    // `detail` is a single free-text line (AI-scan / info toasts). `fields` are
    // structured 标签:值 rows (block toast: 来源/程序/行为/目标). Pass whichever
    // fits the kind; empty ones are simply skipped.
    ToastWindow(Kind kind, const QString& heading, const QString& subtitle,
                const QString& detail, const QList<ToastField>& fields,
                const QStringList& tags, int lifetimeMs, QWidget* parent = nullptr);

    // Move to `topLeft`. The first call fades the toast in at that spot; later
    // calls slide it (used when the stack re-flows as toasts come and go).
    void place(const QPoint& topLeft);

signals:
    void closed(ToastWindow* self);
    void clicked(ToastWindow* self);

protected:
    void enterEvent(QEnterEvent*) override;
    void leaveEvent(QEvent*) override;
    void mousePressEvent(QMouseEvent*) override;

private slots:
    void beginClose();

private:
    QTimer* m_life = nullptr;
    QPropertyAnimation* m_fade = nullptr;
    QPropertyAnimation* m_slide = nullptr;
    int m_lifetimeMs = 6000;
    bool m_shown = false;
    bool m_closing = false;
};
