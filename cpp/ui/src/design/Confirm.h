#pragma once
#include <QString>
#include <QStringList>

#include <optional>

class QWidget;

namespace ui {

// How dangerous the action being confirmed is. It decides the glyph, the colour
// and the confirm button's style — and for Danger, that the user must tick
// 「我已了解」 before the confirm button unlocks (and Enter defaults to 取消).
enum class Risk { Info, Caution, Danger };

struct ConfirmSpec {
    Risk risk = Risk::Caution;
    QString title;               // "永久删除 3 个隔离文件"
    QString summary;             // one sentence: what happens
    QStringList consequences;    // what will happen / what cannot be undone
    QString subjectLabel;        // "程序" / "文件夹" / "规则"
    QString subject;             // the exact object (full path…), shown verbatim
    QString confirmText;         // default "确定"
    QString cancelText;          // default "取消"
    std::optional<bool> requireAck; // default: risk == Danger
    QString ackText;             // default "我已了解上述后果"
};

// Replacement for QMessageBox::question: a Sheet that says what will happen,
// to what, and what can't be undone — then asks. Returns true on confirm.
bool confirm(QWidget* parent, const ConfirmSpec& spec);

// A one-button notice — for the few messages that must be read before going on
// but ask nothing (start-up problems, before any page exists to host a banner).
// `detail` is shown verbatim in a mono block (a path, a log excerpt).
enum class NoticeTone { Info, Warning, Danger };
void notice(QWidget* parent, NoticeTone tone, const QString& title, const QString& body,
            const QString& detail = QString());

} // namespace ui
