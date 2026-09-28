#pragma once
#include <QDateTime>
#include <QLocale>
#include <QString>

// Small, domain-neutral formatting shared by the design layer and pages.
namespace fmt {

// "刚刚" / "3 分钟前" / "2 小时前" / "昨天 14:02" / "09-12 14:02" / "2025-11-03".
// Local time. The absolute timestamp belongs in the tooltip / inspector.
inline QString relativeTime(const QDateTime& when, const QDateTime& now = QDateTime::currentDateTime())
{
    if (!when.isValid())
        return QString();
    const QDateTime t = when.toLocalTime();
    const QDateTime n = now.toLocalTime();
    const qint64 secs = t.secsTo(n);
    if (secs < 0) // clock skew / future timestamp: just show the time
        return t.toString(QStringLiteral("HH:mm"));
    if (secs < 45)
        return QString::fromUtf8("刚刚");
    if (secs < 3600)
        return QString::fromUtf8("%1 分钟前").arg(qMax<qint64>(1, (secs + 30) / 60));
    const QDate d = t.date();
    const QDate today = n.date();
    if (d == today)
        return QString::fromUtf8("%1 小时前").arg(qMax<qint64>(1, secs / 3600));
    if (d == today.addDays(-1))
        return QString::fromUtf8("昨天 ") + t.toString(QStringLiteral("HH:mm"));
    if (d.year() == today.year())
        return t.toString(QStringLiteral("MM-dd HH:mm"));
    return t.toString(QStringLiteral("yyyy-MM-dd"));
}

// Full local timestamp for tooltips and inspector fields.
inline QString absoluteTime(const QDateTime& when)
{
    return when.isValid() ? when.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")) : QString();
}

inline QString bytes(qint64 n)
{
    if (n <= 0)
        return QString::fromUtf8("—");
    return QLocale().formattedDataSize(n, 1, QLocale::DataSizeTraditionalFormat);
}

} // namespace fmt
