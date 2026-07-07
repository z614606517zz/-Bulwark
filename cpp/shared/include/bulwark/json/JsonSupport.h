#pragma once
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QUuid>
#include <QDateTime>
#include <QTimeZone>
#include <QString>
#include <optional>

// Small helpers to keep JSON (de)serialization faithful to the .NET wire format:
//  - Guid  -> lowercase, hyphenated, no braces (matches C# Guid "D" format).
//  - DateTime -> ISO-8601 UTC with milliseconds (round-trips with .NET; the
//    tolerant parser also accepts .NET's higher-precision fractional seconds).
namespace bulwark::json {

inline QString guidToString(const QUuid& id) {
    // QUuid::WithoutBraces yields e.g. "5f3e...-...-...": matches C# default.
    return id.isNull() ? QString() : id.toString(QUuid::WithoutBraces);
}

inline QUuid guidFromString(const QString& s) {
    return s.isEmpty() ? QUuid() : QUuid::fromString(s);
}

inline QString dateTimeToIso(const QDateTime& dt) {
    return dt.toUTC().toString(Qt::ISODateWithMs);
}

// Tolerant parse: accepts trailing 'Z', explicit offset, or .NET's 7-digit
// fractional seconds (trimmed to milliseconds for Qt).
inline QDateTime dateTimeFromIso(const QString& raw) {
    if (raw.isEmpty()) return QDateTime();
    QDateTime dt = QDateTime::fromString(raw, Qt::ISODateWithMs);
    if (!dt.isValid()) dt = QDateTime::fromString(raw, Qt::ISODate);
    if (!dt.isValid()) {
        // Trim over-precise fractional seconds ".1234567" -> ".123".
        QString s = raw;
        int dot = s.indexOf(QLatin1Char('.'));
        if (dot >= 0) {
            int end = dot + 1;
            while (end < s.size() && s[end].isDigit()) ++end;
            const int keep = qMin(end, dot + 4); // dot + up to 3 digits
            s.remove(keep, end - keep);
            dt = QDateTime::fromString(s, Qt::ISODateWithMs);
        }
    }
    if (dt.isValid() && dt.timeSpec() == Qt::LocalTime)
        dt.setTimeZone(QTimeZone(QTimeZone::UTC)); // no zone in the string -> treat as UTC
    return dt.toUTC();
}

// --- optional value helpers --------------------------------------------------
inline QJsonValue optDateToJson(const std::optional<QDateTime>& dt) {
    if (!dt.has_value() || !dt->isValid()) return QJsonValue(QJsonValue::Null);
    return QJsonValue(dateTimeToIso(*dt));
}

inline std::optional<QDateTime> optDateFromJson(const QJsonValue& v) {
    if (v.isNull() || v.isUndefined()) return std::nullopt;
    const QString s = v.toString();
    if (s.isEmpty()) return std::nullopt;
    return dateTimeFromIso(s);
}

// --- safe field getters ------------------------------------------------------
inline QString getStr(const QJsonObject& o, const char* key) {
    return o.value(QLatin1String(key)).toString();
}
inline int getInt(const QJsonObject& o, const char* key, int def = 0) {
    const QJsonValue v = o.value(QLatin1String(key));
    return v.isDouble() ? v.toInt(def) : def;
}
inline qint64 getI64(const QJsonObject& o, const char* key, qint64 def = 0) {
    const QJsonValue v = o.value(QLatin1String(key));
    return v.isDouble() ? static_cast<qint64>(v.toVariant().toLongLong()) : def;
}
inline bool getBool(const QJsonObject& o, const char* key, bool def = false) {
    const QJsonValue v = o.value(QLatin1String(key));
    return v.isBool() ? v.toBool(def) : def;
}

inline QStringList getStrList(const QJsonObject& o, const char* key) {
    QStringList out;
    const QJsonArray arr = o.value(QLatin1String(key)).toArray();
    out.reserve(arr.size());
    for (const QJsonValue& v : arr) out << v.toString();
    return out;
}

inline QJsonArray strListToJson(const QStringList& list) {
    QJsonArray arr;
    for (const QString& s : list) arr.append(s);
    return arr;
}

} // namespace bulwark::json
