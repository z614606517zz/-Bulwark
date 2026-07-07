#include "bulwark/ipc/IpcMessage.h"
#include <QJsonDocument>
#include <QJsonArray>

namespace bulwark::ipc {

IpcMessage IpcMessage::create(IpcMessageType type, const QJsonObject& payloadObj) {
    IpcMessage m;
    m.type = type;
    m.payload = QString::fromUtf8(QJsonDocument(payloadObj).toJson(QJsonDocument::Compact));
    return m;
}

IpcMessage IpcMessage::createRaw(IpcMessageType type, const QString& rawPayload) {
    IpcMessage m;
    m.type = type;
    m.payload = rawPayload;
    return m;
}

QString IpcMessage::serialize() const {
    QJsonObject o;
    o["type"] = static_cast<int>(type);
    o["payload"] = payload;
    return QString::fromUtf8(QJsonDocument(o).toJson(QJsonDocument::Compact));
}

QJsonObject IpcMessage::payloadObject() const {
    if (payload.isEmpty()) return QJsonObject();
    QJsonParseError err{};
    const QJsonDocument d = QJsonDocument::fromJson(payload.toUtf8(), &err);
    return (err.error == QJsonParseError::NoError && d.isObject()) ? d.object() : QJsonObject();
}

std::optional<IpcMessage> IpcMessage::deserialize(const QString& line) {
    const QString t = line.trimmed();
    if (t.isEmpty()) return std::nullopt;
    QJsonParseError err{};
    const QJsonDocument d = QJsonDocument::fromJson(t.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !d.isObject()) return std::nullopt;

    const QJsonObject o = d.object();
    IpcMessage m;
    m.type = static_cast<IpcMessageType>(o.value(QLatin1String("type")).toInt());
    // payload 通常是被转义的 JSON 字符串;也容忍直接内嵌对象/数组的情形。
    const QJsonValue pv = o.value(QLatin1String("payload"));
    if (pv.isString())
        m.payload = pv.toString();
    else if (pv.isObject())
        m.payload = QString::fromUtf8(QJsonDocument(pv.toObject()).toJson(QJsonDocument::Compact));
    else if (pv.isArray())
        m.payload = QString::fromUtf8(QJsonDocument(pv.toArray()).toJson(QJsonDocument::Compact));
    else
        m.payload = QString();
    return m;
}

} // namespace bulwark::ipc
