#include "bulwark/models/ChainEventInfo.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/json/JsonSupport.h"

namespace bulwark {
using namespace bulwark::json;

namespace {
QString truncate(const QString& s, int max) {
    if (s.isEmpty() || s.size() <= max) return s;
    return s.left(max) + QString::fromUtf8("…");
}
} // namespace

ChainEventInfo ChainEventInfo::from(const SecurityEvent& e) {
    ChainEventInfo c;
    c.timestampUtc = e.timestampUtc.isValid() ? e.timestampUtc : QDateTime::currentDateTimeUtc();
    c.type = e.type;
    c.actorPid = e.actorPid;
    c.parentPid = e.parentPid;
    c.actorPath = e.actorPath;
    c.commandLine = truncate(e.commandLine, 256);
    c.target = e.target;
    c.riskScore = e.riskScore;
    return c;
}

QJsonObject ChainEventInfo::toJson() const {
    QJsonObject o;
    o["timestampUtc"] = dateTimeToIso(timestampUtc);
    o["type"] = static_cast<int>(type);
    o["actorPid"] = actorPid;
    o["parentPid"] = parentPid;
    o["actorPath"] = actorPath;
    if (!commandLine.isEmpty()) o["commandLine"] = commandLine;
    o["target"] = target;
    o["riskScore"] = riskScore;
    return o;
}

ChainEventInfo ChainEventInfo::fromJson(const QJsonObject& o) {
    ChainEventInfo c;
    c.timestampUtc = dateTimeFromIso(getStr(o, "timestampUtc"));
    c.type = static_cast<EventType>(getInt(o, "type"));
    c.actorPid = getInt(o, "actorPid");
    c.parentPid = getInt(o, "parentPid");
    c.actorPath = getStr(o, "actorPath");
    c.commandLine = getStr(o, "commandLine");
    c.target = getStr(o, "target");
    c.riskScore = getInt(o, "riskScore");
    return c;
}

} // namespace bulwark
