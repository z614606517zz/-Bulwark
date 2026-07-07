#include "bulwark/models/PersistenceEntry.h"
#include "bulwark/json/JsonSupport.h"

namespace bulwark {
using namespace bulwark::json;

QJsonObject PersistenceEntry::toJson() const {
    QJsonObject o;
    o["id"] = id;
    o["category"] = static_cast<int>(category);
    o["name"] = name;
    o["location"] = location;
    o["command"] = command;
    o["imagePath"] = imagePath;
    o["signed"] = isSigned.has_value() ? QJsonValue(*isSigned) : QJsonValue(QJsonValue::Null);
    o["publisher"] = publisher;
    o["riskScore"] = riskScore;
    o["riskReasons"] = strListToJson(riskReasons);
    o["techniques"] = strListToJson(techniques);
    return o;
}

PersistenceEntry PersistenceEntry::fromJson(const QJsonObject& o) {
    PersistenceEntry e;
    e.id = getStr(o, "id");
    e.category = static_cast<PersistenceCategory>(getInt(o, "category"));
    e.name = getStr(o, "name");
    e.location = getStr(o, "location");
    e.command = getStr(o, "command");
    e.imagePath = getStr(o, "imagePath");
    const QJsonValue sv = o.value(QLatin1String("signed"));
    if (sv.isBool()) e.isSigned = sv.toBool();
    e.publisher = getStr(o, "publisher");
    e.riskScore = getInt(o, "riskScore");
    e.riskReasons = getStrList(o, "riskReasons");
    e.techniques = getStrList(o, "techniques");
    return e;
}

} // namespace bulwark
