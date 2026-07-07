#include "bulwark/models/ReputationUsage.h"
#include "bulwark/json/JsonSupport.h"

namespace bulwark {
using namespace bulwark::json;

QJsonObject ReputationUsage::toJson() const {
    QJsonObject o;
    o["source"] = source;
    o["enabled"] = enabled;
    o["usedToday"] = usedToday;
    o["dailyLimit"] = dailyLimit;
    o["perMinuteLimit"] = perMinuteLimit;
    return o;
}

ReputationUsage ReputationUsage::fromJson(const QJsonObject& o) {
    ReputationUsage u;
    u.source = getStr(o, "source");
    u.enabled = getBool(o, "enabled");
    u.usedToday = getInt(o, "usedToday");
    u.dailyLimit = getInt(o, "dailyLimit");
    u.perMinuteLimit = getInt(o, "perMinuteLimit");
    return u;
}

} // namespace bulwark
