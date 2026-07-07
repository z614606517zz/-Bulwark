#include "bulwark/models/IpReputation.h"
#include "bulwark/json/JsonSupport.h"

namespace bulwark {
using namespace bulwark::json;

QJsonObject IpReputation::toJson() const {
    QJsonObject o;
    o["resource"] = resource;
    o["verdict"] = static_cast<int>(verdict);
    o["threatLabel"] = threatLabel;
    o["confidence"] = confidence;
    o["querySucceeded"] = querySucceeded;
    o["fetchedUtc"] = dateTimeToIso(fetchedUtc);
    return o;
}

IpReputation IpReputation::fromJson(const QJsonObject& o) {
    IpReputation r;
    r.resource = getStr(o, "resource");
    r.verdict = static_cast<ReputationVerdict>(getInt(o, "verdict"));
    r.threatLabel = getStr(o, "threatLabel");
    r.confidence = getInt(o, "confidence");
    r.querySucceeded = getBool(o, "querySucceeded");
    const QDateTime f = dateTimeFromIso(getStr(o, "fetchedUtc"));
    if (f.isValid()) r.fetchedUtc = f;
    return r;
}

} // namespace bulwark
