#include "bulwark/models/FileReputation.h"
#include "bulwark/json/JsonSupport.h"

namespace bulwark {
using namespace bulwark::json;

QJsonObject FileReputation::toJson() const {
    QJsonObject o;
    o["sha256"] = sha256;
    o["verdict"] = static_cast<int>(verdict);
    o["malicious"] = malicious;
    o["totalEngines"] = totalEngines;
    o["threatLabel"] = threatLabel;
    o["source"] = source;
    o["fetchedUtc"] = dateTimeToIso(fetchedUtc);
    o["lastAnalysisUtc"] = optDateToJson(lastAnalysisUtc);
    o["querySucceeded"] = querySucceeded;
    return o;
}

FileReputation FileReputation::fromJson(const QJsonObject& o) {
    FileReputation r;
    r.sha256 = getStr(o, "sha256");
    r.verdict = static_cast<ReputationVerdict>(getInt(o, "verdict"));
    r.malicious = getInt(o, "malicious");
    r.totalEngines = getInt(o, "totalEngines");
    r.threatLabel = getStr(o, "threatLabel");
    r.source = getStr(o, "source");
    r.fetchedUtc = dateTimeFromIso(getStr(o, "fetchedUtc"));
    r.lastAnalysisUtc = optDateFromJson(o.value(QLatin1String("lastAnalysisUtc")));
    r.querySucceeded = getBool(o, "querySucceeded");
    return r;
}

} // namespace bulwark
