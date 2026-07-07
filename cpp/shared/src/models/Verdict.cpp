#include "bulwark/models/Verdict.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/json/JsonSupport.h"

namespace bulwark {
using namespace bulwark::json;

Verdict Verdict::forEvent(const SecurityEvent& e, VerdictAction action,
                          VerdictSource source, bool remember) {
    Verdict v;
    v.eventId = e.id;
    v.action = action;
    v.source = source;
    v.remember = remember;
    return v;
}

QJsonObject Verdict::toJson() const {
    QJsonObject o;
    o["eventId"] = guidToString(eventId);
    o["action"] = static_cast<int>(action);
    o["source"] = static_cast<int>(source);
    o["remember"] = remember;
    return o;
}

Verdict Verdict::fromJson(const QJsonObject& o) {
    Verdict v;
    v.eventId = guidFromString(getStr(o, "eventId"));
    v.action = static_cast<VerdictAction>(getInt(o, "action"));
    v.source = static_cast<VerdictSource>(getInt(o, "source"));
    v.remember = getBool(o, "remember");
    return v;
}

} // namespace bulwark
