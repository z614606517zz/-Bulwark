#include "bulwark/models/AttackGraph.h"
#include "bulwark/json/JsonSupport.h"

#include <QJsonArray>

namespace bulwark {
using namespace bulwark::json;

QString attackNodeKindToString(AttackNodeKind k) {
    switch (k) {
        case AttackNodeKind::Process:       return QStringLiteral("Process");
        case AttackNodeKind::File:          return QStringLiteral("File");
        case AttackNodeKind::Registry:      return QStringLiteral("Registry");
        case AttackNodeKind::Network:       return QStringLiteral("Network");
        case AttackNodeKind::Domain:        return QStringLiteral("Domain");
        case AttackNodeKind::Module:        return QStringLiteral("Module");
        case AttackNodeKind::Service:       return QStringLiteral("Service");
        case AttackNodeKind::ScheduledTask: return QStringLiteral("ScheduledTask");
    }
    return QStringLiteral("Process");
}

AttackNodeKind attackNodeKindFromString(const QString& s) {
    if (s == QLatin1String("File"))          return AttackNodeKind::File;
    if (s == QLatin1String("Registry"))      return AttackNodeKind::Registry;
    if (s == QLatin1String("Network"))       return AttackNodeKind::Network;
    if (s == QLatin1String("Domain"))        return AttackNodeKind::Domain;
    if (s == QLatin1String("Module"))        return AttackNodeKind::Module;
    if (s == QLatin1String("Service"))       return AttackNodeKind::Service;
    if (s == QLatin1String("ScheduledTask")) return AttackNodeKind::ScheduledTask;
    return AttackNodeKind::Process;
}

// ---- Node -------------------------------------------------------------------
QJsonObject AttackGraphNode::toJson() const {
    QJsonObject o;
    o["id"] = id;
    o["kind"] = attackNodeKindToString(kind);
    o["label"] = label;
    if (!detail.isEmpty())      o["detail"] = detail;
    if (pid > 0)                o["pid"] = pid;
    if (parentPid > 0)          o["parentPid"] = parentPid;
    if (!path.isEmpty())        o["path"] = path;
    if (!commandLine.isEmpty()) o["commandLine"] = commandLine;
    o["signedActor"] = signedActor;
    if (!publisher.isEmpty())   o["publisher"] = publisher;
    o["riskScore"] = riskScore;
    o["blocked"] = blocked;
    o["isSeed"] = isSeed;
    o["isRoot"] = isRoot;
    o["depth"] = depth;
    if (originKind != ProcessOriginKind::Unknown) o["originKind"] = static_cast<int>(originKind);
    if (!originLabel.isEmpty()) o["originLabel"] = originLabel;
    o["eventCount"] = eventCount;
    if (firstSeenUtc.isValid()) o["firstSeenUtc"] = dateTimeToIso(firstSeenUtc);
    if (lastSeenUtc.isValid())  o["lastSeenUtc"] = dateTimeToIso(lastSeenUtc);
    return o;
}

AttackGraphNode AttackGraphNode::fromJson(const QJsonObject& o) {
    AttackGraphNode n;
    n.id = getStr(o, "id");
    n.kind = attackNodeKindFromString(getStr(o, "kind"));
    n.label = getStr(o, "label");
    n.detail = getStr(o, "detail");
    n.pid = getInt(o, "pid");
    n.parentPid = getInt(o, "parentPid");
    n.path = getStr(o, "path");
    n.commandLine = getStr(o, "commandLine");
    n.signedActor = getBool(o, "signedActor");
    n.publisher = getStr(o, "publisher");
    n.riskScore = getInt(o, "riskScore");
    n.blocked = getBool(o, "blocked");
    n.isSeed = getBool(o, "isSeed");
    n.isRoot = getBool(o, "isRoot");
    n.depth = getInt(o, "depth");
    n.originKind = static_cast<ProcessOriginKind>(getInt(o, "originKind", 0));
    n.originLabel = getStr(o, "originLabel");
    n.eventCount = getInt(o, "eventCount");
    n.firstSeenUtc = dateTimeFromIso(getStr(o, "firstSeenUtc"));
    n.lastSeenUtc = dateTimeFromIso(getStr(o, "lastSeenUtc"));
    return n;
}

// ---- Edge -------------------------------------------------------------------
QJsonObject AttackGraphEdge::toJson() const {
    QJsonObject o;
    o["eventId"] = guidToString(eventId);
    o["fromId"] = fromId;
    o["toId"] = toId;
    o["type"] = static_cast<int>(type);
    o["label"] = label;
    if (!detail.isEmpty()) o["detail"] = detail;
    o["timestampUtc"] = dateTimeToIso(timestampUtc);
    o["riskScore"] = riskScore;
    o["action"] = static_cast<int>(action);
    o["enforcement"] = static_cast<int>(enforcement);
    o["hasThreatIndicator"] = hasThreatIndicator;
    if (!techniques.isEmpty()) o["techniques"] = strListToJson(techniques);
    if (inferred) o["inferred"] = true;
    return o;
}

AttackGraphEdge AttackGraphEdge::fromJson(const QJsonObject& o) {
    AttackGraphEdge e;
    e.eventId = guidFromString(getStr(o, "eventId"));
    e.fromId = getStr(o, "fromId");
    e.toId = getStr(o, "toId");
    e.type = static_cast<EventType>(getInt(o, "type"));
    e.label = getStr(o, "label");
    e.detail = getStr(o, "detail");
    e.timestampUtc = dateTimeFromIso(getStr(o, "timestampUtc"));
    e.riskScore = getInt(o, "riskScore");
    e.action = static_cast<VerdictAction>(getInt(o, "action", 0));
    e.enforcement = static_cast<EnforcementOutcome>(
        getInt(o, "enforcement", static_cast<int>(EnforcementOutcome::NotApplicable)));
    e.hasThreatIndicator = getBool(o, "hasThreatIndicator");
    e.techniques = getStrList(o, "techniques");
    e.inferred = getBool(o, "inferred");
    return e;
}

// ---- Graph ------------------------------------------------------------------
QJsonObject AttackGraph::toJson() const {
    QJsonObject o;
    o["seedEventId"] = guidToString(seedEventId);
    o["rootPid"] = rootPid;
    o["rootLabel"] = rootLabel;
    QJsonArray na;
    for (const AttackGraphNode& n : nodes) na.append(n.toJson());
    o["nodes"] = na;
    QJsonArray ea;
    for (const AttackGraphEdge& e : edges) ea.append(e.toJson());
    o["edges"] = ea;
    o["techniques"] = strListToJson(techniques);
    if (firstUtc.isValid()) o["firstUtc"] = dateTimeToIso(firstUtc);
    if (lastUtc.isValid())  o["lastUtc"] = dateTimeToIso(lastUtc);
    o["maxRiskScore"] = maxRiskScore;
    o["eventCount"] = eventCount;
    o["truncated"] = truncated;
    o["summary"] = summary;
    return o;
}

AttackGraph AttackGraph::fromJson(const QJsonObject& o) {
    AttackGraph g;
    g.seedEventId = guidFromString(getStr(o, "seedEventId"));
    g.rootPid = getInt(o, "rootPid");
    g.rootLabel = getStr(o, "rootLabel");
    const QJsonArray na = o.value(QLatin1String("nodes")).toArray();
    g.nodes.reserve(na.size());
    for (const QJsonValue& v : na)
        if (v.isObject()) g.nodes.append(AttackGraphNode::fromJson(v.toObject()));
    const QJsonArray ea = o.value(QLatin1String("edges")).toArray();
    g.edges.reserve(ea.size());
    for (const QJsonValue& v : ea)
        if (v.isObject()) g.edges.append(AttackGraphEdge::fromJson(v.toObject()));
    g.techniques = getStrList(o, "techniques");
    g.firstUtc = dateTimeFromIso(getStr(o, "firstUtc"));
    g.lastUtc = dateTimeFromIso(getStr(o, "lastUtc"));
    g.maxRiskScore = getInt(o, "maxRiskScore");
    g.eventCount = getInt(o, "eventCount");
    g.truncated = getBool(o, "truncated");
    g.summary = getStr(o, "summary");
    return g;
}

} // namespace bulwark
