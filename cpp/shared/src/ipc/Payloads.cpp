#include "bulwark/ipc/Payloads.h"
#include "bulwark/json/JsonSupport.h"

#include <QJsonArray>

namespace bulwark::ipc {

QJsonObject HelloPayload::toJson() const {
    QJsonObject o;
    o["processId"] = processId;
    o["role"] = role;
    return o;
}

HelloPayload HelloPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    HelloPayload h;
    h.processId = getInt(o, "processId");
    h.role = o.contains(QLatin1String("role")) ? getStr(o, "role") : QStringLiteral("ui");
    return h;
}

QJsonObject PromptResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["eventId"] = guidToString(eventId);
    o["action"] = static_cast<int>(action);
    o["remember"] = remember;
    o["scope"] = static_cast<int>(scope);
    return o;
}

PromptResponsePayload PromptResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    PromptResponsePayload p;
    p.eventId = guidFromString(getStr(o, "eventId"));
    p.action = static_cast<VerdictAction>(getInt(o, "action", 0));
    p.remember = getBool(o, "remember");
    p.scope = static_cast<RememberScope>(getInt(o, "scope", 0));
    return p;
}

QJsonObject EventLogPayload::toJson() const {
    QJsonObject o;
    o["event"] = event.toJson();
    o["action"] = static_cast<int>(action);
    o["source"] = static_cast<int>(source);
    o["enforcement"] = static_cast<int>(enforcement);
    return o;
}

EventLogPayload EventLogPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    EventLogPayload p;
    p.event = bulwark::SecurityEvent::fromJson(o.value(QLatin1String("event")).toObject());
    p.action = static_cast<VerdictAction>(getInt(o, "action", 0));
    p.source = static_cast<VerdictSource>(getInt(o, "source", static_cast<int>(VerdictSource::DefaultPolicy)));
    p.enforcement = static_cast<bulwark::EnforcementOutcome>(
        getInt(o, "enforcement", static_cast<int>(bulwark::EnforcementOutcome::NotApplicable)));
    return p;
}

QJsonObject EventHistoryResponsePayload::toJson() const {
    QJsonArray arr;
    for (const EventLogPayload& e : events) arr.append(e.toJson());
    QJsonObject o;
    o["events"] = arr;
    return o;
}

EventHistoryResponsePayload EventHistoryResponsePayload::fromJson(const QJsonObject& o) {
    EventHistoryResponsePayload p;
    const QJsonArray arr = o.value(QLatin1String("events")).toArray();
    p.events.reserve(arr.size());
    for (const QJsonValue& v : arr)
        if (v.isObject()) p.events.append(EventLogPayload::fromJson(v.toObject()));
    return p;
}

QJsonObject RemediationSkippedItem::toJson() const {
    QJsonObject o;
    o["target"] = target;
    o["reason"] = reason;
    o["isFile"] = isFile;
    return o;
}

RemediationSkippedItem RemediationSkippedItem::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    RemediationSkippedItem s;
    s.target = getStr(o, "target");
    s.reason = getStr(o, "reason");
    s.isFile = getBool(o, "isFile");
    return s;
}

// ---- helpers for DefenseRule list (de)serialization -------------------------
namespace {
QJsonArray rulesToArray(const QList<bulwark::DefenseRule>& rules) {
    QJsonArray arr;
    for (const auto& r : rules) arr.append(r.toJson());
    return arr;
}
QList<bulwark::DefenseRule> rulesFromArray(const QJsonArray& arr) {
    QList<bulwark::DefenseRule> out;
    out.reserve(arr.size());
    for (const auto& v : arr)
        if (v.isObject()) out.append(bulwark::DefenseRule::fromJson(v.toObject()));
    return out;
}
} // namespace

// ===== 规则管理 =====
QJsonObject RulesResponsePayload::toJson() const {
    QJsonObject o; o["rules"] = rulesToArray(rules); return o;
}
RulesResponsePayload RulesResponsePayload::fromJson(const QJsonObject& o) {
    RulesResponsePayload p;
    p.rules = rulesFromArray(o.value(QLatin1String("rules")).toArray());
    return p;
}

QJsonObject DeleteRulePayload::toJson() const {
    using namespace bulwark::json; QJsonObject o; o["ruleId"] = guidToString(ruleId); return o;
}
DeleteRulePayload DeleteRulePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json; DeleteRulePayload p; p.ruleId = guidFromString(getStr(o, "ruleId")); return p;
}

QJsonObject AddRulePayload::toJson() const {
    QJsonObject o;
    o["actorPath"] = actorPath;
    o["type"] = type.has_value() ? QJsonValue(static_cast<int>(*type)) : QJsonValue(QJsonValue::Null);
    o["targetPattern"] = targetPattern;
    o["action"] = static_cast<int>(action);
    return o;
}
AddRulePayload AddRulePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    AddRulePayload p;
    p.actorPath = getStr(o, "actorPath");
    const QJsonValue tv = o.value(QLatin1String("type"));
    if (tv.isDouble()) p.type = static_cast<bulwark::EventType>(tv.toInt());
    p.targetPattern = getStr(o, "targetPattern");
    p.action = static_cast<bulwark::VerdictAction>(getInt(o, "action", 0));
    return p;
}

// ===== 文件信任 =====
QJsonObject TrustListResponsePayload::toJson() const {
    QJsonObject o; o["entries"] = rulesToArray(entries); return o;
}
TrustListResponsePayload TrustListResponsePayload::fromJson(const QJsonObject& o) {
    TrustListResponsePayload p;
    p.entries = rulesFromArray(o.value(QLatin1String("entries")).toArray());
    return p;
}

QJsonObject AddTrustPayload::toJson() const {
    QJsonObject o; o["actorPath"] = actorPath; o["note"] = note; o["isDirectory"] = isDirectory; return o;
}
AddTrustPayload AddTrustPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json; AddTrustPayload p; p.actorPath = getStr(o, "actorPath"); p.note = getStr(o, "note"); p.isDirectory = getBool(o, "isDirectory"); return p;
}

QJsonObject RemoveTrustPayload::toJson() const {
    using namespace bulwark::json; QJsonObject o; o["ruleId"] = guidToString(ruleId); return o;
}
RemoveTrustPayload RemoveTrustPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json; RemoveTrustPayload p; p.ruleId = guidFromString(getStr(o, "ruleId")); return p;
}

// ===== 威胁情报 / VirusTotal =====
QJsonObject VtRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["kind"] = static_cast<int>(kind);
    o["filePath"] = filePath;
    o["source"] = source;
    return o;
}
VtRequestPayload VtRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    VtRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.kind = static_cast<bulwark::VtRequestKind>(getInt(o, "kind", 0));
    p.filePath = getStr(o, "filePath");
    p.source = getStr(o, "source");
    return p;
}

QJsonObject VtResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["success"] = success;
    o["message"] = message;
    o["reputation"] = reputation.has_value() ? QJsonValue(reputation->toJson()) : QJsonValue(QJsonValue::Null);
    if (usages.has_value()) {
        QJsonArray arr;
        for (const auto& u : *usages) arr.append(u.toJson());
        o["usages"] = arr;
    } else {
        o["usages"] = QJsonValue(QJsonValue::Null);
    }
    return o;
}
VtResponsePayload VtResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    VtResponsePayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.success = getBool(o, "success");
    p.message = getStr(o, "message");
    const QJsonValue rv = o.value(QLatin1String("reputation"));
    if (rv.isObject()) p.reputation = bulwark::FileReputation::fromJson(rv.toObject());
    const QJsonValue uv = o.value(QLatin1String("usages"));
    if (uv.isArray()) {
        QList<bulwark::ReputationUsage> list;
        for (const auto& v : uv.toArray())
            if (v.isObject()) list.append(bulwark::ReputationUsage::fromJson(v.toObject()));
        p.usages = list;
    }
    return p;
}

QJsonObject VtHistoryResponsePayload::toJson() const {
    QJsonArray arr;
    for (const auto& r : records) arr.append(r.toJson());
    QJsonObject o; o["records"] = arr; return o;
}
VtHistoryResponsePayload VtHistoryResponsePayload::fromJson(const QJsonObject& o) {
    VtHistoryResponsePayload p;
    for (const auto& v : o.value(QLatin1String("records")).toArray())
        if (v.isObject()) p.records.append(bulwark::VtScanRecord::fromJson(v.toObject()));
    return p;
}

QJsonObject VtDetailResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["sha256"] = sha256;
    o["success"] = success;
    o["message"] = message;
    o["typeDescription"] = typeDescription;
    o["sizeBytes"] = static_cast<double>(sizeBytes);
    o["firstSubmissionUtc"] = dateTimeToIso(firstSubmissionUtc);
    o["lastAnalysisUtc"] = dateTimeToIso(lastAnalysisUtc);
    o["timesSubmitted"] = timesSubmitted;
    o["reputation"] = reputation;
    o["malicious"] = malicious;
    o["totalEngines"] = totalEngines;
    o["threatLabel"] = threatLabel;
    o["knownNames"] = strListToJson(knownNames);
    o["tags"] = strListToJson(tags);
    o["maliciousDetections"] = strListToJson(maliciousDetections);
    o["suspiciousDetections"] = strListToJson(suspiciousDetections);
    o["droppedFiles"] = strListToJson(droppedFiles);
    o["registryKeys"] = strListToJson(registryKeys);
    o["contactedIps"] = strListToJson(contactedIps);
    o["contactedDomains"] = strListToJson(contactedDomains);
    return o;
}
VtDetailResponsePayload VtDetailResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    VtDetailResponsePayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.sha256 = getStr(o, "sha256");
    p.success = getBool(o, "success");
    p.message = getStr(o, "message");
    p.typeDescription = getStr(o, "typeDescription");
    p.sizeBytes = static_cast<qint64>(o.value(QLatin1String("sizeBytes")).toDouble());
    p.firstSubmissionUtc = dateTimeFromIso(getStr(o, "firstSubmissionUtc"));
    p.lastAnalysisUtc = dateTimeFromIso(getStr(o, "lastAnalysisUtc"));
    p.timesSubmitted = getInt(o, "timesSubmitted");
    p.reputation = getInt(o, "reputation");
    p.malicious = getInt(o, "malicious");
    p.totalEngines = getInt(o, "totalEngines");
    p.threatLabel = getStr(o, "threatLabel");
    p.knownNames = getStrList(o, "knownNames");
    p.tags = getStrList(o, "tags");
    p.maliciousDetections = getStrList(o, "maliciousDetections");
    p.suspiciousDetections = getStrList(o, "suspiciousDetections");
    p.droppedFiles = getStrList(o, "droppedFiles");
    p.registryKeys = getStrList(o, "registryKeys");
    p.contactedIps = getStrList(o, "contactedIps");
    p.contactedDomains = getStrList(o, "contactedDomains");
    return p;
}

// ===== 隔离区 =====
QJsonObject QuarantineItemPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["id"] = guidToString(id);
    o["originalPath"] = originalPath;
    o["fileName"] = fileName;
    o["quarantinedUtc"] = dateTimeToIso(quarantinedUtc);
    o["size"] = static_cast<double>(size);
    o["sha256"] = sha256;
    o["reason"] = reason;
    o["actorPid"] = actorPid;
    return o;
}
QuarantineItemPayload QuarantineItemPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    QuarantineItemPayload p;
    p.id = guidFromString(getStr(o, "id"));
    p.originalPath = getStr(o, "originalPath");
    p.fileName = getStr(o, "fileName");
    p.quarantinedUtc = dateTimeFromIso(getStr(o, "quarantinedUtc"));
    p.size = getI64(o, "size");
    p.sha256 = getStr(o, "sha256");
    p.reason = getStr(o, "reason");
    p.actorPid = getInt(o, "actorPid");
    return p;
}

QJsonObject QuarantineListResponsePayload::toJson() const {
    QJsonArray arr;
    for (const auto& i : items) arr.append(i.toJson());
    QJsonObject o; o["items"] = arr; return o;
}
QuarantineListResponsePayload QuarantineListResponsePayload::fromJson(const QJsonObject& o) {
    QuarantineListResponsePayload p;
    for (const auto& v : o.value(QLatin1String("items")).toArray())
        if (v.isObject()) p.items.append(QuarantineItemPayload::fromJson(v.toObject()));
    return p;
}

QJsonObject QuarantineActionPayload::toJson() const {
    using namespace bulwark::json; QJsonObject o; o["id"] = guidToString(id); return o;
}
QuarantineActionPayload QuarantineActionPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json; QuarantineActionPayload p; p.id = guidFromString(getStr(o, "id")); return p;
}

QJsonObject QuarantineActionResultPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o; o["id"] = guidToString(id); o["success"] = success; o["message"] = message; return o;
}
QuarantineActionResultPayload QuarantineActionResultPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    QuarantineActionResultPayload p;
    p.id = guidFromString(getStr(o, "id"));
    p.success = getBool(o, "success");
    p.message = getStr(o, "message");
    return p;
}

QJsonObject ManualQuarantinePayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o; o["requestId"] = guidToString(requestId); o["path"] = path; return o;
}
ManualQuarantinePayload ManualQuarantinePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    ManualQuarantinePayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.path = getStr(o, "path");
    return p;
}

QJsonObject ManualQuarantineResultPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o; o["requestId"] = guidToString(requestId); o["success"] = success; o["message"] = message; return o;
}
ManualQuarantineResultPayload ManualQuarantineResultPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    ManualQuarantineResultPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.success = getBool(o, "success");
    p.message = getStr(o, "message");
    return p;
}

// ===== 持久化审计 =====
QJsonObject PersistenceListResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonArray arr;
    for (const auto& e : entries) arr.append(e.toJson());
    QJsonObject o;
    o["scannedUtc"] = dateTimeToIso(scannedUtc);
    o["entries"] = arr;
    o["message"] = message;
    return o;
}
PersistenceListResponsePayload PersistenceListResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    PersistenceListResponsePayload p;
    p.scannedUtc = dateTimeFromIso(getStr(o, "scannedUtc"));
    for (const auto& v : o.value(QLatin1String("entries")).toArray())
        if (v.isObject()) p.entries.append(bulwark::PersistenceEntry::fromJson(v.toObject()));
    p.message = getStr(o, "message");
    return p;
}

// ===== AI 病毒扫描 =====
QJsonObject AiScanResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["eventId"] = guidToString(eventId);
    o["available"] = available;
    o["recommendation"] = static_cast<int>(recommendation);
    o["summary"] = summary;
    o["confidence"] = confidence;
    return o;
}
AiScanResponsePayload AiScanResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    AiScanResponsePayload p;
    p.eventId = guidFromString(getStr(o, "eventId"));
    p.available = getBool(o, "available");
    p.recommendation = static_cast<bulwark::VerdictAction>(getInt(o, "recommendation", 0));
    p.summary = getStr(o, "summary");
    p.confidence = getStr(o, "confidence");
    return p;
}

// ===== 足迹清理报告 =====
QJsonObject RemediationReportPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["timestampUtc"] = dateTimeToIso(timestampUtc);
    o["actorPath"] = actorPath;
    o["actorPid"] = actorPid;
    o["reason"] = reason;
    o["actorQuarantined"] = actorQuarantined;
    o["quarantinedFiles"] = strListToJson(quarantinedFiles);
    o["removedRegistryValues"] = strListToJson(removedRegistryValues);
    QJsonArray sk;
    for (const auto& s : skipped) sk.append(s.toJson());
    o["skipped"] = sk;
    o["intelSource"] = intelSource;
    o["intelDroppedFiles"] = strListToJson(intelDroppedFiles);
    o["intelDroppedFilePaths"] = strListToJson(intelDroppedFilePaths);
    o["intelDroppedFileHashes"] = strListToJson(intelDroppedFileHashes);
    o["intelRegistryKeys"] = strListToJson(intelRegistryKeys);
    o["intelContactedIps"] = strListToJson(intelContactedIps);
    o["intelContactedDomains"] = strListToJson(intelContactedDomains);
    o["intelServices"] = strListToJson(intelServices);
    o["intelProcessNames"] = strListToJson(intelProcessNames);
    o["intelMutexes"] = strListToJson(intelMutexes);
    o["intelRulesInjected"] = intelRulesInjected;
    return o;
}
RemediationReportPayload RemediationReportPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    RemediationReportPayload p;
    p.timestampUtc = dateTimeFromIso(getStr(o, "timestampUtc"));
    p.actorPath = getStr(o, "actorPath");
    p.actorPid = getInt(o, "actorPid");
    p.reason = getStr(o, "reason");
    p.actorQuarantined = getBool(o, "actorQuarantined");
    p.quarantinedFiles = getStrList(o, "quarantinedFiles");
    p.removedRegistryValues = getStrList(o, "removedRegistryValues");
    for (const auto& v : o.value(QLatin1String("skipped")).toArray())
        if (v.isObject()) p.skipped.append(RemediationSkippedItem::fromJson(v.toObject()));
    p.intelSource = getStr(o, "intelSource");
    p.intelDroppedFiles = getStrList(o, "intelDroppedFiles");
    p.intelDroppedFilePaths = getStrList(o, "intelDroppedFilePaths");
    p.intelDroppedFileHashes = getStrList(o, "intelDroppedFileHashes");
    p.intelRegistryKeys = getStrList(o, "intelRegistryKeys");
    p.intelContactedIps = getStrList(o, "intelContactedIps");
    p.intelContactedDomains = getStrList(o, "intelContactedDomains");
    p.intelServices = getStrList(o, "intelServices");
    p.intelProcessNames = getStrList(o, "intelProcessNames");
    p.intelMutexes = getStrList(o, "intelMutexes");
    p.intelRulesInjected = getInt(o, "intelRulesInjected");
    return p;
}

// ===== 威胁情报订阅(ThreatFox) =====
QJsonObject IntelRefreshRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o; o["requestId"] = guidToString(requestId); o["previewOnly"] = previewOnly; return o;
}
IntelRefreshRequestPayload IntelRefreshRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    IntelRefreshRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.previewOnly = getBool(o, "previewOnly");
    return p;
}

QJsonObject IntelRefreshResultPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["success"] = success;
    o["iocCount"] = iocCount;
    o["rulesApplied"] = rulesApplied;
    o["generatedRules"] = rulesToArray(generatedRules);
    o["threatContext"] = strListToJson(threatContext);
    o["message"] = message;
    return o;
}
IntelRefreshResultPayload IntelRefreshResultPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    IntelRefreshResultPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.success = getBool(o, "success");
    p.iocCount = getInt(o, "iocCount");
    p.rulesApplied = getInt(o, "rulesApplied");
    p.generatedRules = rulesFromArray(o.value(QLatin1String("generatedRules")).toArray());
    p.threatContext = getStrList(o, "threatContext");
    p.message = getStr(o, "message");
    return p;
}

QJsonObject IntelApplyRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o; o["requestId"] = guidToString(requestId); o["rules"] = rulesToArray(rules); return o;
}
IntelApplyRequestPayload IntelApplyRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    IntelApplyRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.rules = rulesFromArray(o.value(QLatin1String("rules")).toArray());
    return p;
}

} // namespace bulwark::ipc
