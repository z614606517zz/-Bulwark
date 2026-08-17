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

QJsonObject PersistenceCleanupRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["entry"] = entry.toJson();
    return o;
}
PersistenceCleanupRequestPayload PersistenceCleanupRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    PersistenceCleanupRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.entry = bulwark::PersistenceEntry::fromJson(o.value(QLatin1String("entry")).toObject());
    return p;
}

QJsonObject PersistenceCleanupResultPayload::toJson() const {
    using namespace bulwark::json;
    QJsonArray skippedArr;
    for (const auto& s : skipped) skippedArr.append(s.toJson());
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["success"] = success;
    o["entryId"] = entryId;
    o["message"] = message;
    o["quarantinedFiles"] = strListToJson(quarantinedFiles);
    o["removedRegistryValues"] = strListToJson(removedRegistryValues);
    o["skipped"] = skippedArr;
    return o;
}
PersistenceCleanupResultPayload PersistenceCleanupResultPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    PersistenceCleanupResultPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.success = o.value(QLatin1String("success")).toBool();
    p.entryId = getStr(o, "entryId");
    p.message = getStr(o, "message");
    p.quarantinedFiles = getStrList(o, "quarantinedFiles");
    p.removedRegistryValues = getStrList(o, "removedRegistryValues");
    for (const auto& v : o.value(QLatin1String("skipped")).toArray())
        if (v.isObject()) p.skipped.append(RemediationSkippedItem::fromJson(v.toObject()));
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

// ---- helpers for int-list (de)serialization ---------------------------------
namespace {
QJsonArray intListToArray(const QList<int>& list) {
    QJsonArray arr;
    for (int v : list) arr.append(v);
    return arr;
}
QList<int> intListFromArray(const QJsonArray& arr) {
    QList<int> out;
    out.reserve(arr.size());
    for (const QJsonValue& v : arr)
        if (v.isDouble()) out.append(v.toInt());
    return out;
}
} // namespace

// ===== 事件时间线 =====
QJsonObject TimelineRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    if (fromUtc.isValid()) o["fromUtc"] = dateTimeToIso(fromUtc);
    if (toUtc.isValid())   o["toUtc"] = dateTimeToIso(toUtc);
    if (!types.isEmpty())   o["types"] = intListToArray(types);
    if (!actions.isEmpty()) o["actions"] = intListToArray(actions);
    o["minRiskScore"] = minRiskScore;
    o["pid"] = pid;
    o["includeProcessTree"] = includeProcessTree;
    o["text"] = text;
    o["limit"] = limit;
    return o;
}
TimelineRequestPayload TimelineRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    TimelineRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.fromUtc = dateTimeFromIso(getStr(o, "fromUtc"));
    p.toUtc = dateTimeFromIso(getStr(o, "toUtc"));
    p.types = intListFromArray(o.value(QLatin1String("types")).toArray());
    p.actions = intListFromArray(o.value(QLatin1String("actions")).toArray());
    p.minRiskScore = getInt(o, "minRiskScore");
    p.pid = getInt(o, "pid");
    p.includeProcessTree = getBool(o, "includeProcessTree");
    p.text = getStr(o, "text");
    p.limit = getInt(o, "limit", 500);
    return p;
}

QJsonObject TimelineResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonArray arr;
    for (const EventLogPayload& e : events) arr.append(e.toJson());
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["events"] = arr;
    o["scanned"] = scanned;
    o["matched"] = matched;
    o["truncated"] = truncated;
    if (earliestUtc.isValid()) o["earliestUtc"] = dateTimeToIso(earliestUtc);
    o["message"] = message;
    return o;
}
TimelineResponsePayload TimelineResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    TimelineResponsePayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    const QJsonArray arr = o.value(QLatin1String("events")).toArray();
    p.events.reserve(arr.size());
    for (const QJsonValue& v : arr)
        if (v.isObject()) p.events.append(EventLogPayload::fromJson(v.toObject()));
    p.scanned = getInt(o, "scanned");
    p.matched = getInt(o, "matched");
    p.truncated = getBool(o, "truncated");
    p.earliestUtc = dateTimeFromIso(getStr(o, "earliestUtc"));
    p.message = getStr(o, "message");
    return p;
}

// ===== 攻击图 =====
QJsonObject AttackGraphRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["seedEventId"] = guidToString(seedEventId);
    o["rootPid"] = rootPid;
    o["windowSeconds"] = windowSeconds;
    return o;
}
AttackGraphRequestPayload AttackGraphRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    AttackGraphRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.seedEventId = guidFromString(getStr(o, "seedEventId"));
    p.rootPid = getInt(o, "rootPid");
    p.windowSeconds = getInt(o, "windowSeconds", 3600);
    return p;
}

QJsonObject AttackGraphResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["success"] = success;
    o["message"] = message;
    o["graph"] = graph.toJson();
    return o;
}
AttackGraphResponsePayload AttackGraphResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    AttackGraphResponsePayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.success = getBool(o, "success");
    p.message = getStr(o, "message");
    p.graph = bulwark::AttackGraph::fromJson(o.value(QLatin1String("graph")).toObject());
    return p;
}

// ===== 进程管理 =====
QJsonObject ProcessListRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["includeCommandLine"] = includeCommandLine;
    o["resolveOrigin"] = resolveOrigin;
    return o;
}
ProcessListRequestPayload ProcessListRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    ProcessListRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.includeCommandLine = getBool(o, "includeCommandLine", true);
    p.resolveOrigin = getBool(o, "resolveOrigin", true);
    return p;
}

QJsonObject ProcessListResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonArray arr;
    for (const bulwark::ProcessEntry& e : processes) arr.append(e.toJson());
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["snapshotUtc"] = dateTimeToIso(snapshotUtc);
    o["processes"] = arr;
    o["message"] = message;
    return o;
}
ProcessListResponsePayload ProcessListResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    ProcessListResponsePayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.snapshotUtc = dateTimeFromIso(getStr(o, "snapshotUtc"));
    for (const QJsonValue& v : o.value(QLatin1String("processes")).toArray())
        if (v.isObject()) p.processes.append(bulwark::ProcessEntry::fromJson(v.toObject()));
    p.message = getStr(o, "message");
    return p;
}

QJsonObject ProcessActionRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["kind"] = static_cast<int>(kind);
    o["pid"] = pid;
    o["imagePath"] = imagePath;
    return o;
}
ProcessActionRequestPayload ProcessActionRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    ProcessActionRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.kind = static_cast<ProcessActionKind>(getInt(o, "kind", 0));
    p.pid = getInt(o, "pid");
    p.imagePath = getStr(o, "imagePath");
    return p;
}

QJsonObject ProcessActionResultPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["kind"] = static_cast<int>(kind);
    o["pid"] = pid;
    o["success"] = success;
    o["message"] = message;
    if (!sha256.isEmpty()) o["sha256"] = sha256;
    return o;
}
ProcessActionResultPayload ProcessActionResultPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    ProcessActionResultPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.kind = static_cast<ProcessActionKind>(getInt(o, "kind", 0));
    p.pid = getInt(o, "pid");
    p.success = getBool(o, "success");
    p.message = getStr(o, "message");
    p.sha256 = getStr(o, "sha256");
    return p;
}

// ---- 攻击链组合引擎 --------------------------------------------------------- #

QJsonObject AttackChainHitPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["whenUtc"] = dateTimeToIso(whenUtc);
    o["actorPath"] = actorPath;
    o["actorPid"] = actorPid;
    o["titles"] = strListToJson(titles);
    o["grade"] = grade;
    o["maxLevel"] = maxLevel;
    o["support"] = support;
    o["families"] = families;
    o["dryRun"] = dryRun;
    o["action"] = action;
    o["eventType"] = eventType;
    return o;
}

AttackChainHitPayload AttackChainHitPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    AttackChainHitPayload h;
    h.whenUtc = dateTimeFromIso(getStr(o, "whenUtc"));
    h.actorPath = getStr(o, "actorPath");
    h.actorPid = getInt(o, "actorPid");
    h.titles = getStrList(o, "titles");
    h.grade = getStr(o, "grade");
    h.maxLevel = getStr(o, "maxLevel");
    h.support = getInt(o, "support");
    h.families = getStr(o, "families");
    h.dryRun = getBool(o, "dryRun", true);
    h.action = getStr(o, "action");
    h.eventType = getStr(o, "eventType");
    return h;
}

QJsonObject AttackChainResponsePayload::toJson() const {
    QJsonObject o;
    o["enabled"] = enabled;
    o["dryRun"] = dryRun;
    o["version"] = version;
    o["versionLabel"] = versionLabel;
    o["patterns"] = patterns;
    o["markers"] = markers;
    o["trackedProcesses"] = trackedProcesses;
    o["endpoint"] = endpoint;
    o["updateSchedule"] = updateSchedule;
    QJsonArray arr;
    for (const AttackChainHitPayload& h : hits)
        arr.append(h.toJson());
    o["hits"] = arr;
    return o;
}

AttackChainResponsePayload AttackChainResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    AttackChainResponsePayload p;
    p.enabled = getBool(o, "enabled");
    p.dryRun = getBool(o, "dryRun", true);
    p.version = getInt(o, "version");
    p.versionLabel = getStr(o, "versionLabel");   // 老服务端不带此键 -> 空串,界面自行回退
    p.patterns = getInt(o, "patterns");
    p.markers = getInt(o, "markers");
    p.trackedProcesses = getInt(o, "trackedProcesses");
    p.endpoint = getStr(o, "endpoint");
    p.updateSchedule = getStr(o, "updateSchedule");
    for (const QJsonValue& v : o.value(QLatin1String("hits")).toArray())
        p.hits.append(AttackChainHitPayload::fromJson(v.toObject()));
    return p;
}

} // namespace bulwark::ipc

// ===== 在线更新 =====
// 大小走 double:QJsonValue 没有独立的 64 位整型,qint64 一律经 double 存取。
// 载荷大小是几 MB 量级,远在 double 能精确表示整数的范围(2^53)之内。

namespace bulwark::ipc {

QJsonObject UpdateCheckResponsePayload::toJson() const {
    QJsonArray arr;
    for (const UpdateFileBrief& f : files) {
        QJsonObject o;
        o[QStringLiteral("name")] = f.name;
        o[QStringLiteral("size")] = static_cast<double>(f.size);
        arr.append(o);
    }
    QJsonObject o;
    o[QStringLiteral("ok")] = ok;
    o[QStringLiteral("available")] = available;
    o[QStringLiteral("error")] = error;
    o[QStringLiteral("currentVersion")] = currentVersion;
    o[QStringLiteral("version")] = version;
    o[QStringLiteral("label")] = label;
    o[QStringLiteral("notes")] = notes;
    o[QStringLiteral("publishedUtc")] = publishedUtc;
    o[QStringLiteral("endpointMasked")] = endpointMasked;
    o[QStringLiteral("totalBytes")] = static_cast<double>(totalBytes);
    o[QStringLiteral("files")] = arr;
    return o;
}

UpdateCheckResponsePayload UpdateCheckResponsePayload::fromJson(const QJsonObject& o) {
    UpdateCheckResponsePayload p;
    p.ok = o.value(QStringLiteral("ok")).toBool();
    p.available = o.value(QStringLiteral("available")).toBool();
    p.error = o.value(QStringLiteral("error")).toString();
    p.currentVersion = o.value(QStringLiteral("currentVersion")).toString();
    p.version = o.value(QStringLiteral("version")).toString();
    p.label = o.value(QStringLiteral("label")).toString();
    p.notes = o.value(QStringLiteral("notes")).toString();
    p.publishedUtc = o.value(QStringLiteral("publishedUtc")).toString();
    p.endpointMasked = o.value(QStringLiteral("endpointMasked")).toString();
    p.totalBytes = static_cast<qint64>(o.value(QStringLiteral("totalBytes")).toDouble());
    for (const QJsonValue& v : o.value(QStringLiteral("files")).toArray()) {
        const QJsonObject f = v.toObject();
        UpdateFileBrief b;
        b.name = f.value(QStringLiteral("name")).toString();
        b.size = static_cast<qint64>(f.value(QStringLiteral("size")).toDouble());
        p.files.append(b);
    }
    return p;
}

QJsonObject UpdateProgressPayload::toJson() const {
    QJsonObject o;
    o[QStringLiteral("done")] = done;
    o[QStringLiteral("total")] = total;
    o[QStringLiteral("fileName")] = fileName;
    o[QStringLiteral("stage")] = stage;
    return o;
}

UpdateProgressPayload UpdateProgressPayload::fromJson(const QJsonObject& o) {
    UpdateProgressPayload p;
    p.done = o.value(QStringLiteral("done")).toInt();
    p.total = o.value(QStringLiteral("total")).toInt();
    p.fileName = o.value(QStringLiteral("fileName")).toString();
    p.stage = o.value(QStringLiteral("stage")).toString();
    return p;
}

QJsonObject UpdateDownloadResponsePayload::toJson() const {
    QJsonObject o;
    o[QStringLiteral("ok")] = ok;
    o[QStringLiteral("error")] = error;
    o[QStringLiteral("version")] = version;
    o[QStringLiteral("stagingDir")] = stagingDir;
    o[QStringLiteral("verified")] = verified;
    return o;
}

UpdateDownloadResponsePayload UpdateDownloadResponsePayload::fromJson(const QJsonObject& o) {
    UpdateDownloadResponsePayload p;
    p.ok = o.value(QStringLiteral("ok")).toBool();
    p.error = o.value(QStringLiteral("error")).toString();
    p.version = o.value(QStringLiteral("version")).toString();
    p.stagingDir = o.value(QStringLiteral("stagingDir")).toString();
    p.verified = o.value(QStringLiteral("verified")).toInt();
    return p;
}

QJsonObject UpdateApplyResponsePayload::toJson() const {
    QJsonObject o;
    o[QStringLiteral("ok")] = ok;
    o[QStringLiteral("error")] = error;
    o[QStringLiteral("version")] = version;
    o[QStringLiteral("replaced")] = replaced;
    o[QStringLiteral("rolledBack")] = rolledBack;
    o[QStringLiteral("needsRestart")] = needsRestart;
    return o;
}

UpdateApplyResponsePayload UpdateApplyResponsePayload::fromJson(const QJsonObject& o) {
    UpdateApplyResponsePayload p;
    p.ok = o.value(QStringLiteral("ok")).toBool();
    p.error = o.value(QStringLiteral("error")).toString();
    p.version = o.value(QStringLiteral("version")).toString();
    p.replaced = o.value(QStringLiteral("replaced")).toInt();
    p.rolledBack = o.value(QStringLiteral("rolledBack")).toBool();
    // 默认 true:老服务端不下发这个字段时,「需要重启才生效」是安全的一侧 ——
    // 反过来会让界面宣称已经在跑新版,而实际上没有。
    p.needsRestart = o.value(QStringLiteral("needsRestart")).toBool(true);
    return p;
}

// ===== 磁盘垃圾清理 =====

QJsonObject JunkScanRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    if (!categories.isEmpty()) o["categories"] = intListToArray(categories);
    o["minAgeHours"] = minAgeHours;
    return o;
}
JunkScanRequestPayload JunkScanRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    JunkScanRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.categories = intListFromArray(o.value(QLatin1String("categories")).toArray());
    p.minAgeHours = getInt(o, "minAgeHours");
    return p;
}

QJsonObject JunkScanResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonArray arr;
    for (const bulwark::JunkCategoryResult& c : categories) arr.append(c.toJson());
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["scannedUtc"] = dateTimeToIso(scannedUtc);
    o["enabled"] = enabled;
    o["categories"] = arr;
    o["totalBytes"] = static_cast<double>(totalBytes);
    o["totalFiles"] = totalFiles;
    o["minAgeHours"] = minAgeHours;
    o["truncated"] = truncated;
    o["unreadable"] = unreadable;
    o["elapsedMs"] = static_cast<double>(elapsedMs);
    o["message"] = message;
    return o;
}
JunkScanResponsePayload JunkScanResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    JunkScanResponsePayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.scannedUtc = dateTimeFromIso(getStr(o, "scannedUtc"));
    p.enabled = getBool(o, "enabled", true);
    for (const QJsonValue& v : o.value(QLatin1String("categories")).toArray())
        if (v.isObject()) p.categories.append(bulwark::JunkCategoryResult::fromJson(v.toObject()));
    p.totalBytes = getI64(o, "totalBytes");
    p.totalFiles = getInt(o, "totalFiles");
    p.minAgeHours = getInt(o, "minAgeHours");
    p.truncated = getBool(o, "truncated");
    p.unreadable = getInt(o, "unreadable");
    p.elapsedMs = getI64(o, "elapsedMs");
    p.message = getStr(o, "message");
    return p;
}

QJsonObject JunkCleanRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    // 清理请求刻意【无条件】写出 categories,即便为空 —— 空数组在这里是有含义的
    // (「什么都不清理」),不能靠键缺失来表达,否则解析侧分不清「没选」和「旧版本没这个字段」。
    o["categories"] = intListToArray(categories);
    o["minAgeHours"] = minAgeHours;
    return o;
}
JunkCleanRequestPayload JunkCleanRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    JunkCleanRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.categories = intListFromArray(o.value(QLatin1String("categories")).toArray());
    p.minAgeHours = getInt(o, "minAgeHours");
    return p;
}

QJsonObject JunkCleanResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonArray arr;
    for (const bulwark::JunkCleanOutcome& c : outcomes) arr.append(c.toJson());
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["finishedUtc"] = dateTimeToIso(finishedUtc);
    o["success"] = success;
    o["outcomes"] = arr;
    o["freedBytes"] = static_cast<double>(freedBytes);
    o["deletedFiles"] = deletedFiles;
    o["skipped"] = skipped;
    o["message"] = message;
    return o;
}
JunkCleanResponsePayload JunkCleanResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    JunkCleanResponsePayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.finishedUtc = dateTimeFromIso(getStr(o, "finishedUtc"));
    p.success = getBool(o, "success");
    for (const QJsonValue& v : o.value(QLatin1String("outcomes")).toArray())
        if (v.isObject()) p.outcomes.append(bulwark::JunkCleanOutcome::fromJson(v.toObject()));
    p.freedBytes = getI64(o, "freedBytes");
    p.deletedFiles = getInt(o, "deletedFiles");
    p.skipped = getInt(o, "skipped");
    p.message = getStr(o, "message");
    return p;
}

QJsonObject LargeFileScanRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["minBytes"] = static_cast<double>(minBytes);
    o["limit"] = limit;
    return o;
}
LargeFileScanRequestPayload LargeFileScanRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    LargeFileScanRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.minBytes = getI64(o, "minBytes");
    p.limit = getInt(o, "limit");
    return p;
}

QJsonObject LargeFileScanResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonArray arr;
    for (const bulwark::LargeFileEntry& f : files) arr.append(f.toJson());
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["scannedUtc"] = dateTimeToIso(scannedUtc);
    o["enabled"] = enabled;
    o["files"] = arr;
    o["minBytes"] = static_cast<double>(minBytes);
    o["totalBytes"] = static_cast<double>(totalBytes);
    o["scannedFiles"] = scannedFiles;
    o["unreadable"] = unreadable;
    o["truncated"] = truncated;
    o["elapsedMs"] = static_cast<double>(elapsedMs);
    o["message"] = message;
    return o;
}
LargeFileScanResponsePayload LargeFileScanResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    LargeFileScanResponsePayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.scannedUtc = dateTimeFromIso(getStr(o, "scannedUtc"));
    p.enabled = getBool(o, "enabled", true);
    for (const QJsonValue& v : o.value(QLatin1String("files")).toArray())
        if (v.isObject()) p.files.append(bulwark::LargeFileEntry::fromJson(v.toObject()));
    p.minBytes = getI64(o, "minBytes");
    p.totalBytes = getI64(o, "totalBytes");
    p.scannedFiles = getInt(o, "scannedFiles");
    p.unreadable = getInt(o, "unreadable");
    p.truncated = getBool(o, "truncated");
    p.elapsedMs = getI64(o, "elapsedMs");
    p.message = getStr(o, "message");
    return p;
}

QJsonObject JunkProgressPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["cleaning"] = cleaning;
    o["categoryIndex"] = categoryIndex;
    o["categoryTotal"] = categoryTotal;
    o["categoryTitle"] = categoryTitle;
    o["currentPath"] = currentPath;
    o["bytesSoFar"] = static_cast<double>(bytesSoFar);
    o["filesSoFar"] = filesSoFar;
    return o;
}
JunkProgressPayload JunkProgressPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    JunkProgressPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.cleaning = getBool(o, "cleaning");
    p.categoryIndex = getInt(o, "categoryIndex");
    p.categoryTotal = getInt(o, "categoryTotal");
    p.categoryTitle = getStr(o, "categoryTitle");
    p.currentPath = getStr(o, "currentPath");
    p.bytesSoFar = getI64(o, "bytesSoFar");
    p.filesSoFar = getInt(o, "filesSoFar");
    return p;
}

} // namespace bulwark::ipc
