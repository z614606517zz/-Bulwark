#include "bulwark/models/SecurityEvent.h"
#include "bulwark/json/JsonSupport.h"
#include <QJsonArray>

namespace bulwark {
using namespace bulwark::json;

void SecurityEvent::addEvidence(const QString& source, EvidenceKind kind,
                                const QString& description, int scoreDelta,
                                bool alsoReason) {
    Evidence e;
    e.timestampUtc = nowUtc();
    e.source = source;
    e.kind = kind;
    e.description = description;
    e.scoreDelta = scoreDelta;
    evidenceChain.push_back(e);
    // 保持与旧的扁平 riskReasons 兼容(不在此处改动 riskScore —— 由引擎累加)。
    if (alsoReason && !description.isEmpty() && !riskReasons.contains(description))
        riskReasons << description;
}

QString SecurityEvent::originLabel() const {
    switch (originKind) {
        case ProcessOriginKind::Service: {
            if (originService.isEmpty())
                return QString::fromUtf8("服务");
            QString s = QString::fromUtf8("服务:") + originService;
            if (!originServiceDisplay.isEmpty()
                && originServiceDisplay.compare(originService, Qt::CaseInsensitive) != 0)
                s += QStringLiteral(" (") + originServiceDisplay + QLatin1Char(')');
            return s;
        }
        case ProcessOriginKind::ScheduledTask:
            return originTask.isEmpty() ? QString::fromUtf8("计划任务")
                                        : QString::fromUtf8("计划任务:") + originTask;
        case ProcessOriginKind::WmiProvider:    return QString::fromUtf8("WMI 提供者宿主派生");
        case ProcessOriginKind::LogonAutostart: return QString::fromUtf8("登录自启动");
        case ProcessOriginKind::SystemBoot:     return QString::fromUtf8("系统启动");
        case ProcessOriginKind::Interactive:    return QString::fromUtf8("交互式启动");
        case ProcessOriginKind::Unknown:        break;
    }
    return QString();
}

QJsonObject SecurityEvent::toJson() const {
    QJsonObject o;
    o["id"] = guidToString(id);
    o["timestampUtc"] = dateTimeToIso(timestampUtc);
    o["type"] = static_cast<int>(type);

    o["actorPid"] = actorPid;
    o["actorPath"] = actorPath;
    o["actorHash"] = actorHash;
    o["actorSigned"] = actorSigned;
    o["signatureMismatch"] = signatureMismatch;
    o["actorFileSize"] = actorFileSize;
    o["actorPublisher"] = actorPublisher;
    o["actorCertThumbprint"] = actorCertThumbprint;
    o["certNotAfterUtc"] = optDateToJson(certNotAfterUtc);
    o["signingTimeUtc"] = optDateToJson(signingTimeUtc);
    o["certRevoked"] = certRevoked;
    o["signedAfterCertExpiry"] = signedAfterCertExpiry;
    o["isFirstSeen"] = isFirstSeen;
    if (reputation.has_value()) o["reputation"] = reputation->toJson();

    o["originatorPid"] = originatorPid;
    o["originatorPath"] = originatorPath;
    o["parentPid"] = parentPid;
    o["parentPath"] = parentPath;
    if (originKind != ProcessOriginKind::Unknown) o["originKind"] = static_cast<int>(originKind);
    if (!originService.isEmpty())        o["originService"] = originService;
    if (!originServiceDisplay.isEmpty()) o["originServiceDisplay"] = originServiceDisplay;
    if (!originTask.isEmpty())           o["originTask"] = originTask;
    if (!originDetail.isEmpty())         o["originDetail"] = originDetail;
    o["commandLine"] = commandLine;
    o["target"] = target;
    o["detail"] = detail;

    o["riskScore"] = riskScore;
    o["riskReasons"] = strListToJson(riskReasons);

    QJsonArray ev;
    for (const Evidence& e : evidenceChain) ev.append(e.toJson());
    o["evidenceChain"] = ev;

    o["techniques"] = strListToJson(techniques);
    o["hasThreatIndicator"] = hasThreatIndicator;
    o["matchedRuleNote"] = matchedRuleNote;
    o["userModeObserved"] = userModeObserved;
    o["kernelBlocked"] = kernelBlocked;
    o["memoryInjection"] = memoryInjection;
    o["fileDescription"] = fileDescription;

    QJsonArray chain;
    for (const ChainEventInfo& c : chainContext) chain.append(c.toJson());
    o["chainContext"] = chain;
    return o;
}

SecurityEvent SecurityEvent::fromJson(const QJsonObject& o) {
    SecurityEvent e;
    const QUuid parsedId = guidFromString(getStr(o, "id"));
    if (!parsedId.isNull()) e.id = parsedId;
    const QDateTime ts = dateTimeFromIso(getStr(o, "timestampUtc"));
    if (ts.isValid()) e.timestampUtc = ts;
    e.type = static_cast<EventType>(getInt(o, "type"));

    e.actorPid = getInt(o, "actorPid");
    e.actorPath = getStr(o, "actorPath");
    e.actorHash = getStr(o, "actorHash");
    e.actorSigned = getBool(o, "actorSigned");
    e.signatureMismatch = getBool(o, "signatureMismatch");
    e.actorFileSize = getI64(o, "actorFileSize");
    e.actorPublisher = getStr(o, "actorPublisher");
    e.actorCertThumbprint = getStr(o, "actorCertThumbprint");
    e.certNotAfterUtc = optDateFromJson(o.value(QLatin1String("certNotAfterUtc")));
    e.signingTimeUtc = optDateFromJson(o.value(QLatin1String("signingTimeUtc")));
    e.certRevoked = getBool(o, "certRevoked");
    e.signedAfterCertExpiry = getBool(o, "signedAfterCertExpiry");
    e.isFirstSeen = getBool(o, "isFirstSeen");
    const QJsonValue rep = o.value(QLatin1String("reputation"));
    if (rep.isObject()) e.reputation = FileReputation::fromJson(rep.toObject());

    e.originatorPid = getInt(o, "originatorPid");
    e.originatorPath = getStr(o, "originatorPath");
    e.parentPid = getInt(o, "parentPid");
    e.parentPath = getStr(o, "parentPath");
    e.originKind = static_cast<ProcessOriginKind>(getInt(o, "originKind", 0));
    e.originService = getStr(o, "originService");
    e.originServiceDisplay = getStr(o, "originServiceDisplay");
    e.originTask = getStr(o, "originTask");
    e.originDetail = getStr(o, "originDetail");
    e.commandLine = getStr(o, "commandLine");
    e.target = getStr(o, "target");
    e.detail = getStr(o, "detail");

    e.riskScore = getInt(o, "riskScore");
    e.riskReasons = getStrList(o, "riskReasons");

    const QJsonArray ev = o.value(QLatin1String("evidenceChain")).toArray();
    e.evidenceChain.reserve(ev.size());
    for (const QJsonValue& v : ev) e.evidenceChain.push_back(Evidence::fromJson(v.toObject()));

    e.techniques = getStrList(o, "techniques");
    e.hasThreatIndicator = getBool(o, "hasThreatIndicator");
    e.matchedRuleNote = getStr(o, "matchedRuleNote");
    e.userModeObserved = getBool(o, "userModeObserved");
    e.kernelBlocked = getBool(o, "kernelBlocked");
    e.memoryInjection = getBool(o, "memoryInjection");
    e.fileDescription = getStr(o, "fileDescription");

    const QJsonArray chain = o.value(QLatin1String("chainContext")).toArray();
    e.chainContext.reserve(chain.size());
    for (const QJsonValue& v : chain) e.chainContext.push_back(ChainEventInfo::fromJson(v.toObject()));
    return e;
}

} // namespace bulwark
