#include "bulwark/models/ProcessEntry.h"
#include "bulwark/json/JsonSupport.h"

namespace bulwark {
using namespace bulwark::json;

QString ProcessEntry::originLabel() const {
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

QJsonObject ProcessEntry::toJson() const {
    QJsonObject o;
    o["pid"] = pid;
    o["parentPid"] = parentPid;
    o["name"] = name;
    o["imagePath"] = imagePath;
    if (!commandLine.isEmpty())     o["commandLine"] = commandLine;
    if (!parentName.isEmpty())      o["parentName"] = parentName;
    if (!userName.isEmpty())        o["userName"] = userName;
    if (startTimeUtc.isValid())     o["startTimeUtc"] = dateTimeToIso(startTimeUtc);
    o["workingSetBytes"] = workingSetBytes;
    o["threadCount"] = threadCount;
    o["sessionId"] = sessionId;
    o["is64Bit"] = is64Bit;
    o["elevated"] = elevated;
    o["isSigned"] = isSigned;
    o["signatureMismatch"] = signatureMismatch;
    if (!publisher.isEmpty())       o["publisher"] = publisher;
    if (!fileDescription.isEmpty()) o["fileDescription"] = fileDescription;
    if (!sha256.isEmpty())          o["sha256"] = sha256;

    if (originKind != ProcessOriginKind::Unknown) o["originKind"] = static_cast<int>(originKind);
    if (!originService.isEmpty())        o["originService"] = originService;
    if (!originServiceDisplay.isEmpty()) o["originServiceDisplay"] = originServiceDisplay;
    if (!originTask.isEmpty())           o["originTask"] = originTask;
    if (!originDetail.isEmpty())         o["originDetail"] = originDetail;

    o["isCritical"] = isCritical;
    o["isProtectedSelf"] = isProtectedSelf;
    o["isTrusted"] = isTrusted;
    o["riskScore"] = riskScore;
    if (!riskReasons.isEmpty()) o["riskReasons"] = strListToJson(riskReasons);
    return o;
}

ProcessEntry ProcessEntry::fromJson(const QJsonObject& o) {
    ProcessEntry p;
    p.pid = getInt(o, "pid");
    p.parentPid = getInt(o, "parentPid");
    p.name = getStr(o, "name");
    p.imagePath = getStr(o, "imagePath");
    p.commandLine = getStr(o, "commandLine");
    p.parentName = getStr(o, "parentName");
    p.userName = getStr(o, "userName");
    p.startTimeUtc = dateTimeFromIso(getStr(o, "startTimeUtc"));
    p.workingSetBytes = getI64(o, "workingSetBytes");
    p.threadCount = getInt(o, "threadCount");
    p.sessionId = getInt(o, "sessionId");
    p.is64Bit = getBool(o, "is64Bit", true);
    p.elevated = getBool(o, "elevated");
    p.isSigned = getBool(o, "isSigned");
    p.signatureMismatch = getBool(o, "signatureMismatch");
    p.publisher = getStr(o, "publisher");
    p.fileDescription = getStr(o, "fileDescription");
    p.sha256 = getStr(o, "sha256");

    p.originKind = static_cast<ProcessOriginKind>(getInt(o, "originKind", 0));
    p.originService = getStr(o, "originService");
    p.originServiceDisplay = getStr(o, "originServiceDisplay");
    p.originTask = getStr(o, "originTask");
    p.originDetail = getStr(o, "originDetail");

    p.isCritical = getBool(o, "isCritical");
    p.isProtectedSelf = getBool(o, "isProtectedSelf");
    p.isTrusted = getBool(o, "isTrusted");
    p.riskScore = getInt(o, "riskScore");
    p.riskReasons = getStrList(o, "riskReasons");
    return p;
}

} // namespace bulwark
