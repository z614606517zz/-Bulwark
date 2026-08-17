#include "bulwark/models/VtScanRecord.h"
#include "bulwark/json/JsonSupport.h"

namespace bulwark {
using namespace bulwark::json;

QJsonObject VtScanRecord::toJson() const {
    QJsonObject o;
    o["id"] = guidToString(id);
    o["sha256"] = sha256;
    o["filePath"] = filePath;
    o["fileName"] = fileName;
    o["stage"] = static_cast<int>(stage);
    o["percent"] = percent;
    o["outcome"] = static_cast<int>(outcome);
    o["malicious"] = malicious;
    o["totalEngines"] = totalEngines;
    o["threatLabel"] = threatLabel;
    o["message"] = message;
    o["uploaded"] = uploaded;
    o["source"] = source;
    o["intelSource"] = intelSource;
    o["timestampUtc"] = dateTimeToIso(timestampUtc);
    return o;
}

VtScanRecord VtScanRecord::fromJson(const QJsonObject& o) {
    VtScanRecord r;
    const QUuid parsedId = guidFromString(getStr(o, "id"));
    if (!parsedId.isNull()) r.id = parsedId;
    r.sha256 = getStr(o, "sha256");
    r.filePath = getStr(o, "filePath");
    r.fileName = getStr(o, "fileName");
    r.stage = static_cast<VtScanStage>(getInt(o, "stage"));
    r.percent = getInt(o, "percent");
    r.outcome = static_cast<VtScanOutcome>(getInt(o, "outcome"));
    r.malicious = getInt(o, "malicious");
    r.totalEngines = getInt(o, "totalEngines");
    r.threatLabel = getStr(o, "threatLabel");
    r.message = getStr(o, "message");
    r.uploaded = getBool(o, "uploaded");
    r.source = getStr(o, "source");
    r.intelSource = getStr(o, "intelSource"); // 旧历史文件里没有这个键 -> 空,UI 自行兜底
    const QDateTime ts = dateTimeFromIso(getStr(o, "timestampUtc"));
    if (ts.isValid()) r.timestampUtc = ts;
    return r;
}

} // namespace bulwark
