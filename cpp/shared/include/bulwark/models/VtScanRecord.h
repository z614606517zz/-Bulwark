#pragma once
#include <QString>
#include <QUuid>
#include <QDateTime>
#include <QJsonObject>

namespace bulwark {

// VT 上传扫描的进度阶段(服务端逐阶段推送给 UI)。
enum class VtScanStage { Queued = 0, Querying, Uploading, Analyzing, Completed, Error };

// VT 扫描最终结论。
enum class VtScanOutcome { Pending = 0, Clean, Suspicious, Malicious, Unknown, Error };

// 一条 VirusTotal 扫描记录:既是服务端->UI 的实时进度推送负载(随阶段多次推送,以 id 关联),
// 也是「VT 查询记录」视图的持久化条目。对应 .NET Models/VtScanRecord.cs。
struct VtScanRecord {
    QUuid id = QUuid::createUuid();
    QString sha256;                  // 小写十六进制
    QString filePath;
    QString fileName;
    VtScanStage stage = VtScanStage::Queued;
    int percent = 0;                 // 仅 Uploading 阶段有意义
    VtScanOutcome outcome = VtScanOutcome::Pending;
    int malicious = 0;
    int totalEngines = 0;
    QString threatLabel;             // 可空
    QString message;                 // 可空:进度/结论/错误说明
    bool uploaded = false;
    QString source;                  // 双击 / Dropper / 手动
    QDateTime timestampUtc = QDateTime::currentDateTimeUtc();

    bool isTerminal() const { return stage == VtScanStage::Completed || stage == VtScanStage::Error; }

    QJsonObject toJson() const;
    static VtScanRecord fromJson(const QJsonObject& o);
};

} // namespace bulwark
