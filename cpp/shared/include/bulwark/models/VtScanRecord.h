#pragma once
#include <QString>
#include <QUuid>
#include <QDateTime>
#include <QJsonObject>
#include "bulwark/Clock.h"

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
    QString source;                  // 触发来源:双击 / Dropper / 手动
    // 结论【由谁给出】的展示名,与上面的 source(触发来源)是两件事:
    //   "中央服务器·VirusTotal" / "中央服务器" / "VirusTotal" / "MalwareBazaar" / "本机缓存" …
    // 云查毒刻意「先问中央服务器有没有收录、没收录才动本机密钥」,所以「这条结论到底是服务器
    // 给的还是本机直连 VT 查的」是用户和排查都要看的一维。以前它只被拼进 message 文本里,
    // 终态行与详情图都拿不到,详情图的中枢节点因此写死成 "VirusTotal" —— 服务器命中或
    // MalwareBazaar 命中时那个标签是错的。
    QString intelSource;
    QDateTime timestampUtc = nowUtc();

    bool isTerminal() const { return stage == VtScanStage::Completed || stage == VtScanStage::Error; }

    QJsonObject toJson() const;
    static VtScanRecord fromJson(const QJsonObject& o);
};

} // namespace bulwark
