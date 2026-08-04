#pragma once
#include <QString>
#include <QDateTime>
#include <QJsonObject>
#include <optional>
#include "bulwark/models/Enums.h"
#include "bulwark/Clock.h"

namespace bulwark {

// 文件信誉结论(外部信誉源,如 VirusTotal 哈希查询)。仅以缓存形式参与本地评分,
// 绝不进入同步裁决路径的网络调用。对应 .NET Models/FileReputation.cs。
struct FileReputation {
    QString sha256;                              // 查询哈希(小写十六进制)
    ReputationVerdict verdict = ReputationVerdict::Unknown;
    int malicious = 0;                           // 检出引擎数
    int totalEngines = 0;                        // 参与引擎总数
    QString threatLabel;                         // 建议威胁名(可空)
    QString source;                              // 给出该结论的情报源名(VirusTotal / MalwareBazaar / …,可空)
    QDateTime fetchedUtc = nowUtc();
    std::optional<QDateTime> lastAnalysisUtc;    // VT 最近分析时间(可空)
    bool querySucceeded = false;                 // 查询是否权威完成

    bool isMalicious() const { return verdict == ReputationVerdict::Malicious; }

    QJsonObject toJson() const;
    static FileReputation fromJson(const QJsonObject& o);
};

} // namespace bulwark
