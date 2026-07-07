#pragma once
#include <QString>
#include <QJsonObject>

namespace bulwark {

// 单个威胁情报源的实时用量快照(供「情报源连接」页展示今日消耗/配额)。纯展示,不参与裁决。
// 对应 .NET Models/ReputationUsage.cs。
struct ReputationUsage {
    QString source;
    bool enabled = false;
    int usedToday = 0;
    int dailyLimit = 0;
    int perMinuteLimit = 0;

    QJsonObject toJson() const;
    static ReputationUsage fromJson(const QJsonObject& o);
};

} // namespace bulwark
