#pragma once
#include <QString>
#include <QDateTime>
#include <QJsonObject>
#include "bulwark/models/Enums.h"

namespace bulwark {

struct SecurityEvent; // fwd (avoid circular include)

// 进程链关联分析用的「精简事件快照」(对应 .NET Models/ChainEventInfo.cs)。
struct ChainEventInfo {
    QDateTime timestampUtc;
    EventType type = EventType::ProcessCreate;
    int actorPid = 0;
    int parentPid = 0;
    QString actorPath;
    QString commandLine;   // 可空(打包时截断)
    QString target;
    int riskScore = 0;

    // 从一个完整安全事件提取精简快照(命令行截断到 256 字)。
    static ChainEventInfo from(const SecurityEvent& e);

    QJsonObject toJson() const;
    static ChainEventInfo fromJson(const QJsonObject& o);
};

} // namespace bulwark
