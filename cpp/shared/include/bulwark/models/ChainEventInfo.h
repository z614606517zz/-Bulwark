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
    // 该节点进程的「启动来源」(服务 / 计划任务 / 交互式…)与可读标签。让溯源链上的
    // svchost.exe 能显示成「服务:WinDefend」、taskeng/Schedule 派生能显示成具体任务名。
    // 纯溯源展示,不参与评分。
    ProcessOriginKind originKind = ProcessOriginKind::Unknown;
    QString originLabel;   // 例:"服务:Schedule" / "计划任务:\Microsoft\Windows\..."

    // 从一个完整安全事件提取精简快照(命令行截断到 256 字)。
    static ChainEventInfo from(const SecurityEvent& e);

    QJsonObject toJson() const;
    static ChainEventInfo fromJson(const QJsonObject& o);
};

} // namespace bulwark
