#pragma once
#include <QString>
#include <QDateTime>
#include <QJsonObject>
#include "bulwark/models/Enums.h"
#include "bulwark/Clock.h"

namespace bulwark {

// 证据链中的单条记录(对应 .NET Models/Evidence.cs)。把「哪个分析器、什么类别、
// 加了多少分、说了什么」结构化下来,串成可解释的决策时间线。
struct Evidence {
    QDateTime timestampUtc = nowUtc();
    QString source;                       // 产生该证据的分析器/决策点
    EvidenceKind kind = EvidenceKind::Info;
    QString description;
    int scoreDelta = 0;                   // 对 riskScore 的贡献(可正可负)
    QString technique;                    // 可空:ATT&CK 编号
    QString techniqueName;                // 可空:技战术中文名

    QJsonObject toJson() const;
    static Evidence fromJson(const QJsonObject& o);
};

} // namespace bulwark
