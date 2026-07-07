#pragma once
#include <QString>
#include <QDateTime>
#include <QJsonObject>
#include "bulwark/models/Enums.h"

namespace bulwark {

// 远端 IP/域名信誉结论(网络威胁情报,如微步场景 API)。锦上添花的加分项,fail-open。
// 对应 .NET Models/IpReputation.cs。
struct IpReputation {
    QString resource;                                   // IPv4 点分或域名
    ReputationVerdict verdict = ReputationVerdict::Unknown;
    QString threatLabel;                                // 可空:C2/Botnet/...
    int confidence = 0;                                 // 0-100
    bool querySucceeded = false;
    QDateTime fetchedUtc = QDateTime::currentDateTimeUtc();

    QJsonObject toJson() const;
    static IpReputation fromJson(const QJsonObject& o);
};

} // namespace bulwark
