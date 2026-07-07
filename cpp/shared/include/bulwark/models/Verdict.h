#pragma once
#include <QUuid>
#include <QJsonObject>
#include "bulwark/models/Enums.h"

namespace bulwark {

struct SecurityEvent; // fwd

// 对一次安全事件的最终裁决结果(对应 .NET Models/Verdict.cs)。
struct Verdict {
    QUuid eventId;
    VerdictAction action = VerdictAction::Allow;
    VerdictSource source = VerdictSource::DefaultPolicy;
    bool remember = false;

    static Verdict forEvent(const SecurityEvent& e, VerdictAction action,
                            VerdictSource source, bool remember = false);

    QJsonObject toJson() const;
    static Verdict fromJson(const QJsonObject& o);
};

} // namespace bulwark
