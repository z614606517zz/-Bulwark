#pragma once
#include <QJsonObject>
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/Verdict.h"

namespace bulwark::engine {

// 把一次安全事件 + 裁决渲染成 Elastic Common Schema(ECS)告警 JSON 文档,
// 便于导出到 SIEM。附带 bulwark.* 扩展(完整证据链)与 MITRE ATT&CK threat.*。
// 对应 .NET Engine/EcsAlertFormatter.cs。
struct EcsAlertFormatter {
    static constexpr char EcsVersion[] = "8.11.0";

    static QJsonObject format(const bulwark::SecurityEvent& e, const bulwark::Verdict& v);
};

} // namespace bulwark::engine
