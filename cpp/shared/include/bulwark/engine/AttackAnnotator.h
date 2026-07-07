#pragma once
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// ATT&CK 技战术标注器:从证据链各条描述里正则提取 MITRE 编号(T1059 / T1218.010),
// 用 AttackCatalog 解析为「编号 + 名称」写回证据,并汇总去重到 SecurityEvent.techniques。
// 纯标注,零额外检测逻辑。对应 .NET Engine/AttackAnnotator.cs。
struct AttackAnnotator {
    static void annotate(bulwark::SecurityEvent& e);
};

} // namespace bulwark::engine
