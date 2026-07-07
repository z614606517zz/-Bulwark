#pragma once
#include <QString>
#include "bulwark/models/PersistenceEntry.h"

namespace bulwark::engine {

// 持久化项风险分析器。对每个自启动持久化项(PersistenceEntry)研判风险。
//
// 复用策略:把持久化项的「可执行路径 + 命令行」构造成一个合成的进程创建事件,交给
// ThreatDetector 跑完整启发式(LOLBin / 凭据 / 混淆 / 伪装 / 可疑目录 / 无签名 等),
// 无需重复实现检测逻辑;再叠加「该自启动点本身对应的 ATT&CK 持久化技战术」标注,经
// AttackAnnotator 统一汇总。设计原则:持久化「位置」本身中性(大量合法软件也自启),
// 真正风险来自「自启动的是什么、怎么跑的」。纯函数,无状态,线程安全。
// 对应 .NET Engine/PersistenceAnalyzer.cs。
struct PersistenceAnalyzer {
    // 分析并就地填充 entry 的 riskScore / riskReasons / techniques。
    static void analyze(bulwark::PersistenceEntry& entry);

    // 该持久化类别对应的主 ATT&CK 技战术编号(空串表示无)。
    static QString techniqueFor(bulwark::PersistenceCategory c);
};

} // namespace bulwark::engine
