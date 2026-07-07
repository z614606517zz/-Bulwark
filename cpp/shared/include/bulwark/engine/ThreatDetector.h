#pragma once
#include <QString>
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 启发式威胁检测器。对一个安全事件计算风险评分(0-100)并把结构化证据写入事件。
// 不依赖病毒库,基于行为特征:可疑路径 / 缺签名 / 异常父子链 / LOLBin 命令行 /
// 进程伪装等,并汇聚各专项分析器(Lolbin/凭据/规避/注入/混淆/脚本/杀伤链)。
// 对应 .NET Engine/ThreatDetector.cs。
struct ThreatDetector {
    static constexpr int HighRisk = 80;   // >= 高危,建议阻止
    static constexpr int Suspicious = 50; // >= 可疑,建议询问

    static void analyze(SecurityEvent& e);
    static bool isSuspiciousDropDir(const QString& path);
};

} // namespace bulwark::engine
