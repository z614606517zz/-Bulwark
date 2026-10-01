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

    // 该模块名是否「易被搜索顺序劫持」——即它是系统 DLL 的名字,正常应用不会在自己的目录里
    // 放一个私有的同名模块。白加黑侧载检测的互证条件之一,见
    // SecurityEvent::sideloadedUnsignedModulePath 的说明。传文件名或完整路径均可。
    //
    // 放在这里(而不是 Worker 里)是因为判据要在两处使用:Worker 在富化阶段筛同目录模块,
    // ThreatDetector 在计分时复核。两处各抄一份必然漂移。
    static bool isSideloadProneModuleName(const QString& pathOrName);
};

} // namespace bulwark::engine
