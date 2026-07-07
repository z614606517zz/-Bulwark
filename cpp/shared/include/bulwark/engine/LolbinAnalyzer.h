#pragma once
#include <QString>
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine {

// LOLBin(白利用二进制)滥用分析器:检查「已知系统二进制 + 特征滥用参数」组合,
// 命中即评分并标注 ATT&CK。签名无关(这些二进制本身签名健康)。纯函数,无状态。
// 对应 .NET Engine/LolbinAnalyzer.cs。
struct LolbinAnalyzer {
    static ScoreResult analyze(const QString& actorPath, const QString& commandLine);
    // 命令行是否构成「让签名 LOLBin 失去信任豁免」的高置信滥用(供 TrustPolicy 复用)。
    static bool isAbusedLolbin(const QString& actorPath, const QString& commandLine);
};

} // namespace bulwark::engine
