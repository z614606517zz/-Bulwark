#pragma once
#include <QString>
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine {

// 命令行混淆分析器(无特征码):从统计与结构特征(香农熵/符号占比/已知混淆构造/
// 超长 Base64 块)判定命令行是否被刻意混淆。对应 .NET Engine/CommandObfuscationAnalyzer.cs。
struct CommandObfuscationAnalyzer {
    static ScoreResult analyze(const QString& commandLine);
    // 香农熵 H = -Σ p·log2(p);公开供 DgaDomainAnalyzer 复用。
    static double shannonEntropy(const QString& s);
};

} // namespace bulwark::engine
