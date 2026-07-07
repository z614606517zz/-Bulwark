#pragma once
#include <QString>
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine {

// DGA(域名生成算法)随机度分析器:只看域名字符串统计特征(香农熵/元音比例/
// 连续辅音/数字交错),无黑名单。输出为软信号,需与硬指标互证方可升格。
// 对应 .NET Engine/DgaDomainAnalyzer.cs。
struct DgaDomainAnalyzer {
    static ScoreResult analyze(const QString& target);
};

} // namespace bulwark::engine
