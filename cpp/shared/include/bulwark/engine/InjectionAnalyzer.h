#pragma once
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 进程注入 / DLL 侧载分析器:RemoteThread(跨进程远程线程,镂空/APC/劫持落点)与
// ImageLoad(高危可写目录加载未签名模块=侧载)。敏感目标注入置硬指标;合法签名注入软信号。
// 对应 .NET Engine/InjectionAnalyzer.cs。
struct InjectionAnalyzer {
    static ScoreResult analyze(const bulwark::SecurityEvent& e);
};

} // namespace bulwark::engine
