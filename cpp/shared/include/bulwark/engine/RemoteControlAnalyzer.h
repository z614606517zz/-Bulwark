#pragma once
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 远程控制 / RMM 工具滥用 + IM(微信/QQ)群控注入/侧载分析。
// 命令行(RDP 劫持、反弹 shell、无人值守远控)+ 进程/注入/模块加载上下文。
// 对应 .NET Engine/RemoteControlAnalyzer.cs。
struct RemoteControlAnalyzer {
    static ScoreResult analyze(const SecurityEvent& e);
};

} // namespace bulwark::engine
