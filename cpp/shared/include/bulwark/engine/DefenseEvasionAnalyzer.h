#pragma once
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 防御规避分析器(ATT&CK TA0005):篡改/关闭 Defender、AMSI/ETW 致盲、清空事件日志、
// 关闭防火墙/UAC、结束安全软件进程等。高置信规避置硬指标。
// 注:原 .NET DefenseEvasionAnalyzer.cs 源已缺失,此处按用法契约 + 领域知识重建。
struct DefenseEvasionAnalyzer {
    static ScoreResult analyze(const bulwark::SecurityEvent& e);
};

} // namespace bulwark::engine
