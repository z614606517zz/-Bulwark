#pragma once
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 凭据访问 / LSASS 保护分析器(ATT&CK TA0006):从目标/命令行/行为类型语义识别
// LSASS 转储/注入、SAM/SECURITY 蜂巢导出、NTDS.dit 提取、浏览器凭据库读取、DPAPI 访问。
// 对应 .NET Engine/CredentialAccessAnalyzer.cs。
struct CredentialAccessAnalyzer {
    static ScoreResult analyze(const bulwark::SecurityEvent& e);
    // 是否构成「让签名工具失去信任豁免」的高置信凭据攻击(供 TrustPolicy 复用)。
    static bool isHardCredentialAccess(const bulwark::SecurityEvent& e);
};

} // namespace bulwark::engine
