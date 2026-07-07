#pragma once
#include <QString>
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 信任判定结果:是否命中 + 人类可读原因。
struct TrustDecision {
    bool ok = false;
    QString reason;
};

// 信任策略(降误报核心,同时防「合法签名」被滥用)。区分「强可信(可跳过行为检测)」
// 与「一般合法签名(仅风险打折)」。任一档下出现危险命令行/异常链/签名异常一律不放行。
// 对应 .NET Engine/TrustPolicy.cs。
struct TrustPolicy {
    // 已安装的知名安全软件(共存放行):映像名在白名单且位于受保护安装目录。
    static TrustDecision isTrustedSecurityProduct(const bulwark::SecurityEvent& e);
    // 强可信:证书指纹白名单,或微软签名 + 系统目录,且签名健康、无危险行为。
    static TrustDecision isStronglyTrusted(const bulwark::SecurityEvent& e);
    // 健康签名直接放行(排除硬指标 + 空壳新证书画像)。需在 ThreatDetector::analyze 之后调用。
    static TrustDecision isHealthySigned(const bulwark::SecurityEvent& e);
    // 明确安全(仅用于决定是否跳过 VT 上传;不含「首见+新证书」收紧)。
    static TrustDecision isCleanSigned(const bulwark::SecurityEvent& e);
    // 较可信合法签名(仅风险打折,不跳过行为规则)。
    static TrustDecision isBenignSigner(const bulwark::SecurityEvent& e);
    // 可豁免敏感 Ask 规则的强可信 OS 组件(排除 LOLBin/脚本宿主)。
    static TrustDecision isTrustedOsComponent(const bulwark::SecurityEvent& e);
    // 兼容旧调用:等价于 isStronglyTrusted。
    static TrustDecision isTrusted(const bulwark::SecurityEvent& e);
};

} // namespace bulwark::engine
