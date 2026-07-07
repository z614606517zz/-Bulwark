#pragma once
#include <QColor>
#include <QString>

#include "bulwark/models/Enums.h"
#include "Theme.h"

// Shared UI formatting for SecurityEvents / evidence — used by the behavior
// prompt and the attack-timeline window so both read consistently.
namespace evtfmt {

inline QString u(const char* s) { return QString::fromUtf8(s); }

inline QString typeLabel(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return u("进程创建");
    case E::ProcessTerminate: return u("结束进程");
    case E::RemoteThread:     return u("远程线程注入");
    case E::ImageLoad:        return u("模块 / 驱动加载");
    case E::FileWrite:        return u("文件写入");
    case E::FileDelete:       return u("文件删除");
    case E::RegistryWrite:    return u("注册表写入");
    case E::NetworkConnect:   return u("网络外联");
    case E::SelfProtect:      return u("自我保护");
    case E::DnsQuery:         return u("DNS 解析");
    }
    return u("行为");
}

inline QString verb(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return u("尝试创建进程");
    case E::ProcessTerminate: return u("尝试结束进程");
    case E::RemoteThread:     return u("尝试注入远程线程");
    case E::ImageLoad:        return u("尝试加载模块 / 驱动");
    case E::FileWrite:        return u("尝试写入 / 修改文件");
    case E::FileDelete:       return u("尝试删除文件");
    case E::RegistryWrite:    return u("尝试写入注册表");
    case E::NetworkConnect:   return u("尝试网络外联");
    case E::SelfProtect:      return u("触发自我保护");
    case E::DnsQuery:         return u("发起 DNS 解析");
    }
    return u("敏感行为");
}

inline QColor riskColor(int score) {
    if (score >= 80) return theme::danger();
    if (score >= 50) return theme::warning();
    return theme::success();
}

inline QString riskLevel(int score) {
    if (score >= 80) return u("高危");
    if (score >= 50) return u("可疑");
    return u("正常");
}

inline QString evidenceKindLabel(bulwark::EvidenceKind k) {
    using K = bulwark::EvidenceKind;
    switch (k) {
    case K::Info:          return u("上下文");
    case K::SoftSignal:    return u("软信号");
    case K::HardIndicator: return u("硬指标");
    case K::Corroboration: return u("互证");
    case K::Trust:         return u("信任");
    case K::Rule:          return u("规则");
    case K::Decision:      return u("裁决");
    }
    return u("证据");
}

inline QColor evidenceKindColor(bulwark::EvidenceKind k) {
    using K = bulwark::EvidenceKind;
    switch (k) {
    case K::HardIndicator: return theme::danger();
    case K::SoftSignal:    return theme::warning();
    case K::Corroboration: return theme::warning();
    case K::Trust:         return theme::success();
    case K::Rule:          return theme::info();
    case K::Decision:      return theme::accent();
    case K::Info:          return theme::textMuted();
    }
    return theme::textMuted();
}

} // namespace evtfmt
