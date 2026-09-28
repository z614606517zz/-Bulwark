#pragma once
#include <QColor>
#include <QDir>
#include <QFileInfo>
#include <QString>

#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"
#include "design/Identity.h"
#include "design/Theme.h"

// The single source of truth for how security events read in the UI — type
// names, glyphs, risk levels, verdicts and dispositions, one-line summaries.
// The behavior prompt, toasts, every list page, the dashboard and the attack
// timeline all format through here, so the same event never reads two ways.
// (These used to be copied three times — TablePages, DashboardPage and here —
// and had already drifted: "远程线程" vs "远程线程注入", "映像加载" vs "模块 / 驱动加载".)
namespace evtfmt {

inline QString u(const char* s) { return QString::fromUtf8(s); }

struct Badge {
    QString text;
    QColor color;
};

// ---- event types --------------------------------------------------------------

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

// Compact label for chips, filter menus and rule sentences.
inline QString typeShort(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::RemoteThread: return u("远程线程");
    case E::ImageLoad:    return u("模块加载");
    default:              return typeLabel(t);
    }
}

// One glyph per behaviour family, so a list can be scanned by shape.
inline QString typeGlyph(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return QStringLiteral("target");
    case E::ProcessTerminate: return QStringLiteral("power");
    case E::RemoteThread:     return QStringLiteral("zap");
    case E::ImageLoad:        return QStringLiteral("layers");
    case E::FileWrite:
    case E::FileDelete:       return QStringLiteral("file");
    case E::RegistryWrite:    return QStringLiteral("sliders");
    case E::NetworkConnect:
    case E::DnsQuery:         return QStringLiteral("globe");
    case E::SelfProtect:      return QStringLiteral("shield");
    }
    return QStringLiteral("activity");
}

// ...and one hue per family (design/Identity.h), so it can be scanned by colour
// too. Only for events with nothing to say about risk: see glyphColor().
inline identity::Kind typeKind(bulwark::EventType t) {
    using E = bulwark::EventType;
    using K = identity::Kind;
    switch (t) {
    case E::ProcessCreate:
    case E::ProcessTerminate: return K::Process;
    case E::RemoteThread:     return K::Injection;
    case E::ImageLoad:        return K::Module;
    case E::FileWrite:
    case E::FileDelete:       return K::File;
    case E::RegistryWrite:    return K::Registry;
    case E::NetworkConnect:
    case E::DnsQuery:         return K::Network;
    case E::SelfProtect:      break; // neutral, like processes: records never wear the brand jade
    }
    return K::Neutral;
}

inline QColor typeColor(bulwark::EventType t) { return identity::kind(typeKind(t)); }

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

// The action itself, as a short verb phrase ("注入远程线程").
inline QString action(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return u("启动进程");
    case E::ProcessTerminate: return u("结束进程");
    case E::RemoteThread:     return u("注入远程线程");
    case E::ImageLoad:        return u("加载模块");
    case E::FileWrite:        return u("写入文件");
    case E::FileDelete:       return u("删除文件");
    case E::RegistryWrite:    return u("写入注册表");
    case E::NetworkConnect:   return u("网络外联");
    case E::SelfProtect:      return u("触发自我保护");
    case E::DnsQuery:         return u("解析域名");
    }
    return u("敏感行为");
}

inline QString actorName(const QString& path) {
    const QString n = QFileInfo(path).fileName();
    return n.isEmpty() ? (path.isEmpty() ? u("未知程序") : path) : n;
}

// One sentence saying what happened. present=true for a live question
// ("powershell.exe 正试图向 explorer.exe (PID 2204) 注入远程线程"), false for
// a record ("powershell.exe 向 explorer.exe (PID 2204) 注入远程线程").
inline QString sentence(const bulwark::SecurityEvent& e, bool present) {
    using E = bulwark::EventType;
    const QString a = actorName(e.actorPath);
    const QString t = e.target.trimmed();
    const QString tense = present ? u("正试图") : QString();
    if (t.isEmpty())
        return a + u(" ") + (present ? verb(e.type) : action(e.type));
    switch (e.type) {
    case E::RemoteThread:     return u("%1 %2向 %3 注入远程线程").arg(a, tense, t);
    case E::ProcessCreate:    return u("%1 %2启动 %3").arg(a, tense, t);
    case E::ProcessTerminate: return u("%1 %2结束 %3").arg(a, tense, t);
    case E::ImageLoad:        return u("%1 %2加载 %3").arg(a, tense, t);
    case E::FileWrite:        return u("%1 %2写入 %3").arg(a, tense, t);
    case E::FileDelete:       return u("%1 %2删除 %3").arg(a, tense, t);
    case E::RegistryWrite:    return u("%1 %2修改注册表 %3").arg(a, tense, t);
    case E::NetworkConnect:   return u("%1 %2连接 %3").arg(a, tense, t);
    case E::SelfProtect:      return u("%1 触发自我保护:%2").arg(a, t);
    case E::DnsQuery:         return u("%1 %2解析域名 %3").arg(a, present ? u("正在") : QString(), t);
    }
    return a + u(" ") + action(e.type);
}

// Toast one-liner: "powershell.exe 注入远程线程 → explorer.exe".
inline QString arrowLine(const bulwark::SecurityEvent& e) {
    const QString a = actorName(e.actorPath);
    const QString t = e.target.trimmed();
    return t.isEmpty() ? a + u(" ") + action(e.type)
                       : u("%1 %2 → %3").arg(a, action(e.type), t);
}

// ---- risk -----------------------------------------------------------------------

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

// The colour of an event's glyph (list rows, inspector header): its risk when
// that is worth showing (>= 50) — status always wins — otherwise the hue of its
// behaviour family. Below 50 the score itself still reads green / as a number.
inline QColor glyphColor(const bulwark::SecurityEvent& e) {
    return e.riskScore >= 50 ? riskColor(e.riskScore) : typeColor(e.type);
}

// ---- verdicts & dispositions -------------------------------------------------------

// A decision (rule action, AI recommendation): 拦截 / 询问 / 放行.
inline Badge verdict(bulwark::VerdictAction a) {
    switch (a) {
    case bulwark::VerdictAction::Block: return {u("拦截"), theme::danger()};
    case bulwark::VerdictAction::Ask:   return {u("询问"), theme::warning()};
    case bulwark::VerdictAction::Allow: break;
    }
    return {u("放行"), theme::success()};
}

// What was actually DONE about an event. For Block this follows the real
// enforcement outcome, never the verdict alone — a Block that nothing enforced
// must not read "已拦截" (the no-fake-block rule). Only a kernel pre-block, a
// terminated process tree or a module blacklisting count as a real block;
// alert-only and failed enforcement say so.
inline Badge disposition(bulwark::VerdictAction act, bulwark::EnforcementOutcome enf) {
    if (act != bulwark::VerdictAction::Block) {
        if (act == bulwark::VerdictAction::Ask)
            return {u("已询问"), theme::warning()};
        return {u("已放行"), theme::success()};
    }
    using EO = bulwark::EnforcementOutcome;
    switch (enf) {
    case EO::KernelBlocked:     return {u("已拦截"), theme::danger()};        // 内核前拦
    case EO::Terminated:        return {u("已结束进程"), theme::danger()};    // 事后杀成功
    case EO::ModuleBlacklisted: return {u("已禁止加载"), theme::danger()};    // 下次前拦
    case EO::AlertedOnly:       return {u("仅告警·未拦截"), theme::warning()}; // 未实际拦截
    case EO::Failed:            return {u("拦截失败"), theme::warning()};
    case EO::NotApplicable:     break;
    }
    return {u("已拦截"), theme::danger()}; // 历史记录兜底(旧记录没有处置字段)
}

// Which part of the pipeline produced the verdict.
inline QString verdictSourceLabel(bulwark::VerdictSource s) {
    using S = bulwark::VerdictSource;
    switch (s) {
    case S::Rule:          return u("命中规则");
    case S::Heuristic:     return u("启发式评分");
    case S::TrustedSigner: return u("受信签名放行");
    case S::UserPrompt:    return u("用户裁决");
    case S::Timeout:       return u("询问超时,按默认处理");
    case S::DefaultPolicy: return u("默认策略");
    }
    return u("—");
}

// Counts toward "拦截" totals only when something really stopped the action.
inline bool isRealBlock(bulwark::VerdictAction act, bulwark::EnforcementOutcome enf) {
    using EO = bulwark::EnforcementOutcome;
    return act == bulwark::VerdictAction::Block
        && (enf == EO::KernelBlocked || enf == EO::Terminated || enf == EO::ModuleBlacklisted
            || enf == EO::NotApplicable);
}

// One sentence explaining the disposition (inspector / attack timeline).
inline QString dispositionDetail(bulwark::VerdictAction act, bulwark::EnforcementOutcome enf) {
    if (act == bulwark::VerdictAction::Ask)
        return u("该行为交由用户裁决。");
    if (act != bulwark::VerdictAction::Block)
        return u("该行为已放行。");
    using EO = bulwark::EnforcementOutcome;
    switch (enf) {
    case EO::KernelBlocked:     return u("内核在操作发生前将其阻断,动作没有发生。");
    case EO::Terminated:        return u("动作已经发生,发起它的进程树已被结束。");
    case EO::ModuleBlacklisted: return u("这次加载没能拦下;该模块已加入内核禁止加载名单,下次加载会在发生前被阻断。");
    case EO::AlertedOnly:       return u("仅告警:内核无法前拦且没有可结束的进程,未做任何实际阻断,需要人工关注。");
    case EO::Failed:            return u("尝试处置但没有成功(进程已退出、受保护或为关键进程)。");
    case EO::NotApplicable:     break;
    }
    return u("裁决为拦截;这条历史记录没有保存实际处置结果。");
}

// ---- evidence -----------------------------------------------------------------------

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

// ---- process origin ---------------------------------------------------------------------

inline QString originKindLabel(bulwark::ProcessOriginKind k) {
    using O = bulwark::ProcessOriginKind;
    switch (k) {
    case O::Interactive:    return u("交互式启动");
    case O::Service:        return u("服务");
    case O::ScheduledTask:  return u("计划任务");
    case O::WmiProvider:    return u("WMI 提供者");
    case O::LogonAutostart: return u("登录自启动");
    case O::SystemBoot:     return u("系统启动");
    case O::Unknown:        break;
    }
    return u("未知");
}

// Who launched a process, as a hue (design/Identity.h) and a glyph — the same
// kinds as the attack graph's service / scheduled-task nodes and the autostart
// categories, so "服务" reads orchid and "计划任务" rose wherever it appears.
inline identity::Kind originKindOf(bulwark::ProcessOriginKind k) {
    using O = bulwark::ProcessOriginKind;
    using K = identity::Kind;
    switch (k) {
    case O::Interactive:    return K::Process;
    case O::Service:        return K::Service;
    case O::ScheduledTask:  return K::Task;
    case O::WmiProvider:    return K::Network;
    case O::LogonAutostart: return K::Registry;
    case O::SystemBoot:
    case O::Unknown:        break;
    }
    return K::Neutral;
}

inline QColor originColor(bulwark::ProcessOriginKind k) { return identity::kind(originKindOf(k)); }

inline QString originGlyph(bulwark::ProcessOriginKind k) {
    using O = bulwark::ProcessOriginKind;
    switch (k) {
    case O::Service:        return QStringLiteral("server");
    case O::ScheduledTask:  return QStringLiteral("clock");
    case O::WmiProvider:    return QStringLiteral("zap");
    case O::LogonAutostart: return QStringLiteral("power");
    case O::SystemBoot:     return QStringLiteral("cpu");
    case O::Interactive:
    case O::Unknown:        break;
    }
    return QStringLiteral("target");
}

inline QString nativePath(const QString& p) { return QDir::toNativeSeparators(p); }

} // namespace evtfmt
