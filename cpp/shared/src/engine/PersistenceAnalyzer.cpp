#include "bulwark/engine/PersistenceAnalyzer.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/engine/AttackAnnotator.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/Enums.h"

#include <algorithm>

namespace bulwark::engine {

namespace {

QString categoryLabel(bulwark::PersistenceCategory c) {
    using C = bulwark::PersistenceCategory;
    switch (c) {
        case C::RegistryRun:     return QString::fromUtf8("注册表 Run 键");
        case C::RegistryRunOnce: return QString::fromUtf8("注册表 RunOnce 键");
        case C::StartupFolder:   return QString::fromUtf8("启动文件夹");
        case C::ScheduledTask:   return QString::fromUtf8("计划任务");
        case C::Service:         return QString::fromUtf8("Windows 服务");
        case C::WmiSubscription: return QString::fromUtf8("WMI 事件订阅");
        case C::IfeoDebugger:    return QString::fromUtf8("映像劫持");
        case C::Winlogon:        return QString::fromUtf8("Winlogon");
        case C::AppInitDll:      return QString::fromUtf8("AppInit_DLLs");
        default:                 return QString::fromUtf8("其它");
    }
}

} // namespace

QString PersistenceAnalyzer::techniqueFor(bulwark::PersistenceCategory c) {
    using C = bulwark::PersistenceCategory;
    switch (c) {
        case C::RegistryRun:     return QStringLiteral("T1547.001");
        case C::RegistryRunOnce: return QStringLiteral("T1547.001");
        case C::StartupFolder:   return QStringLiteral("T1547.001");
        case C::ScheduledTask:   return QStringLiteral("T1053.005");
        case C::Service:         return QStringLiteral("T1543.003");
        case C::WmiSubscription: return QStringLiteral("T1546.003");
        case C::IfeoDebugger:    return QStringLiteral("T1546.012");
        case C::Winlogon:        return QStringLiteral("T1547.004");
        case C::AppInitDll:      return QStringLiteral("T1546.010");
        default:                 return QString();
    }
}

void PersistenceAnalyzer::analyze(bulwark::PersistenceEntry& entry) {
    using bulwark::EventType;
    using bulwark::EvidenceKind;
    using C = bulwark::PersistenceCategory;

    // 1) 合成进程创建事件,复用 ThreatDetector 全部启发式(证据链已含带 T 编号的 LOLBin/凭据等)。
    bulwark::SecurityEvent synthetic;
    synthetic.type = EventType::ProcessCreate;
    synthetic.actorPath = entry.imagePath.isEmpty() ? entry.command : entry.imagePath;
    synthetic.commandLine = entry.command;
    synthetic.actorSigned = entry.isSigned.value_or(false);
    synthetic.actorPublisher = entry.publisher;
    synthetic.target = entry.location;
    ThreatDetector::analyze(synthetic);

    int score = synthetic.riskScore;
    QStringList reasons = synthetic.riskReasons;

    // 2) 叠加该自启动点本身的 ATT&CK 技战术标注(作为独立证据,供注解器提取编号)。
    const QString tech = techniqueFor(entry.category);
    if (!tech.isEmpty()) {
        const QString posReason =
            QStringLiteral("%1自启动持久化(%2)").arg(categoryLabel(entry.category), tech);
        reasons.append(posReason);
        synthetic.addEvidence(QStringLiteral("PersistenceAnalyzer"), EvidenceKind::Info,
                              posReason, 0, /*alsoReason=*/false);
    }

    // 3) 高危持久化点轻微加权(映像劫持 / WMI 订阅 / AppInit 几乎只被恶意使用)。
    switch (entry.category) {
        case C::IfeoDebugger:
            score += 25;
            reasons.append(QString::fromUtf8("映像劫持(IFEO Debugger):劫持目标程序启动,极少合法用途"));
            break;
        case C::WmiSubscription:
            score += 20;
            reasons.append(QString::fromUtf8("WMI 事件订阅:无文件持久化,常用于隐蔽驻留"));
            break;
        case C::AppInitDll:
            score += 20;
            reasons.append(QString::fromUtf8("AppInit_DLLs:注入所有 GUI 进程,高危持久化"));
            break;
        default:
            break;
    }

    entry.riskScore = std::min(100, score);
    entry.riskReasons = reasons;

    // 4) 汇总技战术(ThreatDetector 证据里的 LOLBin/凭据编号 + 上面的位置技战术)。
    AttackAnnotator::annotate(synthetic);
    entry.techniques = synthetic.techniques;
}

} // namespace bulwark::engine
