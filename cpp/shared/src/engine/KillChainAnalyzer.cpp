#include "bulwark/engine/KillChainAnalyzer.h"
#include <QHash>
#include <QSet>
#include <initializer_list>

namespace bulwark::engine {
using detail::u;
using detail::fileNameLower;

namespace {

const KillChainStage kAll[] = {
    KillChainStage::Execution, KillChainStage::DefenseEvasion, KillChainStage::Persistence,
    KillChainStage::CredentialAccess, KillChainStage::LateralMovement, KillChainStage::Impact,
    KillChainStage::CommandControl, KillChainStage::Discovery,
};

constexpr int kMultiStageThreshold = 3;

bool has(KillChainStage stages, KillChainStage flag) { return (stages & flag) == flag; }

int countStages(KillChainStage stages) {
    int count = 0;
    for (KillChainStage f : kAll) if (has(stages, f)) ++count;
    return count;
}

const QSet<QString>& scriptHosts() {
    static const QSet<QString> s = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "msbuild.exe",
        "installutil.exe", "wmic.exe",
    };
    return s;
}
const QStringList& securityProcessHints() {
    static const QStringList s = {
        "msmpeng.exe", "mpdefendercoreservice.exe", "360tray.exe", "360sd.exe",
        "zhudongfangyu.exe", "hipstray.exe", "usysdiag.exe", "qqpcrtp.exe",
        "kxetray.exe", "avp.exe", "ekrn.exe", "mcshield.exe",
    };
    return s;
}
bool isScriptHost(const QString& name) { return scriptHosts().contains(name); }
bool isSecurityProcess(const QString& target) {
    for (const QString& p : securityProcessHints()) if (target.contains(p)) return true;
    return false;
}
bool containsAny(const QString& s, std::initializer_list<const char*> tokens) {
    if (s.isEmpty()) return false;
    for (const char* t : tokens) if (s.contains(QLatin1String(t))) return true;
    return false;
}

QString stageName(KillChainStage s) {
    switch (s) {
        case KillChainStage::Execution:        return u("执行");
        case KillChainStage::DefenseEvasion:   return u("防御规避");
        case KillChainStage::Persistence:      return u("持久化");
        case KillChainStage::CredentialAccess: return u("凭据访问");
        case KillChainStage::LateralMovement:  return u("横向移动");
        case KillChainStage::Impact:           return u("破坏影响");
        case KillChainStage::CommandControl:   return u("命令控制");
        case KillChainStage::Discovery:        return u("侦察");
        default:                               return QStringLiteral("?");
    }
}

QString describeStages(KillChainStage stages) {
    QStringList names;
    for (KillChainStage f : kAll) if (has(stages, f)) names << stageName(f);
    return names.join(QString::fromUtf8("→"));
}

QString trimTo(const QString& s, int max) {
    return s.size() <= max ? s : s.left(max) + QString::fromUtf8("…");
}

KillChainStage classify(const bulwark::ChainEventInfo& ev) {
    KillChainStage s = KillChainStage::None;
    const QString actor = fileNameLower(ev.actorPath);
    const QString target = ev.target.toLower();
    const QString cmd = ev.commandLine.toLower();

    // 执行
    if (ev.type == EventType::ProcessCreate && isScriptHost(actor))
        s |= KillChainStage::Execution;

    // 命令控制 / 下载执行
    if (ev.type == EventType::NetworkConnect && isScriptHost(actor))
        s |= KillChainStage::CommandControl;
    if (containsAny(cmd, { "downloadstring", "downloadfile", "invoke-webrequest",
                           "certutil", "bitsadmin", "http://", "https://" }))
        s |= KillChainStage::CommandControl;

    // 防御规避
    if (containsAny(cmd, { "bypass", "-enc", "-w hidden", "-windowstyle hidden",
                           "disableantispyware", "disablerealtimemonitoring", "set-mppreference",
                           "testsigning", "nointegritychecks" }))
        s |= KillChainStage::DefenseEvasion;
    if (ev.type == EventType::ProcessTerminate && isSecurityProcess(target))
        s |= KillChainStage::DefenseEvasion;
    if (ev.type == EventType::ImageLoad && target.endsWith(QLatin1String(".sys")))
        s |= KillChainStage::DefenseEvasion; // 可疑驱动加载(BYOVD)

    // 持久化
    if (ev.type == EventType::RegistryWrite &&
        containsAny(target, { "\\run\\", "\\runonce\\", "winlogon", "userinit",
                              "image file execution options", "\\services\\", "appinit_dlls" }))
        s |= KillChainStage::Persistence;
    if (ev.type == EventType::FileWrite &&
        containsAny(target, { "\\startup\\", "\\tasks\\", "normal.dotm", "\\xlstart\\" }))
        s |= KillChainStage::Persistence;
    if (containsAny(cmd, { "schtasks", "__eventfilter", "commandlineeventconsumer", "new-scheduledtask" }))
        s |= KillChainStage::Persistence;

    // 凭据访问
    if (containsAny(target, { "lsass.exe", "\\config\\sam", "ntds.dit",
                              "login data", "logins.json", "\\credentials\\", "\\protect\\" }))
        s |= KillChainStage::CredentialAccess;
    if (containsAny(cmd, { "mimikatz", "sekurlsa", "lsadump", "comsvcs.dll, minidump" }))
        s |= KillChainStage::CredentialAccess;

    // 横向移动
    if (containsAny(cmd, { "psexec", "/node:", "-computername", "enter-pssession",
                           "winrs", "\\admin$", "\\c$", "wmic /node" }))
        s |= KillChainStage::LateralMovement;

    // 影响破坏
    if (containsAny(cmd, { "vssadmin", "shadowcopy", "wbadmin", "delete catalog",
                           "recoveryenabled no", "bcdedit" }))
        s |= KillChainStage::Impact;
    if (containsAny(target, { "_readme.txt", "how_to_decrypt", "recover", "\\boot\\bcd" }))
        s |= KillChainStage::Impact;

    // 侦察
    if (containsAny(cmd, { "whoami", "ipconfig", "net view", "net group",
                           "nltest", "systeminfo", "tasklist", "arp -a", "query user" }))
        s |= KillChainStage::Discovery;

    return s;
}

QString describeEvidence(const bulwark::ChainEventInfo& ev) {
    const QString actor = fileNameLower(ev.actorPath);
    QString detail;
    if (!ev.commandLine.isEmpty()) detail = trimTo(ev.commandLine, 80);
    else if (!ev.target.isEmpty()) detail = trimTo(ev.target, 80);
    else detail = bulwark::eventTypeToString(ev.type);
    return actor + u("(pid=") + QString::number(ev.actorPid) + u("): ") + detail;
}

} // namespace

KillChainAnalyzer::Result KillChainAnalyzer::analyze(const QVector<bulwark::ChainEventInfo>& context) {
    Result r;
    if (context.isEmpty()) return r;

    KillChainStage stages = KillChainStage::None;
    QHash<quint32, QString> perStage;

    for (const bulwark::ChainEventInfo& ev : context) {
        const KillChainStage s = classify(ev);
        if (s == KillChainStage::None) continue;
        for (KillChainStage flag : kAll)
            if (has(s, flag) && !perStage.contains(static_cast<quint32>(flag)))
                perStage.insert(static_cast<quint32>(flag), describeEvidence(ev));
        stages |= s;
    }
    r.stages = stages;

    const int stageCount = countStages(stages);
    if (stageCount < kMultiStageThreshold) return r; // 阶段不足,不计分(降误报)

    int score = 0;
    score += (stageCount - kMultiStageThreshold + 1) * 20;
    r.reasons << (u("进程链横跨 ") + QString::number(stageCount) + u(" 个攻击阶段(") +
                  describeStages(stages) + u(",疑似完整攻击链)"));

    if (has(stages, KillChainStage::Execution) && has(stages, KillChainStage::Persistence)) {
        score += 12;
        r.reasons << u("执行 + 持久化组合(驻留意图明确)");
    }
    if (has(stages, KillChainStage::DefenseEvasion) &&
        (has(stages, KillChainStage::Persistence) || has(stages, KillChainStage::CredentialAccess))) {
        score += 14;
        r.reasons << u("防御规避 + 持久化/凭据访问组合(高危)");
    }
    if (has(stages, KillChainStage::CredentialAccess) && has(stages, KillChainStage::LateralMovement)) {
        score += 18;
        r.reasons << u("凭据访问 + 横向移动组合(疑似定向入侵)");
    }
    if (has(stages, KillChainStage::Impact) &&
        (has(stages, KillChainStage::Execution) || has(stages, KillChainStage::DefenseEvasion))) {
        score += 20;
        r.reasons << u("破坏性影响 + 执行/规避组合(疑似勒索/擦除)");
    }

    for (KillChainStage flag : kAll)
        if (perStage.contains(static_cast<quint32>(flag)))
            r.reasons << (u("· [") + stageName(flag) + u("] ") + perStage.value(static_cast<quint32>(flag)));

    r.score = qMin(score, 100);
    return r;
}

bool KillChainAnalyzer::hasMaliciousStage(KillChainStage stages) {
    return has(stages, KillChainStage::CredentialAccess) ||
           has(stages, KillChainStage::LateralMovement) ||
           has(stages, KillChainStage::Impact);
}

} // namespace bulwark::engine
