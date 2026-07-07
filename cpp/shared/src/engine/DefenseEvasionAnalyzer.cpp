#include "bulwark/engine/DefenseEvasionAnalyzer.h"
#include <QSet>

namespace bulwark::engine {
using detail::u;
using detail::fileNameLower;

namespace {
const QSet<QString>& securityProcesses() {
    static const QSet<QString> s = {
        "msmpeng.exe", "mpdefendercoreservice.exe", "mpcmdrun.exe",
        "securityhealthservice.exe", "smartscreen.exe",
        "360tray.exe", "360sd.exe", "zhudongfangyu.exe", "360rp.exe",
        "hipstray.exe", "hipsdaemon.exe", "wsctrl.exe", "usysdiag.exe",
        "qqpcrtp.exe", "qqpctray.exe", "kxetray.exe", "kxescore.exe", "ksafetray.exe",
        "avp.exe", "egui.exe", "ekrn.exe", "avguard.exe", "mbam.exe", "mbamservice.exe",
    };
    return s;
}
} // namespace

ScoreResult DefenseEvasionAnalyzer::analyze(const bulwark::SecurityEvent& e) {
    ScoreResult r;
    const QString cmd = e.commandLine.toLower();
    const QString target = e.target.toLower();

    auto C = [&](const char* t) { return cmd.contains(QLatin1String(t)); };
    auto T = [&](const char* t) { return target.contains(QLatin1String(t)); };
    auto hit = [&](int d, const QString& reason, bool hard) {
        r.score += d;
        r.reasons << reason;
        if (hard) r.hardSignal = true;
    };

    // 结束安全软件进程(ProcessTerminate 或命令行 taskkill/net stop/sc stop)。
    const QString victim = fileNameLower(e.target);
    if (e.type == EventType::ProcessTerminate && securityProcesses().contains(victim))
        hit(45, u("试图结束安全软件进程 ") + victim + u("(禁用防护,T1562.001)"), true);

    if (!cmd.isEmpty()) {
        const bool killVerb = C("taskkill") || C("net stop") || C("sc stop") ||
                              C("sc config") || C("stop-service") || C("stop-process");
        if (killVerb && (C("msmpeng") || C("windefend") || C("securityhealth") ||
                         C("360") || C("huorong") || C("hips") || C("qqpc") ||
                         C("kxe") || C("kingsoft") || C("usysdiag")))
            hit(45, u("命令行停止/结束安全软件服务或进程(禁用防护,T1562.001)"), true);

        // Defender 篡改
        if (C("set-mppreference") && (C("disablerealtimemonitoring") || C("disablebehaviormonitoring") ||
                                      C("disableioavprotection") || C("disablescriptscanning") ||
                                      C("disableblockatfirstseen")))
            hit(50, u("篡改 Defender 保护开关(Set-MpPreference,T1562.001)"), true);
        if (C("set-mppreference") && (C("mapsreporting") || C("submitsamplesconsent")))
            hit(40, u("禁用 Defender 云保护/样本提交(规避云检测,T1562.001)"), true);
        if (C("add-mppreference") && (C("exclusionpath") || C("exclusionprocess") || C("exclusionextension")))
            hit((C("exclusionpath") && C("c:\\")) ? 45 : 35, u("添加 Defender 排除项(免杀,T1562.001)"), true);
        if (C("disableantispyware"))
            hit(45, u("关闭 Defender 反间谍(DisableAntiSpyware,T1562.001)"), true);

        // AMSI / ETW 致盲
        if (C("amsiinitfailed") || C("amsiutils") || C("amsicontext") || C("amsiscanbuffer"))
            hit(50, u("AMSI 绕过(反射篡改 AmsiUtils/amsiInitFailed,T1562.001)"), true);
        if (C("etweventwrite") || C("etweventunregister"))
            hit(40, u("ETW 致盲(EtwEventWrite 补丁,T1562.006)"), true);

        // 清日志 / 反取证
        if ((C("wevtutil") && (C(" cl ") || C(" cl") || C("clear-log"))) || C("clear-eventlog"))
            hit(45, u("清空事件日志(反取证,T1070.001)"), true);
        if (C("fsutil") && C("usn") && C("deletejournal"))
            hit(40, u("删除 USN 变更日志(反取证,T1070)"), true);

        // 防火墙 / 引导完整性
        if (C("netsh") && (C("advfirewall") || C("firewall")) && (C("off") || C("disable")))
            hit(40, u("关闭 Windows 防火墙(netsh,T1562.004)"), true);
        if (C("bcdedit") && (C("testsigning") || C("nointegritychecks") || C("disable_integrity_checks")))
            hit(40, u("削弱引导完整性/启用测试签名(bcdedit,T1553.006)"), true);
    }

    // 注册表规避
    if (e.type == EventType::RegistryWrite && !target.isEmpty()) {
        if (T("windows defender") && (T("disableantispyware") || T("disablerealtimemonitoring")))
            hit(45, u("注册表关闭 Defender(T1562.001)"), true);
        if (T("windows defender\\exclusions"))
            hit(30, u("向 Defender 添加排除项(注册表,免杀)"), false);
        if (T("\\system\\") && T("enablelua"))
            hit(35, u("关闭 UAC(EnableLUA,T1548.002)"), false);
        if (T("disabletaskmgr") || T("disableregistrytools"))
            hit(28, u("禁用任务管理器/注册表编辑器(T1562.001)"), false);
    }

    r.score = qMin(r.score, 100);
    return r;
}

} // namespace bulwark::engine
