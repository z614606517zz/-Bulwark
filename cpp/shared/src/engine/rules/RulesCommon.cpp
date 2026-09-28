//
// 段文件共用名单。
//
// 为什么集中一处:同一份「脚本宿主」名单在段 2(谁在写 Run 键)、段 3(谁在关 Defender)、
// 段 5(谁在改 hosts)、段 7(谁在注入)里都要用。各段各抄一份的结果是补了一处漏一处 ——
// 而漏掉的那一处不会报错,只会让某一类样本从那个维度静默通过。
//
#include "RuleDsl.h"

namespace bulwark::engine::rules {

//
// 脚本宿主 / LOLBin 主体通配。
//
// 【为什么这里用「仅文件名」的通配是安全的,而 Allow 规则不行】
// isUnsafeAllowRule 只拦 Allow:仅文件名的 Allow 等于给任何改名者发通行证。反过来,仅文件名的
// Block 规则,冒名者改名成 powershell.exe 只会【多命中】一条拦截规则,方向是 fail-safe。
// 真正的 powershell.exe 位置也确实多变(System32 / SysWOW64 / WinSxS / pwsh 装在 Program Files),
// 锚定路径反而会漏。
//
const QStringList& scriptHostActors() {
    static const QStringList s = {
        QStringLiteral("*\\powershell.exe"), QStringLiteral("*\\pwsh.exe"),
        QStringLiteral("*\\cmd.exe"),        QStringLiteral("*\\wscript.exe"),
        QStringLiteral("*\\cscript.exe"),    QStringLiteral("*\\mshta.exe"),
        QStringLiteral("*\\rundll32.exe"),   QStringLiteral("*\\regsvr32.exe"),
        QStringLiteral("*\\certutil.exe"),
    };
    return s;
}

//
// 投递型可写目录片段(与 ThreatDetector::highSuspiciousDirs / LolbinAnalyzer::refsDropDir
// 同一口径)。刻意【不】含 \downloads\ \desktop\ \appdata\roaming\ —— 那三个是用户正常存放
// 安装包与正规软件配置的位置,在这一层当成「投递目录」会把日常下载安装全部卷进来;它们在
// ThreatDetector 里按 mediumSuspiciousDirs 只做提分,是正确的强度。
//
const QStringList& dropDirFragments() {
    static const QStringList s = {
        QStringLiteral("\\appdata\\local\\temp\\"), QStringLiteral("\\windows\\temp\\"),
        QStringLiteral("\\users\\public\\"),        QStringLiteral("\\programdata\\"),
        QStringLiteral("\\$recycle.bin\\"),         QStringLiteral("\\perflogs\\"),
    };
    return s;
}

//
// 安全软件映像名(含本机常见的国内产品)。与 DefenseEvasionAnalyzer::securityProcesses()
// 覆盖同一批对象 —— 那边按行为计分(45 分硬指标),这里出确定裁决。
//
const QStringList& securityImageNames() {
    static const QStringList s = {
        QStringLiteral("msmpeng.exe"), QStringLiteral("mpdefendercoreservice.exe"),
        QStringLiteral("mssense.exe"), QStringLiteral("securityhealthservice.exe"),
        QStringLiteral("360tray.exe"), QStringLiteral("360sd.exe"),
        QStringLiteral("zhudongfangyu.exe"),
        QStringLiteral("hipstray.exe"), QStringLiteral("hipsdaemon.exe"),
        QStringLiteral("usysdiag.exe"),
        QStringLiteral("qqpcrtp.exe"), QStringLiteral("qqpctray.exe"),
        QStringLiteral("kxetray.exe"), QStringLiteral("kxescore.exe"),
        QStringLiteral("avp.exe"), QStringLiteral("ekrn.exe"),
        QStringLiteral("mbamservice.exe"),
    };
    return s;
}

QString imageNameOf(const QString& pattern) {
    const int slash = pattern.lastIndexOf(QLatin1Char('\\'));
    return slash < 0 ? pattern : pattern.mid(slash + 1);
}

} // namespace bulwark::engine::rules
