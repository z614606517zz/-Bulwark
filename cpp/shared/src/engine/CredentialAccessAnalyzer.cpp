#include "bulwark/engine/CredentialAccessAnalyzer.h"
#include <QSet>

namespace bulwark::engine {
using detail::u;
using detail::fileNameLower;

namespace {
const QSet<QString>& browserProcesses() {
    static const QSet<QString> s = {
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe",
        "brave.exe", "360se.exe", "360chrome.exe", "qqbrowser.exe", "vivaldi.exe",
    };
    return s;
}
bool isSystemActor(const QString& name) {
    return name == QLatin1String("lsass.exe") || name == QLatin1String("services.exe") ||
           name == QLatin1String("svchost.exe") || name == QLatin1String("winlogon.exe") ||
           name == QLatin1String("system");
}
} // namespace

ScoreResult CredentialAccessAnalyzer::analyze(const bulwark::SecurityEvent& e) {
    ScoreResult r;
    const QString cmd = e.commandLine.toLower();
    const QString target = e.target.toLower();
    const QString actorName = fileNameLower(e.actorPath);

    auto C = [&](const char* t) { return cmd.contains(QLatin1String(t)); };
    auto T = [&](const char* t) { return target.contains(QLatin1String(t)); };
    auto hit = [&](int delta, const QString& reason, bool isHard) {
        r.score += delta;
        r.reasons << reason;
        if (isHard) r.hardSignal = true;
    };

    // 1) LSASS 注入 / 转储
    const bool targetIsLsass = target.contains(QLatin1String("lsass.exe")) ||
                               target.endsWith(QLatin1String("\\lsass")) ||
                               target == QLatin1String("lsass");
    if (e.type == EventType::RemoteThread && targetIsLsass)
        hit(55, u("向 LSASS 注入远程线程(凭据窃取,T1003.001)"), true);

    if ((C("comsvcs.dll") && C("minidump")) || C("sekurlsa") || C("lsadump") ||
        C("mimikatz") || C("invoke-mimikatz"))
        hit(55, u("LSASS 内存转储 / Mimikatz 凭据抓取(T1003.001)"), true);

    if (e.type == EventType::FileWrite &&
        (target.endsWith(QLatin1String(".dmp")) || target.contains(QLatin1String("lsass"))) &&
        (target.contains(QLatin1String("lsass")) || cmd.contains(QLatin1String("lsass"))))
        hit(45, u("疑似 LSASS 内存转储文件落地(T1003.001)"), true);

    // 2) SAM/SECURITY/SYSTEM 蜂巢导出
    const bool hiveCmd = (C("reg save") || C("reg.exe save") || C("regedit")) &&
        (C("hklm\\sam") || C("hklm\\security") || C("hklm\\system") || C("\\sam ") || C(" sam.hiv"));
    if (hiveCmd)
        hit(50, u("导出 SAM/SECURITY/SYSTEM 注册表蜂巢(本地哈希窃取,T1003.002)"), true);

    if ((T("\\config\\sam") || T("\\config\\security") ||
         target.endsWith(QLatin1String("\\system32\\config\\system"))) &&
        (e.type == EventType::FileWrite || e.type == EventType::FileDelete))
        hit(40, u("直接访问 SAM/SECURITY 注册表蜂巢文件(T1003.002)"), true);

    // 3) 域控 NTDS.dit 提取
    if (C("ntdsutil") || C("ntds.dit") || (C("esentutl") && C("ntds")) || (C("ifm") && C("create")))
        hit(50, u("提取域控 NTDS.dit 凭据库(T1003.003)"), true);
    if (T("ntds.dit"))
        hit(45, u("访问 NTDS.dit 数据库文件(T1003.003)"), true);

    // 4) 浏览器凭据库 / Cookie / DPAPI(软信号:仅非属主进程触碰)
    const bool isBrowser = browserProcesses().contains(actorName);
    const bool credStoreTarget = T("\\login data") || T("logins.json") || T("key4.db") ||
        T("signons.sqlite") || T("\\cookies") || T("cookies.sqlite") || T("\\web data");
    if (credStoreTarget && !isBrowser)
        hit(28, u("非浏览器进程读取浏览器凭据库/Cookie(T1555.003)"), false);

    if (target.contains(QLatin1String("\\microsoft\\protect\\")) && !isSystemActor(actorName))
        hit(24, u("访问 DPAPI 主密钥目录(凭据解密,T1003)"), false);

    if (C("vaultcmd") && C("/list"))
        hit(20, u("枚举 Windows 凭据保管库(T1555.004)"), false);

    r.score = qMin(r.score, 100);
    return r;
}

bool CredentialAccessAnalyzer::isHardCredentialAccess(const bulwark::SecurityEvent& e) {
    return analyze(e).hardSignal;
}

} // namespace bulwark::engine
