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

//
// 「凭据库的属主」判定:主体是否与被访问的凭据库位于【同一个应用安装树】内。
//
// 原实现只按固定的浏览器进程名表(chrome.exe / msedge.exe / ...)判断属主,于是浏览器
// 自带的辅助进程一律被算成「非浏览器进程」。实测误报:
//   主体 …\AppData\Local\360ChromeX\Chrome\Application\23.1.1253.64\installer\360ceupdate.exe
//   目标 …\AppData\Local\360ChromeX\Chrome\User Data\…
// 它就是这个浏览器自己的更新器,读自己的用户数据被判成「读取浏览器凭据库」。同类还有
// Chrome 的 chrome_updater / elevation_service、Edge 的各辅助进程、Firefox 的
// maintenanceservice —— 按名单永远补不全。
//
// 改为结构判定:取两者路径的最长公共目录前缀,要求它【越过通用根目录再往下至少一层】。
//   同树   : c:\users\x\appdata\local\360chromex\           -> 越过 \appdata\local\,属主
//   非同树 : c:\users\x\appdata\local\  (窃取器在 …\local\temp\) -> 未越过,不是属主
// 这样按厂商目录自然成立,不需要维护进程名表。
//
// 残留口子:样本若直接落在厂商安装树内,会被当成属主。可以接受 —— 这一条本身只是【软信号】
// (28 分,hard=false),不单独定罪;而且能写进厂商目录本身就已被「未签名 / 可疑目录 / 首见」
// 等其它判据覆盖。
//
bool sharesApplicationTree(const QString& actorPathLower, const QString& targetLower) {
    if (actorPathLower.isEmpty() || targetLower.isEmpty()) return false;

    QString a = actorPathLower; a.replace(QLatin1Char('/'), QLatin1Char('\\'));
    QString t = targetLower;    t.replace(QLatin1Char('/'), QLatin1Char('\\'));

    // 最长公共前缀,并回退到目录边界。
    int n = 0;
    const int lim = qMin(a.size(), t.size());
    while (n < lim && a.at(n) == t.at(n)) ++n;
    int cut = a.lastIndexOf(QLatin1Char('\\'), n > 0 ? n - 1 : 0);
    if (cut < 0) return false;
    const QString common = a.left(cut + 1);   // 含结尾反斜杠

    // 通用根目录:公共前缀必须越过其中之一,并且后面还有非空的一层(= 厂商/应用目录)。
    static const char* kGenericRoots[] = {
        "\\appdata\\local\\", "\\appdata\\roaming\\", "\\appdata\\locallow\\",
        "\\program files\\", "\\program files (x86)\\", "\\programdata\\",
    };
    for (const char* root : kGenericRoots) {
        const QString r = QLatin1String(root);
        const int at = common.indexOf(r);
        if (at < 0) continue;
        const QString rest = common.mid(at + r.size());
        // rest 形如 "360chromex\" 或 "360chromex\chrome\" —— 只要有一层就说明同属一个应用。
        if (!rest.isEmpty() && rest != QLatin1String("\\")) return true;
    }
    return false;
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
    //    属主 = 已知浏览器进程名,【或】与该凭据库同属一个应用安装树(见 sharesApplicationTree ——
    //    浏览器自带的更新器 / 提权服务 / 维护服务都是这样,按进程名表永远补不全)。
    const bool isBrowser = browserProcesses().contains(actorName) ||
                           sharesApplicationTree(e.actorPath.toLower(), target);
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
