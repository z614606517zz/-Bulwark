#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/engine/LolbinAnalyzer.h"
#include "bulwark/engine/CredentialAccessAnalyzer.h"
#include <QSet>
#include <QStringList>
#include <QDateTime>

namespace bulwark::engine {
using detail::u;
using detail::fileNameLower;

namespace {

const QSet<QString>& strongTrustThumbprints() {
    static const QSet<QString> s = {
        "8FBE4D070EF8AB1BCCAF2A9D5CCAE7282A2C66B3",
        "A4341B9FD50FB9964283220A36A1EF6F6FAA7840",
        "3B1EFD3A66EA28B16697394703A72CA340A05BD5",
    };
    return s;
}
const QStringList& strongPublishers() {
    static const QStringList s = { "Microsoft Corporation", "Microsoft Windows", "Microsoft Windows Publisher" };
    return s;
}
const QSet<QString>& knownSecurityProcessNames() {
    static const QSet<QString> s = {
        "msmpeng.exe", "mpcmdrun.exe", "nissrv.exe", "mpdefendercoreservice.exe", "securityhealthservice.exe",
        "avp.exe", "avpui.exe", "kavfs.exe", "kavfswp.exe", "ksde.exe", "ksdeui.exe",
        "avpsus.exe", "klnagent.exe", "ksn.exe",
        "ekrn.exe", "egui.exe",
        "mcshield.exe", "masvc.exe", "macmnsvc.exe", "mfemms.exe",
        "ccsvchst.exe", "symcorpui.exe", "nortonsecurity.exe", "rtvscan.exe",
        "avastsvc.exe", "avastui.exe", "afwserv.exe", "avgsvc.exe", "avgui.exe",
        "avguard.exe", "avgnt.exe", "sched.exe",
        "bdagent.exe", "vsserv.exe", "bdservicehost.exe",
        "ntrtscan.exe", "pccntmon.exe", "tmbmsrv.exe",
        "savservice.exe", "sophosfs.exe", "sophosfilescanner.exe",
        "360tray.exe", "360sd.exe", "360rp.exe", "zhudongfangyu.exe", "360safe.exe",
        "hipstray.exe", "hipsdaemon.exe", "usysdiag.exe", "wsctrl.exe",
        "qqpcrtp.exe", "qqpctray.exe", "qqpcmgr.exe",
        "kxetray.exe", "kxescore.exe", "kscan.exe", "ksafetray.exe", "kwsprotect64.exe",
    };
    return s;
}
const QStringList& protectedInstallDirs() {
    static const QStringList s = {
        "\\program files\\", "\\program files (x86)\\", "\\programdata\\",
        "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\defender\\",
    };
    return s;
}
const QStringList& benignPublishers() {
    static const QStringList s = {
        "Microsoft Corporation", "Microsoft Windows",
        "Google LLC", "Google Inc", "Mozilla Corporation", "Apple Inc",
        "Adobe Inc", "Adobe Systems",
        "Intel Corporation", "NVIDIA Corporation", "Advanced Micro Devices",
        "Realtek", "Lenovo", "Dell", "HP Inc", "Hewlett",
        "Valve", "Tencent", "Alibaba", "Bytedance",
        "Oracle", "VMware", "Citrix", "JetBrains", "GitHub", "Docker",
        "Igor Pavlov", "Notepad++",
        "Kaspersky", "Beijing Qihu", "Qizhi", "360",
        "Huorong", "Beijing Huorong", "Kingsoft", "WPS", "Baidu",
        "NetEase", "Sogou", "Bilibili", "Shanghai Hode",
        "Beijing Sankuai", "Meituan", "Spotify", "Discord", "Telegram", "Telegram FZ",
        "Zoom", "Slack Technologies", "Dropbox", "Logitech", "Logi",
        "ASUS", "ASUSTeK", "Razer", "Qualcomm", "MediaTek",
        "Western Digital", "Seagate", "Samsung", "WinRAR", "win.rar",
        "TeamViewer", "Cisco", "Postman", "Python Software Foundation",
        "The Git", "Git for Windows", "Canonical", "Epic Games",
        "Blizzard", "Riot Games", "Electronic Arts", "Ubisoft",
        "miHoYo", "Cognosphere", "OBS", "VideoLAN", "Audacity", "GIMP",
        "Doc-Cmd", "Foxit", "Tencent Technology", "Shenzhen Tencent",
    };
    return s;
}
// 已知良性厂商应用(即时通讯 / 常见桌面客户端):正常存在大量周期性心跳保活外联,极易被信标检测 /
// 外联 IP 情报误判为 C2 回连。按映像名快速识别(仍要求健康厂商签名才放行,见 isTrustedVendorApp)。
const QSet<QString>& trustedVendorApps() {
    static const QSet<QString> s = {
        "qq.exe", "tim.exe", "wechat.exe", "weixin.exe", "wxwork.exe",
    };
    return s;
}
const QStringList& systemDirs() {
    static const QStringList s = { "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\" };
    return s;
}
const QStringList& trustedDirs() {
    static const QStringList s = {
        "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\",
        "\\program files\\", "\\program files (x86)\\",
    };
    return s;
}
const QSet<QString>& lolBinsAndHosts() {
    static const QSet<QString> s = {
        "reg.exe", "regedit.exe", "regini.exe",
        "powershell.exe", "pwsh.exe", "cmd.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "sc.exe",
        "wmic.exe", "cmstp.exe", "fodhelper.exe",
    };
    return s;
}
// 命中【任一】即撤销主体的全部信任档:这些构造在正常软件的命令行里基本不出现,单独出现即
// 足以定性(内存下载执行、编码命令、凭据转储、删卷影等)。
const QStringList& hardDangerTokens() {
    static const QStringList s = {
        "-enc", "-encodedcommand", "downloadstring", "downloadfile",
        "invoke-expression", "iex(", "frombase64string", "urlcache",
        "javascript:", "vbscript:",
        "bitsadmin /transfer", "-decode",
        "comsvcs.dll", "minidump", "sekurlsa", "lsadump", "mimikatz", "invoke-mimikatz",
        "vssadmin delete", "wmic shadowcopy delete", "wbadmin delete",
        "invoke-webrequest", "start-bitstransfer", "reflection.assembly",
    };
    return s;
}

// 软构造:恶意软件常用,但【正常自动化脚本同样普遍使用】,单独出现不足以定性 ——
//   · "bypass"(-ExecutionPolicy Bypass):几乎每个正经 PowerShell 自动化脚本的标配,
//     本项目自己的 dev-all.ps1 / package.ps1 / build-driver.ps1 全都用它。以前它在硬名单里,
//     导致「签名健康的 powershell 跑构建脚本」被撤销全部信任 -> 掉进启发式路径 -> 批量删除
//     构建目录被勒索监视器当硬信号 -> 直接拦截。即本软件拦自己的构建脚本。
//   · "-w hidden" / "-windowstyle hidden":大量安装器/更新器/计划任务正常静默运行也用。
// 按本项目既定原则「软信号绝不单独定罪」,要求【至少两个软构造同时出现】才撤销信任 ——
// 这样 `-ep bypass -w hidden -enc ...` 这类真实恶意组合照旧被逮住,而单独 -ExecutionPolicy
// Bypass 不再误伤。单独出现时仍由 ThreatDetector(计 30 分)、ScriptAnalyzer(35 分)与内置
// Ask 规则 `*-executionpolicy bypass*` 继续计分/询问,检测能力并未丢失。
const QStringList& softDangerTokens() {
    static const QStringList s = {
        "bypass", "-w hidden", "-windowstyle hidden",
    };
    return s;
}
const QSet<QString>& officeAndBrowsers() {
    static const QSet<QString> s = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "acrord32.exe",
    };
    return s;
}
const QSet<QString>& scriptHostsSet() {
    static const QSet<QString> s = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    };
    return s;
}

bool containsDir(const QStringList& dirs, const QString& pathLower) {
    for (const QString& d : dirs) if (pathLower.contains(d)) return true;
    return false;
}
bool publisherMatches(const QString& publisher, const QStringList& list) {
    if (publisher.isEmpty()) return false;
    for (const QString& p : list) if (publisher.contains(p, Qt::CaseInsensitive)) return true;
    return false;
}

bool hasDangerousCommandLine(const QString& cmd) {
    if (cmd.isEmpty()) return false;
    const QString c = cmd.toLower();
    for (const QString& t : hardDangerTokens()) if (c.contains(t)) return true;
    // 软构造需互证:两个及以上同时出现才撤销信任(单个如 -ExecutionPolicy Bypass 不定罪)。
    int soft = 0;
    for (const QString& t : softDangerTokens()) if (c.contains(t)) ++soft;
    return soft >= 2;
}
bool isLolBinOrScriptHost(const QString& path) {
    const QString name = fileNameLower(path);
    return !name.isEmpty() && lolBinsAndHosts().contains(name);
}
bool hasDangerousCommandLineOrLolbinAbuse(const bulwark::SecurityEvent& e) {
    return hasDangerousCommandLine(e.commandLine)
        || LolbinAnalyzer::isAbusedLolbin(e.actorPath, e.commandLine)
        || CredentialAccessAnalyzer::isHardCredentialAccess(e);
}
bool isAbnormalChain(const bulwark::SecurityEvent& e) {
    const QString actor = fileNameLower(e.actorPath);
    const QString parent = fileNameLower(e.parentPath);
    return officeAndBrowsers().contains(parent) && scriptHostsSet().contains(actor);
}

} // namespace

TrustDecision TrustPolicy::isTrustedSecurityProduct(const bulwark::SecurityEvent& e) {
    if (e.actorPath.isEmpty()) return {};
    const QString name = fileNameLower(e.actorPath);
    if (name.isEmpty() || !knownSecurityProcessNames().contains(name)) return {};
    QString lower = e.actorPath.toLower();
    lower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!containsDir(protectedInstallDirs(), lower)) return {};
    return { true, u("已安装的知名安全软件(") + name + u("),共存放行") };
}

TrustDecision TrustPolicy::isStronglyTrusted(const bulwark::SecurityEvent& e) {
    if (hasDangerousCommandLineOrLolbinAbuse(e)) return {};
    if (isAbnormalChain(e)) return {};
    if (!e.actorSigned) return {};
    if (e.certRevoked || e.signedAfterCertExpiry) return {};

    if (!e.actorCertThumbprint.isEmpty() &&
        strongTrustThumbprints().contains(e.actorCertThumbprint.toUpper()))
        return { true, u("证书指纹在强可信白名单") };

    const QString pathLower = e.actorPath.toLower();
    if (publisherMatches(e.actorPublisher, strongPublishers()) && containsDir(systemDirs(), pathLower))
        return { true, u("微软签名且位于系统目录") };

    return {};
}

TrustDecision TrustPolicy::isHealthySigned(const bulwark::SecurityEvent& e) {
    if (!e.actorSigned) return {};
    if (e.signatureMismatch || e.certRevoked || e.signedAfterCertExpiry) return {};
    if (e.hasThreatIndicator) return {};
    if (hasDangerousCommandLineOrLolbinAbuse(e)) return {};
    if (isAbnormalChain(e)) return {};

    if (e.isFirstSeen && e.certNotAfterUtc.has_value()) {
        const qint64 secs = QDateTime::currentDateTimeUtc().secsTo(*e.certNotAfterUtc);
        if (secs > 0 && secs <= static_cast<qint64>(186) * 24 * 3600) return {};
    }

    const QString reason = e.actorPublisher.isEmpty()
        ? u("有效数字签名(健康),直接放行")
        : (u("有效数字签名:") + e.actorPublisher + u("(健康),直接放行"));
    return { true, reason };
}

TrustDecision TrustPolicy::isCleanSigned(const bulwark::SecurityEvent& e) {
    if (!e.actorSigned) return {};
    if (e.signatureMismatch || e.certRevoked || e.signedAfterCertExpiry) return {};
    if (e.hasThreatIndicator) return {};
    if (hasDangerousCommandLineOrLolbinAbuse(e)) return {};
    if (isAbnormalChain(e)) return {};

    const QString reason = e.actorPublisher.isEmpty()
        ? u("有合法且健康的数字签名,明确安全,跳过 VT 上传")
        : (u("有合法且健康的数字签名:") + e.actorPublisher + u(",明确安全,跳过 VT 上传"));
    return { true, reason };
}

TrustDecision TrustPolicy::isBenignSigner(const bulwark::SecurityEvent& e) {
    if (!e.actorSigned) return {};
    if (e.certRevoked || e.signedAfterCertExpiry) return {};

    if (!e.actorPublisher.isEmpty()) {
        for (const QString& pub : benignPublishers())
            if (e.actorPublisher.contains(pub, Qt::CaseInsensitive))
                return { true, u("合法签名发行商:") + pub };
    }

    const QString pathLower = e.actorPath.toLower();
    if (containsDir(trustedDirs(), pathLower))
        return { true, u("合法签名且位于标准安装目录") };

    return {};
}

TrustDecision TrustPolicy::isTrustedVendorApp(const bulwark::SecurityEvent& e) {
    // 仅识别内置清单里的即时通讯客户端映像名;其余一律不经此路放行。
    const QString name = fileNameLower(e.actorPath);
    if (name.isEmpty() || !trustedVendorApps().contains(name))
        return {};
    // 必须持有健康签名(未失配 / 未吊销 / 未过期后签名),防止同名恶意程序冒用白名单。
    if (!e.actorSigned || e.signatureMismatch || e.certRevoked || e.signedAfterCertExpiry)
        return {};
    // 且由良性发行商签名(如 Tencent):仅凭文件名不足以放行,签名主体必须可信。
    if (!e.actorPublisher.isEmpty()) {
        for (const QString& pub : benignPublishers())
            if (e.actorPublisher.contains(pub, Qt::CaseInsensitive))
                return { true, u("已知良性厂商应用(") + name + u(")·签名健康(") + pub + u("),检测前放行") };
    }
    return {};
}

TrustDecision TrustPolicy::isTrustedOsComponent(const bulwark::SecurityEvent& e) {
    if (e.hasThreatIndicator) return {};
    if (isLolBinOrScriptHost(e.actorPath)) return {};
    const TrustDecision t = isStronglyTrusted(e);
    if (!t.ok) return {};
    return { true, u("强可信系统组件(") + t.reason + u("),敏感操作豁免") };
}

TrustDecision TrustPolicy::isTrusted(const bulwark::SecurityEvent& e) {
    return isStronglyTrusted(e);
}

} // namespace bulwark::engine
