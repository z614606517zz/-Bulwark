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
        "\\program files\\", "\\program files (x86)\\",
        "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\defender\\",
        //
        // 【\programdata\ 已移除】它同时出现在 ThreatDetector::highSuspiciousDirs 里,
        // 也就是本项目自己把它列为「可疑投放目录」。同一个目录不能既是「可疑投放点」
        // 又是「受保护安装目录(放个杀软名字就无条件信任)」—— 那是直接矛盾,而且矛盾的
        // 两边里放行的那一边赢了(共存放行在管线第 ② 步,早于一切检测)。
        //
        // 影响面:真正装在 ProgramData 下的安全软件(部分国产安全软件的引擎目录)不再走
        // 这条「按名放行」通道,而是由签名信任层(isHealthySigned / isBenignSigner)放行。
        // 它们都带厂商签名,所以不会被误拦;失去的只是「无签名也按名字放行」这一档。
        //
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
// isStronglyTrusted 的目录条件(还要叠加微软签名)。
// 【\windows\servicing\ 的由来】TrustedInstaller.exe 住在这里,它是 Windows 更新 / DISM / sfc 真正
// 动系统文件的那个 SYSTEM 主体(另一半工作由 \windows\winsxs\...servicingstack...\ 下的 TiWorker.exe
// 做,那个已被 winsxs 覆盖)。缺了它,带 exemptOs 的 Block 规则(如替换辅助功能映像)会在正常系统
// 更新替换 System32 文件时命中,后果是拒绝改名 + 结束 TrustedInstaller 进程树。
// 放宽幅度有限:该目录与 System32 一样归 TrustedInstaller 所有,普通管理员写不进去,且这里仍然
// 要求微软签名 + 无危险命令行 + 无异常父子链。
const QStringList& systemDirs() {
    static const QStringList s = {
        "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\",
        "\\windows\\servicing\\",
    };
    return s;
}
const QStringList& trustedDirs() {
    static const QStringList s = {
        "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\",
        "\\program files\\", "\\program files (x86)\\",
    };
    return s;
}
// 这张名单【只】被 isLolBinOrScriptHost -> isTrustedOsComponent 使用,也就是只决定
// 「带 exemptOs 标记的规则要不要放过这个主体」。往里加名字的方向是【收窄豁免】,不会新增拦截。
//
// 后半段那几个复制 / 解包工具是随 exemptOs 用到文件替换类规则一起补的:原先名单里只有注册表和
// 脚本宿主类工具,因为此前 exemptOs 只出现在 RegistryWrite 规则上。一旦文件替换规则(替换
// System32 里的辅助功能映像)也带上 exemptOs,「微软签名 + 位于系统目录」这两个条件就会被
// System32 自带的复制工具原生满足 —— `xcopy evil.exe C:\Windows\System32\sethc.exe` 会拿到
// OS 组件豁免。它们本身是正常运维工具,但「用它们覆盖 System32 里的登录界面可执行文件」不存在
// 正常用途,所以在豁免这条路上一律不认。
//
// certutil / bitsadmin 一类不必列在这里:它们的滥用形态(-decode、urlcache 等)已经在
// hardDangerTokens 里,命中即撤销信任档,isStronglyTrusted 提前返回,根本走不到豁免。
const QSet<QString>& lolBinsAndHosts() {
    static const QSet<QString> s = {
        "reg.exe", "regedit.exe", "regini.exe",
        "powershell.exe", "pwsh.exe", "cmd.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "sc.exe",
        "wmic.exe", "cmstp.exe", "fodhelper.exe",
        "xcopy.exe", "robocopy.exe", "replace.exe",
        "expand.exe", "extrac32.exe", "esentutl.exe",
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

//
// ============ 目录判定必须锚定到盘符,不能用子串包含 ============
//
// 原实现是 `pathLower.contains(dir)`,而 dirs 里的条目形如 "\program files\"。于是:
//     C:\Users\<u>\Program Files\evil.exe    含 "\program files\"
//     C:\temp\Windows\System32\evil.exe      含 "\windows\system32\"
// 这两个目录任何用户都能自己创建,不需要权限。
//
// 对 isTrustedSecurityProduct 这条路径尤其致命:它的判据只有「映像名 ∈ 60 余个杀软进程名」+
// 「路径含受保护安装目录」,【完全不校验签名】,而受保护目录里还包含 \programdata\。也就是说
// 把样本命名成 360tray.exe 丢进 C:\ProgramData\任意子目录,它就在管线第 ② 步拿到「已安装的
// 知名安全软件,共存放行」——ThreatDetector、时序检测、全部规则一概不跑。
//
// 现在改为「盘符 + 目录」锚定前缀。UNC(\\server\share\...)不是本机安装目录,返回 false。
//
bool startsAfterDrive(const QString& pathLower, const QString& dirLower) {
    // pathLower 形如 "c:\program files\..." ;dirLower 形如 "\program files\"
    if (pathLower.size() < 2 || pathLower.at(1) != QLatin1Char(':')) return false;
    return QStringView(pathLower).mid(2).startsWith(dirLower);
}
bool containsDir(const QStringList& dirs, const QString& pathLower) {
    for (const QString& d : dirs) if (startsAfterDrive(pathLower, d)) return true;
    return false;
}
//
// 发行商匹配从「子串包含」改为「词边界匹配」。
//
// benignPublishers 里有 "360" / "Dell" / "Valve" / "Zoom" / "Oracle" 这类极短的条目,配上
// contains 之后,一张主体名为 "360Secure Fake Ltd" 或 "Valverde Software" 的代码签名证书就
// 进了良性发行商名单 —— 而按需要的名字申请一张 OV 代码签名证书是有组织的攻击者的常规操作。
// 同理 strongPublishers 的 "Microsoft Windows" 也会被 "Microsoft Windows Helper Inc" 命中。
//
// 词边界的含义:匹配位置的前后必须是「字符串端点」或「非字母数字字符」。于是
//   "Beijing Qihu Technology Co., Ltd." 对 "360"    -> 不命中(本来也不该由 "360" 命中)
//   "360 Total Security"               对 "360"    -> 命中
//   "360Secure Fake Ltd"               对 "360"    -> 不命中(360 后面紧跟字母)
// 判定仍不区分大小写。
//
// 返回【命中的那条名单项】(便于在原因里如实写出是哪一条),没命中返回空串。
// publisherMatches 是它的布尔封装 —— 两者必须共用同一套匹配口径,不能各写一遍。
QString matchedPublisher(const QString& publisher, const QStringList& list) {
    if (publisher.isEmpty()) return QString();
    const QString hay = publisher.toLower();
    for (const QString& p : list) {
        const QString needle = p.toLower();
        if (needle.isEmpty()) continue;
        int from = 0;
        for (;;) {
            const int at = hay.indexOf(needle, from);
            if (at < 0) break;
            const int end = at + needle.size();
            const bool leftOk = (at == 0) || !hay.at(at - 1).isLetterOrNumber();
            const bool rightOk = (end == hay.size()) || !hay.at(end).isLetterOrNumber();
            if (leftOk && rightOk) return p;
            from = at + 1;
        }
    }
    return QString();
}
bool publisherMatches(const QString& publisher, const QStringList& list) {
    return !matchedPublisher(publisher, list).isEmpty();
}

// ---- 被盗用 / 被滥用的签名者名单(由宿主注入,见 TrustPolicy::setAbusedSigners)----
//
// 【内置为空是刻意的】往这里硬写指纹等于把一份会过时的情报编译进二进制:证书会轮换、
// 盗用会被 CA 吊销、也会有新的被偷。名单该由部署方 / 情报通道给,代码只提供机制。
// 判定本身在下面的 isAbusedSigner,不依赖名单非空 —— 空名单时它恒不命中,行为与本机制
// 加入之前完全一致。
QSet<QString>& abusedThumbprints() {
    static QSet<QString> s;
    return s;
}
QStringList& abusedPublishers() {
    static QStringList s;
    return s;
}
// 指纹归一:去掉空格 / 冒号 / 连字符,转大写。配置里抄自证书管理器的指纹常带空格,
// 而 e.actorCertThumbprint 是无分隔大写十六进制,两边必须先对齐再比。
QString normalizeThumbprint(const QString& raw) {
    QString out;
    out.reserve(raw.size());
    for (const QChar ch : raw) {
        if (ch.isLetterOrNumber()) out.append(ch.toUpper());
    }
    return out;
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

void TrustPolicy::setAbusedSigners(const QStringList& thumbprints, const QStringList& publishers) {
    QSet<QString>& tp = abusedThumbprints();
    tp.clear();
    for (const QString& t : thumbprints) {
        const QString n = normalizeThumbprint(t);
        if (!n.isEmpty()) tp.insert(n);
    }
    QStringList& pubs = abusedPublishers();
    pubs.clear();
    for (const QString& p : publishers) {
        const QString trimmed = p.trimmed();
        // 【短词一律拒收】名单按词边界子串匹配,一个两三字符的条目(如 "AB")会命中大量无关
        // 主体名,而这条名单的后果是撤销签名信任 —— 配错的代价是正常签名软件掉进行为检测。
        // 与 CommandHardBlocks「每个 token >= 4 字符」同一条理由。
        if (trimmed.size() >= 4) pubs.append(trimmed);
    }
}

TrustDecision TrustPolicy::isAbusedSigner(const bulwark::SecurityEvent& e) {
    if (!e.actorCertThumbprint.isEmpty()) {
        const QString n = normalizeThumbprint(e.actorCertThumbprint);
        if (!n.isEmpty() && abusedThumbprints().contains(n))
            return { true, u("签名证书在【被盗用证书】名单内(指纹 ") + n + u(")") };
    }
    const QString pub = matchedPublisher(e.actorPublisher, abusedPublishers());
    if (!pub.isEmpty())
        return { true, u("签名主体在【被盗用证书】名单内:") + pub };
    return {};
}

TrustDecision TrustPolicy::isTrustedSecurityProduct(const bulwark::SecurityEvent& e) {
    if (e.actorPath.isEmpty()) return {};
    const QString name = fileNameLower(e.actorPath);
    if (name.isEmpty() || !knownSecurityProcessNames().contains(name)) return {};
    //
    // 【必须校验签名】这一步是管线的第 ② 步,早于 ThreatDetector 与全部规则,给出的是
    // 【无条件放行】。而原判据只有「映像名 ∈ 杀软进程名」+「路径含安装目录」两条,都不需要
    // 任何凭据 —— 把样本改名成 avp.exe / 360tray.exe 放进 Program Files 的任一子目录即可通过。
    //
    // 对比同一文件里的 isTrustedVendorApp(IM 白名单):它明确要求「健康签名 + 良性发行商」,
    // 理由写的是「仅凭文件名不足以放行,签名主体必须可信」。共存放行的风险更高(作用于全部
    // 事件类型,而不是只有网络维度),却用了更松的判据,这个不一致本身就是问题。
    //
    // 现在要求签名健康(有效 / 未失配 / 未吊销 / 未在证书过期后签名)。真正装了的安全软件
    // 一定带厂商签名,不受影响;冒名者拿不到。
    //
    if (!e.actorSigned || e.signatureMismatch || e.certRevoked || e.signedAfterCertExpiry)
        return {};
    // 签名有效但证书是偷来的 —— 这一档是【无条件放行】,必须一并挡住(见 isAbusedSigner)。
    if (isAbusedSigner(e).ok) return {};
    QString lower = e.actorPath.toLower();
    lower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!containsDir(protectedInstallDirs(), lower)) return {};
    return { true, u("已安装的知名安全软件(") + name + u(")·签名健康,共存放行") };
}

TrustDecision TrustPolicy::isStronglyTrusted(const bulwark::SecurityEvent& e) {
    if (hasDangerousCommandLineOrLolbinAbuse(e)) return {};
    if (isAbnormalChain(e)) return {};
    //
    // 它要执行的【脚本文件正文】命中了行为级判据 —— 不走这条快速放行。
    //
    // 【为什么必须在这里拦一道】本步骤是流水线上「唯一跳过行为检测的通道」,而脚本宿主的
    // 主体永远是 `C:\Windows\System32\cmd.exe` / `wscript.exe` 这类【微软签名 + 系统目录】
    // 的正规程序 —— 正好命中下面那条「微软签名且位于系统目录」。于是在加上本判断之前:
    // 富化阶段已经认定脚本正文是加载器(硬指标 + 风险分 93~100),裁决却在第 7 步就放行了,
    // 第 10 步的硬指标闸门根本轮不到。实测 7 个真实样本全部如此(Allow,risk 100,硬指标)。
    //
    // 只看 scriptFileHardIndicator 而不是笼统的 hasThreatIndicator:后者影响所有强可信主体,
    // 属于另一个范围大得多的改动(第 9 步 isHealthySigned 已经那么做了,本步没有,这个不一致
    // 本身值得单独评估)。这里只修「可信宿主 + 不可信脚本」这一种,不牵动其它路径。
    //
    if (e.scriptFileHardIndicator) return {};
    if (!e.actorSigned) return {};
    if (e.certRevoked || e.signedAfterCertExpiry) return {};
    // 被盗用证书优先于指纹白名单:名单是「这张证书可信」,而这里说的是「这张证书已经不
    // 归原主了」。两者冲突时必须后者赢,否则一张进过白名单的证书被偷之后永远收不回来。
    if (isAbusedSigner(e).ok) return {};

    if (!e.actorCertThumbprint.isEmpty() &&
        strongTrustThumbprints().contains(e.actorCertThumbprint.toUpper()))
        return { true, u("证书指纹在强可信白名单") };

    // containsDir 现在是【盘符锚定】前缀比较,所以这里必须先把 '/' 归一为 '\' ——
    // 否则一条用正斜杠表示的路径会因为形态而不匹配(原来的 contains 对分隔符方向不敏感,
    // 换成锚定后就敏感了)。
    QString pathLower = e.actorPath.toLower();
    pathLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
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
    if (isAbusedSigner(e).ok) return {};

    // 证书有效期的两种异常形态。两者都只在【本机首见】时才收紧 —— 已经在这台机器上跑了很久的
    // 签名软件,不该因为厂商证书到期就忽然掉出快速放行通道。
    if (e.certNotAfterUtc.has_value()) {
        const qint64 secs = nowUtc().secsTo(*e.certNotAfterUtc);
        // ① 证书快到期:空壳公司现买现用的新证书画像(原有判据,未改)。
        if (e.isFirstSeen && secs > 0 && secs <= static_cast<qint64>(186) * 24 * 3600) return {};
        //
        // ② 证书【已经过期】,而签名仍然判为有效 —— 因为本项目的 WinVerifyTrust 调用没有开
        //    WTD_LIFETIME_SIGNING_FLAG(见 ProcessInspector.cpp 里 kWinTrustProvFlags 的说明),
        //    所以「过期证书 + 签名时有合法时间戳」照旧是可信签名,actorSigned 为真。
        //
        //    这个形态【绝大多数是正常的】:大量老软件就长这样。所以不能据此拦截,也不能单凭
        //    过期就取消放行 —— 那会把一批装在 Program Files 里多年的正常程序赶进行为检测。
        //
        //    但它同时是「盗用旧证书」的典型落点:私钥到手时证书往往已经临近或已经过期,签完
        //    再挂一个时间戳,整条链看起来就是完整的,而 certRevoked 要等 CA 吊销 + CRL 下发到
        //    本机才会变真。所以这里按本项目既定原则要求互证,三条同时成立才收紧:
        //        已过期 + 本机首见 + 不在标准安装目录(即出现在用户可写的投放点)。
        //    收紧的含义仅是「不走签名健康快速放行」,让事件回到正常检测流水线;没有硬指标时
        //    第 11 步照样放行,所以这不会凭空产生拦截或弹窗。
        //
        if (secs < 0 && e.isFirstSeen) {
            QString pathLower = e.actorPath.toLower();
            pathLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
            if (!containsDir(trustedDirs(), pathLower)) return {};
        }
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
    // 这一档决定「要不要跳过 VT 上传」。被盗用证书签的样本恰恰是最该送上去的那一类。
    if (isAbusedSigner(e).ok) return {};

    const QString reason = e.actorPublisher.isEmpty()
        ? u("有合法且健康的数字签名,明确安全,跳过 VT 上传")
        : (u("有合法且健康的数字签名:") + e.actorPublisher + u(",明确安全,跳过 VT 上传"));
    return { true, reason };
}

TrustDecision TrustPolicy::isBenignSigner(const bulwark::SecurityEvent& e) {
    if (!e.actorSigned) return {};
    if (e.certRevoked || e.signedAfterCertExpiry) return {};
    if (isAbusedSigner(e).ok) return {};

    //
    // 【必须走 matchedPublisher(词边界),不能用 contains】本文件上方 publisherMatches 的说明
    // 已经论证过为什么子串包含在这里是错的:benignPublishers 里有 "360" / "Dell" / "Valve" /
    // "Zoom" / "Oracle" 这类三四个字符的条目,contains 之下一张签给 "Valverde Software Ltd"
    // 或 "360Secure Fake Ltd" 的证书就直接进了良性发行商名单 —— 而按想要的名字去申请一张 OV
    // 代码签名证书,是有组织攻击者的常规操作,成本远低于偷一把私钥。
    //
    // 那次加固当时只落在 publisherMatches 这个新函数上,isBenignSigner 与 isTrustedVendorApp
    // 两个调用点没有跟着换,于是收紧实际上没生效在这两条路上。这里补齐。
    //
    const QString pub = matchedPublisher(e.actorPublisher, benignPublishers());
    if (!pub.isEmpty())
        return { true, u("合法签名发行商:") + pub };

    // 同上:containsDir 已是盘符锚定,需先归一分隔符。
    QString pathLower = e.actorPath.toLower();
    pathLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
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
    if (isAbusedSigner(e).ok) return {};
    // 且由良性发行商签名(如 Tencent):仅凭文件名不足以放行,签名主体必须可信。
    // 同 isBenignSigner:这里必须按词边界匹配,否则「文件名叫 wechat.exe + 证书主体里带
    // Tencent 字样」就能凑齐放行条件,而主体名是攻击者可以自己申请的那一半。
    const QString pub = matchedPublisher(e.actorPublisher, benignPublishers());
    if (!pub.isEmpty())
        return { true, u("已知良性厂商应用(") + name + u(")·签名健康(") + pub + u("),检测前放行") };
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
