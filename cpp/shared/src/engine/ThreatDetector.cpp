#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/engine/SystemPaths.h"
#include "bulwark/engine/LolbinAnalyzer.h"
#include "bulwark/engine/CredentialAccessAnalyzer.h"
#include "bulwark/engine/DefenseEvasionAnalyzer.h"
#include "bulwark/engine/RemoteControlAnalyzer.h"
#include "bulwark/engine/InjectionAnalyzer.h"
#include "bulwark/engine/CommandObfuscationAnalyzer.h"
#include "bulwark/engine/ScriptAnalyzer.h"
#include "bulwark/engine/KillChainAnalyzer.h"
#include "bulwark/engine/TrustPolicy.h"
#include <QSet>
#include <QHash>
#include <QStringList>
#include <QVector>
#include <QDateTime>

namespace bulwark::engine {

using detail::u;
using detail::fileNameLower; // = C# SafeFileName

namespace {

// 常被滥用的合法系统程序(LOLBins)。
const QSet<QString>& lolBins() {
    static const QSet<QString> s = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
        "msbuild.exe", "installutil.exe", "wmic.exe", "schtasks.exe", "at.exe",
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

// hard=true:命中即视为硬恶意指标(置位 hasThreatIndicator,可单独定罪/弹窗)。
// hard=false:软信号,仅加分,需与其它硬指标互证才升格——用于「弱特征」(如命令行里
// 出现 URL、-NoProfile 等),避免正规(尤其是签名)程序仅因携带 URL 参数就被弹窗。
struct Sig { const char* token; int score; const char* reason; bool hard = true; };

const QVector<Sig>& commandLineSignals() {
    static const QVector<Sig> s = {
        { "-enc", 35, "PowerShell 编码命令(-EncodedCommand,T1027)" },
        { "-encodedcommand", 35, "PowerShell 编码命令(T1027)" },
        { "-nop", 8, "PowerShell 跳过配置文件(-NoProfile)", false },
        { "-noprofile", 8, "PowerShell 跳过配置文件", false },
        { "-windowstyle hidden", 30, "隐藏窗口运行" },
        { "-w hidden", 30, "隐藏窗口运行" },
        // 「绕过执行策略」按【软信号】计,与 TrustPolicy::softDangerTokens 的判断保持一致。
        //
        // TrustPolicy 那边早就得出过结论并写在注释里:正规安装器 / CI 脚本 / 本项目自己的
        // build 脚本全都用 `-ExecutionPolicy Bypass`(那是在 Windows 上跑 .ps1 的标准姿势),
        // 所以它把 "bypass" 放进 softDangerTokens、要求【至少两个软构造同时出现】才撤销信任,
        // 并明确写道「单独出现时仍由 ThreatDetector(计 30 分)…继续计分/询问」—— 也就是说
        // 本表这一条的设计意图从来是「计分 + 询问」,不是「单独定罪」。
        //
        // 但 Sig::hard 默认为 true,于是它实际一直在置 hasThreatIndicator,后果是:
        //   · 健康签名放行(TrustPolicy::isHealthySigned)因 hasThreatIndicator 直接失效;
        //   · 开了静默模式后,风险分过 50 就被静默升级成 Block —— 进程直接被结束。
        // 实测:cmd.exe 因 `-NoProfile` + `-ExecutionPolicy Bypass` + 命令行熵 4.9 得 62 分被杀
        //(这正是那条注释里担心的「本软件拦自己的构建脚本」)。
        //
        // 改为软信号后检出能力不丢:真实恶意几乎总是组合出现 —— `-w hidden`(30,硬)、
        // `-enc`(35,硬)、`downloadstring`(40,硬)任一命中即照旧定罪;内置规则
        // `*-executionpolicy bypass*` 仍会产生 Ask;ScriptAnalyzer 对脚本正文另计 35 分。
        { "-executionpolicy bypass", 30, "绕过执行策略", false },
        { "-ep bypass", 30, "绕过执行策略", false },
        { "downloadstring", 40, "内存下载执行(DownloadString,T1105)" },
        { "downloadfile", 35, "远程下载文件(T1105)" },
        { "invoke-expression", 35, "动态执行(IEX,T1059.001)" },
        { "iex(", 35, "动态执行(IEX,T1059.001)" },
        { "frombase64string", 30, "Base64 解码执行(T1140)" },
        { "urlcache", 40, "certutil 远程下载(-urlcache,T1105)" },
        { "-decode", 25, "certutil 解码(可能还原载荷,T1140)" },
        { "http://", 20, "命令行内含明文 URL", false },
        { "https://", 15, "命令行内含 URL", false },
        { "javascript:", 35, "mshta 执行脚本" },
        { "vbscript:", 35, "mshta 执行脚本" },
        { "bitsadmin /transfer", 35, "BITS 后台下载(T1197)" },
        { "-noninteractive", 5, "非交互运行", false },
        { "comsvcs.dll", 40, "comsvcs 转储 LSASS 内存(凭据窃取,T1003.001)" },
        // 「minidump」单独出现【只作软信号】。这个词是崩溃处理器的本职词汇:Crashpad /
        // Breakpad / WerFault / 各类客户端的崩溃上报组件命令行里都带它,而转储自己进程的内存
        // 恰恰是它们存在的意义。实测 Tencent 签名的
        //   C:\Program Files\Tencent\QQNT\...\crashpad_handler.exe
        // 就因为这一个词被判「疑似凭据窃取」,51 分被拦 4 次。
        //
        // 真正的凭据转储不会只留下这一个词,而且都另有硬判据兜着:comsvcs.dll(上一行,40 分硬)、
        // sekurlsa / lsadump(下面两行,50 分硬)、CredentialAccessAnalyzer 的 LSASS 判定,
        // 以及下面新增的「minidump + lsass 同时出现」合取。所以降为软信号不丢检出。
        { "minidump", 35, "进程内存转储(崩溃上报组件也用此参数,需互证)", false },
        { "sekurlsa", 50, "Mimikatz 凭据抓取(sekurlsa,T1003.001)" },
        { "lsadump", 50, "Mimikatz 凭据转储(lsadump,T1003.001)" },
        { "mimikatz", 55, "Mimikatz 凭据攻击工具(T1003.001)" },
        { "invoke-mimikatz", 55, "PowerShell 版 Mimikatz(T1003.001)" },
        { "procdump", 25, "ProcDump 转储进程内存(可能针对 LSASS,T1003.001)" },
        { "-windowstyle h", 30, "隐藏窗口运行" },
        { "invoke-webrequest", 30, "远程下载(Invoke-WebRequest,T1105)" },
        { "iwr ", 25, "远程下载(iwr 别名,T1105)" },
        { "start-bitstransfer", 30, "BITS 后台下载(PowerShell,T1197)" },
        { "reflection.assembly", 30, "内存加载程序集(无文件,T1027)" },
        { "[reflection.assembly]", 30, "内存加载程序集(无文件,T1027)" },
        //
        // 判别词是 "delete shadows",不是 "vssadmin delete"。
        //
        // 本表是【子串】匹配,而真实命令行是 `vssadmin.exe delete shadows /all /quiet` ——
        // "vssadmin" 与 "delete" 之间隔着 ".exe",所以旧判别词【一次都没命中过】。后果不是
        // 少 45 分那么简单:没有硬指标,事件就一路走到步骤 7 的 isStronglyTrusted(vssadmin
        // 是微软签名 + 位于 System32)被【放行】—— 也就是勒索最标准的前置动作在默认配置下
        // 畅通无阻。裁决快照语料里那条用例的备注写的是「一瞬间完成故必须硬拦」,而黄金结果
        // 记的却是 Allow,正是这处失配被固化下来的样子。
        //
        // 换成 "delete shadows" 后两种写法(带不带 .exe)都命中,且没有任何正常命令行会包含它。
        //
        { "delete shadows", 45, "删除卷影副本(勒索前置,T1490)" },
        { "wmic shadowcopy delete", 45, "删除卷影副本(勒索前置,T1490)" },
        { "wbadmin delete", 40, "删除系统备份(勒索前置,T1490)" },
        { "bcdedit", 25, "修改引导配置(勒索常用,T1490)" },
        // 本表是【子串】匹配,原先这里写作 "-noprofile -e",意图是抓 `-NoProfile -e <base64>`
        //(-e 是 -EncodedCommand 的简写),但它同时命中了 `-NoProfile -ExecutionPolicy Bypass`
        // —— 后者是几乎所有正经 PowerShell 自动化脚本的标配写法,于是每次跑构建/部署脚本都被
        // 贴上「编码执行组合」这个并不存在的理由并白加 25 分(实测 36 次误拦均由此参与)。
        // 拆成两个不会误伤的精确前缀:`-enc`/`-encodedcommand` 与带空格的 `-e <参数>`。
        { "-noprofile -enc", 25, "PowerShell 跳过配置 + 编码执行组合(T1027)" },
        { "-noprofile -e ",  25, "PowerShell 跳过配置 + 编码执行组合(T1027)" },
    };
    return s;
}

const QStringList& highSuspiciousDirs() {
    static const QStringList s = {
        "\\appdata\\local\\temp\\", "\\windows\\temp\\",
        "\\users\\public\\", "\\programdata\\", "\\$recycle.bin\\",
        "\\perflogs\\",
    };
    return s;
}

const QStringList& mediumSuspiciousDirs() {
    static const QStringList s = {
        "\\downloads\\", "\\appdata\\roaming\\",
        "\\desktop\\", "\\documents\\", "\\onedrive\\desktop\\", "\\onedrive\\documents\\",
    };
    return s;
}

// 系统进程的合法目录白名单(键为小写映像名)。
const QHash<QString, QStringList>& systemProcessDirs() {
    static const QHash<QString, QStringList> m = {
        { "svchost.exe",    { "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\" } },
        { "lsass.exe",      { "\\windows\\system32\\" } },
        { "csrss.exe",      { "\\windows\\system32\\" } },
        { "services.exe",   { "\\windows\\system32\\" } },
        { "winlogon.exe",   { "\\windows\\system32\\" } },
        { "smss.exe",       { "\\windows\\system32\\" } },
        { "wininit.exe",    { "\\windows\\system32\\" } },
        { "dllhost.exe",    { "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\" } },
        { "taskhostw.exe",  { "\\windows\\system32\\", "\\windows\\winsxs\\" } },
        { "spoolsv.exe",    { "\\windows\\system32\\" } },
        { "conhost.exe",    { "\\windows\\system32\\" } },
        { "explorer.exe",   { "\\windows\\explorer.exe", "\\windows\\winsxs\\" } },
        { "dwm.exe",        { "\\windows\\system32\\" } },
        { "fontdrvhost.exe", { "\\windows\\system32\\" } },
        { "runtimebroker.exe",      { "\\windows\\system32\\" } },
        { "sihost.exe",             { "\\windows\\system32\\" } },
        { "ctfmon.exe",             { "\\windows\\system32\\" } },
        { "userinit.exe",           { "\\windows\\system32\\" } },
        { "audiodg.exe",            { "\\windows\\system32\\" } },
        { "wuauclt.exe",            { "\\windows\\system32\\" } },
        { "searchindexer.exe",      { "\\windows\\system32\\" } },
        { "searchprotocolhost.exe", { "\\windows\\system32\\" } },
        { "searchfilterhost.exe",   { "\\windows\\system32\\" } },
        { "taskhost.exe",           { "\\windows\\system32\\" } },
        { "smartscreen.exe",        { "\\windows\\system32\\" } },
        { "securityhealthservice.exe", { "\\windows\\system32\\" } },
    };
    return m;
}

const QSet<QString>& legitWindowsSubdirNames() {
    static const QSet<QString> s = {
        "system32", "syswow64", "winsxs", "servicing", "microsoft.net", "assembly",
        "systemapps", "systemresources", "immersivecontrolpanel", "shellexperiences",
        "shellcomponents", "softwaredistribution", "fonts", "inf", "diagnostics",
        "debug", "security", "setup", "ime", "appcompat", "apppatch", "schemas",
        "globalization", "policydefinitions", "branding", "resources", "web", "media",
        "boot", "help", "cursors", "speech", "speech_onecore", "vss", "twain_32",
        "system", "l2schemas", "addins", "containers", "migration", "plugplay",
        "registration", "rescache", "servicestate", "tasks", "temp", "tracing",
        "waas", "winrm", "performance", "panther", "prefetch", "logs", "pchealth",
        "pla", "sysnative", "wbem", "windowspowershell", "downloaded program files",
        "offline web pages", "fixit", "diagtrack", "waasmedic",
    };
    return s;
}

const QStringList& criticalImageNames() {
    static const QStringList s = {
        "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
        "wininit.exe", "smss.exe", "explorer.exe", "spoolsv.exe", "taskhostw.exe",
        "dwm.exe", "conhost.exe", "rundll32.exe", "dllhost.exe", "ctfmon.exe",
        "runtimebroker.exe", "sihost.exe", "searchindexer.exe", "audiodg.exe",
    };
    return s;
}


bool anyContains(const QStringList& needles, const QString& hay) {
    for (const QString& n : needles)
        if (hay.contains(n)) return true;
    return false;
}

bool isSystemProcessName(const QString& name) {
    return systemProcessDirs().contains(name);
}

// 把常见同形字符还原为对应字母(svch0st / 1sass / scvhоst 等)。
QString deHomoglyph(const QString& s) {
    QString out;
    out.reserve(s.size());
    for (const QChar c : s) {
        const QChar lc = c.toLower();
        switch (lc.unicode()) {
            case u'0':      out.append(QLatin1Char('o')); break;
            case u'1':      out.append(QLatin1Char('l')); break;
            case u'5':      out.append(QLatin1Char('s')); break;
            case u'7':      out.append(QLatin1Char('t')); break;
            case 0x0430:    out.append(QLatin1Char('a')); break; // 西里尔 а
            case 0x0435:    out.append(QLatin1Char('e')); break; // 西里尔 е
            case 0x043e:    out.append(QLatin1Char('o')); break; // 西里尔 о
            case 0x0440:    out.append(QLatin1Char('p')); break; // 西里尔 р
            case 0x0441:    out.append(QLatin1Char('c')); break; // 西里尔 с
            default:        out.append(lc); break;
        }
    }
    return out;
}

QString stripExe(const QString& name) {
    const int dot = name.lastIndexOf(QLatin1Char('.'));
    return dot > 0 ? name.left(dot) : name;
}

// Levenshtein 编辑距离是否恰为 1(相等返回 false)。
bool levenshteinAtMost1(const QString& a, const QString& b) {
    const int la = a.size(), lb = b.size();
    if (qAbs(la - lb) > 1) return false;
    if (a == b) return false;

    if (la == lb) {
        int diff = 0;
        for (int i = 0; i < la; ++i)
            if (a.at(i) != b.at(i) && ++diff > 1) return false;
        return diff == 1;
    }

    const QString& shorter = la < lb ? a : b;
    const QString& longer  = la < lb ? b : a;
    int si = 0, li = 0; bool skipped = false;
    while (si < shorter.size() && li < longer.size()) {
        if (shorter.at(si) == longer.at(li)) { ++si; ++li; }
        else {
            if (skipped) return false;
            skipped = true; ++li;
        }
    }
    return true;
}

// 形近仿冒判定:命中返回被仿冒的真实系统进程名,否则返回空。
QString findImpersonatedSystemName(const QString& actorName) {
    if (actorName.isEmpty()) return QString();

    static const QStringList exeExts = { ".exe", ".scr", ".com", ".pif", ".bat", ".cmd" };
    bool isExe = false;
    for (const QString& x : exeExts)
        if (actorName.endsWith(x, Qt::CaseInsensitive)) { isExe = true; break; }
    if (!isExe) return QString();

    QString noSpace;
    noSpace.reserve(actorName.size());
    for (const QChar c : actorName) if (!c.isSpace()) noSpace.append(c);
    for (const QString& real : criticalImageNames())
        if (actorName.compare(real, Qt::CaseInsensitive) != 0 &&
            noSpace.compare(real, Qt::CaseInsensitive) == 0)
            return real;

    const QString deHomo = deHomoglyph(actorName);
    for (const QString& real : criticalImageNames())
        if (actorName.compare(real, Qt::CaseInsensitive) != 0 &&
            deHomo.compare(real, Qt::CaseInsensitive) == 0)
            return real;

    const QString stem = stripExe(actorName);
    if (stem.size() >= 5) {
        for (const QString& real : criticalImageNames()) {
            const QString realStem = stripExe(real);
            if (stem.compare(realStem, Qt::CaseInsensitive) == 0) continue;
            if (levenshteinAtMost1(stem.toLower(), realStem.toLower())) return real;
        }
    }

    return QString();
}

// 系统进程名是否位于其合法目录(前缀锚定,空路径不判伪装)。
bool isInSystemDirFor(const QString& actorName, const QString& pathLower) {
    if (pathLower.isEmpty()) return true;
    const auto it = systemProcessDirs().constFind(actorName);
    if (it == systemProcessDirs().constEnd()) return true;
    const QString rel = SystemPaths::volumeRelative(pathLower);
    for (const QString& d : it.value())
        if (rel.startsWith(d)) return true;
    return false;
}

// 路径是否位于 C:\Windows\ 下的非标准子目录。
bool isNonStandardWindowsSubdir(const QString& path) {
    if (path.isEmpty()) return false;
    QString pathLower = path.toLower();
    pathLower.replace(QLatin1Char('/'), QLatin1Char('\\'));

    if (pathLower.size() < 4 || pathLower.at(1) != QLatin1Char(':')) return false;
    const QString rest = pathLower.mid(2);
    static const QString win = QStringLiteral("\\windows\\");
    if (!rest.startsWith(win)) return false;

    const int nextSlash = rest.indexOf(QLatin1Char('\\'), win.size());
    if (nextSlash < 0) return false;

    const QString firstSub = rest.mid(win.size(), nextSlash - win.size());
    return !legitWindowsSubdirNames().contains(firstSub);
}

bool hasDoubleExtension(const QString& name) {
    static const QStringList docExts = { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".rtf" };
    static const QStringList exeExts = { ".exe", ".scr", ".com", ".bat", ".cmd", ".pif", ".vbs", ".js" };
    for (const QString& d : docExts)
        for (const QString& x : exeExts)
            if (name.endsWith(d + x, Qt::CaseInsensitive)) return true;
    return false;
}

// 路径是否指向 NTFS 备用数据流(ADS),如 C:\path\file.txt:payload.exe。
//
// 【这里曾是一处稳定的误报源】原实现只在冒号【正好位于下标 1】时才跳过盘符:
//     const int start = (path.size() > 1 && path.at(1) == ':') ? 2 : 0;
// 而内核事件源交上来的路径本产品自己就明确期待 NT 命名空间形态(\??\C:\...,见
// Worker 里对该前缀的处理)。那种路径下标 1 是 '?',于是 start=0,接着就把 "C:" 的
// 那个冒号当成了流分隔符 —— 命中「从 NTFS 备用数据流(ADS)执行」并加 40 分【硬指标】。
// 硬指标会让静默模式把 >=50 分直接升级为拦截,也就是普通程序被误杀。
// 修法:先剥掉 NT / Win32 设备命名空间前缀,再按「盘符冒号之后是否还有冒号」判定。
bool isAlternateDataStreamPath(const QString& path) {
    if (path.isEmpty()) return false;
    QString p = path;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));

    // \??\  \\?\  \\.\ 三种前缀都要剥,否则前缀里的字符会把盘符位置算错。
    static const char* kPrefixes[] = { "\\??\\", "\\\\?\\", "\\\\.\\" };
    for (const char* pre : kPrefixes) {
        const QString s = QLatin1String(pre);
        if (p.startsWith(s, Qt::CaseInsensitive)) {
            p = p.mid(s.size());
            break;
        }
    }

    int start = 0;
    if (p.size() > 1 && p.at(1) == QLatin1Char(':') && p.at(0).isLetter())
        start = 2;                                  // 跳过盘符 "X:"
    const int colon = p.indexOf(QLatin1Char(':'), start);
    if (colon < 0) return false;
    return colon + 1 < p.size();                    // 流名必须非空("C:" 结尾不算流)
}

// PowerShell 的执行策略探测:每次启动 PowerShell 都会往临时目录写一个
// __PSScriptPolicyTest_<随机>.ps1,是常态噪音,确实该放过。
//
// 【原判据可被攻击者直接利用】原实现是
//     if (e.target.toLower().contains("__psscriptpolicytest")) return;
// —— 只要目标路径里出现这个字样,本函数【全部】分析(注入、双扩展名、LOLBin、
// 凭据访问、防御规避……)一次都不跑。而 target 是攻击者可控的:把释放物命名成
// __psscriptpolicytest_x.exe,或往那个名字的目录里落盘,就能整体关掉单事件威胁检测。
// 这里收紧成完整签名,四个条件缺一不可。
bool isPowerShellPolicyProbe(const SecurityEvent& e) {
    if (e.type != EventType::FileWrite && e.type != EventType::FileDelete)
        return false;

    const QString actorName = fileNameLower(e.actorPath);
    if (actorName != QLatin1String("powershell.exe") && actorName != QLatin1String("pwsh.exe"))
        return false;

    QString actorLower = e.actorPath.toLower();
    actorLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    QString sysRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows")).toLower();
    sysRoot.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!sysRoot.endsWith(QLatin1Char('\\'))) sysRoot += QLatin1Char('\\');
    if (!actorLower.contains(sysRoot)) return false;   // contains:兼容 \??\ 前缀

    QString targetLower = e.target.toLower();
    targetLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const int slash = targetLower.lastIndexOf(QLatin1Char('\\'));
    const QString targetName = (slash >= 0) ? targetLower.mid(slash + 1) : targetLower;
    // 文件名必须以该前缀【开头】,且扩展名必须是 .ps1(不能是可执行体)。
    if (!targetName.startsWith(QLatin1String("__psscriptpolicytest"))
        || !targetName.endsWith(QLatin1String(".ps1")))
        return false;

    return targetLower.contains(QLatin1String("\\temp\\"))
           || targetLower.contains(QLatin1String("\\appdata\\local\\temp\\"));
}

} // anonymous namespace

void ThreatDetector::analyze(SecurityEvent& e) {
    // 良性系统行为白名单。必须放在【任何状态改写之前】:原实现把这个判断放在函数中段,
    // 已经复位了 hasThreatIndicator、也已经把 e.chainScore 累进局部 score 之后才 return,
    // 于是攻击链组合引擎的跨事件结论被无声丢掉(riskScore 也停在旧值上从不更新)。
    // 这里返回前显式把组合引擎的结论落到事件上 —— 那是跨事件记账的产物,与「本事件是
    // 不是 PowerShell 策略探测」无关,不该被这条白名单顺带抹掉。
    if (isPowerShellPolicyProbe(e)) {
        e.riskScore = e.chainScore;
        e.hasThreatIndicator = e.chainHardIndicator;
        return;
    }

    int score = 0;
    e.hasThreatIndicator = false;

    // 并入攻击链组合引擎的贡献。它在本函数【之前】就完成了匹配(Worker 在 evaluate 前调用),
    // 而本函数开头复位 hasThreatIndicator、结尾用赋值覆盖 riskScore —— 若不在此显式并入,
    // 它的结论就会被无声擦掉。这正是组合表上线后从未生效过一次的原因,勿删。
    // 放在最前面而不是最后:后面「威胁情报判为干净则减 10 分」那一支要读 hasThreatIndicator,
    // 组合命中属互证硬指标,不该被信誉良好抵扣。
    score += e.chainScore;
    if (e.chainHardIndicator)
        e.hasThreatIndicator = true;

    // hard=true 视为硬恶意指标,置位 hasThreatIndicator。
    auto Add = [&](int delta, const QString& reason, bool hard = false,
                   EvidenceKind kind = EvidenceKind::SoftSignal) {
        score += delta;
        e.addEvidence(QStringLiteral("ThreatDetector"),
                      hard ? EvidenceKind::HardIndicator : kind, reason, delta);
        if (hard) e.hasThreatIndicator = true;
    };

    const QString actorName = fileNameLower(e.actorPath);
    const QString parentName = fileNameLower(e.parentPath);
    const QString cmd = e.commandLine.toLower();
    const QString pathLower = e.actorPath.toLower();

    // (PowerShell 策略探测的白名单已上移到函数开头,见那里的说明。)
    const QString targetLower = e.target.toLower();

    const bool inHighSuspiciousDir = anyContains(highSuspiciousDirs(), pathLower);
    const bool inMediumSuspiciousDir = anyContains(mediumSuspiciousDirs(), pathLower);
    const bool inSuspiciousDir = inHighSuspiciousDir || inMediumSuspiciousDir;

    // 1) 无可信签名
    if (!e.actorSigned)
        Add(15, u("无可信数字签名"), false, EvidenceKind::Info);

    // 1b) 签名失配 —— 必须分成「真篡改」与「只是校验不过」两档。
    //
    // 【原实现是一处高频误报的源头】原先只看 signatureMismatch,一律 45 分【硬指标】,理由串
    // 写的是「疑似篡改或盗用证书」。但 signatureMismatch 的含义只是「内嵌了签名、本机验不过」,
    // 它把三件完全不同的事混成一个答案:
    //   ① 文件被改过(TRUST_E_BAD_DIGEST)—— 这才是恶意证据;
    //   ② 本机没有签发者的根证书(企业内部 CA / 自签 / 部分厂商链);
    //   ③ 文件读不出来 —— 自保护的安全软件不让别人读自己的映像,验签必然失败。
    //
    // 实测:卡巴斯基的 avp.exe / avpsus.exe 落在 ③,两天里产生 7434 次询问(占全部询问的
    // 绝大多数),而那两个文件一个字节都没被改过。硬指标还有连带后果 —— 它让
    // isHealthySigned / isCleanSigned 直接失效,并让静默模式把 >=50 分升级为拦截。
    //
    // 现在:① 照旧 45 分硬指标;②③ 只记 10 分软信号,并在理由里如实说明「没验过,不等于被改过」。
    // 检出不丢:真正的篡改样本摘要必然不符,走的仍是 ① 那一支;盗用证书另有 certRevoked /
    // isAbusedSigner / signedAfterCertExpiry 三条专门判据(各 45~60 分硬)。
    if (e.signatureTampered) {
        Add(45, u("数字签名摘要不符:文件在签名之后被改过(篡改/白加黑,T1553.002)"), true);
    } else if (e.signatureMismatch) {
        Add(10, u("内嵌了数字签名但本机校验不过(根证书未导入 / 证书过期 / 文件被独占读不出来;"
                  "摘要并未不符,按软信号计,需互证)"),
            false, EvidenceKind::Info);
    }

    // 1b-1) 侧载模块篡改(「白加黑」):主体签名健康,但它目录里有模块【签名后被改过】。
    //
    // 按硬指标计,而且分值与主体自身失配同级 —— 这不是软信号:一个模块内嵌了厂商签名却
    // 校验不过,只有两种可能,要么文件损坏,要么被人改了代码;放在一个签名壳旁边、又被那个
    // 壳加载,就是「白加黑」的完成态。这也是唯一能穿透「白壳签名健康 -> 第 9 步直接放行」
    // 的判据(见 SecurityEvent::tamperedModulePath 的说明:漏检现场每次风险分只有 5)。
    if (!e.tamperedModulePath.isEmpty())
        Add(50, u("同目录模块签名后被篡改(签名壳侧载恶意模块,T1574.002):") +
                e.tamperedModulePath, true);

    // 1b-1' 白加黑侧载(未签名模块形态)。这是银狐 2026 年的主流落法:签名壳旁边放一个
    // 【完全没有签名】的系统同名 DLL(powrprof / wsc / version …),上面那条要求「内嵌签名
    // 校验不过」,对它一条都不命中(详见 SecurityEvent::sideloadedUnsignedModulePath)。
    //
    // 按硬指标计,但分值 45 —— 低于 HighRisk(80),所以单这一条的结论是【询问】而不是拦截。
    // 刻意如此:对签名主体判 Block 会走 blacklistExec 把映像钉进内核禁运名单(只加不减、
    // 加白也解不开),一次误判就是「这个正规程序永久起不来」。互证已经把绿色软件挡在外面,
    // 但还不足以担保到可以永久钉死的程度,所以把最终处置交给用户。
    // 硬指标本身已经足够:它会让流水线第 9 步的「签名健康直接放行」失效(isHealthySigned
    // 开头就查 hasThreatIndicator),Worker 侧也为它单列了一条不降级(见 onEvent)。
    if (!e.sideloadedUnsignedModulePath.isEmpty()) {
        const QString why = e.sideloadedUnsignedModuleWhy.isEmpty()
                                ? QString()
                                : (u("(") + e.sideloadedUnsignedModuleWhy + u(")"));
        Add(45, u("签名程序同目录存在未签名的系统同名模块,疑似白加黑侧载(T1574.001/002)") +
                why + u(":") + e.sideloadedUnsignedModulePath, true);
    }

    // 1b-2) 吊销 / 过期后签名
    if (e.certRevoked)
        Add(60, u("签名证书已被吊销(疑似盗用证书)"), true);
    if (e.signedAfterCertExpiry)
        Add(45, u("使用过期证书签名(疑似盗用旧证书)"), true);

    // 1b-2') 签名者在【被盗用证书】名单内。
    //
    // 与上面 certRevoked 说的是同一件事(这张证书不该再被信任),区别只在消息来源:那条等
    // CA 吊销 + CRL 下发到本机,这条来自本地/情报侧下发的名单。本机默认只读缓存 CRL
    // (OnlineCertRevocationCheck=false),所以从「私钥被偷」到「certRevoked 变真」之间有一段
    // 很长的空窗期,而银狐这类团伙的投递恰好都发生在这段窗口里。同分值(60)、同样按硬指标计。
    {
        const TrustDecision abused = TrustPolicy::isAbusedSigner(e);
        if (abused.ok)
            Add(60, abused.reason, true);
    }

    // 1b-2'') 证书【已过期】但签名仍然有效(签名时带了时间戳)。
    //
    // 单独出现时【绝大多数是正常的老软件】,所以这里 0 分、只记一条 Info:按本项目原则,软
    // 信号不单独定罪,更不该让一个「证书到期」把正常程序推去弹窗。真正的收紧在
    // TrustPolicy::isHealthySigned 里,且要求「已过期 + 本机首见 + 不在标准安装目录」三者互证
    // 才取消快速放行(仍不等于拦截)。这条记录的作用是让证据链如实显示证书状态 —— 排查盗用
    // 旧证书时,「签名有效」和「签名有效但证书早过期了」是两个完全不同的结论。
    if (e.actorSigned && e.certNotAfterUtc.has_value() && *e.certNotAfterUtc < nowUtc()) {
        Add(0, u("签名证书已于 ") + e.certNotAfterUtc->toString(Qt::ISODate) +
                u(" 过期(签名靠时间戳仍有效;留意是否为盗用旧证书)"),
            false, EvidenceKind::Info);
    }

    // 1b-3) 首见 + 新证书
    if (e.actorSigned && e.isFirstSeen) {
        Add(15, u("带签名但本机首次出现(低流行度)"), false, EvidenceKind::Info);
        if (e.certNotAfterUtc.has_value()) {
            const qint64 secs = nowUtc().secsTo(*e.certNotAfterUtc);
            if (secs > 0 && secs <= static_cast<qint64>(186) * 24 * 3600)
                Add(15, u("签名证书较新(疑似空壳公司新证书)"));
        }
    }

    // 1c) 文件膨胀
    //
    // 「未签名 + 体积超大」原先无条件置硬指标(65 分),单这一条就够 Block 线。但 Electron /
    // Tauri / PyInstaller 打包的正常应用天生就是 150~200MB —— 实测 35 次误拦(占全部拦截 43%)
    // 全部出自这里:Clash for Windows 150MB、kiro-account-manager 171MB,两者都是 Electron。
    //
    // 上一轮的修法是「只在投递型可写目录(Temp / Downloads / Desktop / AppData / ProgramData /
    // Public)里才算硬指标」,理由是安装目录里的大文件必然是安装器放进去的。那半步不够。
    //
    // 【本轮:体积永远不单独定罪】那个区分不成立 ——
    // 用户下载的安装包本来就落在 Downloads / Desktop / Temp。而「未签名」「体积大」「在可写目录」
    // 三项【全是软信号】,凑在一起依然没有任何一项说得出「它干了什么坏事」。硬指标的代价却极重:
    //   15(未签名) + 25(可疑目录运行) + 65(体积) = 105 -> 封顶 100 -> 管线第 10 步直接 Block,
    //   随后 blacklistExec 钉进内核禁运名单(只加不减) + 跨重启拒绝执行 ACE + 隔离载荷。
    // 实测:C:\Users\1\Downloads\决战千年260944.exe(78MB 的自解压游戏安装包)被判 100 分拦截、
    // 搬进隔离区、并留下跨重启的拒绝执行 ACE;222MB 的 NSIS 音乐安装包同样如此 —— 两者的证据
    // 链里一条行为证据都没有,全是「未签名 / 大 / 在桌面」。
    //
    // 现在一律软信号。检出不丢:膨胀只是规避扫描的包装,载荷要起作用总得做点什么(注入 /
    // 持久化 / 关杀软 / 侧载 / C2 外联 / 落地可执行体),这些各自都有硬判据;另有哈希信誉、
    // 云扫描、兜底扫描三条与体积无关的确认路径(lclcache.exe 21/75 就是这么逮住的)。
    constexpr qint64 kBloatThreshold = 60LL * 1024 * 1024;
    constexpr qint64 kBloatThresholdHi = 90LL * 1024 * 1024;
    if (e.actorFileSize >= kBloatThresholdHi && !e.actorSigned) {
        Add(65, u("超大未签名可执行文件(") + QString::number(e.actorFileSize / (1024 * 1024)) +
                u("MB,疑似文件膨胀规避扫描;体积不是行为证据,按软信号计,需互证)"),
            false);
    } else if (e.actorFileSize >= kBloatThreshold && !e.actorSigned) {
        Add(30, u("异常大的可执行文件(") + QString::number(e.actorFileSize / (1024 * 1024)) +
                u("MB,疑似文件膨胀;按软信号计,需互证)"),
            false);
    }

    // 2) 可疑目录运行(仅未签名显著加分)
    if (inSuspiciousDir) {
        if (!e.actorSigned) Add(25, u("未签名程序从可疑目录运行"));
        else Add(5, u("已签名程序从可疑目录运行"), false, EvidenceKind::Info);
    }

    // 2b) Windows 非标准子目录
    if (isNonStandardWindowsSubdir(pathLower)) {
        Add(e.actorSigned ? 12 : 30, u("可执行体位于 Windows 非标准子目录(疑似伪装系统组件,T1036)"));
    }

    // 3) 异常父子链
    const bool parentIsOfficeOrBrowser = officeAndBrowsers().contains(parentName);
    const bool actorIsLolBin = lolBins().contains(actorName);
    if (parentIsOfficeOrBrowser && actorIsLolBin) {
        Add(45, u("异常进程链:") + parentName + u(" 派生 ") + actorName + u("(疑似宏病毒/钓鱼)"), true);
    }

    // 3b) MSI 自定义动作拉起脚本宿主(银狐伪装安装包投递的必经一步)。
    //
    // 银狐把载荷塞进 MSI 的 custom action:msiexec 起来后由它拉起 VBScript / PowerShell / cmd
    // 去解包并跑下一阶段(伪装 Telegram 中文语言包那条链就是 MSI custom action -> VBScript ->
    // zpaqfranz 解 ZPAQ -> PowerShell 做 XOR 解密)。
    //
    // 【只给软信号,刻意不置硬指标】正常 MSI 也会用脚本型 custom action(装驱动前停服务、
    // 写配置、注册组件),数量不多但确实存在。置硬指标等于「装这类软件就弹窗甚至被拦」。
    // 作为软信号它与未签名 / 可疑目录 / 命令行混淆 / 首见等信号叠加,链路真恶意时自然够分。
    //
    // 【为什么不写成内置规则】规则命中即短路启发式(RuleEngine 步骤 6 直接 return),
    // 一条宽 Ask 规则会把 `msiexec -> powershell -enc <base64>` 这种高危事件降级成询问。
    // 详见 Rules07_Injection.cpp 段 7.5b 的说明。
    if (parentName == QLatin1String("msiexec.exe") && actorIsLolBin) {
        Add(30, u("MSI 自定义动作拉起脚本宿主 ") + actorName +
                u("(伪装安装包投递的常见形态,T1218.007)"));
    }

    // 3c) 系统宿主进程的父进程不对(注入落点:进程镂空 / 线程上下文劫持)。
    //
    // 银狐最后一跳就是这个形态:loader 自己起一个【全新的 svchost.exe】,再把 shellcode 用
    // 线程上下文劫持塞进去,ValleyRAT 于是跑在一个「微软签名 + System32」的进程里。
    // 上面 systemProcessDirs / 伪装检测只管「svchost 是不是从错误的目录跑起来的」;这一条管
    // 「它在正确的位置,但【不是 services.exe 生的】」—— 两者互补,原先没有任何判据覆盖后者。
    //
    // 【为什么必须叠加「父进程可疑」才置硬指标】svchost.exe 不在 ProcessInspector::criticalNames()
    // 里,也就是说它【可以被结束】。而静默模式会把「硬指标 + 风险 >= 50」直接升级为拦截并结束
    // 进程树 —— 只凭「父进程不是 services.exe」就置硬指标,一次误判就可能结束一个正常的服务宿主
    // (Schedule / DcomLaunch 那几个组),把机器搞得半残。所以硬指标要求父进程【自己就已经可疑】:
    // 落在投递目录,或者是脚本宿主 / LOLBin。「未签名程序在 ProgramData 里直接起 svchost」没有任何
    // 正常解释,而正常的 services.exe -> svchost 与 svchost -> dllhost 一条都不会命中。
    // 父进程不可疑时只留 20 分软信号,不定罪(留痕即可,靠别的指标互证)。
    //
    // 只在【进程创建】这一刻判:那时父子关系是权威的。其它事件类型的 parentPath 是按 PID 事后
    // 反查的,PID 复用会让它指向错误的进程(本项目没有进程退出事件,见 ProcessChainTracker 的说明)。
    if (e.type == EventType::ProcessCreate && !parentName.isEmpty()) {
        // sihost.exe(Shell Infrastructure Host)正常由 svchost.exe 拉起(UserManager 那一组),
        // 与 dllhost / taskhostw 同一形态。银狐 2026 年的另一条链把 sRDI 载荷注进它
        //(见 docs/yinhu-threat-intel-2026.md [7]),故按同一判据收进来。
        static const QHash<QString, QString> kExpectedParent = {
            { QStringLiteral("svchost.exe"),   QStringLiteral("services.exe") },
            { QStringLiteral("dllhost.exe"),   QStringLiteral("svchost.exe")  },
            { QStringLiteral("taskhostw.exe"), QStringLiteral("svchost.exe")  },
            { QStringLiteral("sihost.exe"),    QStringLiteral("svchost.exe")  },
        };
        const auto expect = kExpectedParent.constFind(actorName);
        if (expect != kExpectedParent.constEnd()
            && isInSystemDirFor(actorName, pathLower)   // 它确实是系统目录里那一份(否则归伪装检测)
            && parentName.compare(expect.value(), Qt::CaseInsensitive) != 0) {
            const QString parentLower = e.parentPath.toLower();
            const bool parentSuspicious =
                isSuspiciousDropDir(e.parentPath) || lolBins().contains(parentName)
                || anyContains(highSuspiciousDirs(), parentLower);
            if (parentSuspicious) {
                Add(45, u("系统宿主进程 ") + actorName + u(" 由可疑父进程 ") + parentName +
                        u(" 直接拉起(应为 ") + expect.value() +
                        u(";疑似进程镂空 / 线程上下文劫持的注入落点,T1055.012)"), true);
            } else {
                Add(20, u("系统宿主进程 ") + actorName + u(" 的父进程是 ") + parentName +
                        u("(通常应为 ") + expect.value() + u(")"), false);
            }
        }
    }

    // 4) 命令行高危特征(硬/软由 Sig.hard 决定;弱特征仅加分,靠互证升格)
    if (!cmd.isEmpty()) {
        for (const Sig& sig : commandLineSignals())
            if (cmd.contains(QLatin1String(sig.token)))
                Add(sig.score, u(sig.reason), sig.hard);

        // 合取判据:「转储工具/动作」+「目标点名 lsass」同时出现 —— 这才是凭据转储,而不是崩溃上报。
        // 上面的 Sig 表是扁平的单 token 匹配,表达不了这种组合,故在此单列一条。
        //
        // 只用 minidump / procdump / nanodump / dumpert 这几个【长且无歧义】的词。
        // 刻意【不用 "-ma"】(procdump 的全内存转储开关):它只有三个字符,裸子串会撞上
        // --max-time / --machine 之类的正常参数 —— 这正是本轮在 RemoteControlAnalyzer 修掉的
        // 那类「短 token 裸匹配」错误,不该在这里重新引入一个。按名字转储 lsass 的形态由
        // procdump 这个词本身覆盖。
        //
        // 注意本条【不是】comsvcs 手法的主要判据:`rundll32 comsvcs.dll, MiniDump <pid> out.dmp full`
        // 传的是 PID 而非进程名,命令行里根本不会出现 "lsass"。那条路由上一行的 comsvcs.dll
        //(40 分硬)以及 CredentialAccessAnalyzer 的 `comsvcs.dll && minidump`(55 分硬)负责。
        // 本条补的是 `procdump -ma lsass.exe` 这种按名字点名的形态。
        const bool namesLsass = cmd.contains(QLatin1String("lsass"));
        const bool dumpVerb = cmd.contains(QLatin1String("minidump")) ||
                              cmd.contains(QLatin1String("procdump")) ||
                              cmd.contains(QLatin1String("nanodump")) ||
                              cmd.contains(QLatin1String("dumpert"));
        if (namesLsass && dumpVerb)
            Add(45, u("对 LSASS 做内存转储(凭据窃取,T1003.001)"), true);
    }

    // 4b) LOLBin 滥用
    {
        const ScoreResult lol = LolbinAnalyzer::analyze(e.actorPath, e.commandLine);
        if (lol.score > 0) {
            score += lol.score;
            bool first = true;
            for (const QString& r : lol.reasons) {
                e.addEvidence(QStringLiteral("LolbinAnalyzer"),
                    lol.hardSignal ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                    r, first ? lol.score : 0);
                first = false;
            }
            if (lol.hardSignal) e.hasThreatIndicator = true;
        }
    }

    // 4c) 凭据访问
    {
        const ScoreResult ca = CredentialAccessAnalyzer::analyze(e);
        if (ca.score > 0) {
            score += ca.score;
            bool first = true;
            for (const QString& r : ca.reasons) {
                e.addEvidence(QStringLiteral("CredentialAccessAnalyzer"),
                    ca.hardSignal ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                    r, first ? ca.score : 0);
                first = false;
            }
            if (ca.hardSignal) e.hasThreatIndicator = true;
        }
    }

    // 4d) 防御规避 / 关杀软
    {
        const ScoreResult de = DefenseEvasionAnalyzer::analyze(e);
        if (de.score > 0) {
            score += de.score;
            bool first = true;
            for (const QString& r : de.reasons) {
                e.addEvidence(QStringLiteral("DefenseEvasionAnalyzer"),
                    de.hardSignal ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                    r, first ? de.score : 0);
                first = false;
            }
            if (de.hardSignal) e.hasThreatIndicator = true;
        }
    }

    // 4e) 远程控制 / 群发滥用
    {
        const ScoreResult rc = RemoteControlAnalyzer::analyze(e);
        if (rc.score > 0) {
            score += rc.score;
            bool first = true;
            for (const QString& r : rc.reasons) {
                e.addEvidence(QStringLiteral("RemoteControlAnalyzer"),
                    rc.hardSignal ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                    r, first ? rc.score : 0);
                first = false;
            }
            if (rc.hardSignal) e.hasThreatIndicator = true;
        }
    }

    // 5) 进程伪装:系统进程名出现在合法目录之外(需完整路径)
    const bool hasFullPath = pathLower.contains(QLatin1Char('\\')) || pathLower.contains(QLatin1Char('/'));
    if (isSystemProcessName(actorName) && hasFullPath && !isInSystemDirFor(actorName, pathLower)) {
        Add(40, u("疑似进程伪装:") + actorName + u(" 不在合法目录(T1036.005)"), true);
    }

    // 5b) 形近仿冒系统进程名(typosquatting)
    if (!isSystemProcessName(actorName)) {
        const QString impersonated = findImpersonatedSystemName(actorName);
        if (!impersonated.isEmpty()) {
            Add(45, u("疑似仿冒系统进程名:") + actorName + u(" 形近 ") + impersonated +
                    u("(典型伪装手法,T1036.005)"), true);
        }
    }

    // 6) 双重扩展名
    if (hasDoubleExtension(actorName))
        Add(30, u("可疑双重扩展名(伪装文档,T1036.007)"), true);

    // 6b) NTFS 备用数据流执行
    if (isAlternateDataStreamPath(e.actorPath))
        Add(40, u("从 NTFS 备用数据流(ADS)执行(隐藏载荷,T1564.004)"), true);

    // 6c) 进程注入 / DLL 侧载
    {
        const ScoreResult inj = InjectionAnalyzer::analyze(e);
        if (inj.score > 0) {
            score += inj.score;
            bool first = true;
            for (const QString& r : inj.reasons) {
                e.addEvidence(QStringLiteral("InjectionAnalyzer"),
                    inj.hardSignal ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                    r, first ? inj.score : 0);
                first = false;
            }
            if (inj.hardSignal) e.hasThreatIndicator = true;
        }
    }

    // 7) 命令行混淆
    if (!cmd.isEmpty()) {
        const ScoreResult obf = CommandObfuscationAnalyzer::analyze(e.commandLine);
        if (obf.score > 0) {
            score += obf.score;
            // 硬 / 软由分析器自己给(与 LolbinAnalyzer / CredentialAccessAnalyzer 等一致)。
            // 【别改回「obf.score >= 30」】:那等于让香农熵 + Base64 长串这两个纯统计量单独
            // 定罪,实测把 Amazon 签名的 Electron 应用永久钉进内核禁止执行名单 ——
            // 原因与代价见 CommandObfuscationAnalyzer::analyze 末尾 hardSignal 处的说明。
            bool first = true;
            for (const QString& r : obf.reasons) {
                e.addEvidence(QStringLiteral("CommandObfuscationAnalyzer"),
                    obf.hardSignal ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                    r, first ? obf.score : 0);
                first = false;
            }
            if (obf.hardSignal) e.hasThreatIndicator = true;
        }
    }

    // 7b) 脚本内容静态分析
    if (!e.commandLine.isEmpty()) {
        const ScriptAnalyzer::Extracted ex = ScriptAnalyzer::extractScriptFromCommandLine(e.commandLine);
        if (ex.content.has_value() && ex.type != ScriptType::Unknown) {
            const ScoreResult sc = ScriptAnalyzer::analyzeScript(*ex.content, ex.type);
            if (sc.score > 0) {
                score += sc.score;
                const bool scriptHard = sc.score >= 60;
                bool first = true;
                for (const QString& r : sc.reasons) {
                    e.addEvidence(QStringLiteral("ScriptAnalyzer"),
                        scriptHard ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                        r, first ? sc.score : 0);
                    first = false;
                }
                if (scriptHard) e.hasThreatIndicator = true;
            }
        }
    }

    // 7c) 脚本【文件正文】判据
    //
    // 与 7b 的区别:7b 只能看到命令行里抠出来的脚本文本(实际上只有 -EncodedCommand
    // 和 mshta 内联这两种拿得到),而脚本宿主的常态是「命令行里只有一个文件路径」——
    // 那条路径下的正文由 Worker::scanScriptFileBody 在富化阶段读入并评过分,结论在
    // e.scriptFile* 里。这里只负责把它并进本次评分与证据链。
    //
    // 硬 / 软由分析器给,不在这里二次判断:它的行为级判据在 4069 个良性脚本语料上零命中,
    // 统计类判据则一律要互证才升硬(取舍与实测数字见 ScriptAnalyzer::analyzeScriptFile)。
    if (e.scriptFileScore > 0 || e.scriptFileHardIndicator) {
        score += e.scriptFileScore;
        bool first = true;
        for (const QString& r : e.scriptFileReasons) {
            e.addEvidence(QStringLiteral("ScriptFileAnalyzer"),
                e.scriptFileHardIndicator ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                r, first ? e.scriptFileScore : 0);
            first = false;
        }
        if (e.scriptFileHardIndicator) e.hasThreatIndicator = true;
    }

    // 8) 杀伤链阶段分析
    if (!e.chainContext.isEmpty()) {
        const KillChainAnalyzer::Result chain = KillChainAnalyzer::analyze(e.chainContext);
        if (chain.score > 0) {
            score += chain.score;
            const bool maliciousChain = KillChainAnalyzer::hasMaliciousStage(chain.stages);
            const EvidenceKind chainKind = maliciousChain ? EvidenceKind::HardIndicator : EvidenceKind::Corroboration;
            bool first = true;
            for (const QString& r : chain.reasons) {
                e.addEvidence(QStringLiteral("KillChainAnalyzer"), chainKind, r, first ? chain.score : 0);
                first = false;
            }
            if (maliciousChain) e.hasThreatIndicator = true;
        }
    }

    // 9) 外部文件信誉(VT 缓存结果,不发起网络调用)
    if (e.reputation.has_value()) {
        const FileReputation& rep = *e.reputation;

        //
        // 情报结论是否【带实据】。只有带实据的结论才配当硬指标(可单独定罪)。
        //
        // 两类源的实据形式不同,都要认:
        //   · 多引擎源(VT / MetaDefender):实据是 malicious/totalEngines 的引擎计数;
        //   · 命中型源(MalwareBazaar / ThreatFox / 微步):没有引擎计数,实据是 threatLabel
        //     那个family/威胁名(onReputationMalicious 里也是这么区分表述的)。
        //
        // 实测事故:微步(Proxy:ThreatBook)返回过
        //     {"verdict":2(可疑),"malicious":0,"totalEngines":0,"threatLabel":""}
        // 也就是【什么实据都没有】的一条「可疑」。原实现照样把它登记成 HardIndicator 并置
        // hasThreatIndicator,理由串直接印成「威胁情报:0/0 个引擎判为可疑」—— 一句自我否定的话
        // 却拥有定罪效力。后果:uniclash-setup 安装包风险分被顶到 70,静默模式据此升级为 Block,
        // 用户看到的就是「安装包一运行就消失」。
        //
        // 零实据的结论现在只作软信号:分数照加(它确实是一点弱线索),但必须与真正的硬指标
        // 互证才能升格 —— 与本项目「软信号绝不单独定罪」一致。理由串也不再谎称有引擎判过。
        //
        const bool hasEngineCounts = rep.totalEngines > 0 && rep.malicious > 0;
        const bool hasLabel = !rep.threatLabel.trimmed().isEmpty();
        const bool substantiated = hasEngineCounts || hasLabel;
        // 有引擎计数就按 "n/m 个引擎" 表述;否则按威胁名表述;两者都无则如实说明「无明细」。
        const QString detail = hasEngineCounts
            ? (QString::number(rep.malicious) + QStringLiteral("/") +
               QString::number(rep.totalEngines) + u(" 个引擎"))
            : (hasLabel ? rep.threatLabel.trimmed() : u("该源未给出引擎计数或威胁名"));
        const QString srcTag = rep.source.trimmed().isEmpty()
            ? u("威胁情报") : (u("威胁情报[") + rep.source.trimmed() + u("]"));

        switch (rep.verdict) {
            case ReputationVerdict::Malicious:
                score += 60;
                e.addEvidence(QStringLiteral("Reputation"),
                    substantiated ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                    srcTag + u(":判为恶意(") + detail + QStringLiteral(")") +
                    (substantiated ? QString() : u("〔无实据,按软信号计,需互证〕")), 60);
                if (substantiated) e.hasThreatIndicator = true;
                break;
            case ReputationVerdict::Suspicious:
                score += 30;
                e.addEvidence(QStringLiteral("Reputation"),
                    substantiated ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                    srcTag + u(":判为可疑(") + detail + QStringLiteral(")") +
                    (substantiated ? QString() : u("〔无实据,按软信号计,需互证〕")), 30);
                if (substantiated) e.hasThreatIndicator = true;
                break;
            case ReputationVerdict::Clean:
                if (!e.hasThreatIndicator && score > 0) {
                    score = qMax(0, score - 10);
                    e.addEvidence(QStringLiteral("Reputation"), EvidenceKind::Trust,
                        u("威胁情报:多引擎未检出(信誉良好)"), -10);
                }
                break;
            case ReputationVerdict::Unknown:
            default:
                break;
        }
    }

    e.riskScore = qMin(100, score);
}

bool ThreatDetector::isSuspiciousDropDir(const QString& path) {
    if (path.isEmpty()) return false;
    const QString pathLower = path.toLower();
    return anyContains(highSuspiciousDirs(), pathLower)
        || anyContains(mediumSuspiciousDirs(), pathLower)
        || isNonStandardWindowsSubdir(pathLower);
}

bool ThreatDetector::isSideloadProneModuleName(const QString& pathOrName) {
    //
    // 只收【系统 DLL 的名字】。判据是「正常应用不会在自己目录里放一个私有的同名模块」——
    // 这些都由 Windows 提供,应用直接从 System32 加载即可;把同名文件放到 exe 旁边的唯一
    // 效果就是让它先被找到(DLL 搜索顺序劫持 T1574.001/002)。
    //
    // 【刻意不收的】libcurl.dll / sqlite3.dll / zlib.dll / Qt*.dll / *.node 这类第三方库:
    // 应用自带它们是完全正常的,而且多数不签名 —— 收进来等于把绿色软件全判成侧载。
    // 同理不收 msvcp*.dll / vcruntime*.dll / ucrtbase.dll:VC++ 运行时本来就允许应用本地部署
    // (app-local deployment 是微软自己推荐的做法),它们是误报大户。
    //
    // powrprof / wsc 两个是银狐 2026 年实际用过的(伪装 Telegram 中文语言包那条链,
    // 侧载宿主是带字节跳动签名的 SodaMusicLauncher.exe)。
    //
    static const QSet<QString> kNames = {
        // 电源 / 系统信息 —— 银狐实际使用
        QStringLiteral("powrprof.dll"), QStringLiteral("wsc.dll"),
        QStringLiteral("wscapi.dll"),
        // 版本 / 多媒体 / 图形:侧载最经典的三个
        QStringLiteral("version.dll"), QStringLiteral("winmm.dll"),
        QStringLiteral("msimg32.dll"), QStringLiteral("dwmapi.dll"),
        QStringLiteral("uxtheme.dll"), QStringLiteral("dbghelp.dll"),
        QStringLiteral("dbgcore.dll"), QStringLiteral("textinputframework.dll"),
        // 加密 / 凭据 / 身份
        QStringLiteral("cryptsp.dll"), QStringLiteral("cryptbase.dll"),
        QStringLiteral("secur32.dll"), QStringLiteral("sspicli.dll"),
        QStringLiteral("bcrypt.dll"), QStringLiteral("ncrypt.dll"),
        QStringLiteral("wintrust.dll"),
        // 用户配置 / 环境
        QStringLiteral("profapi.dll"), QStringLiteral("userenv.dll"),
        QStringLiteral("dwrite.dll"), QStringLiteral("textshaping.dll"),
        // 网络 / 代理
        QStringLiteral("winhttp.dll"), QStringLiteral("wininet.dll"),
        QStringLiteral("iphlpapi.dll"), QStringLiteral("dnsapi.dll"),
        QStringLiteral("winsta.dll"), QStringLiteral("mswsock.dll"),
        // 外壳 / COM
        QStringLiteral("propsys.dll"), QStringLiteral("shcore.dll"),
        QStringLiteral("apphelp.dll"), QStringLiteral("dxgi.dll"),
        QStringLiteral("d3d9.dll"), QStringLiteral("oleacc.dll"),
        QStringLiteral("comctl32.dll"), QStringLiteral("riched20.dll"),
        // 输入法 / 辅助
        QStringLiteral("msctf.dll"), QStringLiteral("mfc42loc.dll"),
        QStringLiteral("srvcli.dll"), QStringLiteral("netapi32.dll"),
        QStringLiteral("logoncli.dll"), QStringLiteral("samcli.dll"),
    };
    QString name = pathOrName.trimmed();
    name.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const int slash = name.lastIndexOf(QLatin1Char('\\'));
    if (slash >= 0) name = name.mid(slash + 1);
    return kNames.contains(name.toLower());
}

} // namespace bulwark::engine
