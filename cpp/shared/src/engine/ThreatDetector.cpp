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
        { "vssadmin delete", 45, "删除卷影副本(勒索前置,T1490)" },
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
bool isAlternateDataStreamPath(const QString& path) {
    if (path.isEmpty()) return false;
    const int start = (path.size() > 1 && path.at(1) == QLatin1Char(':')) ? 2 : 0;
    return path.indexOf(QLatin1Char(':'), start) >= 0;
}

} // anonymous namespace

void ThreatDetector::analyze(SecurityEvent& e) {
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

    // 白名单:PowerShell 临时策略测试文件为正常系统行为,直接跳过。
    const QString targetLower = e.target.toLower();
    if (targetLower.contains(QLatin1String("__psscriptpolicytest")))
        return;

    const bool inHighSuspiciousDir = anyContains(highSuspiciousDirs(), pathLower);
    const bool inMediumSuspiciousDir = anyContains(mediumSuspiciousDirs(), pathLower);
    const bool inSuspiciousDir = inHighSuspiciousDir || inMediumSuspiciousDir;

    // 1) 无可信签名
    if (!e.actorSigned)
        Add(15, u("无可信数字签名"), false, EvidenceKind::Info);

    // 1b) 签名失配
    if (e.signatureMismatch)
        Add(45, u("数字签名校验失败(疑似篡改或盗用证书)"), true);

    // 1b-1) 侧载模块篡改(「白加黑」):主体签名健康,但它目录里有模块【签名后被改过】。
    //
    // 按硬指标计,而且分值与主体自身失配同级 —— 这不是软信号:一个模块内嵌了厂商签名却
    // 校验不过,只有两种可能,要么文件损坏,要么被人改了代码;放在一个签名壳旁边、又被那个
    // 壳加载,就是「白加黑」的完成态。这也是唯一能穿透「白壳签名健康 -> 第 9 步直接放行」
    // 的判据(见 SecurityEvent::tamperedModulePath 的说明:漏检现场每次风险分只有 5)。
    if (!e.tamperedModulePath.isEmpty())
        Add(50, u("同目录模块签名后被篡改(签名壳侧载恶意模块,T1574.002):") +
                e.tamperedModulePath, true);

    // 1b-2) 吊销 / 过期后签名
    if (e.certRevoked)
        Add(60, u("签名证书已被吊销(疑似盗用证书)"), true);
    if (e.signedAfterCertExpiry)
        Add(45, u("使用过期证书签名(疑似盗用旧证书)"), true);

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
    // 真正的「文件膨胀规避扫描」是把载荷填充到超过杀软扫描上限,而这类样本的落点特征很稳定:
    // 投递到用户可写目录(Temp / Downloads / AppData\Roaming / Public / ProgramData / Desktop)。
    // 反之位于 Program Files / AppData\Local\Programs 之类安装目录的大文件,是安装器(需要管理员
    // 或走标准安装流程)放进去的,几乎不可能是投递载荷。
    //
    // 故:仅当文件位于投递型可写目录时才算硬指标;否则保留分数但降为软信号,交由互证升格 ——
    // 与本项目「软信号绝不单独定罪」的既定原则一致。
    constexpr qint64 kBloatThreshold = 60LL * 1024 * 1024;
    constexpr qint64 kBloatThresholdHi = 90LL * 1024 * 1024;
    if (e.actorFileSize >= kBloatThresholdHi && !e.actorSigned) {
        Add(65, u("超大未签名可执行文件(") + QString::number(e.actorFileSize / (1024 * 1024)) +
                u("MB,几乎必为文件膨胀规避扫描)") +
                (inSuspiciousDir ? QString() : u("〔位于安装目录,按软信号计,需互证〕")),
            inSuspiciousDir);
    } else if (e.actorFileSize >= kBloatThreshold && !e.actorSigned) {
        Add(30, u("异常大的可执行文件(") + QString::number(e.actorFileSize / (1024 * 1024)) +
                u("MB,疑似文件膨胀)") +
                (inSuspiciousDir ? QString() : u("〔位于安装目录,按软信号计,需互证〕")),
            inSuspiciousDir);
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

} // namespace bulwark::engine
