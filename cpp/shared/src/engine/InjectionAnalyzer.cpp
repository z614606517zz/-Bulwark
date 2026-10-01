#include "bulwark/engine/InjectionAnalyzer.h"
#include <QSet>
#include <QStringList>

namespace bulwark::engine {
using detail::u;
using detail::fileNameLower;

namespace {

const QSet<QString>& credentialTargets() {
    static const QSet<QString> s = { "lsass.exe", "lsaiso.exe" };
    return s;
}
const QSet<QString>& criticalTargets() {
    static const QSet<QString> s = {
        "winlogon.exe", "csrss.exe", "services.exe", "wininit.exe", "smss.exe",
        "svchost.exe", "spoolsv.exe", "explorer.exe", "dwm.exe", "lsm.exe",
    };
    return s;
}
const QSet<QString>& sensitiveAppTargets() {
    static const QSet<QString> s = {
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe",
        "brave.exe", "outlook.exe", "thunderbird.exe", "360se.exe", "360chrome.exe",
    };
    return s;
}
const QSet<QString>& injectorLolbins() {
    static const QSet<QString> s = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "msbuild.exe",
    };
    return s;
}
const QStringList& highRiskDirs() {
    static const QStringList s = {
        "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\",
        "\\programdata\\", "\\$recycle.bin\\", "\\perflogs\\",
    };
    return s;
}
bool anyContains(const QStringList& needles, const QString& hay) {
    for (const QString& n : needles)
        if (hay.contains(n)) return true;
    return false;
}

// 同一个文件?只做大小写与分隔符归一,不碰短名/符号链接 —— 这里的用途是识别
// 「事件里的模块就是宿主自己的主映像」,而那两个字段来自同一次富化、写的是同一
// 个规范化路径,不需要更强的等价判断。
bool samePathCI(const QString& a, const QString& b) {
    if (a.isEmpty() || b.isEmpty()) return false;
    QString x = a; x.replace(QLatin1Char('/'), QLatin1Char('\\'));
    QString y = b; y.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return x.compare(y, Qt::CaseInsensitive) == 0;
}

//
// 注入发起方是否为「Windows 自身的系统组件」:签名健康 + 位于系统目录 + 不是 LOLBin/脚本宿主。
//
// 补的是一处实测误报:本分析器原来只豁免【自注入】(target == actorPath),`criticalTargets()`
// 里一命中就 +40 且置硬指标,【完全不看谁在注入】。于是 Windows 内部的正常线程创建被当成攻击:
//   · C:\Windows\System32\dwm.exe     -> csrss.exe   85 分被拦(12 次)
//   · C:\Windows\System32\svchost.exe -> csrss.exe   86 分被拦
// 两者都是 Microsoft 签名、位于 System32。桌面窗口管理器和服务宿主与 csrss 之间有大量正常的
// 跨进程线程交互(窗口/会话管理),把它算成 T1055 注入是判据缺了「注入方身份」这个前置条件。
//
// 判据刻意收得很紧,避免变成绕过口子:
//   * 必须签名健康(actorSigned 且未失配 / 未吊销 / 未过期后签名)—— 改名成 dwm.exe 丢在
//     Temp 里的样本不满足;
//   * 必须位于 System32 / SysWOW64 / WinSxS —— 这些目录普通账户写不进去;
//   * 【排除 LOLBin 与脚本宿主】—— powershell / rundll32 / mshta 也签名、也在 System32,
//     但它们做远程注入没有任何正当理由,那正是本分析器最该抓的形态,绝不能连带豁免。
// 三条同时成立时,才认为「这是系统自己在做自己的事」,不再单独定罪(分数照常累加,仍可被
// 其它硬指标互证升格)。
//
bool injectorIsTrustedOsComponent(const bulwark::SecurityEvent& e) {
    if (!e.actorSigned) return false;
    if (e.signatureMismatch || e.certRevoked || e.signedAfterCertExpiry) return false;

    const QString injector = fileNameLower(e.actorPath);
    if (injectorLolbins().contains(injector)) return false;

    QString p = e.actorPath.toLower();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return p.contains(QLatin1String("\\windows\\system32\\"))
        || p.contains(QLatin1String("\\windows\\syswow64\\"))
        || p.contains(QLatin1String("\\windows\\winsxs\\"));
}

ScoreResult analyzeRemoteThread(const bulwark::SecurityEvent& e) {
    ScoreResult r;
    if (e.target.isEmpty()) return r;
    // 自注入(目标==自身)是常见合法行为,不计分。
    if (e.target.compare(e.actorPath, Qt::CaseInsensitive) == 0) return r;

    const QString victim = fileNameLower(e.target);
    const QString injector = fileNameLower(e.actorPath);
    const QString injectorPathLower = e.actorPath.toLower();

    int score = 30; // 跨进程远程线程注入本身即值得关注
    bool hard = false;

    // 「系统组件之间的线程交互」与「攻击者注入系统进程」必须分开(见 injectorIsTrustedOsComponent)。
    const bool osComponent = injectorIsTrustedOsComponent(e);

    if (credentialTargets().contains(victim)) {
        // 凭据进程(lsass / lsaiso)【不】给系统组件豁免:代价太高,宁可让极少数正常交互走一次询问。
        score += 50; hard = true;
        r.reasons << (u("向凭据进程 ") + victim + u(" 注入远程线程(疑似凭据窃取,T1003.001 / T1055)"));
    } else if (criticalTargets().contains(victim)) {
        if (osComponent) {
            // 签名健康的系统目录组件(且非 LOLBin)与另一个系统进程之间的线程创建:
            // Windows 内部的窗口 / 会话 / 服务管理本来就这么工作(实测 dwm.exe、svchost.exe
            // 对 csrss.exe)。保留少量分数留痕、可被其它硬指标互证,但绝不单独定罪。
            score += 10;
            r.reasons << (u("系统组件 ") + injector + u(" 向系统进程 ") + victim +
                          u(" 创建线程(Windows 内部交互的常见形态,仅留痕)"));
        } else {
            score += 40; hard = true;
            r.reasons << (u("向关键系统进程 ") + victim + u(" 注入远程线程(无合法理由,T1055)"));
        }
    } else if (sensitiveAppTargets().contains(victim)) {
        score += 30;
        r.reasons << (u("向浏览器/邮件进程 ") + victim + u(" 注入远程线程(疑似信息窃取/会话劫持,T1055)"));
    } else {
        r.reasons << (u("跨进程远程线程注入 -> ") + victim + u("(进程镂空/APC/线程劫持的共同落点,T1055)"));
    }

    const bool injectorUnsigned = !e.actorSigned;
    const bool injectorIsLolbin = injectorLolbins().contains(injector);
    const bool injectorInHighRiskDir = anyContains(highRiskDirs(), injectorPathLower);

    if (injectorIsLolbin) {
        score += 20; hard = true;
        r.reasons << (u("注入发起方为脚本宿主/LOLBin(") + injector + u("),远程注入几乎必为恶意"));
    }
    if (injectorUnsigned) {
        score += 15; hard = true;
        r.reasons << u("注入发起方无可信签名");
    }
    if (injectorInHighRiskDir) {
        score += 10;
        r.reasons << u("注入发起方位于高危可写目录");
    }

    r.score = qMin(score, 100);
    r.hardSignal = hard;
    return r;
}

ScoreResult analyzeImageLoad(const bulwark::SecurityEvent& e) {
    ScoreResult r;
    const QString module = e.target;
    if (module.isEmpty()) return r;

    //
    // 【排除「进程加载自己的主映像」】—— 那不是侧载。
    //
    // 侧载说的是「宿主进程加载了另一个模块」。每个进程启动时都必然有一次「加载自己的
    // exe」的映像加载事件,原实现没有区分这两件事,于是任何从可写目录运行的未签名
    // 可执行体都会被这条判据判成侧载,而且它置了 hardSignal —— 40 分的硬指标足以让
    // 裁决流水线在第 4 步(ThreatDetector)就 Block,根本走不到第 7 步的显式规则。
    //
    // 实测后果:Inno Setup 做的安装包一个都装不上。它的 SetupLdr 会把真正的安装模块
    // 解压成 %TEMP%\is-XXXXXXXXXX.tmp\<名字>.tmp(未签名)再运行,那个进程刚起来就被
    // 判成侧载 -> 下发内核禁止加载 + 冻结全部线程(不自动解冻)+ 断子,一个窗口都不出现。
    // 用户看到的现象就是「双击安装包没反应」。本产品自己的安装包也在其中,也就是说
    // 原地升级同样装不上去。三次复现,audit 记录里 actorPath 与 target 是同一个路径。
    //
    // 这里的讽刺之处值得记下来:段 7.3 的规则【早就】为安装器做过修正(把 Temp 里加载
    // 未签名 DLL 降成 Ask,并专门把 *.tmp 从伪装扩展名的 Block 名单里剔掉,理由写的就是
    // "is-XXXX.tmp\setup.tmp 是安装器中间产物")。但启发式跑在规则之前,于是那番修正
    // 被这一条整个盖掉了 —— 规则层的收敛,挡不住判据层的过宽。
    //
    // 这条豁免不丢覆盖面:进程自己的映像已经在 ProcessCreate 那条路上被完整评估过
    // (未签名 / 可疑目录 / 本机首见 / 父子链 / 命令行 都在那里),ImageLoad 这一次只是
    // 同一个文件的重复出现,提供不了任何新证据。同文件里 analyzeRemoteThread 早就用
    // 同一个判据(target == actorPath)豁免了自注入,这里只是把漏掉的那一半补上。
    if (samePathCI(module, e.actorPath)) return r;

    //
    // 【这里原来写的是 e.actorSigned,并注释说「ImageLoad 事件里 actorSigned 表示被加载模块
    //   自身的签名」—— 那句话是错的,而且这个误解在 HEAD 里就存在。】
    //
    // 真实情况:驱动把被加载模块放进 TargetPath(ImageMonitor.c),actorPath 由
    // Worker::enrich 第 1 步按 PID 回填成【宿主进程】,第 4 步取的 actorSigned 因此是宿主的。
    // 于是本判据「从高危目录加载未签名模块」实际变成了「未签名的宿主从高危目录加载任意模块」:
    // 签名宿主侧载未签名 DLL(白加黑的典型形态)一条都报不出来。
    //
    // 现在读模块自己的签名(enrich 第 3.9 步富化)。带签名但校验不过的模块(被改过的
    // 合法 DLL)按未签名算 —— 对侧载判据而言,失配和没签名是同一回事。
    const bool moduleSigned = e.targetSigned && !e.targetSignatureMismatch;
    const QString moduleLower = module.toLower();
    const bool inHighRiskDir = anyContains(highRiskDirs(), moduleLower);

    if (!moduleSigned && inHighRiskDir) {
        r.reasons << (u("从高危可写目录加载未签名模块 ") + fileNameLower(module) +
                      u("(疑似 DLL 侧载/搜索顺序劫持,T1574.002)"));
        r.score = 40;
        r.hardSignal = true;
    }
    return r;
}

} // namespace

ScoreResult InjectionAnalyzer::analyze(const bulwark::SecurityEvent& e) {
    switch (e.type) {
        case EventType::RemoteThread: return analyzeRemoteThread(e);
        case EventType::ImageLoad:    return analyzeImageLoad(e);
        default:                      return ScoreResult{};
    }
}

} // namespace bulwark::engine
