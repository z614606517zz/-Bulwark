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

    if (credentialTargets().contains(victim)) {
        score += 50; hard = true;
        r.reasons << (u("向凭据进程 ") + victim + u(" 注入远程线程(疑似凭据窃取,T1003.001 / T1055)"));
    } else if (criticalTargets().contains(victim)) {
        score += 40; hard = true;
        r.reasons << (u("向关键系统进程 ") + victim + u(" 注入远程线程(无合法理由,T1055)"));
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

    // ImageLoad 事件里 actorSigned 表示【被加载模块】自身的签名。
    const bool moduleSigned = e.actorSigned;
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
