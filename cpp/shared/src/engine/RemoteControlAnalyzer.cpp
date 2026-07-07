#include "bulwark/engine/RemoteControlAnalyzer.h"
#include <QSet>
#include <QStringList>

namespace bulwark::engine {

using detail::u;
using detail::fileNameLower; // = C# SafeName

namespace {

const QSet<QString>& remoteTools() {
    static const QSet<QString> s = {
        "anydesk.exe",
        "teamviewer.exe", "tv_w32.exe", "tv_x64.exe", "teamviewer_service.exe",
        "rustdesk.exe",
        "todesk.exe", "todesk_service.exe",
        "sunloginclient.exe", "oray_com.exe",
        "ultraviewer.exe", "ultraviewer_desktop.exe", "ultraviewer_service.exe",
        "aweray_remote.exe", "awesun.exe",
        "quickassist.exe",
        "netsupport.exe", "client32.exe", "pcicfgui.exe",
        "dwagent.exe", "dwagsvc.exe",
        "meshagent.exe",
        "screenconnect.clientservice.exe", "screenconnect.windowsclient.exe",
        "ateraagent.exe",
        "rutserv.exe", "rutview.exe",
        "radmin.exe", "rserver3.exe", "famtrayicon.exe",
        "ammyy_admin.exe", "aa_v3.exe",
        "winvnc.exe", "winvnc4.exe", "tvnserver.exe", "uvnc_service.exe",
        "vncserver.exe", "vncviewer.exe", "winvncsc.exe",
        "za_access.exe",
        "logmein.exe", "lmiguardiansvc.exe", "ramaint.exe", "g2mlauncher.exe",
        "splashtop.exe", "sragent.exe", "srserver.exe", "srmanager.exe",
        "agentmon.exe", "syncro.exe", "action1_agent.exe",
    };
    return s;
}

const QStringList& unattendedFlags() {
    static const QStringList s = {
        "--install", "--silent", "--start-with-win", "--set-password", "--get-id",
        "--service", "--unattended", "--password", "unattended", "assign_token",
        "assignment", "--connect", "--auto-connect", "/silent /install", "--cmd",
    };
    return s;
}

const QSet<QString>& imProcesses() {
    static const QSet<QString> s = {
        "wechat.exe", "weixin.exe", "wechatapp.exe", "wechatappex.exe",
        "wechatocr.exe", "wechatutility.exe", "wxwork.exe", "wxworkweb.exe",
        "qq.exe", "tim.exe", "qqexternal.exe",
    };
    return s;
}

const QStringList& groupControlModules() {
    static const QStringList s = {
        "wxhelper", "wxauto", "wxbot", "wxsender", "wxdump", "wxhook",
        "comwechatrobot", "cwechatrobot", "wechathelper", "wechatspy", "wechatsdk",
        "wechatrobot", "wechatpcapi", "wechatmanager", "wechatferry", "wcferry", "wcf.dll",
        "wcprobe", "ntchat", "vchat", "qqbot", "qqrobot", "qqhelper", "timhook",
        "weworkhook", "wework_api",
    };
    return s;
}

const QStringList& imAutomationTokens() {
    static const QStringList s = {
        "wcferry", "ntchat", "wechaty", "wxpy", "wxauto", "itchat", "pywechatspy",
        "wechatpcapi", "wxpusher", "pywxdump", "sharpwxdump", "wechatmsg", "qqbot",
    };
    return s;
}

const QStringList& suspiciousDirs() {
    static const QStringList s = {
        "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\",
        "\\programdata\\", "\\$recycle.bin\\", "\\perflogs\\",
        "\\downloads\\", "\\appdata\\roaming\\", "\\desktop\\",
    };
    return s;
}

const QSet<QString>& suspiciousParents() {
    static const QSet<QString> s = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    };
    return s;
}

bool anyContains(const QStringList& needles, const QString& hay) {
    for (const QString& n : needles)
        if (hay.contains(n)) return true;
    return false;
}

// ── 命令行:远控配置 / RDP / 反弹 shell / 群发 ──
void analyzeCommandLine(const SecurityEvent& e, ScoreResult& r) {
    const QString cmd = e.commandLine.toLower();
    if (cmd.isEmpty()) return;
    auto C = [&](const char* t) { return cmd.contains(QLatin1String(t)); };

    if (C("tscon") && C("/dest:")) {
        r.score += 55; r.hardSignal = true;
        r.reasons << u("RDP 会话劫持(tscon 接管已登录会话,T1563.002)");
    }

    if (C("fdenytsconnections") && (C("/d 0") || C("/d 0x0") || C(" 0 "))) {
        r.score += 40; r.hardSignal = true;
        r.reasons << u("开启远程桌面(fDenyTSConnections=0,T1021.001)");
    }

    if (C("mstsc") && C("/shadow")) {
        r.score += 25;
        r.reasons << u("发起 RDP 影子会话(监视/接管他人会话,T1563.002)");
    }

    if (C("net ") && C("user") && C("/add") && C("$")) {
        r.score += 50; r.hardSignal = true;
        r.reasons << u("创建隐藏后门账户(账户名以 $ 结尾,T1136.001)");
    } else if (C("localgroup") && C("administrators") && C("/add")) {
        r.score += 30;
        r.reasons << u("将账户加入本地管理员组(维持远控/提权,T1136.001)");
    }

    if (C("net.sockets.tcpclient") && (C("getstream") || C("iex") || C("invoke-expression"))) {
        r.score += 55; r.hardSignal = true;
        r.reasons << u("PowerShell 反弹 shell(TCPClient+流执行,远程控制)");
    }
    if ((C("ncat") || C("nc.exe") || C(" nc ")) &&
        (C("-e cmd") || C("-e /bin") || C("-e powershell") || C(" -e "))) {
        r.score += 50; r.hardSignal = true;
        r.reasons << u("netcat 反弹 shell(-e 执行命令解释器,远程控制)");
    }

    const bool mentionsRemoteTool =
        C("anydesk") || C("teamviewer") || C("rustdesk") || C("todesk") || C("sunlogin") ||
        C("ultraviewer") || C("netsupport") || C("radmin") || C("dwagent") ||
        C("meshagent") || C("screenconnect");
    if (mentionsRemoteTool && anyContains(unattendedFlags(), cmd)) {
        r.score += 45; r.hardSignal = true;
        r.reasons << u("远程控制工具被配置为无人值守/静默/设密码(疑似远控后门,T1219)");
    }

    if (anyContains(imAutomationTokens(), cmd)) {
        r.score += 30;
        r.reasons << u("调用微信/QQ 自动化群控框架(疑似批量群发,T1102)");
    }
}

// ── 远控/RMM 工具从可疑上下文启动 ──
void analyzeRemoteToolLaunch(const SecurityEvent& e, ScoreResult& r) {
    const QString actorName = fileNameLower(e.actorPath);
    if (!remoteTools().contains(actorName)) return;

    const QString pathLower = e.actorPath.toLower();
    const QString parentName = fileNameLower(e.parentPath);
    const bool inSuspiciousDir = anyContains(suspiciousDirs(), pathLower);
    const bool suspiciousParent = suspiciousParents().contains(parentName);
    const bool unsigned_ = !e.actorSigned;

    if (!inSuspiciousDir && !suspiciousParent && !unsigned_) return;

    int add = 30;
    QStringList ctx;
    if (inSuspiciousDir) { add += 25; ctx << u("从用户可写目录运行(疑似被投放而非正常安装)"); }
    if (suspiciousParent) { add += 25; ctx << (u("由 ") + parentName + u(" 拉起(脚本/Office 静默部署)")); }
    if (unsigned_) { add += 15; ctx << u("无可信签名(疑似仿冒/篡改)"); }

    if (inSuspiciousDir || suspiciousParent) r.hardSignal = true;

    r.score += add;
    r.reasons << (u("远程控制工具 ") + actorName + u(" 在可疑上下文启动(") +
                  ctx.join(QStringLiteral("; ")) + u(",疑似诈骗/远控滥用,T1219)"));
}

// ── 注入 IM 进程 ──
void analyzeImInjection(const SecurityEvent& e, ScoreResult& r) {
    const QString victim = fileNameLower(e.target);
    if (!imProcesses().contains(victim)) return;

    if (e.target.compare(e.actorPath, Qt::CaseInsensitive) == 0) return;
    const QString injector = fileNameLower(e.actorPath);
    if (imProcesses().contains(injector)) return;

    int add = 30;
    r.reasons << (u("向 IM 进程 ") + victim + u(" 注入远程线程(疑似群控挂载/盗号,群发前置,T1102 / T1055)"));

    if (!e.actorSigned) {
        add += 20; r.hardSignal = true;
        r.reasons << u("注入方无可信签名(疑似群控外挂宿主)");
    }
    r.score += add;
}

// ── 加载 IM 群控外挂模块 ──
void analyzeImModuleLoad(const SecurityEvent& e, ScoreResult& r) {
    const QString module = e.target.toLower();
    if (module.isEmpty()) return;

    const QString moduleName = fileNameLower(e.target);

    for (const QString& m : groupControlModules()) {
        if (moduleName.contains(m)) {
            r.score += 55; r.hardSignal = true;
            r.reasons << (u("加载已知微信/QQ 群控外挂模块 ") + moduleName + u("(自动群发/盗号/hook,T1102)"));
            return;
        }
    }

    const QString actorName = fileNameLower(e.actorPath);
    if (imProcesses().contains(actorName) && !e.actorSigned && anyContains(suspiciousDirs(), module)) {
        r.score += 35;
        r.reasons << (u("IM 进程 ") + actorName + u(" 从用户可写目录加载未签名模块(疑似群控白加黑侧载,T1574.002)"));
    }
}

} // namespace

ScoreResult RemoteControlAnalyzer::analyze(const SecurityEvent& e) {
    ScoreResult r;

    analyzeCommandLine(e, r);

    switch (e.type) {
        case EventType::ProcessCreate: analyzeRemoteToolLaunch(e, r); break;
        case EventType::RemoteThread:  analyzeImInjection(e, r);      break;
        case EventType::ImageLoad:     analyzeImModuleLoad(e, r);     break;
        default: break;
    }

    r.score = qMin(r.score, 100);
    return r;
}

} // namespace bulwark::engine
