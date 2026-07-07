#include "bulwark/engine/LolbinAnalyzer.h"
#include <QSet>

namespace bulwark::engine {
using detail::u;
using detail::fileNameLower;

namespace {
const QSet<QString>& knownLolbins() {
    static const QSet<QString> s = {
        "regsvr32.exe", "rundll32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
        "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "msiexec.exe",
        "wmic.exe", "mavinject.exe", "forfiles.exe", "pcalua.exe", "scriptrunner.exe",
    };
    return s;
}
} // namespace

ScoreResult LolbinAnalyzer::analyze(const QString& actorPath, const QString& commandLine) {
    ScoreResult r;
    if (commandLine.isEmpty()) return r;

    const QString name = fileNameLower(actorPath);
    if (name.isEmpty() || !knownLolbins().contains(name)) return r;

    const QString cmd = commandLine.toLower();
    auto C = [&](const char* t) { return cmd.contains(QLatin1String(t)); };
    const bool hasRemote = C("http://") || C("https://") || C("ftp://") || C("\\\\");

    auto hit = [&](int delta, const QString& reason, bool isHard = false) {
        r.score += delta;
        r.reasons << reason;
        if (isHard) r.hardSignal = true;
    };

    if (name == QLatin1String("regsvr32.exe")) {
        if (C("scrobj.dll") || C("/i:")) {
            if (hasRemote && (C("scrobj") || C("/i:http")))
                hit(55, u("regsvr32 远程加载 scriptlet(Squiblydoo 无文件执行,T1218.010)"), true);
            else if (C("/i:") && C("scrobj"))
                hit(35, u("regsvr32 经 scrobj.dll 执行 scriptlet(T1218.010)"), true);
        }
        if ((C("/s ") || C("/u")) && hasRemote)
            hit(30, u("regsvr32 静默注册远程组件(T1218.010)"), true);
    } else if (name == QLatin1String("rundll32.exe")) {
        if (C("javascript:") || C("vbscript:") || C("mshtml") || C("runhtmlapplication"))
            hit(50, u("rundll32 执行内联脚本(mshtml/RunHTMLApplication,T1218.011)"), true);
        else if (C("comsvcs.dll") && C("minidump"))
            hit(55, u("rundll32 经 comsvcs 转储 LSASS 内存(凭据窃取,T1003.001)"), true);
        else if (C("url.dll") && (C("openurl") || C("fileprotocolhandler")))
            hit(30, u("rundll32 经 url.dll 打开远程资源(T1218.011)"), hasRemote);
        else if (C("shell32.dll") && C("control_rundll") && hasRemote)
            hit(28, u("rundll32 经 shell32 加载远程 .cpl(T1218.011)"), true);
        else if (hasRemote)
            hit(20, u("rundll32 命令行含远程地址(疑似代理执行,T1218.011)"));
    } else if (name == QLatin1String("mshta.exe")) {
        if (hasRemote)
            hit(50, u("mshta 执行远程 HTA/脚本(T1218.005)"), true);
        else if (C("javascript:") || C("vbscript:"))
            hit(45, u("mshta 执行内联脚本(T1218.005)"), true);
        else if (C(".hta"))
            hit(18, u("mshta 运行 HTA 文件(T1218.005)"));
    } else if (name == QLatin1String("certutil.exe")) {
        if ((C("-urlcache") || C("-verifyctl") || C("-f ")) && hasRemote)
            hit(50, u("certutil 远程下载文件(伪装证书工具,T1105/T1140)"), true);
        else if (C("-decode") || C("-decodehex"))
            hit(30, u("certutil 解码载荷(还原隐藏可执行体,T1140)"), true);
        else if (C("-encode"))
            hit(15, u("certutil 编码数据(可能用于外传/隐藏)"));
    } else if (name == QLatin1String("bitsadmin.exe")) {
        if (C("/transfer") && hasRemote)
            hit(45, u("bitsadmin 后台下载文件(T1197/T1105)"), true);
        else if (C("/addfile") || C("/setnotifycmdline"))
            hit(30, u("bitsadmin 配置传输任务/回调命令(T1197)"), C("/setnotifycmdline"));
    } else if (name == QLatin1String("msbuild.exe")) {
        if (C(".csproj") || C(".xml") || C(".targets") || C(".proj") || hasRemote)
            hit(40, u("msbuild 执行内联任务工程(无文件 C# 执行,T1127.001)"), true);
    } else if (name == QLatin1String("installutil.exe")) {
        if (C("/logfile=") || C("/u") || C("/logtoconsole=false"))
            hit(38, u("installutil 经卸载钩子执行程序集(T1218.004)"), true);
    } else if (name == QLatin1String("regasm.exe") || name == QLatin1String("regsvcs.exe")) {
        if (C("/u") || C(".dll"))
            hit(35, name + u(" 注册/卸载钩子执行程序集(T1218.009)"), true);
    } else if (name == QLatin1String("msiexec.exe")) {
        if (hasRemote && (C("/i") || C("/package") || C("/q")))
            hit(42, u("msiexec 安装远程 MSI 包(T1218.007)"), true);
    } else if (name == QLatin1String("wmic.exe")) {
        if (C("process") && C("call") && C("create"))
            hit(35, u("wmic 创建进程(代理执行,T1047)"), true);
        else if (C("/node:"))
            hit(40, u("wmic 远程节点执行(横向移动,T1047)"), true);
        else if (C("os get") || C("/format:http"))
            hit(25, u("wmic 经远程 XSL 执行(T1220)"), hasRemote);
    } else if (name == QLatin1String("mavinject.exe")) {
        if (C("/injectrunning"))
            hit(48, u("mavinject 向运行中进程注入 DLL(T1218.013)"), true);
    } else if (name == QLatin1String("forfiles.exe")) {
        if (C("/c") && (C("cmd") || C("powershell")))
            hit(28, u("forfiles 代理执行命令(T1202)"), true);
    } else if (name == QLatin1String("pcalua.exe")) {
        if (C("-a"))
            hit(28, u("pcalua(程序兼容助手)代理执行(T1202)"), true);
    } else if (name == QLatin1String("scriptrunner.exe")) {
        if (C("-appvscript"))
            hit(30, u("scriptrunner 代理执行(T1218)"), true);
    }

    r.score = qMin(r.score, 100);
    return r;
}

bool LolbinAnalyzer::isAbusedLolbin(const QString& actorPath, const QString& commandLine) {
    return analyze(actorPath, commandLine).hardSignal;
}

} // namespace bulwark::engine
