//
// 段 6 · 执行与 LOLBin(T1059 / T1218 / T1204 / T1027 / T1105)
//
// 【与 LolbinAnalyzer 的分工】那个分析器按 actor 是哪个 LOLBin 分支处理,已覆盖 regsvr32 /
// rundll32 / mshta / certutil / bitsadmin / msbuild / installutil / regasm / msiexec / wmic /
// mavinject / forfiles / pcalua / scriptrunner。本段补三类它做不到的:
//   1) 内核 LOLBin 名单里但它没有分支的:cmstp / msdt / hh / netsh;
//   2) 【外壳那一层】—— 它只看 actor,所以 `cmd /c certutil -urlcache http://...` 这条事件里
//      actor 是 cmd.exe,它的 certutil 分支根本不会进;
//   3) 异常父子链的确定裁决 —— ThreatDetector 第 3 节只加分,而「Word 派生 PowerShell」这种
//      形态的置信度足够直接拦。
//
// 【父子链规则为什么敢给 Block】Office / PDF 阅读器派生脚本宿主没有正常形态:Office 自己的
// 更新与遥测组件(officeclicktorun.exe / officec2rclient.exe / msoia.exe)不在下面的 actor
// 名单里,所以不会被这批规则碰到。浏览器与压缩软件则给 Ask —— 前者有企业策略调 cmd 的正常
// 情形,后者是用户从压缩包里直接双击脚本(是风险,但确实由用户主动发起)。
//
#include "RuleDsl.h"
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine::rules {

using detail::u;

namespace {
// 父子链规则里当「被派生方」的脚本宿主。
//
// 这份名单是【被乘数】—— 下面 5 组父进程都要和它做交叉展开,多一项就多 20 条规则。故只收
// 「由文档类程序派生即可定性」的六个:certutil / regsvr32 由 Office 派生极罕见,而它们的
// 滥用用法 LolbinAnalyzer 已按 actor 全覆盖,不必在这里再乘一遍。
const char* kSpawnedHosts[] = {
    "*\\powershell.exe", "*\\pwsh.exe", "*\\cmd.exe",
    "*\\wscript.exe", "*\\mshta.exe", "*\\rundll32.exe",
};
} // namespace

void addExecutionRules(QVector<DefenseRule>& out) {
    Segment s(out, "执行与 LOLBin");

    // ------------------------------------------------------------------
    // 6.1 内核名单里但分析器没覆盖的 LOLBin
    // ------------------------------------------------------------------
    // 【Block 与 Ask 在这一段的分界】只有「这个命令行形态本身没有任何文档化的正当用法」才给
    // Block。像 cmstp 静默安装、forfiles 经 cmd 删旧文件、InstallUtil 卸载程序集、App-V 的
    // scriptrunner —— 这些都是微软文档里的正常用法,真实运维脚本里就长这样,给 Block 等于按
    // 「用法可疑」去结束正常进程。它们一律降为 Ask,而滥用形态(远程地址 / 内联脚本 / 注入)
    // 保持 Block。
    s.proc(Ask, "cmstp 静默安装 INF(正常 VPN 配置部署亦如此,但也是 UAC 绕过入口,T1218.003)")
        .actor("*\\cmstp.exe").cmd("*/ni*/s*");
    s.proc(Block, "cmstp 从远程地址加载 INF(T1218.003)").hard()
        .actor("*\\cmstp.exe").cmd("*http*");
    s.proc(Block, "msdt 经诊断包路径代理执行(IT_BrowseForFile,Follina,T1218)").hard()
        .actor("*\\msdt.exe").cmd("*it_browseforfile*");
    s.proc(Block, "msdt 经诊断包路径代理执行(IT_RebrowseForFile,T1218)").hard()
        .actor("*\\msdt.exe").cmd("*it_rebrowseforfile*");
    s.proc(Block, "msdt 跳过诊断向导直接运行(PCWDiagnostic /skip,T1218)").hard()
        .actor("*\\msdt.exe").cmd("*pcwdiagnostic*skip*");
    s.proc(Block, "hh 打开远程 CHM/脚本(T1218.001)").hard()
        .actor("*\\hh.exe").cmd("*http*");
    s.proc(Block, "hh 执行内联脚本(javascript:,T1218.001)").hard()
        .actor("*\\hh.exe").cmd("*javascript:*");
    s.proc(Ask, "hh 打开 CHM 文件(CHM 内可嵌脚本,T1218.001)")
        .actor("*\\hh.exe").cmd("*.chm*");
    // 模式必须是 "add helper"(相邻),不能是 `*add*helper*` —— 后者会被
    // `netsh advfirewall firewall add rule name=helper ...` 这种正常命令凑出来。
    // VPN 客户端确实会注册 netsh helper,故给 Ask 而不是 Block。
    s.proc(Ask, "注册 netsh 助手 DLL(每次 netsh 运行即加载,VPN 客户端亦用,T1546.007)")
        .actor("*\\netsh.exe").cmd("*add helper*");

    // ------------------------------------------------------------------
    // 6.2 分析器已判硬指标的形态:补确定裁决
    // ------------------------------------------------------------------
    s.proc(Block, "regsvr32 经 scrobj 加载远程 scriptlet(Squiblydoo,T1218.010)").hard()
        .actor("*\\regsvr32.exe").cmd("*scrobj*");
    s.proc(Block, "regsvr32 从远程地址注册组件(T1218.010)").hard()
        .actor("*\\regsvr32.exe").cmd("*/i:http*");
    s.proc(Block, "rundll32 执行内联脚本(javascript:,T1218.011)").hard()
        .actor("*\\rundll32.exe").cmd("*javascript:*");
    s.proc(Block, "rundll32 经 mshtml RunHTMLApplication 执行脚本(T1218.011)").hard()
        .actor("*\\rundll32.exe").cmd("*runhtmlapplication*");
    s.proc(Block, "rundll32 加载可写投递目录里的 DLL 导出函数(T1218.011)").hard()
        .actor("*\\rundll32.exe").cmd("*\\appdata\\local\\temp\\*.dll*");
    s.proc(Block, "mshta 执行远程 HTA(T1218.005)").hard()
        .actor("*\\mshta.exe").cmd("*http*");
    s.proc(Block, "mshta 执行内联 VBScript(T1218.005)").hard()
        .actor("*\\mshta.exe").cmd("*vbscript:*");
    s.proc(Block, "mshta 执行内联 JavaScript(T1218.005)").hard()
        .actor("*\\mshta.exe").cmd("*javascript:*");
    s.proc(Block, "mavinject 向运行中进程注入 DLL(T1218.013)").hard()
        .actor("*\\mavinject.exe").cmd("*/injectrunning*");
    // `forfiles /p C:\logs /m *.log /d -7 /c "cmd /c del @path"` 是最常见的日志轮转写法,
    // Block 会把正常的清理脚本杀掉。降为 Ask。
    s.proc(Ask, "forfiles 经 cmd 代理执行(日志轮转的常见写法,也可被用作代理执行,T1202)")
        .actor("*\\forfiles.exe").cmd("*/c*cmd*");
    s.proc(Ask, "forfiles 经 powershell 代理执行(T1202)")
        .actor("*\\forfiles.exe").cmd("*/c*powershell*");
    // pcalua -a 正是「程序兼容助手」自己拉起旧程序时用的形态,用户点了兼容修复就会出现。
    s.proc(Ask, "pcalua(程序兼容助手)代理执行(系统自身兼容修复亦如此,T1202)")
        .actor("*\\pcalua.exe").cmd("*-a*");
    // App-V 部署环境里 scriptrunner -appvscript 是正常机制。
    s.proc(Ask, "scriptrunner 代理执行(App-V 环境下为正常机制,T1218)")
        .actor("*\\scriptrunner.exe").cmd("*-appvscript*");
    s.proc(Ask, "installutil 经安装/卸载钩子执行程序集(正规安装器亦用 InstallUtil,T1218.004)")
        .actor("*\\installutil.exe").cmd("*/logtoconsole=false*");
    // 【必须写成 "空格 + /u"】`*/u*` 会命中任何含 "/U" 的正斜杠路径(如 "C:/Users/..."),
    // 而 regasm 注册 DLL 时传正斜杠路径是完全正常的 —— 那会变成对正常注册动作的误拦。
    s.proc(Ask, "regasm 经注册/卸载钩子执行程序集(T1218.009)")
        .actor("*\\regasm.exe").cmd("* /u*");
    s.proc(Ask, "regsvcs 经注册/卸载钩子执行程序集(T1218.009)")
        .actor("*\\regsvcs.exe").cmd("* /u*");
    // 企业部署确实存在 `msiexec /i https://.../app.msi` 这种用法,故只询问。
    s.proc(Ask, "msiexec 安装远程 MSI 包(企业部署亦用此形态,T1218.007)")
        .actor("*\\msiexec.exe").cmd("*http*");
    s.proc(Block, "wmic 创建进程(代理执行,T1047)").hard()
        .actor("*\\wmic.exe").cmd("*process*call*create*");
    s.proc(Block, "wmic 经远程 XSL 执行(T1220)").hard()
        .actor("*\\wmic.exe").cmd("*/format:http*");

    // ------------------------------------------------------------------
    // 6.3 外壳层的下载执行(LolbinAnalyzer 按 actor 分支,看不到这一层)
    // ------------------------------------------------------------------
    s.proc(Block, "外壳层调用 certutil 远程下载(cmd/powershell 包裹,T1105)").hard()
        .cmd("*certutil*urlcache*http*");
    // 【降级为 Ask】`certutil -decode` 是 Windows 上现成的 base64 解码器,脚本里用它还原证书、
    // 配置文件、打包的文本资源都很常见 —— 在没有 PowerShell 的环境里这几乎是唯一选择。
    // "解了个 base64"本身不说明在还原恶意载荷,判别性要看解出来的东西被不被执行,本条看不到那层。
    s.proc(Ask, "外壳层调用 certutil 解码载荷(T1140)")
        .cmd("*certutil*decode*");
    s.proc(Block, "外壳层调用 bitsadmin 后台下载(T1197/T1105)").hard()
        .cmd("*bitsadmin*/transfer*http*");
    // 【已删除 `*powershell*-enc *`】原意是用尾随空格把 "-enc"(-EncodedCommand 的缩写)与
    // "-Encoding" 的缩写区分开,但这道护栏根本不成立:`Get-Content -Enc UTF8` 这类完全正常的写法
    // 里,"-enc" 后面跟的恰恰就是空格,照样命中 —— 而它是 Block + hardOverride,会把普通脚本连
    // 进程树一起结束。空格挡不住,又没有别的可用信号,故整条删掉。
    // 不补替代形态:全称 `-EncodedCommand` 由紧接下面那条覆盖;「隐藏窗口 + 缩写」的组合由
    // kPsCombo 里的 `*hidden*-enc *` 覆盖。
    s.proc(Block, "外壳层嵌套调用 PowerShell 编码命令(-encodedcommand,T1027)").hard()
        .cmd("*powershell*-encodedcommand*");
    for (const QString& dir : dropDirFragments()) {
        s.proc(Ask, u("经 curl 下载文件到可写投递目录 ") + dir + u("(T1105)"))
            .cmd(u("*curl*http*") + dir + u("*"));
        s.proc(Ask, u("经 Invoke-WebRequest 下载文件到可写投递目录 ") + dir + u("(T1105)"))
            .cmd(u("*-outfile*") + dir + u("*"));
    }

    // ------------------------------------------------------------------
    // 6.4 PowerShell 高危组合
    // ------------------------------------------------------------------
    // 单独的 -EncodedCommand 只给 Ask:Intune / SCCM / 部分正规安装器确实用它下发脚本。
    s.proc(Ask, "PowerShell 编码命令执行(-EncodedCommand,T1027)").cmd("*-encodedcommand*");
    s.proc(Ask, "PowerShell 编码命令执行(-enc 简写,T1027)").cmd("*-enc *");
    // 与「隐藏窗口」或「下载执行」合取后就没有正常解释了。commandLinePattern 只有一条,
    // 故按【出现顺序】写合取 —— 覆盖不到乱序写法,但这几种是实战里绝对主流的形态。
    //
    // 【"iex" 必须写成 "iex(" / "|iex" / "iex " 这些真实调用形态】裸 "iex" 是 "iexplore" 的
    // 前缀,而 `powershell -w hidden Start-Process iexplore` 这种「后台拉起浏览器」的自动化
    // 脚本是真实存在的 —— `*hidden*iex*` 会把它判成「隐藏窗口 + 动态执行」并 Block。
    //
    static const char* kPsCombo[] = {
        "*hidden*-enc *", "*hidden*-encodedcommand*",
        "*hidden*iex(*", "*hidden*|iex*", "*hidden*invoke-expression*",
        "*hidden*frombase64string*", "*hidden*downloadstring*",
        "*downloadstring*iex(*", "*downloadstring*|iex*",
        "*downloadstring*invoke-expression*", "*iex(*downloadstring*",
        "*frombase64string*iex(*", "*frombase64string*invoke-expression*",
        "*iex(*frombase64string*",
        "*invoke-webrequest*iex(*", "*invoke-webrequest*|iex*",
        "*iwr *iex(*", "*downloadfile*start-process*",
        "*start-bitstransfer*start-process*",
    };
    static const char* kPsComboLabel[] = {
        "隐藏窗口 + 编码命令", "隐藏窗口 + 编码命令(全称)",
        "隐藏窗口 + 动态执行 IEX(", "隐藏窗口 + 管道送入 IEX", "隐藏窗口 + Invoke-Expression",
        "隐藏窗口 + Base64 解码", "隐藏窗口 + 内存下载",
        "内存下载 + 动态执行 IEX(", "内存下载 + 管道送入 IEX",
        "内存下载 + Invoke-Expression", "动态执行 + 内存下载",
        "Base64 解码 + 动态执行 IEX(", "Base64 解码 + Invoke-Expression",
        "动态执行 + Base64 解码",
        "Invoke-WebRequest + 动态执行", "Invoke-WebRequest + 管道送入 IEX",
        "iwr + 动态执行", "下载后直接启动",
        "BITS 下载后直接启动",
    };
    // 条数从两张表推导,不再写死:这两张表必须严格一一对应,写死的数字在增删条目时会静默错位,
    // 把某条模式配上另一条的标签(备注错了,派生出来的 id 也就错了)。
    static_assert(sizeof(kPsCombo) / sizeof(*kPsCombo) == sizeof(kPsComboLabel) / sizeof(*kPsComboLabel),
                  "kPsCombo 与 kPsComboLabel 必须一一对应");
    for (size_t i = 0; i < sizeof(kPsCombo) / sizeof(*kPsCombo); ++i)
        s.proc(Block, u("PowerShell 下载执行组合:") + u(kPsComboLabel[i]) + u("(T1059.001/T1105)")).hard()
            .cmd(kPsCombo[i]);
    // 【这两条从上面的合取表里摘出来,单独降为 Ask】它们原来混在 kPsCombo 里吃 Block + hardOverride,
    // 但"用 WebClient 下载"【单独出现】不足以定性:Chocolatey 官方安装就是一行
    // `iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))`,
    // 大量部署脚本、CI 引导脚本同样是这个形态。表里其余条目都是「下载 + 执行」「隐藏 + 执行」这类
    // 真合取,单独一个动作说明不了意图的只有这两条,所以只摘这两条,其余一律不动。
    s.proc(Ask, "PowerShell 用 WebClient 下载文件(Net.WebClient DownloadFile,T1105)")
        .cmd("*net.webclient*downloadfile*");
    s.proc(Ask, "PowerShell 用 WebClient 内存下载(Net.WebClient DownloadString,T1105)")
        .cmd("*net.webclient*downloadstring*");
    // 【改为与 Base64 互证】原来是 `*reflection.assembly*load*` 单独 Block + hardOverride,而
    // `[Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')` 是 PowerShell 弹 GUI 的
    // 标准写法(任何带窗口的运维脚本都这么写),命中即结束进程树。另一条 `*[reflection.assembly]*`
    // 更宽 —— 连方法名都不看,凡是提到这个类型就拦,已删除。
    // 真正说明「无文件执行」的是「反射加载」与「Base64 解码」同时出现:程序集内容来自内存里的
    // base64 串,而不是磁盘上的 dll。两条各写一个顺序,因为 commandLinePattern 只有一条、按出现
    // 顺序匹配。备注必须写得不一样,否则两条派生出同一个 id,后者会静默顶掉前者。
    s.proc(Block, "内存加载 .NET 程序集(反射加载 + Base64 解码,无文件执行,T1620)").hard()
        .cmd("*reflection.assembly*frombase64string*");
    s.proc(Block, "内存加载 .NET 程序集(Base64 解码 + 反射加载,无文件执行,T1620)").hard()
        .cmd("*frombase64string*reflection.assembly*");
    // 与 ThreatDetector / TrustPolicy 已确立的软信号定性保持一致:绝不 Block。
    s.proc(Ask, "PowerShell 绕过执行策略运行(-ExecutionPolicy Bypass,T1059.001)")
        .cmd("*-executionpolicy*bypass*");
    s.proc(Ask, "PowerShell 绕过执行策略运行(-ep bypass 简写,T1059.001)").cmd("*-ep*bypass*");
    s.proc(Ask, "运行时编译并执行 C# 代码(Add-Type -TypeDefinition,开发者亦用,T1027.004)")
        .cmd("*add-type*-typedefinition*");
    s.proc(Ask, "自删除脚本/程序(执行后清除自身,T1070.004)").cmd("*del*%~f0*");
    s.proc(Ask, "经 ping 延时后自删除(经典 dropper 收尾,T1070.004)").cmd("*ping*-n*del*");

    // ------------------------------------------------------------------
    // 6.5 脚本宿主执行投递目录里的脚本
    // ------------------------------------------------------------------
    static const char* kWsh[] = { "*\\wscript.exe", "*\\cscript.exe" };
    for (const char* wsh : kWsh) {
        const QString host = imageNameOf(QString::fromUtf8(wsh));
        for (const QString& dir : dropDirFragments())
            s.proc(Ask, host + u(" 运行可写投递目录 ") + dir + u(" 内的脚本(T1059.005/T1059.007)"))
                .actor(wsh).cmd(u("*") + dir + u("*"));
        s.proc(Block, host + u(" 从远程地址执行 JScript(T1059.007)")).hard()
            .actor(wsh).cmd("*//e:jscript*http*");
        s.proc(Block, host + u(" 从远程地址执行 VBScript(T1059.005)")).hard()
            .actor(wsh).cmd("*//e:vbscript*http*");
        // 这几种扩展名在正常桌面上几乎见不到,是邮件附件投递的常客。
        static const char* kOddExt[] = { "*.wsf*", "*.jse*", "*.vbe*", "*.wsh*" };
        for (const char* ext : kOddExt) {
            const QString e = QString::fromUtf8(ext).mid(1).chopped(1);
            s.proc(Ask, host + u(" 运行 ") + e + u(" 脚本(罕见扩展名,常见于邮件投递,T1059.005)"))
                .actor(wsh).cmd(ext);
        }
    }

    // ------------------------------------------------------------------
    // 6.6 异常父子链
    // ------------------------------------------------------------------
    static const char* kOfficeParents[] = {
        "*\\winword.exe", "*\\excel.exe", "*\\powerpnt.exe", "*\\outlook.exe",
        "*\\msaccess.exe", "*\\onenote.exe",
    };
    for (const char* p : kOfficeParents) {
        const QString parentName = imageNameOf(QString::fromUtf8(p));
        for (const char* a : kSpawnedHosts)
            s.proc(Block, u("Office 组件 ") + parentName + u(" 派生脚本宿主 ") +
                          imageNameOf(QString::fromUtf8(a)) +
                          u("(宏文档执行载荷,T1566.001/T1204.002)")).hard()
                .parent(p).actor(a);
    }
    static const char* kPdfParents[] = {
        "*\\acrord32.exe", "*\\acrobat.exe", "*\\foxitreader.exe",
    };
    for (const char* p : kPdfParents) {
        const QString parentName = imageNameOf(QString::fromUtf8(p));
        for (const char* a : kSpawnedHosts)
            s.proc(Block, u("PDF 阅读器 ") + parentName + u(" 派生脚本宿主 ") +
                          imageNameOf(QString::fromUtf8(a)) +
                          u("(恶意 PDF 执行载荷,T1204.002)")).hard()
                .parent(p).actor(a);
    }
    // 浏览器:企业策略 / 扩展确实会调 cmd,故只询问。
    static const char* kBrowserParents[] = {
        "*\\chrome.exe", "*\\msedge.exe", "*\\firefox.exe",
    };
    for (const char* p : kBrowserParents) {
        const QString parentName = imageNameOf(QString::fromUtf8(p));
        for (const char* a : kSpawnedHosts)
            s.proc(Ask, u("浏览器 ") + parentName + u(" 派生脚本宿主 ") +
                         imageNameOf(QString::fromUtf8(a)) + u("(疑似网页投递执行,T1204.001)"))
                .parent(p).actor(a);
    }
    // 压缩软件:用户从压缩包里直接双击脚本 —— 是风险,但由用户主动发起,故询问。
    static const char* kArchiveParents[] = {
        "*\\winrar.exe", "*\\7zfm.exe", "*\\bandizip.exe",
    };
    for (const char* p : kArchiveParents) {
        const QString parentName = imageNameOf(QString::fromUtf8(p));
        for (const char* a : kSpawnedHosts)
            s.proc(Ask, u("压缩软件 ") + parentName + u(" 派生脚本宿主 ") +
                         imageNameOf(QString::fromUtf8(a)) + u("(直接运行压缩包内脚本,T1204.002)"))
                .parent(p).actor(a);
    }
    // 邮件客户端(非 Office 系)与即时通讯:投递落地后的第一跳。
    static const char* kImParents[] = {
        "*\\foxmail.exe", "*\\wechat.exe", "*\\weixin.exe", "*\\wxwork.exe", "*\\qq.exe",
    };
    for (const char* p : kImParents) {
        const QString parentName = imageNameOf(QString::fromUtf8(p));
        for (const char* a : kSpawnedHosts)
            s.proc(Ask, u("邮件/即时通讯客户端 ") + parentName + u(" 派生脚本宿主 ") +
                         imageNameOf(QString::fromUtf8(a)) + u("(疑似社工投递执行,T1204.002)"))
                .parent(p).actor(a);
    }
}

} // namespace bulwark::engine::rules
