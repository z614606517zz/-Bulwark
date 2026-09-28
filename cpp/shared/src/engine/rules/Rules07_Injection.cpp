//
// 段 7 · 注入 / DLL 侧载 / BYOVD(T1055 / T1574 / T1068)
//
// 【必须先搞清两条事件语义,否则这一段大半规则永不命中】
//   · ImageLoad:用户态模块【只上报 \Temp\ 与 \Users\Public\】。所以写 "*\programdata\*.dll"、
//     "*\downloads\*.dll" 的规则是结构性空转 —— 本段刻意不写。驱动(.sys)则是【用户可写目录
//     全部上报】,且此时 actorPath 是「内核(驱动加载)」,所以 .sys 规则只能按 target 写、
//     不能按 actor 写。
//   · ImageLoad 事件里的 actorSigned 表示【被加载模块自身】的签名,不是宿主进程的。所以
//     unsignedOnly() 用在 image 规则上,含义正是「这个模块没有可信签名」—— 这正是要的判据。
//
// 【BYOVD 名单的价值与边界】下面那批 .sys 都是有真实合法签名、但含任意内存读写原语的驱动,
// 被当作「自带易受攻击驱动」来关掉内核防护。它们在正常机器上确实可能存在(MSI 主板工具、
// Dell 固件工具),但正常安装会把驱动放进 \Windows\System32\drivers\ —— 而 ImageLoad 的 .sys
// 事件只在【用户可写目录】才产生。也就是说:能命中这批规则的加载,本身就已经是非常规位置了。
//
#include "RuleDsl.h"
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine::rules {

using detail::u;

void addInjectionRules(QVector<DefenseRule>& out) {
    Segment s(out, "注入与侧载");

    // ------------------------------------------------------------------
    // 7.1 远程线程注入:按发起方
    // ------------------------------------------------------------------
    // 脚本宿主做跨进程注入没有任何正当理由。InjectionAnalyzer 已给 20 分并置硬指标,
    // 这里出确定裁决(否则 30+20=50 分在步骤 10 只换来询问)。
    for (const QString& host : scriptHostActors())
        s.thread(Block, u("脚本宿主 ") + imageNameOf(host) + u(" 发起跨进程远程线程注入(T1055)")).hard()
            .actor(host);
    s.thread(Block, "msbuild 发起跨进程远程线程注入(内联任务注入,T1055)").hard()
        .actor("*\\msbuild.exe");
    for (const QString& dir : dropDirFragments())
        s.thread(Block, u("可写投递目录 ") + dir + u(" 内的程序发起远程线程注入(T1055)")).hard()
            .actor(u("*") + dir + u("*"));

    // ------------------------------------------------------------------
    // 7.2 远程线程注入:按受害进程
    // ------------------------------------------------------------------
    // 关键系统进程:未签名主体注入它们无正当理由。签名主体刻意不拦 —— InjectionAnalyzer 已
    // 专门为「dwm.exe / svchost.exe 向 csrss.exe 创建线程」这类 Windows 内部交互做了豁免
    // (实测误报 12 次 + 1 次),在规则层重新拦回来等于把那处修复作废。
    static const char* kCritical[] = {
        "*\\winlogon.exe", "*\\csrss.exe", "*\\services.exe", "*\\smss.exe",
        "*\\wininit.exe", "*\\spoolsv.exe",
    };
    for (const char* v : kCritical)
        s.thread(Block, u("未签名程序向关键系统进程 ") + imageNameOf(QString::fromUtf8(v)) +
                        u(" 注入远程线程(T1055)")).hard()
            .target(v).unsignedOnly();
    static const char* kHostish[] = { "*\\explorer.exe", "*\\svchost.exe", "*\\dwm.exe", "*\\taskhostw.exe" };
    for (const char* v : kHostish)
        s.thread(Ask, u("未签名程序向系统宿主进程 ") + imageNameOf(QString::fromUtf8(v)) +
                      u(" 注入远程线程(进程镂空的常见落点,T1055.012)"))
            .target(v).unsignedOnly();
    static const char* kSensitiveApp[] = {
        "*\\chrome.exe", "*\\msedge.exe", "*\\firefox.exe", "*\\outlook.exe",
        "*\\wechat.exe", "*\\weixin.exe", "*\\wxwork.exe", "*\\qq.exe",
    };
    for (const char* v : kSensitiveApp)
        s.thread(Ask, u("未签名程序向 ") + imageNameOf(QString::fromUtf8(v)) +
                      u(" 注入远程线程(会话劫持/信息窃取,T1055)"))
            .target(v).unsignedOnly();

    // ------------------------------------------------------------------
    // 7.3 DLL 侧载(只写 ImageLoad 真会上报的两个目录)
    // ------------------------------------------------------------------
    s.image(Block, "从 %TEMP% 加载未签名模块(DLL 侧载/搜索顺序劫持,T1574.002)").hard()
        .target("*\\appdata\\local\\temp\\*.dll").unsignedOnly();
    s.image(Block, "从 Windows\\Temp 加载未签名模块(T1574.002)").hard()
        .target("*\\windows\\temp\\*.dll").unsignedOnly();
    s.image(Block, "从 Users\\Public 加载未签名模块(T1574.002)").hard()
        .target("*\\users\\public\\*.dll").unsignedOnly();
    // 同样的位置换个扩展名加载(.tmp / .dat / .log 伪装成数据文件的 PE),是规避扩展名检测的常见做法。
    static const char* kDisguised[] = { "*.tmp", "*.dat", "*.log", "*.bin", "*.txt", "*.jpg" };
    for (const char* ext : kDisguised) {
        const QString e = QString::fromUtf8(ext).mid(1);
        s.image(Block, u("从 %TEMP% 加载伪装成 ") + e + u(" 数据文件的未签名模块(T1574.002/T1027)")).hard()
            .target(u("*\\appdata\\local\\temp\\*") + e).unsignedOnly();
    }

    // ------------------------------------------------------------------
    // 7.4 BYOVD:可写目录里加载驱动
    // ------------------------------------------------------------------
    for (const QString& dir : dropDirFragments())
        s.image(Block, u("从可写目录 ") + dir + u(" 加载内核驱动(自带易受攻击驱动,T1068)")).hard()
            .target(u("*") + dir + u("*.sys"));
    s.image(Block, "从用户目录加载内核驱动(BYOVD,T1068)").hard()
        .target("*\\users\\*\\downloads\\*.sys");
    // 已知被 BYOVD 滥用的具名驱动。命中即拦,不看签名 —— 它们【都有】合法签名,那正是被选中的原因。
    static const char* kByovd[] = {
        "iqvw64e.sys", "iqvw64.sys", "rtcore64.sys", "gdrv.sys", "gdrv2.sys",
        "dbutil_2_3.sys", "dbutildrv2.sys", "aswarpot.sys", "procexp152.sys",
        "truesight.sys", "viragt64.sys", "mhyprot2.sys", "mhyprot3.sys",
        "zamguard64.sys", "zam64.sys", "kprocesshacker.sys", "nvflash.sys",
        "speedfan.sys", "winio64.sys", "winring0x64.sys", "amifldrv64.sys",
        "atszio.sys", "elrawdsk.sys", "asrdrv101.sys", "piddrv64.sys",
        "echo_driver.sys", "pcdsrvc.sys",
    };
    for (const char* d : kByovd)
        s.image(Block, u("加载已知可被滥用的易受攻击驱动 ") + u(d) + u("(BYOVD,关内核防护,T1068)")).hard()
            .target(u("*\\") + u(d));

    // ------------------------------------------------------------------
    // 7.5 驱动落地与服务注册
    // ------------------------------------------------------------------
    s.file(Block, "未签名程序向系统驱动目录投放 .sys(为加载恶意驱动铺路,T1068)").hard()
        .target("*\\System32\\drivers\\*.sys").unsignedOnly();
    for (const QString& dir : dropDirFragments())
        s.file(Ask, u("向可写投递目录 ") + dir + u(" 投放内核驱动 .sys(BYOVD 前置,T1068)"))
            .target(u("*") + dir + u("*.sys"));
    s.proc(Block, "创建内核驱动服务(sc create type= kernel,T1543.003)").hard()
        .cmd("*create*type=*kernel*");
    s.proc(Block, "创建指向可写投递目录的服务(sc create binPath= %TEMP%,T1543.003)").hard()
        .cmd("*binpath=*\\appdata\\local\\temp\\*");
    s.proc(Block, "创建指向 Users\\Public 的服务(T1543.003)").hard()
        .cmd("*binpath=*\\users\\public\\*");

    // ------------------------------------------------------------------
    // 7.6 即时通讯客户端 hook(「银狐」一类 IM 群控)
    // ------------------------------------------------------------------
    // RuleEngine 步骤 2b 的注释点名过这批规则:那里把「签名健康的 IM 主体」的放行范围锁回了
    // 网络维度,正是为了让这批 hook 模块的加载重新可被检测到。规则丢失则那处收紧白做。
    static const char* kImHook[] = {
        "*wxhook*.dll", "*wxhelper*.dll", "*wechatsdk*.dll", "*vchat*.dll",
        "*wxapi*.dll", "*wechathook*.dll", "*wxdriver*.dll", "*wechatwin*hook*.dll",
        "*qqhook*.dll", "*imhook*.dll",
    };
    for (const char* m : kImHook)
        s.image(Block, u("加载即时通讯 hook 模块 ") + u(m) + u("(IM 群控/消息劫持,T1055.001)")).hard()
            .target(m);
    // 向 IM 安装目录植入 DLL:侧载宿主就绪的最后一步。
    static const char* kImDir[] = {
        "*\\Tencent\\WeChat\\*.dll", "*\\Tencent\\WXWork\\*.dll", "*\\Tencent\\QQ\\*.dll",
        "*\\Weixin\\*.dll", "*\\DingTalk\\*.dll",
    };
    static const char* kImDirLabel[] = { "微信", "企业微信", "QQ", "微信(新版)", "钉钉" };
    for (int i = 0; i < 5; ++i)
        s.file(Block, u("未签名程序向") + u(kImDirLabel[i]) + u("安装目录植入 DLL(侧载准备,T1574.002)")).hard()
            .target(kImDir[i]).unsignedOnly();

    // ------------------------------------------------------------------
    // 7.7 其它注入落点
    // ------------------------------------------------------------------
    // 把 DLL 写进已签名程序的安装目录(白加黑):正常更新器改自己目录时是签名的,
    // 未签名主体往别人的安装目录塞 DLL 没有正常解释。
    s.file(Ask, "未签名程序向 Program Files 下的安装目录写入 DLL(白加黑侧载准备,T1574.002)")
        .target("*\\Program Files*\\*.dll").unsignedOnly();
    s.proc(Block, "经 SetThreadContext/QueueUserAPC 注入的工具特征(T1055.004)").hard()
        .cmd("*queueuserapc*");
    s.proc(Block, "反射式 DLL 注入(Invoke-ReflectivePEInjection,T1055.001)").hard()
        .cmd("*reflectivepeinjection*");
    s.proc(Block, "经 PowerSploit 注入内存载荷(Invoke-Shellcode,T1055)").hard()
        .cmd("*invoke-shellcode*");
    s.proc(Block, "经 DLL 注入工具注入指定进程(Invoke-DllInjection,T1055.001)").hard()
        .cmd("*invoke-dllinjection*");
    s.proc(Ask, "经 AppDomainManager 劫持 .NET 程序启动(T1574.014)")
        .cmd("*appdomainmanager*");
}

} // namespace bulwark::engine::rules
