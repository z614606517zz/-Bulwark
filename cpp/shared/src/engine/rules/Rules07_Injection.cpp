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
    // 【这三条降级为 Ask】安装器是 temp 目录里加载未签名 DLL 的大户,而且是主流形态:
    //   · Inno Setup 把自己解包到 %TEMP%\is-XXXX.tmp\ 再从那里加载 setup.tmp 与 helper DLL;
    //   · NSIS 把插件 DLL 解到 %TEMP%\nsXXXX.tmp\ 再加载。
    // 这些中间产物基本都不带签名(厂商只签外层安装包),于是"装个软件"就命中 Block + hardOverride。
    //
    // 降 Ask 还解决一个更麻烦的副作用:Block 的 ImageLoad 会走 enforceBlock -> blockModuleLoad,
    // 把路径写进内核的 FileNoLoad 名单,而那份名单【只有 64 槽且只加不减】(FileMonitor.c:200-212),
    // 槽位耗尽后此后所有新的恶意裁决都被丢弃。temp 路径里带随机段(is-A1B2C3.tmp),每次安装都是
    // 一个新路径 —— 等于用一次性路径把这份全局名单烧穿,代价远超这条规则本身的收益。
    // unsignedOnly 保证签名主体不受影响,Ask 对未签名主体不会被降级放行,仍然弹窗询问。
    s.image(Ask, "从 %TEMP% 加载未签名模块(DLL 侧载/搜索顺序劫持,T1574.002)")
        .target("*\\appdata\\local\\temp\\*.dll").unsignedOnly();
    s.image(Ask, "从 Windows\\Temp 加载未签名模块(T1574.002)")
        .target("*\\windows\\temp\\*.dll").unsignedOnly();
    s.image(Ask, "从 Users\\Public 加载未签名模块(T1574.002)")
        .target("*\\users\\public\\*.dll").unsignedOnly();
    // 同样的位置换个扩展名加载(.dat / .log 伪装成数据文件的 PE),是规避扩展名检测的常见做法。
    // 【已移除 *.tmp】它恰好是上面那批安装器的中间产物用的扩展名(is-XXXX.tmp\setup.tmp),
    // 留着它等于把刚降级掉的误报又从伪装这条路上放回来,而且这批是 Block + hard。
    // 其余 5 个扩展名不是安装器中间产物的常规形态,保留 Block + hard。
    static const char* kDisguised[] = { "*.dat", "*.log", "*.bin", "*.txt", "*.jpg" };
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
    // 已知被 BYOVD 滥用的具名驱动。不看签名 —— 它们【都有】合法签名,那正是被选中的原因。
    //
    // 【按"合法软件是否仍在用"拆成两组】驱动的 ImageLoad 上报口径比本节标题写的宽:
    // ImageMonitor.c:113-122 对 .sys 的上报范围是 \Temp\ \Users\Public\ \ProgramData\ \AppData\
    // \Downloads\ \Desktop\。落在这些目录里的既有攻击,也有正常软件:Dell 的更新工具历史上把
    // dbutil_2_3.sys 放在 C:\Windows\Temp\;WinRing0x64.sys / SpeedFan / 各类硬件监控与超频工具
    // 常被用户从桌面或下载目录直接运行,驱动就在旁边。对这类驱动直接 Block + hard 会在正常使用
    // 这些软件时结束进程树。
    //
    // A 组 = 仍随合法软件分发、终端上会正常出现的 -> 降 Ask,保留检出与告警,把处置交给用户。
    // Ask 不会被"签名主体降级放行"吃掉:内核驱动加载事件的 actorPath 是伪串"内核(驱动加载)"
    //(DriverEventSource.cpp:994-998),不是真实文件,签名核验无从成立,actorSigned 恒假。
    static const char* kByovdInUse[] = {
        "rtcore64.sys", "dbutil_2_3.sys", "dbutildrv2.sys", "aswarpot.sys",
        "procexp152.sys", "truesight.sys", "mhyprot2.sys", "mhyprot3.sys",
        "zamguard64.sys", "zam64.sys", "kprocesshacker.sys", "nvflash.sys",
        "speedfan.sys", "winio64.sys", "winring0x64.sys", "amifldrv64.sys",
        "atszio.sys",
    };
    for (const char* d : kByovdInUse)
        s.image(Ask, u("加载可被滥用的易受攻击驱动 ") + u(d) + u("(BYOVD 风险,该驱动仍有合法用途,T1068)"))
            .target(u("*\\") + u(d));
    // B 组 = 厂商已弃用 / 签名已吊销 / 只在攻击样本里见过的 -> 保留 Block + hard。
    // 这组的备注与匹配条件一字未改,id 不变。
    static const char* kByovdMaliciousOnly[] = {
        "iqvw64e.sys", "iqvw64.sys", "gdrv.sys", "gdrv2.sys", "viragt64.sys",
        "elrawdsk.sys", "asrdrv101.sys", "piddrv64.sys", "echo_driver.sys",
        "pcdsrvc.sys",
    };
    for (const char* d : kByovdMaliciousOnly)
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
    // 【降级为 Ask】注册内核服务是【所有】驱动安装的必经一步,不分好坏:显卡/声卡/外设驱动、
    // 虚拟机与沙箱的网卡与磁盘驱动、抓包工具、硬件监控工具,以及本产品自己的驱动安装脚本
    //(走 bulwark.ps1 -File 之外的通道时)都会出现这条命令行。原来是 Block + hardOverride,
    // 等于装任何驱动都被拦并结束进程树。
    // 保留检出:这条仍然会告警,只是把处置交给用户。真正该硬拦的是「注册的驱动来自可写投递目录」,
    // 那由紧接下面的 binPath 系列规则负责 —— 那才是 BYOVD 的判别性形态。
    s.proc(Ask, "创建内核驱动服务(sc create type= kernel,T1543.003)")
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
    // 【降级为 Ask】同 ETW 那两条的问题:拿 Win32 API 名匹配命令行。真正的 APC 注入是在代码里调
    // 这个 API,不会把名字写进命令行;会把 "QueueUserAPC" 写在命令行里的,反而多是调试脚本、
    // 讲解注入原理的教学/研究脚本,以及本产品自己的检测用例。既拦不住真注入,又会误命中。
    s.proc(Ask, "经 SetThreadContext/QueueUserAPC 注入的工具特征(T1055.004)")
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
