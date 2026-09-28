//
// 段 2 · 持久化(T1547 / T1053 / T1543 / T1546 / T1037)
//
// 【这一段的写法为什么几乎全是「按写入方身份判」】
// RegistryWrite 事件的 target 是「键路径 + \ + 值名」,【看不到值数据】。所以「Run 键指向
// C:\Users\x\AppData\Local\Temp\a.exe」这种判据在本引擎里根本无法表达 —— 写成 targetPattern
// 会永远不命中。能用的信息只有:哪个键的哪个值被写了、谁写的、写入方签名如何。
// 于是这一段的结构统一是:
//     「敏感自启动键」 x 「写入方是未签名程序 / 是脚本宿主」
// 未签名 -> Ask(签名安装器与更新器写 Run 键是日常常态,一律拦会把正常装软件拦死);
// 脚本宿主 -> Block(powershell / mshta / rundll32 去写自启动键没有正当用途)。
//
// 【依赖受关注键名单】注册表事件只在键命中 ProtectedRegistryKeys 时才产生。本段用到的键
// 一部分来自 appsettings 默认 6 条(Run / RunOnce / Policies\Explorer\Run / IFEO / Winlogon /
// Services),其余全部来自 DefaultRules::registryWatchFragments() —— 那份名单必须被服务并入
// options.ProtectedRegistryKeys,否则本段过半规则结构性永不命中。接线点见 service/src/main.cpp。
//
#include "RuleDsl.h"
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine::rules {

using detail::u;

void addPersistenceRules(QVector<DefenseRule>& out) {
    Segment s(out, "持久化");

    // ------------------------------------------------------------------
    // 2.1 注册表自启动:Run / RunOnce
    // ------------------------------------------------------------------
    struct RunKey { const char* pattern; const char* label; };
    static const RunKey kRunKeys[] = {
        { "*\\CurrentVersion\\Run\\*",     "Run" },
        { "*\\CurrentVersion\\RunOnce\\*", "RunOnce" },
    };
    for (const RunKey& k : kRunKeys) {
        s.reg(Ask, u("未签名程序写入 ") + u(k.label) + u(" 开机自启动项(T1547.001)"))
            .target(k.pattern).unsignedOnly();
        for (const QString& host : scriptHostActors())
            s.reg(Block, u("脚本宿主 ") + imageNameOf(host) + u(" 写入 ") + u(k.label) +
                         u(" 开机自启动项(T1547.001)"))
                .target(k.pattern).actor(host);
    }

    // 策略版 Run 键。正常第三方软件不写这里(它属于组策略的地盘),而攻击者拿它当「更隐蔽的
    // Run 键」用 —— 大多数自启动查看工具默认不显示它。故不分签名一律拦,只给 OS 组件留豁免。
    s.reg(Block, "写入策略版开机自启动项 Policies\\Explorer\\Run(隐蔽自启动,T1547.001)")
        .target("*\\CurrentVersion\\Policies\\Explorer\\Run\\*").exemptOs();

    // ------------------------------------------------------------------
    // 2.2 映像劫持 / 静默退出劫持
    // ------------------------------------------------------------------
    // IFEO Debugger:被劫持程序一启动,系统改去启动 Debugger 里写的东西。合法使用者只有
    // gflags 那类调试配置,在终端上极罕见,故一律拦(OS 组件豁免)。
    s.reg(Block, "设置映像劫持调试器 IFEO\\Debugger(劫持目标程序启动,T1546.012)")
        .target("*\\Image File Execution Options\\*\\Debugger").exemptOs();
    // GlobalFlag 单独看是正常的调试标志,但它正是 SilentProcessExit 链条的开关(置 0x200 才会
    // 触发 MonitorProcess)。故只给 Ask:单独写它不足以定罪,与下面 SilentProcessExit 的 Block
    // 合起来才是完整链条。
    s.reg(Ask, "设置 IFEO\\GlobalFlag(SilentProcessExit 劫持的前置开关,T1546.012)")
        .target("*\\Image File Execution Options\\*\\GlobalFlag").exemptOs();
    s.reg(Block, "写入静默退出劫持 SilentProcessExit\\MonitorProcess(T1546.012)").hard()
        .target("*\\SilentProcessExit\\*");

    // ------------------------------------------------------------------
    // 2.3 Winlogon
    // ------------------------------------------------------------------
    struct WinlogonVal { const char* pattern; const char* label; };
    static const WinlogonVal kWinlogon[] = {
        { "*\\Winlogon\\Shell",     "Shell" },
        { "*\\Winlogon\\Userinit",  "Userinit" },
        { "*\\Winlogon\\Taskman",   "Taskman" },
        { "*\\Winlogon\\AppSetup",  "AppSetup" },
        { "*\\Winlogon\\Notify\\*", "Notify" },
    };
    for (const WinlogonVal& v : kWinlogon)
        s.reg(Block, u("改写 Winlogon\\") + u(v.label) + u("(登录时执行,T1547.004)"))
            .target(v.pattern).exemptOs();

    // ------------------------------------------------------------------
    // 2.4 全局注入型持久化:AppInit_DLLs / AppCertDlls
    // ------------------------------------------------------------------
    // 这两处一旦写入,DLL 会被注入到几乎所有进程里。AppInit 在开启安全启动的现代 Windows 上
    // 已被系统忽略,正常软件早就不用它;AppCertDlls 连微软自己都不用。属于「只剩攻击者在用」
    // 的位置,给 hardOverride。
    s.reg(Block, "写入 AppInit_DLLs(注入所有 GUI 进程,T1546.010)").hard()
        .target("*\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs");
    s.reg(Block, "开启 LoadAppInit_DLLs(启用全局 DLL 注入,T1546.010)").hard()
        .target("*\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs");
    s.reg(Block, "写入 AppCertDlls(注入所有创建进程的程序,T1546.009)").hard()
        .target("*\\Control\\Session Manager\\AppCertDlls\\*");
    // Windows NT\CurrentVersion\Windows 下的 Load / Run(16 位时代遗留的登录执行位)。
    s.reg(Block, "写入 Windows\\Load 登录执行项(遗留自启动位,T1547.001)").exemptOs()
        .target("*\\Windows NT\\CurrentVersion\\Windows\\Load");
    s.reg(Block, "写入 Windows\\Run 登录执行项(遗留自启动位,T1547.001)").exemptOs()
        .target("*\\Windows NT\\CurrentVersion\\Windows\\Run");

    // ------------------------------------------------------------------
    // 2.5 其它注册表持久化位(合法用途存在,故多为 Ask)
    // ------------------------------------------------------------------
    s.reg(Ask, "写入 cmd 启动自动执行项 Command Processor\\AutoRun(T1546.011)")
        .target("*\\Command Processor\\AutoRun");
    s.reg(Ask, "注册 netsh 助手 DLL(每次运行 netsh 即加载,T1546.007)")
        .target("*\\Microsoft\\Netsh\\*");
    s.reg(Ask, "写入 Active Setup StubPath(下次登录执行一次,T1547.014)")
        .target("*\\Active Setup\\Installed Components\\*\\StubPath");
    s.reg(Ask, "注册打印端口监视器(spoolsv 加载 DLL 并可提权,T1547.012)")
        .target("*\\Control\\Print\\Monitors\\*");
    s.reg(Ask, "改写网络提供程序顺序(NPPSpy 可借此截获登录口令,T1556)")
        .target("*\\Control\\NetworkProvider\\Order\\*");
    // 【为什么没有 BootExecute 规则】BootExecute 是 \Control\Session Manager 这个【键】上的一个
    // 【值】,而受关注键片段只到键这一级(驱动按键路径匹配,不含值名)。要观测到它就得登记整个
    // "\Control\Session Manager" —— 那会连带把 \Session Manager\Environment(安装器改 PATH 的
    // 地方)一起拉进上报通道。BootExecute 持久化在真实样本里极少见,不值得为它换来这份噪音。
    // LSA 扩展包:写进去即被 lsass 加载,既是持久化也是凭据窃取入口。企业密码过滤器是合法
    // 用途(Notification Packages),故 Ask 而非 Block。
    static const char* kLsaPkg[] = {
        "*\\Control\\Lsa\\Security Packages",
        "*\\Control\\Lsa\\Authentication Packages",
        "*\\Control\\Lsa\\Notification Packages",
    };
    static const char* kLsaPkgLabel[] = { "Security Packages", "Authentication Packages",
                                          "Notification Packages" };
    for (int i = 0; i < 3; ++i)
        s.reg(Ask, u("写入 LSA ") + u(kLsaPkgLabel[i]) +
                   u("(被 lsass 加载,兼持久化与凭据窃取,T1547.002/T1547.005)"))
            .target(kLsaPkg[i]);

    // 登录脚本 / 启动目录重定向。两者都依赖新增的受关注键片段。
    s.reg(Ask, "写入登录脚本 UserInitMprLogonScript(登录时执行,T1037.001)")
        .target("*\\Environment\\UserInitMprLogonScript");
    s.reg(Ask, "改写「启动」文件夹位置 User Shell Folders\\Startup(重定向自启动目录,T1547.001)")
        .target("*\\User Shell Folders\\Startup");
    s.reg(Ask, "改写「启动」文件夹位置 Shell Folders\\Startup(重定向自启动目录,T1547.001)")
        .target("*\\Shell Folders\\Startup");

    // 文件关联 / ms-settings 劫持。前者是「打开任意 exe 都先走我」,后者是 fodhelper 绕 UAC
    // 的标准落点 —— 两处都没有第三方软件的正常写入理由。
    s.reg(Block, "劫持 ms-settings 协议处理器(fodhelper 绕过 UAC,T1548.002)").hard()
        .target("*\\Classes\\ms-settings\\shell\\open\\command*");
    s.reg(Block, "劫持 exefile 打开命令(所有可执行文件的启动都被接管,T1546.001)").hard()
        .target("*\\Classes\\exefile\\shell\\open\\command*");

    // ------------------------------------------------------------------
    // 2.6 服务持久化(ImagePath / ServiceDll)
    // ------------------------------------------------------------------
    s.reg(Ask, "未签名程序写入服务映像路径 Services\\*\\ImagePath(T1543.003)")
        .target("*\\Services\\*\\ImagePath").unsignedOnly();
    for (const QString& host : scriptHostActors())
        s.reg(Block, u("脚本宿主 ") + imageNameOf(host) + u(" 写入服务映像路径(创建/劫持服务,T1543.003)"))
            .target("*\\Services\\*\\ImagePath").actor(host);
    s.reg(Ask, "未签名程序写入服务 DLL Services\\*\\Parameters\\ServiceDll(svchost 型服务劫持,T1543.003)")
        .target("*\\Services\\*\\Parameters\\ServiceDll").unsignedOnly();
    s.reg(Ask, "未签名程序改写服务故障恢复命令 Services\\*\\FailureCommand(失败即执行,T1543.003)")
        .target("*\\Services\\*\\FailureCommand").unsignedOnly();

    // ------------------------------------------------------------------
    // 2.7 启动文件夹(在 ProtectedPaths 默认名单里,FileWrite 事件可靠)
    // ------------------------------------------------------------------
    s.file(Block, "未签名程序向「启动」文件夹投放文件(开机自启动,T1547.001)")
        .target("*\\Start Menu\\Programs\\Startup\\*").unsignedOnly();
    for (const QString& host : scriptHostActors())
        s.file(Block, u("脚本宿主 ") + imageNameOf(host) + u(" 向「启动」文件夹投放文件(T1547.001)"))
            .target("*\\Start Menu\\Programs\\Startup\\*").actor(host);
    // 签名主体也要问一次「直接放可执行体/脚本」:正规安装器放的是快捷方式(.lnk),直接把
    // exe / 脚本落进启动目录的极少,而带盗用签名的样本正是这么做的。.lnk 刻意不列入。
    static const char* kStartupExec[] = {
        "*\\Start Menu\\Programs\\Startup\\*.exe", "*\\Start Menu\\Programs\\Startup\\*.scr",
        "*\\Start Menu\\Programs\\Startup\\*.com", "*\\Start Menu\\Programs\\Startup\\*.pif",
        "*\\Start Menu\\Programs\\Startup\\*.bat", "*\\Start Menu\\Programs\\Startup\\*.cmd",
        "*\\Start Menu\\Programs\\Startup\\*.vbs", "*\\Start Menu\\Programs\\Startup\\*.vbe",
        "*\\Start Menu\\Programs\\Startup\\*.js",  "*\\Start Menu\\Programs\\Startup\\*.jse",
        "*\\Start Menu\\Programs\\Startup\\*.wsf", "*\\Start Menu\\Programs\\Startup\\*.hta",
        "*\\Start Menu\\Programs\\Startup\\*.ps1", "*\\Start Menu\\Programs\\Startup\\*.dll",
    };
    for (const char* pat : kStartupExec) {
        const QString ext = QString::fromUtf8(pat).section(QLatin1Char('.'), -1);
        s.file(Ask, u("向「启动」文件夹投放 .") + ext + u(" 文件(自启动持久化,T1547.001)"))
            .target(pat);
    }
    s.del(Ask, "删除「启动」文件夹内的项(可能是清理自启动痕迹,T1070.004)")
        .target("*\\Start Menu\\Programs\\Startup\\*");

    // ------------------------------------------------------------------
    // 2.8 计划任务
    // ------------------------------------------------------------------
    // 任务定义落盘。段 1 已放行「任务计划程序服务(svchost,父 services.exe)写入 Tasks 目录」,
    // 那是注册任务时的正常写入者;剩下的直接写 Tasks 目录的主体都是绕过 API 手工塞任务。
    s.file(Block, "未签名程序直接写入计划任务定义目录(绕过任务 API,T1053.005)")
        .target("*\\System32\\Tasks\\*").unsignedOnly();
    for (const QString& host : scriptHostActors())
        s.file(Block, u("脚本宿主 ") + imageNameOf(host) + u(" 直接写入计划任务定义(T1053.005)"))
            .target("*\\System32\\Tasks\\*").actor(host);
    s.del(Ask, "删除计划任务定义文件(可能是清理持久化痕迹,T1070.009)")
        .target("*\\System32\\Tasks\\*");

    // schtasks 本体(在内核 LOLBin 名单里,ProcessCreate 会上报)。
    s.proc(Ask, "schtasks 创建计划任务(T1053.005)")
        .actor("*\\schtasks.exe").cmd("*/create*");
    s.proc(Block, "schtasks 创建以 SYSTEM 身份运行的计划任务(提权持久化,T1053.005)").hard()
        .actor("*\\schtasks.exe").cmd("*/create*/ru*system*");
    static const char* kTaskPayload[] = {
        "powershell", "pwsh", "mshta", "rundll32", "regsvr32", "certutil",
        "wscript", "cscript", "bitsadmin",
    };
    for (const char* p : kTaskPayload)
        s.proc(Block, u("schtasks 创建的计划任务以 ") + u(p) + u(" 为执行体(脚本宿主驻留,T1053.005)")).hard()
            .actor("*\\schtasks.exe").cmd(u("*/create*") + u(p) + u("*"));
    for (const QString& dir : dropDirFragments())
        s.proc(Block, u("schtasks 创建的计划任务指向可写投递目录 ") + dir + u("(T1053.005)")).hard()
            .actor("*\\schtasks.exe").cmd(u("*/create*") + dir + u("*"));
    s.proc(Ask, "schtasks 修改已有计划任务(可能劫持正常任务,T1053.005)")
        .actor("*\\schtasks.exe").cmd("*/change*");
    s.proc(Ask, "schtasks 删除计划任务(可能是清理痕迹或停掉安全巡检,T1070.009)")
        .actor("*\\schtasks.exe").cmd("*/delete*");
    // at.exe 在现代 Windows 上已被 schtasks 取代且默认不再可用,还在用它的基本只有旧攻击脚本。
    s.proc(Block, "使用已废弃的 at 命令创建计划任务(T1053.002)")
        .actor("*\\at.exe");

    // ------------------------------------------------------------------
    // 2.9 WMI 事件订阅(无文件持久化,T1546.003)
    // ------------------------------------------------------------------
    // 这三个词只出现在「订阅永久事件消费者」这件事上,正常运维脚本查询 WMI 不会碰它们。
    static const char* kWmiSub[] = {
        "*root\\subscription*", "*__eventfilter*", "*commandlineeventconsumer*",
        "*activescripteventconsumer*", "*__filtertoconsumerbinding*",
    };
    static const char* kWmiSubLabel[] = {
        "root\\subscription 命名空间", "__EventFilter 事件过滤器", "CommandLineEventConsumer 消费者",
        "ActiveScriptEventConsumer 消费者", "__FilterToConsumerBinding 绑定",
    };
    // 主体只收这三个:wmic 与 PowerShell 是操作永久事件订阅的唯一现实途径。mshta / cscript
    // 想订阅 WMI 也得经由 WScript.Shell 拉起它们其中之一,那一跳会被上面的规则接住,不必在这里
    // 再乘一遍(每多一个主体就多 5 条规则,收益递减)。
    static const char* kWmiActor[] = {
        "*\\wmic.exe", "*\\powershell.exe", "*\\pwsh.exe",
    };
    for (int i = 0; i < 5; ++i)
        for (const char* a : kWmiActor)
            s.proc(Block, u("经 ") + imageNameOf(QString::fromUtf8(a)) + u(" 操作 WMI ") +
                          u(kWmiSubLabel[i]) + u("(无文件持久化,T1546.003)")).hard()
                .actor(a).cmd(kWmiSub[i]);
    s.proc(Ask, "编译 MOF 文件入 WMI 仓库(可植入永久事件订阅,T1546.003)")
        .cmd("*mofcomp*");
    s.proc(Ask, "注册 WMI 事件订阅(Register-WmiEvent,T1546.003)")
        .cmd("*register-wmievent*");

    // ------------------------------------------------------------------
    // 2.10 辅助功能劫持(T1546.008)
    // ------------------------------------------------------------------
    // 替换这些映像后,在登录界面按快捷键即可拿到 SYSTEM 外壳 —— 这是不需要任何凭据的后门。
    // 它们位于 System32,正常只有 Windows 更新会改(段 1 已放行 TrustedInstaller / TiWorker)。
    static const char* kAccessibility[] = {
        "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe",
        "displayswitch.exe", "atbroker.exe",
    };
    for (const char* n : kAccessibility) {
        s.file(Block, u("替换辅助功能程序 ") + u(n) + u("(登录界面后门,T1546.008)")).hard()
            .target(u("*\\System32\\") + u(n));
        s.reg(Block, u("为辅助功能程序 ") + u(n) + u(" 设置映像劫持调试器(登录界面后门,T1546.008)")).hard()
            .target(u("*\\Image File Execution Options\\") + u(n) + u("\\*"));
    }
}

} // namespace bulwark::engine::rules
