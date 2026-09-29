//
// 段 3 · 防御规避(T1562 / T1070 / T1548 / T1112 / T1553)
//
// DefenseEvasionAnalyzer 已经覆盖了这一类的大部分命令行判据并给到 40~50 分的硬指标,但它
// 【只加分,不出裁决】—— 45 分的硬指标走到 RuleEngine 步骤 10 时低于 HighRisk(80),结果是
// 「询问」。对「关掉实时防护」「清空事件日志」这种一次成功就永久失效的动作,询问等于给了
// 一个窗口。本段的作用就是把其中最确定的那些变成确定性 Block。
//
// 【与 kill 事件有关的一处刻意让步】结束安全软件进程的规则只对 unsignedOnly 主体 Block。
// 原因:Defender 平台自更新会重启 MsMpEng,用户也会在任务管理器里手动结束安全软件 —— 这两种
// 情形的主体都是签名健康的。对签名主体 Block 会拦掉正常操作,故交回 DefenseEvasionAnalyzer 的
// 45 分硬指标走步骤 10(-> 询问),由用户裁决。
//
// 【已知残留:停用安全软件服务的规则会误伤共存的安全软件自身】下面 kSecServices 那组
// `*stop*<服务名>*` 不带 actor 条件,而 TrustPolicy::isTrustedSecurityProduct 只看 e.actorPath
//(TrustPolicy.cpp:247-269)。于是安全软件自己的更新器若经 `cmd /c sc stop <自己的服务>` 重启
// 服务,主体是 cmd.exe,共存放行认不出来,这组规则照样 Block。
// 刻意不降级:停掉安全软件服务的危害高于这处误伤,而且降 Ask 之后签名主体会被 Worker 的
// 「信任已签名主体」降级为放行(Worker.cpp:505-512),等于这组规则对签名攻击者彻底失效。
// 真正的修法是让共存判定能穿透 cmd/powershell 去看实际发起者,那要动 TrustPolicy,不在本次范围。
//
#include "RuleDsl.h"
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine::rules {

using detail::u;

void addDefenseEvasionRules(QVector<DefenseRule>& out) {
    Segment s(out, "防御规避");

    // ------------------------------------------------------------------
    // 3.1 Defender 排除项与保护开关
    // ------------------------------------------------------------------
    // 【刻意只给 Ask】Add-MpPreference 与用户在 Defender 界面里手动加排除项,写入方【都是】
    // MsMpEng.exe。Block 会拦掉用户自己的正常操作,所以这条只询问;段 1 也因此刻意没有放行
    // MsMpEng 对 Exclusions 的写入。
    s.reg(Ask, "向 Defender 添加扫描排除项(免杀的最常见一步,T1562.001)")
        .target("*\\Windows Defender\\Exclusions\\*");
    for (const QString& host : scriptHostActors())
        s.reg(Block, u("脚本宿主 ") + imageNameOf(host) + u(" 向 Defender 添加排除项(免杀,T1562.001)")).hard()
            .target("*\\Windows Defender\\Exclusions\\*").actor(host);

    // 【口径注意】RegistryWrite 的 target 是「键路径 + \ + 值名」,拿不到值数据。所以这 9 条的
    // 真实语义是「写了 DisableRealtimeMonitoring 这个值」,把它写成 0(也就是【启用】实时防护)
    // 同样命中。组策略下发加固基线、以及各种安全加固脚本都会显式写这些值,而本条是 Block +
    // hardOverride,ruleTier 1 恒定压过段 1 的系统维护放行 —— 命中后会结束 gpsvc 所在的 svchost。
    // 故加 exemptOs:微软签名且位于系统目录的 svchost / MpCmdRun 之类走策略通道时豁免。
    // 攻击者那一侧不受影响:reg.exe / powershell / wmic 都在 LOLBin 名单里拿不到豁免,未签名样本
    // 直接过不了签名条件。
    static const char* kDefenderOff[] = {
        "DisableAntiSpyware", "DisableAntiVirus", "DisableRealtimeMonitoring",
        "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableScriptScanning",
        "DisableBlockAtFirstSeen", "DisableOnAccessProtection", "TamperProtection",
    };
    for (const char* v : kDefenderOff)
        s.reg(Block, u("注册表关闭 Defender 保护开关 ") + u(v) + u("(T1562.001)")).hard().exemptOs()
            .target(u("*\\Windows Defender*\\") + u(v));
    // 兜底:组策略也从这个键下手,故只 Ask。
    s.reg(Ask, "改写 Defender 组策略配置(可能关闭防护或改上报行为,T1562.001)").exemptOs()
        .target("*\\Policies\\Microsoft\\Windows Defender\\*");

    s.proc(Block, "命令行关闭 Defender 保护开关(Set-MpPreference -Disable*,T1562.001)").hard()
        .cmd("*set-mppreference*disable*");
    s.proc(Block, "关闭 Defender 云保护上报(MAPSReporting,规避云检测,T1562.001)").hard()
        .cmd("*set-mppreference*mapsreporting*");
    s.proc(Block, "关闭 Defender 样本自动提交(SubmitSamplesConsent,T1562.001)").hard()
        .cmd("*set-mppreference*submitsamplesconsent*");
    // 加排除项在运维里确实会做(给编译输出目录、给杀软共存),故只询问。
    s.proc(Ask, "命令行为 Defender 添加排除项(Add-MpPreference -Exclusion*,T1562.001)")
        .cmd("*add-mppreference*exclusion*");
    s.proc(Ask, "卸载 Defender 组件(Uninstall-WindowsFeature Windows-Defender,T1562.001)")
        .cmd("*uninstall-windowsfeature*windows-defender*");

    // ------------------------------------------------------------------
    // 3.2 停用安全软件的服务与进程
    // ------------------------------------------------------------------
    // 这批规则【不设 actor】。原因:真正执行动作的 sc.exe / net.exe / taskkill.exe 都不在内核
    // LOLBin 名单里,驱动不上报它们的进程创建 —— 能被观测到的是拉起它们的那层外壳
    // (cmd.exe /c ... 或 powershell.exe ...),而外壳可能是 cmd / powershell / pwsh / 甚至
    // 别的程序。不设 actor 即覆盖全部外壳,少写一个都可能漏。
    //
    // 【名单里刻意不收短名】"Sense"、"avp" 这类 3~5 字符的服务/映像名,用在 `*stop*<名>*`
    // 这种子串模式里会撞上无关命令行里的普通英文("dispense"、"nonsense"、含 avp 的路径段),
    // 而这批规则是 Block + hardOverride —— 误报的代价是直接结束一个正常进程。检出并不因此丢失:
    // DefenseEvasionAnalyzer 的 killVerb 判据已覆盖 msmpeng / windefend / securityhealth / 360 /
    // huorong / hips / qqpc / kxe / usysdiag 并给 45 分硬指标,下面按【带扩展名的完整映像名】
    // 写的 taskkill 规则也覆盖 avp.exe / mssense.exe。
    //
    static const char* kSecServices[] = {
        "windefend", "wdnissvc", "wdfilter", "wdboot", "mssense",
        "securityhealthservice", "sgrmbroker", "wscsvc", "webthreatdefsvc",
        "zhudongfangyu", "hipsdaemon", "usysdiag", "sophosagent",
        "qqpcrtp", "kxescore", "mbamservice", "ekrnservice",
    };
    for (const char* svc : kSecServices) {
        s.proc(Block, u("命令行停止安全软件服务 ") + u(svc) + u("(禁用防护,T1562.001)")).hard()
            .cmd(u("*stop*") + u(svc) + u("*"));
        s.proc(Block, u("命令行禁用安全软件服务 ") + u(svc) + u(" 的启动类型(T1562.001)")).hard()
            .cmd(u("*config*") + u(svc) + u("*disabled*"));
        s.proc(Block, u("命令行删除安全软件服务 ") + u(svc) + u("(T1562.001)")).hard()
            .cmd(u("*delete*") + u(svc) + u("*"));
    }
    for (const QString& img : securityImageNames()) {
        // taskkill 一律按【完整映像名】匹配(攻击脚本写的就是 /IM msmpeng.exe),避免短名撞车。
        s.proc(Block, u("命令行强杀安全软件进程 ") + img + u("(taskkill,T1562.001)")).hard()
            .cmd(u("*taskkill*") + img + u("*"));
        // Stop-Process 用的是不带扩展名的进程名,故这里必须用词干 —— 但只对足够长、不会撞上
        // 普通英文的词干出规则。
        const QString stem = img.left(img.lastIndexOf(QLatin1Char('.')));
        if (stem.size() >= 6)
            s.proc(Block, u("命令行强杀安全软件进程 ") + img + u("(Stop-Process,T1562.001)")).hard()
                .cmd(u("*stop-process*") + stem + u("*"));
        // ProcessTerminate 维度:只对未签名主体定罪,理由见文件头。
        s.kill(Block, u("未签名程序结束安全软件进程 ") + img + u("(禁用防护,T1562.001)")).hard()
            .target(u("*\\") + img).unsignedOnly();
    }
    // 【降级为 Ask】原注释断言"没有任何正常运维理由在终端上做",这个前提在开发机上不成立:
    // fltmc unload / detach 是文件系统过滤驱动【开发与调试】的标准动作(本产品自己的驱动就是
    // minifilter,改一版卸一次),备份与虚拟化软件的排障步骤里也有。命令行本身分不出"卸我自己的
    // 驱动"还是"卸 EDR 的驱动"—— 要分辨得看被卸的驱动归谁,这条规则拿不到那个信息。
    // 保留告警,把处置交给用户。
    s.proc(Ask, "卸载文件系统过滤驱动(fltmc unload,致盲 EDR,T1562.001)")
        .cmd("*fltmc*unload*");
    s.proc(Ask, "卸载内核驱动(sc delete / fltmc detach 针对安全驱动,T1562.001)")
        .cmd("*fltmc*detach*");

    // ------------------------------------------------------------------
    // 3.3 AMSI / ETW 致盲
    // ------------------------------------------------------------------
    static const char* kAmsi[] = {
        "*amsiinitfailed*", "*amsiutils*", "*amsiscanbuffer*", "*amsicontext*",
        "*amsisession*",
    };
    static const char* kAmsiLabel[] = {
        "amsiInitFailed 反射置位", "AmsiUtils 类型反射", "AmsiScanBuffer 补丁",
        "amsiContext 篡改", "amsiSession 篡改",
    };
    for (int i = 0; i < 5; ++i)
        s.proc(Block, u("AMSI 绕过:") + u(kAmsiLabel[i]) + u("(T1562.001)")).hard()
            .cmd(kAmsi[i]);
    // 【降级为 Ask】这两条是拿 Win32 API 名去匹配命令行,而 API 名出现在命令行里这件事本身没有
    // 方向性:ETW 相关的诊断脚本、性能分析工具、以及讲解这些 API 的文档/教学脚本都会带上它们。
    // 真正的 ETW 致盲是在进程内存里改函数入口,根本不经过命令行 —— 也就是说这两条既拦不住真攻击
    // (它不写命令行),又会被同名字符串误命中,原来还是 Block + hardOverride。
    s.proc(Ask, "ETW 致盲:EtwEventWrite 补丁(T1562.006)").cmd("*etweventwrite*");
    s.proc(Ask, "ETW 致盲:EtwEventUnregister 注销(T1562.006)").cmd("*etweventunregister*");
    // 【降级为 Ask】`*scriptblocklogging*` 只是命令行里出现了这个词,分不出开还是关:
    // `Set-ItemProperty …\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1` 是加固基线
    // 【开启】日志的标准写法,与关闭它的命令行形态完全一致。原来是 Block + hardOverride,
    // 等于开日志也被拦 + 结束进程树。这条按 API/配置名匹配的规则天生方向不可辨,只能降处置强度。
    // 备注同时改成方向中性的措辞 —— Ask 的文案要弹给用户看,不能写成"关闭"。
    s.proc(Ask, "改写 PowerShell 脚本块日志配置(ScriptBlockLogging,T1562.002)")
        .cmd("*scriptblocklogging*");
    // 注册表侧同理(target 只有键路径 + 值名,看不到值数据),但键路径本身已经很窄,保留
    // Block + hard,只给 OS 组件留豁免:组策略下发日志配置时 actor 是 svchost(gpsvc),微软签名 +
    // 系统目录,可豁免;reg.exe / powershell 在 LOLBin 名单里,照旧拦。
    // 残留:第三方(未签名)配置工具【开启】脚本块日志仍会被 Block —— 这条路上没有可用的方向信号。
    s.reg(Block, "注册表关闭 PowerShell 脚本块日志(T1562.002)").hard().exemptOs()
        .target("*\\PowerShell\\ScriptBlockLogging\\*");

    // ------------------------------------------------------------------
    // 3.4 清日志 / 反取证
    // ------------------------------------------------------------------
    // 【"cl" 后面必须跟空格】`*wevtutil*cl*` 会被 `wevtutil epl Security C:\clean\out.evtx`
    // 这种正常的日志导出命令凑出来(路径里有 "cl"),而这是 Block + hardOverride。
    s.proc(Block, "清空 Windows 事件日志(wevtutil cl,T1070.001)").hard().cmd("*wevtutil*cl *");
    s.proc(Block, "清空 Windows 事件日志(wevtutil clear-log,T1070.001)").hard().cmd("*wevtutil*clear-log*");
    s.proc(Block, "清空 Windows 事件日志(Clear-EventLog,T1070.001)").hard().cmd("*clear-eventlog*");
    s.proc(Block, "移除 Windows 事件日志(Remove-EventLog,T1070.001)").hard().cmd("*remove-eventlog*");
    s.proc(Block, "清空 Windows 事件日志(Clear-WinEvent/wevtutil epl 后清,T1070.001)").hard()
        .cmd("*clear-winevent*");
    s.del(Block, "直接删除事件日志文件 .evtx(反取证,T1070.001)").hard()
        .target("*\\winevt\\Logs\\*.evtx");
    s.proc(Block, "删除 USN 变更日志(抹掉文件改动记录,T1070)").hard()
        .cmd("*usn*deletejournal*");
    s.proc(Ask, "清空审核策略(auditpol /clear,T1562.002)").cmd("*auditpol*/clear*");
    s.proc(Ask, "关闭审核成功事件(auditpol /success:disable,T1562.002)")
        .cmd("*auditpol*success:disable*");
    s.proc(Ask, "擦除磁盘可用空间(cipher /w,使已删除文件不可恢复,T1070.004)").cmd("*cipher*/w*");
    s.proc(Ask, "清空回收站以销毁证据(Clear-RecycleBin,T1070.004)").cmd("*clear-recyclebin*");
    s.proc(Ask, "清空 Prefetch 记录(抹掉程序执行痕迹,T1070)").cmd("*del*\\prefetch\\*");

    // ------------------------------------------------------------------
    // 3.5 UAC / 系统策略回退
    // ------------------------------------------------------------------
    // 这些值都只能看到「被写了」,看不到写成了什么(见段 2 文件头的说明),而组策略与企业
    // 加固脚本也会写它们,所以一律只给 Ask —— 写成 Block 会在域环境里天天误拦。
    struct PolVal { const char* pattern; const char* label; const char* tech; };
    static const PolVal kPolicies[] = {
        { "*\\Policies\\System\\EnableLUA",                  "EnableLUA(UAC 总开关)",        "T1548.002" },
        { "*\\Policies\\System\\ConsentPromptBehaviorAdmin", "管理员提权确认行为",            "T1548.002" },
        { "*\\Policies\\System\\PromptOnSecureDesktop",      "安全桌面提权提示",              "T1548.002" },
        { "*\\Policies\\System\\FilterAdministratorToken",   "内置管理员令牌过滤",            "T1548.002" },
        { "*\\Policies\\System\\LocalAccountTokenFilterPolicy", "本地账户远程管理令牌策略",    "T1078.003" },
        { "*\\Policies\\System\\DisableTaskMgr",             "禁用任务管理器",                "T1562.001" },
        { "*\\Policies\\System\\DisableRegistryTools",       "禁用注册表编辑器",              "T1562.001" },
        { "*\\Policies\\System\\DisableCMD",                 "禁用命令提示符",                "T1562.001" },
    };
    for (const PolVal& p : kPolicies)
        s.reg(Ask, u("改写系统策略 ") + u(p.label) + u("(") + u(p.tech) + u(")"))
            .target(p.pattern);

    // ------------------------------------------------------------------
    // 3.6 凭据保护与安全模式
    // ------------------------------------------------------------------
    // UseLogonCredential=1 让 lsass 重新在内存里缓存明文口令。没有任何正当用途 —— 这是
    // Mimikatz 时代之后微软专门关掉的行为,只有攻击者会把它打开。
    s.reg(Block, "开启 WDigest 明文口令缓存 UseLogonCredential(为凭据转储铺路,T1112/T1003.001)").hard()
        .target("*\\SecurityProviders\\WDigest\\UseLogonCredential");
    s.reg(Ask, "改写 LSA 保护开关 RunAsPPL(企业加固也写此值,方向不可辨)")
        .target("*\\Control\\Lsa\\RunAsPPL");
    s.reg(Ask, "改写 Credential Guard 配置 LsaCfgFlags(T1562.001)")
        .target("*\\Control\\Lsa\\LsaCfgFlags");
    s.reg(Ask, "改写 LSA 限制匿名/缓存登录配置(T1112)")
        .target("*\\Control\\Lsa\\DisableRestrictedAdmin");
    // 安全模式:攻击者把自己注册成安全模式服务,再重启进安全模式 —— 那里绝大多数安全软件不启动。
    s.reg(Ask, "改写安全模式启动项 SafeBoot(勒索常用:进安全模式后加密,T1562.009)")
        .target("*\\Control\\SafeBoot\\*");
    // 【降级为 Ask】方向不可辨:`bcdedit /deletevalue {current} safeboot` 是【退出】安全模式的
    // 标准命令,也含 "bcdedit" 与 "safeboot" 两个词,同样命中。而排障时进安全模式再出来是极常规的
    // 操作。要区分进/出得看是 /set 还是 /deletevalue,但那样写模式会越来越脆,故只降处置强度。
    s.proc(Ask, "把系统配置为下次启动进入安全模式(bcdedit safeboot,T1562.009)")
        .cmd("*bcdedit*safeboot*");

    // ------------------------------------------------------------------
    // 3.7 防火墙 / 系统还原
    // ------------------------------------------------------------------
    s.reg(Ask, "改写 Windows 防火墙策略开关(T1562.004)")
        .target("*\\WindowsFirewall\\*\\EnableFirewall");
    s.proc(Block, "关闭 Windows 防火墙(netsh advfirewall set state off,T1562.004)").hard()
        .actor("*\\netsh.exe").cmd("*advfirewall*state*off*");
    s.proc(Block, "关闭 Windows 防火墙(netsh firewall opmode disable,T1562.004)").hard()
        .actor("*\\netsh.exe").cmd("*firewall*opmode*disable*");
    s.reg(Ask, "关闭系统还原 SystemRestore\\DisableSR(T1490)")
        .target("*\\SystemRestore\\DisableSR");
    s.reg(Ask, "关闭系统还原配置 SystemRestore\\DisableConfig(T1490)")
        .target("*\\SystemRestore\\DisableConfig");
    // 【降级为 Ask】关系统还原在装机脚本、镜像封装(sysprep 前)、虚拟机模板制作、以及为省磁盘
    // 空间做的常规调优里都会出现,是运维会主动做的事。上面两条同语义的注册表规则本来就只给 Ask,
    // 命令行这条却是 Block + hardOverride —— 同一件事两种强度,按较弱的那个统一。
    s.proc(Ask, "关闭系统还原(Disable-ComputerRestore,T1490)")
        .cmd("*disable-computerrestore*");

    // ------------------------------------------------------------------
    // 3.8 Office 宏安全回退(T1112)
    // ------------------------------------------------------------------
    static const char* kOfficeSec[] = {
        "*\\Word\\Security\\VBAWarnings",  "*\\Word\\Security\\AccessVBOM",
        "*\\Excel\\Security\\VBAWarnings", "*\\Excel\\Security\\AccessVBOM",
        "*\\Word\\Security\\DisableAllActiveX", "*\\Excel\\Security\\DisableAllActiveX",
    };
    static const char* kOfficeSecLabel[] = {
        "Word 宏警告级别", "Word VBA 对象模型访问", "Excel 宏警告级别",
        "Excel VBA 对象模型访问", "Word ActiveX 开关", "Excel ActiveX 开关",
    };
    for (int i = 0; i < 6; ++i)
        s.reg(Ask, u("回退 Office 宏安全设置:") + u(kOfficeSecLabel[i]) + u("(为宏文档铺路,T1112)"))
            .target(kOfficeSec[i]);
    s.reg(Ask, "关闭 Office 受保护视图(外来文档直接可执行宏,T1112)")
        .target("*\\Security\\ProtectedView\\*");

    // ------------------------------------------------------------------
    // 3.9 引导完整性 / 签名校验
    // ------------------------------------------------------------------
    // 本产品自己的安装脚本要开测试签名,但它走的是 RuleEngine 步骤 a2 的「维护脚本无条件放行」
    // 通道(早于规则匹配),不受这两条影响。
    s.proc(Ask, "启用测试签名模式(bcdedit testsigning,可加载未签名驱动,T1553.006)")
        .actor("*\\bcdedit.exe").cmd("*testsigning*");
    s.proc(Ask, "关闭驱动完整性校验(bcdedit nointegritychecks,T1553.006)")
        .actor("*\\bcdedit.exe").cmd("*nointegritychecks*");
    s.proc(Block, "经启动参数关闭驱动签名校验(DISABLE_INTEGRITY_CHECKS,T1553.006)").hard()
        .cmd("*disable_integrity_checks*");
    s.proc(Block, "关闭 Windows 驱动签名强制(bcdedit -set loadoptions,T1553.006)").hard()
        .cmd("*bcdedit*loadoptions*");
}

} // namespace bulwark::engine::rules
