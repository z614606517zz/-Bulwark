//
// 段 8 · 横向移动 / 远控 / C2(T1021 / T1047 / T1090 / T1219 / T1572 / T1136)
//
// 【这一段刻意不写网络维度的静态名单】
//   · NetworkConnect 的 target 只有 "ip:port",没有域名 —— 按端口或 IP 写死名单要么误报
//     (4444/8080 正常服务也用),要么很快过期。恶意 IP 由 ThreatFox 情报 feed 动态注入规则,
//     信标周期性与扇出由 BeaconDetector / EgressRateMonitor 按档位 + 互证处理,那里已经为
//     代理 / VPN / BT 客户端的正常外联做过专门的误报抑制。
//   · DnsQuery 同样不写:它是高频观测型事件,给 Ask 会造成弹窗风暴,而 DgaDomainAnalyzer
//     已经在软信号层面覆盖随机域名。动态 DNS 域名留给情报侧。
//
// 【远控工具为什么只拦「落在投递目录」的】RemoteControlAnalyzer 已经持有一份完整的远控工具
// 映像名单并按行为计分。正常安装的远控(ToDesk / 向日葵 / AnyDesk)位于 \Program Files\ 或
// \AppData\Local\<厂商>\,而驱动对 \Program Files\ 下的映像根本不上报进程创建 —— 也就是说
// 「用户自己装的远控」在这一层天然不可见。能被看到的是从 %TEMP% / Users\Public 直接跑起来的
// 便携版,那正是攻击者静默投放远控的形态。
//
#include "RuleDsl.h"
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine::rules {

using detail::u;

void addLateralAndC2Rules(QVector<DefenseRule>& out) {
    Segment s(out, "横移与远控");

    // ------------------------------------------------------------------
    // 8.1 静默投放远控工具
    // ------------------------------------------------------------------
    // 名单取「实战中被当作后门投放最多」的那一批,不追求穷尽 RemoteControlAnalyzer 的全表 ——
    // 这里每加一个工具名要乘以目录数和宿主数,收益递减而规则数线性膨胀;没被本段收进来的工具
    // 仍由 RemoteControlAnalyzer 按行为计分。
    static const char* kRemoteTools[] = {
        "todesk", "anydesk", "rustdesk", "sunloginclient", "aweray_remote",
        "ultraviewer", "meshagent", "dwagent", "rutserv", "winvnc",
        "screenconnect", "netsupport",
    };
    static const char* kRemoteDirs[] = {
        "*\\appdata\\local\\temp\\*", "*\\windows\\temp\\*",
        "*\\users\\public\\*", "*\\programdata\\*",
    };
    static const char* kRemoteDirLabel[] = {
        "%TEMP%", "Windows\\Temp", "Users\\Public", "ProgramData",
    };
    for (const char* t : kRemoteTools)
        for (int i = 0; i < 4; ++i)
            s.proc(Block, u("远控工具 ") + u(t) + u(" 从可写投递目录 ") + u(kRemoteDirLabel[i]) +
                          u(" 启动(静默植入远控,T1219)")).hard()
                .actor(u(kRemoteDirs[i]) + u(t) + u("*.exe"));
    // 远控工具由脚本宿主直接拉起 —— 用户手动打开远控不会经过 PowerShell / mshta。
    static const char* kRemoteParents[] = {
        "*\\powershell.exe", "*\\cmd.exe", "*\\mshta.exe", "*\\wscript.exe",
    };
    for (const char* t : kRemoteTools)
        for (const char* p : kRemoteParents)
            s.proc(Block, u("远控工具 ") + u(t) + u(" 由脚本宿主 ") +
                          imageNameOf(QString::fromUtf8(p)) + u(" 拉起(无人值守植入,T1219)")).hard()
                .actor(u("*\\") + u(t) + u("*.exe")).parent(p);
    // 【降级为 Ask】原注释说"正常用户装远控是走界面的",但这条模式【没有 actor 锚定】—— 它拦的是
    // 任何程序的命令行里出现 --silent-install,而静默安装参数是企业批量部署的通用做法(MDM / SCCM /
    // Intune / 各家装机脚本),被拦的多数其实是正常部署。而且 IT 远程支持工具本来就常以静默方式
    // 下发,这也是合规场景。判别性应该来自"装的是哪个远控",那由上面按远控映像名写的规则负责。
    s.proc(Ask, "远控工具静默安装(--silent-install / /S 无人值守,T1219)")
        .cmd("*--silent-install*");
    s.proc(Ask, "配置远控工具的无人值守密码(T1219)").cmd("*--set-password*");

    // ------------------------------------------------------------------
    // 8.2 远程执行与服务型横移
    // ------------------------------------------------------------------
    static const char* kPsexec[] = { "*\\psexec.exe", "*\\psexec64.exe", "*\\paexec.exe", "*\\psexesvc.exe" };
    for (const char* p : kPsexec)
        s.proc(Ask, u("运行远程执行工具 ") + imageNameOf(QString::fromUtf8(p)) +
                    u("(横向移动,T1569.002)"))
            .actor(p);
    // 【"sc" 只有两个字符,必须带后随空格】否则 `*sc*\\*create*` 会被任何含 "sc" 的词
    // (Discover、Desc…)加上一个 UNC 路径和 "create" 就凑出来 —— 这是 Block+hardOverride,
    // 误报代价是结束一个正常进程。
    s.proc(Block, "经 sc 在远程主机创建服务(sc \\\\host create,T1021.002)").hard()
        .cmd("*sc \\\\*create*");
    s.proc(Block, "经 sc.exe 在远程主机创建服务(T1021.002)").hard()
        .cmd("*sc.exe \\\\*create*");
    s.proc(Block, "经 sc 在远程主机启动服务(T1021.002)").hard().cmd("*sc \\\\*start*");
    s.proc(Block, "wmic 指定远程节点执行(T1047)").hard().actor("*\\wmic.exe").cmd("*/node:*");
    s.proc(Block, "经 WMI 在远程主机创建进程(Invoke-WmiMethod Create,T1047)").hard()
        .cmd("*invoke-wmimethod*create*");
    s.proc(Ask, "挂载远程主机的 IPC$ 管道共享(横移前置,T1021.002)").cmd("*net*use*ipc$*");
    s.proc(Ask, "挂载远程主机的 ADMIN$ 管理共享(T1021.002)").cmd("*net*use*admin$*");
    s.proc(Ask, "挂载远程主机的盘符管理共享 C$(T1021.002)").cmd("*net*use*\\\\*c$*");
    s.proc(Ask, "向远程主机管理共享复制文件(投递载荷,T1570)").cmd("*copy*\\\\*admin$*");
    s.proc(Ask, "经 PowerShell 远程会话执行命令(Invoke-Command -ComputerName,T1021.006)")
        .cmd("*invoke-command*-computername*");
    s.proc(Ask, "建立 PowerShell 远程会话(New-PSSession,T1021.006)").cmd("*new-pssession*");
    s.proc(Ask, "进入 PowerShell 远程会话(Enter-PSSession,T1021.006)").cmd("*enter-pssession*");
    s.proc(Ask, "经 winrs 在远程主机执行命令(T1021.006)").cmd("*winrs*-r:*");
    // wsmprovhost 是 WinRM 服务端落地执行的宿主:它派生脚本宿主就是「远程有人在这台机器上跑东西」。
    for (const QString& host : scriptHostActors())
        s.proc(Ask, u("远程 WinRM 会话宿主派生 ") + imageNameOf(host) +
                    u("(远程命令在本机落地执行,T1021.006)"))
            .parent("*\\wsmprovhost.exe").actor(host);

    // ------------------------------------------------------------------
    // 8.3 开启远程访问通道
    // ------------------------------------------------------------------
    s.reg(Ask, "开启远程桌面(Terminal Server\\fDenyTSConnections,T1021.001)")
        .target("*\\Control\\Terminal Server\\fDenyTSConnections");
    s.reg(Ask, "改写远程桌面端口(Terminal Server\\*\\PortNumber,T1021.001)")
        .target("*\\Control\\Terminal Server\\*\\PortNumber");
    s.reg(Ask, "允许多会话并发远程桌面(fSingleSessionPerUser,T1021.001)")
        .target("*\\Control\\Terminal Server\\fSingleSessionPerUser");
    s.proc(Block, "配置端口转发(netsh interface portproxy add,内网穿透/跳板,T1090.001)").hard()
        .actor("*\\netsh.exe").cmd("*portproxy*add*");
    s.proc(Ask, "为远程桌面放行防火墙规则(netsh advfirewall add rule 3389,T1021.001)")
        .actor("*\\netsh.exe").cmd("*add*rule*3389*");
    s.proc(Ask, "开启远程桌面(Set-ItemProperty fDenyTSConnections / reg add,T1021.001)")
        .cmd("*fdenytsconnections*");

    // ------------------------------------------------------------------
    // 8.4 隧道与反向代理
    // ------------------------------------------------------------------
    // 【降级为 Ask】"chisel" 这个词并不专属于那个隧道工具:它也是 Chisel 硬件描述语言(Scala 写的
    // RTL DSL)的名字,芯片/FPGA 方向的工程目录、构建命令、依赖名里到处都是;日常英文词义(凿子)
    // 也会出现在无关路径里。而本条是子串匹配 + Block + hardOverride,命中即结束进程树。
    s.proc(Ask, "运行 chisel 反向 TCP 隧道(T1572)").cmd("*chisel*");
    s.proc(Block, "经 plink 建立反向端口转发(plink -R,T1572)").hard().cmd("*plink*-r *");
    // ssh -R 是开发者真会用的正常能力(反向端口转发调试),故只询问 —— plink 在 Windows 终端上
    // 出现基本意味着有人带了 PuTTY 套件进来,那是另一回事。
    s.proc(Ask, "经 ssh 建立反向端口转发(ssh -R,开发调试亦用,T1572)").cmd("*ssh*-r *:*");
    s.proc(Block, "运行 lcx/iox 端口转发工具(T1090.001)").hard().cmd("*lcx*-slave*");
    // 这几个有明确的正当用途(开发调试、企业接入),故只询问。
    s.proc(Ask, "运行 ngrok 内网穿透(可被用作 C2 通道,T1572)").cmd("*ngrok*tcp*");
    s.proc(Ask, "运行 cloudflared 隧道(可被用作 C2 通道,T1572)").cmd("*cloudflared*tunnel*");
    s.proc(Ask, "运行 frp 客户端(内网穿透,T1572)").cmd("*frpc*-c*");
    s.proc(Ask, "运行 nps 客户端(内网穿透,T1572)").cmd("*npc*-server*");

    // ------------------------------------------------------------------
    // 8.5 反弹 shell
    // ------------------------------------------------------------------
    s.proc(Block, "PowerShell 反弹 shell(System.Net.Sockets.TCPClient,T1059.001)").hard()
        .cmd("*net.sockets.tcpclient*");
    s.proc(Block, "PowerShell 反弹 shell(TcpListener 监听等待连入,T1059.001)").hard()
        .cmd("*net.sockets.tcplistener*");
    // 一律按【带扩展名的映像名】写。裸 "nc" 是两个字符,且是 encode / function / since 这类
    // 常见英文里的子串,用在 Block+hardOverride 上会误杀正常进程。
    s.proc(Block, "netcat 反弹 shell(nc.exe -e cmd,T1059.003)").hard().cmd("*nc.exe*-e*cmd*");
    s.proc(Block, "netcat 反弹 shell(nc.exe -e powershell,T1059.001)").hard()
        .cmd("*nc.exe*-e*powershell*");
    s.proc(Block, "ncat 反弹 shell(ncat -e cmd,T1059.003)").hard().cmd("*ncat*-e*cmd*");
    s.proc(Block, "经 socat 建立交互式反弹通道(T1059)").hard().cmd("*socat*exec:*");

    // ------------------------------------------------------------------
    // 8.6 账户操纵与权限维持
    // ------------------------------------------------------------------
    s.proc(Ask, "创建本地账户(net user /add,T1136.001)").cmd("*net*user*/add*");
    s.proc(Ask, "创建本地账户(New-LocalUser,T1136.001)").cmd("*new-localuser*");
    s.proc(Ask, "把账户加入本地管理员组(net localgroup administrators /add,T1098)")
        .cmd("*localgroup*administrators*/add*");
    s.proc(Ask, "把账户加入本地管理员组(Add-LocalGroupMember,T1098)")
        .cmd("*add-localgroupmember*administrators*");
    s.proc(Block, "把账户加入域管理员组(net group \"domain admins\" /add,T1098)").hard()
        .cmd("*group*domain admins*/add*");
    s.proc(Ask, "启用被禁用的内置管理员账户(net user administrator /active:yes,T1078.001)")
        .cmd("*user*administrator*/active:yes*");
    s.proc(Ask, "创建域账户(net user /add /domain,T1136.002)").cmd("*net*user*/add*/domain*");
    s.proc(Ask, "隐藏账户不在登录界面显示(SpecialAccounts\\UserList,T1564.002)")
        .cmd("*specialaccounts*userlist*");

    // ------------------------------------------------------------------
    // 8.7 域侦察(只收「几乎只有攻击者才跑」的那几条)
    // ------------------------------------------------------------------
    // 刻意不收 whoami / ipconfig / tasklist / systeminfo / net view —— 那些是运维每天在用的
    // 只读命令,没有互证条件时写成规则纯粹是噪音。
    s.proc(Ask, "枚举域控制器列表(nltest /dclist,T1018)").cmd("*nltest*/dclist*");
    s.proc(Ask, "枚举域信任关系(nltest /domain_trusts,T1482)").cmd("*nltest*domain_trusts*");
    s.proc(Ask, "枚举域管理员组成员(net group \"domain admins\" /domain,T1069.002)")
        .cmd("*group*domain admins*/domain*");
    s.proc(Ask, "经 LDAP 查询枚举域对象(Get-ADUser -Filter *,T1087.002)")
        .cmd("*get-aduser*-filter*");
    static const char* kReconTool[] = {
        "*sharphound*", "*bloodhound*", "*adfind*", "*invoke-bloodhound*",
        "*powerview*", "*seatbelt*", "*sharpview*", "*adrecon*",
    };
    static const char* kReconLabel[] = {
        "SharpHound", "BloodHound", "AdFind", "Invoke-BloodHound",
        "PowerView", "Seatbelt", "SharpView", "ADRecon",
    };
    for (int i = 0; i < 8; ++i)
        s.proc(Block, u("域侦察工具特征:") + u(kReconLabel[i]) + u("(攻击链侦察阶段,T1087/T1069)")).hard()
            .cmd(kReconTool[i]);

    // ------------------------------------------------------------------
    // 8.8 C2 框架落地特征
    // ------------------------------------------------------------------
    static const char* kC2[] = {
        "*cobaltstrike*", "*beacon.dll*", "*metasploit*", "*meterpreter*",
        "*sliver*implant*", "*havoc*demon*", "*brute*ratel*", "*posh-c2*",
        "*empire*launcher*", "*koadic*",
    };
    static const char* kC2Label[] = {
        "Cobalt Strike", "Beacon 载荷", "Metasploit", "Meterpreter",
        "Sliver implant", "Havoc demon", "Brute Ratel", "PoshC2",
        "Empire launcher", "Koadic",
    };
    for (int i = 0; i < 10; ++i)
        s.proc(Block, u("C2 框架特征:") + u(kC2Label[i]) + u("(远控植入,T1219/T1071)")).hard()
            .cmd(kC2[i]);
}

} // namespace bulwark::engine::rules
