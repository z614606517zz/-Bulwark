//
// 段 4 · 凭据窃取(T1003 / T1555 / T1558)
//
// CredentialAccessAnalyzer 已覆盖 LSASS 远线程、comsvcs+MiniDump、sekurlsa/lsadump/mimikatz、
// reg save HKLM\SAM、ntds.dit、浏览器凭据库(软信号)、DPAPI 目录(软信号)。本段做两件它做不到的事:
//   1) 把 LSASS 相关的硬判据变成确定性 Block(硬指标 55 分在步骤 10 只换来「询问」,
//      而凭据一旦被读走,询问就没有意义了 —— 拒绝必须在动作之前);
//   2) 覆盖它没有的路径:SAM 蜂巢文件落地、RegBack、DPAPI 主密钥文件、Kerberos 票据攻击工具、
//      已知凭据窃取工具名。
//
// 【这一段刻意不写的东西】浏览器 Login Data / key4.db、DPAPI 主密钥的【读取】没有对应事件维度
// (本引擎没有 FileRead 事件),写成规则永远不命中。那一类只能靠 CredentialAccessAnalyzer 在
// 其它维度(写 / 删 / 进程行为)顺带捕捉,以及靠「非同应用树主体」那条软信号。
//
#include "RuleDsl.h"
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine::rules {

using detail::u;

void addCredentialAccessRules(QVector<DefenseRule>& out) {
    Segment s(out, "凭据窃取");

    // ------------------------------------------------------------------
    // 4.1 LSASS
    // ------------------------------------------------------------------
    s.thread(Block, "向 LSASS 注入远程线程(凭据窃取,T1003.001)").hard().target("*\\lsass.exe");
    s.thread(Block, "向 Credential Guard 隔离进程 lsaiso 注入远程线程(T1003.001)").hard()
        .target("*\\lsaiso.exe");
    // 结束 lsass 会直接导致系统崩溃/强制注销,没有任何正常理由 —— 这一条不分签名。
    s.kill(Block, "结束 LSASS 进程(系统凭据服务,结束即破坏,T1531)").hard().target("*\\lsass.exe");

    s.proc(Block, "经 comsvcs.dll 转储 LSASS 内存(rundll32 MiniDump,T1003.001)").hard()
        .cmd("*comsvcs*minidump*");
    static const char* kCredTool[] = {
        "*sekurlsa*", "*lsadump*", "*mimikatz*", "*invoke-mimikatz*", "*safetykatz*",
        "*pypykatz*", "*nanodump*", "*lsassy*", "*sharpdpapi*", "*lazagne*",
        "*dumpert*", "*handlekatz*", "*mimilib*",
    };
    static const char* kCredToolLabel[] = {
        "sekurlsa 模块", "lsadump 模块", "Mimikatz", "PowerShell 版 Mimikatz", "SafetyKatz",
        "pypykatz", "nanodump", "lsassy", "SharpDPAPI", "LaZagne",
        "Dumpert", "HandleKatz", "mimilib",
    };
    for (int i = 0; i < 13; ++i)
        s.proc(Block, u("凭据攻击工具特征:") + u(kCredToolLabel[i]) + u("(T1003.001)")).hard()
            .cmd(kCredTool[i]);
    // 「minidump」单独出现是崩溃上报组件的本职参数(ThreatDetector 已为此降为软信号),
    // 所以这里必须与 lsass 合取才出规则。
    s.proc(Block, "转储 LSASS 进程内存(procdump -ma lsass,T1003.001)").hard().cmd("*procdump*lsass*");
    s.proc(Block, "转储 LSASS 进程内存(minidump + lsass 合取,T1003.001)").hard().cmd("*minidump*lsass*");
    s.proc(Block, "经任务管理器/WER 创建 LSASS 转储(createdump lsass,T1003.001)").hard()
        .cmd("*createdump*lsass*");
    s.file(Block, "LSASS 内存转储文件落地(T1003.001)").hard().target("*lsass*.dmp");
    // 其它 .dmp 落地只在主体是脚本宿主时才可疑(崩溃上报组件天天写 .dmp)。
    for (const QString& host : scriptHostActors())
        s.file(Ask, u("脚本宿主 ") + imageNameOf(host) + u(" 写出进程内存转储文件(T1003)"))
            .target("*.dmp").actor(host);

    // ------------------------------------------------------------------
    // 4.2 SAM / SECURITY / SYSTEM 蜂巢
    // ------------------------------------------------------------------
    // 【模式末尾加空格】原来是 `*save*hklm\system*`,会把「备份某个服务子键」这种常规运维写法
    // 一起拦掉:`reg save HKLM\SYSTEM\CurrentControlSet\Services\Foo foo.hiv`。区别在于蜂巢名
    // 【后面跟什么】—— 导整个蜂巢时后面是分隔命令行参数的空格,备份子键时后面是 `\`。
    // 加一个空格就把两者分开了,同时 `reg save HKLM\SAM sam.hiv` 这类真导出照旧命中。
    //
    // 残留:加引号的写法(`reg save "HKLM\SAM" out.hiv`)因为蜂巢名后面是引号而不再命中本条。
    // 不在这里补形态,因为紧接下面的 `*reg*save*.hiv*` 覆盖了它 —— 除非攻击者把输出文件改成
    // 非 .hiv 扩展名,那种组合才会漏。
    static const char* kHive[] = { "hklm\\sam", "hklm\\security", "hklm\\system" };
    for (const char* h : kHive)
        s.proc(Block, u("导出注册表蜂巢 ") + u(h) + u("(本地口令哈希窃取,T1003.002)")).hard()
            .cmd(u("*save*") + u(h) + u(" *"));
    s.proc(Block, "经 reg.exe 导出全部本地蜂巢(reg save + hiv 落地,T1003.002)").hard()
        .cmd("*reg*save*.hiv*");
    // 蜂巢文件本体。正常改写者只有 Windows 更新(段 1 已放行 TrustedInstaller / TiWorker)。
    static const char* kHiveFile[] = {
        "*\\System32\\config\\SAM", "*\\System32\\config\\SECURITY",
        "*\\System32\\config\\SYSTEM", "*\\System32\\config\\RegBack\\*",
    };
    static const char* kHiveFileLabel[] = {
        "SAM", "SECURITY", "SYSTEM", "RegBack 蜂巢备份",
    };
    for (int i = 0; i < 4; ++i) {
        s.file(Ask, u("访问/改写本地凭据蜂巢 ") + u(kHiveFileLabel[i]) + u("(T1003.002)"))
            .target(kHiveFile[i]);
        s.del(Ask, u("删除本地凭据蜂巢 ") + u(kHiveFileLabel[i]) + u("(破坏或掩盖痕迹,T1003.002)"))
            .target(kHiveFile[i]);
    }
    // 卷影拷贝取蜂巢:vssadmin create shadow 之后从快照里直接复制 SAM。备份软件走 VSS API,
    // 不走 vssadmin 命令行,故这条的误报面很小 —— 但毕竟存在手工运维,给 Ask。
    s.proc(Ask, "创建卷影副本(可用于绕过文件锁读取 SAM/NTDS,T1003.002)")
        .actor("*\\vssadmin.exe").cmd("*create*shadow*");
    // 直接按卷影设备名匹配即可,不必把 \\?\GLOBALROOT\Device\ 前缀写进模式 —— 那段里的 '?'
    // 在本引擎的通配语义下是「任意单字符」,写进去只会让模式更难读,匹配结果并无不同。
    // 【降级为 Ask】走卷影副本读文件正是备份软件的标准工作方式 —— 要在文件被占用时取到一致的
    // 副本,只能从快照里读,所以备份/归档/磁盘镜像/数据库日志搬运都会出现这个设备名。
    // 判别性不在"从快照读",而在"读的是哪个文件";而本条只看命令行里的设备名,看不到那一层。
    // 真正取凭据库的形态由 4.2 节的蜂巢规则与 CredentialAccessAnalyzer 覆盖。
    s.proc(Ask, "从卷影副本路径复制文件(绕过文件锁取凭据库,T1003.002)")
        .cmd("*harddiskvolumeshadowcopy*");

    // ------------------------------------------------------------------
    // 4.3 域凭据:NTDS.dit
    // ------------------------------------------------------------------
    s.proc(Block, "经 ntdsutil IFM 导出域凭据库(T1003.003)").hard().cmd("*ntdsutil*ifm*");
    s.proc(Block, "经 esentutl 复制正在使用的 NTDS.dit(T1003.003)").hard().cmd("*esentutl*ntds*");
    // 【降级为 Ask】"命令行里提到 ntds.dit"不等于在窃取它:域控的备份脚本、健康巡检、容量统计、
    // 碎片整理(ntdsutil 的离线维护)都会把这个文件名写在命令行里。上面两条带动作词的
    //(`*ntdsutil*ifm*` / `*esentutl*ntds*`)才是判别性形态,保持 Block + hard 不动;
    // 这条只有文件名、没有动作,降为询问。
    s.proc(Ask, "命令行引用域凭据库 ntds.dit(T1003.003)").cmd("*ntds.dit*");
    s.file(Ask, "写入/复制域凭据库文件 ntds.dit(T1003.003)").target("*\\ntds.dit");
    s.del(Ask, "删除域凭据库文件 ntds.dit(破坏域控,T1485)").target("*\\ntds.dit");
    s.proc(Block, "DCSync 式凭据复制工具特征(T1003.006)").hard().cmd("*dcsync*");
    s.proc(Ask, "经 DSInternals 读取域账户哈希(T1003.006)").cmd("*get-adreplaccount*");

    // ------------------------------------------------------------------
    // 4.4 DPAPI / 凭据保管库 / 无线口令
    // ------------------------------------------------------------------
    // DPAPI 主密钥文件本身:只有 lsass 与本用户的正常解密流程会碰它,未签名主体写它没有理由。
    s.file(Block, "未签名程序改写 DPAPI 主密钥文件(凭据解密,T1003)").hard()
        .target("*\\Microsoft\\Protect\\*").unsignedOnly();
    // 【补 unsignedOnly】保管库文件由 Windows 自己在用户登录、保存网络凭据、RDP 记住密码等
    // 常规流程里改写,原来不分签名一律 Ask,是纯噪音。加签名条件后:签名主体的正常改写不再打扰,
    // 未签名主体碰保管库仍然询问。
    s.file(Ask, "改写 Windows 凭据保管库文件(T1555.004)")
        .target("*\\Microsoft\\Credentials\\*").unsignedOnly();
    s.proc(Ask, "枚举 Windows 凭据保管库(vaultcmd /list,T1555.004)").cmd("*vaultcmd*/list*");
    s.proc(Ask, "枚举已保存的凭据(cmdkey /list,T1555.004)").cmd("*cmdkey*/list*");
    s.proc(Ask, "导出无线网络明文口令(netsh wlan show profile key=clear,T1555)")
        .actor("*\\netsh.exe").cmd("*wlan*show*profile*key=clear*");
    s.proc(Block, "经 DPAPI 主密钥离线解密浏览器/系统凭据(SharpChrome 等,T1555.003)").hard()
        .cmd("*sharpchrome*");

    // ------------------------------------------------------------------
    // 4.5 Kerberos 票据攻击(T1558)
    // ------------------------------------------------------------------
    static const char* kKerb[] = { "*rubeus*", "*kekeo*", "*invoke-kerberoast*", "*ticketer*" };
    static const char* kKerbLabel[] = { "Rubeus", "Kekeo", "Invoke-Kerberoast", "ticketer" };
    for (int i = 0; i < 4; ++i)
        s.proc(Block, u("Kerberos 票据攻击工具特征:") + u(kKerbLabel[i]) + u("(T1558)")).hard()
            .cmd(kKerb[i]);
    s.proc(Ask, "枚举服务主体名(setspn -q,Kerberoast 前置,T1558.003)").cmd("*setspn*-q*");
    s.proc(Ask, "导出/清理 Kerberos 票据缓存(klist purge,T1558)").cmd("*klist*purge*");
}

} // namespace bulwark::engine::rules
