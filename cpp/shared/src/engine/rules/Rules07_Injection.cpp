//
// 段 7 · 注入 / DLL 侧载 / BYOVD(T1055 / T1574 / T1068)
//
// 【必须先搞清两条事件语义,否则这一段大半规则永不命中】
//   · ImageLoad:用户态模块【只上报 \Temp\ 与 \Users\Public\】。所以写 "*\programdata\*.dll"、
//     "*\downloads\*.dll" 的规则是结构性空转 —— 本段刻意不写。驱动(.sys)则是【用户可写目录
//     全部上报】,且此时 actorPath 是「内核(驱动加载)」,所以 .sys 规则只能按 target 写、
//     不能按 actor 写。
//   · 【本段原先这里写错了】原文称「ImageLoad 事件里的 actorSigned 表示被加载模块自身的签名」。
//     不是。`Worker::enrich` 第 1 步按 actorPid 把 actorPath 回填成【宿主进程】映像,第 4 步的
//     actorSigned 取的就是宿主的签名;内核模块加载时 actorPath 是伪串「内核(驱动加载)」,
//     不是真实文件,于是 actorSigned 恒假。也就是说 unsignedOnly() 用在 image 规则上,判的是
//     宿主 / 那个伪串,不是模块。
//     要判【模块自己】有没有可信签名,用 targetUnsignedOnly() / targetSignedOnly() ——
//     它们读 targetSigned / targetSignatureMismatch,由 Worker::enrich 专为 ImageLoad 富化。
//   · 【6b 已改,上面那段描述现在只适用于内核驱动加载】DefenseRule::matches 里的
//     unsignedOnly() / signedOnly() 现在分两种情况:
//       - 用户态模块加载(actorPid > 0):判【被加载模块】自身的签名。下面 7.3 那三条 %TEMP%
//         侧载规则因此真正活过来了 —— 此前它们判宿主签名,签名壳 + Temp 未签名 DLL 的白加黑
//         一条都不命中,是结构性漏检。
//       - 内核驱动加载(actorPid <= 0,actorPath 是伪串「内核(驱动加载)」):保持判主体,
//         也就是 actorSigned 恒假。具名 BYOVD 名单的 Ask 档依赖这一点(Worker 的「签名主体
//         默认放行」不会触发),所以这一侧刻意没跟着改。
//     要按【驱动自身】签名分档的规则,仍必须显式写 targetUnsignedOnly() / targetSignedOnly(),
//     段 7.4 的两组通用 .sys 规则就是这么做的。
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
    // sihost.exe:银狐 2026 用 sRDI 注入它(情报文档 [7])。它与本组另外四个同属「微软签名 +
    // System32 的 GUI 宿主」,被注入后载荷跑在一个看起来完全正常的进程里。
    static const char* kHostish[] = {
        "*\\explorer.exe", "*\\svchost.exe", "*\\dwm.exe", "*\\taskhostw.exe",
        "*\\sihost.exe",
    };
    for (const char* v : kHostish)
        s.thread(Ask, u("未签名程序向系统宿主进程 ") + imageNameOf(QString::fromUtf8(v)) +
                      u(" 注入远程线程(进程镂空的常见落点,T1055.012)"))
            .target(v).unsignedOnly();
    // 浏览器与邮件客户端:保持 Ask —— 注入它们确实有正常形态(无障碍辅助、输入法、密码管理器、
    // 截图与翻译工具都会往渲染进程里挂东西),硬拦的代价大于收益。本次刻意只动 IM 那一组。
    //
    // 【但要知道这一组现在实际是什么强度:对改了名的注入方是「放行」,不是「询问」】
    // 实测(bulwark_snapshot 重放):未签名程序位于 %APPDATA%\Microsoft\Update\setup.exe、
    // 向 chrome.exe 创建远程线程 —— riskScore 100、带硬指标,最终裁决却是 Allow 且
    // matchedRuleNote 为空。原因是步骤 6 的
    //   `if (hit.action == Ask && DefaultRules::isDevTool(e.actorPath)) -> Allow`
    // 把本组这条 Ask 降级了,而 isDevTool 是纯文件名匹配、名单里有 setup.exe。
    // 也就是说这一组对「会改名的攻击者」等于不存在,只对不改名的程序起作用。
    //
    // 这里【不】顺手把浏览器也提成 Block:那是另一个取舍(上面那批正常注入方多是签名的,但
    // unsignedOnly 挡不住未签名的国产输入法与截图工具),应当单独评估、单独承担误报面,
    // 不该搭车在一次「IM 群发防护」的改动里。留档在 docs/yinhu-threat-intel-2026.md §5.2。
    static const char* kSensitiveApp[] = {
        "*\\chrome.exe", "*\\msedge.exe", "*\\firefox.exe", "*\\outlook.exe",
    };
    for (const char* v : kSensitiveApp)
        s.thread(Ask, u("未签名程序向 ") + imageNameOf(QString::fromUtf8(v)) +
                      u(" 注入远程线程(会话劫持/信息窃取,T1055)"))
            .target(v).unsignedOnly();
    //
    // IM 进程单独一组并【提到 Block】。这是银狐劫持微信/QQ 群发的那一步本身,不是它的前兆。
    //
    // 【为什么原来的 Ask 挡不住】RuleEngine 步骤 6 里有
    //   `if (hit.action == Ask && DefaultRules::isDevTool(e.actorPath)) -> Allow`,
    // 而 isDevTool 是【纯文件名】匹配,名单里有 setup.exe / installer.exe / python.exe /
    // node.exe / agent.exe / runner.exe(DefaultRules.cpp 的 devToolProcessNames)。也就是说
    // 注入方把自己改名成 setup.exe,这条 Ask 就变成放行 —— 而改名是零成本的。本文件顶部 DSL
    // 注释的第 3 条硬约束说的正是这种情形:「凡是改名即可规避会造成实质漏防的判据,一律 Block」。
    //
    // 【提到 Block 没有不对称代价,这一点是本次核实过才敢改的】RemoteThread 的 Block 在
    // Worker::enforceBlock 里只走「结束注入方进程」一条路:那里的 blacklistExec 只在
    // e.type == ProcessCreate 时调,blockModuleLoad 只在 e.type == ImageLoad 时调。
    // 所以这一档【不会】往内核那两份只有 64 槽、只加不减、跨重启续拦的名单里写任何东西。
    //
    // 误报面也窄:unsignedOnly 已经把签名的输入法 / 安全软件 / 微信自己的多进程架构排除在外
    //(IM 自己的子进程互相注入由 RemoteControlAnalyzer::analyzeImInjection 的同族判断负责,
    // 规则层这里按 target 写,actor 是 IM 自己时同样是未签名才命中 —— 而 IM 都是签名的)。
    //
    // whatsapp.exe:银狐 2026 年的 WhatsApp 盗号链(情报文档 [12][13])。注入 IM 进程是
    // 「挂群控 / 拿会话」的标准形态,与微信系同档。
    static const char* kImApp[] = {
        "*\\wechat.exe", "*\\weixin.exe", "*\\wxwork.exe", "*\\qq.exe",
        "*\\tim.exe", "*\\whatsapp.exe",
    };
    for (const char* v : kImApp)
        s.thread(Block, u("未签名程序向即时通讯进程 ") + imageNameOf(QString::fromUtf8(v)) +
                        u(" 注入远程线程(挂群控/劫持会话,批量群发的直接手段,T1055)")).hard()
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

    // 镜像容器落地即提示(银狐 2026 主流投递形态:.vbs -> ZIP + 侧载 -> .img / .vhd,
    // 用 ISO9660 容器绕过 MOTW,见 docs/yinhu-threat-intel-2026.md §3.1 与 [10][12])。
    //
    // 【不加 unsignedOnly】写入方通常是签名的浏览器或 IM 客户端,加了等于永不命中。
    //
    // 这是一条廉价兜底,不是那条链的正解 —— 真正的修法是给 Worker::detectSideloadedTamperedModule
    // 的形态 ② 增加「模块位于非固定磁盘」这第三条互证(情报文档 §5.2 缺口 3),因为镜像里的
    // DLL 既不是系统 DLL 名、也从未在本机被写入过,两条既有互证同时失效。那属于另一轮。
    //
    // 【两处已核实的行为,读这条规则时要知道】
    //   · 它【不会】对签名写入方弹窗:Worker.cpp 在 trustSignedActors(默认开)下把签名健康
    //     主体的 Ask 降级为放行,只留一行日志。真正会弹的是未签名主体落镜像 —— 那正是要抓的。
    //   · 它是一条【无 actor 条件的 Ask】,命中即 return(RuleEngine 步骤 6),会短路步骤 10 的
    //     启发式。也就是说「高危未签名主体落一个 .iso」由本条给出 Ask,而不再由启发式给 Block。
    //     代价可接受:target 收得很窄(只有这四个扩展名),且降级后仍会弹窗由用户裁决。
    //
    // 已核对不与段 5.4 冲突:那里是 s.del 维度(删除备份文件 *.vhd),这里是 s.file 写入维度。
    static const char* kImageContainer[] = { "*.img", "*.iso", "*.vhd", "*.vhdx" };
    for (const char* ext : kImageContainer) {
        const QString e = QString::fromUtf8(ext).mid(1);   // 与本文件既有写法一致
        s.file(Ask, u("落地磁盘镜像容器 ") + e +
                    u("(绕过 MOTW 的投递容器,银狐 2026 主流形态,T1553.005)"))
            .target(ext);
    }

    // ------------------------------------------------------------------
    // 7.4 BYOVD:可写目录里加载驱动
    // ------------------------------------------------------------------
    //
    // 【这两组必须看驱动【自己】的签名】原来是无条件 Block + hardOverride:任何 .sys 从这些
    // 目录加载都拦,不问签名。真实事故:卡巴斯基把带 AO Kaspersky Lab 有效签名的 klids.sys
    // 装在 \ProgramData\ 下,于是每次加载都命中这条并被判成 BYOVD。hardOverride 的排序高于
    // 「已安装安全软件共存放行」,共存那一层根本轮不到;还顺带往内核 FileNoLoad 名单里钉了
    // 一条跨重启的永久条目(那份名单只有 64 槽、只加不减)。
    //
    // 分档判据是 targetUnsignedOnly() / targetSignedOnly() —— 读的是【被加载模块自身】的签名
    // (targetSigned),不是 actorSigned。内核模块加载的 actorPath 是伪串「内核(驱动加载)」,
    // 拿 unsignedOnly() 写在这里恒真,等于没写。
    //
    //   · 验不出可信签名 -> 保持 Block + hard。开了 DSE 的机器上这种驱动本来就加载不起来,
    //     它能出现只有两种解释:测试签名开着,或签名校验被绕过 —— 都没有正常用途。
    //   · 有可信签名 -> Ask。不能直接放行:BYOVD 用的驱动【都】有合法签名,那正是被选中的
    //     原因。但「安全软件 / 硬件厂商把签名驱动放在 ProgramData 或 Temp 下加载」是真实存在
    //     的正常形态,对它硬拦的代价远大于收益。与 A 组那 17 个具名驱动同一处置强度。
    //
    // 已知被滥用的具名驱动由下面三组名单按文件名拦,不受本分档影响(它们本来就不看签名)。
    //
    for (const QString& dir : dropDirFragments()) {
        s.image(Block, u("从可写目录 ") + dir + u(" 加载验不出签名的内核驱动(BYOVD,T1068)")).hard()
            .target(u("*") + dir + u("*.sys")).targetUnsignedOnly();
        s.image(Ask, u("从可写目录 ") + dir + u(" 加载带签名的内核驱动(自带易受攻击驱动,T1068)"))
            .target(u("*") + dir + u("*.sys")).targetSignedOnly();
    }
    s.image(Block, "从用户目录加载验不出签名的内核驱动(BYOVD,T1068)").hard()
        .target("*\\users\\*\\downloads\\*.sys").targetUnsignedOnly();
    s.image(Ask, "从用户目录加载带签名的内核驱动(BYOVD,T1068)")
        .target("*\\users\\*\\downloads\\*.sys").targetSignedOnly();
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
    // A' 组 = 银狐(Winos 4.0 / ValleyRAT)2026 年各条链里实际用过的驱动。
    //
    // 单列一组的理由是【处置强度不同】:这些驱动没有「用户自己装了某个硬件工具所以它就该在」
    // 的正常解释 —— amsdk / wamsdk 来自 WatchDog Antimalware、wsftprm 来自 Wise Force Deleter、
    // BootRepair / EnPortv 来自 Zeon、wnBios 来自 WnBios 内存访问库,它们要么早已停止分发、
    // 要么只在样本里出现。而且这批驱动的用途是【关掉杀软】(有的直接提供任意物理内存读写),
    // 一旦加载成功,本产品自身的内核回调也可能被摘掉 —— 这是「拦晚了就等于没拦」的一类,
    // 所以给 Block + hard,不留询问的时间窗。
    //
    // 仍然只在【用户可写目录】加载时才会产生 ImageLoad 事件(见本段开头的事件语义说明),
    // 所以正常安装到 System32\drivers 的同名驱动不受影响。
    static const char* kByovdSilverFox[] = {
        "amsdk.sys", "wamsdk.sys", "wsftprm.sys",
        "bootrepair.sys", "enportv.sys", "wnbios.sys", "wnbios64.sys",
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
    for (const char* d : kByovdSilverFox)
        s.image(Block, u("加载银狐(Winos 4.0 / ValleyRAT)惯用的易受攻击驱动 ") + u(d) +
                       u("(BYOVD 关杀软,T1068)")).hard()
            .target(u("*\\") + u(d));
    // 驱动落地即拦:这批驱动被【写到磁盘上】就已经没有正常解释了,不必等到加载。
    // FileWrite 的上报口径见本段开头(新建可执行体/脚本 + 删改全量),.sys 落地会被 ETW 看到。
    for (const char* d : kByovdSilverFox)
        s.file(Block, u("投放银狐惯用的易受攻击驱动 ") + u(d) + u("(BYOVD 前置,T1068)")).hard()
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
    // 上面两条只覆盖了 Temp 与 Public,而【ProgramData / AppData\Roaming / Downloads / Desktop
    // 才是银狐的主落点】(伪装 Telegram 语言包那条链注册的就是 AppShellElevationService)。
    // 服务的 binPath 指向这些目录同样没有正常解释:正规软件的服务可执行体装在
    // Program Files 或自己的 AppData\Local\Programs 安装目录下,不会挂在漫游/下载/桌面目录。
    // 刻意【不含 \appdata\local\】—— 那里有正规的 app-local 安装(*\AppData\Local\Programs\...),
    // 收进来会误拦一批按用户安装的正常软件。
    //
    // 【ProgramData 单独给 Ask】它是「所有用户共享的应用数据」的标准位置,确实有厂商把服务
    // 可执行体装在那里(部分国产安全软件的引擎目录、若干虚拟化与容器组件)。与段 2 的计划任务
    // 规则刻意排除 \programdata\ 同一个理由。其余四处没有「正规服务的可执行体住在那里」的解释,
    // 保留 Block + hard。
    {
        struct Zone { const char* frag; const char* label; };
        static const Zone kZones[] = {
            { "*binpath=*\\appdata\\roaming\\*",  "AppData\\Roaming" },
            { "*binpath=*\\downloads\\*",         "Downloads" },
            { "*binpath=*\\desktop\\*",           "Desktop" },
            { "*binpath=*\\windows\\temp\\*",     "Windows\\Temp" },
        };
        for (const Zone& z : kZones)
            s.proc(Block, u("创建指向 ") + u(z.label) + u(" 的服务(binPath 落在可写目录,T1543.003)")).hard()
                .cmd(z.frag);
        s.proc(Ask, "创建指向 ProgramData 的服务(binPath 落在共享数据目录,T1543.003)")
            .cmd("*binpath=*\\programdata\\*");
    }

    // ------------------------------------------------------------------
    // 7.5b 银狐伪装安装包链路里的 LOLBin
    // ------------------------------------------------------------------
    // zpaqfranz:合法的归档工具,被银狐当 LOLBin 用来解嵌套 ZPAQ 包(伪装 Telegram 中文语言包
    // 那条链:MSI custom action -> VBScript -> zpaqfranz 解包 -> PowerShell XOR 解密)。
    //
    // 【给 Ask 而不是 Block,两个理由,后一个是硬的】
    //   · 它本身是正经工具,拿它做备份 / 开发的用户确实存在,「运行了它」不等于已失陷;
    //   · ProcessCreate 的 Block 会走 enforceBlock -> blacklistExec,把【完整路径】钉进内核
    //     FileExecBlock —— 那份名单只有 64 槽、只加不减、由内核写回注册表持久化。而这个工具
    //     正是被投递到随机临时目录里运行的,每跑一次就是一个新路径,等于用一次性路径把全局
    //     名单烧穿,之后所有真正的恶意裁决都会因为没有槽位而被丢弃。本段 7.3 的 %TEMP% 侧载
    //     规则当初降级为 Ask,就是同一个原因。
    // Ask 不会被「isDevTool 按文件名放行」吃掉:zpaqfranz.exe 不在那份名单里。
    s.proc(Ask, "运行 zpaqfranz 解包(银狐用其解嵌套 ZPAQ 载荷,T1140)")
        .actor("*\\zpaqfranz.exe");
    //
    // 【刻意不在这里写「msiexec 拉起脚本宿主 / 拉起 Temp 里的未签名程序」这两类规则】
    //
    //   · 写成 Ask 会造成实质漏防:规则命中即 `return`(RuleEngine 步骤 6),直接跳过步骤 10
    //     的启发式处置。于是 `msiexec -> powershell -enc <一大段 base64>` 这种 risk 95 + 硬指标
    //     的事件会被这条宽 Ask 规则按下来变成「询问」—— 见本文件顶部 DSL 注释的第 3 条硬约束。
    //   · 写成 Block 会误拦正常安装:MSI 的 EXE 型自定义动作【本来就是】由 msiexec 把一个
    //     未签名的 MSIxxxx.tmp 解到 %TEMP% 再执行的,这是 Windows Installer 的标准行为。
    //
    // 所以这条判据不适合做成确定性规则,改由 ThreatDetector 按【软信号】计分(见那里的
    // 「MSI 自定义动作拉起脚本宿主」一节):它与未签名 / 可疑目录 / 命令行混淆等信号叠加,
    // 由既有流水线自己得出 Ask 还是 Block,既不短路启发式,也不单独定罪。

    // ------------------------------------------------------------------
    // 7.6 即时通讯客户端 hook(「银狐」一类 IM 群控 / 批量群发)
    // ------------------------------------------------------------------
    // RuleEngine 步骤 2b 的注释点名过这批规则:那里把「签名健康的 IM 主体」的放行范围锁回了
    // 网络维度,正是为了让这批 hook 模块的加载重新可被检测到。规则丢失则那处收紧白做。
    //
    // 【群发这条链在本引擎里哪一段可见、哪一段不可见 —— 先说清,免得照着不存在的维度写规则】
    // 银狐劫持微信/QQ 做群发的完整动作是:① 投放群控模块 -> ② 注入 IM 进程或白加黑侧载 ->
    // ③ 解密本地库拿通讯录与会话 -> ④ 遍历联系人并驱动发送。
    //   · ①②③ 分别落在 FileWrite / RemoteThread / ImageLoad / ProcessCreate 上,可见,由本段
    //     与 7.2 负责;
    //   · ④【结构性不可见】。真正的发送要么在被注入的微信进程内部直接调用其内部函数,要么走
    //     UI 自动化(FindWindow + PostMessage/SendMessage/SendInput、剪贴板、UIAutomation COM)。
    //     EventType 里没有窗口消息 / 输入合成 / 剪贴板任何一个维度(见 Enums.h),这两条路全程
    //     在进程内或 win32k 里完成,不产生进程、文件、注册表、网络事件。按 ④ 写规则是空转。
    // 所以这一类的检测只能锚在【前置条件】上,且前置条件必须拦得住 —— 到了 ④ 就只剩事后了。
    //
    // 【为什么这份名单必须写全,而不是「分析器已经给 55 分了」】实测过的一条完整漏防:
    // 一个未列名的群控模块(wcferry.dll / ntchat.dll / wxauto.dll …)落在 %TEMP%、被【合法签名的】
    // 微信加载,今天的裁决是【放行】,三步叠出来的:
    //   1) 它不匹配本名单任何一条 -> 没有 Block + hard 规则命中;
    //   2) 7.3 的通用规则「从 %TEMP% 加载未签名模块」(Ask)命中,RuleEngine 步骤 6 命中即 return,
    //      【短路掉步骤 10 的启发式】—— RemoteControlAnalyzer 给的 55 分 + 硬指标就此作废
    //      (而且 55 < ThreatDetector::HighRisk=80,就算不短路也只换来 Ask);
    //   3) Worker 在 trustSignedActors(默认开)下把签名健康主体的 Ask 降级为放行,只留一行日志。
    // 补进本名单即可翻盘:ruleTier 对 hardOverride 给 1、对 7.3 那条给 0,而层级是比较器的
    // 【第一级】(排在具体度之前),所以 Block + hard 稳定胜出 —— 这也正是本组刻意带 .hard() 的理由。
    //
    // 名单与 RemoteControlAnalyzer::groupControlModules() 对齐(那里是打分维度,这里是裁决维度)。
    // 刻意不收 comwechatrobot / cwechatrobot:两者都含 "wechatrobot",已被下面那条子串模式吃掉。
    static const char* kImHook[] = {
        "*wxhook*.dll", "*wxhelper*.dll", "*wechatsdk*.dll", "*vchat*.dll",
        "*wxapi*.dll", "*wechathook*.dll", "*wxdriver*.dll", "*wechatwin*hook*.dll",
        "*qqhook*.dll", "*imhook*.dll",
        // 以下为对齐 groupControlModules() 补入的部分(微信系)
        "*wxauto*.dll", "*wxbot*.dll", "*wxsender*.dll", "*wxdump*.dll",
        "*wechathelper*.dll", "*wechatspy*.dll", "*wechatrobot*.dll",
        "*wechatpcapi*.dll", "*wechatmanager*.dll", "*wechatferry*.dll",
        "*wcferry*.dll", "*wcprobe*.dll", "*ntchat*.dll",
        // QQ / TIM / 企业微信系
        "*qqbot*.dll", "*qqrobot*.dll", "*qqhelper*.dll", "*timhook*.dll",
        "*weworkhook*.dll", "*wework_api*.dll",
        // WeChatFerry 的 Python 绑定模块。【刻意写成 "*\wcf.dll" 而不是 "*wcf*.dll"】:
        // 后者三个字母太短,会撞上任意含 "wcf" 的模块名;前者带 "\" 前缀等价于【整个文件名
        // 精确等于 wcf.dll】。Windows 自身没有这个文件(WCF 的程序集都叫 System.ServiceModel.*)。
        "*\\wcf.dll",
    };
    for (const char* m : kImHook)
        s.image(Block, u("加载即时通讯 hook 模块 ") + u(m) + u("(IM 群控/消息劫持,T1055.001)")).hard()
            .target(m);
    //
    // 【同一批名字再补一个落地维度】——上面那组只在模块【被加载】时才有机会命中,而用户态
    // ImageLoad 的上报口径只有 \Temp\ 与 \Users\Public\ 两处(ImageMonitor.c 的
    // BlwPathIsSuspicious,与本段开头的事件语义说明一致)。于是群控 DLL 只要暂存到 ProgramData、
    // 或者干脆放进微信自己的聊天数据目录,加载那一刻【根本不产生事件】,上面一条都轮不到。
    //
    // FileWrite 这一侧没有这个盲区:ETW 对「用户可写目录里新建可执行体」是按后缀判的,
    // 名单含 .dll,目录含 \Users\ \ProgramData\ \Windows\Temp\ \Temp\ \PerfLogs\
    //(EtwProcessEventSource.cpp 的 isDroppedExecutable)。所以落地能看见的范围比加载宽得多。
    //
    // 与 7.4 对 kByovdSilverFox 的处理同一个形状(「加载即拦」+「落地即拦」两条),理由也同一个:
    // 这批名字被写到磁盘上就已经没有正常解释了,不必等到它被加载。
    //
    // 【不加 unsignedOnly】写入方常常是签名的解压工具 / 浏览器 / 安装器,加了等于永不命中。
    // FileWrite 的 Block 只结束写入方进程,不碰内核禁止执行名单(enforceBlock 里 blacklistExec
    // 只对 ProcessCreate 调),所以这一档没有「烧穿 64 槽」的不对称代价。
    for (const char* m : kImHook)
        s.file(Block, u("投放即时通讯群控模块 ") + u(m) + u("(批量群发/盗号前置,T1055.001)")).hard()
            .target(m);
    // 向 IM 安装目录植入 DLL:侧载宿主就绪的最后一步。
    //
    // 【WhatsApp 这一条的价值有限,但仍然写】它在 Windows 上主要以 Store / UWP 形式装在
    // \Program Files\WindowsApps\5319275A.WhatsAppDesktop_*\ 下,那棵子树普通用户写不进去,
    // 所以「未签名程序往里塞 DLL」这件事在正常权限下根本做不到(见情报文档 §5.2 缺口 2 的
    // 约束说明)。真正接住 WhatsApp 链路的是段 6.6 的父子链派生规则。
    // 保留本条的理由:非 Store 的旧版 / 侧载安装包确实装在可写目录下,且提权后 WindowsApps
    // 也不是不可写 —— 一条 Block 规则的成本只是一个名单项。
    static const char* kImDir[] = {
        "*\\Tencent\\WeChat\\*.dll", "*\\Tencent\\WXWork\\*.dll", "*\\Tencent\\QQ\\*.dll",
        "*\\Weixin\\*.dll", "*\\DingTalk\\*.dll", "*\\WhatsApp\\*.dll",
    };
    static const char* kImDirLabel[] = {
        "微信", "企业微信", "QQ", "微信(新版)", "钉钉", "WhatsApp",
    };
    // 条数从两张表推导,不写死 —— 与段 6.4 的 kPsCombo 同一个理由:写死的数字在增删条目时
    // 会静默错位,把某条模式配上另一条的标签(备注错了,派生出来的 id 也就错了)。
    static_assert(sizeof(kImDir) / sizeof(*kImDir) == sizeof(kImDirLabel) / sizeof(*kImDirLabel),
                  "kImDir 与 kImDirLabel 必须一一对应");
    for (size_t i = 0; i < sizeof(kImDir) / sizeof(*kImDir); ++i)
        s.file(Block, u("未签名程序向") + u(kImDirLabel[i]) + u("安装目录植入 DLL(侧载准备,T1574.002)")).hard()
            .target(kImDir[i]).unsignedOnly();
    //
    // 【聊天数据目录,与上面的安装目录分开写】这一组才是低门槛的那条路:
    //   · 上面那组指向 \Program Files\Tencent\... 与 \Program Files\WindowsApps\...,普通用户
    //     写不进去,得先提权;而且它们【不在】ETW 新建可执行体的上报目录名单里
    //     (isDroppedExecutable 的目录只有 \Users\ \ProgramData\ \Windows\Temp\ \Temp\ \PerfLogs\),
    //     所以那组实际只能靠驱动「偏移 0 写」的全局 1/32 采样被撞见 —— 存在,但不可靠。
    //   · 聊天数据目录在 \Users\<u>\Documents\ 下,【免提权可写】且【确实会上报】。
    //     攻击者没有任何理由选更难的那条路,所以这一组的实战价值高于上面一组。
    //
    // 这几个目录里只有聊天记录、图片、视频、小程序包(.wxapkg),【没有任何正常的 DLL】。
    // 加 unsignedOnly 兜住唯一可能的例外:微信/QQ 自己往自己数据目录写东西时是签名主体,不命中。
    static const char* kImDataDir[] = {
        "*\\WeChat Files\\*.dll",     // 微信 3.x
        "*\\xwechat_files\\*.dll",    // 微信 4.x(新版)
        "*\\Tencent Files\\*.dll",    // QQ / TIM
        "*\\WXWork\\*\\Cache\\*.dll", // 企业微信缓存
    };
    static const char* kImDataDirLabel[] = {
        "微信(3.x)聊天数据", "微信(新版)聊天数据", "QQ/TIM 聊天数据", "企业微信缓存",
    };
    // 条数从两张表推导,理由同上面 kImDir / kImDirLabel。
    static_assert(sizeof(kImDataDir) / sizeof(*kImDataDir) ==
                  sizeof(kImDataDirLabel) / sizeof(*kImDataDirLabel),
                  "kImDataDir 与 kImDataDirLabel 必须一一对应");
    for (size_t i = 0; i < sizeof(kImDataDir) / sizeof(*kImDataDir); ++i)
        s.file(Block, u("未签名程序向") + u(kImDataDirLabel[i]) +
                      u("目录植入 DLL(免提权的群控侧载暂存点,T1574.002)")).hard()
            .target(kImDataDir[i]).unsignedOnly();

    // ------------------------------------------------------------------
    // 7.6b 微信本地库解密/导出工具落地(群发的前置:先拿到通讯录与会话)
    // ------------------------------------------------------------------
    // 群发不是凭空发的 —— 得先有联系人列表。微信把这些放在本地加密 SQLite 里
    // (MicroMsg.db / MSG0.db / ChatMsg.db),于是「解密导出」成了这条链的固定一环,
    // 对应 RemoteControlAnalyzer::imAutomationTokens 里那批名字。
    //
    // 【只写 FileWrite,刻意不写 ProcessCreate】后者的 Block 会走 enforceBlock ->
    // blacklistExec,把【完整路径】钉进内核 FileExecBlock —— 那份名单只有 64 槽、只加不减、
    // 由内核写回注册表跨重启续拦、协议上没有「删除单条」。而这类工具正是被投递到随机临时目录
    // 里运行的,每跑一次就是一个新路径,等于用一次性路径把全局名单烧穿,之后所有真正的恶意
    // 裁决都会因为没有槽位而被丢弃。7.3 的 %TEMP% 侧载规则与 7.5b 的 zpaqfranz 当初降级,
    // 都是同一个原因。拦在落地这一步更早,也没有这份代价。
    //
    // 【也刻意不写命令行维度】这些是 6~11 字符的纯字母数字包名,而 DefenseRule 的通配匹配
    // 【没有词边界】:一条 cmd("*ntchat*") 会被命令行里的 base64 按概率撞中 —— 这不是假想,
    // RemoteControlAnalyzer::containsDelimitedToken 的注释记着实测事故(ssh.exe 的命令行含一段
    // 5424 字符 base64,于是被判「调用微信/QQ 自动化群控框架」)。那一侧已经用带词边界的匹配
    // 做对了,规则层再用裸通配抄一遍只会把修掉的误报放回来,而且规则命中会短路启发式。
    //
    // 这几个名字都是专为「解密微信本地库」而存在的工具,终端上没有正常用途,故 Block + hard。
    // 已知代价:在用户目录下的 venv 里 pip 装这类包会被拦下并结束 pip。那恰恰是该拦的动作,
    // 真有研究需要的用户可以在界面加白(加白后 blacklistExec / 禁止加载都会跳过该路径)。
    static const char* kWxDumpTool[] = {
        "*\\pywxdump.exe", "*\\wxdump.exe", "*\\sharpwxdump.exe", "*\\wechatmsg.exe",
    };
    for (const char* t : kWxDumpTool)
        s.file(Block, u("投放微信本地库解密/导出工具 ") + u(t) +
                      u("(窃取通讯录与会话,群发前置,T1005)")).hard()
            .target(t);

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
