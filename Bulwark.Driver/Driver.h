/*++
    Driver.h
    磐垒主动防御内核驱动 - 全局声明与共享状态。
--*/

#pragma once

#include <fltKernel.h>
#include <ntddk.h>
#include <wdm.h>
#include "Protocol.h"

#define BLW_TAG 'dhSI'   // 'IShd' 池标记

//
// ==================== 池分配:唯一入口(Win10 兼容性硬约束)====================
//
// 【绝不要改回 ExAllocatePool2】
//
// 本工程用 WDK/SDK 10.0.26100(Win11 24H2)编译,而 ExAllocatePool2 / ExAllocatePool3
// 是 ntoskrnl 从 **Windows 10 2004(build 19041)** 才开始导出的新 DDI。用它编译出的
// Bulwark.sys 会在导入表里留下一条 ExAllocatePool2 —— 于是在 1703 / 1709 / 1803 /
// 1809(含 LTSC 2019)/ 1903 / 1909 这些仍在服役的 Win10 上,加载器解析导入直接失败:
//
//     STATUS_PROCEDURE_NOT_FOUND (0xC0000139) -> 驱动【整个加载不起来】
//
// 后果不是「少一个功能」,而是全部内核防护(执行前拦截 / 文件反篡改 / 注册表硬拦 /
// 自保护 / 网络阻断)一起消失,用户态服务降级成 WMI 观测模式 —— 表现就是「在 Win10 上
// 时好时坏、拦不住东西」。而开发机是 Win11,这个问题在开发机上永远不会复现。
//
// 微软对此的官方指引(见 ExAllocatePool2 文档 "targeting versions of Windows prior to
// Windows 10, version 2004")就是改用 ExAllocatePoolZero。但 26100 的头文件里,
// ExAllocatePoolZero 的 down-level 零初始化分支要靠 POOL_ZERO_DOWN_LEVEL_SUPPORT 打开,
// 而该宏又引用了这套头文件里【并不存在】的 SYSTEM_POOL_ZEROING_INFORMATION(实测:
// 26100 全套 km/shared 头里搜不到该类型),一开就编不过。
//
// 所以这里自己包一层:底层只用 ExAllocatePoolWithTag —— 自 NT 起就有、每个在服役的
// Windows 都导出 —— 再显式清零。语义与 ExAllocatePool2(POOL_FLAG_*) 完全一致
// (同样返回全零内存),但导入表里不再有任何带版本门槛的符号。
//
// 顺带说明本驱动【当前】的真实最低版本:去掉 ExAllocatePool2 之后,导入表里剩下的最高
// 门槛来自 WFP 的 FwpsCalloutRegister3(Win10 1703 / build 15063 起导出),因此实际底线
// 是 1703。这条底线由构建后的导入表检查(Bulwark.Driver.vcxproj 里的 BlwVerifyImportFloor)
// 把守 —— 那里也记录了「为什么不能用 NTDDI_VERSION 钉死」,别再走那条路。
//
// 池类型映射:POOL_FLAG_PAGED -> PagedPool;POOL_FLAG_NON_PAGED -> NonPagedPoolNx
// (显式写 NonPagedPoolNx 而不是 NonPagedPool:后者在 POOL_NX_OPTIN 下是个变量,
//  语义依赖 ExInitializeDriverRuntime 已经跑过;写死 NX 更直白,且 Win8 起即支持)。
//
FORCEINLINE PVOID
BlwAllocPool(_In_ POOL_TYPE PoolType, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag)
{
    PVOID p;

    // 4996/28751:ExAllocatePoolWithTag 被标记为 deprecated。这里是【刻意】使用它 ——
    // 它是唯一在所有目标 Windows 版本上都存在的池分配导出,理由见上方大段说明。
#pragma warning(suppress: 4996 28751)
    p = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
    if (p != NULL) {
        RtlZeroMemory(p, NumberOfBytes);
    }
    return p;
}

//
// ============================ 架构总则:零同步 IPC ============================
//
// 历史教训:旧实现在注册表/文件回调里「同步 FltSendMessage 等用户态裁决(最长 1s)」。
// 受保护键用的是 \Services / \Internet Settings 等系统高频写入的宽子串,导致每次写入
// 都把内核线程阻塞最长 1 秒;而用户态回复管线又慢(签名校验 + 证书吊销网络查询 + 哈希)
// 且会重入内核回调,4 个富化 worker 一旦全部卡住就没有任何裁决产出 ——
// 全系统线程被逐个卡满 → 彻底卡死。
//
// 新架构的硬性铁律:
//   * 任何内核回调都【绝不】调用「带回复 / 非零超时」的 FltSendMessage。
//   * 需要实时拦截的防护(文件反篡改),裁决【完全在内核本地】用已下发的配置完成,
//     不依赖任何用户态往返 —— 本地查表是微秒级,既实时又永不卡死。
//   * 其余防护一律 fire-and-forget 异步遥测(0 超时,用户态来不及收就丢弃这条遥测),
//     由用户态规则引擎事后处置(启动后结束进程等)。
//
// 因此本头文件不再有任何「裁决超时」常量 —— 内核永不等待用户态。
//
#define BLW_MAX_PROTECTED 64   // 最多保护的路径条数

// 卸载时注销 WFP callout 的退让重试:关引擎之后,在途 classify 排空需要一点时间,
// 期间 FwpsCalloutUnregisterById 会返回 STATUS_DEVICE_BUSY。总等待上限 = 5 × 50ms = 250ms,
// 足够覆盖排空,又不会把 fltmc unload 拖成"看起来卡住"。用尽仍失败则拒绝卸载(见 BlwFilterUnload)。
#define BLW_WFP_UNREG_RETRIES  5
#define BLW_WFP_UNREG_DELAY_MS 50

// 内核本地「事后研判」:已知恶意 SHA-256 集合上限与待扫描 PID 队列容量。
#define BLW_MAX_HASHES     1024  // 内置已知恶意哈希上限(32KB;线性匹配,off 热路径)
#define BLW_HASH_QUEUE_CAP 128   // 待扫描 PID 环容量(满则丢弃,漏扫下次仍会扫)
// 必须是 2 的幂:下标推进用位与而非取模(下标为有符号 LONG,编译器无法把 % 优化成位与)。
#define BLW_HASH_QUEUE_MASK (BLW_HASH_QUEUE_CAP - 1)
C_ASSERT((BLW_HASH_QUEUE_CAP & BLW_HASH_QUEUE_MASK) == 0);

//
// ============ PID 集合的「无锁布隆快速否决」位 ============
//
// 四个 PID 集合(受保护 / 反注入 / 凭据保护 / 已封禁)都是 64 槽线性表。而查表发生在
// 内核里最高频的位置:ObCallbacks 句柄回调对【全系统每一次进程/线程句柄打开或复制】都要
// 查最多 4 个集合;BlwPidIsBanned 还额外出现在每次文件 CREATE / SET_INFO / WRITE、
// 每次注册表写、每次外发连接(DISPATCH_LEVEL)、每次进程创建上。原实现每次都要遍历
// 64 个 volatile 槽,绝大多数结果是「不在集合中」—— 这些遍历全是白费。
//
// 优化:为每个集合额外维护一个 64 位掩码,PID 映射到 1 位(Windows 的 PID 恒为 4 的倍数,
// 故先 >>2 再取低 6 位,分布均匀)。查表先做【一次 64 位原子读 + 一次位测试】:位为 0 即
// 该 PID 绝不在集合中,立刻返回 —— 把「64 次内存访问」降为「1 次」。位命中时才退回原来的
// 线性扫描给出最终判定,故【判定结果与原实现完全一致】(布隆只会误报、绝不漏报)。
//
// 写侧的定序铁律(保证任何时刻都不会出现「集合里有、掩码里没有」的假否决):
//   * 加入:先 OR 上掩码位,再写入槽位  —— 读者若看到位已置但槽未写,线性扫描返回 FALSE,
//     等价于「尚未加入」,安全。
//   * 摘除:先清空槽位,再重算掩码      —— 读者若看到旧掩码位仍置,线性扫描返回 FALSE,
//     等价于「已摘除」,安全。
//   * 摘除时的重算与并发加入互斥(BannedLock),否则重算可能把刚加入的 PID 的位擦掉,
//     造成真正的假否决。只有【已封禁】集合存在并发写(进程退出摘除 vs 情报确认加入),
//     故仅它需要这把锁;其余三个集合只在配置下发(单线程)时变更。
//
#define BLW_PID_BIT(pid)  (1ULL << (((pid) >> 2) & 63))

// 网络黑名单 IP 的布隆位。IPv4 低位变化最快,先把高位折下来再取 6 位,避免同一网段全撞一位。
// 只对 IP 取位、不含端口:端口为 0 的条目匹配任意端口,故「IP 位未置」才是可靠的否决条件。
#define BLW_IP_BIT(ip)    (1ULL << ((((ip) >> 13) ^ (ip)) & 63))

//
// 一条受保护路径(子串匹配,大小写不敏感)。
//
// 【存储约定】Path 里保存的是【已大写化】的模式串(由 BlwAddToList 在加入时归一化一次)。
// 匹配始终是大小写不敏感的,预先归一化模式串使热路径上的比较退化为纯宽字符比较,不必再
// 对每个滑动窗口做一次大小写不敏感的整串比较(见 BLW_MATCH_CTX)。
// 副作用仅是「写回注册表 \Policy 的名单是大写形式」—— 这些值只被本驱动自己读回(读回后
// 再次归一化,幂等),用户态从不比较它们,故无任何行为影响。
//
typedef struct _BLW_PROTECTED_PATH {
    WCHAR   Path[BLW_MAX_PATH];   // 已大写化的模式串
    USHORT  Length;            // 字符数
    BOOLEAN InUse;
} BLW_PROTECTED_PATH, *PBLW_PROTECTED_PATH;

//
// ============ 大小写不敏感子串匹配的公共基元 ============
//
// 归一化单个宽字符,与 RtlCompareUnicodeString(..., TRUE) 共用同一套 Unicode 大写表,
// 因此基于它的比较与原来的「大小写不敏感整串比较」结果逐字符等价。
// ASCII(路径里的绝大多数字符)走内联快路,只有非 ASCII 才调 RtlUpcaseUnicodeChar。
// 可在任意 IRQL 调用。
//
FORCEINLINE WCHAR
BlwUpcaseChar(_In_ WCHAR c)
{
    if (c >= L'a' && c <= L'z') {
        return (WCHAR)(c - L'a' + L'A');
    }
    if (c < 0x80) {
        return c;   // 其余 ASCII 的大写形式就是自身
    }
    return RtlUpcaseUnicodeChar(c);
}

//
// 预归一化的匹配目标。
//
// 一次文件 IRP_MJ_CREATE 最多要对 4 个名单做子串匹配,一次注册表写要对 2 个。原实现每个
// 名单、每个模式、每个窗口偏移都要重新做大小写归一化,同一条路径被反复归一化几十上百次。
// 现在改为:回调里把目标串【一次性】大写化进 Up[],之后所有名单匹配都只是宽字符比较
// (命中首尾字符后直接 RtlEqualMemory 整段),归一化成本从 O(名单数 × 模式长 × 路径长)
// 降到 O(路径长)。
//
// 目标超过 BLW_MAX_PATH 字符时不做预归一化(Chars=0),改由 Original 走「即时归一化」的
// 回退路径 —— 语义与快路径完全一致,只是不缓存归一化结果。这样绝不会因为路径过长而
// 漏掉本该命中的名单项(超长路径正是攻击者可能用来绕过的手法)。
//
typedef struct _BLW_MATCH_CTX {
    PCUNICODE_STRING Original;      // 原始目标(仅在 Chars==0 的回退路径使用,须在 ctx 生命周期内有效)
    USHORT           Chars;         // Up 中的有效字符数;0 = 未预归一化(走 Original 回退)
    WCHAR            Up[BLW_MAX_PATH];   // 已大写化的目标
} BLW_MATCH_CTX, *PBLW_MATCH_CTX;

// 一条网络黑名单(IPv4 + 端口,端口 0 表示任意)
typedef struct _BLW_BLOCK_IP {
    ULONG   IpV4;              // 主机字节序
    USHORT  Port;              // 0 = 任意端口
    BOOLEAN InUse;
} BLW_BLOCK_IP, *PBLW_BLOCK_IP;

// 驱动全局上下文
typedef struct _BLW_GLOBALS {
    PFLT_FILTER     Filter;          // Minifilter 句柄
    PFLT_PORT       ServerPort;      // 服务端口
    PFLT_PORT       ClientPort;      // 已连接的用户态客户端端口(单连接)
    EX_RUNDOWN_REF  ClientPortRundown; // 保护 ClientPort 使用与关闭的竞争:
                                       // 发送方先 acquire,断开时 wait-for-idle 后再关闭,
                                       // 避免对已释放端口做 FltSendMessage(use-after-free 蓝屏)。
    BOOLEAN         ProcessCallbackRegistered;
    volatile BOOLEAN Active;         // 是否已连接客户端并启用拦截。volatile:由连接/断开回调写,
                                     // 由所有拦截回调读,不能让编译器把它缓存进寄存器。
                                     //
                                     // 注意:NextEventId 已【移到下面的事件队列块】。它原本紧邻
                                     // Active,而它每产生一条事件就要 InterlockedIncrement64 一次 ——
                                     // 于是每条事件都会把「所有拦截回调都在读」的 Active 所在缓存行
                                     // 在其它核上作废(伪共享)。挪到队列块后,这个写只会碰
                                     // 本来就在被同一把 RingLock 写的那条缓存行。

    // 文件防护:受保护路径列表(子串匹配,大小写不敏感)
    BLW_PROTECTED_PATH ProtectedPaths[BLW_MAX_PROTECTED];
    FAST_MUTEX      PathLock;        // 保护 ProtectedPaths 的访问
    volatile LONG   ProtectedPathCount; // 当前 InUse 项数(快速判空,避免每次 I/O 都拿锁查询)

    // 文件「内核硬拦截」名单:命中即内核本地拒绝任何【写/删/重命名/覆盖】打开
    // (STATUS_ACCESS_DENIED),不发 IPC、不等用户态 —— 真·原地阻断且零延迟。
    // 比 ProtectedPaths 更强:不仅防删除/重命名,还防内容篡改(只读打开仍放行)。
    // 仅用于「绝不允许被改一次」的关键文件(如 hosts、sethc.exe、SAM)。
    BLW_PROTECTED_PATH FileHardBlock[BLW_MAX_PROTECTED];
    FAST_MUTEX      FileHardLock;    // 保护 FileHardBlock 的访问
    volatile LONG   FileHardCount;   // 当前 InUse 项数(快速判空)

    // 自保护足迹(owner-aware 反勒索):本产品「完整内容」所在的路径子串(安装目录全部文件 +
    // %ProgramData%\Bulwark 数据目录 + 驱动 .sys)。命中且为【写/删/改名】打开时,除【本产品自身
    // 受保护进程(BlwPidIsProtected)与内核态】外,一律 STATUS_ACCESS_DENIED —— 勒索病毒/任何外部
    // 进程都无法加密/篡改/删除本产品的任何文件,而本产品自身仍可正常读写自己的数据(信誉缓存/规则/
    // 日志/隔离区等持续写入)。这正是与 FileHardBlock 的关键区别:FileHardBlock 对所有人(含本产品)
    // 拒写,只适合永不变的文件;SelfGuard 放行属主,故可覆盖持续写入的数据目录。
    // 不持久化(不写 \Policy):由服务连接时下发、断连时清除,从而更新/卸载本产品无需先卸载驱动
    //(停服务即解除自保,复制新文件后再启动)。owner 判定复用自我保护的受保护 PID 集。
    BLW_PROTECTED_PATH SelfGuard[BLW_MAX_PROTECTED];
    FAST_MUTEX      SelfGuardLock;   // 保护 SelfGuard 的访问
    volatile LONG   SelfGuardCount;  // 当前 InUse 项数(快速判空,未启用时热路径零开销)

    // 「禁止加载」模块名单:命中且本次打开带【执行/映射】意图时,内核本地直接拒绝
    // (STATUS_ACCESS_DENIED),使该模块无法被任何进程加载/映射执行。
    // 专治白加黑:把已确认恶意的侧载 DLL 钉死,合法签名宿主下次也无法再侧载它。
    // 与 FileHardBlock 互补:那个拦「写/删/改」,这个拦「执行加载」;只读数据访问不受影响。
    BLW_PROTECTED_PATH FileNoLoad[BLW_MAX_PROTECTED];
    FAST_MUTEX      FileNoLoadLock;  // 保护 FileNoLoad 的访问
    volatile LONG   FileNoLoadCount; // 当前 InUse 项数(快速判空)

    // 「禁止执行」名单(执行前拦截):进程创建回调里,新进程映像路径命中该名单即内核本地
    // 直接把 CreateInfo->CreationStatus 置为 STATUS_ACCESS_DENIED,使已确认恶意的样本
    // 【根本无法启动】。与 FileNoLoad 互补:那个拦「DLL/模块被加载」,这个拦「进程被创建」。
    // 零用户态往返、无竞态,补上「事后 kill 让样本先跑几十毫秒」的短板。名单由用户态在
    // VT/规则/记忆确认恶意后下发其映像路径,重启后重推保持持久。关键系统进程绝不受影响(防蓝屏)。
    BLW_PROTECTED_PATH FileExecBlock[BLW_MAX_PROTECTED];
    FAST_MUTEX      FileExecBlockLock;  // 保护 FileExecBlock 的访问
    volatile LONG   FileExecBlockCount; // 当前 InUse 项数(快速判空,进程创建热路径先查计数再决定是否解析)

    // 「命令行硬拦」名单(执行前拦截·按用法而非按身份):进程创建回调里,新进程的【完整命令行】
    // 命中该名单即内核本地直接把 CreateInfo->CreationStatus 置为 STATUS_ACCESS_DENIED,
    // 危险命令【根本不会执行】。
    //
    // 为什么必须在内核做:LOLBin(vssadmin / wmic / powershell / certutil / bcdedit ...)本体位于
    // System32、签名可信、路径受 WRP 保护 —— 无论怎么按「身份」判定都是可信的,威胁完全来自
    // 「用法」。原实现为此在内核给 LOLBin 开了个口子(不走可信路径快速放行),把命令行交给用户态
    // 检测,于是回到「事后 kill」模型:`vssadmin delete shadows` 这种一瞬间就完成的破坏性命令,
    // 等用户态裁决回来时卷影早已删干净,kill 掉进程也无法挽回。而 PS_CREATE_NOTIFY_INFO.CommandLine
    // 在内核回调里本来就【直接可读】,本地查表是微秒级 —— 这是纯粹的能力浪费。
    //
    // 与 FileExecBlock 的分工:那个按【映像路径】拦(已确认恶意的样本不许启动),这个按【命令行
    // 用法】拦(可信程序不许被用来做特定破坏动作)。两者互补,共用同一套名单/持久化/护栏机制。
    // 模式语法是 '+' 分隔的 token 合取(见 Protocol.h 的 BLW_CMD_ADD_CMDBLOCK),故参数顺序、
    // 空格数量、大小写、是否带全路径都绕不过去。
    BLW_PROTECTED_PATH CmdHardBlock[BLW_MAX_PROTECTED];
    FAST_MUTEX      CmdHardLock;     // 保护 CmdHardBlock 的访问
    volatile LONG   CmdHardCount;    // 当前 InUse 项数(快速判空:为 0 时进程创建热路径完全不碰命令行)

    // 文件行为遥测开关(BLW_CMD_SET_FILETELEMETRY 下发)。开启后,内核对未命中任何
    // 名单的「重命名 / 删除标记」操作做 fire-and-forget 上报(绝不阻断),供用户态
    // 勒索行为时序聚合。默认关闭,避免无谓的事件量。仅观测高价值的删/改名信号,
    // 不上报普通写(普通写量极大,会拖垮上报通道)。
    volatile LONG   FileTelemetryEnabled;

    // 写采样计数器(就地加密检测):IRP_MJ_WRITE 钩子对"偏移 0 起写"按
    // BLW_WRITE_SAMPLE_RATE 取模采样,避免对每次写都解析文件名。仅诊断/节流用。
    //
    // 【独占一条缓存行】它是真正被多核并发写的原子量(每次「偏移 0 起写」一次带锁 xadd),
    // 而紧挨着的 FileTelemetryEnabled 是每次 CREATE / SET_INFO / WRITE 都要读的门闸。
    // 若同处一行,勒索式批量改写会让这条被全系统文件 I/O 高频读取的行不断在各核间作废。
    // 故给它单独一行:前面用 DECLSPEC_CACHEALIGN 对齐,后面紧跟的成员也对齐以隔断尾部。
    DECLSPEC_CACHEALIGN volatile LONG WriteSampleCounter;

    // 注册表防护
    DECLSPEC_CACHEALIGN LARGE_INTEGER RegCookie;  // CmRegisterCallbackEx 返回的 cookie
    BOOLEAN         RegCallbackRegistered;
    BLW_PROTECTED_PATH ProtectedRegKeys[BLW_MAX_PROTECTED]; // 受保护注册表键(子串)
    FAST_MUTEX      RegLock;         // 保护 ProtectedRegKeys 的访问
    volatile LONG   ProtectedRegCount; // 当前 InUse 项数(快速判空,避免每次写键都解析键路径)

    // 注册表「内核硬拦截」名单:命中即内核本地直接拒绝写入(STATUS_ACCESS_DENIED),
    // 不发 IPC、不等用户态 —— 真·原地阻断且零延迟。仅用于极少数「绝不允许被改一次」的
    // 精确键值(如 Winlogon\Shell、IFEO\<exe>\Debugger),名单必须精确,绝不可放宽热键。
    BLW_PROTECTED_PATH RegHardBlock[BLW_MAX_PROTECTED];
    FAST_MUTEX      RegHardLock;     // 保护 RegHardBlock 的访问
    volatile LONG   RegHardCount;    // 当前 InUse 项数(快速判空)

    // 自我保护(ObRegisterCallbacks)
    PVOID           ObRegHandle;     // ObRegisterCallbacks 返回句柄
    BOOLEAN         ObCallbackRegistered;
    volatile LONG   ProtectedPids[BLW_MAX_PROTECTED]; // 受保护进程 PID(0 表示空槽)
    volatile LONG64 ProtectedPidMask;                 // 布隆快速否决位(见 BLW_PID_BIT)

    // 内存防护(反注入):高价值受害进程 PID 列表(0 表示空槽)。
    // 非可信进程对这些 PID 申请「写内存 / 远程线程」类权限时,在同一个 ObCallbacks
    // 回调里剥离这些权限,使跨进程注入写不进去。与 ProtectedPids 复用回调,
    // 区别仅在「保护对象不同 + 剥离的权限集不同」。PID 由用户态在 PASSIVE 解析
    // 高价值进程后下发,内核回调只做无锁 PID 查表(任意 IRQL 安全)。
    volatile LONG   MemProtPids[BLW_MAX_PROTECTED];
    volatile LONG64 MemProtPidMask;                   // 布隆快速否决位(见 BLW_PID_BIT)

    // 凭据保护(反转储):凭据存储进程 PID 列表(主要是 lsass;0 表示空槽)。
    // 在 MemProtPids 的「反注入」基础上【额外剥离 PROCESS_VM_READ】—— 读 lsass 内存正是
    // mimikatz 等凭据转储的核心手段。非可信进程对这些 PID 申请 读/写内存/内存操作/远程线程/
    // 挂起 权限时,在同一 ObCallbacks 回调里一并剥离,凭据既读不出、也注入不进。保留
    // QUERY/TERMINATE(不影响进程枚举/管理)。System(4)/本软件受保护进程/目标自身操作豁免。
    volatile LONG   CredProtPids[BLW_MAX_PROTECTED];
    volatile LONG64 CredProtPidMask;                  // 布隆快速否决位(见 BLW_PID_BIT)

    // 已封禁主体(情报确认恶意的 PID):这些 PID 的【任何】文件写/删/改、注册表写、网络外联、
    // 创建子进程,在各回调里一律 STATUS_ACCESS_DENIED —— 不依赖「杀进程」的时机,做到「情报一确认
    // 即全维封杀」。即便结束进程被反抗/滞后,这期间它也一个动作都做不成。由驱动 HashScan 命中内置
    // 已知恶意集时自动登记,或由用户态在信誉/规则确认恶意时下发。无锁 Interlocked 读写(任意 IRQL 可查);
    // BannedPidCount 供热路径先判空(空则零额外开销);进程退出时移除对应 PID(防 PID 复用误伤)。
    volatile LONG   BannedPids[BLW_MAX_PROTECTED];
    volatile LONG   BannedPidCount;
    volatile LONG64 BannedPidMask;   // 布隆快速否决位(见 BLW_PID_BIT)
    KSPIN_LOCK      BannedLock;      // 仅【写侧】互斥(加入 / 摘除 / 清空);读侧全程无锁。
                                     // 唯一存在并发写的 PID 集合:进程退出摘除 vs 情报确认加入,
                                     // 若不互斥,摘除时的掩码重算可能擦掉刚加入 PID 的位(假否决)。

    // 网络防护(WFP)
    //
    // 状态机(全部在 WfpLock 下变更,见 NetMonitor.c):
    //   WfpCalloutId != 0     内核 callout 已注册(在 netio 里,不随 BFE 消失)
    //   WfpEngine    != NULL  引擎已开 + 管理层 callout/sublayer/filter 已加(随 BFE 消失)
    //   WfpRegistered         上面两半都就绪 = 网络防护真正生效
    // 这三者【必须分开看】:BFE 未就绪时可能出现"callout 有、引擎没有"的半就绪态,
    // 只看 WfpRegistered 会在卸载时漏拆那个已注册的 callout —— 悬空指针。
    HANDLE          WfpEngine;       // WFP 引擎句柄(动态会话:关闭即移除本驱动加的对象)
    UINT32          WfpCalloutId;    // 已注册 callout 的运行时 id
    UINT64          WfpFilterId;     // 已添加 filter 的 id
    BOOLEAN         WfpRegistered;
    PDEVICE_OBJECT  WfpDeviceObject; // 注册 callout 需要的设备对象
    HANDLE          WfpBfeSubscription; // BFE 状态变更订阅句柄(延迟拉起 + BFE 重启后重建)
    FAST_MUTEX      WfpLock;         // 串行化 WFP 拉起 / 拆除 / BFE 状态回调三方
    BLW_BLOCK_IP    BlockList[BLW_MAX_PROTECTED]; // 网络黑名单
    KSPIN_LOCK      NetLock;         // 保护 BlockList(WFP classify 可能在 DISPATCH_LEVEL,
                                     // 必须用自旋锁而非 FAST_MUTEX,否则会触发 IRQL_NOT_LESS_OR_EQUAL 蓝屏)
    volatile LONG   BlockIpCount;    // 当前 InUse 项数(在 NetLock 下与 BlockList 一致地读写,
                                     // 供扫描「扫完即止」)
    volatile LONG64 BlockIpMask;     // 黑名单 IP 的布隆位(见 BLW_IP_BIT)。WFP classify 对
                                     // 【每一条外发连接】都要查黑名单,原实现无论名单空不空都要
                                     // 取一次自旋锁并扫满 64 项。现在先做一次无锁位测试:
                                     // 位未置 => 该 IP 绝不在名单里,连锁都不必取。
                                     // 名单为空(绝大多数部署的常态)时掩码恒为 0,开销趋零。
                                     // 定序与 PID 集合一致:加入先置位再写项,清空先清项再清位。

    // ============ 异步事件队列(彻底消除卡顿的核心)============
    // 所有回调只做「入队」:在自旋锁下把事件 memcpy 进预分配的环形缓冲(微秒级),
    // 立即返回。真正的 FltSendMessage 由一个后台系统线程统一在 PASSIVE_LEVEL 完成,
    // 完全移出内核热路径 —— 任何回调都不再因发送/用户态而产生哪怕一次延迟。
    // 队列满即丢弃(遥测可丢,稳定性与流畅度优先)。
    //
    // 【缓存行布局】本块整体对齐到缓存行,并把「每产生一条事件都要写」的成员
    // (RingHead / RingTail / RingLock / SenderIdle / NextEventId / DroppedEvents)集中放在
    // 头部 48 字节内 —— 它们本来就在同一把 RingLock 下被同一个核修改,同处一行是最优解;
    // 关键是不要再和前面那些「所有回调都在读」的名单计数、门闸标志共享缓存行。
    DECLSPEC_CACHEALIGN PBLW_EVENT_MESSAGE EventRing;  // 预分配环形缓冲(BLW_EVENT_QUEUE_CAP 条)
    volatile LONG   RingHead;         // 生产者写入下标(与容量掩码相与)
    volatile LONG   RingTail;         // 消费者读取下标(与容量掩码相与)
    KSPIN_LOCK      RingLock;         // 保护环形缓冲下标(入队可能在 DISPATCH_LEVEL)
    volatile LONG   SenderIdle;       // 1 = 发送线程正在(或即将)等待事件。生产者据此判断
                                      // 是否真的需要 KeSetEvent —— 该调用要拿调度器锁,
                                      // 在突发事件流里对每条都做一次纯属浪费。
    volatile LONG   SenderStop;       // 发送线程停止标志
    volatile LONG64 NextEventId;      // 事件序号自增(在 RingLock 下随填槽一起自增)
    volatile LONG64 DroppedEvents;    // 队列满丢弃计数(诊断用)
    KEVENT          RingEvent;        // 有事件入队时唤醒发送线程
    PETHREAD        SenderThread;     // 后台发送线程对象

    // ============ 策略写回去抖 ============
    // 原实现在【每一条】BLW_CMD_ADD_* 里都把整份名单重新序列化并写一次注册表值(还带一次
    // 约 66KB 的分页池分配)。服务连接时的初始配置下发是几十上百条连续 ADD,于是变成
    // O(n²) 次分配 + 注册表写,开机最忙的时候白白压上一堆 I/O。
    //
    // 现在改为:命令处理只置一个「脏」位并唤醒后台线程;线程被唤醒后先等一小段(去抖),
    // 再把每个脏名单【各写一次】。一次配置下发因此收敛成每个名单最多一次写回。
    // 卸载时会把剩余脏位刷完,不会丢掉任何「已学习裁决」。
    volatile LONG   PolicyDirtyMask;  // 待写回名单的位图(BLW_POLICY_DIRTY_*)
    KEVENT          PolicyEvent;      // 有名单变脏时唤醒写回线程
    PETHREAD        PolicyThread;     // 后台写回线程对象
    volatile LONG   PolicyStop;       // 写回线程停止标志

    // 服务注册表键(DriverEntry 的 RegistryPath 副本),供内核把「已学习裁决」写回 \Policy 子键,
    // 实现裁决缓存跨【杀服务】与【重启】持久化。仅 DriverEntry 保存一次,之后只读。
    WCHAR           RegistryPathBuffer[300];
    UNICODE_STRING  RegistryPath;

    // ============ 内核本地「事后研判」:内置已知恶意 SHA-256 集合 + 异步哈希扫描 ============
    // 默认惰性:KnownBadCount==0 时进程创建回调根本不入队,本能力零开销、零风险。
    // 情报由注册表 Policy\KnownBadSha256(REG_MULTI_SZ,每条 64 位十六进制)在开机时载入。
    UCHAR           KnownBadHashes[BLW_MAX_HASHES][32];  // 已知恶意 SHA-256(32 字节/条)
    volatile LONG   KnownBadCount;                       // 当前条数(热路径先查此值判空)
    FAST_MUTEX      KnownBadLock;                         // 保护 KnownBadHashes

    // 待扫描 PID 环形队列:进程创建回调只入队(自旋锁下写),真正读文件+哈希由 worker 完成。
    volatile LONG   HashRing[BLW_HASH_QUEUE_CAP];
    volatile LONG   HashRingHead;
    volatile LONG   HashRingTail;
    KSPIN_LOCK      HashRingLock;
    KEVENT          HashRingEvent;
    PETHREAD        HashWorkerThread;
    volatile LONG   HashWorkerStop;
} BLW_GLOBALS, *PBLW_GLOBALS;

// 环形队列容量(条)。每条约 2KB,1024 条约占 2MB 非分页内存。
// 足够吸收登录/开机时的事件突发;发送线程会快速排空。
// 必须是 2 的幂:下标推进用「与掩码」而非取模(下标是有符号 LONG,编译器无法把 % 优化成
// 位与,会真的生成一条除法)。
#define BLW_EVENT_QUEUE_CAP  1024
#define BLW_EVENT_QUEUE_MASK (BLW_EVENT_QUEUE_CAP - 1)
C_ASSERT((BLW_EVENT_QUEUE_CAP & BLW_EVENT_QUEUE_MASK) == 0);

// 写采样率(就地加密检测):每 N 次"偏移 0 起写"才解析文件名并上报一次。
// 取较大值以保证热路径开销极低;勒索批量加密会产生大量首块写,采样仍足以
// 让用户态在滑窗内聚合出高改写速率。普通程序极少高频从偏移 0 重写,几乎不被采到。
#define BLW_WRITE_SAMPLE_RATE 32

extern BLW_GLOBALS g_Blw;

// ProcessMonitor.c
NTSTATUS BlwRegisterProcessCallback(void);
void     BlwUnregisterProcessCallback(void);
// 驱动级结束进程(BLW_CMD_KILL_PID):内核结束指定 PID,带硬护栏(PID>4、非受保护、非关键系统进程)。
NTSTATUS BlwKillProcessById(_In_ ULONG Pid);

// 「命令行硬拦」名单管理(进程创建命中即内核本地拒绝创建)。模式为 '+' 分隔的 token 合取。
void     BlwClearCmdHardBlock(void);
void     BlwAddCmdHardBlock(_In_ PCWSTR Pattern, _In_ USHORT Length);
// 判定一条命令行是否命中名单。直接吃原始 UNICODE_STRING(不截断、不预归一化)——
// 命令行可长达 32767 字符,若先截到 BLW_MAX_PATH 再匹配,攻击者只要在前面填充垫料
// 就能把真正的危险 token 推到截断点之外从而绕过。故这里逐字符即时大写化比较,宁可
// 多花几微秒也绝不给出可绕过的判定。仅 PASSIVE_LEVEL(进程创建回调)调用。
BOOLEAN  BlwCmdLineIsBlocked(_In_opt_ PCUNICODE_STRING CommandLine);

// ImageMonitor.c
NTSTATUS BlwRegisterImageCallback(void);
void     BlwUnregisterImageCallback(void);

// ThreadMonitor.c
NTSTATUS BlwRegisterThreadCallback(void);
void     BlwUnregisterThreadCallback(void);

// FileMonitor.c
FLT_PREOP_CALLBACK_STATUS BlwPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS BlwPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

// IRP_MJ_WRITE 预操作:就地加密检测(采样遥测,绝不拦截)。
FLT_PREOP_CALLBACK_STATUS BlwPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

// 把目标串预归一化进 Ctx(每个回调对每个目标只做一次),供下面所有名单查询复用。
void     BlwPrepareMatch(_Out_ PBLW_MATCH_CTX Ctx, _In_opt_ PCUNICODE_STRING Target);

// 配置:受保护文件路径管理(线程安全)
void     BlwClearProtectedPaths(void);
void     BlwAddProtectedPath(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwPathIsProtected(_In_ PBLW_MATCH_CTX Ctx);
// 文件「内核硬拦截」名单管理(命中即内核本地拒绝写/删/改打开)。
void     BlwClearFileHardBlock(void);
void     BlwAddFileHardBlock(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwFileIsHardBlocked(_In_ PBLW_MATCH_CTX Ctx);
// 自保护足迹名单管理(owner-aware:命中且写/删/改名意图,且发起者非本产品受保护进程即拒绝)。
void     BlwClearSelfGuard(void);
void     BlwAddSelfGuard(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwFileIsSelfGuarded(_In_ PBLW_MATCH_CTX Ctx);
// 「禁止加载」模块名单管理(命中且执行/映射意图打开即内核本地拒绝)。
void     BlwClearFileNoLoad(void);
void     BlwAddFileNoLoad(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwFileIsNoLoad(_In_ PBLW_MATCH_CTX Ctx);
// 「禁止执行」名单管理(进程创建命中即内核本地拒绝创建)。
void     BlwClearFileExecBlock(void);
void     BlwAddFileExecBlock(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwFileIsExecBlocked(_In_ PBLW_MATCH_CTX Ctx);

// 通用:在受保护项数组中做子串匹配(大小写不敏感)。线程安全由调用方持锁。
//   Count    - 名单中在用项数(必须与 List 内容在同一把锁下读取);用于扫完即止,
//              不再无谓地遍历剩余空槽。
//   UseChars - 只匹配 Ctx 目标的前 UseChars 个字符;0 = 匹配整个目标。
//              (注册表回调用它在同一个 "键\值" ctx 上分别做「整串」与「仅键部分」两种匹配。)
BOOLEAN  BlwMatchInListCtx(_In_ BLW_PROTECTED_PATH* List, _In_ LONG Count,
                           _In_ PBLW_MATCH_CTX Ctx, _In_ USHORT UseChars);
// 向名单追加一项(内部会把模式串大写化后存入,见 BLW_PROTECTED_PATH 的存储约定)。
void     BlwAddToList(_In_ BLW_PROTECTED_PATH* List, _In_ PCWSTR Path, _In_ USHORT Length);
// 宽字符串子串匹配(大小写不敏感)。供多模块复用。
BOOLEAN  BlwWideContainsCI(_In_ PCWSTR Str, _In_ USHORT StrChars, _In_ PCWSTR Sub);

//
// ============ 「路径以 \<文件名> 结尾」类名单的公共判定 ============
//
// 关键系统进程(14 条)、LOLBin(28 条)、高价值注入目标(10 条)都是这种「按文件名匹配」的
// 常量名单。原实现对每一条都做一次 RtlInitUnicodeString(内含 wcslen)+ RtlCompareUnicodeString
// 尾部比较 —— 一次进程创建要跑 42 次带 wcslen 的整串比较,一次跨进程建线程要跑 10 次。
//
// 现在:先【一次】反向扫描取出文件名,再用「长度 + 首字符」筛掉名单里绝大多数条目,只有极少数
// 候选才逐字符比较;条目长度在编译期由 BLW_NAME 算出,运行时不再有 wcslen。
// 语义与原尾部匹配一致,包括「路径中必须真的出现过 '\'」这一点。
//
typedef struct _BLW_NAME_ENTRY {
    PCWSTR Name;    // 文件名(不含前导 '\')
    USHORT Chars;   // Name 的字符数(编译期常量)
} BLW_NAME_ENTRY;

#define BLW_NAME(s) { (s), (USHORT)(sizeof(s) / sizeof(WCHAR) - 1) }

BOOLEAN  BlwImageNameIn(_In_reads_(TableCount) const BLW_NAME_ENTRY* Table,
                        _In_ ULONG TableCount,
                        _In_opt_ PCWSTR Path, _In_ USHORT Chars);

// RegistryMonitor.c
NTSTATUS BlwRegisterRegistryCallback(_In_ PDRIVER_OBJECT DriverObject);
void     BlwUnregisterRegistryCallback(void);
void     BlwClearProtectedRegKeys(void);
void     BlwAddProtectedRegKey(_In_ PCWSTR Key, _In_ USHORT Length);
// 注册表「内核硬拦截」名单管理(精确子串,命中即内核本地拒绝写入)。
void     BlwClearRegHardBlock(void);
void     BlwAddRegHardBlock(_In_ PCWSTR Key, _In_ USHORT Length);

// SelfProtect.c
NTSTATUS BlwRegisterObCallbacks(void);
void     BlwUnregisterObCallbacks(void);
void     BlwClearProtectedPids(void);
void     BlwAddProtectedPid(_In_ ULONG Pid);
BOOLEAN  BlwPidIsProtected(_In_ ULONG Pid);
// 内存防护(反注入)目标 PID 管理。
void     BlwClearMemProtPids(void);
void     BlwAddMemProtPid(_In_ ULONG Pid);
BOOLEAN  BlwPidIsMemProtected(_In_ ULONG Pid);
void     BlwClearCredProtPids(void);
void     BlwAddCredProtPid(_In_ ULONG Pid);
BOOLEAN  BlwPidIsCredProtected(_In_ ULONG Pid);
// 已封禁主体(情报确认恶意)PID 管理:命中即各回调全维拒绝其行为。护栏:绝不封 PID<=4 /
// 本软件受保护进程 / 凭据保护进程。进程退出时由 BlwRemoveBannedPid 摘除以防 PID 复用误伤。
void     BlwClearBannedPids(void);
void     BlwAddBannedPid(_In_ ULONG Pid);
void     BlwRemoveBannedPid(_In_ ULONG Pid);
BOOLEAN  BlwPidIsBanned(_In_ ULONG Pid);

// NetMonitor.c
// 【武装】网络防护:BFE 已运行则当场拉起,未运行则订阅 BFE 状态、等它就绪后自动拉起。
// 两种情况都返回成功 —— boot-start 时 BFE 必然还没起来,那不是失败,不要据此放弃网络防护。
NTSTATUS BlwWfpStart(_In_ PDEVICE_OBJECT DeviceObject);
// 返回值【必须检查】:失败(典型 STATUS_DEVICE_BUSY)表示 WFP 仍持有本驱动的 classifyFn,
// 此时【绝不能】让镜像卸载,否则下一条外发连接就会跳进已释放内存。见 BlwFilterUnload。
_Must_inspect_result_
NTSTATUS BlwUnregisterWfp(void);
void     BlwClearBlockList(void);
void     BlwAddBlockIp(_In_ ULONG IpV4, _In_ USHORT Port);

// Comms.c
NTSTATUS BlwInitCommunication(_In_ PDRIVER_OBJECT DriverObject);
void     BlwTearDownCommunication(void);

// Policy.c
// 内核自足基线:开机从注册表(<RegistryPath>\Policy)加载各本地拦截名单,并把「已学习裁决」写回。
void     BlwSaveRegistryPath(_In_opt_ PUNICODE_STRING RegistryPath); // DriverEntry 保存服务键(供加载+写回)
void     BlwLoadPolicyFromRegistry(void);                            // 从 \Policy 载入基线(须在 Save 之后)
// 策略写回(去抖):命令处理路径只标脏 + 唤醒后台线程,真正的序列化与 ZwSetValueKey
// 由后台线程在 PASSIVE_LEVEL 合并完成。见 BLW_GLOBALS 里 PolicyDirtyMask 处的说明。
#define BLW_POLICY_DIRTY_PATHS      0x0001   // ProtectedPaths
#define BLW_POLICY_DIRTY_FILEHARD   0x0002   // FileHardBlock
#define BLW_POLICY_DIRTY_NOLOAD     0x0004   // FileNoLoad
#define BLW_POLICY_DIRTY_EXECBLOCK  0x0008   // FileExecBlock
#define BLW_POLICY_DIRTY_REGKEYS    0x0010   // ProtectedRegKeys
#define BLW_POLICY_DIRTY_REGHARD    0x0020   // RegHardBlock
#define BLW_POLICY_DIRTY_CMDHARD    0x0040   // CmdHardBlock(命令行硬拦:持久化后服务不在也续拦)

NTSTATUS BlwStartPolicyPersist(void);                    // DriverEntry 启动写回线程
void     BlwStopPolicyPersist(void);                     // Unload:刷完脏位并等线程退出
void     BlwMarkPolicyDirty(_In_ LONG DirtyBits);        // 标脏(可在 PASSIVE_LEVEL 调用)

// Cleanup.c
// 内核级足迹清理:以「忽略共享访问检查」读取 / POSIX 强制删除被独占锁定、已映射的文件
//(用户态因共享冲突 / 映像占用打不开、删不掉时才走这条路)。
// 供 Comms.c 的 BLW_CMD_QUARANTINE_READ / BLW_CMD_FORCE_DELETE 调用。仅 PASSIVE_LEVEL;
// 任何失败都只返回 NTSTATUS 供用户态回退,绝不蓝屏。
// 强制删除内部带「不许删本产品自身内容 / 硬拦名单」的护栏。
NTSTATUS BlwCleanupReadFile(_In_ PCWSTR Path, _In_ ULONG64 Offset,
                            _Out_writes_bytes_(BufLen) PVOID Buffer, _In_ ULONG BufLen,
                            _Out_ PULONG BytesRead);
NTSTATUS BlwCleanupForceDelete(_In_ PCWSTR Path);

// 单次 BLW_CMD_QUARANTINE_READ 允许的最大读取字节数。用户态请求多大缓冲就分配多大是不可接受的
// (那等于让用户态左右内核分页池的分配尺寸),故在此夹断;用户态按偏移分块循环,夹断只是让它
// 多转几圈,不影响结果。服务端当前每块 64KB。
#define BLW_CLEANUP_READ_MAX  (1024UL * 1024UL)

// HashScan.c
// 内核本地事后研判:异步哈希扫描 worker + 已知恶意 SHA-256 集合管理。
NTSTATUS BlwStartHashWorker(void);
void     BlwStopHashWorker(void);
void     BlwEnqueueHashScan(_In_ ULONG Pid);        // 进程创建回调入队(默认惰性:KnownBadCount>0 才调用)
void     BlwClearKnownBad(void);
void     BlwAddKnownBadHex(_In_ PCWSTR Hex, _In_ USHORT Length); // 追加一条 64 位十六进制 SHA-256

// 异步事件队列:启动 / 停止后台发送线程(在 DriverEntry / Unload 调用)。
NTSTATUS BlwStartEventQueue(void);
void     BlwStopEventQueue(void);

//
// 入队一条事件(所有内核回调的唯一对外路径)。
//
// 仅做自旋锁下的「就地填槽」+ 必要时唤醒发送线程,微秒级返回,可在 <= DISPATCH_LEVEL 调用。
// 队列满则丢弃并计数。真正的 FltSendMessage 由后台线程在 PASSIVE_LEVEL 完成,
// 内核回调热路径上【绝不】发生任何 IPC / 等待 —— 这是「彻底不卡顿」的根本保证。
//
// 参数直接给字段,而不是让调用方先在栈上拼一个 BLW_EVENT_MESSAGE:该结构约 2.1KB,原来的
// 做法要在每个回调帧上占 2.1KB 栈、全量 RtlZeroMemory 一遍、再整体 memcpy 进环 —— 等于把
// 2KB 数据摸三遍。现在直接写进环形槽,只摸一遍,回调栈上也不再有这 2.1KB。
//
// TargetPath / ImagePath 可为 NULL(该字段留空)。ParentPid 在部分事件里被复用为「目标 PID」
// 或「原始操作类型」,沿用既有约定。
//
void BlwReportEvent(
    _In_ ULONG Type,
    _In_ ULONG ActorPid,
    _In_ ULONG ParentPid,
    _In_opt_ PCUNICODE_STRING TargetPath,
    _In_opt_ PCUNICODE_STRING ImagePath,
    _In_ ULONG RemoteIpV4,
    _In_ USHORT RemotePort);
