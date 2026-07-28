/*++
    Protocol.h
    内核驱动 <-> 用户态服务 通过 Minifilter 通信端口交换的消息结构定义。
    用户态(C#)需以相同的内存布局解释这些结构。
--*/

#pragma once

// 与 Bulwark.Core.Models.EventType 对应(只列驱动当前产生的类型)
typedef enum _BLW_EVENT_TYPE {
    BlwEventProcessCreate = 0,
    BlwEventProcessTerminate = 1,
    BlwEventFileDelete = 2,
    BlwEventFileRename = 3,
    BlwEventRegistrySetValue = 4,
    BlwEventRegistryDeleteValue = 5,
    BlwEventRegistryDeleteKey = 6,
    BlwEventSelfProtect = 7,
    BlwEventNetworkConnect = 8,
    BlwEventImageLoad = 9,
    BlwEventRemoteThread = 10,
    BlwEventMemoryProtect = 11,   // 反注入:已剥离对高价值进程的写内存/远程线程权限
    BlwEventImageBlocked = 12,    // 已阻断「禁止加载名单」中的模块被加载(白加黑 DLL 侧载)
    BlwEventFileModify = 13,      // 【观测·非拦截】用户态进程对文件的重命名/删除标记。
                                  //   不命中任何受保护/硬拦截名单,内核【不阻断】,仅 fire-and-forget
                                  //   上报供用户态做行为时序聚合(勒索批量改写/扩展名同化/蜜罐触碰)。
                                  //   命中聚合阈值后由用户态补偿处置(结束发起进程树)。
    BlwEventCommandBlocked = 14,  // 已阻断「危险命令行」进程创建(执行前拦截,零 IPC)。
                                  //   命中命令行硬拦名单(如 vssadmin+delete+shadows)时,内核在进程
                                  //   创建回调里直接置 CreationStatus=STATUS_ACCESS_DENIED —— 命令
                                  //   【根本没有执行过】。ImagePath=映像路径,TargetPath=被拦下的命令行。
    BlwEventRegistryHiveDump = 15,// 注册表 hive 转储(ZwSaveKey / reg save)。命中内置凭据 hive
                                  //   (\REGISTRY\MACHINE\SAM|SECURITY)时内核本地直接拒绝 —— 挡住
                                  //   「离线破解 SAM 偷本机账户口令」这条不经过 lsass 的凭据窃取路径。
} BLW_EVENT_TYPE;

// 裁决动作,与 Bulwark.Core.Models.VerdictAction 对应
typedef enum _BLW_VERDICT {
    BlwVerdictAllow = 0,
    BlwVerdictBlock = 1,
} BLW_VERDICT;

#define BLW_MAX_PATH 520   // 路径最大字符数(宽字符)

// 内核 -> 用户态:一条待裁决事件
typedef struct _BLW_EVENT_MESSAGE {
    ULONG64       EventId;          // 事件序号(驱动内自增)
    ULONG         Type;             // BLW_EVENT_TYPE
    ULONG         ActorPid;         // 发起进程 PID
    ULONG         ParentPid;        // 父进程 PID(文件/注册表事件为 0)
    USHORT        ImagePathLength;  // ImagePath 实际字符数(文件事件可为 0)
    WCHAR         ImagePath[BLW_MAX_PATH];  // 进程映像路径(进程事件)
    USHORT        TargetPathLength; // TargetPath 实际字符数
    WCHAR         TargetPath[BLW_MAX_PATH]; // 操作目标(文件事件为被操作文件路径)
    ULONG         RemoteIpV4;       // 网络事件:远端 IPv4(主机字节序),0 表示非网络事件
    USHORT        RemotePort;       // 网络事件:远端端口
} BLW_EVENT_MESSAGE, *PBLW_EVENT_MESSAGE;

// 用户态 -> 内核:对某事件的裁决回复
typedef struct _BLW_VERDICT_REPLY {
    ULONG64       EventId;          // 对应事件序号
    ULONG         Verdict;          // BLW_VERDICT
} BLW_VERDICT_REPLY, *PBLW_VERDICT_REPLY;

// 用户态 -> 内核:配置消息(下发受保护路径)。通过 FilterSendMessage 发送,
// 由内核 MessageNotifyCallback 接收。
#define BLW_CMD_CLEAR_PATHS    1   // 清空受保护文件路径列表
#define BLW_CMD_ADD_PATH       2   // 追加一条受保护文件路径(子串,大小写不敏感)
#define BLW_CMD_CLEAR_REGKEYS  3   // 清空受保护注册表键列表
#define BLW_CMD_ADD_REGKEY     4   // 追加一条受保护注册表键(子串,大小写不敏感)
#define BLW_CMD_CLEAR_PIDS     5   // 清空受保护进程 PID 列表(自我保护)
#define BLW_CMD_ADD_PID        6   // 追加一个受保护进程 PID(自我保护)
#define BLW_CMD_CLEAR_BLOCKIP  7   // 清空网络黑名单
#define BLW_CMD_ADD_BLOCKIP    8   // 追加一条网络黑名单(IPv4 + 端口,端口0表示任意)
#define BLW_CMD_HANDSHAKE      9   // 协议握手:校验内核/用户态结构体布局一致
#define BLW_CMD_CLEAR_REGHARD  10  // 清空「内核硬拦截」注册表名单
#define BLW_CMD_ADD_REGHARD    11  // 追加一条「内核硬拦截」注册表项(精确子串,key 或 key\value)
                                   //   命中即内核本地直接 STATUS_ACCESS_DENIED 拒绝写入,
                                   //   不发任何 IPC、不等用户态 —— 真·原地阻断且零延迟。
                                   //   仅用于极少数「绝不允许被改一次」的精确键值,
                                   //   名单必须精确(不可用 \Services 这类宽热键,否则拦死系统)。
#define BLW_CMD_CLEAR_FILEHARD 12  // 清空「内核硬拦截」文件名单
#define BLW_CMD_ADD_FILEHARD   13  // 追加一条「内核硬拦截」文件项(精确子串)
                                   //   命中即内核本地拒绝任何写/删/重命名/覆盖打开,只读放行。
                                   //   比受保护路径更强(防内容篡改),仅用于关键文件(hosts/sethc/SAM)。
#define BLW_CMD_CLEAR_MEMPROT  14  // 清空「内存防护(反注入)」目标 PID 列表
#define BLW_CMD_ADD_MEMPROT    15  // 追加一个「内存防护(反注入)」目标进程 PID。
                                   //   非可信进程对该 PID 申请写内存/远程线程权限时,
                                   //   内核本地剥离这些权限(ObCallbacks),让注入写不进去。
                                   //   只剥写类权限,保留读/查询;系统/本软件/目标互操作豁免。
#define BLW_CMD_CLEAR_NOLOAD   16  // 清空「禁止加载」模块名单
#define BLW_CMD_ADD_NOLOAD     17  // 追加一条「禁止加载」模块文件(精确子串,大小写不敏感)。
                                   //   命中且本次打开带「执行/映射」意图时,内核本地直接
                                   //   STATUS_ACCESS_DENIED,使该模块无法被任何进程加载/映射。
                                   //   专治白加黑:把已确认恶意的侧载 DLL 钉死,合法签名宿主
                                   //   下次/重启后也无法再侧载它。普通读/写不受影响(只拦执行映射)。
#define BLW_CMD_SET_FILETELEMETRY 18 // 开/关「文件行为遥测」(Pid 字段:0=关,非0=开)。
                                    //   开启后,内核对未命中任何名单的「重命名/删除标记」操作
                                    //   做 fire-and-forget 上报(不阻断),供用户态聚合勒索行为。
                                    //   默认关闭,由用户态按是否启用文件防护维度动态下发。
#define BLW_CMD_QUARANTINE_READ 19 // 内核级足迹清理·读:以「忽略共享访问检查」打开被独占锁定/
                                   //   已映射的文件并读取一段,供用户态做可逆金库副本(用户态因
                                   //   共享冲突打不开时才走此路)。复用 BLW_CONFIG_MESSAGE:
                                   //   Path=源文件;Pid=读取偏移低 32 位;BlockIpV4=读取偏移高 32 位。
                                   //   OutputBuffer 收原始字节;ReturnOutputBufferLength=本次读到的
                                   //   字节数(0=到达文件尾 / 空文件)。纯读,绝不改动原文件。
#define BLW_CMD_FORCE_DELETE   20  // 内核级足迹清理·删:以「忽略共享访问检查 + 强制删除(POSIX
                                   //   语义)」删除被占用 / 已映射(运行中 exe·已加载 dll)的文件——
                                   //   用户态 DeleteFile 因共享冲突 / 映像占用删不掉时才走此路。
                                   //   复用 BLW_CONFIG_MESSAGE:Path=目标文件。
                                   //   OutputBuffer 收 BLW_FILEOP_REPLY{ Status }。
#define BLW_CMD_KILL_PID       21  // 驱动级结束进程:内核 PsLookupProcessByProcessId + ObOpenObjectByPointer
                                   //   + ZwTerminateProcess 结束指定 PID(比用户态 TerminateProcess 更强、
                                   //   难被反杀)。复用 BLW_CONFIG_MESSAGE:Pid=目标进程。内核侧硬护栏:
                                   //   PID>4、非本软件受保护进程、非关键系统进程(防 CRITICAL_PROCESS_DIED)。
                                   //   fire-and-forget:不写 OutputBuffer;失败/被护栏拦下由用户态兜底结束。
#define BLW_CMD_CLEAR_EXECBLOCK 22 // 清空「禁止执行」名单(执行前拦截)。
#define BLW_CMD_ADD_EXECBLOCK  23  // 追加一条「禁止执行」映像路径(精确子串,大小写不敏感)。
                                   //   进程创建回调命中即内核本地直接 CreationStatus=STATUS_ACCESS_DENIED,
                                   //   使已确认恶意的样本【根本无法启动】—— 零用户态往返、无竞态,补上
                                   //   「事后 kill 让样本先跑几十毫秒」的短板,且重启后仍拦(名单持久重推)。
                                   //   由用户态在 VT/规则/记忆确认恶意后下发其映像路径。内核硬护栏:关键
                                   //   系统进程绝不受此影响(防 CRITICAL_PROCESS_DIED),即便名单误含也不拦。
#define BLW_CMD_CLEAR_CREDPROT 24  // 清空「凭据保护(反转储)」目标 PID 列表。
#define BLW_CMD_ADD_CREDPROT   25  // 追加一个「凭据保护(反转储)」目标进程 PID(主要是 lsass)。
                                   //   在反注入(MEMPROT)基础上【额外剥离 PROCESS_VM_READ】—— 读 lsass
                                   //   内存正是 mimikatz 等凭据转储的核心手段。非可信进程对该 PID 申请
                                   //   读/写内存/内存操作/远程线程/挂起权限时,内核本地(ObCallbacks)一并
                                   //   剥离,使凭据无法被读出、也无法被注入。保留 QUERY/TERMINATE(不影响
                                   //   进程枚举/管理)。System(PID 4)/本软件受保护进程/目标自身操作一律豁免。

#define BLW_CMD_CLEAR_BANNED   26  // 清空「已封禁主体」PID 集(情报确认恶意的全维封杀目标)。
#define BLW_CMD_ADD_BANNED     27  // 追加一个「已封禁主体」PID:该 PID 的任何文件写/删/改、注册表写、
                                   //   网络外联、创建子进程,内核各回调一律 STATUS_ACCESS_DENIED ——
                                   //   「情报一确认即全维封杀」,不依赖结束进程时机(杀不掉/滞后也做不成事)。
                                   //   复用 BLW_CONFIG_MESSAGE(Pid 字段),不改任何结构体布局,故与 v9 驱动/
                                   //   服务【线布局完全一致】,协议版本【保持 9】以兼容已部署的 v9 服务(旧驱动
                                   //   不认此命令时返回 STATUS_INVALID_PARAMETER,服务侧无害降级)。内核硬护栏:
                                   //   PID<=4 / 本软件受保护进程 / 凭据保护进程绝不封;进程退出时自动摘除(防 PID 复用)。

#define BLW_CMD_CLEAR_SELFGUARD 28 // 清空「自保护足迹」路径子串集。
#define BLW_CMD_ADD_SELFGUARD  29  // 追加一条本产品「完整内容」路径子串(安装目录 / %ProgramData%\Bulwark
                                   //   数据目录 / 驱动 .sys)。此后【非本产品自身受保护进程】对该路径的写/删/
                                   //   改名一律内核本地 STATUS_ACCESS_DENIED —— 勒索病毒/任何外部进程都无法
                                   //   加密/篡改/删除本产品的任何文件,而本产品自身仍可读写自己的数据(owner-aware,
                                   //   属主判定复用自我保护的受保护 PID 集)。只读打开放行(不影响本产品被加载执行)。
                                   //   复用 BLW_CONFIG_MESSAGE(Path 字段),不改任何结构体布局,故协议版本【保持 9】,
                                   //   与已部署 v9 驱动/服务线布局一致;旧驱动不认此命令时返回 STATUS_INVALID_PARAMETER,
                                   //   服务侧无害降级(自保足迹不可用,其余防护不受影响)。【故意不持久化】:仅服务连接
                                   //   期间有效、断连即清除,使更新/卸载本产品无需先卸载驱动。

#define BLW_CMD_CLEAR_CMDBLOCK 30  // 清空「命令行硬拦」名单。
#define BLW_CMD_ADD_CMDBLOCK   31  // 追加一条「命令行硬拦」模式(Path 字段)。进程创建回调命中即内核本地
                                   //   直接 CreationStatus=STATUS_ACCESS_DENIED —— 危险命令【根本不会执行】,
                                   //   零用户态往返、无竞态,也不存在「事后 kill 时命令已经跑完」的窗口。
                                   //
                                   //   这补上的是本项目最大的一处能力浪费:LOLBin(powershell/vssadmin/wmic/
                                   //   certutil...)本体在 System32、签名可信,原先只能整体放行给用户态看命令行,
                                   //   而内核回调里 PS_CREATE_NOTIFY_INFO.CommandLine 本来就【拿得到完整命令行】。
                                   //
                                   //   ===== 模式语法:token 合取(AND),而不是整串子串 =====
                                   //   模式用 '+'(BLW_CMD_TOKEN_SEP)分隔为多个 token,【每个 token 都必须】
                                   //   作为大小写不敏感子串出现在命令行里才算命中。例:
                                   //       VSSADMIN+DELETE+SHADOWS
                                   //   可命中 `vssadmin.exe  Delete   Shadows /All /Quiet`、
                                   //         `C:\Windows\System32\vssadmin.exe /for=c: delete shadows /quiet`
                                   //   —— 参数顺序、空格数量、大小写、是否带全路径全都不影响判定。
                                   //   若改用整串子串匹配,只要攻击者调换参数顺序或多打一个空格就能绕过,
                                   //   所以这里必须是 token 合取。
                                   //
                                   //   内核硬护栏:关键系统进程绝不受此名单影响(防 CRITICAL_PROCESS_DIED 0xEF),
                                   //   即便名单被误配也拦不死系统。命中时上报 BlwEventCommandBlocked 供 UI 展示。
                                   //   名单持久化到 \Policy\CmdHardBlock,故【服务未启动 / 被杀 / 重启后】仍由内核
                                   //   独立续拦 —— 反勒索最关键的「删卷影」不再依赖任何用户态进程活着。

// 「命令行硬拦」模式里的 token 分隔符(见 BLW_CMD_ADD_CMDBLOCK 的语法说明)。
// 选 '+' 而非空格:模式本身要能自由书写,而空格在命令行里是天然噪声(数量不定),
// 不能当分隔符;'+' 在真实的危险命令行里几乎不出现,不会与 token 内容混淆。
#define BLW_CMD_TOKEN_SEP  L'+'

// 协议版本号。任何会改变下列结构体内存布局的修改都必须 +1,
// 用户态据此 + 结构体大小做握手校验,布局不一致时拒绝拦截(防错位误判)。
// v3: 新增 BlwEventFileModify 文件行为遥测(枚举值新增,结构体布局未变,
//     但为确保新旧两端语义一致仍提升版本号,旧版用户态将因版本不符而降级)。
// v4: 新增 BLW_CMD_CLEAR_SHADOW_PIDS / BLW_CMD_ADD_SHADOW_PID 影子模式(沙盒)。
// v5: 移除影子模式(沙盒)相关命令(BLW_CMD_*SHADOW* / *SANDBOX*)与事件
//     (BlwEventShadowFileCreate)—— 该能力已从内核彻底下线。
// v6: 内核级足迹清理(强删 / 读取被占用文件)版本。其新增命令复用现有 BLW_CONFIG_MESSAGE,
//     不改动任何握手校验结构体的内存布局,故与 v5 驱动【线布局完全一致】。此处提升版本号至 6,
//     使本服务与已部署的 v6 驱动握手匹配(结构体大小仍逐一相等,内存安全)。
// v7: 新增 BLW_CMD_KILL_PID 驱动级结束进程(内核 ZwTerminateProcess)。复用现有 BLW_CONFIG_MESSAGE,
//     不改动任何握手校验结构体的内存布局,故与 v5/v6 驱动【线布局完全一致】。旧驱动不支持该命令时
//     返回 STATUS_INVALID_PARAMETER,服务据此回退到用户态结束进程(试探 + 回退,不靠版本门控)。
// v8: 新增 BLW_CMD_ADD_EXECBLOCK / BLW_CMD_CLEAR_EXECBLOCK「执行前拦截」(进程创建回调本地拒绝
//     已确认恶意映像启动)。复用现有 BLW_CONFIG_MESSAGE(Path=映像路径子串),不改动任何握手校验
//     结构体的内存布局,故与 v5/v6/v7 驱动【线布局完全一致】。旧驱动不支持该命令时返回
//     STATUS_INVALID_PARAMETER,服务据此静默降级(执行前拦截不可用,事后 kill 仍生效)。
// v9: 新增 BLW_CMD_ADD_CREDPROT / BLW_CMD_CLEAR_CREDPROT「凭据保护(反转储)」(对 lsass 在反注入
//     基础上额外剥离 PROCESS_VM_READ,挡住 mimikatz 类凭据转储)。复用现有 BLW_CONFIG_MESSAGE
//     (Pid=目标进程),不改动任何握手校验结构体的内存布局,故与 v5..v8 驱动【线布局完全一致】。
//     旧驱动不支持该命令时返回 STATUS_INVALID_PARAMETER,服务据此静默降级(反转储不可用,反注入仍在)。
// v9(续): 新增 BLW_CMD_*_BANNED(26/27,已封禁主体全维拦截)与 BLW_CMD_*_SELFGUARD(28/29,
//     owner-aware 自保护足迹·反勒索)。二者均只【新增】复用现有 BLW_CONFIG_MESSAGE 的命令,不改动
//     任何握手校验结构体的内存布局,故协议版本【保持 9】,与已部署的 v9 驱动/服务线布局完全一致;
//     旧驱动不认新命令时返回 STATUS_INVALID_PARAMETER,服务侧无害降级。
// v9(续 2): 新增 BLW_CMD_*_CMDBLOCK(30/31,命令行硬拦·执行前拦截)与两个事件类型
//     BlwEventCommandBlocked(14)/ BlwEventRegistryHiveDump(15),并补齐注册表回调覆盖面
//     (RegNtPreRenameKey / PreSaveKey / PreLoadKey / PreSetKeySecurity / PreCreateKeyEx)。
//     协议版本【仍保持 9】,理由是两个方向都无害降级、且线布局逐字节不变:
//       * 结构体布局:新命令复用现有 BLW_CONFIG_MESSAGE(Path 字段),新事件复用现有
//         BLW_EVENT_MESSAGE —— 三个握手校验结构体的大小【一个字节都没变】,内存安全不受影响。
//       * 新服务 + 旧驱动:旧驱动不认 30/31,返回 STATUS_INVALID_PARAMETER,服务静默降级
//         (命令行硬拦不可用,其余防护照常);新事件类型自然永不到达。
//       * 新驱动 + 旧服务:旧服务的 mapType/buildAndQueue 都有 default 分支,未知事件类型
//         退化为一条普通遥测记录(不置 userModeObserved,故不会触发任何补偿处置)—— 无害。
//     若在此改为 v10,反而会让已部署的 v9 服务/驱动因版本不符而【整体降级为不拦截】,
//     那是比"少认识两个事件类型"严重得多的退化。故刻意保持 9。
#define BLW_PROTOCOL_VERSION   9

// 内核 -> 用户态:握手应答(BlwMessageNotify 的 OutputBuffer)。
// 用户态据此确认双方 Protocol.h 完全一致,否则一律降级、绝不拦截。
typedef struct _BLW_HANDSHAKE_REPLY {
    ULONG ProtocolVersion;       // = BLW_PROTOCOL_VERSION
    ULONG EventMessageSize;      // = sizeof(BLW_EVENT_MESSAGE)
    ULONG ConfigMessageSize;     // = sizeof(BLW_CONFIG_MESSAGE)
    ULONG VerdictReplySize;      // = sizeof(BLW_VERDICT_REPLY)
} BLW_HANDSHAKE_REPLY, *PBLW_HANDSHAKE_REPLY;

// 内核 -> 用户态:内核级文件强制操作结果(BLW_CMD_FORCE_DELETE 的 OutputBuffer)。
// Status=0 表示成功;非 0 为 NTSTATUS,用户态据此回退到用户态清理 / 计划重启删除。
typedef struct _BLW_FILEOP_REPLY {
    LONG Status;                 // 0 = 成功;否则为失败的 NTSTATUS
} BLW_FILEOP_REPLY, *PBLW_FILEOP_REPLY;

typedef struct _BLW_CONFIG_MESSAGE {
    ULONG         Command;          // BLW_CMD_*
    ULONG         Pid;              // 受保护进程 PID(用于 ADD_PID)
    ULONG         BlockIpV4;        // 网络黑名单 IPv4(主机字节序,用于 ADD_BLOCKIP)
    USHORT        BlockPort;        // 网络黑名单端口(0=任意,用于 ADD_BLOCKIP)
    USHORT        PathLength;       // Path 实际字符数
    WCHAR         Path[BLW_MAX_PATH];
} BLW_CONFIG_MESSAGE, *PBLW_CONFIG_MESSAGE;

// 通信端口名称(用户态 FilterConnectCommunicationPort 使用)
#define BLW_PORT_NAME L"\\BulwarkPort"
