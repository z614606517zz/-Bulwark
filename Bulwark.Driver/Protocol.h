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
    BlwEventShadowFileCreate = 14, // 【影子模式】影子进程创建了新文件。用于会话结束后提示用户清理。
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
#define BLW_CMD_CLEAR_SHADOW_PIDS 19 // 清空「影子模式(沙盒)」进程 PID 列表
#define BLW_CMD_ADD_SHADOW_PID   20  // 追加一个「影子模式」进程 PID。
                                    //   影子进程的文件写入/删除/重命名、注册表写入
                                    //   在内核本地返回 SUCCESS 但不真实下发(吞掉副作用),
                                    //   同时 fire-and-forget 上报行为事件供用户态分析。
                                    //   网络连接一律 BLOCK(防止真实外联)。
                                    //   子进程自动继承影子身份。
#define BLW_CMD_SET_SHADOW_OBSERVE 21 // 开/关「影子观察模式」(Pid 字段:0=关,非0=开)。
                                    //   开启后,影子进程的操作【不拦截】(全部放行),
                                    //   但仍 fire-and-forget 上报行为事件。
                                    //   由用户态在会话结束后【回滚】所有变更(文件/注册表)。
                                    //   默认关闭(即拦截模式)。仅在影子模式生效时有意义。
#define BLW_CMD_SET_SHADOW_FSREDIRECT 22 // 开/关「影子文件系统虚拟化」(Pid 字段:0=关,非0=开)。
                                    //   开启后,影子进程的文件写入/创建/删除/重命名
                                    //   被重定向到沙盒目录(Path 字段指定),真实文件系统
                                    //   完全不受影响。读取时先查沙盒,再查真实文件系统。
                                    //   会话结束后删除沙盒目录 = 100% 回滚。
#define BLW_CMD_SET_SHADOW_SANDBOX  23 // 设置沙盒根目录路径(Path 字段)。
                                    //   影子文件系统虚拟化的重定向目标。
#define BLW_CMD_SET_SHADOW_ISOLATION 24 // 开/关「微内核隔离模式」(Pid 字段:0=关,非0=开)。
                                    //   开启后,影子进程的文件/注册表操作被透明重定向到
                                    //   沙盒目录,程序完全正常运行但所有变更发生在沙盒中。
                                    //   关闭沙盒 = 100% 清理。与 FSREDIRECT 不同,
                                    //   此模式真正实现文件系统虚拟化(不是仅追踪)。
#define BLW_CMD_SET_SANDBOX_EXEMPT 25 // 开/关「沙盒豁免模式」(Pid 字段:0=关,非0=开)。
                                    //   开启后,影子进程的所有操作绕过磐垒防护规则,
                                    //   不触发任何拦截/弹窗,但仍记录行为事件。
                                    //   用于沙盒分析:让恶意程序完整释放行为,不被防护打断。

// 协议版本号。任何会改变下列结构体内存布局的修改都必须 +1,
// 用户态据此 + 结构体大小做握手校验,布局不一致时拒绝拦截(防错位误判)。
// v3: 新增 BlwEventFileModify 文件行为遥测(枚举值新增,结构体布局未变,
//     但为确保新旧两端语义一致仍提升版本号,旧版用户态将因版本不符而降级)。
// v4: 新增 BLW_CMD_CLEAR_SHADOW_PIDS / BLW_CMD_ADD_SHADOW_PID 影子模式(沙盒)。
#define BLW_PROTOCOL_VERSION   4

// 内核 -> 用户态:握手应答(BlwMessageNotify 的 OutputBuffer)。
// 用户态据此确认双方 Protocol.h 完全一致,否则一律降级、绝不拦截。
typedef struct _BLW_HANDSHAKE_REPLY {
    ULONG ProtocolVersion;       // = BLW_PROTOCOL_VERSION
    ULONG EventMessageSize;      // = sizeof(BLW_EVENT_MESSAGE)
    ULONG ConfigMessageSize;     // = sizeof(BLW_CONFIG_MESSAGE)
    ULONG VerdictReplySize;      // = sizeof(BLW_VERDICT_REPLY)
} BLW_HANDSHAKE_REPLY, *PBLW_HANDSHAKE_REPLY;

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
