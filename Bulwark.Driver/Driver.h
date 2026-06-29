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

// 一条受保护路径(子串匹配)
typedef struct _BLW_PROTECTED_PATH {
    WCHAR   Path[BLW_MAX_PATH];
    USHORT  Length;            // 字符数
    BOOLEAN InUse;
} BLW_PROTECTED_PATH, *PBLW_PROTECTED_PATH;

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
    volatile LONG64 NextEventId;     // 事件序号自增
    BOOLEAN         Active;          // 是否已连接客户端并启用拦截

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

    // 「禁止加载」模块名单:命中且本次打开带【执行/映射】意图时,内核本地直接拒绝
    // (STATUS_ACCESS_DENIED),使该模块无法被任何进程加载/映射执行。
    // 专治白加黑:把已确认恶意的侧载 DLL 钉死,合法签名宿主下次也无法再侧载它。
    // 与 FileHardBlock 互补:那个拦「写/删/改」,这个拦「执行加载」;只读数据访问不受影响。
    BLW_PROTECTED_PATH FileNoLoad[BLW_MAX_PROTECTED];
    FAST_MUTEX      FileNoLoadLock;  // 保护 FileNoLoad 的访问
    volatile LONG   FileNoLoadCount; // 当前 InUse 项数(快速判空)

    // 文件行为遥测开关(BLW_CMD_SET_FILETELEMETRY 下发)。开启后,内核对未命中任何
    // 名单的「重命名 / 删除标记」操作做 fire-and-forget 上报(绝不阻断),供用户态
    // 勒索行为时序聚合。默认关闭,避免无谓的事件量。仅观测高价值的删/改名信号,
    // 不上报普通写(普通写量极大,会拖垮上报通道)。
    volatile LONG   FileTelemetryEnabled;

    // 写采样计数器(就地加密检测):IRP_MJ_WRITE 钩子对"偏移 0 起写"按
    // BLW_WRITE_SAMPLE_RATE 取模采样,避免对每次写都解析文件名。仅诊断/节流用。
    volatile LONG   WriteSampleCounter;

    // 注册表防护
    LARGE_INTEGER   RegCookie;       // CmRegisterCallbackEx 返回的 cookie
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

    // 内存防护(反注入):高价值受害进程 PID 列表(0 表示空槽)。
    // 非可信进程对这些 PID 申请「写内存 / 远程线程」类权限时,在同一个 ObCallbacks
    // 回调里剥离这些权限,使跨进程注入写不进去。与 ProtectedPids 复用回调,
    // 区别仅在「保护对象不同 + 剥离的权限集不同」。PID 由用户态在 PASSIVE 解析
    // 高价值进程后下发,内核回调只做无锁 PID 查表(任意 IRQL 安全)。
    volatile LONG   MemProtPids[BLW_MAX_PROTECTED];

    // 影子模式(沙盒):影子进程 PID 列表(0 表示空槽)。
    // 影子进程的文件写入/删除/重命名、注册表写入在内核本地返回 SUCCESS 但不真实下发
    // (吞掉副作用),同时 fire-and-forget 上报行为事件供用户态分析。
    // 网络连接一律 BLOCK(防止真实外联)。子进程在 ProcessMonitor 回调中自动继承。
    volatile LONG   ShadowPids[BLW_MAX_PROTECTED];

    // 影子观察模式开关(BLW_CMD_SET_SHADOW_OBSERVE 下发)。开启后,影子进程的操作
    // 【不拦截】(全部放行),但仍上报行为事件,由用户态在会话结束后回滚所有变更。
    // 关闭时(默认)为拦截模式:直接阻断破坏性操作。
    volatile LONG   ShadowObserveMode;

    // 影子文件系统虚拟化开关(BLW_CMD_SET_SHADOW_FSREDIRECT 下发)。开启后,
    // 影子进程的文件写入/创建/删除/重命名被重定向到沙盒目录,
    // 真实文件系统完全不受影响。读取时先查沙盒,再查真实文件系统。
    volatile LONG   ShadowFsRedirect;

    // 微内核隔离模式开关(BLW_CMD_SET_SHADOW_ISOLATION 下发)。
    // 开启后,影子进程的文件操作被透明重定向到沙盒目录,
    // 程序完全正常运行但所有变更发生在沙盒中。
    volatile LONG   ShadowIsolationMode;

    // 沙盒根目录路径(如 \??\C:\Users\xxx\AppData\Local\Temp\bulwark_sandbox\)
    WCHAR           SandboxPath[BLW_MAX_PATH];
    USHORT          SandboxPathLength;  // 字符数

    // 沙盒豁免模式开关(BLW_CMD_SET_SANDBOX_EXEMPT 下发)。开启后,影子进程的所有操作
    // 绕过磐垒防护规则,不触发任何拦截/弹窗,但仍记录行为事件。
    // 用于沙盒分析:让恶意程序完整释放行为,不被防护打断。
    volatile LONG   SandboxExemptMode;

    // 网络防护(WFP)
    HANDLE          WfpEngine;       // WFP 引擎句柄
    UINT32          WfpCalloutId;    // 已注册 callout 的运行时 id
    UINT64          WfpFilterId;     // 已添加 filter 的 id
    BOOLEAN         WfpRegistered;
    PDEVICE_OBJECT  WfpDeviceObject; // 注册 callout 需要的设备对象
    BLW_BLOCK_IP    BlockList[BLW_MAX_PROTECTED]; // 网络黑名单
    KSPIN_LOCK      NetLock;         // 保护 BlockList(WFP classify 可能在 DISPATCH_LEVEL,
                                     // 必须用自旋锁而非 FAST_MUTEX,否则会触发 IRQL_NOT_LESS_OR_EQUAL 蓝屏)

    // ============ 异步事件队列(彻底消除卡顿的核心)============
    // 所有回调只做「入队」:在自旋锁下把事件 memcpy 进预分配的环形缓冲(微秒级),
    // 立即返回。真正的 FltSendMessage 由一个后台系统线程统一在 PASSIVE_LEVEL 完成,
    // 完全移出内核热路径 —— 任何回调都不再因发送/用户态而产生哪怕一次延迟。
    // 队列满即丢弃(遥测可丢,稳定性与流畅度优先)。
    PBLW_EVENT_MESSAGE EventRing;     // 预分配环形缓冲(BLW_EVENT_QUEUE_CAP 条)
    volatile LONG   RingHead;         // 生产者写入下标(模容量)
    volatile LONG   RingTail;         // 消费者读取下标(模容量)
    KSPIN_LOCK      RingLock;         // 保护环形缓冲下标(入队可能在 DISPATCH_LEVEL)
    KEVENT          RingEvent;        // 有事件入队时唤醒发送线程
    PETHREAD        SenderThread;     // 后台发送线程对象
    volatile LONG   SenderStop;       // 发送线程停止标志
    volatile LONG64 DroppedEvents;    // 队列满丢弃计数(诊断用)
} BLW_GLOBALS, *PBLW_GLOBALS;

// 环形队列容量(条)。每条约 2KB,1024 条约占 2MB 非分页内存。
// 足够吸收登录/开机时的事件突发;发送线程会快速排空。
#define BLW_EVENT_QUEUE_CAP 1024

// 写采样率(就地加密检测):每 N 次"偏移 0 起写"才解析文件名并上报一次。
// 取较大值以保证热路径开销极低;勒索批量加密会产生大量首块写,采样仍足以
// 让用户态在滑窗内聚合出高改写速率。普通程序极少高频从偏移 0 重写,几乎不被采到。
#define BLW_WRITE_SAMPLE_RATE 32

extern BLW_GLOBALS g_Blw;

// ProcessMonitor.c
NTSTATUS BlwRegisterProcessCallback(void);
void     BlwUnregisterProcessCallback(void);

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

// 配置:受保护文件路径管理(线程安全)
void     BlwClearProtectedPaths(void);
void     BlwAddProtectedPath(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwPathIsProtected(_In_ PCUNICODE_STRING Path);
// 文件「内核硬拦截」名单管理(命中即内核本地拒绝写/删/改打开)。
void     BlwClearFileHardBlock(void);
void     BlwAddFileHardBlock(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwFileIsHardBlocked(_In_ PCUNICODE_STRING Path);
// 「禁止加载」模块名单管理(命中且执行/映射意图打开即内核本地拒绝)。
void     BlwClearFileNoLoad(void);
void     BlwAddFileNoLoad(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwFileIsNoLoad(_In_ PCUNICODE_STRING Path);

// 通用:在受保护项数组中做子串匹配(大小写不敏感)。线程安全由调用方持锁。
BOOLEAN  BlwMatchInList(_In_ BLW_PROTECTED_PATH* List, _In_ PCUNICODE_STRING Target);
void     BlwAddToList(_In_ BLW_PROTECTED_PATH* List, _In_ PCWSTR Path, _In_ USHORT Length);
// 宽字符串子串匹配(大小写不敏感)。供多模块复用。
BOOLEAN  BlwWideContainsCI(_In_ PCWSTR Str, _In_ USHORT StrChars, _In_ PCWSTR Sub);

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

// 影子模式(沙盒)PID 管理。
void     BlwClearShadowPids(void);
void     BlwAddShadowPid(_In_ ULONG Pid);
BOOLEAN  BlwPidIsShadow(_In_ ULONG Pid);
// 沙盒路径管理。
void     BlwSetSandboxPath(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwBuildSandboxPath(_In_ PCUNICODE_STRING OriginalPath,
             _Out_ PWCHAR SandboxBuffer, _In_ ULONG SandboxBufferChars,
             _Out_ PUSHORT SandboxLength);

// NetMonitor.c
NTSTATUS BlwRegisterWfp(_In_ PDEVICE_OBJECT DeviceObject);
void     BlwUnregisterWfp(void);
void     BlwClearBlockList(void);
void     BlwAddBlockIp(_In_ ULONG IpV4, _In_ USHORT Port);

// Comms.c
NTSTATUS BlwInitCommunication(_In_ PDRIVER_OBJECT DriverObject);
void     BlwTearDownCommunication(void);

// 异步事件队列:启动 / 停止后台发送线程(在 DriverEntry / Unload 调用)。
NTSTATUS BlwStartEventQueue(void);
void     BlwStopEventQueue(void);

// 入队一条事件(所有内核回调的唯一对外路径)。
// 仅做自旋锁下的 memcpy 入队 + 唤醒发送线程,微秒级返回,可在 <= DISPATCH_LEVEL 调用。
// 队列满则丢弃并计数。真正的 FltSendMessage 由后台线程在 PASSIVE_LEVEL 完成,
// 内核回调热路径上【绝不】发生任何 IPC / 等待 —— 这是「彻底不卡顿」的根本保证。
void BlwReportEvent(_In_ PBLW_EVENT_MESSAGE Event);
