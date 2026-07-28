# Bulwark.Driver(内核驱动 / M2–M6)

磐垒主动防御的内核驱动。对文件 / 注册表 / 网络 / 自我保护在**动作发生前**内核本地原地阻断。

进程创建有两条路:命中内核本地名单(**禁止执行的映像** / **危险命令行** / 封禁主体派生子进程)时**直接拒绝创建**,真·执行前阻断;其余走「遥测 + 启动后补偿结束」模型(稳定性优先,绝不在内核挂起进程创建等用户态裁决)。

## 它做了什么

进程防护(M2)+ 文件防护(M3)+ 注册表防护(M4)+ 自我保护(M5)+ 网络防护(M6):

- 注册一个 **Minifilter**,既挂接 I/O 操作回调(文件防护),又借用 Filter Manager 的**通信端口**(`FltCreateCommunicationPort` / `FltSendMessage`)与用户态服务通信。
- 用 **`PsSetCreateProcessNotifyRoutineEx`** 拦截每个进程创建。
- **命令行硬拦(执行前拦截·按用法而非按身份)**:在同一个进程创建回调里直接读 `PS_CREATE_NOTIFY_INFO.CommandLine`,命中「命令行硬拦名单」即内核本地 `CreationStatus = STATUS_ACCESS_DENIED`,**危险命令一次都不会执行**。这一维专治 LOLBin 滥用 —— `vssadmin` / `wmic` / `bcdedit` / `wbadmin` / `fsutil` / `reg` 本体在 System32、签名可信,按任何「身份」判定都拦不住,威胁全在用法;而 `vssadmin delete shadows` 这类命令毫秒级就完成不可逆破坏,「事后 kill」根本来不及。判定刻意排在可信系统路径快速放行**之前**(目标全住在可信路径里),唯一护栏是「关键系统进程绝不拦」。
- 用 **`IRP_MJ_CREATE`(FILE_DELETE_ON_CLOSE)** 与 **`IRP_MJ_SET_INFORMATION`(FileDispositionInformation / FileRenameInformation)** 预操作回调拦截**受保护文件**的删除与重命名。
- 用 **`CmRegisterCallbackEx`** 拦截对**受保护注册表键**的八类危险操作:写值(`RegNtPreSetValueKey`,如启动项)、删值(`RegNtPreDeleteValueKey`)、删键(`RegNtPreDeleteKey`)、**改名**(`RegNtPreRenameKey` —— 改个名字就能让所有路径型匹配整体失效)、**hive 导出**(`RegNtPreSaveKey` —— `reg save HKLM\SAM` 绕开 lsass 偷凭据)、**hive 挂载**(`RegNtPreLoadKey`)、**改 ACL**(`RegNtPreSetKeySecurity` —— 先放开权限,后续写入即「合法」)、**建键**(`RegNtPreCreateKeyEx` —— IFEO 劫持要先新建子键)。
- **内置凭据 hive 硬拦(零配置、恒生效)**:对 `\REGISTRY\MACHINE\SAM` 与 `\REGISTRY\MACHINE\SECURITY` 之下的 `SaveKey` 一律内核本地拒绝,不依赖用户态下发任何名单。刻意不放进通用注册表硬拦名单 —— 那会连带拦下对 SAM 的写值,而创建用户 / 改密码正是 lsass 走写值完成的。
- 用 **`ObRegisterCallbacks`** 实现**自我保护**:其他进程试图以危险权限(结束/写内存/远程线程/挂起)打开本软件的受保护进程时,**剥离这些权限**,使攻击失效。
- 用 **WFP(Windows Filtering Platform)** 在 `FWPM_LAYER_ALE_AUTH_CONNECT_V4` 层注册 callout + filter,**阻断命中黑名单的外发连接**。
- **处置模型(稳定性优先)**:进程创建走 **fire-and-forget 遥测**——`FltSendMessage` 用 0 超时、绝不阻塞在用户态裁决上(由后台发送线程 + 预分配环形缓冲统一发送,队列满即丢弃遥测);内核对系统目录 / 关键进程走白名单零延迟放行;裁决为 `Block` 时由用户态即时 `TerminateProcess` 结束该进程树(启动后补偿),**不在内核挂起进程创建**。
- 文件 / 注册表 / **命令行**硬拦名单与禁止加载、禁止执行名单命中即**内核本地直接返回 `STATUS_ACCESS_DENIED`**(不发 IPC、不等用户态);自我保护 / 反注入 / 网络拦截运行在高 IRQL **不阻塞**,直接剥离危险权限 / `FWP_ACTION_BLOCK` + 异步记录。
- 连接时先做**协议握手**(校验版本号 + 各结构体大小),不一致则用户态一律降级、绝不拦截。
- 受保护路径 / 注册表键 / 进程 PID / 反注入目标 / 网络黑名单 / 命令行硬拦模式由用户态通过 `FilterSendMessage` 下发。
- **内核自足基线**:执行前拦截、禁止加载、文件 / 注册表 / **命令行**硬拦名单等都持久化到 `HKLM\SYSTEM\CurrentControlSet\Services\Bulwark\Policy`,开机由 `Policy.c` 载入。因此**服务未启动 / 被杀 / 从未安装**时,这些拦截依旧生效 —— 反勒索最关键的「删卷影」不依赖任何用户态进程活着。
- 全部使用微软**文档化 API**,PatchGuard 友好,不做 SSDT Hook。

### 命令行硬拦的模式语法

模式是 **`'+'` 分隔的 token 合取**:每个 token 都必须作为大小写不敏感子串出现在命令行里才算命中。

```
VSSADMIN+DELETE+SHADOWS
```

可命中 `vssadmin.exe  Delete   Shadows /All /Quiet`、`C:\Windows\System32\vssadmin.exe /for=c: delete shadows /quiet`
—— 参数顺序、空格数量、大小写、是否带全路径全都不影响判定。若改用整串子串匹配,攻击者调换一次参数顺序就能绕过。

匹配直接吃**原始命令行**,不截断、不预归一化:命令行可长达 32767 字符,若先截到 520 字符再匹配,
在前面填充垫料就能把危险 token 推出截断范围。

> **写模式的硬规矩:每个 token 保持 >= 4 字符。** token 是纯子串,像 `cl` 这种短 token 会命中
> `include` / `class` 之类无关单词造成误报。内置基线为此放弃了 `wevtutil cl Security` 这条。

内置基线(`appsettings.json` 的 `CommandHardBlockBaseline` 控制开关,`CommandHardBlocks` 追加自定义):

| 类别 | 模式 | 拦住什么 |
|---|---|---|
| 反勒索 | `VSSADMIN+DELETE+SHADOWS` | 删除卷影副本 |
| 反勒索 | `VSSADMIN+RESIZE+SHADOWSTORAGE` | 压缩卷影存储以清空全部还原点 |
| 反勒索 | `WMIC+SHADOWCOPY+DELETE` | 走 WMI 删卷影 |
| 反勒索 | `WIN32_SHADOWCOPY+DELETE` | PowerShell / WMI 对象方式删卷影 |
| 反勒索 | `WBADMIN+DELETE+CATALOG` | 删除 Windows 备份目录 |
| 反勒索 | `WBADMIN+DELETE+SYSTEMSTATEBACKUP` | 删除系统状态备份 |
| 反勒索 | `BCDEDIT+RECOVERYENABLED` | 关闭 Windows 恢复环境 |
| 反勒索 | `BCDEDIT+BOOTSTATUSPOLICY` | 关闭启动失败自动修复 |
| 反勒索 | `FSUTIL+DELETEJOURNAL` | 删 USN 变更日志(反取证 + 阻碍恢复) |
| 反凭据窃取 | `SAVE+HKLM\SAM` | 导出 SAM(本机账户口令哈希) |
| 反凭据窃取 | `SAVE+HKLM\SECURITY` | 导出 SECURITY(LSA 机密) |
| 反凭据窃取 | `SAVE+HKEY_LOCAL_MACHINE\SAM` | 同上,根键长写法 |
| 反凭据窃取 | `SAVE+HKEY_LOCAL_MACHINE\SECURITY` | 同上,根键长写法 |

最后四条与 `RegNtPreSaveKey` 的内置 hive 硬拦构成双重保险:这里连 `reg.exe` 都起不来,那里兜住任何其它调用 `ZwSaveKey` 的程序。

> **为什么要列根键的两种写法**:实测 `reg save HKEY_LOCAL_MACHINE\SAM out.hiv` 不含子串 `HKLM\SAM`,
> 只写短写法时这条命令行模式被直接绕过 —— 当时全靠内核 `SaveKey` 那层兜住(纵深防御奏效),
> 但外层这个口子该堵。`reg.exe` 对两种写法等价接受,攻击者自然会选没被覆盖的那个。
>
> 这也说明命令行层的定位:它是**可选外层**,按「字面命令行」判定,天然存在写法变体的长尾;
> 真正的兜底始终是内核按**解析后的键路径 / 映像路径**做的判定 —— 那一层与命令怎么写无关。
> 新增自定义模式时请记住这一点:能在内核按对象判定的,就不要只依赖命令行模式。

源文件:
- `Driver.c` — DriverEntry / 卸载 / Minifilter 注册(I/O 回调 + 实例附加)+ 网络设备对象
- `ProcessMonitor.c` — 进程创建回调与拦截 + 命令行硬拦(token 合取匹配 + 名单管理)+ 驱动级结束进程
- `FileMonitor.c` — 文件删除/重命名拦截 + 受保护项通用匹配
- `RegistryMonitor.c` — 注册表八类通知拦截(写值/删值/删键/改名/hive 导出/hive 挂载/改 ACL/建键)+ 内置凭据 hive 硬拦 + 受保护键管理
- `Policy.c` — 内核自足基线:开机从注册表 `\Policy` 载入各拦截名单 + 已学习裁决去抖写回
- `HashScan.c` — 异步 SHA-256 worker + 内核本地已知恶意哈希集(命中即封禁并结束)
- `Cleanup.c` — 内核级足迹清理(忽略共享访问读 / POSIX 强制删除被占用文件)
- `SelfProtect.c` — ObRegisterCallbacks 句柄回调,剥离对受保护进程的危险权限
- `NetMonitor.c` — WFP callout/filter,阻断黑名单外联 + 黑名单管理
- `Comms.c` — 通信端口、`FltSendMessage` 等待裁决/异步上报、接收配置消息
- `Protocol.h` — 内核↔用户态消息结构(用户态 `DriverEventSource.cpp` 直接 `#include` 复用此头,单一事实来源)
- `ImageMonitor.c` / `ThreadMonitor.c` — 映像加载(`PsSetLoadImageNotifyRoutine`)与远程线程(`PsSetCreateThreadNotifyRoutine`)通知型监控(仅上报供研判)

## 编译(在装有 WDK + VS2022 BuildTools 的机器)

```powershell
.\scripts\build-driver.ps1 -Configuration Debug
# 产物:build\driver\Debug\Bulwark.sys
```

## ⚠ 加载测试(只在带快照的测试虚拟机里)

内核驱动回调里出错会**直接蓝屏(BSOD)**。务必:
1. 用一台**测试虚拟机**,先打快照。
2. 开启测试签名:`bcdedit /set testsigning on` 然后重启。
3. 运行部署脚本(自动建测试证书、签名、安装、启动):

```powershell
.\scripts\deploy-driver-vm.ps1 -Configuration Debug
```

4. 让用户态服务以"驱动模式"运行(连接驱动端口):把 `cpp\service\appsettings.json`(部署后的副本在 `cpp\dist\appsettings.json`)的 `EventSource` 改为 `"Driver"`,然后以管理员运行服务和 UI。
   也可以让部署脚本代改:`.\scripts\deploy-driver-vm.ps1 -Configuration Debug -SetServiceMode`。
   (旧路径 `Bulwark.Service\appsettings.json` 属于已下线的 .NET 原型,现已不再使用。)

5. 观察:用 **DebugView**(勾选 *Capture Kernel*)看 `[Bulwark]` 内核日志;在 UI 弹窗里点"阻止",对应进程将被用户态立即结束(启动后补偿)。

卸载:
```powershell
sc.exe stop Bulwark
sc.exe delete Bulwark
```

## 工作流

```
新进程启动
   │  (内核回调 PASSIVE_LEVEL)
   ▼
封禁主体派生子进程? ─────是──▶ CreationStatus = STATUS_ACCESS_DENIED(内核本地,零 IPC)
   │否
   ▼
映像命中「禁止执行」名单? ─是──▶ CreationStatus = STATUS_ACCESS_DENIED(样本根本起不来)
   │否
   ▼
命令行命中「命令行硬拦」? ─是──▶ CreationStatus = STATUS_ACCESS_DENIED(危险命令一次不执行)
   │否                                 ▲
   │                                   └─ 必须在下一步之前判定:目标 LOLBin 全住在可信路径里
   ▼
系统目录 / 关键进程? ──是──▶ 直接放行(零延迟,不发 IPC;LOLBin 例外,继续上报)
   │否
   ▼
ProcessMonitor 组装事件 ──FltSendMessage(遥测,0 超时,不等待)──▶ 用户态 DriverEventSource
   │                                                          │
   ▼                                                   规则引擎评估 / UI 弹窗
进程立即正常启动                                                 │
                                                               ▼
                                          裁决 = Block → 用户态 TerminateProcess 结束进程树
```

> 上面三条 `STATUS_ACCESS_DENIED` 分支是**真·执行前阻断**,全程不发 IPC、不等用户态,且名单持久化后
> 在服务不在时同样生效。所有分支之上还有一条不可逾越的硬底线:**关键系统进程绝不拦、绝不上报**
> (防 `CRITICAL_PROCESS_DIED` 0xEF),即便名单被误配也拦不死系统。
>
> 文件 / 注册表硬拦、自我保护、反注入、网络黑名单同理:它们在内核本地(或高 IRQL)即时阻断,
> 不走启动后补偿路径。

## 局限与后续

- 已实现全部六个里程碑:进程创建拦截(M2)、文件删除/重命名拦截(M3)、注册表拦截(M4)、自我保护(M5)、网络外联黑名单拦截(M6)。
- 自我保护默认保护**服务进程自身**;UI 连接服务时会上报其 PID,服务再下发内核一并保护。
- 自保用 `ObRegisterCallbacks`,**驱动必须带 `/INTEGRITYCHECK` 链接**(已配置)且镜像须有有效签名,否则注册返回 `STATUS_ACCESS_DENIED`。
- 网络防护当前为 IPv4 + 黑名单(精确 IP/端口);可扩展为域名解析黑名单、IPv6(ALE_AUTH_CONNECT_V6)、入站(`ALE_AUTH_RECV_ACCEPT`)、监听端口(`ALE_RESOURCE_ASSIGNMENT`,防后门 bind)、按进程放行等。
- 文件/注册表防护用"子串匹配"判断受保护项,简单但够用;后续可换成更精确的前缀/规范化匹配(现状:`D:\Program Files\` 也会命中可信目录判定)。
- **刻意未处理 `RegNtPreLoadKeyEx`**:`REG_LOAD_KEY_INFORMATION_V2` 首成员是 `Size` 而非 `Object`,与 V1 布局不同。合并处理会把一个 `ULONG` 当指针交给 `CmCallbackGetKeyObjectIDEx`,直接蓝屏。宁可少覆盖一条通知,也不引入这种解引用风险。已覆盖 `RegNtPreLoadKey`(V1)。
- 命令行硬拦命中时**内核直接拒绝、不弹窗**,故名单必须只收「几乎不存在良性用法」的破坏性动作;命中后仍上报 `BlwEventCommandBlocked` 供 UI 如实展示拦了什么。发起方(父进程)本身**不会**被自动结束 —— 事件标记 `kernelBlocked`,按现有语义不再补杀。若要对「刚试过删卷影的进程」直接封禁,需另接 `BLW_CMD_ADD_BANNED`,不在当前实现内。
- `ImageMonitor.c` / `ThreadMonitor.c` 仍是**通知型**(内核 API 本身不支持阻止),映像加载的实际阻断依赖 `FileNoLoad` 名单在 `IRP_MJ_CREATE` 上拦执行映射;BYOVD 尚无专门的驱动服务注册拦截。
- 正式发布需 EV 证书 + 微软 WHQL/附件签名,测试证书仅供本地验证。
- 驱动目前**没有任何自动化测试**。名单匹配那几个纯函数(`BlwWideContainsCI` / `BlwImageNameIn` / `BlwCmdPatternMatches`)最容易出错也最容易测,抽成可在用户态编译的独立文件跑 host 单测是成本最低的下一步。
