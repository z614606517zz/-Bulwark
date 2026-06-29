# Bulwark.Driver(内核驱动 / M2 进程防护)

磐垒主动防御的内核驱动。提供**真正的驱动级进程拦截**:可在进程启动前阻止它。

## 它做了什么

进程防护(M2)+ 文件防护(M3)+ 注册表防护(M4)+ 自我保护(M5)+ 网络防护(M6):

- 注册一个 **Minifilter**,既挂接 I/O 操作回调(文件防护),又借用 Filter Manager 的**通信端口**(`FltCreateCommunicationPort` / `FltSendMessage`)与用户态服务通信。
- 用 **`PsSetCreateProcessNotifyRoutineEx`** 拦截每个进程创建。
- 用 **`IRP_MJ_CREATE`(FILE_DELETE_ON_CLOSE)** 与 **`IRP_MJ_SET_INFORMATION`(FileDispositionInformation / FileRenameInformation)** 预操作回调拦截**受保护文件**的删除与重命名。
- 用 **`CmRegisterCallbackEx`** 拦截对**受保护注册表键**的写值(`RegNtPreSetValueKey`,如启动项)、删值(`RegNtPreDeleteValueKey`)、删键(`RegNtPreDeleteKey`)。
- 用 **`ObRegisterCallbacks`** 实现**自我保护**:其他进程试图以危险权限(结束/写内存/远程线程/挂起)打开本软件的受保护进程时,**剥离这些权限**,使攻击失效。
- 用 **WFP(Windows Filtering Platform)** 在 `FWPM_LAYER_ALE_AUTH_CONNECT_V4` 层注册 callout + filter,**阻断命中黑名单的外发连接**。
- 进程/文件/注册表事件会发给用户态**同步等待裁决**(最长 5 秒,可调);自我保护与网络拦截因运行在高 IRQL **不阻塞**,直接处置 + 异步记录。
- 裁决为 `Block` 时:进程事件设 `CreateInfo->CreationStatus = STATUS_ACCESS_DENIED`;文件/注册表事件返回 `STATUS_ACCESS_DENIED`;网络命中黑名单则 `FWP_ACTION_BLOCK`。
- 受保护路径/注册表键/进程 PID/网络黑名单由用户态通过 `FilterSendMessage` 下发。
- 全部使用微软**文档化 API**,PatchGuard 友好,不做 SSDT Hook。

源文件:
- `Driver.c` — DriverEntry / 卸载 / Minifilter 注册(I/O 回调 + 实例附加)+ 网络设备对象
- `ProcessMonitor.c` — 进程创建回调与拦截
- `FileMonitor.c` — 文件删除/重命名拦截 + 受保护项通用匹配
- `RegistryMonitor.c` — 注册表写值/删值/删键拦截 + 受保护键管理
- `SelfProtect.c` — ObRegisterCallbacks 句柄回调,剥离对受保护进程的危险权限
- `NetMonitor.c` — WFP callout/filter,阻断黑名单外联 + 黑名单管理
- `Comms.c` — 通信端口、`FltSendMessage` 等待裁决/异步上报、接收配置消息
- `Protocol.h` — 内核↔用户态消息结构(C# 侧 `DriverStructs.cs` 与之对应)

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

4. 让用户态服务以"驱动模式"运行(连接驱动端口):把 `Bulwark.Service\appsettings.json` 的 `EventSource` 改为 `"Driver"`,然后以管理员运行服务和 UI。

5. 观察:用 **DebugView**(勾选 *Capture Kernel*)看 `[Bulwark]` 内核日志;在 UI 弹窗里点"阻止",对应进程将无法启动。

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
ProcessMonitor 组装事件 ──FltSendMessage──▶ 用户态服务 DriverEventSource
   ▲                                              │
   │                                       规则引擎评估 / UI 弹窗
   │                                              ▼
   └──────FilterReplyMessage(裁决)◀──────── Allow / Block
   │
   ▼
Block → CreationStatus=STATUS_ACCESS_DENIED(进程被拒绝)
Allow → 进程正常启动
```

## 局限与后续

- 已实现全部六个里程碑:进程创建拦截(M2)、文件删除/重命名拦截(M3)、注册表写值/删值/删键拦截(M4)、自我保护(M5)、网络外联黑名单拦截(M6)。
- 自我保护默认保护**服务进程自身**;UI 连接服务时会上报其 PID,服务再下发内核一并保护。
- 自保用 `ObRegisterCallbacks`,**驱动必须带 `/INTEGRITYCHECK` 链接**(已配置)且镜像须有有效签名,否则注册返回 `STATUS_ACCESS_DENIED`。
- 网络防护当前为 IPv4 + 黑名单(精确 IP/端口);可扩展为域名解析黑名单、IPv6(ALE_AUTH_CONNECT_V6)、按进程放行等。
- 文件/注册表防护用"子串匹配"判断受保护项,简单但够用;后续可换成更精确的前缀/规范化匹配。
- 正式发布需 EV 证书 + 微软 WHQL/附件签名,测试证书仅供本地验证。
