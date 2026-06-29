# 磐垒主动防御(Bulwark)

简体中文 | [English](README.en.md)

一个类似磐垒的主机入侵防御(HIPS)软件骨架。核心思路:**监控系统敏感行为 → 规则引擎决策 → 必要时弹窗让用户裁决(允许/阻止/记住)**。

> 当前进度:已打通 `内核驱动(R0) ↔ 用户态服务(R3) ↔ UI` 完整链路,**六个防护里程碑(M1–M6)全部完成**。
> - **M1+**:服务↔UI 链路、WMI 真实进程观测、Authenticode 签名校验、SHA-256、规则管理、服务安装。
> - **M2–M6(内核驱动)**:进程拦截、文件防护、注册表防护、自我保护、网络外联拦截。驱动已能编译产出 `Bulwark.sys`,详见 `Bulwark.Driver/README.md`。

> 三种事件源可切换(appsettings.json 的 `EventSource`):`Driver`(内核拦截,含全部 M2–M6)、`Wmi`(用户态观测)、`Simulated`(演示)。

## 解决方案结构

```
Bulwark.sln
├─ Bulwark.Core      共享层:事件模型、裁决、规则、规则引擎、IPC 协议
│   ├─ Models/          SecurityEvent / Verdict / DefenseRule / Evidence(证据链)
│   ├─ Engine/          RuleEngine(决策中心)+ ThreatDetector / LolbinAnalyzer(白利用)
│   │                   / KillChainAnalyzer / AttackCatalog + AttackAnnotator(ATT&CK 标注)等
│   └─ Ipc/             IpcMessage(命名管道消息协议)
├─ Bulwark.Driver    内核驱动(R0):进程创建拦截 + Filter Manager 通信端口
│   ├─ Driver.c         DriverEntry / Minifilter 注册
│   ├─ ProcessMonitor.c PsSetCreateProcessNotifyRoutineEx 拦截
│   ├─ Comms.c          通信端口 + FltSendMessage 等待裁决
│   └─ Protocol.h       内核↔服务消息结构
├─ Bulwark.Service   用户态服务(R3):决策宿主 + 命名管道服务端
│   ├─ Ipc/             IpcServer
│   ├─ Driver/          FilterApi(fltlib P/Invoke) + DriverStructs(布局对应 Protocol.h)
│   ├─ Monitoring/      IEventSource 三实现:DriverEventSource(内核拦截)
│   │                   / WmiProcessEventSource(观测) / SimulatedEventSource(演示)
│   │                   + ProcessInspector(签名/哈希) + IVerdictSink(裁决回写)
│   ├─ Storage/         RuleStore(规则 JSON 持久化)
│   ├─ BulwarkOptions.cs  配置(事件源/信任策略/超时)
│   └─ Worker.cs        主防御循环
└─ Bulwark.UI.Scifi  Avalonia 界面(科幻风):状态、实时日志、行为弹窗、规则管理
    ├─ Services/        IpcClient / TrayManager
    ├─ Views/           MainWindow 主窗口 + Dashboard/InterceptLog/Rules/Quarantine/Settings/Trust 页
    ├─ PromptWindow     行为询问弹窗(允许/阻止/记住)
    ├─ RulesPage        规则管理(查看/刷新/删除)
    └─ app.manifest     请求管理员权限

scripts/
├─ build-driver.ps1      编译内核驱动(WDK)
├─ deploy-driver-vm.ps1  在测试虚拟机里签名/安装/启动驱动
├─ install-service.ps1   发布并注册为 Windows 服务(管理员)
└─ uninstall-service.ps1 停止并删除服务(管理员)
```

## 配置(appsettings.json 的 Bulwark 节)

```jsonc
{
  "Bulwark": {
    "EventSource": "Wmi",        // Driver=内核拦截 / Wmi=用户态观测 / Simulated=演示
    "TrustSignedActors": true,    // 自动放行带可信签名的程序
    "DefaultAction": "Allow",     // 无规则/超时兜底:Allow 或 Block
    "PromptTimeoutSeconds": 30,   // 弹窗等待超时
    "ProtectedPaths": [           // 仅 Driver 模式生效:受保护文件路径(子串匹配)
      "\\Bulwark_Protected\\"
    ],
    "ProtectedRegistryKeys": [    // 仅 Driver 模式生效:受保护注册表键(子串匹配)
      "\\CurrentVersion\\Run"
    ],
    "BlockedRemoteEndpoints": [   // 仅 Driver 模式生效:网络黑名单(IP 或 IP:端口)
      "203.0.113.66:443"
    ]
  }
}
```

## 运行(开发调试)

真实进程监控(WMI)需要**管理员权限**。需要两个终端,先启动服务,再启动 UI,**两者都用管理员身份运行**:

```powershell
# 终端 1:启动服务(控制台模式调试运行)
dotnet run --project Bulwark.Service

# 终端 2:启动 UI(manifest 已声明 requireAdministrator)
dotnet run --project Bulwark.UI.Scifi
```

UI 顶部状态点变绿表示已连接服务。现在每当系统有**真实进程启动**:
- 带可信签名的进程 → 引擎自动放行,直接出现在日志;
- 无签名的进程 → 弹窗让你选择「允许 / 阻止」,可勾选「记住我的选择」生成持久规则。

点「规则管理」可查看/删除已保存的规则。规则持久化在 `%ProgramData%\Bulwark\rules.json`。

> 想先看演示而不监控真实进程,把 `appsettings.json` 的 `EventSource` 改为 `"Simulated"`。

## 作为 Windows 服务安装(管理员)

```powershell
# 以管理员身份运行 PowerShell
.\scripts\install-service.ps1     # 发布并注册自启动服务
.\scripts\uninstall-service.ps1   # 卸载
```

## 决策优先级(RuleEngine)

1. 命中已有规则 → 直接 Allow/Block
2. 主体带可信签名且开启信任 → Allow
3. 否则 → 弹窗询问用户(超时按默认策略处置,默认 Allow,可改 Block)

## 可解释性与高级检测(已完成)

在「只对真危险行为动手、低误报、互证」原则下,新增以下相互增强的能力:

- **证据链时间线(可解释性)**:每个事件都附带结构化 `EvidenceChain`,逐条记录
  「来源分析器 / 类别(硬指标·软信号·互证升格·信任·规则·裁决)/ 风险分贡献 / 说明」,
  末尾以「最终裁决」收尾。行为弹窗里以彩色时间线呈现「为什么这么判」,不再只有一个孤立分数;
  同一结构化数据也作为 AI 研判的输入。与旧的扁平 `RiskReasons` 并存,完全向后兼容。

- **LOLBins(白利用)滥用分析(`LolbinAnalyzer`)**:识别微软签名的系统二进制
  (regsvr32 / rundll32 / mshta / certutil / bitsadmin / msbuild / installutil / msiexec /
  wmic / mavinject 等)被「二进制 + 特征参数」滥用的已知技战术(Squiblydoo、远程 HTA、
  certutil 下载、msbuild 内联任务、wmic 远程执行、comsvcs 转储 LSASS 等)。
  高置信滥用作为硬指标,并让 `TrustPolicy` 的「强可信/健康签名放行」门禁失效 ——
  这是「签名可信 ≠ 行为可信」的关键补强(只看签名永远抓不到白利用)。

- **MITRE ATT&CK 技战术标注(`AttackCatalog` + `AttackAnnotator`)**:把各分析器命中
  统一映射到 ATT&CK 技战术编号(如 T1218.010 Squiblydoo、T1003.001 LSASS 转储、
  T1490 抑制系统恢复),写回每条证据并在事件上汇总去重。行为弹窗以技战术标签展示,
  告警与 AI 报告从「一句话原因」升级为标准化技战术标签。几乎零运行时成本(查表 + 文本提取)。

- **凭据访问 / LSASS 保护(`CredentialAccessAnalyzer`)**:从「目标/路径 + 命令行 + 行为类型」
  识别凭据窃取 —— LSASS 内存转储/注入(T1003.001)、导出 SAM/SECURITY 蜂巢(T1003.002)、
  提取域控 NTDS.dit(T1003.003)、浏览器凭据库/DPAPI(T1555)。高置信攻击作为硬指标,
  并让签名系统工具(reg.exe/ntdsutil 等)在做凭据导出时失去信任放行豁免。

- **持久化审计视图(`PersistenceScanner` + `PersistenceAnalyzer` + 持久化审计页)**:
  只读枚举七类自启动持久化点 —— 注册表 Run/RunOnce、启动文件夹、Windows 服务、计划任务、
  映像劫持(IFEO)、Winlogon、AppInit_DLLs;每项复用 ThreatDetector 启发式打分并标注
  ATT&CK 持久化技战术(T1547/T1543/T1546/T1053)。UI 按风险等级(高危/可疑/关注/正常)
  着色排序展示,帮助快速发现可疑驻留。绝不修改任何自启动项,清理仍走既有规则/隔离流程。

- **ECS 结构化告警导出(`EcsAlertFormatter` + `AlertExporter`)**:把每个已处置事件格式化为
  Elastic Common Schema 风格 JSON-lines(`event.* / process.code_signature.* / destination.* /
  threat.technique[] / threat.tactic[]`,并在 `bulwark.*` 下保留证据链与原因),写入
  `%ProgramData%\Bulwark\alerts\alerts-yyyyMMdd.jsonl`,可无缝接入 SIEM(Elastic/Splunk/
  OpenSearch)。由 `appsettings.json` 的 `ExportEcsAlerts` 开关控制,默认关闭,不改变任何裁决。

- **规则有效期与作用范围**:`DefenseRule` 支持可选到期时间(`ExpiresUtc`)与「仅本次会话」
  作用域(`SessionOnly`)。行为弹窗「记住选择」可选范围 —— 永久 / 本次会话 / 1 小时 / 1 天:
  会话规则不落盘、重启即失效;限时规则到期自动失效并被清理。降低「记住」一时之选却造成
  永久误放行的风险。

- **信誉缓存分级 TTL + 离线兜底(`ReputationCache`)**:恶意结论永久缓存、干净结论按天 TTL、
  可疑结论独立较短 TTL(更快重校验)、Unknown 短期负缓存。富化读取(`TryGetForEnrichment`)在
  TTL 过期后仍返回上一次已知结论,使断网/查询失败时仍能用「最近已知信誉」富化;新鲜度由后台
  重查负责。信誉全程只加/减分,绝不单独处置,断网不影响实时防护。

## 驱动级防护(M2,已完成)

详见 `Bulwark.Driver/README.md`。简要流程:

```powershell
# 1) 编译驱动(本机有 WDK 即可)
.\scripts\build-driver.ps1 -Configuration Debug   # 产出 build\driver\Debug\Bulwark.sys

# 2) 仅在【带快照的测试虚拟机】里加载(回调出错会蓝屏!)
.\scripts\deploy-driver-vm.ps1                    # 开测试签名/建测试证书/签名/安装/启动

# 3) 把 appsettings.json 的 EventSource 改为 "Driver",以管理员运行服务+UI
```

驱动通过 `PsSetCreateProcessNotifyRoutineEx` 在进程启动前拦截,经通信端口把事件交给服务裁决,
裁决为 Block 时设置 `CreationStatus=STATUS_ACCESS_DENIED`,进程无法启动。

## 后续里程碑

| 里程碑 | 内容 | 关键内核机制(均为微软文档化 API) | 状态 |
|--------|------|-----------------------------------|------|
| M2 | 进程防护 | `PsSetCreateProcessNotifyRoutineEx` | ✅ 已完成 |
| M3 | 文件防护 | Minifilter I/O 回调(`IRP_MJ_CREATE` / `IRP_MJ_SET_INFORMATION`) | ✅ 已完成 |
| M4 | 注册表防护 | `CmRegisterCallbackEx`(写值/删值/删键) | ✅ 已完成 |
| M5 | 自我保护 | `ObRegisterCallbacks`(剥离危险句柄权限) | ✅ 已完成 |
| M6 | 网络防护 | WFP(`ALE_AUTH_CONNECT_V4` 黑名单阻断) | ✅ 已完成 |

新增防护维度时**无需改动 UI/规则引擎**:在驱动里新增回调并复用同一通信端口上报事件,
服务侧 `DriverEventSource` 解析新事件类型即可。

> 驱动需数字签名:开发期开启测试签名(`bcdedit /set testsigning on`)+ 测试虚拟机;正式发布需 EV 证书与 WHQL 认证。务必在带快照的虚拟机中调试,回调错误会导致蓝屏(BSOD)。

## 安全说明

本项目为正当的终端安全防护工具(与杀软/EDR 同类),自我保护应保留用户可控的正常卸载入口,不做成"无法卸载"。
