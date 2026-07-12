# 磐垒主动防御(Bulwark)

简体中文 | [English](README.en.md)

一个类似磐垒的主机入侵防御(HIPS)软件骨架。核心思路:**监控系统敏感行为 → 规则引擎决策 → 必要时弹窗让用户裁决(允许/阻止/记住)**。

磐垒采用三层协作架构:**内核态驱动(R0)** 负责真正的「行为发生前」拦截,**用户态 Windows 服务(R3)** 承载决策逻辑,**Qt 桌面 UI** 负责状态展示、实时日志、行为弹窗与规则管理。驱动 ↔ 服务经 Filter Manager 通信端口对话,服务 ↔ UI 经命名管道对话。无论事件来自哪个事件源,统一由一个 `RuleEngine` 作为决策中心,并由威胁启发式、LOLBin 白利用检测、MITRE ATT&CK 标注、凭据访问检测与多引擎哈希信誉共同增强。

> 当前进度:本项目为 **C++ / Qt** 实现(由早期 .NET 原型移植而来)。用户态链路 `服务(R3) ↔ UI` + **ETW 实时观测** 可直接编译运行;**内核驱动(R0)** 可编译产出 `Bulwark.sys`,且用户态对接(连接 / 协议握手 / 事件收取 / 裁决回写)已完备。六个防护维度(M1–M6)在代码层面均已实现。
> - **用户态(R3 + UI)**:服务↔UI 命名管道链路、ETW 实时进程/网络/注册表/文件观测、Authenticode 签名校验、SHA-256、规则管理、SCM 服务安装(`bulwark_service.exe --install`)。
> - **内核驱动(M2–M6)**:进程遥测、文件防护、注册表防护、自我保护、网络外联拦截。详见 `Bulwark.Driver/README.md` 与文末章节。

> ⚠ **驱动尚未在真实内核里验证过端到端拦截**:`Bulwark.sys` 需在**带快照的测试虚拟机**里开测试签名并加载后才能真正启用「行为发生前」内核拦截(见文末驱动章节)。默认发布产物跑的是 ETW 用户态观测链路。

> 三种事件源可切换(`appsettings.json` 的 `EventSource`):`Driver`(启用内核驱动 + ETW 观测,含全部 M2–M6)、`Wmi`(仅 ETW 用户态观测,历史沿用「Wmi」这一取值名)、`Simulated`(演示,不监控真实系统)。

## 解决方案结构

```
cpp/                     C++ / Qt 实现(CMake 顶层:cpp/CMakeLists.txt)
├─ shared/            共享契约层(静态库,仅依赖 Qt6::Core;服务与 UI 共用)
│   ├─ src/models/       SecurityEvent / Verdict / DefenseRule / Evidence(证据链)
│   ├─ src/engine/       RuleEngine(决策中心)+ ThreatDetector / LolbinAnalyzer(白利用)
│   │                    / KillChainAnalyzer / AttackCatalog + AttackAnnotator(ATT&CK)
│   │                    / CredentialAccessAnalyzer / PersistenceAnalyzer / DefaultRules 等
│   └─ src/ipc/          IpcMessage(命名管道消息协议)
├─ service/           用户态服务(R3,生成 bulwark_service.exe):决策宿主 + 命名管道服务端
│   ├─ src/main.cpp                装配 + SCM 集成(--install / --uninstall / --service)
│   ├─ src/Worker.cpp              主防御循环:事件 → 富化 → 引擎 → 裁决 → 处置/清理
│   ├─ src/IpcServer.cpp           命名管道服务端(与 UI 通信)
│   ├─ src/EventSourceCoordinator.cpp  合并 ETW + 用户态行为源 +(热切换的)内核驱动源
│   ├─ src/DriverEventSource.cpp   连 \BulwarkPort:握手 + 下发配置 + 收事件 + 回写裁决
│   ├─ src/DriverControl.cpp       按需注册 / 加载 Bulwark.sys(minifilter,幂等)
│   ├─ src/EtwProcessEventSource.cpp / SimulatedEventSource.cpp  两种基础事件源
│   ├─ src/monitoring/ProcessInspector.cpp  签名 / 哈希 / 命令行取证
│   ├─ src/reputation/             VirusTotal / 微步 / MalwareBazaar / OTX 等信誉客户端
│   └─ src/*Store.cpp              规则 / 隔离 / 事件历史等 JSON 持久化
└─ ui/                桌面 UI(生成 bulwark_ui.exe):Qt Widgets,经命名管道连服务

Bulwark.Driver/         内核驱动(R0),与 cpp/ 平级,用 MSBuild + WDK 构建:Minifilter + 通信端口
├─ Driver.c             DriverEntry / 卸载 / Minifilter 注册 + 网络设备对象
├─ ProcessMonitor.c     PsSetCreateProcessNotifyRoutineEx 进程遥测
├─ FileMonitor.c / RegistryMonitor.c / SelfProtect.c / NetMonitor.c / ImageMonitor.c / ThreadMonitor.c
├─ Comms.c              通信端口 + FltSendMessage 上报 / 接收配置
└─ Protocol.h           内核↔服务消息结构(用户态 DriverEventSource 直接复用此头,单一事实来源)

scripts/
├─ build-driver.ps1      编译内核驱动(WDK + MSBuild)→ build\driver\<Cfg>\Bulwark.sys
└─ deploy-driver-vm.ps1  在测试虚拟机里签名 / 注册 minifilter / 加载驱动
```

## 配置(appsettings.json 的 Bulwark 节)

```jsonc
{
  "Bulwark": {
    "EventSource": "Driver",       // Driver=内核驱动+ETW / Wmi=仅 ETW 观测 / Simulated=演示
    "KernelDriverEnabled": true,   // 启用内核驱动(EventSource=Driver 时等效开启)
    "TrustSignedActors": true,     // 自动放行带可信签名的程序
    "PromptTimeoutSeconds": 30,    // 弹窗等待超时
    "ProtectedPaths": [            // 受保护文件路径(子串匹配):Driver 模式内核拦截,Wmi 模式作 ETW 观测集
      "\\Start Menu\\Programs\\Startup\\", "\\System32\\drivers\\etc\\hosts", "\\Tasks\\"
    ],
    "ProtectedRegistryKeys": [     // 受保护注册表键(子串匹配)
      "\\CurrentVersion\\Run", "\\CurrentVersion\\RunOnce", "\\Winlogon", "\\Services\\"
    ],
    "MemoryProtectionTargets": [ "lsass.exe" ],   // 反注入保护目标(仅 Driver 模式)
    "BlockedRemoteEndpoints": [ ],                // 网络黑名单 IP[:端口](仅 Driver 模式)
    "Etw": { "Enabled": true, "KernelNetwork": true, "KernelRegistry": true, "KernelFile": true }
  }
}
```

> 完整默认配置见 `cpp/service/appsettings.json`(须与 `bulwark_service.exe` 同目录);另含威胁情报各源(`VirusTotal` / `MalwareBazaar` / `Otx` / `ThreatBook` / `MetaDefender` / `HybridAnalysis` / `ThreatFoxFeed`)与 `Ai` 大模型节点,默认全关。

## 快速开始(一键启动)

仓库根目录提供两个一键脚本,会自动请求管理员权限,依次完成:编译 → 部署到 `cpp\dist` → 安装并启动 `BulwarkService` → 打开 UI。

- **`一键启动-仅用户态.bat`** —— 推荐首次使用。只跑用户态 ETW 观测链路,**不加载内核驱动、不改测试签名、无蓝屏风险**。
- **`一键启动.bat`** —— 完整链路,额外编译并加载内核驱动 `Bulwark.sys`(会开启测试签名并需重启一次)。⚠ **内核回调出错可能蓝屏(BSOD),请务必在带快照的测试虚拟机中运行。**

其余根目录脚本:`启用驱动.bat`(单独加载内核驱动)、`诊断驱动.bat`(驱动加载诊断,结果写入 `driver_diag.txt`)。

> 需预装 **Visual Studio 2022(含 C++ 工具链)** 与 **Qt 6.8**;脚本默认 Qt 路径为 `C:\Qt\6.8.3\msvc2022_64`,可编辑 `cpp\scripts\dev-all.ps1` 调整。

## 构建与运行(开发调试)

需要 **Visual Studio 2022(含 C++ 工具链)** 与 **Qt 6.8**。ETW 实时观测与内核驱动都需**管理员权限**。

```powershell
# 1) 配置 + 构建(顶层 CMake 一并构建 shared / service / ui)
cmake -G "Visual Studio 17 2022" -A x64 -S cpp -B cpp\build -DCMAKE_PREFIX_PATH="C:/Qt/6.8.3/msvc2022_64"
cmake --build cpp\build --config Release

# 2) 以管理员分别运行服务与 UI(appsettings.json 需与 bulwark_service.exe 同目录)
.\cpp\build\service\Release\bulwark_service.exe   # 终端 1:服务(控制台调试模式)
.\cpp\build\ui\Release\bulwark_ui.exe             # 终端 2:UI(manifest 已声明 requireAdministrator)
```

UI 顶部状态点变绿表示已连接服务。每当系统有**真实进程启动**:
- 带可信签名的进程 → 引擎自动放行,直接出现在日志;
- 无签名的进程 → 弹窗让你选择「允许 / 阻止」,可勾选「记住我的选择」生成持久规则。

点「防护规则」可查看/删除已保存的规则。规则持久化在 `%ProgramData%\Bulwark\rules.json`。

> `cpp\dist\` 下已有一份打包产物(`bulwark_service.exe` + `bulwark_ui.exe` + Qt 运行库),可直接以管理员运行。
> 想先看演示而不监控真实系统,把 `appsettings.json` 的 `EventSource` 改为 `"Simulated"`;想启用内核「行为前」拦截,改为 `"Driver"` 并按文末章节在测试虚拟机加载驱动。

## 界面功能与使用方法

UI 左侧导航共 10 个页面(顺序如下),顶部状态点变绿(链路在线)表示已连接服务。侧栏底部标注 `v1.0.0 · Qt Edition`。关闭主窗口会最小化到系统托盘,后台持续防护。

### ▣ 仪表盘(Dashboard)
总览页,纯展示无需操作。包含:顶部「防护中 / 未连接服务」状态横幅与 ONLINE/OFFLINE 指示;**KERNEL** 行显示内核驱动连接状态与文案;**AI CREDITS** 月度用量进度条(优先显示小米平台官方用量,否则本地估算,并列出各 AI 功能的调用次数/Credits 分项);四张统计卡片 **ALLOWED / BLOCKED / AI SCANS / TOTAL**;底部 **LIVE LOG** 实时滚动被处置的进程/文件/注册表/网络事件。

### 📋 拦截记录(InterceptLog)
被「直接拦截」的确定性高危行为。每条显示类型徽标、主体名 + 动作、目标、主体路径、时间、「已拦截」标记。**双击任意条目可打开「攻击时间线」窗口**回溯整个攻击链。

### 📡 活动日志(ActivityLog)
更全的事件流:带风险分的放行、需询问、被拦截的事件都在此。每条显示类型、主体+动作、目标、路径、时间、裁决文案(着色)与风险分。**双击可查看攻击时间线**。事件历史落盘保留,重启后回填。

### ⚡ 防护规则(Rules)
查看与管理防御规则。每行显示:规则说明、主体、命中条件、状态标签(临时/会话/停用)、行为类型、处置(拦截=红 / 放行·询问=青)。操作:
- **+ 新增规则** — 打开规则编辑器手动新建(主体自动识别为精确路径 / 通配 / 裸文件名)。
- **🤖 AI 生成** — 用自然语言描述需求(如「禁止 wscript 创建子进程」),AI 给出 1~5 条建议规则,逐条点 **采纳** 加入。
- **↻ 刷新** / 每行 **删除**。
- 提示:在行为弹窗里勾选「记住选择」也会自动生成规则。

### ✓ 信任名单(Trust)
受信任的程序与目录名单,名单内目标的行为**直接放行、不再检测**。操作:**+ 添加信任** 选择可执行文件**或整个目录**(目录信任放行其下所有程序)、每行 **移除**、**↻ 刷新**。每行显示路径与备注。

### 🗃 隔离区(Quarantine)
被确认恶意并隔离的文件。列:FILE(文件名+原路径)/ REASON(原因)/ DATE(隔离时间)/ OPS。操作:**还原**(恢复到原位置)、**删除**(永久删除)、**↻ 刷新**。

### ⚓ 自启动项(Persistence)
点 **↻ 扫描** 只读枚举七类自启动持久化点:注册表 Run/RunOnce、启动文件夹、Windows 服务、计划任务、映像劫持(IFEO)、Winlogon、AppInit_DLLs。每行显示类别、名称、命令、位置、命中的 ATT&CK 技战术、原因,以及风险等级 + 分值(按等级着色)。**只读,绝不修改任何自启动项**,清理仍走规则/隔离流程。

### ☁ 云信誉(Reputation)
多引擎哈希信誉查询中心,聚合 **VirusTotal(旗舰,内置默认 Key)+ 微步 ThreatBook + MalwareBazaar + OTX + MetaDefender + HybridAnalysis** 六个源。页面含:各源的启用/连接**状态**与测试连接、按**文件/哈希手动查询**信誉、以及 **VirusTotal 查询历史**(双击启动未签名/本机首见程序时会自动上传查询并在此留痕:文件名、来源、路径、SHA256、状态与时间)。查毒命中恶意/可疑会自动弹出行为关系图详情窗口。

### 🤖 AI 研判(AiScan)
由小米 MiMo 大模型基于**静态内容特征**(签名/路径/PE 结构/脚本源码/字符串/熵等)研判文件恶意性,**不执行样本**。按钮:**🔍 扫描溯源**(选一个文件,研判后弹出详细报告)、**📄 扫描文件**、**📁 扫描文件夹**、**⏹ 停止**。顶部统计 SCANNED / CLEAN / SUSPICIOUS / MALICIOUS;结果列表含 文件路径+SHA256、判定、置信度、摘要,每行可点 **溯源**。

### ⚙ 设置(Settings)
- **主动防御**总开关(关闭后所有事件直接放行)。
- **防护维度**:进程 / 文件 / 注册表 / 自我保护 / 网络,逐项开关。
- **决策策略**:自动信任签名程序、默认阻止(无规则/超时兜底)、静默模式(询问类自动放行,仅拦确定性高危)、拦截即隔离。
- **内核驱动**:启用内核驱动开关,并显示连接状态 / 内核状态 / 当前事件源。
- **威胁情报**:启用 VirusTotal 后台信誉查询、测试连接、按文件路径手动查询信誉。
- **AI / 大模型研判**:双击启动 AI 扫描、研判期间挂起进程、研判失败时拦截(严格模式)、灰区 AI 研判、Credits 预算护栏 + 月度额度(亿)、官方用量显示(填 Cookie)+ 测试获取。
- **持续行为防护(事后)**:用户态持续行为监控、勒索蜜罐(诱饵文件)、行为基线异常检测。
- **模型配置**:API 基址 / API Key / 模型,并可「测试 AI」。
- **扫描内容上限**:脚本源码上限(KB)、二进制采样上限(MB)、字符串提取条数。

### 弹窗与通知
- **行为裁决弹窗(PromptDialog)**:无规则命中且主体不可信时弹出。顶部按风险等级着色的横幅 + 等级徽标;数字签名 + VirusTotal 情报两张卡;程序 / 说明 / 命令行 / 行为(含 ATT&CK 标签)/ 目标明细;SHA256 + 风险评分;可展开「**进程溯源**」与「**判定依据 · 证据链时间线**」;「🤖 AI 安全助手」可生成攻击叙事;底部「不再提醒(记住此选择)」+ 范围下拉(永久 / 本次会话 / 1 小时 / 1 天)+ **✓ 允许** / **✕ 拦截**。
- **拦截通知(ToastWindow · Block)**:确定性高危被直接拦截时弹出的角标通知(由 `ToastNotifier` 统一堆叠管理)。
- **AI 扫描提示(ToastWindow · AiScan)**:双击启动程序触发 AI 研判时的轻量提示。
- **托盘**:关闭主窗口最小化到系统托盘,后台持续防护。

## 作为 Windows 服务安装(管理员)

服务自带 SCM 注册,无需额外脚本(用户态服务名 `BulwarkService`,与内核驱动服务 `Bulwark` 区分):

```powershell
# 以管理员身份运行
.\bulwark_service.exe --install     # 注册为自动启动服务
sc start BulwarkService             # 启动
.\bulwark_service.exe --uninstall   # 停止并卸载
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

## 内核驱动(R0):真正的「行为发生前」拦截

`Bulwark.Driver` 是磐垒的内核态组件,让磐垒能在危险动作**发生之前**就拦下来,而不是只做事后观测。全部使用微软**文档化 API**、不做 SSDT Hook,因此 **PatchGuard 友好**。它注册一个 **Minifilter**,既挂接 I/O 回调,又借用 Filter Manager 的**通信端口**(`FltCreateCommunicationPort` / `FltSendMessage`)与用户态服务通信。

五大防护维度:

| 维度 | 内核机制 | 拦截内容 |
|------|----------|----------|
| **进程(M2)** | `PsSetCreateProcessNotifyRoutineEx` | 每个进程创建(遥测上报;命中拦截由用户态在启动后即时结束进程树) |
| **文件(M3)** | Minifilter 预操作 `IRP_MJ_CREATE`(delete-on-close)+ `IRP_MJ_SET_INFORMATION`(改名/删除处置) | 受保护文件的删除与重命名 |
| **注册表(M4)** | `CmRegisterCallbackEx`(`RegNtPreSetValueKey` / `RegNtPreDeleteValueKey` / `RegNtPreDeleteKey`) | 对受保护键的写值/删值/删键(如启动项) |
| **自我保护(M5)** | `ObRegisterCallbacks` | 他进程试图以危险权限(结束/写内存/远程线程/挂起)打开磐垒受保护进程时,剥离这些权限 |
| **网络(M6)** | WFP callout + filter(`FWPM_LAYER_ALE_AUTH_CONNECT_V4`) | 命中黑名单的外发连接 |

**处置模型**(参考 Sysmon / EDR,以稳定性优先):

- **进程创建** 采用 **Fire-and-Forget 遥测 + 启动后补偿**:内核对系统目录 / 关键进程走白名单直接放行(零延迟),其余进程仅**上报、不阻塞**;若用户态裁决为 `Block`,由用户态即时 `TerminateProcess` 结束该进程树(样本通常仅运行数十毫秒)。**不再挂起进程创建**,避免用户态卡顿把整个系统拖死。
- **文件 / 注册表硬拦截**(`FileHardBlocks` / `RegistryHardBlocks` 精确名单)在**内核本地**直接返回 `STATUS_ACCESS_DENIED` —— 不发 IPC、不等用户态,真·原地阻断且零延迟。
- **自我保护 / 反注入 / 网络** 运行在高 IRQL,**不阻塞**:直接剥离危险句柄权限 / `FWP_ACTION_BLOCK`,并异步记录。

受保护路径、注册表键、硬拦名单、受保护进程 PID、反注入目标、网络黑名单均由用户态经 `FilterSendMessage` 下发。

```
新进程启动
   │  (内核回调 PASSIVE_LEVEL)
   ▼
系统目录 / 关键进程? ──是──▶ 直接放行(零延迟,不发 IPC)
   │否
   ▼
ProcessMonitor 组装事件 ──FltSendMessage(遥测,不等待)──▶ 用户态 DriverEventSource
   │                                                          │
   ▼                                                   规则引擎评估 / UI 弹窗
进程立即正常启动                                                 │
                                                               ▼
                                        裁决 = Block → 用户态 TerminateProcess 结束进程树
```

> 文件 / 注册表硬拦、自我保护、反注入、网络黑名单则不同:它们在内核本地(或高 IRQL)**即时阻断**,不经上述启动后补偿路径。

**驱动源文件**(`Bulwark.Driver/`):
- `Driver.c` — DriverEntry / 卸载 / Minifilter 注册(I/O 回调 + 实例附加)+ 网络设备对象
- `ProcessMonitor.c` — 进程创建回调与拦截
- `FileMonitor.c` — 文件删除/重命名拦截 + 受保护项匹配
- `RegistryMonitor.c` — 注册表写值/删值/删键拦截 + 受保护键管理
- `SelfProtect.c` — `ObRegisterCallbacks` 句柄回调,剥离对受保护进程的危险权限
- `NetMonitor.c` — WFP callout/filter + 黑名单管理
- `ImageMonitor.c` / `ThreadMonitor.c` — 映像加载与远程线程监控
- `Comms.c` — 通信端口、`FltSendMessage` 等待裁决/异步上报、接收配置消息
- `Protocol.h` — 内核↔用户态消息结构(用户态 `DriverEventSource.cpp` 直接 `#include` 复用此头,单一事实来源,消除结构体布局漂移)

简要流程:

```powershell
# 1) 编译驱动(本机有 WDK 即可)
.\scripts\build-driver.ps1 -Configuration Debug   # 产出 build\driver\Debug\Bulwark.sys

# 2) 仅在【带快照的测试虚拟机】里加载(回调出错会蓝屏!)
.\scripts\deploy-driver-vm.ps1                    # 开测试签名/建测试证书/签名/安装/启动

# 3) 把 appsettings.json 的 EventSource 改为 "Driver",以管理员运行服务+UI
```

进程创建走「遥测 + 启动后补偿结束」模型(见上文「处置模型」);文件 / 注册表硬拦、自我保护、
反注入与网络黑名单则是内核本地即时阻断。驱动以 `/INTEGRITYCHECK` 链接(`ObRegisterCallbacks`
自保所需)且镜像须有有效签名;正式发布需 EV 证书 + 微软 WHQL/附件签名。

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
