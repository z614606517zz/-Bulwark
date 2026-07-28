# 更新记录 (Changelog)

本文件记录磐垒主动防御 (Bulwark) 的主要变更。

> ⚠ **阅读须知:2026-07-02 及更早的条目属 .NET 原型时期**,其中引用的路径(`Bulwark.Core/`、
> `Bulwark.Core.Tests/`、`Bulwark.Service/`、`tools/`)在当前 C++ / Qt 代码树中**已不存在**。
> 这些条目保留作为历史记录,但**不能据此判断当前代码状态**——尤其是其中提到的规则单元测试:
> C++ 迁移后测试基建尚未重建(`cpp/CMakeLists.txt` 里 `enable_testing()` 仍为注释),
> 当前仓库**没有任何自动化测试**。规则本身已随 `cpp/shared/src/engine/DefaultRules.cpp` 迁移过来。

---

## [v2.0.3] - 2026-07-29 (GitHub同步发布)

### 发布 🚀
- **源代码已同步至 GitHub** - https://github.com/z614606517zz/-Bulwark
  - 完整的 V2.0.3 版本代码库
  - 190 个文件更新,21903+ 行代码新增
  - 包含驱动、服务、UI、ML训练管道的完整实现

### 主要特性总览 ✨
本次发布整合了以下核心功能模块:

#### 1. 攻击溯源与可视化
- **攻击图构建器** (`cpp/shared/src/engine/AttackGraphBuilder.cpp`)
  - 将孤立事件还原为完整攻击链
  - 进程树关联与时间线重建
  - 节点类型:进程/文件/注册表/网络/服务/计划任务
- **进程启动来源溯源** (`cpp/service/src/monitoring/ProcessOriginResolver.cpp`)
  - 将 svchost.exe 还原为具体服务名
  - 计划任务宿主还原为任务名
  - SCM/COM 权威快照与注册表回退机制
- **取证服务** (`cpp/service/src/ForensicsService.cpp`)
  - 事件时间线查询(按时间窗/类型/PID/关键字)
  - 攻击关系图生成与下发
  - 历史事件深度检索(扫描 events.jsonl)
- **UI 增强**
  - 攻击图窗口 (`cpp/ui/src/dialogs/AttackGraphWindow.cpp`)
  - 进程详情对话框 (`cpp/ui/src/dialogs/ProcessDetailDialog.cpp`)
  - 事件时间线页面(新增)

#### 2. 进程管理与监控
- **进程枚举器** (`cpp/service/src/monitoring/ProcessEnumerator.cpp`)
  - 带取证能力的进程管理视图
  - 启动来源列(服务名/计划任务名)
  - 签名验证与静态风险提示
  - 处置功能:结束/挂起/恢复/隔离/信任
  - 自我保护:拒绝操作自身组件与关键系统进程

#### 3. 主动防护增强
- **内核命令行硬拦截** (`Bulwark.Driver/ProcessMonitor.c` + `Policy.c`)
  - 执行前拦截(零 IPC、零往返)
  - LOLBin 用法检测(vssadmin/wmic/bcdedit/reg等)
  - 内置 13 条反勒索/反凭据窃取基线
  - 持久化到注册表,服务未启动时仍生效
- **注册表防护补齐** (`Bulwark.Driver/RegistryMonitor.c`)
  - 新增 5 类通知覆盖:Rename/SaveKey/SetSecurity/CreateKey/LoadKey
  - 内置凭据 hive 硬拦(SAM/SECURITY 导出零配置拒绝)
  - 修复键改名/ACL 篡改绕过路径型防护的漏洞
- **哈希扫描模块** (`Bulwark.Driver/HashScan.c`)
  - 内核本地已知恶意哈希查杀
  - 独立于用户态服务运行
- **规则作用域修复**
  - 收窄"良性厂商应用"信任通道至仅 NetworkConnect/DnsQuery
  - 修复 IM 客户端规则旁路问题(微信/QQ 群控防护规则现已生效)

#### 4. 云信誉与情报整合
- **代理声誉服务** (`cpp/service/src/reputation/ProxyReputationService.cpp`)
  - 中央信誉服务集成(默认 https://vt.bulwark.icu:8787)
  - 失败时自动回退到直连 VirusTotal
  - 仅发送 SHA-256 摘要,不传输文件内容
- **主动防护规则生成** (`Worker.cpp::buildRulesFromProfile()`)
  - 从 VirusTotal 行为画像自动生成 5 类拦截规则:
    1. 释放文件哈希拦截(ProcessCreate → Block)
    2. C2 IP 拦截(NetworkConnect → Block)
    3. C2 域名拦截(DnsQuery → Block,新增)
    4. 释放文件名监控(FileWrite → Ask)
    5. 注册表持久化拦截(RegistrySetValue → Block,新增)
  - 智能过滤:排除 CDN/云服务商域名,限制规则数量避免误报

#### 5. ML 训练管道
- **数据采集工具** (`ml/tools/`)
  - Collect-BenignPE.ps1 - 良性 PE 样本采集
  - Collect-BenignSamples.ps1 - 通过 winget 采集可信应用
  - Collect-CleanWim.ps1 - 从 Windows WIM 镜像提取系统文件
  - Collect-MalwareBazaar.ps1 - 恶意样本下载与管理
  - github_dl.py - GitHub 热门项目可执行文件下载
- **特征提取与训练** (`ml/train/`)
  - extract_features.py - PE 静态特征提取
  - behavior_runtime_features.py - 运行时行为特征
  - train.py - LightGBM 模型训练主流程
  - vt_enrich.py / vt_behaviours.py - VirusTotal 情报增强
  - mb_enrich.py - MalwareBazaar 元数据集成
- **注意**: 产品不包含已训练模型,检测能力来自规则+启发式+云信誉

#### 6. 部署与工具
- **构建脚本**
  - build.bat / build_service_v2.ps1 - 服务构建
  - cpp/build_ui.bat - UI 构建
  - rebuild_all_for_portable.ps1 - 便携版完整构建
- **部署脚本** (`scripts/`)
  - _kiro_deploy_service.ps1 - 服务部署
  - _kiro_load_now.ps1 - 驱动加载
  - _kiro_restart_svc.ps1 - 服务重启
  - deploy-driver-vm.ps1 - 虚拟机驱动部署
- **启动器与辅助工具** (`tools/`)
  - bulwark_launcher.cpp - 启动器实现
  - auto-allow.ps1 - 自动信任规则生成
- **服务端组件** (`server/bulwark-broker/`)
  - broker.py - 中央信誉代理服务
  - ember_pkg/features.py - EMBER 特征提取

### 文档与配置 📚
- **新增文档**
  - PROACTIVE_DEFENSE.md - 主动防护技术文档
  - REAL_TIME_PROTECTION_STATUS.md - 实时防护状态分析
  - SYSTEM_TOOL_PROTECTION.md - 系统工具保护机制
  - TESTING_GUIDE.md - 综合测试指南
  - V2.0.2_TEST_GUIDE.md - V2.0.2 测试指南
  - V2.0.3_RELEASE.md - V2.0.3 发布说明
  - SUMMARY.md - 项目概要
- **配置完善**
  - cpp/dist/appsettings.json - 运行时配置模板
  - cpp/service/appsettings.json - 服务配置示例
  - cpp/scripts/set-baseline-policy.ps1 - 基线策略设置

### 技术架构变更 🔧
- **协议保持兼容** - IPC 协议版本维持 v9,新旧两端可降级互通
- **事件类型扩展** - 新增 CommandBlocked / RegistryHiveDump 等事件类型
- **数据模型增强**
  - SecurityEvent / ChainEventInfo 新增 origin* 字段
  - ProcessEntry / AttackGraph 模型(新增)
  - ProcessOriginKind 枚举类型(新增)
- **IPC 消息扩展** - IpcMessageType 追加 50-57(时间线/攻击图/进程管理相关)

### 安全与隐私 🔒
- **明确数据外发行为**
  - 默认开启中央信誉服务(仅发送 SHA-256 摘要)
  - README 已说明关闭方法与自建方式
  - 本地 API Key 不会上传到中央服务
- **自我保护增强**
  - 进程管理拒绝操作自身组件
  - 关键系统进程保护(防 0xEF 蓝屏)
  - 驱动独立运行能力(服务停止时仍拦截)

### 已知限制 ⚠️
- **上报逻辑缺陷**: 引擎裁决 Allow 但内核已拦截时,UI 会错误显示为"放行"
  - 影响事件: SelfProtect / MemoryProtect / ImageBlocked / NetworkConnect / CommandBlocked / RegistryHiveDump
  - 原因: `Worker::enforceBlock` 仅在裁决为 Block 时调用
  - 建议: `kernelBlocked=true` 时无条件报告 `KernelBlocked`(待决策)
- **测试覆盖**: C++ 版本无自动化测试(enable_testing() 仍注释状态)
- **模型推理**: 当前版本不包含 ML 模型推理路径,ml/ 仅用于离线训练

### 致谢 🙏
感谢所有参与测试、反馈问题和贡献代码的用户与开发者。

---

## [未发布] - 2026-07-28 (最新)

### 修复 🐛
- **系统工具误删保护** - 添加系统可执行文件白名单，防止清理时误删关键工具
  - 保护列表: cmd.exe, powershell.exe, notepad.exe, taskmgr.exe, regedit.exe 等 21 个系统工具
  - 原因: 用户报告 Visual Studio 开发工具快捷方式（指向 cmd.exe）被清理
  - 修复: 在 `isSafeToRemove()` 中增加**第一优先级**检查，系统工具绝对不删
  - 位置: `cpp/service/src/ThreatRemediator.cpp`
- **文件清理失败问题** - VT 沙箱确认的释放文件现在会绕过签名保护进行清理
  - 问题: 带签名的恶意释放物之前会被跳过，导致"清理失败"提示
  - 修复: `droppedFilePaths` 中的文件即使带签名也会被隔离
  - 位置: `cpp/service/src/ThreatRemediator.cpp`
- **扩展文件清理落地区** - 新增 6 个常见恶意软件落地区
  - 新增: `\users\`（用户根）、`c:\temp\`、`c:\tmp\`、`\music\`、`\videos\`、`\pictures\`
  - 原因: 恶意软件常释放到这些位置，之前被"不在用户可写落地区"跳过

### 技术细节
- **文件清理安全检查优先级**（从高到低）:
  1. ⭐ 系统工具白名单检查（v2.0.3 新增） - 绝对保护 cmd/powershell 等
  2. 系统/安装目录检查 - 保护 System32/Program Files
  3. 落地区检查 - 只清理用户可写区域
  4. 签名保护检查 - 3 种绕过机制（主体异常/哈希匹配/VT 确认）

### 新增 ✨
- **实时注册表写入拦截规则** - 根据 VirusTotal 行为报告自动生成注册表拦截规则
  - 恶意样本尝试写入 VT 报告中的注册表键（自启动/劫持/持久化）时直接拦截
  - 限制 30 条规则，过滤系统关键路径（`\Windows\`）避免误拦
  - 补齐主动防护的最后一环：阻止恶意软件重建持久化
  - 实现位置：`cpp/service/src/Worker.cpp::buildRulesFromProfile()`
- **C2 域名 DNS 阶段拦截** - 在 DNS 解析阶段就拦截恶意域名
  - 比 IP 拦截更早（在 IP 解析之前就阻断）
  - 自动排除合法 CDN/云服务商域名（microsoft/google/amazon/cloudflare/akamai）
  - 限制 50 条域名规则避免误报

### 增强 🔧
- **主动防护规则生成增强** - `buildRulesFromProfile()` 现在生成 5 类规则：
  1. 释放文件哈希拦截（ProcessCreate → Block，精确硬拦）
  2. C2 外联 IP 拦截（NetworkConnect → Block）
  3. C2 外联域名拦截（DnsQuery → Block，新增）
  4. 释放文件名监控（FileWrite → Ask，软提示）
  5. 注册表持久化拦截（RegistrySetValue → Block，新增）
- **日志增强** - 情报行为画像日志现在清晰显示各类 IOC 数量和注入的规则总数
  ```
  情报行为画像[VirusTotal]:释放文件 5、注册表 3、外联IP 2、域名 1;
  已注入主动拦截规则 11 条。
  ```

### 文档 📚
- 新增 `PROACTIVE_DEFENSE.md` - 主动防护完整技术文档（规则类型/工作流程/配置/测试）
- 新增 `REAL_TIME_PROTECTION_STATUS.md` - 实时防护与威胁清理状态分析文档

---

## [未发布] - 2026-07-28 (之前)

### 新增
- **进程启动来源溯源:把 svchost.exe / 任务宿主还原成「具体哪个服务、哪个计划任务」**
  `cpp/service/src/monitoring/ProcessOriginResolver.cpp`(新增)+ `Worker.cpp`(富化接入)
  + `SecurityEvent` / `ChainEventInfo` 新增 `origin*` 字段 + `Enums.h` 新增 `ProcessOriginKind`

  补的是溯源链上一处一直断掉的关键环节。内核 / ETW 的进程事件只给得出「父进程」,而 Windows 上
  两条最常被滥用的启动路径恰好都把父进程抹平成了无区分度的宿主:
  - **服务**:共享型服务全部跑在 `svchost.exe` 里,父进程是 `services.exe`。溯源链上看到
    `services.exe → svchost.exe` 完全不知道是哪个服务,更看不出那是不是攻击者刚装的服务。
  - **计划任务**:Win8+ 由任务计划程序服务(`svchost` 里的 `Schedule`)**直接创建**目标进程,
    父进程就是那个 `svchost.exe`;Win7 是 `taskeng.exe`。溯源到这里就断了。

  于是「持久化 → 落地执行」这条最关键的因果关系在日志上**根本看不见**。现在按逐级降级的策略补回来,
  且每一级都如实标注置信度,不猜完就当事实:
  - 服务:① SCM 权威快照(`EnumServicesStatusEx` + `SERVICE_STATUS_PROCESS.dwProcessId`)直接
    PID → 服务名,共享宿主里的多个服务全部列出;② 父进程是 `services.exe` 但快照里还没有本 PID
    (服务刚创建的竞态)→ 强制刷新一次(带 250ms 节流);③ 仍未命中 → 回退到注册表
    `\CurrentControlSet\Services` 的 `ImagePath` 反查(服务注册**早于**进程启动,所以这条永远拿得到),
    唯一命中记中置信,多个则列候选。
  - 计划任务:① 先判定「是不是任务拉起的」——父进程为 `taskeng.exe`,或父进程是**承载 `Schedule`
    服务**的 `svchost.exe`(用 SCM 快照判定,不靠命令行 `-k` 分组名猜);② 再定名:任务计划程序 COM
    的运行中任务列表按 `EnginePID` 精确匹配;③ COM 不可用 → 扫 `%WINDIR%\System32\Tasks` 的任务 XML
    按映像路径反查候选。
  - **刻意不参与风险评分**:结论只写入事件的 `origin*` 字段并记一条 `Info` 证据(0 分)。
    「由计划任务启动」本身完全合法,不该因此提分;它的价值在于分析时能一眼看到因果 ——
    这与「软信号绝不单独触发处置」的既有原则一致。
  - 敢在事件富化热路径上调 SCM / 任务计划程序这两个 RPC,前提是驱动侧本就是
    fire-and-forget 异步上报(`FltSendMessage` 0 超时),被创建的进程**不会**阻塞等我们的裁决,
    因此不存在「对方在等我们、我们又在等对方」的死锁。即便如此仍加了四层 TTL 缓存
    (SCM 3s / 运行中任务 1.5s / 服务注册表索引 5min / 任务 XML 索引 5min)与「每 PID 结论备忘」
    (60s,键带映像文件名以规避 PID 复用),并且只有「看起来像服务或任务宿主派生」的进程才会
    走 COM 这条重路径。任何一步失败都降级返回,溯源永远不许影响裁决。
  - 溯源链上**每一级**都标出自己的启动来源(`Worker::seedAncestryChain`,限前 6 级封顶开销),
    所以一条链读下来是「计划任务 \Foo → powershell.exe → dropper.exe」而不是
    「svchost.exe → powershell.exe → dropper.exe」——后者根本看不出因果。

- **事件时间线 + 攻击关系图:把孤立记录还原成一次入侵的形状**
  `cpp/shared/src/models/AttackGraph.cpp` / `engine/AttackGraphBuilder.cpp`(新增)
  + `cpp/service/src/ForensicsService.cpp`(新增)+ `EventHistoryStore` 查询能力
  + `cpp/ui/src/dialogs/AttackGraphWindow.cpp`(新增)+ 新页面「事件时间线」

  「活动日志」是实时流水,回答「刚刚发生了什么」;新增的两个视图回答另外两个问题:
  - **事件时间线**(新页面):按时间窗 / 行为类型 / 裁决 / 风险分 / PID(可含整棵进程树)/ 关键字
    检索历史。查询直接扫服务端落盘的 `events.jsonl`(比内存环形缓冲的 500 条深得多),所以能回看
    「昨天下午三点前后那台机器上发生了什么」。表格里专门有一列**启动来源**,`svchost.exe` 那行会
    显示成「服务:Schedule」。
  - **攻击关系图**(弹窗,可从拦截记录 / 活动日志 / 时间线右键、攻击时间线窗口按钮、进程管理页打开):
    以某条事件(或某 PID)为种子,把时间窗内属于同一进程树的事件还原成一张分层有向图 ——
    节点是进程 / 文件 / 注册表键 / 远端地址 / 域名 / 模块 / **服务** / **计划任务**,边是一次具体行为
    (带时间、风险分、裁决与**真实处置结果**)。虚线边表示由父子链或启动来源**推导**出的关系,
    与真实观测到的事件在视觉上严格区分。
  - 关联范围刻意限定为「种子的祖先链(限层)+ 种子自身 + 种子的全部后代」,**不取祖先的兄弟分支** ——
    否则从 `explorer.exe` 往下能把用户开的所有程序都拽进来,图会失去意义。
  - **关联逻辑只有服务端一份**(`AttackGraphBuilder` 在 `bulwark_shared`,由服务调用后整图下发)。
    UI 只负责画,不做任何关联推断 —— 界面上看到的因果与引擎实际依据的因果永远一致,不会出现
    「图上连着、日志里对不上」这种排查事故时最要命的偏差。
  - 时间线查询与建图都可能解析数万条 JSON,故一律在后台线程完成、算完编组回主线程回推
    (与云信誉详情同一套路),并纳入停机等待,不阻塞服务的事件循环。

- **进程管理(新页面)** `cpp/service/src/monitoring/ProcessEnumerator.cpp`(新增)
  + `cpp/ui/src/dialogs/ProcessDetailDialog.cpp`(新增)+ `pages::processes`

  不是任务管理器的复刻,而是「带取证与溯源的进程视图」。三件事是别处看不到的:
  ① **启动来源列**:`svchost.exe` 显示成具体服务名,任务宿主派生的进程显示成具体计划任务名;
  ② **签名与静态提示**:未签名 / 签名失配 / 跑在用户可写目录 / 使用系统进程名但不在系统目录,
     一眼可见,默认按此列降序,打开页面第一眼就落在最值得看的进程上;
  ③ **处置就在手边**:结束 / 结束进程树 / 挂起 / 恢复 / 结束并隔离映像 / 加入信任名单。

  三条红线写进了实现:
  - 所有处置都要用户**显式点击**并二次确认,页面本身不做任何自动动作;静态提示分只用于排序着色,
    **绝不当成判定结论**(详情窗口里也明说了这一点)。
  - **自我保护**:服务端拒绝从这里结束磐垒自身组件(自身 PID + 已连接的 UI PID + 安装目录下的
    `bulwark_service.exe` / `bulwark_ui.exe`),UI 上一并置灰并写明原因。一个能一键结束自家服务的
    进程管理器等于给恶意软件递刀;要停防护有设置里的总开关和正常卸载流程。
  - **关键系统进程**同样拒绝(结束会 `CRITICAL_PROCESS_DIED` 0xEF 蓝屏),复用既有的
    `ProcessInspector::isCriticalProcess` 双重护栏。
  - 处置结果一律弹回执:失败必须说明**为什么没做成**(关键进程 / 自我保护 / 权限不足 / 进程已退出),
    不允许静默成功 —— 与「杜绝假拦截显示」是同一条原则。
  - 首次快照要对几百个映像验签(数秒),故在后台线程完成;验签结果按「路径|大小|修改时间」缓存,
    后续刷新是毫秒级。自动刷新默认**关闭**。

### 变更
- `IpcMessageType` 追加 50–57(时间线请求/响应、攻击图请求/响应、进程列表请求/响应、
  进程处置请求/响应)。序号是冻结的线协议,一律追加在末尾,不复用空洞。
- 左侧导航现已 12 项,放进无边框透明滚动区:窗口高度不足(最小 620)时可滚动,
  而不是把底部的连接状态条挤掉。
- 攻击时间线窗口新增「启动来源」板块与「查看攻击关系图」入口;溯源链每一级都显示启动来源。

## [未发布] - 2026-07-27

### 新增
- **内核「命令行硬拦」:按用法而非按身份的执行前拦截**
  `Bulwark.Driver/ProcessMonitor.c` / `Driver.h` / `Protocol.h` / `Comms.c` / `Policy.c`
  + `cpp/service/src/DriverEventSource.cpp` / `BulwarkOptions.{h,cpp}` / `appsettings.json`

  补的是一处一直存在的能力浪费:LOLBin(`vssadmin` / `wmic` / `bcdedit` / `wbadmin` / `fsutil` /
  `reg` ...)本体位于 System32、签名可信、路径受 WRP 保护 —— 无论怎么按「身份」判定都是可信的,
  威胁完全来自「用法」。原实现为此在内核给 LOLBin 开了个口子(不走可信路径快速放行),把命令行
  交给用户态检测,于是回到「事后 kill」模型。而 `vssadmin delete shadows /all /quiet` 这类命令在
  毫秒级就完成不可逆破坏,等用户态裁决回来卷影早已删干净,结束进程也挽回不了。
  与此同时,`PS_CREATE_NOTIFY_INFO.CommandLine` 在内核回调里【本来就直接可读】,驱动里此前
  一次都没引用过它。

  现在进程创建回调直接读完整命令行做本地查表,命中即 `CreationStatus = STATUS_ACCESS_DENIED`,
  命令**一次都不会执行**。零 IPC、零往返、无竞态。

  - 判定位置刻意放在「可信系统路径快速放行」**之前** —— 目标全部住在可信路径里,放在之后等于不存在;
    唯一护栏仍是「关键系统进程绝不拦」(防 `CRITICAL_PROCESS_DIED` 0xEF)。
  - 模式语法是 `'+'` 分隔的 **token 合取**:每个 token 都必须作为大小写不敏感子串出现,
    因此参数顺序、空格数量、大小写、是否带全路径都绕不过去。若用整串子串匹配,攻击者调换一次
    参数顺序就能绕过。
  - 直接匹配**原始命令行、不截断、不预归一化**:命令行可长达 32767 字符,若先截到 520 字符再匹配,
    在前面填充垫料就能把危险 token 推出截断范围。
  - 名单持久化到 `HKLM\...\Services\Bulwark\Policy\CmdHardBlock`,故**服务未启动 / 被杀 / 刚重启**
    时内核仍独立续拦 —— 反勒索最关键的「删卷影」不再依赖任何用户态进程活着。
  - 内置基线 13 条(反勒索:删卷影 / 压缩卷影存储 / 删备份目录与系统状态备份 / 关恢复环境 /
    关启动失败自动修复 / 删 USN 日志;反凭据窃取:导出 SAM 与 SECURITY hive,根键短/长写法各一条),由
    `CommandHardBlockBaseline` 开关控制,`CommandHardBlocks` 可追加自定义模式。
    选取原则写进了代码注释:**每个 token >= 4 字符** —— token 是纯子串,像 `cl` 这种短 token 会
    命中无关单词造成误报(为此放弃了 `wevtutil cl Security` 这条)。
  - 实机验证时发现并修掉一处自己引入的缺口:`reg save HKEY_LOCAL_MACHINE\SAM` 不含子串
    `HKLM\SAM`,只列短写法时这条命令行模式被直接绕过(当时全靠内核 `SaveKey` 那层兜住,
    纵深防御奏效)。已补上根键长写法。**这暴露了命令行层的固有定位**:它按「字面命令行」判定,
    天然有写法变体的长尾,只能当**可选外层**;真正的兜底必须是内核按「解析后的对象」判定的那一层。
  - 新增事件 `BlwEventCommandBlocked`。主体刻意取**父进程**而非被拒的新 PID:那个 PID 的进程根本
    没起来,按它解析映像只会拿到空值,PID 被复用后还会错误指向无关进程。

- **注册表回调覆盖面补齐五类通知** `Bulwark.Driver/RegistryMonitor.c`

  原实现只挂了 `RegNtPreSetValueKey` / `PreDeleteValueKey` / `PreDeleteKey` 三条,以下四条路
  **完全不设防**:
  - `RegNtPreRenameKey` —— 把受保护键改个名字,即可让所有**基于路径**的匹配(含本驱动硬拦名单
    与用户态规则)整体失效,再从容操作。绕过路径型防护最省事的一招。
  - `RegNtPreSaveKey` —— `reg save HKLM\SAM out.hiv` 导出后离线破解。这条路**不经过 lsass**,
    故现有的凭据反转储(剥 lsass 的 `PROCESS_VM_READ`)对它完全无效。
  - `RegNtPreSetKeySecurity` —— 先把受保护键 ACL 改成谁都能写,后续写入在系统看来完全合法,
    路径型防护被这一步整体解除。
  - `RegNtPreCreateKeyEx` —— 只拦「已存在键的写值」意味着「新建一个持久化键」是放开的
    (IFEO 劫持要新建 `\Image File Execution Options\<exe>` 子键)。
  另加 `RegNtPreLoadKey`(挂载自带 hive 植入持久化配置)。

  实现要点:
  - 新增**内置凭据 hive 硬拦**:`\REGISTRY\MACHINE\SAM` 与 `\REGISTRY\MACHINE\SECURITY` 之下的
    `SaveKey` 一律内核本地拒绝,**零配置、恒生效、不依赖用户态下发任何名单**。刻意不放进通用
    `RegHardBlock`:那会连带拦下对 SAM 的 `SetValue`,而创建用户 / 改密码正是 lsass 走 `SetValue`
    完成的,会直接打死账户管理。前缀判定带边界检查(要求其后是串尾或 `\`),避免同前缀键误命中。
  - `SaveKey` 设为 hardOnly,使 `BlwEventRegistryHiveDump` **只可能由拒绝分支产生** ——
    用户态因此可以无歧义地标记 `kernelBlocked`,不会把真正拦下的 SAM 转储显示成「事后处置」
    并触发无谓补杀。
  - `CreateKeyEx` 只参与硬拦匹配、不做软监控上报:受保护键是 `\Services` 这类宽子串,
    在建键路径上按它上报会形成事件风暴。键此时还不存在,故目标路径由 `RootObject` 路径 +
    `CompleteName` 拼出;只读这两个成员是刻意的 —— `REG_CREATE_KEY_INFORMATION` 与 `_V1`
    在这两个成员上偏移相同,无论系统投递哪个版本都安全。
  - 三级判定(内置 hive → 硬拦名单 → 软监控)抽成单一函数,两种目标构造方式共用,不会日后走偏。

  **刻意未做**:不处理 `RegNtPreLoadKeyEx`。`REG_LOAD_KEY_INFORMATION_V2` 首成员是 `Size` 而非
  `Object`,与 V1 布局不同,合并处理会把一个 `ULONG` 当指针交给 `CmCallbackGetKeyObjectIDEx`
  直接蓝屏。宁可少覆盖一条通知,也不引入这种解引用风险。

  **实机验证**(测试签名 + 驱动加载 + 服务/UI 运行,Win11 26200):命令行硬拦 12/12 用例通过
  (含乱序 / 多余空格 / 大小写混杂的正向,以及缺 token 的负向全部放行);注册表侧 7/7 通过 ——
  SAM hive 导出被拒且内核如实上报 `内核拦截 · 已阻止导出注册表 hive \REGISTRY\MACHINE\SAM`
  (`kernelBlocked=true`),普通 hive 导出与普通建键均不受影响(无回归),
  新建 `...\sethc.exe\Debugger` 键被拒,改名 `\Services\Bulwark` 被拒,`sc config Bulwark` 被拒。

  **已知上报缺陷(本次未改,影响面更大)**:`Worker::enforceBlock` 只在裁决为 `Block` 时才被调用,
  于是当引擎对一个 `kernelBlocked=true` 的事件裁决为 `Allow`(例如主体命中用户信任)时,
  `enforcement` 被记为 `NotApplicable`,UI 会把**内核确实已阻断**的操作显示为「放行」。
  这与项目「绝不谎称拦截」的原则是同一个问题的反面(谎称放行)。本次新增的两类事件让它更容易被看到,
  但它对既有的 `SelfProtect` / `MemoryProtect` / `ImageBlocked` / `NetworkConnect` 同样成立。
  修法很直接(`kernelBlocked` 为真时无条件如实报 `KernelBlocked`),但它改动裁决/处置语义,留待决策。

  协议版本**保持 9**:新命令复用现有 `BLW_CONFIG_MESSAGE`、新事件复用现有 `BLW_EVENT_MESSAGE`,
  三个握手校验结构体大小一个字节都没变;新服务遇旧驱动静默降级,新驱动遇旧服务由 `default`
  分支退化为普通遥测记录。若改为 v10,反而会让已部署的 v9 两端因版本不符而**整体降级为不拦截**。

### 修复
- **收窄「良性厂商应用」信任通道的作用域,修掉一条规则旁路**
  `cpp/shared/src/engine/RuleEngine.cpp`(步骤 2b)+ `cpp/shared/include/bulwark/engine/TrustPolicy.h`

  `TrustPolicy::isTrustedVendorApp` 原先对**全部事件类型**早返回 `Allow` 并置 `userTrusted = true`。
  它的初衷只是压制「IM 客户端周期性心跳保活被信标检测 / IP 情报判成 C2 回连」这一类误报,
  但实际效果是:`qq.exe` / `tim.exe` / `wechat.exe` / `weixin.exe` / `wxwork.exe` 这五个映像名
  一旦持有健康的腾讯签名,它们作为主体的**任何**行为都不再经过 `ThreatDetector`、也不再匹配显式规则,
  并且跳过全部后台扫描(VT / 微步 IP / AI)。

  后果是上面 2026-07-02 那批「银狐微信/QQ 群控防护」规则有一半从未生效——具名 hook 模块
  (`wxhook` / `WeChatSDK` / `vchat` 等)**被 IM 本体加载**这一半,事件主体正是 `WeChat.exe`,
  直接走信任通道放行;`InjectionAnalyzer` 的「可写目录加载未签名模块(DLL 侧载)」检测同样失效。
  攻击者只要把合法签名的 IM 主程序连同恶意 DLL 一起投递,主体就是「签名健康的微信」。

  现在这一档**只对 `NetworkConnect` / `DnsQuery` 生效**,其余维度(进程创建 / 模块加载 / 文件写 /
  注册表写 / 注入)照常走完整流水线。误报抑制效果不变(误报本来只出在外联维度)。
  已知残留:这类主体的外联本身仍被放行,被侧载的 IM 宿主可维持 C2 通道;收掉这一条需要
  模块级(而非进程级)的外联归因,不在本次范围内,但投递阶段的落地 / 加载 / 注入 / 持久化现在都能检测到。

### 移除
- **删除全部已训练模型与训练语料** `ml/`
  移除 `ml/train/behavior_model_v1.txt`、`behavior_runtime_model.txt`、`model_behavior.txt`
  三个 LightGBM 模型产物,以及整个 `ml/data/`(样本语料目录骨架 + VT 哈希清单)。
  产品**不再有「已训练模型」这回事**:当前代码里没有任何模型推理路径,检测能力全部来自
  规则 + 启发式 + 各分析器 + 云信誉。`ml/` 下仅保留离线训练脚本,不参与 C++ 构建。

### 文档
- **修正 README / README.en / steering 与代码不一致处**(逐条核对代码后修改):
  - 新增「中央信誉服务」小节:`ReputationProxy` 在随包配置里**默认开启**,会把本机文件 SHA-256
    发到 `https://vt.bulwark.icu:8787`。此前 README 完全未提及此功能,却写着「情报源全部 opt-in、
    默认关闭」「你填的 Key 只保存在本机」,读者会据此认为不填 Key 即无外发。现已写明外发内容
    (仅摘要,不传文件)、默认值、关闭方法、失败回退行为与自建方式。
  - 澄清「代码默认关」与「随包配置全开」的矛盾:`BulwarkOptions.h` 各源默认 `Enabled = false`,
    但 `cpp/service/appsettings.json` 把 8 项全置为 `true`,配置覆盖代码默认。
  - 修正密钥表述:模板 `cpp/service/appsettings.json` 各 Key 确为空,但 `cpp/dist/`(被 `.gitignore`
    排除的本地运行目录)可能含开发者真实 Key,README 原先把该目录当可分发产物推荐,已加警示。
  - 决策流程补上缺失的第 3 步「已知良性厂商应用」(此前 11 步漏写这一档,正是上面那条旁路
    长期未被发现的原因),并加注「三条信任通道排在显式规则之前,写 Block 规则压不过它们」。
  - 同步修正 `.kiro/steering/product.md` 的 decision priority——原文写作
    「matched rule → threat score → trusted signature → default」,与实际流水线顺序不符。
  - 修正内核 M2 描述:原先只写「遥测 + 启动后结束」,漏掉 `ProcessMonitor.c` 里两条**内核本地
    事前拒绝**(exec-block 名单命中、封禁主体派生子进程 → `STATUS_ACCESS_DENIED`)与
    `HashScan.c` 的内核本地已知恶意哈希查杀,以及「服务不在也拦」的自足基线设计。
  - 驱动源码清单补上 `HashScan.c`、`Policy.c`;解决方案结构补上 `server/`、`Bulwark.Sandbox/`、`ml/`。
  - 配置样例补上 `DefaultAction`(决定弹窗超时后的动作)与 `ReputationProxy`,并列出代码支持
    但样例省略的键(`Etw` 实为 14 个键、`VirusTotal.PriorityDailyReserve`、
    `UiClientAllowedThumbprints` / `UiClientAllowedPublishers` 等)。

---

## [未发布] - 2026-07-02(.NET 原型时期,路径已失效)

### 新增
- **银狐微信/QQ 群控防护(批次 14c)** `Bulwark.Core/Engine/DefaultRules.cs`
  新增 `AddImHarvestAndFrameworkRules`,补齐"银狐控制微信/QQ 群发"链路:
  - 具名群控/hook 模块 DLL 落地与加载(`wxhook`、`WeChatSDK`、`vchat`、
    `WeChatRobotCE`、`wxbotpp`、`WeChatManager`、企业微信 `WeWorkHook`/`wework_api`、
    `wxDump`、`QQHook`)→ **Block**;
  - 微信数据库解密/导出工具命令行(`PyWxDump`、`SharpWxDump`、`wxdump`、
    `WeChatMsg`,群发目标采集前置步骤)→ **Ask**;
  - 补充注入落点:`WeChatOCR.exe`、`WeChatUtility.exe`、`WXWorkWeb.exe`
    (仅未签名注入方命中)→ **Ask**;
  - 企业微信安装目录植入接口 DLL(`WXWork\*\wwapi*.dll`)→ **Ask**。
  - 设计取舍:**不对微信本体正常写库(`MicroMsg.db`/`MSG*.db`)下 FileWrite 规则**,
    避免海量误报,只锁定正常环境不出现的具名外挂特征。
- **规则单元测试** `Bulwark.Core.Tests/SilverFoxImRulesTests.cs`
  把真实内置规则集加载进 `RuleEngine`,以具体事件跑完整决策链验证上述裁决(全部通过)。
- **无害行为测试脚本** `tools/银狐防护测试.ps1`
  复现群控可观测特征(落 `wxhook.dll`、含 `PyWxDump`/`wcferry` 的命令行、向 IM 目录写 DLL)
  用于实机验证监控层+拦截是否生效。脚本不含任何真实群发/窃密逻辑,并自动清理。

### 安全 / 配置
- **停止跟踪 `Bulwark.Service/appsettings.json`**(其中含真实情报源 API 密钥),
  加入 `.gitignore`,改用 **`Bulwark.Service/appsettings.example.json`** 模板(密钥留空)。
  首次使用请复制该模板为 `appsettings.json` 并按下表填入自己的密钥。
- `.gitignore` 补充忽略:`bin_verify_svc/`、`__*.txt`、`ui_out.txt`、`ui_err.txt`、`query` 等调试残留。

---

## 情报源 API 获取地址

各情报源密钥填入 `appsettings.json` 对应节点(`Bulwark:<源>:ApiKey` 或 `AuthKey`)。
以下均为官方申请页面,**请勿将真实密钥提交到仓库**。

| 情报源 | 配置节点 | 申请/获取地址 |
|--------|----------|---------------|
| VirusTotal | `VirusTotal:ApiKey` | https://www.virustotal.com/gui/my-apikey (注册后在个人资料页获取) |
| MalwareBazaar (abuse.ch) | `MalwareBazaar:AuthKey` | https://auth.abuse.ch/ (注册 abuse.ch 账号后生成 Auth-Key) |
| AlienVault OTX | `Otx:ApiKey` | https://otx.alienvault.com/api (登录后在 API 页获取 OTX Key) |
| 微步在线 ThreatBook | `ThreatBook:ApiKey` | https://x.threatbook.com/ (社区版 API Key,个人中心获取) |
| OPSWAT MetaDefender | `MetaDefender:ApiKey` | https://metadefender.opswat.com/ (经 https://id.opswat.com/ 注册获取) |
| Hybrid Analysis (CrowdStrike) | `HybridAnalysis:ApiKey` | https://www.hybrid-analysis.com/apikeys/info (注册后在 API keys 页获取) |
| ThreatFox (abuse.ch) | `ThreatFoxFeed:AuthKey` | https://auth.abuse.ch/ (与 MalwareBazaar 共用 abuse.ch Auth-Key) |

> 提示:各源均可通过 `appsettings.json` 中对应的 `Enabled` 开关单独启停;
> `RequestsPerMinute` / `RequestsPerDay` 为本地限速,请按各源免费额度调整。
