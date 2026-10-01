# 磐垒(Bulwark)整体架构重写 · 需求与约束

> 本文是架构重写的**权威交接文档**。调研已完成,结论见第 2 节,**新会话不需要重新调研**。
> 每条现状结论都标了证据来源;标「未确认」的是现有文件证实不了的,不要当成事实。
>
> 配套文档:`design.md`(目标架构与关键设计)、`tasks.md`(分阶段任务)。

---

## 0. 给接手会话的速读

**项目是什么** —— Windows 主机入侵防御系统(HIPS),四个组件:

| 组件 | 路径 | 规模(实测行数) |
|---|---|---|
| 内核驱动 R0 | `Bulwark.Driver/` | 14 文件 / 7877 行 |
| 共享契约与决策引擎 | `cpp/shared/` | 100 文件 / 13097 行 |
| 用户态服务 R3(SYSTEM) | `cpp/service/` | 88 文件 / 24424 行 |
| 桌面 UI | `cpp/ui/` | 119 文件 / 24545 行 |
| 自动化测试 | `cpp/tests/` | 1 文件 / 1950 行 |
| 情报服务端(Python) | `server/` | 29 文件 / 26124 行 |

**要重写什么** —— 架构骨架:数据模型、流水线与线程模型、进程边界、内核协议、IPC、存储、内容分发。

**不重写什么** —— 检测内容。955 条内置规则(`bulwark_snapshot --check-ruleset` 实测)+ 十几个分析器 + 代码里约 300 处「实测 / 原实现 / 误报 / 漏检 / 回归」现场修复注释(实测分布:driver 56 / shared 60 / service 110 / ui 6 / server 74),**全部原样迁移,且每条转成回归用例**。

**第一件事不是写代码** —— 见 4.1「阶段 0」。git 只有 14 个提交(HEAD `a60397d`),工作区有 227 处未提交改动;而 2026-07 勒索事故永久丢失的 35 个源文件,正是当时没提交的那批。**阶段 0 不依赖任何待定决策,可以立刻开工。**

---

## 1. 目标与非目标

### 1.1 目标

- **R1** 决策链路可离线、确定性回放,任何裁决漂移在 CI 里立刻可见。
- **R2** 消除单线程串行热路径,进程创建事件从内核到决策 p99 < 50ms,事件风暴不再靠丢队列兜底。
- **R3** 以 SYSTEM 运行的进程不联网、不解析不可信文件。
- **R4** 一切改变机器状态的动作收敛到唯一执行器,有影响面上限、有日志、可撤销。
- **R5** 服务器下发的、能影响裁决的内容一律签名;验签失败保留上一份可用版本。
- **R6** 「没有内核驱动」是一等公民场景,策略按传感器实际能力降级,UI 如实呈现覆盖面。
- **R7** 内核协议支持删除单条策略、不截断路径与命令行、可无损演进。
- **R8** 安全护栏(关键进程 / 系统路径 / 自身目录 / 公共基础设施 IP)**只有一份定义**,三端由它生成。
- **R9** 密钥不再明文跨进程传递、不再明文落盘。
- **R10** 保住现有检测能力:迁移前后裁决差异逐条审过并留档,不允许「不明原因的差异」。

### 1.2 非目标

- 不做 ML 模型推理(`ml/` 是历史离线实验目录,当前产品无任何推理路径)。
- 不追求 EDR 级全量遥测落库。
- 不把自我保护做成「卸不掉」,始终保留用户可控的正常卸载入口。
- 不在本轮扩充检测规则数量。

---

## 2. 现状调研结论(已核实)

### 2.1 决策核心

- **2.1.1 上帝对象 + 阶段间互相覆写。** `SecurityEvent`(`cpp/shared/include/bulwark/models/SecurityEvent.h`)约 50 字段,事实 / 富化结果 / 中间分数 / 结论同居一体。`ThreatDetector::analyze` 会**复位** `hasThreatIndicator`、**覆盖** `riskScore`;攻击链贡献因此被静默擦除过,CHANGELOG v2.0.4 原话:「组合表上线后一次都没生效过,而组合自测始终全绿」。补救方式是另开 `chainScore` / `chainHardIndicator` 旁路字段(`AttackChainEngine` 相关说明),再接一个信号源就要再开一组。同类旁路:`tamperedModulePath`、`originKind`。
- **2.1.2 两处反直觉优先级,`cpp/shared/src/engine/rules/RuleDsl.h` 自己写明了:**
  - 一条宽 Ask 规则能把「风险 95 + 硬指标」降级成询问 —— 步骤 6 命中即 `return`,跳过步骤 10 的启发式处置。
  - `isDevTool` **纯文件名**匹配(名单含 `setup.exe` / `installer.exe` / `node.exe` / `python.exe`),样本改名即可让所有 Ask 规则失效。
- **2.1.3 信任通道排在显式规则之前。** 用户写的 Block 规则压不过「无条件放行 / 安全软件共存 / 厂商应用」三条通道(`.kiro/steering/product.md` 与 README 均记录)。
- **2.1.4 规则是 C++ 代码交叉展开。** `cpp/shared/src/engine/rules/Rules01..08_*.cpp` + `RuleDsl.h` 的链式 DSL,`DefaultRules.cpp` 按「备注 + 全部匹配条件」派生 UUIDv5 作 id。改一条规则要重新编译发版。
- **2.1.5 测试薄。** `cpp/tests/` 仅三条 ctest(裁决快照 / 内置规则 id 唯一 / 攻击链回归,第三条跑的是 `bulwark_service --attackchain-selftest`);语料 `corpus.json` 65810 字节、黄金 `golden.json` 72161 字节,**全为合成事件**,共 38 条。

### 2.2 用户态服务

- **2.2.1 组合根与编排器过大。** `main.cpp` 2402 行(`serviceRun` 约 1500 行,全靠 lambda 接线),`Worker.cpp` 2947 行 —— 一个类同时负责富化、分发、弹窗、处置、隔离、VT 上传扫描、IP 情报互证、兜底扫描。
- **2.2.2 热路径单线程串行。** 出队 / 富化 / 裁决 / IPC / 弹窗超时巡检同线程。富化阶段同步做 `WinVerifyTrust`、SHA-256、SCM+任务计划 COM RPC(`ProcessOriginResolver`),以及最长 `InlineReputationBudgetMs`(默认 800ms)的同步云查。事件风暴靠 4096 深队列丢弃兜底(= 漏检)。
- **2.2.3 补偿处置五份实现。** `onReputationMalicious` / `onAiMalicious` / `onEgressMalicious` / `handleSweptMalicious` / `onPromptResponse` 各自成路,每条都得记得先调 `abortIfTrustedNow`(`Worker.h` 有该方法存在理由的完整说明)。
- **2.2.4 网络经外部进程。** 所有 HTTP 走 `QProcess` 拉起 `curl.exe`(`cpp/service/src/reputation/ReputationCurl.cpp`),以 SYSTEM 身份解析第三方 JSON。约 15 处 `std::thread` 散落各处(Worker / ReputationManager / ThreatFoxFeed / ThreatIntelUploader / AttackChainEngine / Logger / EventHistoryStore / EtwProcessEventSource / DriverEventSource / main 的取证与更新 lambda)。
- **2.2.5 存储十来份各写各的。** rules / settings / firstSeen / baseline / events.jsonl / vt 历史 / 审计 / attackchain_hits.jsonl / pending_intel_upload.jsonl / reputation.jsonl / ECS alerts,原子写与轮转逻辑重复实现。
- **2.2.6 隔离区脆弱。** `QuarantineManager.cpp`:单字节 XOR(`kXorKey`)+ `index.json`;金库文件以 GUID 命名、**不含元数据**,索引一丢则所有已隔离文件永久无法还原(该文件注释已记录这个坑,并已修过一次「空表覆盖」事故)。
- **2.2.7 内存/容量护栏是逐处补的。** `Worker.h` 里 `kMaxAiPending 256` / `kIpCacheMax 4096` / `kAllowFoldMaxKeys 512` / `kMemVtCacheMax 1024` 各带一段「旁边的都有闸、只有它漏了」的注释 —— 说明缺的是统一的有界容器约定。

### 2.3 内核驱动

- **2.3.1 协议 v9 已到极限。** `Bulwark.Driver/Protocol.h`:
  - `BLW_EVENT_MESSAGE` 定长 `WCHAR ImagePath[520]` + `TargetPath[520]`,命令行走 TargetPath 会被截断。CHANGELOG 记录过绕过手法:「在前面填充垫料就能把危险 token 推出截断范围」。
  - 31 个 `BLW_CMD_*` 复用同一个 `BLW_CONFIG_MESSAGE`,版本号为兼容已部署端而**刻意冻结在 9**(头文件里有三段「仍保持 9」的理由说明)。
  - `BLW_VERDICT_REPLY` 存在,但架构铁律是零同步 IPC(`FltSendMessage` 0 超时),进程创建的灰区走「遥测 + 事后补偿结束」。
- **2.3.2 策略容器定长 + 线性子串匹配。** `Driver.h`:`BLW_MAX_PROTECTED 64` 每类一份定长数组 + 各自一把 `FAST_MUTEX`;`BLW_MAX_HASHES 1024`、`BLW_HASH_QUEUE_CAP 128`。协议没有「删除单条」,只有「追加 / 整表清空」。
- **2.3.3 加白不彻底的根因。** 内核 `FileExecBlock` / `FileNoLoad` 由内核自己写回注册表持久化,跨重启续拦;于是 UI 加白无效,必须回读注册表对账再整表重推(`Worker::reconcileKernelBlocksAfterTrust`,其注释即根因描述)。
- **2.3.4 上报过滤硬编码在内核。** `ProcessMonitor.c` 的 `BlwImageIsTrustedSystemPath`(System32 / SysWOW64 / WinSxS / Program Files 等)直接不上报,仅 `BlwImageIsLolBin`(约 30 个 LOLBin)开口子。后果:名单外的 System32 程序(`reg.exe` / `sc.exe` / `net.exe`)在用户态**永远没有事件可判**。
- **2.3.5 观测覆盖面本身是「有条件才上报」。** 注册表只报命中受关注键名单的键;文件写靠 ETW 新建文件 + 驱动 `IRP_MJ_WRITE` 的 **1/32 采样**;用户态模块加载只报 `\Temp\` 与 `\Users\Public\`。`--attackchain-check` 的可达性诊断实测:18 条组合里 6 条只能算「稀疏」。
- **2.3.6 签名现实。** 驱动只能测试签名加载,用户必须 `bcdedit /set testsigning on` —— 这本身降低系统安全性。`Driver.h` 有一大段「绝不要改回 `ExAllocatePool2`」的说明:改用 `ExAllocatePoolWithTag` + 显式清零,当前真实最低版本由 `FwpsCalloutRegister3` 决定(Win10 1703),并由 vcxproj 的 `BlwVerifyImportFloor` 把守。altitude:ObCallbacks `385199`、注册表回调 `385200`。
- **2.3.7 已做对、必须保留的:** 零同步 IPC + 后台发送线程 + 预分配环形缓冲;握手校验版本与三个结构体大小,不一致即整体降级不拦截;服务不在时内核自持基线;`EX_RUNDOWN_REF ClientPortRundown` 防对已释放端口发送;`Cleanup.c` 强删的两道自毁护栏(入参路径预判 + 打开后规范化名权威判定,判不出来即拒);`Comms.c` 的 `BlwClientIsTrusted`(映像名 + TOFU 路径)+ `BlwCommandIsDestructive` 毁灭性命令白名单。

### 2.4 UI 与 IPC

- **2.4.1 AI 清理执行任意脚本(最高危)。** `cpp/ui/src/dialogs/AiCleanupDialog.cpp` 的 `runElevatedScript`:大模型生成的 PowerShell 写进 `QDir::tempPath()`,再 `Start-Process -Verb RunAs` 以管理员执行,参数含 `-ExecutionPolicy Bypass -NoExit`,**执行前无任何校验**。两个问题:脚本落在用户可写目录,存在替换窗口;喂给模型的行为画像来自攻击者可控的沙箱数据,存在提示词注入面。
- **2.4.2 密钥明文跨进程。** `RuntimeSettings`(`cpp/shared/src/models/RuntimeSettings.cpp`)把 6 个情报源 Key + `aiApiKey` 明文序列化,整体经 IPC 发给 UI(`cpp/ui/src/ipc/IpcClient.cpp:193` 直接 `m_ai->setConfig(s.aiApiKey, ...)`),并明文落 `settings.json`。
- **2.4.3 控制管道。** `cpp/service/src/IpcServer.cpp`:`QLocalServer` + `WorldAccessOption`(Qt 只给 User/Group/Other/World 四档,改不了 DACL);帧是换行分隔 JSON,`payload` 里再嵌一层 JSON 字符串(`IpcMessage.cpp`);`IpcMessageType` 0..75 含 **12 个废弃占位**,无统一请求 ID / 错误码 / 版本协商。真正边界是 `IpcClientAuth`(同目录 + 同名强制层,fail-closed),与内核 SelfGuard + ObCallbacks 咬合。
- **2.4.4 UI 侧直连系统。** `cpp/ui/src/ai/` 自行读写 `%ProgramData%\Bulwark\ai_scan_history.json` 与 `ai_credit.json`;`Bootstrap.cpp` 用 `ShellExecuteExW` runas 拉起服务。
- **2.4.5 未确认。** README 称 UI「manifest 已声明 requireAdministrator」,但 `cpp/ui` 下搜不到该 manifest,`Bootstrap.cpp` 反而按「可能未提权」处理(`isElevated()` 分支)。重写前需查清实际 UAC 级别。
- **2.4.6 god class。** `MainWindow.cpp` 1088 行、`AttackGraphWindow.cpp` 949、`DashboardPage.cpp` 881、`ReputationPage.cpp` 791、`RulesPage.cpp` 755、`SettingsPage.cpp` 706。设计系统(`src/design/`,ListShell 770 行 + Theme 610 + Icons 594)复用度不错,**保留**。

### 2.5 内容分发与服务端

- **2.5.1 攻击链组合表无内容签名。** `AttackChainEngine.cpp` 拉 `/v1/engine/patterns` 只靠 `TlsMode::Pinned`,**无签名校验**;而随包 `appsettings.json` 是 `DryRun: false`(代码默认 `true`)。服务器一旦被攻破,可向所有客户端下发「拦截 / 结束任意程序」的组合。
- **2.5.2 服务端是巨型单体。** `server/bulwark-intel/app.py` **7296 行**,基于 stdlib `ThreadingHTTPServer` + `sqlite3`;信誉代理、特征库下发、在线更新、登录、客服长轮询、反馈、公开 API、样本上传、内嵌 HTML 全在一个进程。旁边还有 `dashboard.py` 3974 行、`engine_build.py` 2046 行、`webui.html` 1947 行。
- **2.5.3 重复代码树。** `server/bulwark-intel-backup-node-45/scripts/` 与 `server/bulwark-intel/` 有同名脚本(`bulwark-sync.py` / `bulwark-benign-push.py`),内容不同。**未确认**线上跑的是哪一份。
- **2.5.4 客户端 ↔ 服务端契约(已核实调用点):**
  | 客户端 | 端点 |
  |---|---|
  | `ProxyReputationService.cpp:511` | `POST /v1/reputation/hash` |
  | `ProxyReputationService.cpp:366` | `POST /v1/reputation/submit` |
  | `ProxyReputationService.cpp:620` | `GET /health` |
  | `AttackChainEngine.cpp:1382` | `GET /v1/engine/patterns?since=` |
  | `ThreatIntelUploader.cpp:72` | `POST /v1/intel/contribute` |
  | `UpdateService.cpp:112` | `GET /v1/update/manifest?channel=` |
  | `UpdateService.cpp:441` | `GET /v1/update/file/<channel>/<name>` |
  | Worker(IP 情报) | `GET /v1/reputation/ip/<ipv4>` |
- **2.5.5 无 CI、无静态分析配置。** 未找到 `.github/`、`.gitlab-ci.yml`、`.clang-tidy`、`.clang-format`。构建靠 CMake + 散落脚本(`scripts/`、`cpp/scripts/`、根目录多个 `.bat`/`.ps1`、`bulwark-recovery/deploy_*.ps1`),其中有硬编码机器路径(如 `d:\bulwark-recovery\git-recovered-tree\cpp\build-fix\...`)。
- **2.5.6 更新机制做得扎实,保留。** `UpdateService.cpp`:URL 白名单 + 拒明文 HTTP、size + SHA-256、Authenticode **钉死签名者指纹**、按 `TRUST_E_BAD_DIGEST` 区分「被改动」与「链不受信」、拒绝同版本与降级、逐文件 park/rollback。`build_update/{beta,stable}/manifest.json` 含 version / published / notes / files[name,size,sha256]。

### 2.6 2026-07 勒索事故(事实与推断分界)

**事实(来自 `bulwark-recovery/` 清单与取证脚本):**
- 勒索家族标记 CLEARWATER;加密文件尾部 264 字节 footer,magic `MYEK`(`exe_probe.py`、`footer_scan.py`、`analyze.py`)。
- 每文件密钥被 **RSA-2048 包裹**,`ENCRYPTED-ONLY-unrecoverable/_MANIFEST.txt` 结论:解密不可行。
- **35 个手写源文件永久丢失**,均「未提交 git、且不在 Kiro 本地历史」,内容是 7 月 19 日在做的 behavior ML 特征工程(`BehaviorFeatureExtractor` / `BehaviorModel` / `ml/train/*` / `tools/vt_web_server.py` 等)。
- 另有约 24 个工具配置文件只剩加密副本(`C-ENCRYPTED-ONLY/`):`~/.claude`、`~/.codex`、`~/.config/clash`、`~/.config/opencode`、`~/.gemini`、`~/.hermes` —— 清单注明可再生(重填 API Key / 重导 VPN 配置)。
- 取证脚本做过已知明文攻击尝试(`cipher_test.py` / `cipher_test2.py`:按 `plaintext_size == cipher_size - 264` 配对,算 keystream 熵与周期、查跨文件 keystream 复用)。

**推断 / 未确认:**
- 当时 Bulwark 是否在运行、跑的是 Driver 还是 Wmi 模式 —— **无证据**。
- 感染来源 —— 无证据。但当时 `ml/tools/` 有从 MalwareBazaar 拉活样本的脚本(`Collect-MalwareBazaar.ps1`、`Import-LocalMalware.ps1`),**在开发机直接接触活样本**本身就是高风险。
- 加密**不是**本产品自身造成的:`QuarantineManager` 是单字节 XOR + `index.json`,与 RSA-2048 包裹 + `MYEK` footer 的形态完全不符。

**对架构的直接要求:** 见 R4(影响面上限 + 可撤销)、`design.md` 第 12 节(反勒索)、`tasks.md` 阶段 0(备份 / 样本隔离)。

---

## 3. 关键决策 D1-D7(已拍板)

> **已于 2026-09-29(第 3 轮)全部拍板:一律采纳「我的建议」栏。** 阶段 1 不再被决策阻塞。

| # | 问题 | 我的建议 | 决定 |
|---|---|---|---|
| D1 | 渐进式迁移 vs 推倒重来 | **渐进式**。推倒重来会丢掉约 300 处现场修复里的大部分 | **采纳:渐进式** |
| D2 | 引擎与服务是否去 Qt(改纯 C++20 + WIL + WinHTTP + SQLite,UI 保留 Qt Widgets) | **引擎先去 Qt**;服务外壳可暂留 QtCore,分两步走 | **采纳:引擎先去 Qt,服务外壳暂留 QtCore,分两步** |
| D3 | 进程拆分范围:先 core + cloud,`bulwark_scan` 延后? | **同意先两个** | **采纳:先 core + cloud,`bulwark_scan` 延后** |
| D4 | 是否办 EV 证书 / 走微软 attestation 签名 | 不办的话,驱动只能定位为测试与内部能力,**ETW 模式必须按主力产品设计** | **采纳:不办 EV。驱动定位为测试与内部能力,ETW 模式按主力产品设计(约束 tasks.md 3.9)** |
| D5 | 接受两处决策语义变化?① 信任不再压过用户显式 Block 规则 ② Ask 不再能降级硬指标 | **接受**,并用回放逐条审差异 | **采纳:接受两处变化,差异用回放逐条审** |
| D6 | AI 清理改为结构化动作计划、产品不再执行任意 PowerShell(保留「导出脚本」给用户自行执行) | **接受** | **采纳:接受** |
| D7 | 内核协议与 IPC 均不兼容旧版,新旧组件必须整体升级 | **接受**(换取 R7 / R9) | **采纳:接受,不兼容旧版** |

---

## 4. 验收标准

### 4.1 阶段 0(保底,不依赖任何决策)

- **A0.1** 227 处未提交改动已提交并推送到远端;仓库有一份异地备份。
- **A0.2** CI 能编出 shared / service / ui 与三条 ctest,PR 触发。
- **A0.3** 旧服务能把原始事件录成 trace 文件(用于阶段 1 的新旧对照)。
- **A0.4** 开发机与活样本隔离:`ml/tools/` 的样本拉取脚本不在开发机运行;样本只在隔离环境处理。

### 4.2 阶段 1(契约与引擎)

- **A1.1** `Facts` / `Signal` / `Decision` 三段模型落地,阶段间**只追加不改写**,用编译期手段保证。
- **A1.2** 决策优先级 L0..L5 写成规格文档,并有表驱动测试覆盖每一档与档间冲突。
- **A1.3** 旧引擎 955 条内置规则导出成 YAML,新引擎装载后规则集等价(id 与匹配条件逐条比对)。
- **A1.4** 新旧引擎在 `corpus.json`(38 条)+ 真机 trace(≥ 1 周)上的差异**逐条审过并留档**,无「不明原因差异」。
- **A1.5** 约 300 处现场修复注释逐条对应一个回放用例,用例名引用原注释位置。

### 4.3 阶段 2(新服务用户态)

- **A2.1** 进程创建事件 p99 < 50ms(内核事件 → 决策),每阶段有耗时与队列深度指标。
- **A2.2** SYSTEM 进程无任何出网调用;网络全部在 `bulwark_cloud`。
- **A2.3** 所有状态变更动作经唯一 `ActionExecutor`,有影响面上限与按事件撤销。
- **A2.4** 密钥经 DPAPI 加密入库;UI 只能看到「已配置」+ 末四位。
- **A2.5** 影子模式(只判定不处置)与旧服务同机并跑,差异全部可解释。

### 4.4 阶段 3(驱动 v2)

- **A3.1** 协议 v2:变长 TLV + 批量 + 序号 + 丢弃计数,路径与命令行不截断。
- **A3.2** 策略整份快照 + generation 号 + 原子切换;热路径无锁读;支持删除单条(推新快照)。
- **A3.3** Driver Verifier 全项开启、事件风暴、加载卸载循环、72 小时稳定性全部通过。
- **A3.4** 上报过滤 / LOLBin 名单 / 关键进程名单全部来自快照数据,驱动内只留最小安全默认值。

### 4.5 阶段 4-5

- **A4.1** 服务端拆成 edge-api / content-builder / portal;OpenAPI 契约 + 双端契约测试。
- **A4.2** 内容包(规则 / 攻击链 / IOC / 内核基线 / 更新清单)统一 manifest + payload + Ed25519 签名,私钥离线。
- **A5.1** 用户数据迁移、升级与回滚演练通过;旧代码树删除。

---

## 5. 硬约束(不可协商)

- **C1** 保留设计原则:软信号绝不单独定罪;结构化证据链;规则可到期与会话作用域;可正常卸载;内核零同步 IPC;握手不一致即降级;服务不在时内核自持基线;处置结果如实回报(不报假拦截)。
- **C2** 保留检测内容:955 条规则、全部分析器与时序检测器、`IpBlockPolicy`(实测 68 个「C2 地址」里 48 个是公共基础设施 = 71%)、攻击链可达性诊断。
- **C3** 保留已做扎实的实现:更新校验链(2.5.6)、情报共享写盘前脱敏(唯一执行点 `ThreatIntelContribStore::sanitize`)、驱动强删自毁护栏(2.3.7)。
- **C4** UI 设计系统与 12 个页面保留外观与交互,只换通信层并把业务逻辑挪回服务。
- **C5** 仓库不含任何厂商 API 密钥;`cpp/dist/` 是本地运行目录(已 gitignore,可能含真实 Key),**不得整目录分发、不得提交**。
