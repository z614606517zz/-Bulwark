# 磐垒(Bulwark)整体架构重写 · 目标架构与关键设计

> 前置阅读:`requirements.md`(需求、现状结论、7 个待定决策)。
> 本文的编号 S1..S14 被 `tasks.md` 引用。

---

## 0. 进程与组件全景

```text
[用户会话 · 普通权限]                [SYSTEM]                                      [低权限 / 受限]
bulwark_ui (Qt Widgets)  <-- Pipe v2 -->  bulwark_core                    <-->  bulwark_cloud
  只做展示与交互                           Sensors -> Ingest -> Enrich             (LocalService / 虚拟服务账号)
  不联网 / 不写 ProgramData                -> Detect -> Policy -> Respond          WinHTTP:信誉 / 上传 / 内容 / 更新 / AI
  不执行脚本                               PromptBroker · Store(SQLite)            唯一出网进程
                                          ContentManager(验签) · Updater
                                          ActionExecutor(唯一状态变更入口)  <-->  bulwark_scan(可选,后期)
                                                  ^                                受限令牌 · 无网络
                                                  | 内核协议 v2                     解析不可信文件(PE / 脚本)
                                          Bulwark.sys
                                            采集 + 执行策略快照 + 最小内置基线

服务端:
  edge-api        FastAPI + pydantic,nginx/Caddy 前置 —— 信誉 / 内容下发 / 更新 / 情报接收
  content-builder 离线批处理 + Ed25519 签名(私钥离线保管)
  portal          网页 / 客服 / 反馈,独立进程独立认证
```

**五条原则**

1. 内核只做采集 + 执行用户态编译好的策略快照,外加一份内置最小安全基线。
2. 所有判断在 core 内完成,且是纯函数 —— 能离线确定性回放。
3. SYSTEM 进程不联网、不解析不可信文件。
4. 一切状态变更走同一个执行器 + 同一份安全策略,有日志、可撤销。
5. 服务器下发的、能影响裁决的内容一律签名;验签失败保留上一份可用版本。

**S0 · 无驱动是一等公民。** 每个传感器声明自己的 `capability`(能看到什么 / 能否事前拦截 / 采样率),策略编译器按实际能力降级并产出「覆盖面报告」,UI 如实显示。理由见 `requirements.md` 2.3.5/2.3.6:驱动需测试签名,ETW 模式才是默认发布形态。

---

## S1 · 只追加的分阶段数据模型

替换 `SecurityEvent` 上帝对象(现状 2.1.1)。

```text
RawEvent   传感器原样上报(内核 TLV / ETW / 用户态行为源),不可变
   |  Enrich
Facts      每一项带 Provenance{source, timestampUtc, confidence}
   |         取不到就是 Unknown —— 绝不默认成「未签名」
Signal[]   每条 = {analyzer, kind: Hard|Soft|Trust|Rule|Info, weight, evidence, attackTechnique?}
   |  Policy
Decision   {action: Allow|Ask|Block, source, matchedRuleIds[], signalRefs[], rationale}
   |  Respond
ActionResult[]  {actionType, target, outcome, undoToken?, failureReason?}
```

- 每层结构体只暴露追加接口(`addSignal` / `addFact`),没有 setter 能改写上一层。建议用 `const` 成员 + builder,或 `std::variant` 分层。
- **攻击链、侧载篡改、迟到的云信誉、AI 结论都只是 `Signal` 的来源之一** —— `chainScore` / `chainHardIndicator` / `tamperedModulePath` 三个旁路字段随之删除。
- 风险分不再是可覆写的字段,而是 `Signal[]` 的**纯函数聚合**,同一份 `Signal[]` 永远得到同一个分数。

## S2 · 决策优先级写成规格,表驱动测试钉住

| 档 | 含义 | 变化 |
|---|---|---|
| L0 | 安全不变量:关键系统进程、本产品组件 —— 只记录不处置 | 不变 |
| L1 | 内核已前拦的事件 —— 如实记录 `KernelBlocked` | 修掉现状「引擎判 Allow 但内核已拦时 UI 显示放行」 |
| L2 | 显式策略(用户规则 + 信任) | **变化**:信任不再无条件压过 Block 规则;按具体度比较,平局取 Block,UI 标注冲突(D5) |
| L3 | 确定性证据(硬指标 / 时序检测命中 / 攻击链定性) | **变化**:Ask 规则与 devTool 豁免不得降级 L3(D5) |
| L4 | 软信号 | 只加分,永不单独处置 |
| L5 | 默认策略(`defaultBlock` / 弹窗超时兜底) | 不变 |

- 规格文档 + 表驱动测试:每一档 × 每一种档间冲突各一个用例。
- `isDevTool` 改为「文件名 + 签名健康 + 位于标准安装目录」三条合取,堵掉改名绕过(现状 2.1.2)。

## S3 · 流水线与线程模型

目标 R2。替换现状 2.2.2 的单线程串行。

- **分通道有界 ring**,按优先级:① 进程创建 / 远程线程 ② 注册表 / 网络 ③ 文件遥测。丢弃**按通道计数**并经 IPC 上报,UI 显示「遥测丢失 N 条」—— 不再静默丢(静默丢 = 漏检)。
- **富化走线程池**。文件事实缓存键 = `文件 ID(FileId) + 最后写入时间`,取代现状的「小写路径|大小|修改时刻」。热路径**只读本地信誉缓存,绝不联网** —— `InlineReputationBudgetMs` 这个概念随之消失。
- **检测与决策按进程树分片**:同一 shard 单线程(保证 `BeaconDetector` / `RansomwareBehaviorMonitor` 等时序检测器的顺序语义),不同 shard 并行。
- **迟到结论统一成 `LateSignal`** 回灌决策阶段 —— 现状 2.2.3 的五条补偿路径合成一条,`abortIfTrustedNow` 变成 `LateSignal` 处理链上的一个固定环节,不再靠每处记得调。
- 每阶段导出指标:入队 / 出队 / 耗时分位 / 丢弃数。

## S4 · 内核协议 v2 与策略快照

替换现状 2.3.1~2.3.4。

**消息层**
- 变长 **TLV**,批量发送(一次 `FltSendMessage` 带 N 条),消息头含 `seq` + `droppedSinceLastSeq`。
- 路径与命令行不再截断;超长则分片,携带 `truncated` 标志由用户态决定是否重取。
- 握手保留现有形态(版本 + 结构体尺寸校验,不一致整体降级),加上「能力位图」:驱动声明自己支持哪些维度。

**策略层(关键改动)**
- 用户态编译出**整份策略快照**(单块连续内存 + generation 号)下发;内核校验后**原子切换**(指针替换 + rundown 等旧快照排空),热路径**无锁读**。
- 每条策略带 `{id, source, ttl}`。**删一条 = 推一份不含它的新快照** —— 现状 2.3.3「加白后回读注册表对账再整表重推」整段逻辑删除。
- 上报过滤、LOLBin 名单、关键进程名单、受关注注册表键**全部变成快照里的数据**;编进驱动的只剩「绝不可拦」的最小安全默认值。
- 匹配从「64 条定长数组线性子串」升级为快照内预建索引(后缀集 / 前缀 trie),热路径复杂度与名单长度解耦。

**保留不动**:零同步 IPC 铁律、后台发送线程 + 预分配环形缓冲、`EX_RUNDOWN_REF` 端口保护、`Cleanup.c` 双道自毁护栏、`BlwClientIsTrusted` + 毁灭性命令白名单、`ExAllocatePoolWithTag` 包装与导入表下限检查。

**进程创建仍做不到事前询问**(零同步 IPC 的必然代价)。补法是「**落盘即扫 · 执行即拦**」:可执行体一写入用户可写目录就送扫描,结论提前进内核快照的 exec-block,于是「事后 kill 让样本先跑几十毫秒」的窗口被前移消除。

## S5 · 单一安全策略源(R8)

现状:关键进程名单在 **8 处**各自维护且内容不一致 —— `ProcessMonitor.c` `kCritical`、`FileMonitor.c` `BLW_SYS_BOTH`、`ThreadMonitor.c`、`InjectionAnalyzer.cpp` `criticalTargets()`、`ThreatDetector.cpp` `criticalImageNames()`、`ThreatRemediator.cpp`、`ProcessInspector.cpp`、`ProcessEnumerator.cpp`。

- 新增 `contracts/safety_policy.yaml`,定义:关键进程(**映像名 + 必须所在的系统目录**,防改名伪装)、系统路径、本产品目录、受保护用户数据目录、公共基础设施 IP 段(即现 `IpBlockPolicy`)。
- 生成器一次产出三份:驱动 C 头文件、core C++ 表、服务端 Python 表。
- 服务端据此**拒绝发布**任何会命中关键进程的内容包。

## S6 · 执行器、影响面上限与撤销(R4)

- `ActionExecutor` 是唯一能结束进程 / 隔离文件 / 删注册表 / 改内核名单的地方。
- 每个动作固定四步:**安全检查(S5) → 写含撤销信息的日志 → 执行 → 如实回报**。
- **影响面上限**:单事件最多隔离 N 个文件、每分钟最多结束 M 个进程;超限即停手并询问用户。UI 提供「按事件撤销」。
- **隔离区改自描述容器**:内容用 CNG AES-GCM,每条目独立密钥并由 DPAPI 包裹;索引进 SQLite,**索引丢失可从各容器头部重建** —— 修掉现状 2.2.6。

## S7 · 存储与密钥(R9)

- 一个 SQLite(WAL)替换现状 2.2.5 的十来份 JSON/JSONL。时间线查询走 SQL(现状是扫 `events.jsonl`)。
- 审计表做**哈希链**,可发现篡改。
- API Key 经 DPAPI 加密入库;`RuntimeSettings` 不再携带明文 Key,UI 只收到「已配置 + 末四位」——修掉现状 2.4.2。

## S8 · IPC v2

- 原生命名管道 + **显式 SDDL**(只放行 SYSTEM 与当前交互用户),摆脱 `QLocalServer` 四档粗粒度限制。
- 连接后依次校验:PID → 映像路径 → 签名指纹(现 `IpcClientAuth` 的强制层保留并加强)。
- 帧 = **长度前缀 + protobuf**,自带 `requestId` / `errorCode` / 版本协商。现状约 1500 行手写 `Payloads.cpp/.h` 由生成代码替代;`IpcMessageType` 的 12 个废弃占位随之清理。
- 每客户端独立**有界发送队列**,慢客户端拖不住服务。
- **操作分权**:关闭防护、加信任、还原隔离、执行清理,以及**在带硬指标的弹窗上点「允许」**,都需一次 UAC 同意(安全桌面)。这样即使同用户下的恶意程序能模拟点击 UI,也点不动 UAC。

## S9 · 进程拆分(R3)

- `bulwark_cloud`:独立服务,LocalService 或虚拟服务账号。**WinHTTP 取代 `curl.exe`**(现状 2.2.4),集中限流 / 熔断 / 配额 / TLS 信任锚(自有端点 Pinned,公网源完整校验)。
- `bulwark_scan`(D3,可延后):受限令牌 + 无网络,负责解析不可信 PE 与脚本。
- UI 不联网、不写 `%ProgramData%`、不执行脚本 —— 修掉现状 2.4.4。

## S10 · AI 清理改造(D6)

- 大模型只允许输出**结构化 JSON 动作计划**(终止进程 / 删文件 / 清注册表值 / 防火墙阻断 / hosts 屏蔽,各带明确参数)。
- 三道闸:**schema 校验 → S5 安全策略过滤 → `ActionExecutor` 执行**。产品不再执行任意 PowerShell(修掉现状 2.4.1)。
- 「导出为脚本」保留,由用户自行决定是否运行 —— 保住可复核性,但执行责任明确回到用户。
- 行为画像来自攻击者可控数据,故计划里的每个目标路径 / 键都要过 S5,且沙箱数据只作为**候选**、不作为授权。

## S11 · 签名内容通道(R5)

- 统一格式:`manifest + payload + Ed25519 签名`,适用于规则包、攻击链组合表、IOC feed、内核基线、更新清单。
- 私钥离线,只在 `content-builder` 上签。
- 新内容默认先「只记录」一段观察期再转强制;版本只许前进(沿用 `UpdateService` 的 `isNewerThanCurrent` 思路)。
- 修掉现状 2.5.1:攻击链组合表当前**无签名**且随包 `DryRun: false`。
- **规则迁移工具**:写一次性导出器,链接旧 `bulwark_shared`、调 `DefaultRules::build()`,把 955 条规则原样导成 YAML。`.kiro/tmp/` 下已有 `rules_before.json`(505KB)/ `rules_now.json`(499KB)/ `DefaultRules.decoded.cpp`(115KB),可作交叉校验基准。

## S12 · 反勒索(针对 2026-07 事故)

- 内核按进程统计**写入量 / 改名次数 / 扩展名变化 / 写入熵**,越阈值即在内核本地拒绝写入(不依赖用户态往返)。
- **受保护文件夹**:文档 / 桌面 / 源码目录只允许可信进程修改;其他进程首次修改时询问。
- 保留现有勒索诱饵(canary)机制:`UserModeBehaviorSource` 投放诱饵 + `engine_.addCanaryFile` 登记,触碰即 Block。
- 可选(难度最高,放后期):文档首次写入前做写时复制备份,支持按事件回滚。

## S13 · 服务端拆分(R5 配套)

- `edge-api`:FastAPI + pydantic 校验,nginx/Caddy 前置;承接 2.5.4 契约表里的全部端点。
- `content-builder`:离线跑 `engine_build.py` 的继任者 + 签名。
- `portal`:网页 / 客服长轮询 / 反馈,独立进程与认证 —— 把 7296 行单体(现状 2.5.2)切开。
- OpenAPI 定义契约,客户端与服务端**双向契约测试**。
- 先查清 `bulwark-intel-backup-node-45` 与 `bulwark-intel` 线上跑哪份(现状 2.5.3),再合并。

## S14 · 工程与测试

- **构建**:CMake presets + vcpkg manifest,依赖版本钉死。保留现有加固选项(`/guard:cf` `/CETCOMPAT` `/W4` `/permissive-`,`/Qspectre` 仍可选)。
- **CI**:编 core / UI / 测试 + EWDK 编驱动 + CodeQL;PR 触发。
- **回放**:core 能把 `RawEvent` 录成 trace;回放器离线确定性跑完整流水线。**约 300 处现场修复注释逐条变成回放用例。**
- **驱动测试**:Hyper-V 检查点 + Driver Verifier 全项 + 事件风暴 + 加载卸载循环 + 72h 稳定性。
- **行为测试**:用 Atomic Red Team 之类模拟器;活样本只在隔离环境碰(见 `requirements.md` A0.4)。
- **Fuzz**:IPC 帧、内核 TLV 消息、内容包、PE 解析四处。
