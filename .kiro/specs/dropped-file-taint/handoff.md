# 释放物拦截缺口 · 交接文档

**状态**（2026-09-29 更新）：项 1、2、3、4a 已实现；用户态全量构建通过，ctest 三条全绿（golden 零差异）；驱动用 `SpectreMitigation=false` 编译通过但**未部署**；第四节手工验收**未做**。项 4b / 4c 未动。
实现与原方案的差异：
- 注入器去重（`main.cpp` `setIntelRuleInjector`）原先只比 type/action/target/hash，会把第二个起的污点文件全当重复丢掉，已加上 `actorPath` / `commandLinePattern`；
- 命中污点规则的 Block 一律 `persistentBlacklist=false`（`onEvent` / `onPromptResponse`），否则污点会经 `blacklistExec` / `blockModuleLoad` 绕回内核名单；
- 写类事件（FileWrite / RegistryWrite）的「确定性恶意」要求硬指标或 `[情报` / 污点规则（`Worker::isDeterministicMaliciousBlock`），保护型规则拦一次写入不触发清理 / 污点；
- 签名写入方（浏览器、msiexec、解压器）只把与被拦主体**同一私有目录**的文件算同批，公共目录（Temp / Downloads / Desktop / AppData 根…）不算；
- 脚本与 .msi/.msp 按命令行匹配，DLL 按 ImageLoad 目标匹配，均去盘符；
- 撤销：加白后 `purgeTaintRulesAfterTrust`；用户对污点询问点放行时 `dropTaintRulesMatching`。
**目标**：让「威胁被拦下之后，它此前释放的文件」也能被清理，并且之后运行时能被拦住。

本文所有 `文件:行号` 都是读代码核实过的（截至本文编写时）。未核实的地方明确标了「待核实」。

---

## 一、问题与结论

用户问：「目前是不是阻止威胁以后，威胁释放的文件没办法拦截」——**基本是的**。

拦截只处理主体进程本身。它被拦之前释放的文件，多数情况下不会被清理，之后运行时也不会和这次拦截关联起来。

### 1.1 拦截时实际做了什么

| 动作 | 位置 | 覆盖面 |
|---|---|---|
| 结束进程树 + 内核封禁 PID | `Worker.cpp:1033-1043` → `banProcess` | 封禁后它的文件写/删/执行打开、注册表写、外联、建子进程全被内核拒绝（`FileMonitor.c:740`(create) / `931`(setinfo) / `1150`(write)、`RegistryMonitor.c:572`、`NetMonitor.c:184`、`ProcessMonitor.c:510`）。**拦截之后**再释放新文件这一段是挡住的 |
| 加内核禁止执行名单 | `Worker.cpp:1378` | 只传 `e.actorPath`，且只在 ProcessCreate 事件时加。**释放物从不进这个名单** |
| 隔离主体载荷 | `Worker.cpp:1399` `maybeQuarantineOnBlock` | 默认关（`RuntimeSettings.h:87` `quarantineOnBlock = false`），开了也只隔离主体自己 |
| 足迹清理（含释放物） | `Worker.cpp:1448` `remediateIfMalicious` | 条件极窄，见 1.2 |

### 1.2 释放物漏掉的六个原因

1. **足迹清理触发条件三重与**（`Worker.cpp:1454-1459`）：`v.action == Block` 且 `v.source ∈ {Rule, Heuristic}` 且 `e.type ∈ {ProcessCreate, RemoteThread}`。于是以下全都不清理：
   - 用户在弹窗点「阻止」→ `onPromptResponse` 只调 `enforceBlock`（`Worker.cpp:688`），`source` 是 `UserPrompt`；
   - 弹窗超时按默认策略拦截（`resolvePromptByDefault`，`source = Timeout`）；
   - 因写 Run 键 / 联网 / 写文件 / 加载模块被拦（`type` 不在白名单里）。**dropper 最常见的就是在写持久化这一步被拦，此时载荷已经落好了**。

2. **ProcessCreate 场景下足迹本来就是空的**：`collectTreeEvents(pid)`（`ProcessChainTracker.cpp:144`）只从该 PID 往下 BFS 找后代。新进程刚创建，没有后代、没有事件。拉起它的父进程、父进程的其他释放物，都不在范围内。

3. **内核已前拦的事件直接返回**（`Worker.cpp:1355` `if (e.kernelBlocked) return KernelBlocked;`）：不杀、不封禁。主体继续运行，可以换个地方接着释放。这是刻意的（避免误伤只是误触受保护目标的正常程序），但对确认恶意的主体是缺口。

4. **服务看不全释放了什么**：
   - 驱动 `BlwPreCreate` 不上报新建文件，只报 delete-on-close（`FileMonitor.c:762` `needTelemetry = telemetryOn && deleteOnClose`）；
   - `IRP_MJ_WRITE` 只对偏移 0 的写做全局 1/32 采样（`FileMonitor.c:1185`，`BLW_WRITE_SAMPLE_RATE=32` 定义在 `Driver.h:583`）；
   - 重命名只上报**源**文件名（`FileMonitor.c:1113`）。「先写 x.tmp 再改名成 x.exe」只会记下一个已经不存在的 x.tmp。目标名只在**被拒绝**时才上报（`FileMonitor.c:1100`）；
   - ETW 补了一类：`\Users\ \ProgramData\ \Windows\Temp\ \Temp\ \PerfLogs\` 下新建 22 种可执行/脚本后缀（`EtwProcessEventSource.cpp:97` `isDroppedExecutable`，挂在 `kFileCreateNew=30`）。**不订阅重命名**；.dat/.bin 类载荷、覆盖已有文件、其他目录（如 `D:\Tools\`）都看不到。默认 `KernelFile = true`、每进程每分钟 240 条上限（`BulwarkOptions.h:26`）；
   - 进程链每 PID 只留最近 64 条事件、30 分钟过期（`ProcessChainTracker` 构造默认值）。

5. **清理本身有护栏**（`ThreatRemediator.cpp:272` `isSafeToRemove`）：只清 `kDropZones`（`ThreatRemediator.cpp:99`）里的文件；带可信签名的跳过，除非 bypass（主体签名异常 / 哈希确认 / VT 沙箱确认，`ThreatRemediator.cpp:389-392`）。白加黑里带签名的宿主会留下。

6. **释放物之后运行时，和这次拦截没有关联**：
   - `recentExeWrites_` 只记「路径 → 时间」，**不记写入方 PID、也不记写入方有没有被拦**（`ProcessChainTracker.cpp:57`）。唯一用途是 5 分钟内运行的文件挑出来送 VT（`Worker.cpp:2082` `isRecentlyDroppedExecutable`，`kRecentDropWindowSecs=300`，`Worker.cpp:55`），且需要配了 VT + 开了双击扫描；
   - 规则引擎从零评估：未签名 / 首见 / 可疑路径都只是软信号，无硬指标即放行（决策管线见 `.kiro/steering/product.md`）；
   - 内核在进程创建时只能拒三种：父进程已封禁、路径命中 FileExecBlock、命令行命中 CmdHardBlock（`ProcessMonitor.c:511 / 567 / 591`）。内核已知恶意哈希集只在驱动加载时从注册表 `Policy\KnownBadSha256` 读（`Policy.c:311`），**运行期没有任何 `BLW_CMD_*` 能下发哈希**（见 `.kiro/specs/av-engine/handoff.md` 第三节「重大缺口」）。

### 1.3 唯一比较完整的那条路

`onReputationMalicious`（`Worker.cpp:1547`）——云端信誉确认恶意时会：把 VT 沙箱报告里的释放路径翻译成本机路径、按哈希在落地区搜索（`ThreatRemediator::locateDroppedFilesByHash`）、给释放物哈希注入「禁止运行」规则（`buildRulesFromProfile`，`Worker.cpp:97`）。

前提是云端认识这个样本且有行为报告。新样本 / 定制样本走不到这里。

---

## 二、已确定的方案（用户已批准「按推荐的来」）

按收益排序。**项 1、2 不动驱动**，改动集中在 `Worker` + `ProcessChainTracker`。

### 项 1 · 污点标记（taint）：释放物继承「被拦」这件事

**思路**：拦截时把该进程树写过的文件登记为污点；这些文件之后启动或被加载为模块时，按硬指标拦下。

**载体选 `DefenseRule` 注入，不选内核名单。** 理由（重要，别改回去）：
- 决策管线第 1 步是「用户信任的文件/文件夹无条件放行」，早于第 7 步的显式规则 → **用户加白一定能撤销污点**；
- 内核 `FileExecBlock` 是 64 槽定长、只加不减、内核自己写回注册表持久化、协议无「删除单条」。一次误判就是「该程序永久起不来，用户在 UI 怎么加白都没用」——已有实测事故（Kiro 被静默模式升级为 Block 后永久钉死，只能手工改注册表）。完整说明在 `Worker.cpp:1082-1100` 与 `Worker.h:172-175`；
- 复用现成设施：`RuleStore` 落盘、`main.cpp:1858` 注入器的累加去重、UI 规则页可见、`DefenseRule::expiresUtc` 到期自动失效。

**分级**（对齐产品原则「最小化误报」，也对齐 `buildRulesFromProfile` 里「释放文件名 → 落地即询问」的既有口径）：

| 拦截来源 | 污点规则动作 | 有效期 |
|---|---|---|
| 引擎自判 Block（`source ∈ {Rule, Heuristic}`）、信誉/AI/兜底扫描确认恶意 | `Block` + `hardOverride = true` | 30 天 |
| 用户点「阻止」、弹窗超时兜底 | `Ask`（落地即询问，不阻断） | 7 天 |

不确定的处置绝不产出 `Block + hardOverride` —— 与 `enforceBlock(persistentBlacklist=false)` 同一原则。

**规则形态**：
- `actorPath` = 释放物完整路径（精确、大小写不敏感），**不用 `actorPattern` 通配**；
- 后台补算 SHA-256 后再追加一条 `actorHashes` 规则（文件被改名/搬走也能命中）；
- `type = ProcessCreate`（.exe .scr .com .bat .cmd .ps1 .vbs .js .hta .jar …）；
- `type = ImageLoad`（.dll .sys .ocx .cpl .drv）—— 这条是白加黑侧载的正面覆盖；
- `note` 统一前缀 `[污点-释放物]`，便于识别、去重、以后整批撤销。

**护栏**（缺一不可，照 `blacklistExec` + `isSafeToRemove` 的口径）：
1. `engine_->trustNoteForPath(path)` 命中 → 跳过（已加白）；
2. `Worker::isSweepExemptPath(path)`（System32 / SysWOW64 / WinSxS / 本产品目录）→ 跳过；
3. 只收落在 `kDropZones`（`ThreatRemediator.cpp:99`）里的文件。**建议把这份名单和 `isSafeToRemove` 一起提到共用位置**，别复制第二份；
4. `ProcessInspector::isSigned(path)` 为真 → 跳过，除非该文件是哈希/情报确认的恶意；
5. 数量上限：单次拦截最多 20 条、污点规则总量最多 200 条（规则库是定长预算，被垃圾条目占满会挤掉真规则。既有先例：`kMaxIpRules = 50`、`nameRules >= 20`）；
6. 绝不因污点去 `blacklistExec` / `blockModuleLoad`（内核名单）。

**需要的数据：写入方归属。** 现在没有。改 `ProcessChainTracker`：
```cpp
// 现状：QHash<QString, QDateTime> recentExeWrites_;   // 只有时间
// 改为：
struct ExeWrite { QDateTime when; int writerPid = 0; QString writerPath; };
QHash<QString, ExeWrite> recentExeWrites_;
```
`writerPath` 必须存 —— 本项目**没有进程退出事件**，PID 会被复用（`ProcessChainTracker.h:48-62` 有完整说明），只靠 PID 反查会认错进程。

新增两个方法（`wasRecentlyWritten` 保持原样，`Worker.cpp:2088` 还在用它，别动签名）：
```cpp
// 该 PID(及其后代)记录过的 FileWrite/FileDelete 目标
QVector<QString> filesWrittenBy(int pid, bool includeDescendants = true) const;
// 某路径最近的写入方(时间窗内)；返回 {pid, path},用 path 校验 PID 没被复用
struct Writer { int pid = 0; QString path; };
Writer lastWriterOf(const QString& path, int withinSeconds) const;
```

**接入点**：新增 `void Worker::taintDroppedFiles(const SecurityEvent& e, VerdictAction grade, const QString& tag);`
- `onEvent` 的 `case VerdictAction::Block`（紧跟 `Worker.cpp:569` 的 `remediateIfMalicious` 之后）；
- `onPromptResponse` 的 Block 分支（`Worker.cpp:688-690`），grade = `Ask`；
- `onReputationMalicious`（`Worker.cpp:1578` 附近）、`onAiMalicious`（`Worker.cpp:1711`）、`handleSweptMalicious`（`Worker.cpp:2940` 附近），grade = `Block`。

**候选文件来源**（两路并集）：
1. `chain_.filesWrittenBy(pid)` —— 被拦主体及其后代写过的文件。项 3 放开触发条件后这一路才有料；
2. `chain_.lastWriterOf(e.actorPath, kRecentDropWindowSecs)` —— 若被拦的是「刚被释放出来的那个进程」，回溯出写它的那个 dropper，再取 `filesWrittenBy(dropper)`，把**同批的其他载荷**一起标。这是本项最大的实际收益。

**线程**：候选收集在主线程；SHA-256 计算（`QuarantineManager::tryComputeSha256`）必须扔后台线程，算完 `QMetaObject::invokeMethod` 回主线程调 `injectIntelRules_`（该注入器**只能在主线程调**，`Worker.h:105` 注释写明）。照 `confirmReputationMaliciousAsync`（`Worker.cpp:1510`）的写法。

### 项 2 · 用户点「阻止」时也做足迹清理

`remediateIfMalicious` 刻意拒绝 `UserPrompt`（`Worker.cpp:1455`，理由是「避免误清理良性程序」）。**不要放宽它**，另开一条路：

```cpp
void Worker::remediateOnUserBlock(const bulwark::SecurityEvent& e);
```
- 在 `onPromptResponse` 的 Block 分支调用（`Worker.cpp:688-690` 之后）；
- 内部仍走 `remediator_->remediate(e, chain_.collectTreeEvents(pid))` + `applyRegHardening`；
- 隔离是**可还原**的（进隔离区，UI 可还原/永久删除），用户又是显式选的「阻止」，所以这个激进度是可接受的。`isSafeToRemove` 的落地区 + 签名护栏全部保留；
- 事件类型放开到 `ProcessCreate / RemoteThread / FileWrite / RegistryWrite`；
- 结果走现成的 `ipc_->sendRemediationReport(makeRemediationPayload(...))`，UI 的「清理报告」页会列出已清理 / 未清理项并支持「重试隔离」。

**不新加确认弹窗**：清理报告已经存在且是可还原的，再加一个 IPC + UI 对话框收益不抵成本。

### 项 3 · 放开 `remediateIfMalicious` 的事件类型

`Worker.cpp:1457` 的 `e.type != ProcessCreate && e.type != RemoteThread` → 追加 `RegistryWrite`、`FileWrite`。

- 这才是让项 1 第一路候选（`filesWrittenBy`）真正有料的前提：dropper 通常是在写持久化那一步被拦的，那时它的 FileWrite 足迹都在链里；
- 主体路径的安全性由 `isSafeToRemove` 兜（`isSystemExecutable` 要求「名字命中 **且** 真在系统目录」，`ThreatRemediator.cpp:254`）。写注册表的主体经 `enrich` 第 0 步已把 SCM 还原成真凶（`Worker.cpp:760`）；
- 注意 `kDropZones` 含 `\users\` 这种宽条目，`C:\Users\x\AppData\Local\Programs\<app>\app.exe` 也在落地区内，此时唯一的保护就是签名护栏。别把签名护栏一起放宽。

### 项 4 · 扩大可见面（可独立推进）

**4a 驱动：重命名也上报目标名。** `BlwPreSetInformation` 末尾（`FileMonitor.c:1113`）现在只报源名。在未被任何名单拒绝的重命名路径上，若 `KeGetCurrentIrql() == PASSIVE_LEVEL`，再调一次 `FltGetDestinationFileNameInformation`，把目标名同样交给 `BlwReportFileTelemetry(BlwEventFileRename, &destInfo->Name)`。
- **比原设想简单**：`BlwReportFileTelemetry`（`FileMonitor.c:641`）内部本来就固定发 `BlwEventFileModify`，并把原始操作类型打包进 `ParentPid` 字段；用户态在 `DriverEventSource.cpp:917-931` 按 `ParentPid` 还原成 FileDelete / FileWrite。所以直接复用它即可，不用新事件类型，也不会进 `needsVerdict()`（`DriverEventSource.cpp:201`，不含 FileModify）的裁决追踪；
- 遥测开关、Active 判空、IRQL 检查都在该函数内部，调用点不用重复判断；
- 取目标名的代码形态照 `FileMonitor.c:1040-1102` 那段（`FltGetDestinationFileNameInformation` + `FltReleaseFileNameInformation` 配对，失败时 fail-open 不拦）；
- **协议不变**（不新增命令、不改结构体布局）→ 协议版本保持 9，无需双端同步。

**4b ETW：订阅重命名。** `kKeywordFile = 0x1400`（CREATE_NEW_FILE | DELETE_PATH），`EtwProcessEventSource.cpp:75`。要加 rename。
- **待核实**：Microsoft-Windows-Kernel-File 的 rename keyword 位与事件 ID。用 `logman query providers Microsoft-Windows-Kernel-File` 或 `wevtutil gp Microsoft-Windows-Kernel-File` 现场确认，别照记忆填；
- 加完后 `isDroppedExecutable` 判据要对「目标名」跑一遍（改名成 .exe 才是投递完成的时刻）。

**4c USN 日志「写完即扫」**：已在 `.kiro/specs/av-engine/proposal.md` §4.2（E2）规划过——`FSCTL_READ_USN_JOURNAL` + `ReturnOnlyOnClose=1`，不采样、不需要驱动、不碰零同步 IPC 铁律。**本文不重复设计，落地时直接引用那份。**

---

## 三、不能破的约束

1. **零同步 IPC 铁律**：驱动侧 `FltSendMessage` 一律 0 超时 + 后台发送线程 + 预分配环形缓冲。热路径绝不做同步 IPC。
2. **不确定的处置绝不进内核持久名单**：`FileExecBlock` / `FileNoLoad` 由内核写回注册表、跨重启续拦、无「删除单条」。见 `Worker.cpp:1082-1100`、`Worker.h:172-175`、`reconcileKernelBlocksAfterTrust`（`Worker.cpp:1237`）。
3. **加白必须能撤销一切**：污点走用户态规则就是为这个（管线第 1 步 > 第 7 步）。任何新增处置路径都要在动手前调一次 `abortIfTrustedNow`（`Worker.cpp:1109`）。
4. **规则库是定长预算**：所有注入都要有条数上限。
5. **自我保护必须保留用户可驱动的卸载/清理路径**（`product.md` 设计原则第三条）。
6. **`golden.json` 零差异**：项 1-3 只在运行期注入规则，不改 `RuleEngine` / `ThreatDetector` 的求值逻辑，`verdict_snapshot` 应当不变。如果变红，说明改到管线了，停下来先解释清楚。
7. **`.ps1` 一律 ASCII**：中文 Windows 上 PowerShell 5.1 会把无 BOM 的 UTF-8 当 ANSI/GBK 读，中文字面量会被弄坏（`rebuild_full.ps1` 头部有说明）。`.cpp` 里中文没问题（CMake 全局加了 `/utf-8`），但**资源可见的头文件必须保持纯 ASCII**（`VersionNumbers.h` 的注释解释了 rc.exe 那个坑）。
8. **PID 会复用**：没有进程退出事件（`ProcessChainTracker.h:48-62`、`AttackChainEngine.h` 同结论）。任何按 PID 归属的新状态都要同时存映像路径做校验。

---

## 四、构建与验证

**构建必须先停驱动** —— 内核基线把 `\WINDOWS\SYSTEM32\CMD.EXE` 钉在 FileExecBlock 里，而 MSBuild 要用 cmd.exe 跑 Qt autogen，minifilter 加载期间根本编不过（MSB6003 / 0x80004005）。

```powershell
# 管理员 PowerShell。停 UI/服务/驱动 → 全量构建 → 部署 dist → finally 里重启服务恢复防护
.\rebuild_full.ps1
```

回归测试（`cpp/tests/CMakeLists.txt` 三条，都必须绿）：
```powershell
ctest --test-dir cpp\build -C Release --output-on-failure
#   verdict_snapshot        12 步决策管线的黄金裁决逐字段比对
#   builtin_ruleset_ids     内置规则 id 两两不同(撞 id 会静默丢规则)
#   attackchain_regression  攻击链组合引擎(bulwark_service --attackchain-selftest)
```

**手工验收**（项 1+2）：
1. 用脚本往 `%TEMP%` 释放一个无害 exe，再让脚本去写一个 Run 键触发拦截；
2. 查 `service.log`：应出现「污点-释放物」注入日志 + 足迹清理报告；
3. 双击那个释放出来的 exe：引擎自判来源应直接 Block，用户点「阻止」来源应弹询问；
4. 在 UI 把该 exe 加白，再双击 → **必须放行**（验证管线第 1 步压过污点规则）；
5. 确认内核 `FileExecBlock` 名单里**没有**这个释放物（`cpp\scripts\set-baseline-policy.ps1` 可读回，或查 `HKLM\SYSTEM\CurrentControlSet\Services\Bulwark\Policy`）。

---

## 五、关键文件索引

| 文件 | 作用 |
|---|---|
| `cpp/service/src/Worker.cpp` | 裁决落地、处置、后台扫描。170KB，本次主战场 |
| `cpp/service/include/bulwark/service/Worker.h` | 上面每个私有方法的「为什么这么设计」都在注释里，改之前先读 |
| `cpp/shared/src/engine/ProcessChainTracker.cpp` | 进程链 + `recentExeWrites_`，项 1 要改这里 |
| `cpp/service/src/ThreatRemediator.cpp` | 足迹清理、落地区/护栏名单、按哈希定位释放物 |
| `cpp/service/src/main.cpp` | 接线（`setIntelRuleInjector` 在 1858 行）。144KB |
| `Bulwark.Driver/FileMonitor.c` | minifilter 三个 pre 回调，项 4a 在这里 |
| `Bulwark.Driver/Protocol.h` | 全部 `BLW_CMD_*` 与协议版本演进史 |
| `.kiro/steering/product.md` | 12 步决策管线的权威描述（`inclusion: manual`，用 `#` 引入） |
| `.kiro/specs/av-engine/handoff.md` | 内核现状核实（第三节）+ 内核哈希集缺口。与本文互补 |
| `.kiro/specs/av-engine/proposal.md` | USN「落盘即扫」设计（§4.2 E2），项 4c 直接用 |

---

## 六、下一步

按 **项 3 → 项 1 → 项 2 → 项 4** 的顺序做。项 3 最小（一行条件），但它是项 1 候选文件有料的前提；项 1 是主体；项 2 复用项 1/3 铺好的东西；项 4 可并行，且 4a 只动驱动、4b 只动 ETW，互不干扰。

开工前先读 `Worker.h` 里 `enforceBlock` / `blacklistExec` / `remediateIfMalicious` / `reconcileKernelBlocksAfterTrust` 四段注释 —— 本次要避开的坑全在那儿写着。
