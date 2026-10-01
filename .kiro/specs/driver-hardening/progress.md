# 内核驱动优化 · 进度与交接(2026-09-30)

**状态**:9 项已实现,驱动 `.\scripts\build-driver.ps1 -Configuration Debug` **0 错 0 警**(/W4 + /WX),
`ctest --test-dir cpp\build -C Release` **4/4 通过**(新增第 4 条 `driver_match_unit`,88 条断言)。
**未部署、未在 VM 里加载验收。未提交**(见第六节)。

只动了 `Bulwark.Driver/` 与 `cpp/tests/`,没有碰任何用户态服务/UI 代码。

---

## 一、这一轮之前的现状(已核实,不必重查)

- `Bulwark.Driver/` 源文件 17 个;协议版本 9;池分配只走 `BlwAllocPool`(理由在 `Driver.h` 顶部,别改回 `ExAllocatePool2`)。
- 唯一一处未提交的驱动改动是 `FileMonitor.c` 的「重命名额外上报目标名」(dropped-file-taint 项 4a),
  本轮保留未动,它现在和本轮改动混在同一个工作区里。
- 三处与旧交接文档不符、本轮核实的事实:
  1. **撤销路径已经存在**,是 `Worker::reconcileKernelBlocksAfterTrust`(`Worker.cpp:1509`)的
     「CLEAR + 重下发保留项」。它的真实缺陷不是「没有撤销」,而是**保留项为空时不标脏 → 重启后条目复活**
     (`Comms.c` 里 CLEAR 刻意不标脏,只有 ADD 标脏)。这条改变了「删除单条」的设计动机。
  2. `BlwAddKnownBadHex`(`HashScan.c:191`)**本来就自带去重与格式校验**,所以运行期下发哈希的内核侧
     几乎没有新逻辑,只是补两条命令。
  3. `BlwCmdPatternMatches` 早已是独立纯函数(吃 `BLW_PROTECTED_PATH*` + 原始串),抽取成本比预估低。
- 一处代码与注释不符:`BlwPreWrite` 上方写「进程级采样」,实现是全局 `WriteSampleCounter`。本轮一并修正。

---

## 二、本轮做了什么(按实施顺序)

### A1 · 名单匹配核心抽成可在用户态编译的独立文件 + host 单测

- 新增 `Bulwark.Driver/MatchCore.h` / `MatchCore.c`,从 `Driver.h` / `FileMonitor.c` / `ProcessMonitor.c`
  搬出:`BlwUpcaseChar`、`BlwStartsWithCI`、`BlwVolumeRelativeOffset`、`BlwVolumePathStartsWith`、
  `BLW_VOLPATH_STARTS`、`BLW_PROTECTED_PATH`、`BLW_MATCH_CTX`、`BLW_NAME_ENTRY`/`BLW_NAME`、
  `BLW_MAX_PROTECTED`、`BlwPrepareMatch`、`BlwMatchInListCtx`、`BlwAddToList`、`BlwLogPattern`、
  `BlwWideContainsCI`、`BlwImageNameIn`、`BlwCmdPatternMatches`(由 static 改为对外)。
  **搬移部分语义零变化。**
- 环境约定:内核侧由 `Driver.h` 在包含内核头之后 include 它(`MatchCore.h` 刻意不自带任何内核头);
  用户态定义 `BLW_MATCHCORE_HOST` 打开垫片段,**垫片刻意不含 `<windows.h>`**——那会引入
  「`UNICODE_STRING` 由哪个头定义」之类的环境差异。
- 新增 `cpp/tests/DriverMatchTest.c` + ctest `driver_match_unit`。**本工程 `project()` 只启用了 CXX**
  (`cpp/CMakeLists.txt:6`),所以这两个 `.c` 在 CMake 侧用 `set_source_files_properties(... LANGUAGE CXX)`
  显式标成 C++;不标的话 MSVC 生成器会把 `.c` 静默跳过,表现是链接期「找不到 main」,极难一眼看出原因。
  选这个而不是改顶层 `project()`,是为了不牵动整个工程重新配置。
- 覆盖 10 组:卷前缀剥离 5 种形态 / 两起历史事故的回归哨兵 / 按文件名匹配 / 宽串子串 /
  名单去重·满槽·精确删除·槽位复用 / 子串语义 / 锚定语义 12 例 / 超长目标回退路径 /
  命令行 token 合取(含 `HKLM\SAM` 与 `HKEY_LOCAL_MACHINE\SAM` 两种写法) / 带盘符死条目判据。

### B1a · 带盘符的死条目在入口拒收

- `FileMonitor.c` 新增 `BlwRejectDeadPathPattern`,挂在 5 份**文件路径**名单的 Add 入口:
  `ProtectedPaths` / `FileHardBlock` / `SelfGuard` / `FileNoLoad` / `FileExecBlock`。
- **`CmdHardBlock` 与 `RegHardBlock` 刻意不套**(命令行里 `C:\` 正常;注册表值名允许含 `:`)。
- 磁盘自愈:新增 `g_Blw.PolicyDeadDropMask` + `BlwMarkDeadEntryDrop` / `BlwPersistDeadEntryDrops`。
  `DriverEntry` 第 8.6 步(**必须排在 8.5 启动写回线程之后**)调用一次,让受影响名单各写回一次。
  排在 8.5 之后是为了走去抖线程,而不是在 `DriverEntry` 里同步写注册表。

### B1b · 禁止执行 / 禁止加载改用锚定匹配

- `MatchCore.c` 的 `BlwMatchScan` 增加 `BLW_MATCH_MODE` 参数;新增对外入口
  `BlwMatchInListAnchoredCtx`;`BlwFileIsNoLoad` / `BlwFileIsExecBlocked` 改用它。
  其余 5 份名单**一个字节没动**,仍是子串。
- 判据:起点边界(模式以 `\` 开头 | 匹配从串首起 | 前一字符是 `\`)+ 终点边界(模式以 `\` 结尾的
  目录前缀语义 | 匹配到串尾 | 其后紧跟 `:`,即备用数据流)。
- **为什么不用卷相对锚定前缀**(更紧但不能用):`set-baseline-policy.ps1` 的文档用法是
  `-FileExecBlock '\evil.exe'`(只给文件名片段),前缀锚定会直接废掉它;而卷前缀认不出来时
  (`\Device\Mup\`、影子卷)前缀锚定整条失效,等于拿覆盖面换精度。

### B2 · 运行期下发已知恶意 SHA-256

- `Protocol.h`:`BLW_CMD_CLEAR_KNOWNBAD=32` / `BLW_CMD_ADD_KNOWNBAD=33`,复用 `BLW_CONFIG_MESSAGE.Path`
  (64 个十六进制宽字符),**协议版本保持 9**。`CLEAR` 归入 `BlwCommandIsDestructive`。
- **刻意不持久化**(不写 `\Policy\KnownBadSha256`):内核哈希集没有「删除单条」,写进跨重启基线
  一次误判就是「那个文件永久起不来且加白无效」。

### B3 · 名单精确删除单条

- `Protocol.h`:`BLW_CMD_DEL_PATH/_FILEHARD/_NOLOAD/_EXECBLOCK/_REGHARD/_CMDBLOCK` = 34..39,
  复用 `Path` 字段,**协议版本保持 9**,全部归入 destructive。
- `MatchCore.c` 新增 `BlwRemoveFromList`(精确整串、大小写不敏感);`FileMonitor.c` 新增公共外壳
  `BlwRemoveFromGuardedList`(持锁 + 只在真删掉时重算计数),三个模块共用;各名单 7 个薄封装。
- **只在真删掉时才 `BlwMarkPolicyDirty`** —— 删不存在的条目是完全无副作用的操作,不触发注册表写。
- `SelfGuard` 与 `ProtectedRegKeys` 没有 DEL:前者本就不持久化、断连即整体清除;后者是软监控名单。

### 1b · 驱动服务注册的遥测(BYOVD 加载之前的观测点)

- `RegistryMonitor.c`:`RegNtPreSetValueKey` 分支先做**廉价的值名判断**(`BlwRegValueNameIs(valueName,
  L"IMAGEPATH", 9)`,不需要解析键路径),命中才强制解析键路径(绕过「无名单即放行」的快速路径,
  做法与既有 `builtinHive` 完全一致);键路径在 `\REGISTRY\MACHINE\SYSTEM\…\Services\` 之下则
  fire-and-forget 上报一条 `BlwEventRegistrySetValue`,然后 `return STATUS_SUCCESS` 避免第 3 级重复上报。
- 键路径判据写成「以 `\REGISTRY\MACHINE\SYSTEM` 开头 且 含 `\SERVICES\`」,以同时覆盖
  `CurrentControlSet` 与 `ControlSetNNN`(内核给出的规范化键路径通常是后者)。
- **刻意不读 `ImagePath` 的值数据**:`REG_SET_VALUE_KEY_INFORMATION::Data` 可能指向用户态缓冲,
  安全读取要 `ProbeForRead` + `__try/__except` —— 在注册表回调里新增一处可能出错的解引用,
  换来的只是省掉用户态回读一次注册表,不划算。

### C1b · 写采样按 PID 分槽 + 同文件去重

- `Driver.h`:`WriteSampleCounter`(单个)→ `WriteSampleSlots[64]` + `WriteSeenFile[64]`,
  新增 `BLW_WRITE_SLOTS` / `BLW_WRITE_SLOT_MASK`(定义在 `BLW_GLOBALS` 之前,结构体里要用)。
- `FileMonitor.c` 新增 `BlwWriteSampleShouldReport(Pid, FileObject)`:全程无锁,
  一次 `InterlockedExchange64`(同文件去重)+ 一次 `InterlockedIncrement`(计数)。
- `FileObject` 只作**不透明身份标签**,**绝不解引用**(它可能早已释放;比错的后果仅是多/少一条遥测)。
- 取模走无符号 + 位与:计数器溢出成负数后 `%` 结果落在 `{-31..0}`,原写法会让该槽永久停止上报。

### C1a · 落地区新建可执行/脚本文件的上报

- `FileMonitor.c` 新增 `BlwIsDroppedPayload`(落地区**卷相对锚定前缀** 5 条 + 24 种扩展名后缀)
  与 `BlwCreateDispositionWrites`(Disposition ∈ SUPERSEDE/CREATE/OPEN_IF/OVERWRITE/OVERWRITE_IF)。
- `BlwPreCreate` 增加 `needDropWatch`(遥测开 + 写意图 + 会新建/覆盖 + 非 delete-on-close),
  并入那批 `needXxx` 快速放行判断;命中且发起者不是本产品受保护进程时上报。
- 子类型复用 `BlwEventFileRename`:用户态按 `ParentPid` 还原时,非「删除标记」一律映射为 `FileWrite`
  (`DriverEventSource.cpp` 的 `BlwEventFileModify` 分支),正是这里要的语义。
  **代价**:UI 详情文案会显示成「重命名/移动」。要精确区分得新增子类型 + 改用户态映射。
- **已知代价**:pre-create 不知道创建最终是否成功,会有少量「其实没创建成」的上报。刻意不加
  post-create 回调(新注册一个回调风险更高,而本机不能加载测试)。

### C2(第一步)· WFP 改表驱动 + 出站 IPv6

- `Driver.h`:`BLW_WFP_LAYER_COUNT = 2`;`WfpCalloutId`/`WfpFilterId`(单个)→ 数组;
  新增对外 `BlwWfpHasCallouts()`。
- `NetMonitor.c`:新增 `BLW_CALLOUT_V6_GUID`(一个 callout 只能绑一个层,必须各自一个 GUID);
  新增层表 `kBlwWfpLayers` + `C_ASSERT` 与 `BLW_WFP_LAYER_COUNT` 对齐;
  拉起 / 回滚(`calloutAddedHere[]`)/ 卸载三条路径全部改成按表循环。
- 卸载路径:**一层失败也继续拆完其余层**(提前 return 会把其它层的 callout 一起留下),
  残留由 `BlwWfpHasCallouts()` 报告给卸载路径,它据此拒绝卸载并保留网络设备对象。
- `BlwClassifyFn` 用 `inFixedValues->layerId` 分支:两层都拦「已封禁主体」的任何外联;
  **IPv4 黑名单匹配只在 V4 层做**(`BLW_BLOCK_IP` 是 32 位,装不下 128 位地址)。
  补的这一维是真实缺口:此前已被情报确认恶意的进程改走 IPv6 就完全不受阻。
- `Driver.c` 两处 `WfpCalloutId == 0` 判断改为 `!BlwWfpHasCallouts()`。

---

## 三、刻意没做 / 明确不要顺手补的

1. **`RegNtPreLoadKeyEx` 仍不处理**。`REG_LOAD_KEY_INFORMATION_V2` 首成员是 `Size` 而非 `Object`,
   合并处理会把一个 `ULONG` 当指针交给 `CmCallbackGetKeyObjectIDEx`,直接蓝屏。
2. **BYOVD 的真阻断没做**。要做得给 `BlwPreCreate` 的「内核态 I/O 一律放行」开一个窄口子
   (仅 `FileNoLoadCount > 0 && executeIntent && !SL_OPEN_PAGING_FILE`,且只查 FileNoLoad 这一份名单,
   再加「卷相对路径以 `\Windows\` 开头一律不拦」的护栏——误配一条就可能开不了机)。
   那是唯一能真阻断的路,但它触碰最保守的那条铁律,且本机无法验证,留给带 VM 的会话定夺。
   另注:用户态已按 rules-fp-fix 9.2 改为「内核驱动加载不下发 FileNoLoad」,所以即便内核补上,
   `.sys` 条目也只能从 `\Policy\FileNoLoad` 离线基线通道进来——对 BYOVD 来说那恰好是正确的通道。
3. **事件路径字段 520 WCHAR 的截断没改**。改长度必动 `BLW_EVENT_MESSAGE` 布局 → 必须升协议版本 +
   双端同步,而升版本会让已部署的 v9 两端因版本不符而**整体降级为不拦截**。留到下次确实要改布局时一起做。
   命令行硬拦**刻意吃原始串不截断**,别给它加截断(填充垫料把危险 token 推出截断范围是可利用的绕过)。
4. **命令行硬拦命中后不封禁发起方**。事件的 `ParentPid` 里就是父 PID,用户态据此发
   `BLW_CMD_ADD_BANNED` 即可,内核不需要新机制。不在内核自动封禁的理由:发起方通常就是管理员
   自己在用的 cmd.exe / powershell.exe,封禁后它一切行为被拒,而 `BannedPids` 只在进程退出时解除。
5. **内核名单仍无「自动过期」**。到期失效归用户态规则(`DefenseRule::expiresUtc`);
   内核名单没有时间维度,不确定的处置仍然绝不该进内核持久名单。

---

## 四、构建与验证口径

```powershell
# 构建前必须先停服务 + 卸载 minifilter:内核基线把 cmd.exe 钉在 FileExecBlock 里,
# minifilter 加载期间 MSBuild 用不了 cmd.exe,编不过(MSB6003)。
Get-Process bulwark_ui -ErrorAction SilentlyContinue | Stop-Process -Force
sc.exe stop BulwarkService
fltmc.exe unload Bulwark

.\scripts\build-driver.ps1 -Configuration Debug        # 要求 0 错 0 警(/W4 + /WX)
cmake --build cpp\build --target driver_match_unit --config Release
ctest --test-dir cpp\build -C Release --output-on-failure
```

本轮实测结果:驱动构建 4 次全部 0 错 0 警(13 个 `.c` 全部重编,导入表护栏 `BlwVerifyImportFloor`
未触发),`ctest` 4/4 通过(`verdict_snapshot` / `builtin_ruleset_ids` / `attackchain_regression` /
`driver_match_unit`),`driver_match_unit` 88 条断言 0 失败。

**没有验证过的**(全部需要带快照的测试 VM):
- 任何内核回调的实际行为 —— 锁与 IRQL 语义、`BlwPreCreate` 新增分支的真实事件量、
  注册表回调新分支、写采样分槽在多核下的实际分布;
- **WFP 两层的拉起与拆除**(这是本轮风险最高的一块:拆除路径漏掉一个 callout 就是蓝屏);
- 死条目自愈是否真的把注册表里那 3 条带盘符的 `FileNoLoad` 清掉;
- `BLW_CMD_DEL_*` / `BLW_CMD_*_KNOWNBAD` 的端到端效果(用户态还没有调用方,见第五节)。

VM 里验收时建议按这个顺序看 DebugView(勾 *Capture Kernel*)里的 `[Bulwark]` 日志:
1. 加载后是否出现 `Policy: rewriting lists 0x... to purge dead (drive-letter) entries`,
   以及 `NoLoad entry REJECTED (drive-letter pattern never matches)`;
2. `WFP registered on 2 layer(s).`;
3. `fltmc unload` 后不蓝屏、`WFP unregistered.`;
4. 往 `%TEMP%` 写一个 `.exe`,看是否有对应遥测;
5. `sc create` 一个驱动服务,看是否出现 Services\…\ImagePath 的遥测。

---

## 五、留给用户态那条线的事(驱动侧已具备能力,没有调用方)

1. **`BLW_CMD_ADD_KNOWNBAD`**:云信誉 / 兜底扫描 / 情报确认恶意后,把 SHA-256 喂进内核。
   建议在服务连接时把「已确认恶意哈希」整批重推一遍(内核侧去重,重推无代价)。
2. **`BLW_CMD_DEL_*`**:把 `reconcileKernelBlocksAfterTrust` 的「CLEAR + 重下发保留项」换成
   「对每条要撤销的条目发一次 DEL」。这样才真正修掉第一节第 1 点那个跨重启漏洞
   (也顺带消掉「清空到重推之间该维防护是真空」的窗口)。旧驱动不认这些命令时返回
   `STATUS_INVALID_PARAMETER`,服务应静默回退到现有 CLEAR + 重推路径。
3. **驱动服务注册遥测的消费**:用户态收到 `…\Services\<名字>\ImagePath` 的 `RegistryWrite` 后,
   回读该值拿到 `.sys` 路径,做签名/情报判定。这是 BYOVD 在模块进内核之前唯一的定性机会。
4. **释放物落地遥测的 UI 文案**:当前复用 `BlwEventFileRename` 子类型,UI 详情会显示成
   「重命名/移动」。要精确区分需新增子类型 + 改 `DriverEventSource` 的 `BlwEventFileModify` 分支映射。

---

## 六、提交状态

**未提交。** 工作区里同时有:
- 本轮的驱动改动 + `cpp/tests/` 两个文件 + `CHANGELOG.md` + `Bulwark.Driver/README.md`;
- 上一轮遗留的 `FileMonitor.c` 项 4a(重命名额外上报目标名,已混在同一个文件里);
- 其它线的 100+ 个未提交文件,其中 nodriver-hardening 那条线明确要求
  「用户态服务 `0xC0000374` 堆破坏定位清楚前不要提交」。

因此**不要顺手替别人提交**。要提交本轮内容时,只取:

```
Bulwark.Driver/MatchCore.h  MatchCore.c  Driver.h  Driver.c  FileMonitor.c
Bulwark.Driver/ProcessMonitor.c  RegistryMonitor.c  NetMonitor.c  Comms.c  Policy.c
Bulwark.Driver/Protocol.h  Bulwark.Driver.vcxproj  README.md
cpp/tests/DriverMatchTest.c  cpp/tests/CMakeLists.txt
CHANGELOG.md
```

注意 `FileMonitor.c` 里混着项 4a 的改动 —— 提交信息里要写明,或者先和 dropped-file-taint 那条线对一下。

git 约定:`git -c safe.directory=*`,身份用
`-c user.name=z614606517zz -c user.email=z614606517zz@users.noreply.github.com`(不写进 config)。

---

## 七、关键文件索引

| 文件 | 本轮作用 |
|---|---|
| `Bulwark.Driver/MatchCore.h` | 两种编译环境的约定 + 全部匹配基元的声明。改判定前先读顶部 |
| `Bulwark.Driver/MatchCore.c` | `BLW_MATCH_MODE` 处写着子串 / 锚定两种语义的完整判据与取舍 |
| `cpp/tests/DriverMatchTest.c` | 88 条断言。往 MatchCore 加判定必须同时加断言 |
| `Bulwark.Driver/Protocol.h` | `BLW_CMD_*_KNOWNBAD` / `BLW_CMD_DEL_*` 的设计理由;协议版本演进史 |
| `Bulwark.Driver/FileMonitor.c` | 死条目拦门、精确删除外壳、写采样分槽、释放物可见面 |
| `Bulwark.Driver/NetMonitor.c` | `kBlwWfpLayers` 层表;加层只需加一行 |
| `Bulwark.Driver/README.md` | 「局限与后续」已按本轮结果重写 |
| `.kiro/specs/rules-fp-fix/progress.md` 第九节 | klids.sys + FileNoLoad 失效的原始分析 |
| `.kiro/specs/dropped-file-taint/handoff.md` | 释放物拦截缺口的全景;项 4a 已在工作区实现 |
| `.kiro/specs/av-engine/handoff.md` 第三节 | 内核现状核实 + 哈希集缺口(本轮 B2 补上) |
