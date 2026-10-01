# 内置规则误拦截治理 · 会话交接文档

> 上一会话已完成**全量调研 + 方案拍板**，结论全部内联在本文。
> **新会话不要重新调研、不要整份读本文。** 按第 5 节的批次逐批读、逐批改、逐批停下来给用户看。
> 相关：`.kiro/steering/product.md`（产品原则）、`.kiro/tmp/list_rules.py`（规则清单导出工具）。

---

## 一、任务

用户原话：「查看所有规则有没有会误拦截的」→「需要（动手改）」。

范围 = `cpp/shared/src/engine/rules/Rules01..08_*.cpp` 共 8 段、约 588 条内置规则。
目标 = 消除会拦正常系统/软件行为的规则，**不降低对真实攻击的检出**。
产品原则（steering）：「最小化误报 / 用户打扰」「只对真正危险的行为动手」。

---

## 二、已核实的机制事实（新会话不要重新验证）

读过并确认的代码（括号内是本文引用到的行号，需要时只读这几段，**不要整份读**）：

| 文件 | 已确认的事实 |
|---|---|
| `cpp/shared/src/models/DefenseRule.cpp:124-140` | `wildcardMatch` 只认 `*`（任意长度，**跨 `\` 分隔符**）与 `?`；大小写不敏感；**整串锚定**（首尾都要匹配完），所以子串语义必须自己写 `*...*` |
| 同上 `:52-60` | `targetPattern` **仅 ProcessCreate** 会回退匹配 `actorPath` |
| `cpp/shared/src/engine/RuleEngine.cpp:256-261` | `ruleTier`：精确 actorPath/actorHashes = 2，`hardOverride` = 1，其余 = 0 |
| 同上 `:710-725` | 排序：tier > 具体度 > 动作强度(Block2>Ask1>Allow0) > createdUtc > id，取 `matches.first()` |
| 同上 `:727-740` | 命中后先看 `exemptTrustedOsComponent`→`isTrustedOsComponent` 放行；再看 `action==Ask && isDevTool(actorPath)`→放行 |
| `cpp/shared/src/engine/TrustPolicy.cpp:359-364` | `isTrustedOsComponent` = `!hasThreatIndicator` **且** `!isLolBinOrScriptHost(actorPath)` **且** `isStronglyTrusted`（微软签名 + 系统目录 + 无危险命令行 + 无异常父子链） |
| 同上 `:247-269` | `isTrustedSecurityProduct` **只看 `e.actorPath`** —— 经 `cmd /c` 发起的动作认不出来 |
| `cpp/service/src/Worker.cpp:505-512` | `Ask` + `trustSignedActors` + 签名健康 → **降级为 Allow**。所以 Ask 规则实际只对未签名主体弹窗 |
| 同上 `:1355-1400` | `enforceBlock`：ImageLoad→`blockModuleLoad`(持久 FileNoLoad)；ProcessCreate→`blacklistExec`(持久 FileExecBlock)；其余→`killMalicious` 结束进程树 |
| `Bulwark.Driver/ImageMonitor.c:113-122` | `.sys` 的 ImageLoad 上报口径 = `\Temp\ \Users\Public\ \ProgramData\ \AppData\ \Downloads\ \Desktop\`（**比段 7 注释里写的宽**）；用户态 DLL 只有 `\Temp\ \Users\Public\` |
| `Bulwark.Driver/FileMonitor.c:200-212` | FileNoLoad/FileExecBlock **只有 64 槽、只加不减**，槽位耗尽后「此后所有新的恶意裁决都被丢弃」 |
| `cpp/service/src/DriverEventSource.cpp:179,202` | `BlwEventFileRename` → `EventType::FileWrite`，**全量遥测且内核阻塞等裁决**（不是 1/32 采样） |
| `cpp/service/appsettings.json:26-40` | ProtectedPaths 默认只有 Startup / hosts / `\Tasks\`；受关注注册表键另由 `DefaultRules::registryWatchFragments()` 并入 |

**两条推导出来的结构性结论：**

- **S1**：段 1「系统维护放行」全部是 tier 0（`actorPattern`+`signedOnly`，无 actorPath）。任何 `.hard()` 的 Block 是 tier 1，**恒定压过段 1**。所以段 2/段 4 注释里「段 1 已放行 TrustedInstaller / TiWorker」这个推理**不成立**。给段 1 加 `.hard()` 也救不回来（tier 打平后 `rulePriority` Block=2 > Allow=0，Block 仍胜）→ 唯一不动引擎的修法是给冲突的 Block 规则加 `.exemptOs()`。
- **S2**：RegistryWrite 的 target 是「键路径 + `\` + 值名」，**看不到值数据**。所以所有「关闭 X」的注册表规则，真实语义是「写了 X 这个值」，**包含把它写成开启**。段 3 在 3.5 节（UAC 策略）已按这个理由给 Ask，但 3.1 / 3.3 两处给了 hard Block —— 同文件内口径不一致。

---

## 三、缺陷清单（已定级，不要重新分析）

### A 级 — 会拦正常行为，且后果带持久化

| # | 位置 | 模式 | 误拦场景 |
|---|---|---|---|
| A1 | `Rules02:253-262` | 7 个辅助功能映像 `*\System32\<n>` Block+hard，无签名条件、无 exemptOs | Windows Update / DISM / `sfc` 替换文件走 rename → 全量遥测 + 内核阻塞；因 S1 压过段 1 → 拒绝改名 + 结束 TiWorker/TrustedInstaller |
| A2 | `Rules03:41-44` | kDefenderOff 9 个值 `*\Windows Defender*\<v>` Block+hard | 见 S2：GPO / 加固基线显式**启用**实时防护也命中 → 结束 gpsvc 所在 svchost |
| A3 | `Rules03:128` | `*\PowerShell\ScriptBlockLogging\*` Block+hard | 同 S2，**开**日志也拦 |
| A4 | `Rules03:125-126` | 命令行 `*scriptblocklogging*` Block+hard | 同上 |
| A5 | `Rules05:106,108` | `*\System32\*.exe` / `*.dll` + unsignedOnly + hard | `*` 跨分隔符 → 覆盖 `\System32\config\systemprofile\AppData\Local\Temp\`（SYSTEM 上下文临时目录）、`\System32\spool\drivers\x64\3\`（打印驱动安装）。未签名厂商安装器/更新器命中 |
| A6 | `Rules07:73-76` + 伪装扩展名那批 | `*\appdata\local\temp\*.dll` / `*.tmp` 等 + unsignedOnly + hard | Inno Setup 从 `is-XXXX.tmp\` 加载 `setup.tmp` 与 helper DLL、NSIS 从 `%TEMP%\nsXXXX.tmp\` 加载插件 DLL，基本都未签名。额外代价：`blockModuleLoad` 把随机化 temp 路径写进 64 槽名单 → 烧光槽位 |
| A7 | `Rules07:95-107` | kByovd 26 个具名 `.sys`，不看签名不看位置 | 上报口径含 `\Temp\ \ProgramData\ \Downloads\ \Desktop\`：Dell 的 `dbutil_2_3.sys` 历史上落在 `C:\Windows\Temp\`；`WinRing0x64.sys` 一类便携硬件监控工具常从桌面/下载目录直接跑 |
| A8 | `Rules06:184,186` | `*reflection.assembly*load*`、`*[reflection.assembly]*` | `[Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')` 是 PowerShell 弹 GUI 的标准写法 |
| A9 | `Rules06:162` | `*net.webclient*downloadfile*` / `*downloadstring*` | Chocolatey 官方安装一行命令就是这形态 |
| A10 | `Rules06:131` | `*powershell*-enc *` | 想用尾随空格挡 `-Encoding` 缩写，但 `-Enc UTF8` 正好带空格 → 护栏无效 |
| A11 | `Rules02:201,208,211` | schtasks `/create*/ru*system*`、`/create*<脚本宿主>*`、`/create*\programdata\*` 全 hard | 「任务以 SYSTEM 跑」「任务跑 PowerShell」「任务指向 ProgramData」都是正常部署形态 |
| A12 | `Rules07:117` | `*create*type=*kernel*` | 任何合法驱动安装，含本产品自己的驱动安装脚本（若不走 `bulwark.ps1 -File` 通道） |
| A13 | `Rules04:67` | `*save*hklm\system*` | `reg save HKLM\SYSTEM\CurrentControlSet\Services\X x.hiv` 是备份单个服务键的常规写法 |
| A14 | `Rules04:91` | `*harddiskvolumeshadowcopy*` | 走卷影快照读文件是备份软件的正常形态 |
| A15 | `Rules08:61-62` | `*--silent-install*`，无 actor 锚定 | 企业静默部署普遍用这个参数 |

### B 级 — 频率低或方向不可辨，但仍是 Block

`*etweventwrite*`、`*etweventunregister*`、`*queueuserapc*`（按 API 名匹配命令行）；
`*bcdedit*safeboot*`、`*fltmc*unload*`、`*fltmc*detach*`、`*disable-computerrestore*`（**退出**安全模式 / 驱动开发 / 运维同形）；
`*physicaldrive0*`（读系统盘做镜像也命中）；`*certutil*decode*`（脚本解 base64 的常规用法）；
`*ntds.dit*`（域控备份/巡检脚本）；`*chisel*`（Chisel 也是硬件描述 DSL）；
段 3 `kSecServices` 的 `*stop*<svc>*` 等无 actor 规则（安全软件自己的更新器经 `cmd /c sc stop` 停自己服务时 actor 是 cmd.exe，`isTrustedSecurityProduct` 只看 actorPath，认不出来）。

### C 级 — Ask 噪音（带 unsignedOnly 的救不了，因为签名降级对它们无效）

段 5 `kBackupExt` 里的 `*.bak`（FileDelete 全量遥测，日常工具链到处都是）；
段 5 `kLiveData` 里的 `*.ldf`（也是 LaTeX 语言定义文件扩展名）；
段 4 `*\Microsoft\Credentials\*`（无 unsignedOnly）。

---

## 四、决策（已拍板，新会话直接执行，**不要再问用户**）

原则：**保留检出、降低处置强度**。优先级 = ① 加 `.exemptOs()` 让签名系统组件豁免（`isTrustedOsComponent` 天然排除 LOLBin/脚本宿主，所以攻击者走 cmd/powershell 仍被拦）；② 把模式改精确；③ 都做不到才降 Block→Ask。**不动 `RuleEngine` / `ruleTier` / `Worker`**（风险大于收益）。

1. A1 → 7 条辅助功能文件替换规则加 `.exemptOs()`，保留 Block+hard。
2. A2 → kDefenderOff 9 条加 `.exemptOs()`，保留 Block+hard。
3. A3 → ScriptBlockLogging 注册表条加 `.exemptOs()`，保留 Block+hard。
4. A4 → 命令行 `*scriptblocklogging*` 降为 **Ask**，去 `.hard()`。
5. A5 → 两条降为 **Ask**、去 `.hard()`；注释里写明「`*` 跨分隔符，覆盖面远大于 System32 本身」。`\System32\drivers\*.sys` 那条不动。
6. A6 → 伪装扩展名列表**删掉 `.tmp`**（保留 dat/log/bin/txt/jpg）；三条 `*.dll` 侧载规则降为 **Ask**、去 `.hard()`。
7. A7 → kByovd 拆两组：**A 组降 Ask**（合法软件在用：`dbutil_2_3` `dbutildrv2` `rtcore64` `winring0x64` `procexp152` `kprocesshacker` `speedfan` `atszio` `nvflash` `winio64` `amifldrv64` `mhyprot2` `mhyprot3` `aswarpot` `zam64` `zamguard64` `truesight`）；**B 组保留 Block+hard**（`iqvw64e` `iqvw64` `gdrv` `gdrv2` `viragt64` `elrawdsk` `asrdrv101` `piddrv64` `echo_driver` `pcdsrvc`）。备注要逐条不同（id 由备注+条件派生）。
8. A8 → 删掉 `*[reflection.assembly]*`；`*reflection.assembly*load*` 改为与 base64 互证的两条：`*reflection.assembly*frombase64string*`、`*frombase64string*reflection.assembly*`。
9. A9 → 两条降为 **Ask**。合取形态（`*downloadstring*iex(*` 等）保持 Block+hard 不动。
10. A10 → **删掉** `*powershell*-enc *`；`*hidden*-enc *` 与 `*powershell*-encodedcommand*` 已覆盖，不补。
11. A11 → `/create*/ru*system*` 与 `/create*<脚本宿主>*` 降为 **Ask**；`/create*<投递目录>*` 那组**从循环里排除 `\programdata\`**（其余 temp/public/recycle/perflogs 保留 Block+hard）。
12. A12 → `*create*type=*kernel*` 降为 **Ask**。
13. A13 → 三条蜂巢导出改为**尾随空格**精确化：`*save*hklm\sam *` / `*save*hklm\security *` / `*save*hklm\system *`（子键备份后面跟 `\` 不跟空格，天然排除），保留 Block+hard。
14. A14 → `*harddiskvolumeshadowcopy*` 降为 **Ask**。
15. A15 → `*--silent-install*` 降为 **Ask**。
16. B 级 → 全部降为 **Ask**、去 `.hard()`，逐条在备注/注释里写明降级理由。`kSecServices` 那批**保持 Block**（停用安全软件服务的危害高于误伤），但在段 3 文件头补一句已知残留：经 cmd 发起时共存放行认不出来。
17. C 级 → `kBackupExt` 删 `*.bak`；`kLiveData` 删 `*.ldf`；`*\Microsoft\Credentials\*` 加 `.unsignedOnly()`。

**独立议题，做完上面再单独问用户，不要自己改**：
- `Worker::enforceBlock` 对 ImageLoad 下发 `blockModuleLoad` 会把随机化 temp 路径永久占槽（64 槽只加不减）。是否要加「路径含 temp 随机段就不持久化」的护栏。注：批 3 把三条 temp DLL 侧载规则降为 Ask 后，烧槽的主要触发源已经没了，但机制本身仍在。
- （批 4 新增）`hardDangerTokens` 里的 `downloadstring` / `downloadfile` / `reflection.assembly` 单独出现即撤销全部信任档，使决策 8/9 的降级可能在规则之外被重新拦回来。详见第 6 节批 4 条目。

---

## 五、施工批次（每批做完**停下来**给用户看 diff，等确认再下一批）

- **批 0**：先只读 `cpp/shared/src/engine/TrustPolicy.cpp` 里 `systemDirs()` 与 `strongPublishers()` 两个函数（用 grep 定位，别整份读），确认 `\windows\servicing\`、`\windows\winsxs\`、`\windows\system32\` 是否都能让 `isStronglyTrusted` 通过。若 WinSxS / servicing 不在名单里，则决策 1 的 `.exemptOs()` 救不了 TiWorker/TrustedInstaller —— 此时改为把 A1 的 7 条降为 Ask，并把这个偏差记进第 6 节。
- **批 1**：决策 1、2、3（三处加 `.exemptOs()`）+ 决策 4。改 `Rules02_Persistence.cpp`、`Rules03_DefenseEvasion.cpp`。
- **批 2**：决策 5、17。改 `Rules05_Impact.cpp`、`Rules04_CredentialAccess.cpp`。
- **批 3**：决策 6、7。改 `Rules07_Injection.cpp`。
- **批 4**：决策 8、9、10、12。改 `Rules06_Execution.cpp`、`Rules07_Injection.cpp`。
- **批 5**：决策 11、13。改 `Rules02_Persistence.cpp`、`Rules04_CredentialAccess.cpp`。
- **批 6**：决策 14、15、16（B 级批量降级）。改 `Rules03`、`Rules04`、`Rules05`、`Rules08`。
- **批 7**：验证（见第 7 节）。

每批的动作固定三步：① 只读要改的那几十行；② 用 `str_replace` 精确改；③ 报告「改了哪几条、Block→Ask 各几条、理由一句话」，然后停。

---

## 六、偏差记录（新会话发现与本文不符时写在这里）

- **批 0（2026-09-29）· 决策 1 的前提只成立一半**
  - `TrustPolicy.cpp:96-99` `systemDirs()` = `\windows\system32\` `\windows\syswow64\` `\windows\winsxs\`，**没有 `\windows\servicing\`**；`:22-25` `strongPublishers()` = Microsoft Corporation / Microsoft Windows / Microsoft Windows Publisher。
  - `containsDir`（`:178-186`）是「盘符 + 目录」锚定前缀：TiWorker.exe（`\Windows\WinSxS\…servicingstack…\`）能过目录条件，TrustedInstaller.exe（`\Windows\servicing\`）过不了。
  - 按第 5 节，这触发了「A1 降 Ask」回退。但回退有检出代价：`Worker.cpp:507-508` 的 Ask→Allow 降级只看签名健康，**不排除 LOLBin/脚本宿主**。提权 cmd 里 `copy cmd.exe sethc.exe` 是标准粘滞键手法，主体是微软签名的 cmd.exe，在 Ask 下会被静默放行。另外全规则集里 `sethc` 等 7 个名字只出现在 kAccessibility 这一组，没有命令行规则兜底。
  - 决策 1 本身也有残留（与上面选哪个无关）：`lolBinsAndHosts()`（`:107-115`）只有 15 个名字（reg/regedit/regini/powershell/pwsh/cmd/wscript/cscript/mshta/rundll32/regsvr32/sc/wmic/cmstp/fodhelper），**不含 xcopy/robocopy/esentutl/replace/expand/extrac32 这类微软签名的复制工具**。加 exemptOs 后用它们替换 sethc.exe 会被豁免（前提是命令行与父子链检查也放过），而现状下它们是被拦的。该名单只被 `isLolBinOrScriptHost` → `isTrustedOsComponent` 使用，往里补名字只会收窄 exemptOs 豁免。
  - **用户已选 ②**（2026-09-29）：维持决策 1 的 exemptOs + Block+hard，在 `systemDirs()` 补 `\windows\servicing\`，并把 6 个复制/解包工具补进 `lolBinsAndHosts()`。即批 1 实际改了 3 个文件（多出 `TrustPolicy.cpp`），**超出"只改 Rules0X"的原定范围**，后续批次仍只改规则文件。
  - 补 `lolBinsAndHosts()` 的副作用已核实为零：该名单唯一消费者是 `isLolBinOrScriptHost` → `isTrustedOsComponent`（`RuleEngine.cpp:742` 处只服务于 exemptOs 规则）；`InjectionAnalyzer.cpp:68` 的 `injectorIsTrustedOsComponent` 是另一套独立实现，不读这张表。改动前已有的 exemptOs 规则**全是 RegistryWrite**（Rules02 的 Policies\Explorer\Run、IFEO\Debugger、IFEO\GlobalFlag、Winlogon 4 条、Windows\Load、Windows\Run；Rules03 的 Defender 组策略），复制工具不写注册表，故不受影响。
  - `certutil` / `bitsadmin` 未加入名单：其滥用形态（`-decode`、`urlcache`）已在 `hardDangerTokens`（`:120-131`）里，命中即撤信任档，`isStronglyTrusted` 提前返回，走不到豁免。

- **批 7（2026-09-29）· 第 7 节的验证步骤有三处与实际不符，已换等效做法**
  1. `--dump-rules` **不在 `bulwark_service.exe` 上**，而在测试工具 `bulwark_snapshot` 上（`cpp/tests/SnapshotTool.cpp:1849`）。正确命令：先 `cmake --build cpp\build --target bulwark_snapshot --config Release`，再 `cpp\build\tests\Release\bulwark_snapshot.exe --dump-rules <out.json>`。**运行前必须把 Qt bin 加进 PATH**（`C:\Qt\6.8.3\msvc2022_64\bin`），否则报 0xC0000135 缺 DLL。
  2. 同一个工具还有 `--check-ruleset`，**直接做 id 冲突检查并打印总条数**，比手工比对清单可靠。结果：`内置规则 950 条，唯一 id 950 个 OK`（exit 0）。
  3. **基线文件全部过期，第 7 节的 diff 做不了**：`rules_now.txt` 667 行、`rules_before.txt` 676 行，而当前是 950 条 —— 差 283 条，是本次治理之外的其它工作产生的，不能用来对照。**git 也用不了**：仓库报 `dubious ownership`（`.git` 属另一个 SID），修它要改 git 全局配置，已按约定不动。
  - 替代做法：新写了 `.kiro/tmp/verify_batch.py`，直接拿 `--dump-rules` 的 JSON 逐条核对批 1~6 的每一项意图（动作、hardOverride、exemptOs、requireUnsigned、以及该删的是否真没了、该保留的是否还在），共 130 余项断言，**全部通过**（exit 0）。新基线留在 `.kiro/tmp/rules_after.json` / `rules_after.txt`，**后续会话请以这两个为基线，不要再用 rules_now.txt**。
  - 额外跑了 `verdict_snapshot` 回归（`--verify cpp/tests/data/corpus.json cpp/tests/data/golden.json`）：**38 条用例 0 条不一致**，exit 0，golden.json 不需要更新。**但要注意这说明语料没覆盖本次改动的规则** —— 它证明了「没有回归」，没有正面证明降级生效。
  - 第 7 节第 3 条的第三项（服务启动日志无新增「拒绝加载不安全的 Allow 规则」）**没有实跑服务**。替代证据：全量 950 条里 Allow 规则 15 条，本次六批改动一条 Allow 都没碰，`isUnsafeAllowRule` 的输入未变。
  - 规则总数 950。净减 5 条这一结论**是按源码改动推算 + 逐条确认「该删的已不在导出里」得到的**，不是与改动前的条数直接相减（没有可用的改动前基线）。

- **批 6（2026-09-29）· 实际改了 6 个文件，不是第 5 节写的 4 个**
  - 第 5 节批 6 写「改 Rules03、Rules04、Rules05、Rules08」，但 B 级清单里有两条不在这 4 个文件里：`*certutil*decode*` 在 `Rules06_Execution.cpp:125`，`*queueuserapc*` 在 `Rules07_Injection.cpp:191`。批 6 因此覆盖 Rules03/04/05/06/07/08。
  - 决策 16 逐条落地情况（全部 Block+hard → Ask，共 11 条）：`*etweventwrite*`、`*etweventunregister*`、`*queueuserapc*`（三条同一个病根：拿 Win32 API 名匹配命令行，真攻击在内存里改函数入口、不经命令行，所以既拦不住又会误命中调试/教学脚本）；`*fltmc*unload*`、`*fltmc*detach*`（minifilter 开发调试的标准动作，本产品自己的驱动就是 minifilter）；`*bcdedit*safeboot*`（`/deletevalue safeboot` 是退出安全模式，同样命中）；`*disable-computerrestore*`（同语义的两条注册表规则本来就只 Ask，命令行这条却是 Block，按弱的统一）；`*physicaldrive0*`（原注释只考虑了"写目标盘"，漏了"给整机做镜像要读 0 号盘"）；`*certutil*decode*`（无 PowerShell 环境里现成的 base64 解码器）；`*ntds.dit*`（只有文件名没有动作词，域控备份/巡检脚本都会带；带动作词的 `*ntdsutil*ifm*` / `*esentutl*ntds*` 保持 Block+hard 不动）；`*chisel*`（也是 Scala 写的 RTL 硬件描述 DSL 的名字）。
  - `kSecServices` 按决策**保持 Block**，已在 Rules03 文件头补记残留成因。补充一条决策文档没写的理由：这组若降 Ask，签名主体会被 `Worker.cpp:505-512` 的「信任已签名主体」降级为放行，等于对签名攻击者彻底失效 —— 所以这里不能用降级的办法解，只能靠让共存判定穿透 cmd/powershell（要动 TrustPolicy，不在本次范围）。

- **批 5（2026-09-29）· 决策 11 的排除方式，与决策 13 的一处已知漏网**
  - `dropDirFragments()`（`RulesCommon.cpp:38-46`）共 6 项：`\appdata\local\temp\` `\windows\temp\` `\users\public\` `\programdata\` `\$recycle.bin\` `\perflogs\`。决策 11 只要求 schtasks 那一组排除 `\programdata\`，所以是在 Rules02 的那个循环里 `if (dir == ...) continue;`，**没有动共享表** —— 它还有 5 个调用点（Rules06 curl 下载 / Rules06 脚本宿主运行脚本 / Rules07 远程线程注入 / Rules07 加载驱动 / Rules07 投放 .sys），那几处的口径不在本次范围内。
  - 决策 13 的尾随空格有一个已知漏网形态：`reg save "HKLM\SAM" out.hiv`（加引号）因为蜂巢名后面是引号而不再命中三条 kHive 规则。紧邻的 `*reg*save*.hiv*` 覆盖了绝大多数这类写法，只有「加引号 + 输出文件不用 .hiv 扩展名」的组合才会真漏。已写进代码注释，**未补新模式**（补形态超出决策范围）。

- **批 4（2026-09-29）· 决策 8/9/10 降级后仍有规则之外的残留路径（未核实，需用户定夺）**
  - `TrustPolicy.cpp:120-131` 的 `hardDangerTokens()` 里包含 `downloadstring`、`downloadfile`、`frombase64string`、`reflection.assembly`、`-enc`、`-encodedcommand`。命中**任一**即撤销主体的全部信任档（`hasDangerousCommandLineOrLolbinAbuse` → `isStronglyTrusted` / `isHealthySigned` / `isCleanSigned` 全部返回空）。
  - 也就是说：把规则从 Block 降到 Ask，只解决了「规则这条路上的拦截」。Chocolatey 的一行安装命令含 `downloadstring`、`[Reflection.Assembly]::LoadWithPartialName` 含 `reflection.assembly`、`Get-Content -Enc UTF8` 含 `-enc`，**这些仍会让 powershell 掉出信任档**，之后是否被 ThreatDetector / 启发式路径重新判成拦截，本次**没有追踪，属未核实**。
  - 第 3 节 A8/A9/A10 的误拦场景描述是按「规则命中」写的，若实测仍被拦，根因可能在 `hardDangerTokens` 而不在规则。**建议作为批 7 之后的独立议题**：`downloadstring` / `downloadfile` / `reflection.assembly` 这三个词单独出现是否还配得上「硬危险」定级（注释里已写明 `bypass` 当年正是因为同样的理由从硬名单里挪走的）。
  - 批 4 另外做了一处**决策之外的小改动**：`kPsCombo` / `kPsComboLabel` 两张平行表原来靠写死的 `i < 21` 遍历，本批删了 2 个条目必须改这个数字；改成由 `sizeof` 推导并加了 `static_assert` 校验两表等长。理由是写死的数字在增删条目时会静默错位，把模式配上别人的标签 —— 备注错了，派生出的 id 也就错了。如不认可可以改回字面量 19。

- **批 3（2026-09-29）· kByovd 实际是 27 条，不是第三节写的 26 条**
  - 逐个核对：原 `kByovd` 有 27 个具名 `.sys`。决策 7 的 A 组名单（17 个）+ B 组名单（10 个）恰好 = 27，**无遗漏、无重复、无多余**，所以拆组不需要额外判断。
  - A 组 17 条：`rtcore64` `dbutil_2_3` `dbutildrv2` `aswarpot` `procexp152` `truesight` `mhyprot2` `mhyprot3` `zamguard64` `zam64` `kprocesshacker` `nvflash` `speedfan` `winio64` `winring0x64` `amifldrv64` `atszio`。B 组 10 条：`iqvw64e` `iqvw64` `gdrv` `gdrv2` `viragt64` `elrawdsk` `asrdrv101` `piddrv64` `echo_driver` `pcdsrvc`。
  - A 组降 Ask 不会被「签名主体降级放行」吃掉，已核实链路：`DriverEventSource.cpp:994-998` 对内核驱动加载（`ActorPid==0`）把 `actorPath` 置为伪串「内核(驱动加载)」；它不是真实文件，`Worker.cpp:855-858` 的占位符短路只认 `PID ` 前缀所以不走那条分支，但后续 `collectForensics` 对不存在的路径验不出签名，`actorSigned` 仍为假 → `Worker.cpp:507-508` 的 Ask→Allow 不触发 → 仍然弹窗。
  - B 组的备注、target、action、hard 一字未改，**这 10 条 id 不变**。

- **批 2（2026-09-29）· 更正第 7 节对 id 派生口径的描述**
  - 本文原先写「id 由『备注 + 全部匹配条件』派生」，**不完整**。实际见 `DefaultRules.cpp:72-96` `stableIdFor`：参与 hash 的字段依次是 note、actorPath、actorPattern、targetPattern、commandLinePattern、parentPattern、type、**action**、**requireUnsigned**、**requireSigned**、**hardOverride**、**exemptTrustedOsComponent**、actorHashes。
  - 也就是说 **Block→Ask、加 `.hard()`/去 `.hard()`、加 `.exemptOs()`、加 `.unsignedOnly()` 都会改 id**。本次治理几乎每条被碰过的规则 id 都会变。批 1 的报告里曾说「这些改动不参与 id 派生」，那句是错的。
  - **但 id 变动无后果**，已核实：`main.cpp:608-616` 每次启动都用 `DefaultRules::build()` 重建内置规则，并把持久化库里备注以 `builtInTag()` 开头的旧副本**整批丢弃**（按备注前缀，不按 id），只保留用户/信任/情报规则。所以既不会新旧并存（旧的 Block+hard 不会残留下来压过新的 Ask），也不存在按内置 id 保存的用户状态被孤立的问题。
  - 对第 7 节验证的影响：清单 diff 里被碰过的规则会表现为「旧 id 一行消失 + 新 id 一行出现」，**不能只看行数**，要按备注文本配对比较。真正需要盯的仍是「有没有两条规则撞同一个 id」。

---

## 七、验证方式

1. 编译：只需构建 shared 库即可暴露语法错误（规则是纯数据构造，无运行时依赖）。
2. 规则集自检：`bulwark_service.exe --dump-rules` 导出 JSON，再跑
   `python .kiro/tmp/list_rules.py <导出的json> <输出txt>` 生成一行一条的可读清单，与 `.kiro/tmp/rules_now.txt` 做 diff。
   基线文件已存在：`.kiro/tmp/rules_before.json` / `rules_now.json` / `rules_now.txt`。
3. 必须确认三件事：
   - 规则条数变化与决策一致（有增删的只有 A7 拆组、A8 改写、A10 删除、A11/C 级删表项）；
   - **没有 id 冲突** —— id 由「备注 + 全部匹配条件」派生 UUIDv5，撞 id 会让后者静默顶掉前者。按名单展开的规则组必须把区分词拼进备注（见 `RuleDsl.h` 的 `Segment::add` 注释）；
   - 服务启动日志里**没有新增** `[RuleEngine] 拒绝加载不安全的 Allow 规则`。
4. 本次改动**不碰** Allow 规则，所以 `isUnsafeAllowRule` 那道闸不受影响。

## 八、进度

- [x] 批 0 核实 systemDirs/strongPublishers（结论见第 6 节；决策 1 待用户选 ①/②/③）
- [x] 批 1（决策 1-4）· 已编译通过（`cmake --build cpp\build --target bulwark_shared --config Release`，三个 .obj 均已重编），规则集自检留到批 7
- [x] 批 2（决策 5、17）· 已编译通过（Rules04/Rules05 均重编）
- [x] 批 3（决策 6、7）· 已编译通过（Rules07 重编）
- [x] 批 4（决策 8、9、10、12）· 已编译通过（Rules06/Rules07 重编，static_assert 通过）
- [x] 批 5（决策 11、13）· 已编译通过（按 .obj 时间戳核实 Rules02/Rules04 均已重编）
- [x] 批 6（决策 14、15、16）· 已编译通过（exit 0，Rules03/04/05/06/07/08 六个文件重编）
- [x] 批 7 验证 · `verify_batch.py`=0（130+ 项意图断言全过）、`--check-ruleset`=0（950 条/950 id）、`verdict_snapshot`=0（38 用例 0 不一致）；基线换成 `.kiro/tmp/rules_after.json`
- [x] 已提交（2026-09-29，由 architecture-rewrite 会话代提交，本地 `main`，未推送）：`c142146` rules: cut false positives in the built-in rules, keep detection —— 本线的 8 个文件 + `CHANGELOG.md`（规则数 950、`[未发布]` 补一条「变更 · 内置规则误拦截治理」）。提交前按「将要提交的那棵树」在临时目录重新编译：ctest 3/3、`--check-ruleset` 950/950、`--dump-rules` 与 `.kiro/tmp/rules_after.json` 逐条一致。**之后再改规则请另起提交**；`Rules07` 接下来还会被 architecture-rewrite 的 ImageLoad 签名修复改注释（见 `architecture-rewrite/progress.md` 第 6 步 6b）。
- [x] 单独议题：ImageLoad 的 FileNoLoad 持久化护栏 —— **2026-09-30 已处理**（另起一线做的，未提交，见下）

---

## 九、klids.sys 误报 + FileNoLoad 失效（2026-09-30，未提交）

起因：内置规则「从可写目录 `\programdata\` 加载内核驱动」拦下了卡巴斯基的 `klids.sys`。

### 9.1 两处根因（都已实测确认，不是推断）

1. **规则不看签名。** 段 7.4 那两组 `.sys` 规则原来是无条件 `Block + hardOverride`。
   `hardOverride` 在 `ruleTier` 里排第一，**高于管线第 ② 步的「已安装安全软件共存放行」**，所以
   共存那一层根本轮不到 —— 一个带 `AO Kaspersky Lab` 有效签名的驱动被当成 BYOVD。
   而 `unsignedOnly()` 在这里救不了：ImageLoad 的 `actorSigned` 是**宿主**的签名，内核模块加载
   时 `actorPath` 是伪串「内核(驱动加载)」，`actorSigned` 恒假（本文第 6 节批 3 已核实过这条链路）。
2. **FileNoLoad 名单一条都没生效过。** `Worker::enforceBlock` 把**带盘符**的完整路径下发给驱动，
   而驱动按「去盘符、大小写不敏感的子串」比对 `FLT_FILE_NAME_NORMALIZED`（`\Device\HarddiskVolumeN\…`），
   带盘符的条目永远不是那个串的子串。旁边的 `blacklistExec` 早就做了去盘符（`Worker.cpp:1167-1173`），
   这里漏了。**现场证据**：`HKLM\SYSTEM\CurrentControlSet\Services\Bulwark\Policy\FileNoLoad`
   当时 3 条，全带 `C:\` 前缀、全是死条目，却各占了 64 槽之一并跨重启续留。
3. **附带发现：对 `.sys` 下发 FileNoLoad 本身不可能有效。** 驱动映像是内核自己
   （`MmLoadSystemImage`）打开的，`Data->RequestorMode == KernelMode`，而 `BlwPreCreate` 第一句
   就对 KernelMode 放行。所以 klids.sys 那条既拦不住加载、也永远不会被匹配到。
   （静态阅读 `FileMonitor.c` / `ImageMonitor.c`，未在真实内核里下断点验证。）

### 9.2 改法

- `SecurityEvent` 新增 `targetSigned` / `targetSignatureMismatch`（**被加载模块自身**的签名），
  `toJson`/`fromJson` 加键，旧报文缺键 = 未签名，判定与加入前逐字节相同。
  这两个字段正是 `architecture-rewrite` 第 6 步 6b design B 要加的那一对，6b 可以直接用。
- `DefenseRule` 新增 `requireTargetUnsigned` / `requireTargetSigned`，DSL 是
  `targetUnsignedOnly()` / `targetSignedOnly()`。**`stableIdFor` 只在置位时追加 `|TU` / `|TS`**，
  刻意不写成「恒定追加一位 0/1」—— 那会让全部内置规则 id 一起变，而它们的判别性内容一个字节都没动。
- `Worker::enrich` 新增第 3.9 步：对 ImageLoad 求目标文件的签名（`collectForensics(includeCert=false)`，
  按文件身份缓存），并记一条 0 分 Info 证据「模块签名：…」供弹窗展示。放在第 4 步主体取证**之前**，
  因为内核模块加载的 actorPath 不是真实文件。
- 段 7.4 两组通用 `.sys` 规则按模块签名分档，**7 条 → 14 条**：验不出可信签名 → 保持
  `Block + hard`；有可信签名 → `Ask`。三组具名 BYOVD 名单**一字未改**（本来就刻意不看签名）。
- `Worker::enforceBlock` 的 FileNoLoad 下发：去盘符 + 子串 < 6 字符放弃（与 `blacklistExec` 同门槛）；
  `actorPid <= 0`（内核驱动加载）**直接不下发**，只记一行 info 说明原因。

### 9.3 验证

- 临时构建（`cpp/` + `Bulwark.Driver/`，VS 2022 + Qt 6.8.3 Release）**0 错误 0 警告**（252 s）。
- `ctest` **3/3**：`verdict_snapshot` 38 例 0 不一致（golden 未动）、`builtin_ruleset_ids`
  **977 条 / 977 id OK**、`attackchain_regression` 41/41。
  （977 = 已提交的 950 + 工作区里 av-engine 那条线未提交的 20 条 + 本次 7 条。）
- 合成 8 例裁决（临时语料，**没有**碰仓库里的 corpus/golden）：
  签名 klids.sys → **Ask**；未签名 / 签名失配 → **Block+hard**；`rtcore64.sys`（A 组，签名）→ Ask；
  `amsdk.sys`（银狐组，签名）→ **Block+hard**（具名硬拦仍压过通用 Ask 档，排序正确）；
  Downloads 下签名 / 未签名 → Ask / Block；回归哨兵「签名宿主 + Temp 未签名 DLL」→ 仍 Allow，
  即段 7.3 那三条**仍按宿主签名判**，没被顺手改掉。

### 9.4 留给别人的事

- **段 7.3 的 `unsignedOnly()` 仍在判宿主**，签名壳 + Temp 未签名 DLL 的白加黑不命中。这是已知漏检，
  归 `architecture-rewrite` 6b（改它会动裁决快照，要连 golden 重录一起做）。已在 `Rules07` 段头写明。
- **静默模式**下 Ask 会因 `hasThreatIndicator && risk >= 50` 升级为 Block（合成用例里签名 klids.sys
  的 risk 是 55、带硬指标）。这是既有的静默模式语义，对所有 Ask 规则一视同仁，本次没动。
- 注册表里那 3 条带盘符的死条目仍在（它们匹配不上任何东西，但占着槽位）。`reconcileKernelBlocksAfterTrust`
  会把注册表条目原样重推，所以不会自己变好，也不会开始生效。要清得手工改注册表值。
- **部署后 FileNoLoad 才第一次真正生效**：此前所有条目都是死的。也就是说凡是走到 `enforceBlock`
  的用户态模块加载误判，从此会真的被内核拒绝映射。部署前值得先把误报面收干净。
