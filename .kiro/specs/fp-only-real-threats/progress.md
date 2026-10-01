# 只拦真威胁：拆掉「软信号单独定罪」的五条链路（2026-10-01，未提交）

用户原话：「真威胁才拦截不要乱拦截 有些没有签名的软件也不代表是恶意的 真正有恶意行为的在拦截」。

产品原则（`.kiro/steering/product.md`）本来就写着「软信号（未签名 / 可疑路径 / 本机首见 / 新证书）
绝不单独触发拦截或弹窗」。本轮做的事就是把代码改回符合这句话 —— 它在五处被违反了，而且每一处
都已经在这台机器的 `audit` / `service.log` 里产出了真实误拦。

---

## 一、怎么定位的（证据，不是推断）

全部来自本机实际记录，可复查：

| 来源 | 关键结论 |
|---|---|
| `C:\ProgramData\Bulwark\audit\audit-2026093*.jsonl` + `audit-20261001*.jsonl` | 按 `(action, source, type)` 聚合全部 Block/Ask 及其 `reasons`。最大一类是 **7434 条** `Ask / Heuristic / FileDelete`，全是卡巴斯基 `avp.exe`；理由只有「无可信数字签名」+「数字签名校验失败」+「批量改写」 |
| `C:\ProgramData\Bulwark\service.log(.1)` | 逐条还原处置链：`静默模式:确定性高危升级为拦截` → `封禁主体` → `冻结` → `断子` → `内核结束` → `隔离` → `拒绝执行 ACE` |
| `C:\ProgramData\Bulwark\history\events.jsonl` | 拿到被拦事件的完整 `matchedRuleNote` 与 `hasThreatIndicator` |
| `C:\ProgramData\Bulwark\quarantine\index.json` | 确认被隔离的文件与原因 |

实测的六个误拦现场（每一个都没有任何行为证据）：

1. `C:\Users\1\Downloads\决战千年260944.exe`（78MB 自解压游戏安装包）→ 风险 100 拦截 + 隔离 +
   内核禁运 + 跨重启拒绝执行 ACE。理由全文：无可信数字签名 / 异常大的可执行文件(78MB) /
   未签名程序从可疑目录运行 / 命令行熵 4.6 / msedge 首次派生该子进程。**五条全是软信号。**
2. `qishui_Music_X6485152.exe`（222MB NSIS 安装包）→ 同上。
3. `%TEMP%\is-NTWO3EF9ID.tmp\innosetup-6.7.3.tmp`（winget 装的**官方** Inno Setup）→
   一次写 116 个文件 → 「批量改写 + 扩展名同化 .tmp」→ 静默模式升级为拦截 → 结束进程树。
4. 卡巴斯基 `avp.exe` / `avpsus.exe` → 7434 次询问。根因是「内嵌了签名但验不过」被当成篡改 ——
   而它验不过的原因是**自保护不让别人读自己的映像**。
5. Microsoft 的 `WidgetService.exe`（WindowsApps，目录签名验不出来）→ 12 个文件即被拦。
6. `四方接码客户端.exe` → 被结束进程 + 隔离 + 跨重启拒绝执行 ACE。它自己的证据链是
   `hasThreatIndicator=false`、风险 56、云端**未收录**；被拦的唯一理由是「和一个确认恶意的文件
   同一次被 360zip 解包到同一个目录」。

另外两处本轮**之前**就已修好、不重复改：`InjectionAnalyzer::analyzeImageLoad` 对
「进程加载自己的主映像」的豁免（`samePathCI`），以及它改读 `targetSigned` 而不是宿主签名。

---

## 二、改了什么（五处，含理由与代价）

### C1 · 签名校验失败 ≠ 篡改
`signatureMismatch` 的真实含义只是「内嵌了签名、本机验不过」，它把三件事混成一个答案：
① 文件被改过；② 本机没有签发者的根证书；③ 文件读不出来。只有 ① 是恶意证据。
原来一律 45 分**硬指标**，文案还写「疑似篡改或盗用证书」。

- `ProcessInspector.h/.cpp`：`ForensicFacts` 新增 `signatureDigestMismatch`，由新的
  `computeSignatureDigestMismatch()` 只认 `TRUST_E_BAD_DIGEST`；新建 `g_digestMismatchCache`，
  **仅在「无可信签名且内嵌了签名」时求值**，不额外 stat、不让正常文件多验一次签。
- `SecurityEvent`：新增 `signatureTampered`（+ toJson/fromJson；旧报文缺键 = false，
  这正是正确的保守方向）。
- `Worker::enrich`：回填。
- `ThreatDetector` 1b：真篡改 → 45 分硬（文案改成「数字签名摘要不符:文件在签名之后被改过」）；
  仅校验不过 → 10 分软 Info，并在理由里写明「摘要并未不符」。
- **信任侧一个字没动**：`TrustPolicy` 仍然读 `signatureMismatch`，验不过就不给信任。
  「不给信任」和「判它恶意」是两件事，这次分开的就是这两件事。
- 检出不丢：盗用证书另有 `certRevoked` / `isAbusedSigner` / `signedAfterCertExpiry` 三条硬判据。

### C2 · 文件膨胀永不单独定罪
`ThreatDetector` 1c。上一轮已经把「安装目录里的大文件」降成软信号，但投递型可写目录
（Temp / Downloads / Desktop / AppData / ProgramData / Public）里的仍是硬指标 —— 那个区分不成立，
**用户下载的安装包本来就落在那里**。15(未签名) + 25(可疑目录) + 65(体积) = 100 → 直接 Block。
现在分数照加、`hard` 一律 false。检出不丢：膨胀只是包装，载荷要起作用总得做点什么（注入 /
持久化 / 关杀软 / 侧载 / C2 / 落地可执行体），另有哈希信誉、云扫描、兜底扫描三条与体积无关的路。

### C3 · 「批量改写 / 扩展名同化」不因未签名就变硬指标
两处：

- `RuleEngine` 第 4 步 `rm.hardSignal == false` 分支：原来「主体没有可信签名」就置
  `hasThreatIndicator` 并 `return Ask`。**那是用软信号给软信号升格** —— 与 DGA、外联速率两处
  已经修掉的 `!e.actorSigned` 互证完全同类。现在不置硬指标、不提前返回，只在已有硬指标时记一条
  `Corroboration`。勒索的三条真判据都在另一支（已知勒索扩展名 ×3 / 勒索说明文件 / 蜜罐诱饵），
  诱饵那条在更前面无条件 Block，连签名抑制都不受。
- `RansomwareBehaviorMonitor`：新增 `toolchainExts()`，「扩展名同化」排除安装器/解压器/编译器/
  同步工具的中间扩展名（tmp temp part crdownload download partial log etl dmp bak old ~tmp
  pyc pyo obj o pdb ilk lastbuildstate tlog json db db-journal ldb sqlite-journal journal
  cache idx pack manifest res）。刻意**不含 `.lock`**：它在 `knownEncryptedExts()` 里、
  且那一支排在前面门槛更低，两张表重叠会让代码自相矛盾。

### C4 · 静默模式 Ask→Block 升级需要互证
`Worker::onEvent`。原条件 `hasThreatIndicator && riskScore >= Suspicious(50)` 有两个问题：
① `hasThreatIndicator` 是布尔或运算，「一处判据 + 一堆软信号凑到 50」与「三个维度都指向恶意」
在这条闸上完全等价；② 它比引擎自己的拦截线**更松** —— `RuleEngine` 第 10 步要 >= 80 才 Block，
50~79 引擎明确给的是 Ask（「该问用户」）。静默模式的语义是「不要为决策打扰我」，不该顺手把
引擎拿不准的那一档改成结束进程树 + 隔离 + 足迹清理 + 连带处置发起方。

现在：`risk >= HighRisk(80)` **或** `>= 2 个不同来源的硬指标`（新增 `hardEvidenceSourceCount()`，
按 `Evidence::source` 去重 —— 不去重的话一个分析器写三四行理由就能自己凑出「2 条」）。
够 50 分但没凑到互证的那一档**必须留一行 warning**：静默模式不弹窗，不说出来就等于无声地
改了处置强度而没人知道。

### C5 · 污点「同批兄弟」降为询问
`Worker::taintDroppedFiles`。原来 `direct`（被拦主体亲手写出来的载荷）和 `batches`
（第三方 dropper —— 压缩软件 / 浏览器 / 安装器 —— 同一批写出来的兄弟文件）**共用同一个 grade**。
于是一个压缩包里混进一份恶意样本，同目录其它文件全部拿到 `Block + hardOverride`。

- `TaintResult` 新增 `byAssociation`；`consider(c, byAssociation)`。
- `direct` 与「未签名 dropper 自身」→ `byAssociation=false`（载荷是从它肚子里出来的，
  这一点由它自己的行为作证）；`batches` 里的兄弟文件 → `true`。
- 档位**逐条**决定：`hard = (grade == Block) && !byAssociation`。关联档 → `Ask` + 7 天，
  note 里带「(同批解包的关联文件)」。
- 日志按两档分开报（「硬拦 N 个」/「询问 M 个」），不再用一个按整批 grade 算出来的 scope。
- 静默模式下关联档会按静默语义放行并留痕 —— 用户既然选了「不要问我」，对一条「拿不准」的
  关联就不该替他做销毁性处置。

---

## 三、验证

### 构建
停服务 + `fltmc unload Bulwark` 后（内核基线把 `cmd.exe` 钉在 `FileExecBlock` 里，minifilter
加载期间 MSBuild 用不了 cmd.exe，编不过 MSB6003）：

```powershell
cmake --build "D:\新建文件夹 (3)\cpp\build" --target bulwark_shared bulwark_service bulwark_snapshot `
      --config Release --parallel 4
```
`BUILD_EXIT=0`，0 错 0 警。六个被改的编译单元**全部重编**（按 `.obj` 对 `.cpp`/`.h` 的
时间戳逐对核实，`stale=0`）：ThreatDetector / RuleEngine / RansomwareBehaviorMonitor /
SecurityEvent / Worker / ProcessInspector。

> 注：`cmake --build ... -- -m:4` 会被 PowerShell 拆成 `-m: 4` 而报 MSB1031，用 `--parallel 4`。

### 回归（最强的一条证据）
**在重录 golden 之前**跑 `ctest`：4/4 通过，其中 `verdict_snapshot` 用的是改动前的 39 条黄金裁决。
也就是说 C1~C3 **一条既有裁决都没改变**。这条顺序很重要 —— 先重录再跑测试什么都证明不了。

### 新增语料（把本轮意图钉进测试套件）
`cpp/tests/data/corpus.json` 39 → **62** 条，新增 23 条（`fp-` 误拦回归 / `det-` 检出哨兵），
golden 用 `--record` 重录。随后 `ctest` 4/4；另外用一次性脚本对新 golden 逐条断言本轮意图
（断言脚本是一次性的，已删；**结论已固化进 golden，由 `verdict_snapshot` 持续守着**）：

| 用例 | 结果 |
|---|---|
| `fp-bloat-unsigned-installer-in-downloads`（78MB @Downloads） | **Allow** hard=false risk=70 |
| `fp-bloat-huge-unsigned-installer-on-desktop`（222MB @Desktop） | **Allow** hard=false risk=100 |
| `det-bloat-plus-real-behavior-still-blocked`（同样超大 + 删除卷影） | **Block** hard=true risk=100 |
| `fp-signature-unverifiable-not-tampered` | **Allow** hard=false risk=25 |
| `det-signature-digest-mismatch-still-hard` | **Block** hard=true risk=85 |
| `fp-installer-burst-tmp-00..13`（未签名解包器连写 14 个 .tmp） | 14 条**全部 Allow** hard=false（最后一拍 risk 74） |
| `det-ransomware-known-ext-02/03`（.locked ×3、×4） | **Block** hard=true risk=80 |
| 既有哨兵：诱饵触碰 / 删除卷影 / lsass 远程线程 / 证书吊销 | 仍 **Block** |
| 既有哨兵：健康签名 / 未签名纯软信号 | 仍 **Allow** |

注意 `risk=100` 仍然 **Allow** —— 这正是本轮的要点：**分数高不等于有行为证据**。

### 部署与线上观察
`cpp\build\service\Release\bulwark_service.exe`（sha256 前 16 位 `fa3c3e830b3318e1`）已覆盖
`cpp\dist\bulwark_service.exe`，旧件备份在 `.kiro\tmp\bulwark_service.prefp.bak`
（`8be45aa248507f2a`）。服务起回来、`fltmc load Bulwark` 成功、UI 拉起后 minifilter 7 个实例在位。

线上立刻看到改动生效（同一批样本、同样的事件）：
- `放行 RegistryWrite … qishui_Music_X6485152.exe (风险 100)` —— 改动前这是 Block；
- `放行 FileWrite TG20260903BI.exe -> …\VCRUNTIME140.dll (风险 86)`；
- `放行 ImageLoad …\is-UBKPO.tmp\Proton.tmp -> 自己 (风险 40)`（自身主映像豁免）；
- C4 新增的那行「硬指标 N 个来源 + 风险」已出现 1 次。

---

## 三·五、旧逻辑钉下的持久处置已回溯撤销（2026-10-01 09:27，用户确认后执行）

代码改完只管「以后」。旧逻辑已经钉进磁盘和注册表的东西不会自己好，所以按同一条原则做了一次
回溯清理。**判据只有一条：内核持久名单与硬拦只配给「哈希已被确认恶意」的东西**，靠启发式分数或
「同批解包」进来的一律撤销。

实查结果触目：**全部 114 条污点规则、57 个路径里，一个哈希都没被确认恶意过。** 这 75 条
`Block + hardOverride` 全是从 `lclcache.exe` 那**一次**确认（中央服务器 21/75，trojan.mint/phil）
按「同批解包」传染出来的。

### 做了什么（备份在 `.kiro/tmp/`，可整体回退）

| 对象 | 改动前 | 改动后 | 判据 |
|---|---|---|---|
| 内核 `FileExecBlock` | 7 条 | **3 条** | 只留 3 份 `LCLCACHE.EXE`（唯一有情报凭据的）。撤销 `决战千年260944.EXE`（用户投诉的那个游戏安装包）、`UAINE_X6418151.EXE`、`WPS.EXE`、`TSETUP-X64.7.1.2.EXE` |
| 内核 `FileNoLoad` | 23 条 | **0 条** | 逐条核过，0 条是确认恶意的模块。里面钉着本项目自己的 `BULWARK_SNAPSHOT/SERVICE/UI.EXE`、`BULWARK-SETUP-1.0.3.TMP`×4、`CDBAR_TEST.EXE`、`TEST_7Z/7ZCON/IXP.EXE`、6 个 PyInstaller 运行时 `_MEI317042\*.PYD`（ctypes/bz2/lzma/hashlib/cryptography-rust/cffi）、4 个 Inno Setup 解包 stub，以及 3 条带盘符的死条目 |
| 污点规则 | 114 条（75 Block+hard / 39 Ask） | **89 条，Block=0 / Ask=89** | 删 25 条（本项目构建产物、测试探针、`_shfoldr.dll`、`InstallOptions.dll` —— 无歧义误报）；52 条 `Block+hard → Ask`、有效期按新代码口径从 30 天改为 7 天、note 里标注「回溯降级:仅「同批解包」关联,无针对该文件的证据」；原本就是 Ask 的 37 条未动 |
| 跨重启 DENY ACE | 2 个 | **0 个** | `tsetup-x64.7.1.2.exe`、`新建文件夹 (8)\wcxxrphz.exe`，`icacls /remove:d Everyone`，复核 DENY 已消失 |
| `[情报-恶意]` 哈希硬拦 | 1 条 | **1 条，没动** | 那条是真凭据（`68820341f896…`），刻意保留 |

`FileNoLoad` 为什么敢整表清空：① 一条都不是确认恶意；② 它**只加不减**，留着只会继续长出误报；
③ `.sys` 条目在这份名单上**本来就不可能生效**（驱动映像由内核自己 `MmLoadSystemImage` 打开，
`BlwPreCreate` 第一句就对 `KernelMode` 放行）—— `KLIDS.SYS` 占了一年槽位却从未拦住任何东西。

### 怎么做到的 / 复核

改注册表必须先 `fltmc unload Bulwark`：`RegHardBlock` 里有 `\SERVICES\BULWARK`，驱动在就写不进去。
顺序是「停服务 → 等 STOPPED → 卸驱动 → 确认 `fltmc filters` 里没有 Bulwark → 才动手」，
驱动没卸干净就中止、不做任何修改。

恢复后复核（完整输出见本目录 `cleanup-20261001.log` 的「恢复后复核」段）：
- 驱动已加载、服务 Running、UI 在跑 —— 防护完整；
- `FileExecBlock` = 3 条、`FileNoLoad` = 0 条，**没有被服务重新推回去**（担心的是
  `reconcileKernelBlocksAfterTrust` 的「CLEAR + 重下发保留项」会复活条目，实测没有）；
- `已加载 1098 条规则`，污点 **Block=0 / Ask=89**，日志里没有「拒绝加载不安全的 Allow 规则」；
- 重启后至今 **0 条拦截 / 0 条询问 / 0 条 error**；
- 新代码的三行文案都已在真实事件上出现过：`静默模式:硬指标只有` ×2（C4 放过并留痕）、
  `同批解包的关联文件` ×5（C5 新建的关联档）、`个来源 + 风险` ×8（C4 升级路径）。

### 备份与回退

都放在**本 spec 目录**里（刻意不留在 `.kiro/tmp`，那里迟早被当临时文件清掉）：

| 文件 | 内容 |
|---|---|
| `policy-20261001-092704.reg` | 改动前的整个 `\Services\Bulwark\Policy` 键（`reg import` 即可整体回退） |
| `rules-20261001-092704.json.bak` | 改动前的 `rules.json`（893546 字节，1123 条） |
| `bulwark_service.prefp.bak` | 改动前的服务二进制（`8be45aa2…`，2767872 字节） |
| `cleanup-20261001.log` | 本次清理的完整执行实录 + 恢复后复核输出 |

回退要同样先停服务 + 卸驱动，否则写不进去。

### 刻意没动：隔离区

隔离区 15 个文件，其中 **14 个是「仅关联/启发式」**，只有 `lclcache.exe` 有真凭据：
`四方接码客户端.exe`、`wcxxrphz.exe`、`omega.exe`、`Proton.exe`、`qishui_Music_X6485152.exe`、
`InstallOptions.dll` ×2、`QISHUIl_setbp_X6436339.exe`、`TG20260903BI.exe`、`uaine_X6418151.exe`、
`wps.exe`、`最新版2345看图王_KTWa4.exe`、`xenofix.exe`、`pigggggg.exe`。

**没有自动还原**。前面几项改的都是「策略」（规则 / 名单 / ACL），错了改回来没有副作用；
把二进制放回桌面是「数据落位」，而这批文件来自一个混着真样本的目录，风险和决定权都该归用户。
还原入口在界面的「隔离区」页面，逐个还原。

---

## 四、没做 / 做不到 / 留给下一棒

1. **信标检测没动。** `sing-box.exe`（用户自己装的代理）因「间隔 ≈300s、CV=0.00」落进低抖动硬指标
   档被 Block。`kHardMaxPeriodSec=600` 把 5 分钟一次的订阅刷新也圈了进来，而 Cobalt Strike 默认
   60s、真 C2 普遍**故意加抖动**。收紧上限是个凭感觉定的数字，没有实测依据就不动 —— 留作独立议题。
4. **C4 / C5 不在裁决快照的覆盖范围内**：它们在 `Worker`（服务层），而 `verdict_snapshot` 只跑
   `RuleEngine`。这两项是按代码审查 + 线上日志确认的，没有自动化断言。要覆盖得给 Worker 建
   第二套 harness，不在本轮范围。
5. **`isTrustedSecurityProduct` 为什么没放行卡巴斯基，没查。** 它本该在管线第 2 步就共存放行
   `avp.exe`，实际没有（否则不会有 7434 条询问）。C1+C3 已经让这些事件变成 Allow，所以症状没了，
   但**根因没定位** —— 它只看 `e.actorPath`，而那批事件的 actorPath 确实是 `avp.exe`，所以更可能
   是安装检测（注册表/安装目录枚举）没认出 KES 14.1 的布局。留作独立议题。
6. **未提交。** 工作区里还混着 nodriver-hardening 那条线「服务 `0xC0000374` 堆破坏定位清楚前
   不要提交」的要求，以及 driver-hardening 的驱动改动。本轮只碰了这 10 个文件：

```
cpp/shared/include/bulwark/models/SecurityEvent.h
cpp/shared/src/models/SecurityEvent.cpp
cpp/shared/src/engine/ThreatDetector.cpp
cpp/shared/src/engine/RuleEngine.cpp
cpp/shared/src/engine/RansomwareBehaviorMonitor.cpp
cpp/service/include/bulwark/service/monitoring/ProcessInspector.h
cpp/service/src/monitoring/ProcessInspector.cpp
cpp/service/include/bulwark/service/Worker.h
cpp/service/src/Worker.cpp
cpp/tests/data/corpus.json + cpp/tests/data/golden.json
```

---

## 五、环境事实（下一棒会踩的坑）

- **`grepSearch` 工具在本工作区（中文路径）返回 0 命中**，连 `evaluateInternal` 这种纯 ASCII
  标识符也搜不到。替代件：`.kiro/tmp/fp_grep.py`（`python fp_grep.py <out.txt> <regex> <path...> [-C n]`）。
- `str_replace` 对含 `——` `〔〕` 的长中文注释块匹配会失败，用短的**代码**锚点。
- `execute_pwsh` 的 `cwd` 参数不可靠（会漂到上一次的子目录），且长时间前台命令的 stdout 会丢。
  可靠做法：命令里一律用绝对路径，输出写文件再 `read_file`；长任务用 `control_pwsh_process`。
- `service.log` 是 UTF-8；`Tee-Object` / 默认重定向会写出 UTF-16，用 `Out-File -Encoding utf8`。
- 运行 `bulwark_snapshot.exe` 前要把 `C:\Qt\6.8.3\msvc2022_64\bin` 加进 PATH，否则 0xC0000135。
- **服务是自启动的，还会被 UI 按 `protectionFollowsUi` 拉起**：换 `cpp\dist\bulwark_service.exe`
  必须先 `sc stop` 并等到 STOPPED，否则运行中的进程占着文件，`copy` 报 `PermissionError(13)`。
- `protectionFollowsUi=true` + UI 没开 = 服务启动即**待机**，不加载驱动、不提供任何防护。
  改完别忘了把 UI 拉起来，否则机器是裸的。
