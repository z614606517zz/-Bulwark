# 杀毒引擎 · 新会话交接文档

> 上一个会话已完成全量调研，结论全部内联在本文，**新会话不要重复调研**。
> 本文的产出目标是**方案文档 + 推荐路线**；写代码前先把方案交用户确认。
> 相关文档：`.kiro/specs/architecture-rewrite/{requirements,design,tasks}.md`、`.kiro/steering/product.md`。

---

## 一、任务

用户原话：「这个软件什么都不缺 就缺一个杀毒引擎 你有什么方案吗」。

需要给出 2~3 条可选路线（自研静态引擎 / 复用 ClamAV 或 YARA / 端侧 ML 推理 / 云侧为主的组合），
逐条说明覆盖能力、误报风险、工程量、与现有架构的契合度，给出推荐路线与分阶段落地计划。
按架构重写文档的编号体系挂接（S1 / S4 / S9 / S11、R3 / R5 / R10、A1.4）。

---

## 二、客户端现状（已核实）

**结论：没有任何杀毒引擎。** 今天的检出全部依赖「SHA-256 + 云信誉 + 行为规则」，
没有一行代码看文件内容做定性。

### 哈希
- `ProcessInspector::tryComputeSha256` —— 大写十六进制、256MB 上限、FactCache 键 = `小写路径|大小|mtime`、
  8192×2 两代（hot 降级到 cold，不清空）。
- `QuarantineManager::tryComputeSha256` —— 小写、无上限、无缓存。
- `Worker::enrich` 调 `collectForensics` 一次 stat 取齐 签名 / 发布者 / SHA-256 / 证书画像 / 体积。

### 本地已知恶意集
| 载体 | 上限 / TTL | 来源 |
|---|---|---|
| `DefenseRule.actorHashes` | 随规则集 | `onReputationMalicious` 注入的「[情报-恶意]」哈希规则；ThreatFoxFeed（每 12h，单次上限 500，TTL 7 天）；VT 行为画像的释放物哈希 |
| `reputation.jsonl` | 50000 条 | 恶意永久 / 干净 7 天 / 可疑 1 天 / 未收录短期负缓存 |
| `confirmedMaliciousHashes_`（内存） | **无上限** | 启动时从所有 Block 规则的 actorHashes 灌入 |
| `memVtCachedMalicious_`（内存） | 1024，FIFO 淘汰 128 | 内存防护 VT 验证 |
| `vt_scan_history.json` | 确定性结论永久 / Unknown 24h | 扫描去重 |

### 云链路
`Worker::runVtScan`（4 线程 / 队列 64）分级：
本地缓存 → 中央服务器 `queryServerOnly` → 本机 VT 查哈希 → 其他源聚合
（MalwareBazaar / OTX / 微步 / MetaDefender / HybridAnalysis）→ VT 上传整文件（32MB 直传 / 650MB 大文件 URL）
→ 回传服务器。
所有 HTTP 经 `QProcess` 拉 `curl.exe`。热路径同步查走有界预算 `InlineReputationBudgetMs=800`
（单槽 inline lane，超时放手，迟到结论转补偿处置）。

### 唯一的文件内容静态分析
`cpp/ui/src/ai/StaticFeatureExtractor.cpp`：
- 只读前 12MB（可配，clamp 到 64KB~256MB）。
- PE 头：MZ / `PE\0\0`、machine、节区数、Characteristics DLL 位、Subsystem、DataDirectory[14] 判 .NET。
- 逐节 Shannon 熵，> 7.2 计 `packedSections`（「加壳」只有熵这一个判据）。
- 45 个危险 API 名做**裸字节子串搜索**（不走导入表）→ 能力标签。
- ASCII + UTF-16LE 可打印串（≥5 字符，上限 60000 段）+ URL 正则 + IPv4 正则 + 43 个可疑 token。
- 按扩展名取脚本片段（ps1/bat/vbs/js/hta/lnk… 共 18 种），无反混淆。

**仅编入 `bulwark_ui`，唯一消费者是 `AiScanner.cpp:346-349` 拼 LLM prompt**，
结论从不进 `ThreatDetector` / `RuleEngine`。

**不存在**：导入表 / 导出表 / 资源 / overlay / Rich 头 / imphash、YARA、字节特征、ssdeep / TLSH、
Office 宏 OLE/OOXML、压缩包、PDF、LNK 解析、AMSI provider 或 consumer、MOTW / Zone.Identifier、
U 盘、全盘 / 定时扫描、服务端按需扫描 API。
（UI 侧只有云信誉页最多 10 个文件查哈希、AI 研判页手动送 LLM，后者结果不回服务。）

`ScriptAnalyzer` 只分析**命令行里抠出来的**脚本文本（`extractScriptFromCommandLine`），
从不打开脚本文件；≥60 分算硬指标。

### 触发点
都在 `Worker::onEvent` 里、`engine_->evaluate` 之后，`userTrusted` 或已判 Block 则跳过：
- `maybeScanDoubleClick` —— 父 = explorer / 未签名+首见+可疑目录 / 5 分钟内被写过（`kRecentDropWindowSecs=300`）。
- `maybeScanInstallerPackage` —— 双击 msiexec，从命令行抠 `.msi`。
- `maybeScanDroppedInstaller` —— FileWrite 落盘 `.msi/.msp/.exe/.scr` 到 Downloads/Desktop/Public/Temp 等，
  合成 PID=0 事件 → 命中只隔离文件，不杀写入方。
- `maybeVerifyMemoryInjection` —— 限流 4/小时。
- AI 灰区会诊 —— 需显式开 `aiGrayZoneConsultEnabled`。
- `sweepLoop` —— 每 60s 枚举 PID 算哈希，比对已确认恶意 + 信誉缓存；哈希缓存键 `路径+大小+mtime`，上限 2048。
- `ThreatRemediator::locateDroppedFilesByHash` —— 判恶意后按哈希在落地区找释放物（深度 5 / 最多看 20 万 / 最多算 8000 个哈希）。

### 定性与处置
- `ThreatDetector` 里 `hard=true` 即置 `hasThreatIndicator`；
  `RuleEngine` 第 10 步：`hasThreatIndicator ? (riskScore>=80 ? Block : Ask)`。
- **带实据的云端恶意只给 60 分 → 单独只到 Ask**，需再凑 20 分才 Block。
  确定性拦截的正确做法是注入 `hardOverride` 的 `actorHashes` 规则。
- 异步链路统一入口 `confirmReputationMaliciousAsync` → `onReputationMalicious`：
  `abortIfTrustedNow` → 记哈希 → 分数抬到 90 → `killMalicious` → `blacklistExec` → `recordEvent`
  → 注入情报规则 → `remediate` → 审计。`handleSweptMalicious` 是轻量版（不拉画像、不注规则）。
- 新引擎命中最自然的表达：构造
  `FileReputation{source=<引擎名>, verdict=Malicious, threatLabel=<签名名>, querySucceeded=true}`
  再走这条链（`threatLabel` 非空即算「有实据」）。

### 隔离区
`%ProgramData%\Bulwark\quarantine\<GUID>`，64KB 流式**单字节 XOR 0x5A**（混淆，非加密）+ `index.json`。
金库文件不含元数据，索引一丢就永久还原不了（已修过一次「空表覆盖」事故）。
有内核 `QUARANTINE_READ` / `FORCE_DELETE` 兜底读写被占用文件。

---

## 三、内核现状（已核实，对「落盘即扫」至关重要）

- `Driver.c:116` 注册的 minifilter 回调只有三个 pre：
  `IRP_MJ_CREATE` / `IRP_MJ_SET_INFORMATION` / `IRP_MJ_WRITE`。
  **没有 `IRP_MJ_CLEANUP`、没有 `ACQUIRE_FOR_SECTION_SYNCHRONIZATION`、没有任何 post 回调、没有 stream context**
  → 今天不存在「文件写完关闭即扫」这个经典触发点，要做得新增回调。
- `HashScan.c`：内核**自带纯 C SHA-256**（不依赖 BCrypt，算错也只是不处置，fail-safe）。
  进程创建回调只把 PID 入环（`BLW_HASH_QUEUE_CAP=128`，自旋锁，满即丢）；
  独立系统线程在 PASSIVE_LEVEL 读文件算哈希，比对 `KnownBadHashes[BLW_MAX_HASHES=1024][32]`
  （FAST_MUTEX + 线性匹配），命中即 ban PID + 结束进程。
  默认惰性：`ProcessMonitor.c:631` `if (g_Blw.KnownBadCount > 0)` 才入队。
- **重大缺口**：这份内核哈希集**只能**由注册表 `Policy\KnownBadSha256`（REG_MULTI_SZ）在驱动加载时载入
  （`Policy.c:311`）。`cpp/` 下**没有任何 `BLW_CMD_*` 能在运行时下发哈希**，
  唯一写入者是 `cpp\scripts\set-baseline-policy.ps1`。
  即：内核已经有一个可用的哈希查杀引擎，而用户态服务喂不进去。
- `FileExecBlock` / `FileNoLoad`：`BLW_MAX_PROTECTED=64` 定长数组 + 路径**子串**匹配，
  内核自己写回注册表持久化，协议只有「追加 / 整表清空」。
  `blacklistExec` 会去盘符、要求子串 ≥6 字符、已加白则跳过。
- 零同步 IPC 铁律：`FltSendMessage` 一律 0 超时 + 后台发送线程 + 预分配环形缓冲。
  `BLW_VERDICT_REPLY` 结构存在（握手校验其 size），但**进程创建是 fire-and-forget，无法事前询问**。
- `BLW_EVENT_MESSAGE` 定长 `WCHAR ImagePath[520]` + `TargetPath[520]`（会截断）。
  事件类型 0..15，含 `BlwEventFileModify=13`（观测型改名 / 删除标记）；
  `IRP_MJ_WRITE` 按 `WriteSampleCounter` 做 1/32 采样。
- pre-create 用 `FLT_FILE_NAME_NORMALIZED` 是刻意的（防短名 / 挂载点绕过，注释有完整理由）；
  `executeIntent = DesiredAccess & FILE_EXECUTE`。
- 驱动只有测试签名，用户需 `bcdedit /set testsigning on`。故「无驱动（ETW）模式」必须是一等公民。

---

## 四、服务端与 ml 资产（已核实，可复用）

- `server/bulwark-intel/app.py`（7296 行 stdlib `ThreadingHTTPServer` + `sqlite3`）：
  `/v1/engine/manifest` 与 `/v1/engine/patterns` 下发攻击链组合表
  （表 `engine_markers` / `engine_patterns` / `engine_versions`），由 `engine_build.py` 每日离线构建 ——
  **无模型、纯计数**，只用 VT 报告里的 `sigma_analysis_results`（medium 以上）与人工同义表，
  `USE_MITRE=False`，`GENERIC_DF_RATIO=0.45`。当前**无内容签名**（design.md S11 要补 Ed25519）。
- 白语料 `benign_reports`：滚动 20000 行，`slim_benign_report` 现已保留
  `type_tag / type_description / type_extension / magic / size / imphash / vhash / tlsh / ssdeep / signature_info`。
  `app.py:871` 的注释提到一个「云查引擎 `scan_engine.py` / `BEN_MIN_CORPUS`」做家族相似度判定 ——
  **该文件在仓库里不存在**，只在注释里被引用（线上独有或已丢失，需向用户确认）。
- `server/bulwark-broker/broker.py`：`reputation` 表已有 `imphash / ssdeep / tlsh / vhash` 列 + `idx_imphash` 索引，
  提供 `GET /similar/imphash/<32hex>` 返回 `none/weak/strong` 软信号 + 家族分布
  （刻意只作软信号，因为 imphash 会被正常打包器共享）。
  `ember_pkg/features.py` 是完整 EMBER v2 实现，但写的是 LIEF 0.9 老 API，现代 LIEF 跑不起来。
- `ml/train/` 现存可用管线：
  - `pe_features.py` —— `PEFeatureExtractor`，用 pefile 重写 EMBER 分块，`SCHEMA_VERSION=1`，
    刻意排除 文件名/路径、签名者名、`has_signature`、`TimeDateStamp`（每条都是实测过的标签泄漏方向，
    尤其 `has_signature` 方向是反的：系统文件走 .cat 目录签名、恶意侧反而自带被盗嵌入证书）。
  - `extract_features.py` / `build_features.py` / `train.py` —— LightGBM，**按 family 分组切分**防同族泄漏，
    按目标 FPR 挑阈值，导出 `.txt` 原生格式「便于 C++ 侧加载」+ 阈值 / 维度元数据。
  - `infer_probe.py`、`behavior_runtime_features.py`、`vt_*.py`。
  - `requirements.txt`：numpy / scikit-learn / lightgbm / pandas / pyarrow / pefile / tqdm / pyzipper（Python 3.12）。
  - `ml/tools/`：`Collect-MalwareBazaar.ps1`、`Collect-BenignPE.ps1`、`Collect-CleanWim.ps1`、
    `Download-BenignWinget.ps1`、`harvest_{benign,malicious}.py`、`gen_intel_rules.py` 等。
- **注意**：`requirements.md` 的非目标写着「不做 ML 模型推理，`ml/` 是历史离线实验目录，当前产品无推理路径」。
  若方案要动 ML，必须明确这是对该非目标的修订，并让用户确认。

---

## 五、构建事实（加第三方库要用）

- CMake ≥ 3.21 / C++20 / Qt **6.8.3** msvc2022_64 / 生成器 VS 17 2022。
- 全局编译 `/W4 /permissive- /guard:cf /utf-8`；
  链接 `/guard:cf /CETCOMPAT /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA`；`/Qspectre` 可选（默认 OFF）；无 `/WX`。
- **无 vcpkg、无 CMakePresets、无 conan、无 FetchContent**；
  唯一 vendored 第三方是 `cpp/third_party/krabsetw`（header-only, MIT）。
  无 yara / libyara、无 OpenSSL、无 sqlite、无 zlib / libarchive。
  加密全走 `QCryptographicHash` + Windows CryptoAPI / WinTrust。
- `bulwark_shared` 是 STATIC 且只链 `Qt6::Core`（引擎不做网络 I/O，**要保持**）。
- ctest 三条：`verdict_snapshot`（比对 `tests/data/golden.json`）、`builtin_ruleset_ids`、
  `attackchain_regression`，均 `QT_HASH_SEED=0`。
- **任何改动评分的做法都会改 `golden.json`，必须逐条审差异**（对应 A1.4「无不明原因差异」）。

---

## 六、方案里必须回答的问题

1. **引擎跑在哪个进程**？design.md S9 规划过 `bulwark_scan`（受限令牌 + 无网络，专解析不可信 PE 与脚本），
   D3 当时倾向「先 core + cloud，scan 延后」。杀毒引擎是否让 `bulwark_scan` 提前？
   R3 要求 SYSTEM 进程不解析不可信文件 —— 把 PE 解析放进 SYSTEM 服务是直接违反 R3 的。
2. **触发模型**：如何实现 design.md S4 的「落盘即扫 · 执行即拦」？
   需要内核补哪个回调（CLEANUP？post-create？section sync？），还是先在用户态靠现有 FileWrite 遥测兜？
   注意零同步 IPC 铁律不能破，且 `IRP_MJ_WRITE` 是 1/32 采样。
3. **命中如何落地**：注入 `hardOverride` 哈希规则（用户态），还是补一条 `BLW_CMD` 把哈希推进内核
   `KnownBadHashes`（能让「服务没跑 / 重启后」也拦，但 1024 条上限 + 线性匹配 + 只能整表清空）。
   `FileExecBlock` 那套「钉死后用户加白无效」的坑不能再犯一次 ——
   参见 `blacklistExec` 与 `reconcileKernelBlocksAfterTrust` 的注释。
4. **特征库分发**：走 `UpdateService` 那条已经做扎实的链（URL 白名单 + size + SHA-256 +
   Authenticode 钉死签名者指纹 + 拒降级 + 逐文件 park/rollback），还是 S11 的
   `manifest + payload + Ed25519` 新通道？
5. **误报闸门**：新引擎结论按「硬指标」还是「软信号」计？
   本项目铁律是软信号绝不单独定罪，且代码里有大量实测误报修复现场 ——
   Electron 大包被当「文件膨胀」误拦 35 次、`crashpad_handler` 因 `minidump` 一个词被拦 4 次、
   Kiro（Amazon 有效签名）因两个统计信号凑到硬指标被静默模式永久钉进内核禁运。
   方案必须说明如何不重演。
6. **语料与样本安全**：A0.4 明令样本只在隔离环境处理
   （2026-07 CLEARWATER 勒索事故永久丢了 35 个未提交源文件）。
   签名 / 模型的生产管线放哪、谁跑、怎么隔离。

---

## 七、待确认 / 未核实

- `scan_engine.py` 是否只存在于线上服务器（仓库里没有，只在 `app.py` 注释里被引用）。
- `ml/data` 的实际体量与 `ml/.venv` 是否可用（上一会话的统计命令被 PowerShell 吞了，未取到数）。
- `requirements.md` 第 3 节 D1~D7 七个待定决策**全部还是「待填」**，
  其中 D2（引擎去 Qt）、D3（进程拆分范围）、D4（EV 证书 / 驱动签名）直接影响本方案，需要先问用户。
- 工作区有 227 处未提交改动，且用户当前打开着 `%TEMP%\bw_prep\build05_errs.txt`（像是在排构建错误）——
  动代码前先确认构建是绿的，并提醒用户阶段 0 的提交与异地备份（A0.1）。

---

## 八、交付要求

先给方案（对比 + 推荐 + 分阶段 + 风险），**不要直接改代码**。
方案获批后再落地，落地时遵守：读代码再改、改完跑 CMake 构建 + 三条 ctest、
评分变动逐条解释 `golden.json` 差异、不新增未钉版本的依赖。回复用中文。
