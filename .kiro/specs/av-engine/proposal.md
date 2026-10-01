# 杀毒引擎方案（待确认）

> 状态：**方案稿，未获批，没有改任何代码**。依据 `handoff.md`（上一会话调研结论）+ 本轮补核（§1.3）。
> 编号沿用 `architecture-rewrite/`：R* / A* / C* / D* 见 requirements，S* 见 design，任务号见 tasks。
> 本文新增编号：阶段 **E0–E5**，待决策 **V1–V8**。获批后把 E 系列拆进 `tasks.md` 对应阶段。

---

## 0. 一页结论

- **推荐路线一**：YARA-X 做匹配引擎 + 签名 IOC 哈希集，跑在新增的沙箱进程 `bulwark_scan`，结论走现有异步处置链落地。ClamAV 不进客户端；ML 不在本期（非目标保持不动）。
- **S4「落盘即扫 · 执行即拦」分两步兑现**：落盘即扫在用户态做（USN 日志「写完关闭」触发，驱动 / ETW 两种模式一致）；执行即拦随驱动 v2，section-sync 回调只查本地快照，零同步 IPC。
- **误报闸门**：只有指名家族、过了良性语料 + 误报回归集 + 观察期的规则才算硬指标；其余一律软信号，不处置、不入分。引擎命中不走 `blacklistExec` 路径钉死。
- **评分不动**：E1 / E2 不改 `ThreatDetector` / `RuleEngine`，`golden.json` 预期零差异。
- **开工前提**：A0.1（227 条改动仍未提交）、A0.4（隔离样本环境）、§7 的 8 个决策。

---

## 1. 定位、边界与本轮补核

### 1.1 引擎补什么

今天的检出 = 哈希 + 云信誉 + 行为规则。缺的是：**离线时、云端没收录时、样本还没运行时**，没有任何基于文件内容的定性。引擎补三件事：

1. 离线、执行前的已知家族与 IOC 定性；
2. 抗「改一个字节换哈希」的家族级识别；
3. 给内核执行拦截（S4）提供提前量。

### 1.2 不做什么，以及对预期的校正

- **不追商业引擎检出率。** 单人维护的规则库做不到，也不该拿它衡量。价值在于和行为链、处置链咬合，以及对本地高发家族（如仿冒安装包类）做定向覆盖。
- **不注册成系统杀毒。** 进 Windows 安全中心需要微软 MVI 准入（含 ELAM 驱动），本项目连驱动正式签名都还没有（D4）。Defender 会一直开着，按共存设计（§6 #7）。
- **「什么都不缺」要打个折。** 规格里有比引擎更急的洞：AI 清理以管理员执行模型生成的脚本（2.4.1）；攻击链组合表无签名且随包 `DryRun: false`（2.5.1）。本方案 E2 的签名通道会顺手关掉 2.5.1；2.4.1 建议别排在引擎后面。

### 1.3 本轮补核（交接文档第七节）

| 项 | 结论 |
|---|---|
| `ml/data` | **0 个文件**（只做 stat，未打开任何文件）；脚本用法示例里的 `D:\samples` 不存在 |
| `ml/.venv` | 可用。Python **3.13.14**（`requirements.txt` 写的是 3.12）；numpy 2.5.2 / scikit-learn 1.9.0 / lightgbm 4.7.0 / pandas 3.0.5 / pyarrow 25.0.1 / pefile 2024.8.26 / pyzipper 0.4.0 均可导入 |
| `scan_engine.py` | 工作区（含忽略文件）没有；`git log --all` 全部历史没有 → 只可能在线上服务器，需你确认 |
| `build05_errs.txt` | 第一次临时构建的摘要（导出树缺 `Bulwark.Driver/Protocol.h`）。补导出后重跑的 `build05_errs2.txt` 0 错误、ctest 3/3 通过，与 progress.md 1.6 一致 → 不是悬而未决的构建错误 |
| git | HEAD `a60397d`，`status --porcelain` 仍是 227 条，A0.1 未完成 |
| 许可证 | 仓库根目录没有 LICENSE，README 也没声明 → 影响 GPL 组件能否用（路线二） |

---

## 2. 路线对比

| | 路线一：YARA-X + 签名 IOC（推荐） | 路线二：ClamAV 进程外集成 | 路线三：端侧 ML + 云相似度 |
|---|---|---|---|
| 覆盖 | 已知家族 / 工具（取决于规则质量）+ IOC 精确哈希；pe / dotnet / lnk 模块现成，msi / vba / olecf 是 1.20 新增的实验模块；无脱壳、无仿真 | 格式最广（压缩包 / OLE / PDF / HTML / 邮件，部分脱壳），签名量最大 | 未知 PE 泛化最好；脚本 / 文档 / LNK 不覆盖 |
| 未知新样本 | 弱 | 弱 | 强，但按铁律只能作软信号 |
| 误报可控性 | **高**：逐条分级、逐条过闸、可单条停用 | 中低：库归 Talos 维护，误报只能本地排除；PUA / 启发式类要关 | **低**：非典型良性（安装器、Electron、未签名开源工具、打包器）正是本项目反复踩过的误报面 |
| 端侧资源 | 规则包 MB～数十 MB（需实测），扫描进程可限 512MB | 重：官方文档称每日重载特征时内存峰值可达 2.4 GiB；2025-12 退役旧签名后 main≈80MB / daily≈22MB | 模型数 MB；特征提取 CPU 中等 |
| 许可 | YARA-X BSD-3；规则逐条看许可 | GPLv2：链接即需 GPL 化，进程外算不算「聚合」要法务意见；本仓库还没有 LICENSE | LightGBM MIT；自写树模型推理可零依赖 |
| 安全面 | Rust 解析器（内存安全语言），仍需沙箱；条件会 JIT，沙箱不能开 ACG | C 解析器，2026 年已连发多条解析器 CVE（ZIP 堆越界写、Aspack 重建溢出、PESpin 脱壳器、HTML DoS），必须沙箱 + 紧跟补丁 | 要自写 PE 特征解析器 = 新攻击面，放沙箱 |
| 构建 | + Rust 工具链（cargo-c 产出 `yara_x_capi.lib`），钉 tag + `Cargo.lock` | + Rust + OpenSSL / zlib / bzip2 / libxml2 / PCRE2 / json-c / libcurl 等，和「无 OpenSSL / zlib」现状冲突最大 | 无新构建依赖，或 + LightGBM C API |
| 首版工程量（粗估） | 4–6 人周（E1） | 3–5 人周接入；镜像、内存、误报是长期成本 | 6–10 人周（语料为 0 要重建；C++ 特征与 pefile 逐位对齐是主要风险） |
| 持续运营 | 规则维护（可从公开高质量集起步） | 镜像同步 + 本地排除表 | 定期重训 + 漂移监控 + 语料更新 |
| 架构契合 | S9 / R3（沙箱进程）、S11 / R5（签名包）、S0（两模式一致）、R10（不动评分） | R3 可满足；CVD 自带 Talos 签名；端侧体积和轻量定位冲突 | 必须**修订非目标**「不做 ML 模型推理」 |
| 结论 | **主干** | 不进客户端；可作服务端数据源（服务端自用不涉及分发） | 不在本期；E5 先做云侧分诊，端侧另议 |

**为什么没有单独的「纯自研」路线。** 自己写 PE / OLE / ZIP / LNK 解析器 + 匹配器，等于同时背上路线二的 CVE 面和路线一缺的规则生态。本方案里的自研只限于：调度、沙箱、IPC、结论映射、规则包流水线，以及用 Info 级规则产出文件事实（不写解析器）。

**为什么「云侧为主」只当补充。** 离线零覆盖；broker 的 `/similar/imphash` 本来就刻意只给软信号；`scan_engine.py` 不在仓库；服务端单体待 S13 拆分。放 E5。

**YARA-X 还是 libyara（V2）。** 2025-06 YARA-X 稳定后，YARA 4.x 官方进入维护模式，只修 bug 不加功能（最新 4.5.8，2026-07-28）。libyara 的好处：纯 C、MSVC 直编、扫描进程能开 ACG；代价：C 解析器，没有 msi / vba / olecf 模块。推荐 YARA-X；libyara 作「Rust 工具链进不了构建」时的退路，规则语法基本兼容，可切换。

---

## 3. 推荐架构（路线一）

### 3.1 进程与数据流

```text
[SYSTEM] bulwark_service（现） / bulwark_core（重写后）
  触发(§4.2) ──> ScanService：有界优先队列 · 去重缓存(FileId + 最后写入时间 + 包版本)
                 只做：打开文件 → 读入共享内存 / 复制只读句柄；算 SHA-256；验签规则包
                 不做：任何结构解析（R3）
                   │  继承的匿名管道（只给这一个子进程），长度前缀二进制帧
                   ▼
[LPAC 沙箱] bulwark_scan.exe  纯 C++20 + Win32 + YARA-X；无 Qt、无网络、无文件系统权限
                 反序列化规则包 → 扫描 → {status, matches[], facts[]}
                   │
                   ▼
  结论映射（纯函数，放 bulwark_shared，不链 YARA-X）
    Hard ─> E1/E2：FileReputation{source="bulwark-scan", …} → confirmReputationMaliciousAsync（带落地策略）
            E3 起：LateSignal → ActionExecutor
    Soft ─> 只记录 / UI 展示 / AI 会诊证据 / 提高云查优先级
    Info ─> 文件事实（安装器类型、Electron、.NET、overlay …）
```

不放 `bulwark_cloud`：那个进程有网络，「能联网 + 解析不可信文件」同处一个进程，被打穿就能直接外传。

### 3.2 引擎分层

| 层 | 内容 | 结论级别 |
|---|---|---|
| IOC 哈希 | 把现有 `reputation.jsonl` / ThreatFox / 已确认恶意统一成一个有界存储，用户态 O(1) 查 | 多源确认 = Hard |
| 家族规则 | YARA-X 规则；meta 带 `bw_grade` / `bw_family` / `bw_source` / `bw_license` / `bw_observe_until` | 过闸 = Hard，否则 Soft |
| 能力 / 启发规则 | 加壳、可疑 API 组合、混淆脚本、熵、体积 | **永远 ≤ Soft** |
| 事实规则 | NSIS / Inno / WiX / MSI / SFX、Electron、.NET、overlay 大小 | Info，只作上下文（例：大 overlay + 已知安装器格式 ≠「文件膨胀」） |

### 3.3 结论模型

- 状态四种：`Clean` / `Match` / `Partial`（超限或超时）/ `Failed`（崩溃）。**`Partial` 和 `Failed` 都是 Unknown，不是 Clean**（S1「取不到就是 Unknown」）。
- 缓存只存结论、不存信任；规则包升级即令缓存里的 Clean 失效，下次触发重扫。
- 处置前按哈希复核一次，防扫描与处置之间文件被调包。

---

## 4. 六个问题的回答

### 4.1 引擎跑在哪个进程（S9 / R3 / D3）

**提前上 `bulwark_scan`，修订 D3。** PE / LNK / MSI / 脚本解析放 SYSTEM 里直接违反 R3，而 YARA-X 的 pe 等模块本身就是解析器。所以引擎一上就要有 scan 进程。它只做「扫描」一件事，不牵动 core / cloud 拆分：E1 由现服务拉起，E3 起归 core 管。

- **令牌**：LPAC（零能力 → 天然无网络、无文件系统访问）。SYSTEM 派生 AppContainer 令牌的细节要先做原型；走不通就退到「受限令牌 + Untrusted 完整性 + 防火墙按程序阻断出站」。
- **Job**：内存上限（初值 512MB）、活动进程数 1、禁子进程、随父退出。
- **缓解策略**：禁 win32k 系统调用、CFG、严格句柄检查、禁远程 / 低标签映像加载。YARA-X 把条件编译成 WASM 再转机器码，**不能开 ACG**（选 libyara 则可以）。
- **输入**：文件由 SYSTEM 打开（共享读 / 写 / 删，不影响用户程序），读入共享内存或以只读句柄复制过去；规则包同样以只读内存交给它。沙箱自己打不开任何文件。
- **生命周期**：常驻，规则只加载一次；单文件超时（`yrx_scanner_set_timeout`）+ 外部看门狗；崩溃按退避重启，当次文件记 `Failed`。
- **代码归属**：`bulwark_scan` 纯 C++20 + Win32，D2 怎么定都不冲突。`bulwark_shared` 只加契约类型与结论映射，保持「只链 Qt6::Core、不做 I/O」。
- **附带**：`StaticFeatureExtractor` 今天在 UI 进程里解析不可信 PE（只喂 LLM 提示词），后续迁进 scan，UI 只收结果（S9「UI 只做展示」）。

### 4.2 触发模型（S4）

**落盘即扫：用户态，驱动 / ETW 两种模式一致（S0）**

- **E1**：复用现有触发点 `maybeScanDoubleClick` / `maybeScanInstallerPackage` / `maybeScanDroppedInstaller` / `sweepLoop`。本地引擎排在网络查询之前：命中 Hard 就不再整文件上传 VT（少传一次整文件，也是隐私收益）；Soft 命中反过来提高云查优先级。
- **E2**：新增 **USN 日志消费者**。每个 NTFS 卷 `FSCTL_READ_USN_JOURNAL`，`ReturnOnlyOnClose=1`，只取累计原因含 `DATA_OVERWRITE` / `DATA_EXTEND` / `FILE_CREATE` / `RENAME_NEW_NAME` 的关闭记录：
  - 语义就是「写完关闭」，且**不采样**（驱动写遥测是 1/32）；
  - 记录自带 `FileReferenceNumber`，直接满足 S3 的 FileId 缓存键；
  - 不需要驱动，也不碰零同步 IPC 铁律；
  - 过滤：先按记录里的文件名 / 扩展名粗筛，再按父目录 FileId 映射到用户可写区（Downloads / Desktop / Temp / Public / AppData …），最后按魔数（MZ、脚本、LNK、MSI / OLE、ZIP）入队；
  - 缺口：FAT / exFAT（U 盘）没有 USN → 卷到达时对根目录 `ReadDirectoryChangesW` + 执行时扫；日志回绕丢记录可由 `UsnJournalID` / USN 断档发现，发现即对落地区补扫一轮；
  - MOTW（`Zone.Identifier`）只作排队优先级，不作信号。
- **不选**：扩大 `IRP_MJ_WRITE` 采样（扫描只关心「关闭时改过没有」，不需要每次写）；ETW 文件关闭类事件做主触发（全系统文件 I/O 量级，CPU 待实测，只作无 USN 卷的备选）。

**执行即拦：内核，随驱动 v2（tasks 3.6）**

- 新增 `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` 预回调：创建可执行映像节时**只查本地快照**，FileId 命中即 `STATUS_ACCESS_DENIED`。
- 可选增强：对快照指定的用户可写路径里的新映像，在这里本地算一次 SHA-256 缓存进 stream context（任何写入即失效），命中哈希快照即拒。这把 `HashScan.c` 现在的「进程建好再杀」前移成「映射前拒绝」；代价是每个新文件首次执行多一次哈希，A3.3 实测后再定上限。
- 无 USN 的卷：stream handle context 记「本句柄写过」，`IRP_MJ_CLEANUP` 时经现有后台发送环 fire-and-forget 通知用户态去扫，合并去重。
- 未扫 / 未知一律放行 + 事后补偿；内核从不等用户态，零同步 IPC 铁律不破。
- ETW 模式没有这一层：靠「命中即隔离（文件没了就执行不了）」+ 事后结束，覆盖面报告如实写（S0）。

### 4.3 命中如何落地

三条原则：**绑内容不绑路径**（哈希 / FileId）；**用户态是唯一真相，内核只拿派生集合**；**内核不自行累加持久化状态**，持久化内容永远等于用户态最近一次整份下发的集合。第三条就是 `FileExecBlock` 坑的根因：`blacklistExec` 的注释写明了内核把名单写回注册表、协议没有删除单条，钉进去之后 UI 加白不生效。

**E1（纯用户态）**：Hard 结论构造 `FileReputation{source="bulwark-scan", verdict=Malicious, threatLabel="<家族>/<规则>", querySucceeded=true}`，走 `confirmReputationMaliciousAsync`。但**不新开第六条补偿路径**（2.2.3 已经五条），而是给 `onReputationMalicious` 加一个「落地策略」参数：

- 引擎来源一律跳过 `blacklistExec`（该函数今天在这条链上是无条件调用的，只受加白检查拦）；
- 引擎结论不写进 `reputation.jsonl`（那里的恶意结论是永久缓存），只进引擎自己的缓存，随包版本失效；
- `retainThreatIntel`（情报共享）对引擎来源默认不上送，免得把本地误报喂进中央库；家族规则命中注入的哈希规则，备注用「[引擎-恶意]」，不写「云端确认恶意」；
- 按证据强度分级处置（IOC 一行随 E2 的统一 IOC 存储生效）：

| 证据 | 动作 |
|---|---|
| IOC 精确哈希（多源确认） | 与云端恶意相同：结束 + 隔离 + 清持久化 + 注入 `[情报-恶意]` 哈希规则 |
| 家族规则 Hard | 结束 + 隔离文件本身（可还原）+ 注入哈希规则。清持久化、`applyRegHardening`（内核注册表硬拦）、释放物追查这些**扩散型动作**，等云端或用户确认后再做 |
| Soft | 不处置、不入分 |

**E2（加内核）**：v9 追加「追加已知恶意哈希」「清空已知恶意哈希」两条 `BLW_CMD`（与现有名单同样的追加 / 清空语义），用户态按「清空 → 逐条追加」整份重推。命令码追加、结构体尺寸不变，协议号保持 9。

- 持久化：落地时二选一，视 SelfGuard 对服务写 `Policy\KnownBadSha256` 的放行情况而定。用户态直接写该键（内核仍只在加载时读，`Policy.c:311`），或内核只镜像最近一次整份下发。两种都满足「加白 → 重算 → 整份重推」即撤销，服务没跑 / 重启后也拦。
- 入选：本机确认的 Hard 命中 + IOC 高置信子集，按最近命中排序截断到 1024（`BLW_MAX_HASHES`）。软信号永不进内核。
- 待核实：旧驱动收到未知命令码的行为（预期拒绝，用户态降级为纯用户态并记日志）；「清空 → 追加」之间的短暂空窗（S4 原子切换后消失）。驱动哪怕只加两条命令，也要走一轮 Verifier 冒烟。

**E4**：S4 策略快照（generation + 原子切换 + 删单条 = 推新快照）取代 1024 条线性表；FileId 条目与哈希条目同表，预建索引。

### 4.4 特征库分发（S11 / R5）

**结论**：内容走 S11 新通道，不塞进 `UpdateService`。但 E1 先不建新通道：内置规则包作为资源编进 `bulwark_scan.exe`，随 Authenticode 签名的二进制走现有 `UpdateService`（钉死签名者指纹、拒降级、逐文件回滚都现成，C3）。

内容为什么不走 `UpdateService`：

1. Authenticode 只护 PE。`manifest.json` 只有 version / published / notes / files[name,size,sha256]（2.5.6），本身无签名 → 非 PE 文件的完整性只剩 TLS + manifest 里的哈希，服务器一被攻破就失守（与 2.5.1 同类）；
2. 拒同版本 / 降级是按程序版本号判的，内容版本是另一条线；
3. 规则要日更，程序是月更。

它的传输纪律（URL 白名单、拒明文、size + SHA-256、park / rollback）抽成共用下载器复用。

**E2 的 S11 通道**：

- 格式 `manifest + payload + Ed25519`；私钥离线（§4.6）。
- core 先对原始字节验签、再解析 manifest（verify-then-parse）。payload（编译后规则）只在沙箱里反序列化，签过名也按不可信处理：YARA 4.5.8 有加载畸形编译规则触发断言崩溃的 CVE-2026-88341，YARA-X 1.19 修过反序列化不可信规则的未定义行为。
- 编译产物与引擎版本绑定：manifest 声明 `engine=yara-x 1.20.0`，不匹配不加载、保留上一份；内置包永远与引擎同版本，兜底。
- 版本只进不退；分批灰度；新规则默认观察期（只记录）；另发一份很小的「规则停用清单」做 kill-switch；验签失败保留上一份（R5）。
- 验签实现：据公开文档，CNG 没有 Ed25519 签名原语（curve25519 只用于密钥交换）。用 vendored **Monocypher 4.0.3**（2026-06-15 发布，修了 EdDSA 计时泄漏；BSD-2 / CC0 双许可）的 Ed25519 可选模块。备选 ECDSA P-256 走 CNG 原生、零新依赖（V4）。
- 顺手：攻击链组合表（`/v1/engine/patterns`）迁到同一通道，关掉 2.5.1。

### 4.5 误报闸门（C1 / R10 / A1.4）

**分级**：Hard（可处置）/ Soft（只加证据，永不单独处置）/ Info（事实）。Soft 不能靠叠加变成 Hard：S1 里 `kind` 与 `weight` 分开；E1 / E2 更干脆，Soft 根本不入分。

**Hard 准入（全部满足）**

1. 规则指名家族 / 工具。能力类、统计类（熵、体积、API 组合、单个字符串 token）永远 ≤ Soft。
2. 良性语料零命中：Windows 安装镜像文件、winget 常用安装包及安装后文件、主流开发工具链、国内常用软件；外加**误报回归集**，按事故命名，每条同时是 A1.5 的回放用例。
3. `safety_policy` 关键二进制零命中（S5；服务端拒发，tasks 4.5）。
4. 隔离环境的恶意验证集至少命中 1 个（防死规则）。
5. 慢规则剔除（`yrx_scanner_iter_slowest_rules` 画像）。
6. 先以 Soft 观察 ≥ 14 天，无误报再提级（S11 观察期）。

**运行期护栏**

- 有效签名且签名者在强信任名单：Hard 降为 Soft，除非规则显式针对被盗证书（带证书指纹条件）。
- 单规则熔断：本机单位时间内命中的不同文件数超阈值 → 该规则自动降为只记录并上报。
- 影响面上限：每分钟 / 每事件隔离数（S6），超限停手问用户。
- 用户信任（L2）永远压过引擎；引擎命中不进 `FileExecBlock`；内核集合随加白撤销。
- 静默模式下 Hard 只做可撤销动作（隔离，不删除）+ 通知。

**三起事故怎么不重演**

| 事故 | 挡住它的闸 |
|---|---|
| Electron 大包被当「文件膨胀」误拦 35 次 | 体积 / overlay 类永远 ≤ Soft；Info 规则识别安装器与 Electron 格式；进回归集 |
| `crashpad_handler` 因 `minidump` 一个词被拦 4 次 | 单 token 字符串规则 ≤ Soft；进回归集 |
| Kiro（有效签名）两个统计信号凑成硬指标，被静默模式钉进内核 | Soft 不叠加成 Hard；有效签名降级；不走 `FileExecBlock`；内核集合随加白撤销；静默模式只做可撤销动作 |

**golden.json**

- E1 / E2 不改 `ThreatDetector` / `RuleEngine`，`verdict_snapshot` 应零差异；出现差异按缺陷处理。
- E3 引擎结论并入 `Signal` 聚合时才会动分数，届时按 A1.4 逐条审。
- 引擎另建文件级语料与金标准。合成夹具在测试运行时生成，否则 Defender 会在开发机上把测试文件隔离掉。

### 4.6 语料与样本安全（A0.4）

**现状**：`ml/data` 为空、`D:\samples` 不存在 → 开发机现在没有语料。重建可以一开始就放隔离环境，没有迁移负担。

**三区分离，单向流动**

| 区 | 放什么 | 出口 |
|---|---|---|
| 样本区（隔离 VM 或独立机） | 恶意样本，一律 `infected` 密码 zip，不在宿主解开；拉样本脚本（`Collect-MalwareBazaar.ps1`、`harvest_malicious.py`、`datalake_probe.py`）只在这里跑（tasks 0.6） | 只出规则源码 + 检出率报告（文本） |
| 构建区（content-builder，S13） | 规则源码、良性语料 | 只出签名后的规则包 |
| 开发机 / CI | 代码、良性语料子集、编译后规则 | — |

- 样本区：不开共享文件夹 / 剪贴板 / 增强会话；网络只放行样本源与 VT；每次用完回滚快照。
- 私钥：Ed25519 私钥离线（硬件令牌或离线机），不进 CI、不进服务器。
- 规则源码：仓库是公开的（progress.md 4.3e）。自有 Hard 规则不进公开仓库，只发编译 + 签名后的包；规则文本含恶意特征串，会被 Defender 当威胁，落盘加密存放。
- 公开规则：从 YARA-Forge Core（官方说明已剔除高误报与拖慢扫描的规则）、ReversingLabs（官方称在 100 亿+ 二进制上持续测试）起步；每条保留来源与许可，按许可白名单入包。白名单由你拍板（必要时找法务），本文不做法律判断。

---

## 5. 分阶段落地

工程量是单人 + AI 辅助的粗估，不含等决策与驱动测试环境的时间。

### E0 · 前置（不写引擎代码，与架构阶段 0 并行）

- [ ] A0.1：progress.md 第 3 节的 10 个提交 + 推送或 `git bundle`（卡在身份 / 推送目标 / 脱敏三个决定）
- [ ] A0.4：搭样本区（§4.6）
- [ ] 良性语料 v1 + 误报回归集：`Collect-CleanWim.ps1` / `Download-BenignWinget.ps1` / `Collect-BenignPE.ps1`（良性，可在开发机跑）
- [ ] 拍板 V1–V8，以及 D2 / D3 / D4
- 出口：工作区干净且有异地副本；样本区可用；语料 v1 清单入库（只入清单与哈希，不入文件）

### E1 · 扫描进程 + 内置规则（4–6 人周）

- [ ] `cpp/third_party/yara-x`：钉 v1.20.0 tag + `Cargo.lock`（含校验和），`--locked` 构建；crates 是 vendor 进仓库还是走本地镜像，看体积再定（wasmtime 依赖树不小）；`rust-toolchain.toml` 钉工具链；Rust 侧加 `-C control-flow-guard` 保住 `/guard:cf` 覆盖；CRT 与现有 /MD 一致
- [ ] `bulwark_scan`：LPAC + Job + 缓解策略、匿名管道、看门狗、超时
- [ ] 内置规则包：自测规则 + Info 规则 + 首批家族规则，**全部以 Soft 观察**
- [ ] `ScanService`（新类，不塞进 `Worker.cpp`）：有界优先队列（执行 > 落盘 > 巡检 > 手动）+ 丢弃计数、去重缓存、接 4 个现有触发点；Worker 只加钩子和落地策略参数
- [ ] 新增 ctest `scan_engine_selftest`：沙箱拉起、夹具运行时生成、结论映射
- 出口：CMake 构建 + 4 条 ctest 全绿；`golden.json` 零差异；记录 `bulwark_scan` 体积与内存实测值；本机试运行 ≥ 2 周，Soft 命中逐条复核无误报后，首批规则提级 Hard

### E2 · 落盘即扫 + 签名通道 + 内核哈希（7–9 人周，不含 tasks 2.8）

- [ ] **先做 tasks 2.8**（隔离区自描述容器）：引擎会成为最大的隔离来源，而今天索引一丢就全部无法还原（2.2.6）
- [ ] USN 消费者 + U 盘兜底 + MOTW 优先级
- [ ] S11 客户端（Monocypher 验签、verify-then-parse、last-good、观察期、kill-switch）+ 构建区最小流水线 + 下发端点；攻击链组合表迁入（关 2.5.1）
- [ ] 统一有界 IOC 存储（顺带给无上限的 `confirmedMaliciousHashes_` 加上限）
- [ ] 内核：追加 / 清空两条 `BLW_CMD` + 持久化 + 派生集合 + 加白重推
- [ ] 单规则熔断、影响面上限
- [ ] UI：手动扫描文件 / 文件夹 + 结果列表（沿用现 IPC）
- 出口：两种模式下「落盘 → 结论」p95 延迟有测量值；「加白后内核集合一次重推内撤销」有自动化用例；规则包篡改 / 降级 / 引擎版本不匹配三类用例全拒且保留上一份

### E3 · 并入新架构（随架构阶段 1–2）

- [ ] 结论 → `Signal{analyzer="scan", kind}`，经 `LateSignal` 回灌（S1 / S3，tasks 1.2 / 2.4）；处置经 `ActionExecutor`（S6，tasks 2.7），带撤销
- [ ] `FileReputation` 适配器与落地策略参数，随五条补偿路径一起删除
- [ ] 引擎纳入 A1.4 差异审计与 A2.5 影子模式；内容下载归 `bulwark_cloud`（tasks 2.11）
- [ ] 全盘 / 定时扫描在新 IPC 上做（优先级低）

### E4 · 执行即拦（随驱动 v2，tasks 3.6）

- [ ] section-sync 预回调 + FileId / 哈希快照 + stream context 哈希缓存；无 USN 卷的 CLEANUP 通知
- [ ] A3.3 全套（Verifier / 风暴 / 加载卸载循环 / 72h）+ 首次执行延迟测量
- 取决于 D4：不办 EV，这就是「驱动模式加分项」，ETW 模式靠 E2 兜底，S0 覆盖面报告写明

### E5 · 可选增强（每项单独立项）

- 云侧相似度：客户端只上送 imphash / TLSH，服务端给软信号；服务端对已收样本跑 ClamAV / YARA 回溯，结论以 IOC 回灌。依赖 S13 与 `scan_engine.py` 的下落。
- ML：先做云侧分诊，仍需修订非目标（V6）。
- AMSI provider：能拿到运行时解混淆后的脚本内容；但 DLL 会被加载进所有 AMSI 宿主进程，稳定性与自保护成本高。1903 起系统提供（默认关闭的）provider 签名检查，企业环境开了就要求正式签名 → 取决于 D4。

---

## 6. 风险与对策

| # | 风险 | 对策 |
|---|---|---|
| 1 | 坏规则包批量误杀（2010 年 McAfee 把 svchost.exe 判成病毒那一类事故） | S5 关键二进制拒发；灰度；观察期；单规则熔断；只隔离不删除；kill-switch |
| 2 | 隔离量放大 2.2.6 的脆弱性 | tasks 2.8 提前到 E2 前；E1 期间设每小时隔离上限 |
| 3 | 恶意文件利用解析器漏洞 | LPAC 沙箱；跟进 YARA-X 版本；IPC 帧与规则加载入 fuzz（S14） |
| 4 | 性能与电量 | 后台低优先级；体积上限；优先级队列；丢弃计数上报（S3） |
| 5 | Rust 工具链让构建变复杂 | 钉工具链 + `Cargo.lock` + `--locked`；CI（A0.2）一并装；退路 libyara（V2） |
| 6 | 规则许可 | 逐条元数据 + 许可白名单（V7） |
| 7 | 与 Defender 共存 | 处置容忍文件已被对方隔离；规则包与测试夹具加密落盘；不和 Defender 抢同一文件的删除 |
| 8 | 公开仓库暴露检测逻辑 | 自有 Hard 规则私有。本文也属于 progress.md 4.3e 那类「弱点清单」，是否公开提交与 spec 一起定 |
| 9 | 规则运营跟不上 | 公开高质量集 + IOC 源自动更新保底；自有规则只覆盖本地高发家族 |
| 10 | 与重写并行造成返工 | E1 / E2 只在 Worker 留钩子与一个参数；scan 进程、规则流水线、S11 客户端都是重写后原样保留的部件 |

---

## 7. 需要你拍板

| # | 决策 | 建议 |
|---|---|---|
| V1 | 主干路线 | 路线一 |
| V2 | YARA-X 1.20.0（Rust 进构建）/ libyara 4.5.8（纯 C，维护模式） | YARA-X |
| V3 | `bulwark_scan` 提前到 E1，只做扫描（修订 D3） | 同意 |
| V4 | Ed25519 + Monocypher 4.0.3 / ECDSA P-256（CNG 原生） | Ed25519，与 S11 一致 |
| V5 | 内核哈希下发：E2 用 v9 追加命令 / 等驱动 v2 快照 | E2 先做 |
| V6 | 「不做 ML 模型推理」非目标 | 保持，E5 再议 |
| V7 | 规则许可白名单；自有 Hard 规则不进公开仓库 | 同意 |
| V8 | tasks 2.8 隔离区改造提前到 E2 前 | 同意 |

交接遗留：

- `scan_engine.py` 是否只在线上服务器；若在，它的家族相似度逻辑是 E5 云侧的起点。
- D2 / D3 / D4 仍是「待填」；D4 决定 E4 与 AMSI 的定位。
- A0.1 未完成（227 条未提交，HEAD `a60397d`）。E1 开工前必须先提交并留异地副本。

---

## 8. 编号挂接速查

| 本方案 | 架构文档 |
|---|---|
| scan 进程；UI 不再解析文件 | S9 · R3 · D3 |
| 结论 = `Signal{Hard / Soft / Info}`，事实带 Provenance | S1 · A1.1 · tasks 1.2 |
| 迟到结论统一回灌 | S3 · tasks 2.4 |
| 落盘即扫 · 执行即拦；无驱动模式等价 | S4 · tasks 3.6 · S0 · R6 |
| 规则包不许命中关键二进制 | S5 · tasks 1.1 / 4.5 |
| 分级处置、影响面上限、撤销、隔离区 | S6 · R4 · tasks 2.7 / 2.8 |
| 签名内容通道、观察期、只进不退 | S11 · R5 · A4.2 · tasks 2.13 / 4.4 |
| 解析器与 IPC fuzz | S14 |
| 不动评分、差异逐条审、事故转用例 | R10 · A1.4 · A1.5 · A2.5 |
| 软信号不单独定罪 | C1 |
| 样本隔离 | A0.4 · tasks 0.6 |

---

## 附：外部事实出处（内容已转述）

- YARA-X 稳定、YARA 进入维护模式：<https://virustotal.github.io/yara-x/blog/yara-x-is-stable/>
- YARA-X v1.19 / v1.20 变更（反序列化修复、msi / vba / olecf 实验模块）：<https://github.com/VirusTotal/yara-x/releases>
- YARA-X C API 与 Windows 产物：<https://virustotal.github.io/yara-x/docs/api/c/c-/>
- YARA-X 条件编译为 WASM 再转机器码：<https://github.com/vthib/boreal/discussions/84>
- YARA 4.5.8：<https://en.wikipedia.org/wiki/YARA>；CVE-2026-88341：<https://ubuntu.com/security/CVE-2026-88341>
- ClamAV 签名退役与库体积：<https://blog.clamav.net/2025/11/clamav-signature-retirement-announcement.html>
- ClamAV 内存峰值：<https://docs.clamav.net/manual/Installing/Docker.html>
- ClamAV 2026 安全补丁：<https://blog.clamav.net/2026/07/clamav-153-and-145-security-patch.html>、<https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html>、<https://blog.clamav.net/search/label/clamav?max-results=20>
- AMSI provider 签名检查：<https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider>
- Monocypher 4.0.3 与 Ed25519 可选模块：<https://monocypher.org/changelog>、<https://monocypher.org/>
- YARA-Forge Core：<https://yarahq.github.io/>
- ReversingLabs YARA 规则：<https://github.com/reversinglabs/reversinglabs-yara-rules>
