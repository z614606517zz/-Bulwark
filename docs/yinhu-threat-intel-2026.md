# 银狐（Silver Fox / ValleyRAT）2026 年情报综述

> 编写日期：2026-09-30 · 覆盖区间：2026-02 — 2026-09
> 每条事实后的 `[n]` 对应文末「参考来源」的编号。来源原文的连续引用均不超过 30 词，其余内容已改写。

---

## 一句话结论

银狐在 2026 年已经从「一个用 ValleyRAT 的中文黑产团伙」变成一套**有分发商、有联盟制、有投递基础设施、能按访客身份决定是否投毒的犯罪即服务生态**，2026 年 6 月公安部抓捕 63 人 [9] 之后十天内仍有 400+ 新恶意域名注册 [7]，说明打掉的是执行层而非供给层。

### 相比 2025 年的关键变化

以下五条都是来源自身明确描述为「新增 / 演进」的，不是我的推断：

| 变化 | 证据 |
| --- | --- |
| **载荷不再有稳定哈希**——仿冒下载站的 ZIP 每次下载都由服务端动态生成，哈希每次都不同 | [1] |
| **投递侧新增「访客识别」**——基础设施能区分真实受害者与安全研究员，只对前者投毒；暴露的链接管理后台会记录点击者 IP、地理位置、时间与 campaign 标签 | [13] |
| **投递容器从脚本换成磁盘镜像**——形态演进路径为 `.vbs` → `ZIP + DLL 侧载` → `.img / .vhd`，用 ISO9660 容器绕过 MOTW | [12][10] |
| **出现非 C/C++ 的新家族**——Rust 编写的模块化 RAT「MODBEACON」，以 gRPC 隧道流做 C2 并复用 Xray/V2Ray 传输层 | [6] |
| **目标与动机双轨化**——从纯捞钱扩展到「间谍 + 捞钱」，地域从中国大陆扩到台湾、日本、马来、印度、印尼、新加坡、泰国、菲律宾 | [11] |

补充一条属于我的推断（来源未直接如此表述）：前两条合在一起意味着**以样本哈希为核心的情报共享模型对银狐的 dropper 层已基本失效**——研究员拿到的样本可能根本不是受害者拿到的那个。详见「检测启示」§7。

---

## 一、组织画像与别名

银狐不是单一团伙，而是多个「分发商」共用一套工具与基础设施的生态，同时兼任**网络犯罪军火商**与**流量中介**两种角色 [6]。DomainTools 从域名注册数据里识别出三个相互独立的注册者集群 [7]，这与「联盟制 / MaaS」的判断一致。

### 别名对应关系

| 类别 | 名称 |
| --- | --- |
| 组织别名 | 银狐、Silver Fox、Yinhu、SwimSnake（游蛇）、UTG-Q-1000、Void Arachne、谷堕大盗 |
| 主力木马 | **ValleyRAT = Winos 4.0 = WinosStager**（同一家族的不同命名） |
| 家族血缘 | payload 为魔改 Gh0stRAT [7] |
| 2026 新增家族 | MODBEACON（Rust，gRPC C2）[6]、VenomRAT v6.0.3（PAPERMILL 集群）[10]、伪装 WhatsApp 的 Python 窃密器 [11] |
| 关联集群 | GoldenEyeDog 的子集群 CuboidalCanine（同样在用 ValleyRAT）、CylindricalCanine（关联 2026 年 4 月 DigiCert 证书事件）[14]、PAPERMILL（JumpSec 定为「近似」集群）[10]、Campaign KCPhoenix（Atos）[5] |

规模数据：2026 全年 ValleyRAT 相关检出超过 10 万次，受影响用户 1500+，主要分布在中国和印度 [3]。

---

## 二、2026 年投递渠道盘点

1. **SEO 投毒 + 仿冒下载站** — 域名多为 `.com.cn` / `.hl.cn`，仿冒 Razer、Edge、Kaspersky、百度网盘、搜狗、draw.io 等 [1]；另有仿冒火绒官网投毒 [14]。
2. **税务 / HR 主题钓鱼邮件** — 台湾税务主题的 Winos 4.0 大规模投递 [14]；国家计算机病毒应急处理中心预警的变种用「违纪名单」「裁员名单及补偿方案」「人事通知」等文件名，图标伪装成文件夹 / 快捷方式 / 回收站，双后缀 `.pdf.exe`，重点打中大型单位的 HR 与财务岗 [8]。
3. **即时通讯** — 微信 / 钉钉；WhatsApp 盗号后向联系人发「财务报表」「欠款确认」，且 WhatsApp Web 会话会自动向联系人二次扩散 [12]；马来西亚的 WhatsApp 财务主题链路为 `ZIP → IMG → 侧载` [13]。
4. **捆绑在国产软件里** — 带合法签名的 QN Wallpaper（壁纸广告软件）投递 ValleyRAT [3]；伪装 Telegram 中文语言包的 MSI [14]。
5. **木马化合法安装包** — 木马化 AnyDesk 安装包（Campaign KCPhoenix）[5]。
6. **假杀软官网** — 仿冒火绒 [14]、仿冒 Kaspersky 下载页 [1]。

> 用户原始任务清单里列了「npm 仿冒包」与「AI 搜索结果投毒」两项，但上一轮收集到的 14 条来源中**没有任何一条支撑这两条**。按「不编造」的要求，此处不写；如确有来源请补充后再加。

---

## 三、技术手法演进

### 3.1 载荷动态化与反分析

- ZIP 服务端动态生成，每次下载哈希不同；落地路径随机 [1]。
- Inno Setup 把安装包填充到 **117–147 MB** 以超出沙箱 / 杀软扫描上限，配合 OLLVM 混淆、伪装成 PNG 的加密载荷 [7]。
- 假节名反分析；沙箱检查失败时 **Sleep 5 分钟而非退出**（对抗「短时运行即判定」的动态分析）[10]。
- `.img`（ISO9660，用 pycdlib 生成）绕过 MOTW [10]。
- 访客识别：只对真实受害者投毒 [13]。

### 3.2 BYOVD 驱动清单（2026 年实际出现过的）

| 驱动 | 来源软件 / 说明 | 情报来源 |
| --- | --- | --- |
| `BootRepair.sys` | Zeon | [4] |
| `EnPortv.sys` | Zeon | [4] |
| `wsftprm.sys` | Wise Force Deleter | [4] |
| `wnBios.sys` / `wnBios64.sys` | WnBios 内存访问库 | [14] |
| `amsdk.sys` / `wamsdk.sys` | WatchDog Antimalware | 仓库既有名单，见 §6.1 |

Cato 记录的日本制造企业攻击使用**三驱动 BYOVD**组合 [4]；Seqrite 记录 WhatsApp 链路在 2026-09 **新加入 BYOVD**，但未点名具体驱动 [12]。

### 3.3 DLL 侧载的签名宿主清单

| 签名宿主 | 被侧载的模块 | 签名方 / 说明 | 来源 |
| --- | --- | --- | --- |
| `QnWallpaper.exe` | `libcef.dll` | QN Wallpaper 带合法签名 | [3] |
| `ConvertToPDF.exe` / `PDFDirect.exe` | `PDFCORE8.dll` | — | [4] |
| 重命名的 Notepad++ 签名程序 | 代理转发型 `libcurl.dll` | PAPERMILL 集群 | [10] |
| `active_desktop_launcher.exe` | `active_desktop_render_x64.dll` | 酷狗（Guangzhou Kugou）签名 | [13] |
| `SodaMusicLauncher.exe` | `powrprof.dll` / `wsc.dll` | 字节跳动签名 | [14] |

### 3.4 防御规避与破坏链

- **Defender**：写扫描排除项（Microsoft 记录的形态是由一个 **SYSTEM 权限的临时计划任务**写入）[1]；关 `DisableAntiSpyware` [3]。
- **Windows Update 破坏**：停用 `wuauserv`、`UsoSvc`、`uhssvc`、`WaaSMedicSvc` [1]。
- **反恢复**：删除卷影副本 [1]。
- **锁定落地目录**：用 `icacls` 锁目录阻止清除 [1]。
- **自保护**：`RtlSetProcessIsCritical` 把自身标记为关键进程，终止即蓝屏 [3]。
- **NTDLL unhooking**，对抗用户态挂钩 [4]。
- **双看门狗互救** [4]；另一条链把看门狗放在 `uhssvc.exe` 里 [7]。
- **计划任务约 60 秒复活** [1]。
- **伪造杀软注册**，让 Windows 安全中心显示「已受保护」[5]。
- **UAC 绕过**：`ICMLuaUtil` COM 接口 [7]。

### 3.5 注入落点

- shellcode 注入 `svchost.exe`（loader 自起一个全新 svchost 再塞入）[4]。
- sRDI 注入 `sihost.exe` [7]。
- Chaskey 加密的定制 Donut 加载器 [5]；Donut → VenomRAT [10]。

### 3.6 C2 通道

- **非标准端口**：5090、7031、7032、7088–7090、8050、28290、28300 [1]；5040 [14]；441 / 442 / 443、6666 / 8888 [3]；4449 [10]；443 [13]。
- **KCP over UDP**（ValleyRAT，Campaign KCPhoenix）[5]。
- **gRPC 隧道流**，复用 Xray/V2Ray 传输层（MODBEACON）[6]。
- 枢纽 IP `202.95.14[.]237`（CTG Server Ltd）[1]。

---

## 四、执法与生态

- 2026-05：国家计算机病毒应急处理中心预警新变种 [8]。
- 2026-06-16：公安部公布 5 起银狐典型案例，共抓 63 人；主犯潘某 6 月 4 日在越南被抓、6 月 6 日押解回国，另有 11 人在广东广西同步归案；杨某团伙涉案超 300 万元 [9]。
- 2026-06-17 — 06-27：抓捕后的十天内仍新注册 400+ 恶意域名，三个独立注册者集群 [7]。

**读法**：域名注册速度未受抓捕影响，加上分发商结构，指向 MaaS / 联盟制——被抓的是运营端与变现端，工具与基础设施的供给方仍在运转 [7][6]。对终端防护的含义是：**不要期待上游治理带来检出压力下降，按持续对抗建设**。

---

## 五、对 Bulwark 的检测启示

> 本节逐条对应到我实际读过的文件。已读完整文件：`Rules01`–`Rules08`、`RulesCommon.cpp`、`RemoteControlAnalyzer.cpp`、`BeaconDetector.cpp`；已读关键片段：`Worker::detectSideloadedTamperedModule`、`ThreatDetector` 的侧载/父子链判据与 `isSideloadProneModuleName`、`ThreatFoxFeed::generateIntelRules`、`Worker::buildRulesFromProfile`、`NetMonitor.c` 的 WFP 层注册、`Enums.h` 的 `EventType`。
>
> **工具可靠性声明**：本工作区路径含非 ASCII 字符，`grep_search` 对已确认存在的字符串返回「无匹配」。本节所有「仓库中不存在 X」的结论均由 `Get-ChildItem -Recurse | Select-String` 全仓扫描 + 定向精读双重确认，不依赖 `grep_search`。

### 5.1 已覆盖（且覆盖得不错）

| 银狐手法 | 覆盖位置 | 处置 |
| --- | --- | --- |
| BYOVD 具名驱动 [4][14] | `Rules07` §7.4 `kByovdSilverFox` = `amsdk.sys`、`wamsdk.sys`、`wsftprm.sys`、`bootrepair.sys`、`enportv.sys`、`wnbios.sys`、`wnbios64.sys`，**ImageLoad 与 FileWrite 双维度** | Block + hard |
| 白加黑侧载（主流落法）[3][4][10][13][14] | `Worker::detectSideloadedTamperedModule`，两种形态：①模块内嵌签名校验不过 → `tamperedModulePath`（50 分硬指标）；②模块完全无签名 + 互证 → `sideloadedUnsignedModulePath`（45 分硬指标）。互证二者取一：**系统同名模块**（`isSideloadProneModuleName`，已含银狐实际用过的 `powrprof.dll` / `wsc.dll` / `wscapi.dll`）**或最近才落地**（`wasRecentlyWritten`） | Ask（刻意不 Block，避免 `blacklistExec` 永久钉死正规程序） |
| shellcode 注入 svchost [4] | `ThreatDetector` §3c `kExpectedParent`：svchost 不是 `services.exe` 生的 + 父进程自身可疑 → 45 分硬指标。代码注释直接点名银狐 | 硬指标 |
| 文件膨胀 117–147MB [7] | `ThreatDetector` §1c：未签名 ≥90MB 且位于投递目录 → 65 分硬指标；≥60MB → 30 分 | 硬指标 |
| 删卷影 [1] | `Rules05` §5.1 `vssadmin delete shadows` | Block + hard |
| 关 `DisableAntiSpyware` [3] | `Rules03` §3.1 `kDefenderOff` | Block + hard + exemptOs |
| MSI 投递链 [14] | `ThreatDetector` §3b「MSI 自定义动作拉起脚本宿主」30 分软信号（刻意不做成规则，避免短路启发式）；`Rules07` §7.5b `zpaqfranz` | 软信号 / Ask |
| RMM 工具落地 [5][12] | `RemoteControlAnalyzer::remoteTools()` 已含 `anydesk.exe`、`ateraagent.exe`、`syncro.exe`、`action1_agent.exe`、`meshagent.exe`、`screenconnect.*`；`analyzeCommandLine` 的 `unattendedFlags` 含 `--set-password`（对应 [12] 的「带密码」）；`Rules08` §8.1 拦 12 款远控从投递目录或脚本宿主父进程启动 | Block + hard / 45 分硬指标 |
| IM 群控 hook / 微信 QQ 批量群发 [12] | `Rules07` §7.6 `kImHook`（30 条模式，与 `groupControlModules` 对齐，**ImageLoad 与 FileWrite 双维度**）、IM 安装目录与**聊天数据目录**植入 DLL、§7.6b 本地库解密工具落地；§7.2 `kImApp` 未签名程序注入 IM 进程；`RemoteControlAnalyzer` 的 `groupControlModules` / `imProcesses` | Block + hard |
| HKCU Run 持久化 [13] | `Rules02` §2.1，未签名 → Ask，脚本宿主 → Block | Ask / Block |

#### 5.1b 微信 / QQ 群发链的补齐（2026-10-01），以及两条必须知道的引擎机制

这一轮针对「银狐劫持微信 / QQ 做批量群发」把 §5.2 之外的几处补上了。三条**实测核实过**的引擎机制是改动的依据，记在这里避免后人重新踩（机制 ③ 见 §5.2 原缺口 8，根因已一并修掉）：

**机制 ①：一条宽 Ask 规则会把「群控模块加载」变成放行。** 一个未列名的群控模块（`wcferry.dll` / `ntchat.dll` / `wxauto.dll` …）落在 `%TEMP%`、被**合法签名的**微信加载，改动前的裁决是**放行**，由三步叠成：

1. 它不匹配 `kImHook` 任何一条 → 没有 Block + hard 规则命中；
2. §7.3 的通用规则「从 %TEMP% 加载未签名模块」（Ask）命中，而 `RuleEngine` 步骤 6 命中即 `return`，**短路掉步骤 10 的启发式** → `RemoteControlAnalyzer` 给的 55 分 + 硬指标作废（而且 55 < `ThreatDetector::HighRisk` = 80，不短路也只换来 Ask）；
3. `Worker` 在 `trustSignedActors`（默认开）下把签名健康主体的 Ask 降级为放行。

补进 `kImHook` 即可翻盘：`ruleTier` 对 `hardOverride` 给 1、对 §7.3 那条给 0，而层级是步骤 6 比较器的**第一级**（排在具体度之前）。重放验证：裁决 Block，命中新规则，riskScore 95。

**机制 ②：`blacklistExec` 没有签名护栏，只有系统目录护栏。** `RuleDsl.h` 原先写的是「见 `Worker::blacklistExec` 的签名护栏」——不准确，已据实改写。实际三道闸是「已加白」、「`isSweepExemptPath`（System32 / SysWOW64 / WinSxS + 本产品目录）」、「去盘符后子串 ≥ 6 字符」，**没有任何签名判断**。直接后果：**不要写只按 `commandLinePattern` 匹配的 ProcessCreate Block 规则去拦某个框架/库的用法**——那类命令行的主体通常是 `python.exe` / `node.exe` / `pip.exe`，它们不在 System32 下，会被按完整路径钉进只有 64 槽、只加不减、跨重启续拦的内核禁运名单，整台机器再也起不了 Python。§7.6b 的「不写命令行维度」就是按这一条决定的。

本轮新增（均已用 `bulwark_snapshot --record` 重放确认裁决）：

| 新增项 | 位置 | 判据 | 重放结果 |
| --- | --- | --- | --- |
| `kImHook` 由 10 → 30 条模式，与 `groupControlModules()` 对齐 | §7.6 | ImageLoad | `wcferry.dll` / `ntchat.dll` → Block（95） |
| 同一批名字补 **FileWrite（落地）** 维度 | §7.6 | FileWrite | `\ProgramData\stage\wcf.dll` → Block（40） |
| IM **聊天数据目录**植入 DLL（`WeChat Files` / `xwechat_files` / `Tencent Files` / `WXWork\*\Cache`） | §7.6 | FileWrite + unsignedOnly | `\Documents\WeChat Files\helper.dll` → Block（40） |
| 微信本地库解密/导出工具落地（`pywxdump` / `wxdump` / `sharpwxdump` / `wechatmsg`） | §7.6b | FileWrite | `\Downloads\pywxdump.exe` → Block（40） |
| 未签名程序注入 IM 进程由 Ask **提到 Block**（`kImApp`，含 `tim.exe`） | §7.2 | RemoteThread + unsignedOnly | 注入方改名 `setup.exe` 置于 `%APPDATA%\Microsoft\Update\` → Block（100） |

两点补充说明：

- **为什么 FileWrite 维度是必需的，不是冗余**：用户态 `ImageLoad` 的上报口径只有 `\Temp\` 与 `\Users\Public\`（`ImageMonitor.c` 的 `BlwPathIsSuspicious`），群控 DLL 只要暂存到 `ProgramData` 或微信自己的聊天数据目录，**加载那一刻根本不产生事件**。而 ETW 对「用户可写目录里新建可执行体」按后缀判，名单含 `.dll`，目录含 `\Users\` `\ProgramData\` `\Windows\Temp\` `\Temp\` `\PerfLogs\`（`isDroppedExecutable`）——落地能看见的范围比加载宽得多。与 §7.4 对 `kByovdSilverFox` 的双维度处理同一形状。
- **为什么 IM 那组提 Block 没有不对称代价**：`RemoteThread` 的 Block 在 `Worker::enforceBlock` 里只走「结束注入方进程」一条路（`blacklistExec` 只在 `ProcessCreate` 时调，`blockModuleLoad` 只在 `ImageLoad` 时调），**不会**往内核那两份 64 槽名单写任何东西。原来的 Ask 则会被步骤 6 的 `isDevTool` 纯文件名匹配降级为放行，而 `setup.exe` / `python.exe` 就在那份名单里——改名零成本。
- **机制 ③：那条 `isDevTool` 降级本身是个通用后门，已按事件类型收掉**。它不只影响 IM 这一组，而是让**任何** Ask 规则都能被「改名成 `setup.exe`」绕过。本轮给降级加了 `devToolExemptionApplies()`，把 `RemoteThread` 与 `ProcessTerminate` 排除在豁免之外；代价经核实为零（这两个维度上只有两条 Ask 规则，且都带 `unsignedOnly()`，真实开发工具都是签名的、匹配不上）。详见 §5.2 原缺口 8。顺带把银狐 sRDI 注入 `sihost.exe` [7] 那条也从「改名即放行」拉回 Ask。

**群发动作本身（遍历联系人 + 驱动发送）在本引擎里结构性不可见**，这一条要诚实写明：它要么在被注入的微信进程内部直接调用其内部函数，要么走 UI 自动化（`FindWindow` + `PostMessage`/`SendMessage`/`SendInput`、剪贴板、UIAutomation COM）。`EventType`（`Enums.h`）里没有窗口消息、输入合成、剪贴板任何一个维度，这两条路全程在进程内或 win32k 里完成，不产生进程、文件、注册表、网络事件。所以这一类只能锚在**前置条件**上——上表五项正是前置条件，到了「已经在发」就只剩事后了。要覆盖发送动作本身必须新增管道（与缺口 6 的 `RtlSetProcessIsCritical` 同一性质，属架构改动）。

### 5.2 缺口与具体规则建议

#### 缺口 1 · Windows Update 破坏链完全未覆盖（最高优先级）

全仓扫描确认 `wuauserv`、`UsoSvc`、`WaaSMedicSvc`、`uhssvc` **在整个代码库中零出现**。`Rules03` §3.2 的 `kSecServices` 只收安全软件服务，不含更新服务。而这是 Microsoft 记录的标准动作 [1]，`uhssvc.exe` 还兼作看门狗宿主 [7]。

建议加在 `Rules03_DefenseEvasion.cpp` §3.2，紧邻 `kSecServices`：

```cpp
// 银狐 2026:停用 Windows Update 链路,让系统再也拿不到 Defender 情报与补丁(来源见
// docs/yinhu-threat-intel-2026.md [1])。uhssvc 同时是某条链的看门狗宿主([7])。
//
// 【给 Ask 不给 Block】停 wuauserv 是真实存在的运维与个人操作(排障、按流量计费网络、
// 第三方更新管理器、大量「关闭自动更新」工具),Block + hard 会直接结束正常进程树。
// 判别性不在「停了更新服务」,而在「停更新服务 + 加 Defender 排除项 + 建计划任务」的组合,
// 那一层属于 AttackChainEngine。
//
// 四个名字都 >= 6 字符,满足本文件头「不收短名」的约束,不会撞普通英文子串。
static const char* kUpdateServices[] = {
    "wuauserv", "usosvc", "uhssvc", "waasmedicsvc",
};
for (const char* svc : kUpdateServices) {
    s.proc(Ask, u("命令行停止 Windows 更新服务 ") + u(svc) + u("(阻断补丁与安全情报,T1562.001)"))
        .cmd(u("*stop*") + u(svc) + u("*"));
    s.proc(Ask, u("命令行禁用 Windows 更新服务 ") + u(svc) + u(" 的启动类型(T1562.001)"))
        .cmd(u("*config*") + u(svc) + u("*disabled*"));
    s.proc(Ask, u("命令行删除 Windows 更新服务 ") + u(svc) + u("(T1562.001)"))
        .cmd(u("*delete*") + u(svc) + u("*"));
}
```

#### 缺口 2 · WhatsApp 在四份 IM 名单里全部缺席

来源 12 与 13 把 WhatsApp 放在 2026 年这条链的中心（盗号 → 向联系人发财务主题文件 → WhatsApp Web 自动二次扩散）[12][13]，但仓库四处 IM 名单**一处都没有它**：

- `Rules06` §6.6 `kImParents`：只有 foxmail / wechat / weixin / wxwork / qq
- `Rules07` §7.2 `kSensitiveApp`：只有 chrome / msedge / firefox / outlook / wechat / weixin / wxwork / qq
- `Rules07` §7.6 `kImDir`：只有腾讯系 + 微信新版 + 钉钉
- `RemoteControlAnalyzer::imProcesses()`：只有微信系 + QQ 系

建议四处同步补 `whatsapp.exe` / `*\WhatsApp\*.dll`。**注意一处真实约束**：WhatsApp 在 Windows 上主要以 Store / UWP 形式安装在 `WindowsApps` 下，而它位于 `Program Files` 子树——这意味着 §7.6 的「向安装目录植入 DLL」那条对它价值有限（普通用户写不进去），而 §6.6 的**父子链派生规则才是真正有用的那条**：

```cpp
// Rules06 §6.6 kImParents 补一项(银狐 2026 年的 WhatsApp 链路,见情报文档 [12][13])
"*\\whatsapp.exe",
```

#### 缺口 3 · `.img` / `.vhd` 投递会绕过侧载扫描的互证

这是我认为**最值得修**的一条，因为它让 §5.1 里那条最有效的检测在最新投递形态下静默失效。

`Worker::detectSideloadedTamperedModule` 形态 ② 的互证是「系统同名模块 **或** 最近才落地」。而 `.img` / `.vhd` 链路 [10][12][13] 的特点是：

1. 被侧载的 DLL（`active_desktop_render_x64.dll`、`PDFCORE8.dll`、代理型 `libcurl.dll`）**不是系统 DLL 名**——且 `isSideloadProneModuleName` 的注释明确说**刻意排除** `libcurl.dll` 这类第三方库，以免把绿色软件全判成侧载；
2. DLL 是**随镜像一起来的，从未被写到那个挂载卷上**——`wasRecentlyWritten` 查不到记录。

两条互证都不成立 → 一个签名健康的宿主从挂载卷加载恶意 DLL，**这条路径上一个信号都不产生**。`Rules07` §7.3 也接不住：它只覆盖 `%TEMP%` / `Windows\Temp` / `Users\Public` 三个目录，挂载卷是独立盘符。

真正的修法在 `Worker.cpp` 而不是规则层——给形态 ② 增加**第三个互证选项**：模块所在卷不是固定磁盘。下面的 `isNonFixedVolume()` 是**需要新写的**辅助函数（取盘符后调 `GetDriveTypeW`，判 `DRIVE_CDROM` / `DRIVE_REMOVABLE`），仓库里目前没有它：

```cpp
// 形态 2 的第三条互证:模块位于【非固定磁盘】。
// 银狐 2026 年改用 .img / .vhd 容器投递(绕 MOTW),DLL 随镜像进来,从未在本机被"写入"过,
// 所以 wasRecentlyWritten 恒假;而它们又不是系统 DLL 名(libcurl / PDFCORE8 /
// active_desktop_render_x64),isSideloadProneModuleName 也不认。两条既有互证同时失效。
// 挂载的 ISO/VHD 是 DRIVE_CDROM 或 DRIVE_REMOVABLE —— 正规软件不会从那儿加载私有模块。
else if (isNonFixedVolume(modPath))
    why = QStringLiteral("位于挂载镜像/可移除卷");
```

配套补一条规则层的廉价兜底（可单独先上）：

```cpp
// Rules07 §7.3 追加:镜像容器落地即提示。写入方通常是签名的浏览器/IM 客户端,
// 故【不加 unsignedOnly】(加了等于永不命中)。
static const char* kImageContainer[] = { "*.img", "*.iso", "*.vhd", "*.vhdx" };
for (const char* ext : kImageContainer) {
    const QString e = QString::fromUtf8(ext).mid(1);   // 与本文件既有写法一致
    s.file(Ask, u("落地磁盘镜像容器 ") + e +
                u("(绕过 MOTW 的投递容器,银狐 2026 主流形态,T1553.005)"))
        .target(ext);
}
```

> 已核对不与 `Rules05` §5.4 冲突：那里是 `s.del` 维度（删除备份文件 `*.vhd`），这里是 `s.file` 写入维度，事件类型不同。

#### 缺口 4 · `sihost.exe` 不在注入落点名单

sRDI 注入 `sihost.exe` [7]，但：

- `Rules07` §7.2 `kHostish` = explorer / svchost / dwm / taskhostw，**无 sihost**
- `ThreatDetector` §3c `kExpectedParent` = svchost / dllhost / taskhostw，**无 sihost**

两处各补一行。`sihost.exe` 的正常父进程同样是 `svchost.exe`：

```cpp
// Rules07 §7.2 kHostish
"*\\sihost.exe",

// ThreatDetector §3c kExpectedParent
{ QStringLiteral("sihost.exe"), QStringLiteral("svchost.exe") },
```

#### 缺口 5 · `icacls` 的拒绝式用法未覆盖

`Rules05` §5.5 只有 `*icacls*everyone*` 与 `*icacls*/t*/grant*`——都是**授权**方向。而 [1] 记录的是用 `icacls` **锁定**落地目录阻止清除，那是 `/deny` 与 `/inheritance:r`：

```cpp
s.proc(Ask, "用 icacls 拒绝访问指定对象(锁定落地目录阻止清除,T1222.001)")
    .cmd("*icacls*/deny*");
s.proc(Ask, "用 icacls 剥离权限继承(隔离落地目录,T1222.001)")
    .cmd("*icacls*/inheritance:r*");
```

给 Ask 而非 Block：`/deny` 与 `/inheritance:r` 都是企业加固基线的正常写法。

#### 缺口 6 · 两条结构性不可见项（诚实说明，不硬给规则）

- **`RtlSetProcessIsCritical` 自保护** [3]：全仓扫描确认零出现。本引擎**没有对应的事件维度**——它是进程内的一次 `NtSetInformationProcess` 调用，不产生进程创建、文件、注册表或网络事件。写任何规则都是结构性空转。要覆盖必须新增管道（例如在 `ProcessInspector` 侧定期比对 `criticalNames()` 之外的进程是否被标记为 critical，或在驱动侧加回调）。这属于架构改动，不是一条规则能解决的。
- **`ICMLuaUtil` COM 绕 UAC** [7]：同理不可见——它没有命令行、不写注册表（`Rules02` §2.5 覆盖的 `ms-settings` 劫持是 **fodhelper** 路径，不是这条）。COM 提权走的是 `CoCreateInstance` + 提权 moniker，全程在进程内。

#### 缺口 7 · 假杀软注册（部分可行，但不编造键路径）

[5] 记录银狐伪造杀软注册让 Windows 安全中心显示「已受保护」。WSC 注册的**具体注册表落点，来源原文没有给出**——我不会凭空写一个键路径进规则。

可以先落的是 ImageLoad 维度的廉价信号：`wsc.dll` / `wscapi.dll` **已经在** `isSideloadProneModuleName` 名单里（注释标明是银狐 2026 实际使用）。建议把这两个名字在侧载扫描里**提权重**（命中时附加说明「疑似伪造安全中心注册」），而不是新增一条判据。确认 WSC 键路径后再补注册表规则。

#### ~~缺口 8~~ · 改名即可让整个 Ask 档失效（2026-10-01 已修，按事件类型收敛）

这一条不属于微信 QQ 群发，是补 §7.2 时顺带实测出来的。**根因已修**，过程与残留记在这里。

**原状**：`RuleEngine` 步骤 6 里有

```cpp
if (hit.action == Ask && DefaultRules::isDevTool(e.actorPath)) -> Allow
```

而 `isDevTool` 是**纯文件名**匹配，名单（`DefaultRules.cpp` 的 `devToolProcessNames`）含 `setup.exe`、`installer.exe`、`python.exe`、`node.exe`、`pip.exe`、`agent.exe`、`runner.exe`。于是**把样本改个名就能让所有 Ask 规则静默失效**。`RuleDsl.h` 的硬约束 3 与 `EtwProcessEventSource.cpp` 的 `isOsThreadInjector` 注释都把这件事记成「同类教训」，但真正的降级点一直没收。

`bulwark_snapshot --record` 重放实测（修前）：未签名程序位于 `%APPDATA%\Microsoft\Update\setup.exe`（银狐的真实落地目录 [13]）、向 `chrome.exe` 创建远程线程 —— **riskScore 100、带硬指标，最终裁决 `Allow`，`matchedRuleNote` 为空**。

**修法**：给这条降级加一道**事件类型闸** `devToolExemptionApplies()`，把 `RemoteThread` 与 `ProcessTerminate` 排除在豁免之外。判据是「正常开发与安装会不会做这件事」——构建工具、包管理器、IDE 在正常工作里不会往第三方进程创建远程线程，也不会去结束别人的进程。

**为什么这道闸的误报代价是零，不是权衡**：把全部内置规则过一遍，`RemoteThread` + `ProcessTerminate` 维度上一共只有**两条** Ask 规则（`Rules07` §7.2 的 `kHostish` 与 `kSensitiveApp`），其余同维度规则全是 Block、本就不受本降级影响。而那两条都带 `unsignedOnly()`——主体必须**未签名**才可能命中，真实的开发工具与安装器都是签名的，压根匹配不上。所以收紧只影响「改了名的未签名样本」。

重放验证（修后，`golden.json` **无需重录**，说明改动是外科式的）：

| 用例 | 修前 | 修后 |
| --- | --- | --- |
| 未签名 `setup.exe` 注入 `chrome.exe` | Allow（100） | **Ask**（100）——与不改名的 `svc32.exe` 完全一致，文件名不再换来任何东西 |
| 未签名 `python.exe` 注入 `sihost.exe`（银狐 sRDI 落点 [7]） | Allow（85） | **Ask**（85） |
| 未签名 `setup.exe` 从 `%TEMP%\is-A1B2C3.tmp\` 加载未签名 DLL（Inno Setup 真实形态） | Allow | **Allow（不变）**——回归护栏，证明非注入维度的豁免完好 |
| 未签名 `setup.exe` 注入 `wechat.exe` | — | **Block（不变）**——§5.1b 的 `kImApp` 不受影响 |

**刻意没做的事**：没有顺手把浏览器那一组提成 Block。注入浏览器确有正常形态（无障碍辅助、输入法、密码管理器、截图与翻译工具），且 `unsignedOnly` 挡不住未签名的国产输入法与截图工具，误报面需要单独评估。修了根因之后这一组回到它设计时的强度（Ask，会弹窗由用户裁决），已经不再是「静默放行」，所以不必再冒那个误报风险。

**已知残留（单列一轮）**：`isDevTool` 的另一半是 `devToolPathPatterns` 的路径子串分支，其中 `\venv\`、`\.venv\`、`\env\`、`\.env\`、`\packages\`、`\node_modules\` 是攻击者可自行创建的目录名。所以在**仍然豁免**的那些维度（`ProcessCreate` / `FileWrite` / `RegistryWrite` / `ImageLoad` / 网络）上，「造一个 venv 目录」依旧能拿到降级。要收那一侧必须面对一个真实约束：venv 里的 `pip.exe` 等 console-script 垫片是 pip 在本地生成的，**天然没有签名**，所以不能简单地「要求签名健康」。可行方向是把路径分支从「子串包含」改成「该目录下存在可信签名的解释器/工具主程序」之类的互证，需要单独评估。

### 5.3 IOC 投喂路径：用情报流水线，不要改 `Rules08`

`Rules08` 文件头已明确说明**刻意不写静态端口 / IP / 域名名单**（端口会误报、IP 会过期）。正确入口是 `ThreatFoxFeed.cpp::generateIntelRules`，它支持三类 IOC：

| IOC 类型 | 生成的规则 | 处置 |
| --- | --- | --- |
| `sha256_hash` | `actorHashes`，`type` 留空（任意行为都拦） | Block + hardOverride |
| `ip:port` | `NetworkConnect`，`targetPattern = "<ip>:*"`（已去端口，且经 `isUnsafeToBlanketBlockIp` 排除共享基础设施） | Block |
| `domain` | `NetworkConnect`，`targetPattern = "*<domain>*"` | Block |

有 TTL（`RuleTtlDays`）与条数上限（`MaxRules`）兜底，适合投喂本文 §6 的 IOC 表。

#### ⚠ 顺带发现一处疑似缺陷：域名 IOC 规则可能结构性永不命中

这条不是本次任务要求的内容，但在核对投喂路径时撞上了，且证据链完整，建议单独排查：

- `generateIntelRules` 的 `domain` 分支把规则挂在 `EventType::NetworkConnect` 上，模式为 `*<domain>*`。
- 但 `NetworkConnect` 的 `target` 是 **`ip:port`**，不含域名——`Rules08` 文件头如此声明，`Worker::extractRemoteIpv4` 也按 `ip:port` 解析该字段。
- 域名是另一个维度：`EventType::DnsQuery`（`Enums.h:21`，序号 9，唯一来源是 ETW `Microsoft-Windows-DNS-Client` 事件 3006 的 `QueryName`），`RuleDsl.h:122` 还专门提供了 `dns()` 助手。
- **同一产品内的另一条路径就是这么做的**：`Worker::buildRulesFromProfile` 的域名分支写的是 `r.type = bulwark::EventType::DnsQuery; // 拦截 DNS 查询`，注释还说明「拦截在 DNS 阶段，IP 未解析就阻断」。

即两处处理同一类 IOC 用了不同维度，而情报 feed 那一处用的维度与 `target` 的实际内容不匹配。若确认，修法是把 `domain` 分支改为 `DnsQuery`（与 `buildRulesFromProfile` 对齐）。

**这对银狐的直接影响**：[1] 给出的 `iualef[.]net`、`oijfwe[.]net` 两个 C2 域名，如果从 ThreatFox 走 domain 类型进来，可能一条都不生效。

### 5.4 哈希 IOC 的保质期问题

`generateIntelRules` 的 `GenerateHashRules` 对**银狐 dropper 层近乎无效**：仿冒站 ZIP 每次下载哈希都不同 [1]，加上访客识别式投递让研究员与受害者拿到的可能不是同一个文件 [13]。

但哈希对**链路后段仍然有效**——BYOVD 驱动、侧载 DLL、加载器这些是编译产物，不随下载动态变化。建议投喂时按环节区分预期：驱动与 DLL 的哈希值得收，dropper 的 ZIP 哈希收了也很快过期。

### 5.5 需要实测而非直接断言的两项

- **KCP over UDP** [5]：`NetMonitor.c` 只注册 `FWPM_LAYER_ALE_AUTH_CONNECT_V4`，且**未做协议过滤**，所以出站 UDP 流会作为 `NetworkConnect` 上报（WFP 在该层对 UDP 首包也会发起 ALE 授权）。但 `BeaconDetector` 判硬指标要求 `CV ≤ 0.15` 且均值 ≤ 600s——KCP 是带自定义重传与拥塞控制的连续流，它的节奏是否落在这个窗口内**我没有实测数据，不做结论**。建议拿样本流量跑一遍 `BeaconDetector` 再定。
- **计划任务约 60 秒复活** [1]：`Rules02` §2.8 覆盖「任务指向投递目录」（Block + hard，但**刻意排除 `\programdata\`**），而 [13] 的落地目录是 `%APPDATA%\Microsoft\Update`——`\appdata\roaming\` **不在** `dropDirFragments` 里（`RulesCommon.cpp` 注释说明是刻意不收）。所以这条链只被通用的 `schtasks /create` Ask 接住。「被杀后 60 秒重建」这种时序判据应归 `AttackChainEngine`——**该文件我本次没有审阅**，不对它现有能力做任何断言，仅建议在那里评估。

---

## 六、IOC 附表

> 所有 IP / 域名均已做点号转义（`[.]`），可直接投喂 `generateIntelRules`。

### 6.1 C2 域名

| 域名 | 说明 | 来源 |
| --- | --- | --- |
| `iualef[.]net` | 仿冒下载站 campaign C2 | [1] |
| `oijfwe[.]net` | 同上 | [1] |

仿冒站域名模式：`.com.cn` / `.hl.cn` 顶级域下的仿品牌域名 [1]。2026-06-17 — 06-27 间新注册 400+ 恶意域名，三个独立注册者集群 [7]。

### 6.2 C2 地址与端口

| IP:端口 | 家族 / 说明 | 来源 |
| --- | --- | --- |
| `202.95.14[.]237` | 枢纽服务器，CTG Server Ltd | [1] |
| `103.45.66[.]18:441` / `:442` / `:443` | ValleyRAT（QN Wallpaper 链） | [3] |
| `192.253.225[.]173:6666` / `:8888` | 同上 | [3] |
| `43.128.26[.]132` | 日本制造企业攻击的外部服务器 | [4] |
| `154.36.188[.]201:4449` | VenomRAT v6.0.3（PAPERMILL） | [10] |
| `134.122.155[.]135:443` | 马来西亚 WhatsApp 链 | [13] |

**非标准端口清单**（仿冒站 campaign）：5090、7031、7032、7088、7089、7090、8050、28290、28300 [1]；5040（Telegram 语言包链）[14]。

### 6.3 恶意驱动（BYOVD）

`BootRepair.sys`、`EnPortv.sys`、`wsftprm.sys` [4] · `wnBios.sys` / `wnBios64.sys` [14]

### 6.4 侧载宿主与恶意模块

| 签名宿主 | 恶意模块 | 来源 |
| --- | --- | --- |
| `QnWallpaper.exe` | `libcef.dll` | [3] |
| `ConvertToPDF.exe` / `PDFDirect.exe` | `PDFCORE8.dll` | [4] |
| 重命名的 Notepad++ 程序 | `libcurl.dll` | [10] |
| `active_desktop_launcher.exe` | `active_desktop_render_x64.dll` | [13] |
| `SodaMusicLauncher.exe` | `powrprof.dll` / `wsc.dll` | [14] |

### 6.5 文件路径与持久化

| 项 | 值 | 来源 |
| --- | --- | --- |
| 落地目录 | `%APPDATA%\Microsoft\Update` | [13] |
| 注册表持久化 | `HKCU\...\CurrentVersion\Run` 下值名 `MicrosoftUpdate` | [13] |
| 看门狗宿主 | `uhssvc.exe` | [7] |
| 注入落点 | `svchost.exe`（新建后注入）[4] · `sihost.exe`（sRDI）[7] | [4][7] |
| 被停服务 | `wuauserv`、`UsoSvc`、`uhssvc`、`WaaSMedicSvc` | [1] |
| 伪造服务名 | `AppShellElevationService`（Telegram 语言包链注册） | [14] |
| LOLBin | `zpaqfranz.exe`（解嵌套 ZPAQ 包） | [14] |
| 配置标记 | `@@RAPID_CFG_START@@`、配置内含「默认分组」 | [13] |
| 文件名诱饵 | 「违纪名单」「裁员名单及补偿方案」「人事通知」，双后缀 `.pdf.exe` | [8] |
| 投递容器 | `.img`（ISO9660，pycdlib 生成）、`.vhd`、`.zip` | [10][12] |
| 载荷体积 | Inno Setup 填充至 117–147 MB | [7] |

**哈希**：来源均未公开具体样本哈希值，且仿冒站 ZIP 哈希每次下载都变 [1]——本表不列哈希，避免给出无效 IOC。

### 6.6 计划任务与服务名

已知的具名持久化项只有 `AppShellElevationService`（服务，[14]）与 Run 值 `MicrosoftUpdate`（[13]）。Microsoft 记录的计划任务**使用随机名称与随机路径** [1]，因此**没有可列的固定任务名**——这也正是 §5.2 缺口 1 建议按「行为组合」而非「任务名」检测的原因。

---

## 七、参考来源

1. Microsoft Defender Experts，2026-09-01，《Counterfeit installers to system compromise》 — [microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/)（含完整 KQL 猎杀查询与 ATT&CK 映射）
2. The Hacker News，2026-09 — 同一事件报道，附 Kaspersky 的 QN Wallpaper DLL 侧加载投递 ValleyRAT
3. The Hacker News / Kaspersky，2026-08-31 — ValleyRAT 藏于带签名的 QN Wallpaper；`RtlSetProcessIsCritical` 自保护；2026 全年检出 >10 万次、受影响用户 >1500
4. The Hacker News / Cato Networks，2026-07 — 攻击日本制造企业；三驱动 BYOVD；NTDLL unhooking；双看门狗
5. Atos TRC，2026-09，《Campaign KCPhoenix》 — [atos.net](https://atos.net/en/lp/cybershield/campaign-kcphoenix-inside-silver-fox-latest-valleyrat-chain)（木马化 AnyDesk；伪造杀软注册；Chaskey 加密的 Donut 加载器；KCP over UDP）
6. QiAnXin（经 The Hacker News 报道），2026-07 — Rust 模块化 RAT「MODBEACON」，gRPC 隧道 C2，复用 Xray/V2Ray；银狐的「分发商」生态与军火商 / 流量中介双重角色
7. DomainTools，2026-09 — 抓捕后十天 400+ 新域名；三个注册者集群；魔改 Gh0stRAT；Inno Setup 填充 117–147MB；OLLVM；伪装 PNG 的加密载荷；sRDI 注入 `sihost.exe`；`uhssvc.exe` 看门狗；`ICMLuaUtil` 绕 UAC
8. 环球时报，2026-05 — 国家计算机病毒应急处理中心预警新变种；HR 主题文件名；图标伪装；双后缀
9. 环球时报，2026-07 — 公安部 6 月 16 日公布 5 起典型案例，共抓 63 人；主犯潘某越南落网；杨某团伙涉案超 300 万元
10. JumpSec，2026-09 — PAPERMILL 集群：`.img` 绕 MOTW；重命名 Notepad++ 侧载 `libcurl.dll`；假节名；沙箱检查失败 Sleep 5 分钟；Donut → VenomRAT v6.0.3
11. Sekoia（经 Infosecurity 报道），2026-09 — 三波演进：ValleyRAT/HoldingHands → RMM 工具 → 伪装 WhatsApp 的 Python 窃密器；目标含台湾、日本、马来、印度、印尼、新加坡、泰国、菲律宾；间谍 + 捞钱双重动机
12. Seqrite（经 ETCISO 报道），2026-09-26 — WhatsApp 传播链；格式演进 `.vbs` → `ZIP + DLL 侧载` → `.img`/`.vhd`；新增 BYOVD；带密码与自保护的合法 RMM；WhatsApp Web 自动二次扩散
13. gbhackers / Pelagosx，2026-09 — 投递侧「访客识别」；马来西亚 WhatsApp 财务主题链；酷狗签名宿主侧载；`@@RAPID_CFG_START@@`；`MicrosoftUpdate` Run 值；NCC Group 另发现银狐链接管理后台记录点击者 IP / 地理位置 / 时间 / campaign 标签
14. 其他 — Fortinet（台湾税务主题 Winos 4.0 大规模投递）· Malwarebytes（仿火绒官网投毒）· SOC Prime（Telegram 中文语言包 MSI → `zpaqfranz` LOLBin → wnBios 驱动 BYOVD → 字节跳动签名 `SodaMusicLauncher.exe` 侧载，C2 端口 5040）· Expel（GoldenEyeDog 子集群 CuboidalCanine 使用 ValleyRAT；CylindricalCanine 关联 2026-04 DigiCert 证书事件）· Check Point（ValleyRAT builder 与内核 rootkit 分析）

> 来源 2、3、4、6、11、12、13、14 为经二手媒体报道的一手研究，本文按报道内容记述。内容已改写以符合授权限制。
