# 无驱动模式防护补强（EventSource=Wmi / 驱动掉线）

目标：把「没有内核驱动时 Bulwark 还剩什么」从**只有观测**补到**有可撤销的拦截与处置**。
分四阶段：观测补齐 → 可撤销用户态前拦原语 → 处置编排 → 用户确认型加固。

八条不可破约束（全程未破）：零同步 IPC / 不确定处置不进内核持久名单 / 加白必须能撤销一切 /
规则注入有上限 / 软信号不单独定罪 / ctest 三绿且 golden 差异逐条解释 / `.ps1` 一律 ASCII 且
构建前先停驱动 / 动 `Worker.cpp` 前先看三条并行 spec 状态。

---

## 新增组件（10 个文件，均在 `cpp/service/`）

| 组件 | 阶段 | 作用 | 可撤销性 |
| --- | --- | --- | --- |
| `UserModeExecBlock` | 1.1 | share-mode-0 独占句柄挡 `CreateProcess` 与模块加载 | 是（reconcile 清空重下发） |
| `UserModeNetworkBlock` | 1.2 | WFP `ALE_AUTH_CONNECT_V4` BLOCK 过滤器 | 是（纯会话内，config 唯一权威） |
| `OccupiedFileAccess` | 1.5 | 备份特权绕 DACL 读/删 + RstrtMgr 报出占用者 | 不产生持久状态 |
| `UserModeProcessContainment` | 2.1–2.3 | 可逆冻结 + 不可逆断子 + 六级处置阶梯 | 冻结是；**断子不是** |
| `SystemHardening` | 3.1–3.5 | 跨重启拒绝执行 ACE、注册表 DENY、即时回滚、只读体检 | 是（均有配对撤销） |

---

## 实测机制事实（全部本机测得，可直接引用）

### 文件与执行
- share-mode-0 句柄挡 `CreateProcess`（winerr **32**）与 DLL 加载；**可以给正在运行的映像加锁**
  （加载器建完 image section 就关句柄，保护运行中 exe 的是 `MmFlushImageSection`，读从未被挡）
  → 顺序必须「**先加锁再 kill**」，不是先 kill 再锁。
- 加锁期间改名/删除/复制全被拒；**没有更温和的共享模式**（共享检查把 `FILE_EXECUTE` 归进读一类）。
- 文件 `DENY Everyone:(FILE_EXECUTE)`：执行 → winerr **5**；**读取不受影响**（因此不像 share-mode-0
  那样妨碍自己的隔离）；可撤销；**DENY 压过 ALLOW**（补 `SYSTEM:(F)` 后执行仍被拒）；
  **按文件不按路径**，复制一份即可绕过（副本不继承 ACE）。
- 备份语义（`SeBackupPrivilege` + `FILE_FLAG_BACKUP_SEMANTICS`）**只对 ERROR_ACCESS_DENIED(5) 有效，
  对共享冲突 32 无效** —— 共享访问由 I/O 管理器每次打开都查，用户态无特权可豁免。
- RstrtMgr `RmGetList` 先返回 234(MORE_DATA)+needed，再按量取。

### 进程
- Job `ActiveProcessLimit=1`：已在运行的进程**可以**被塞进新建 Job；命中限制时子进程创建失败
  **winerr 1816 ERROR_NOT_ENOUGH_QUOTA**；目标已在别的 Job 里时嵌套仍成功（Win8+）；
  **关掉我方 Job 句柄后限制依然生效**；**没有任何 API 能把进程移出 Job**。
  → 后两条决定了断子**不可撤销**，只能用在「反正要结束该进程」的路径上。
- 竞态窗口实测（gate2）：从第一次恶意写入到收容生效，**0.499 秒内 20 次写全部落地**。
  这就是无驱动部署实际承受的损失量，只有内核回调路径能让它为零。

### 网络
- WFP 拦下 connect 立刻返回 **WSAEACCES(10013)**，不可达是 timeout → 精确判别式；
  靶子用 RFC 5737 TEST-NET-3（`203.0.113.0/24`）零附带影响。
- `FWPM_CONDITION_IP_REMOTE_ADDRESS` 在 V4 层用 `FWP_UINT32` 且要求**主机字节序**。

### 注册表
- `DENY Everyone:(SetValue)` 生效后写值失败 winerr **5**，移除后立刻恢复；
  但**必须用带 `ChangePermissions` 的句柄打开键**才能改 DACL —— 用只读句柄去改会抛异常，
  而后续写入测试会「成功」，看上去像 deny 无效，实际是 ACE 从没被加上（第一轮探针整条作废）。
- **注册表安全描述符在「键」上不在「值」上** → DENY ACE 做不到「保护 Run 下某一个值、
  同时让 Run 本身可写」。故 3.2 只用于恶意独占键，Run 这类共享键交给 3.1 监视回滚。

### ETW
- 事件 3 = ThreadStart，`EVENT_HEADER.ProcessId` = 创建方，EventData `ProcessID` = 线程归属。
- 误报源三个：子进程初始线程也归创建方、PID 4 内核线程、csrss 的 CtrlRoutine。
- 事件 5 = ImageLoad，`ImageName` 是 `\Device\HarddiskVolumeN\...` 需归一；
  5.5 秒内 161 条全在系统目录 → 「非系统目录」过滤挡掉 100%。
- Kernel-Process 在一个 ETW 会话只能 enable 一次 → `0x10|0x20|0x40` 必须合并进同一掩码。

---

## 修掉的既存缺陷（不是本项目新增功能，而是原本就坏的东西）

1. **勒索蜜罐整维是死的**。服务是 LocalSystem，`QStandardPaths` 与 `%APPDATA%` 都解析到
   `C:\Windows\system32\config\systemprofile\`，该目录下没有 Documents/Desktop/Pictures，
   于是 `deployCanaries` 的 `if (!exists) continue` 跳过全部 → `canaryFiles_` 恒空 →
   `addCanaryFile` 从未被调用 → 「canaryHit 无条件 Block + 100 分」永远不可能成立。
   而且 0 投放时原实现一行日志都不打，与正常运行完全无法区分。
   修法：从 `ProfileList` 枚举真实用户配置文件；0 投放时强制 warning。
2. **`bindEtw` 漏绑 4 个键**（`KernelRegistry` / `KernelFile` / `PerProcessRegPerMinute` /
   `PerProcessFilePerMinute`）—— appsettings 里写着 true 却是死配置。
3. **`addBlockedIp` 有 4 处定义、0 个调用者**；真正喂内核 IP 黑名单的 `BlockedRemoteEndpoints`
   只在 `DriverEventSource::pushInitialConfig` 下发 → 无驱动时部署方配的出站黑名单完全无效且无提示。
4. **段 7.3 三条 Temp-DLL 侧载规则从来不可能命中**（6b）：`unsignedOnly()` 判的是宿主签名，
   而白加黑的宿主必然是签名的。同一个错误还在 `InjectionAnalyzer` 与 `RemoteControlAnalyzer`
   里各有一份（后者判 IM 宿主签名，微信/QQ 恒为签名 → 整条规则永久空转）。
5. **合成 PID 被当成真实处置目标**。`kSyntheticActorPid = 0x0B00000 = 11534336` 是归因失败时的
   占位值，注释写着「不结束进程，不存在误杀风险」—— 但诱饵命中是无条件 Block，流水线照常走到
   `killMalicious`。后果：`banProcess(11534336)` 把一个不存在的 PID 写进内核封禁集（它是 4 的倍数，
   完全可能是将来某个真实进程的 PID）；`waitForExit` 对不存在的 PID 按「已退出」处理，于是整条
   路径以一行「恶意进程终结」收尾。修法：核对进程快照，不在就中止并明说没有可结束的进程。
6. **「已封禁主体，其行为仍被内核全维拒绝」在无驱动时是假话**。`banProcess` 是内核能力，
   `EventSource` 默认实现直接 return false。原实现丢弃返回值后无条件宣称封禁成功 ——
   恰好出现在最需要说实话的地方（杀不掉）。修法：接住返回值，按实际拿到的手段分别陈述。
7. **产品把自己的勒索诱饵当恶意释放物隔离**（0.5 实测同一次触碰 3 次）。诱饵天生满足
   「用户可写落地区里的一个文档」，位置护栏没错，缺的是「这个文件是我们自己放的」这条信息。
8. **加白对账只挂在「用户点加白」那一下**，而两份内核名单都跨重启 → 上次运行钉进去的条目
   若对应路径后来成了受信目标，用户不会再点一次加白。修法：启动时也跑一次。
9. **「已降级为用户态观测」在阶段 1/2 之后变成低报**。用户态此时已有三种真实拦截手段，
   却仍被告知只有观测能力 —— 与「驱动偏旧却说行为前拦截生效」是同一类失真，方向相反。
   修法：2.5 的能力矩阵按运行时状态导出，生效与未生效两半都报。
10. **服务 DACL 体检的误报**（我自己第一版引入）：只看 `;IU)` 出现过就报未加固，而实测
    IU/SU 只有 `CC LC SW LO CR RC`，没有 WP/DC/SD —— DACL 本来就是紧的。一个只读体检报出
    不存在的问题比不报更坏：它会把人引向一次没必要、却真的会改系统的操作。
    修法：逐条 ACE 解析，只在宽泛主体真的握着 DC/WP/SD/WD/WO 时才报。
11. **每用户的自启动持久化完全不在监视范围**（原「仍待跟进」第 1 项，已修）。
    `autorunRegLocations()` 里那 4 条 `HKEY_CURRENT_USER` 在 LocalSystem 服务里解析到
    S-1-5-18。这一处比第 1 条更隐蔽：HKCU 路径不会报错，它只是安静地读了一个几乎永远是空的
    键，看起来和「这个用户没有可疑自启动项」一模一样。
    修法：枚举 `HKEY_USERS` 下已加载的 hive（跳过 `*_Classes`，但 `.DEFAULT` 与
    S-1-5-18/19/20 都保留 —— 往默认用户模板或服务账户 hive 写 Run 项同样是持久化手段），
    `RegLoc` 拆成 `sub`（打开用）与 `display`（基线 keyId 用）两个字段。
    原来按固定 rootName 拼 keyId，两个用户的同名键会互相覆盖基线，那会产生
    「另一个用户装了软件 → 这个用户被报新增项」。每轮重新枚举，否则漏掉服务启动后才登录的用户。
    **实测**：监视键数 8 → **29**（机器 5 + 6 个已加载 hive × 4）；写入真实用户 hive 后
    `[Behavior] 检测到自启动注册表变更:HKU\S-1-5-21-…\…\Run\BulwarkHkcuProbe`，
    修复前的构建产生不出这一行。同一次写入新维度给 40 分（解析出了目标程序），
    内核原始路径只给 16 分。
    覆盖边界：只覆盖**已加载**的 hive。未登录用户的 `NTUSER.DAT` 不挂在 `HKEY_USERS` 里，
    要覆盖得 `RegLoadKey` 挂载 —— 对几秒一轮的轮询过于侵入，刻意不做；实际影响很小，
    他的 Run 项要到登录时才执行，而那时 hive 已加载。
12. **2.5 的能力矩阵在阶段 3 落地后变成低报**（我自己造的第二个同类错误）。
    那张表写在阶段 3 之前，「注册表写入阻断」一行的边界文字是「无驱动时不存在（用户态只能
    事后回滚）」—— 当时回滚只是个假设。3.1 真做出来并接上之后，表里**仍然没有它的行**，
    于是能力表把实际拥有的手段说少了，和它当初要修的那句「已降级为用户态观测」一模一样。
    这说明「新增能力必须同步更新能力表」需要是一条纪律，而不是记性。
    修法：拆成「注册表写入阻断（写入前）」与「注册表持久化即时回滚」两行（写不进去 vs
    写进去再还原是两件事，合并会把能力说高），另加「跨重启的执行阻断」一行；
    两项的 `inForce` 经注入探针取**运行时状态**（配置说开而监视线程没起来必须报假），
    自保护那行也补上「服务 DACL 收紧不是自保护的等价物」。
13. **能力表根本没有可观测路径**（查第 12 条时才发现，同样是我自己造的）。
    `protectionSummary()` 只在 `ipc.settingsRequested` 里被用 —— 那是**UI 主动来问才会跑的
    回调**。UI 没运行（无人值守的机器，或者 UI 正好被恶意软件杀掉）就没有任何地方记下它，
    事后也无从核实；写验证脚本时才暴露：日志里根本搜不到这张表。
    这与 0.4 当初要修的「设置页一行实时派生的文字、服务重启即消失」是同一个毛病。
    修法：把能力集写进 0.4 那条 `KernelProtectionState` 审计记录（新增 `capabilities` 数组
    + `protectionTierDetailed` 三档档位，旧 `protectionTier` 字段保留以兼容按 `"Wmi"` 筛的
    用法），并单独打一行人类可读摘要。那条审计记录存在的理由本来就是「出事后第一个要回答的
    问题：那会儿到底有没有内核前拦」—— 只写 `connected` 只能回答一半，驱动没连上时当时到底
    有没有独占句柄、有没有 WFP 出站封禁、回滚开着没开着，决定了那段时间的暴露面差别很大。
    **实测**（同一个二进制，只翻开关）：
    `生效 7/13 个维度:…;未生效:进程创建前阻断、命令行硬拦、注册表写入阻断(写入前)、
    注册表持久化即时回滚、跨重启的执行阻断、自身进程/文件自保护`
    → 打开 `RegistryInstantRollbackEnabled` 后变成 `生效 8/13`，回滚那一项移到生效侧。
    同一二进制报出两种状态，这才排除了「硬编码为真」。
14. **`applyRegHardening` 在无驱动时是彻底的 no-op 且一行日志都不打**。
    `hardenRegistryKey` 是内核能力，而那句成功日志只在 `n>0` 时打 —— 所以 EventSource=Wmi
    时的真实情况是：清理完持久化 → 反重建一条都没下发 → 日志里连一行「没做到」都没有，
    「清理→守护进程秒级重写」那个竞态完全敞开而排查的人看不出异常。与第 3 条同类。
    修法：接住返回值，未受理的走用户态补位并**按键的性质分工**——
    共享键（Run 等）下的单个值走 3.1 即时回滚（注册表 ACL 在键上不在值上，DENY 做不到只保护
    一个值）；恶意**独占**键走 3.2 的 DENY ACE（写都写不进去，比写进去再还原更彻底）。
    补位受 `RegistryInstantRollbackEnabled` 约束，但**关掉时必须把「没做到」说出来** ——
    沉默才是这段代码原本真正的问题，而不是能力缺失本身。

---

## 各阶段门禁结果

| 门禁 | 结果 |
| --- | --- |
| 阶段 0（gate0） | 改动范围 +969/−46；三份快照零漂移；ImageLoad 冷启动压测 delta +0.45 个百分点、落地区过滤器放过 0 条 |
| 阶段 1（gate1） | +1296/−66；`cpp/tests/data` 零漂移；`Worker.cpp` diff 不含我的任何标识符（约束 8） |
| 6b（snap6b） | golden 差异逐条解释；`--check-ruleset` 1004 条唯一 1004 个；chain_table 零漂移 |
| 阶段 2（gate2） | ctest 3/3；snapshot 39/0；竞态窗口 20 次写 / 0.499s；chain_table 零漂移 |
| 阶段 3（gate3） | DACL 误报已消除且 RunAsPPL 仍正确报未加固；10 个新文件齐；ctest 3/3；snapshot 39/0 |
| C1 每用户自启动（verify_hkcu） | 监视键 8 → 29；写入真实用户 hive 后 `[Behavior] 检测到自启动注册表变更:HKU\S-1-5-21-…` —— 修复前的构建产生不出这一行 |
| 能力表（verify_caps） | 13 个维度齐；同一二进制只翻开关即 7/13 → 8/13，证明 `inForce` 读运行时状态而非硬编码 |
| 文档自检（doccheck） | 查出本文件编号错序 2 处、配置漂移数字写错、脚本清单不全 —— 均已修 |
| K2 降级 Toast（verify_k2） | 卸驱动瞬间 UI 可见顶层窗口 1 → 2（新窗口即 toast），同刻服务日志给出降级 + 能力摘要；首次设置推送不弹 |
| 遗留配置键（mergelegacy） | 5 个键逐一证明与内置默认相等后合入，拒绝数 0；live 16373 → 19181 字节，漂移归零 |
| 3.3/3.4 确认闸（verify_final） | 开关置 true 且现状已达标时**跳过不重写**；`RunAsPPL` 刻意留 false，未对本机施加 |

---

## 诚实的能力边界（必须随功能一起交付）

- 阶段 1/2 的**一切都不跨重启**：独占句柄、WFP 动态会话、冻结、Job 收容全随服务进程消失。
  唯一跨重启的是 3.5 的 ACE。
- **冻结不是拦截**：它买到的是「决定期间不再变坏」，已经做过的事不回滚。
- **断子不可撤销**，所以只用在即将结束该进程的路径；等用户裁决一律用可逆的冻结。
- **3.5 按文件不按路径**，复制一份即可绕过。
- **3.4 不是自保护**：有管理员权限的恶意软件仍能改回 DACL。真正的自保护在内核 SelfGuard，
  无驱动时没有等价物。
- **3.3 必须写 `RunAsPPL = 2` 而不是 1**：1 会写进 UEFI 变量，之后删注册表值也关不掉。

---

## ⚠ 本次会话末尾发现的服务崩溃（必须先读这一节）

**现象**：`bulwark_service.exe` 以 `0xC0000374`（`STATUS_HEAP_CORRUPTION`）崩溃，
故障模块 `ntdll.dll`，退出码 1067。2026-09-30 18:31–18:47 之间崩了 8 次，
分属 **5 个不同的崩溃桶** —— 这是内存破坏的典型表现：越界／悬垂发生在一处，
却在之后某次无关的堆操作上才炸，所以每次栈都不一样。

**责任归属（实测，不是推断）**：WER 报告里有 **3 份早于今天**（2026-08-07 ×2、2026-08-15），
所以这个缺陷**不是本次会话引入的**；但今天 12 分钟内崩 8 次的频率显然是本次会话
（尤其 18:30/18:31 那次部署之后）把它从罕见推到了常发。两件事都要如实说：
既不能把一个既存缺陷记成自己的新 bug，也不能拿「它本来就有」当作不追的理由。

**已修掉的三处（均可由代码审查证明是错的，与崩溃的因果关系尚未最终证实）**：
1. `EventSourceCoordinator` 用两个 `std::function<bool()>` 持有捕获 `&hardening` 的 lambda，
   而 `hardening` 在 `main` 里声明**在 coordinator 之后** → 析构时它先死，协调器还活着，
   关停路径上任何一次能力查询都在调用捕获了已死对象的 lambda。**这是确定的悬垂**。
   改成两个普通 `bool` 由 main 推进来：没有捕获、没有生命周期耦合。
2. `regReadString` 把第一次 `RegQueryValueExW` 得到的 `cb` 直接复用给第二次调用。
   那个参数是 **in/out**：传进去是容量、传出来是实际长度。两次之间那个值完全可能被别人
   改长（自启动键正是恶意软件与安装程序都在写的地方），此时第二次会按新的更大长度写进
   只够旧长度的缓冲区 —— **越界写堆**。现在每次都重新告知容量并对返回长度做上界裁剪，
   且按显式长度构造 `QString`（REG_SZ 允许没有终止符）。
3. `readAutorunValues` 把 `ERROR_MORE_DATA` 与 `ERROR_SUCCESS` 一起放过，然后拿 `nameLen`
   去构造 `QString`。但 `RegEnumValueW` 在该错误码下**不保证回填**那个长度
   （与 `RegQueryInfoKey` 不同，它不返回所需长度），于是会按一个不可信的长度读一整片
   **未初始化**的 32KB 栈缓冲。现在跳过该条并把缓冲区初始化。
   注：本项目把监视键从 8 个扩到 29 个（缺陷 11），正是这条从「几乎踩不到」变成「常踩」的原因。

**当前状态**：修完后在「反复写每用户 Run 值 + 触碰诱饵」的负载下持续观察。
上一版在启动后 **5 秒**就死；修完后的观察结果见 `crashwatch.log`。

**如果它还在崩，下一步该怎么做（不要继续靠读代码猜）**：
- 崩溃转储在 `C:\ProgramData\Microsoft\Windows\WER\ReportArchive\AppCrash_bulwark_service._*`，
  用 `cdb -z <dump> -c "!analyze -v; k"` 一条命令就能拿到真实栈，比任何推理都快。
- 堆破坏要定位到**写坏的那一刻**而不是崩溃点，开 PageHeap：
  `gflags /p /enable bulwark_service.exe /full`（查完记得 `/disable`）。
- 二分范围：本次会话服务侧改动集中在 5 个新组件 + `Worker.cpp` / `main.cpp` /
  `UserModeBehaviorSource.cpp` / `EventSourceCoordinator.cpp`。
  最可疑的是每几秒就跑一次的 `scanRegistryDelta`（键数 8→29）。
- **不要在崩溃定位清楚之前把本次会话的改动提交上去。**

## 仍待跟进

1. ~~`autorunRegLocations()` 的 HKCU 缺陷~~ —— **已修并实测，见上面第 11 条**。
2. ~~同一次诱饵触碰产出 4 条拦截 + 3 次足迹清理，缺去重~~ —— **已修**。
   根因不是逻辑重复：Windows 对一次写会生成多个变更通知（打开／写／改时间戳／关闭），
   `QFileSystemWatcher` 把它们逐个递上来，而每一条都走完整的「无条件 Block + 结束进程树 +
   足迹清理」。后果三层：日志里同一件事刷 4 遍把真实事件淹掉、清理器对同一批文件重复隔离、
   处置阶梯被重复施加。
   修法：`onFileChanged` 按诱饵路径去重，窗口 **3 秒**。窗口刻意取短 —— 真正的勒索是在
   **多个**文件上连续加密，会持续触发别的诱饵、也会在窗口外再次触发这一个，所以短窗口不会
   把一波真实加密压成一条。压制时记日志（每 3 条一行，避免它自己变成新噪声源），不做静默合并。
3. **live `appsettings.json` 缺 14 个键，其中 9 个是本项目新增的全部配置键**（实测，
   见 `doccheck.py`；此前凭记忆写的「缺 5 个 + 本项目 5 个」是错的）。
   源模板 44 键 / live 31 键。缺的 9 个本项目键：
   `UserModeExecBlockEnabled` `UserModeExecBlockMax` `UserModeNetworkBlockEnabled`
   `UserModeNetworkBlockMax` `UserModeContainmentMax` `UserModeFreezeTtlMs`
   `UserModeFreezeOnDetect` `FileDenyExecuteEnabled` `RegistryInstantRollbackEnabled`。
   此前就缺的 5 个：`AbusedSignerThumbprints` `AbusedSignerPublishers`
   `EventDrainIntervalMs` `InlineReputationBudgetMs` `SelfHostedTls`。
   反向多出 1 个：`MemoryProtectionVtVerifyPerHour`（live 有、源模板没有）。
   **影响**：这台机器上本项目的每一项功能都跑在内置默认值上，部署方一个都调不了 ——
   包括那两个「用户确认型」开关，等于它们目前没有打开的途径。
   成因不是遗漏而是工具边界：`build2.py` 只拷 exe 不拷配置，只有 `rebuild_full.ps1` 才部署
   appsettings。
   **本项目那 9 个键已由 `mergekeys.py` 合入 live 配置**（连同解释每个开关代价的
   `_comment_*` 一起 —— 一个开关的代价只写在源模板里等于在真正要看它的地方没写）。
   合并是行为中性的：每个值都与代码内置的默认值相同，变的只是部署方现在能调了，
   包括那两个「用户确认型」开关 —— 在此之前它们根本没有打开的途径。
   live 10538 → 16373 字节，原文件逐字备份在 `probe\dist_appsettings.premerge.bak`。
   **刻意没有合并那 5 个此前就缺的键**：它们的模板值可能与内置默认不同，照搬会改变行为，
   那是独立决定，不该作为我这次改动的副作用发生。
4. ~~K2 降级 Toast 被 UI 工作线阻塞~~ —— **已做，而且那个「阻塞」判断本身是错的**。
   理由原先写的是「需要新增 IPC 消息类型，涉及 8 个全都有未提交改动的文件」。实际不需要：
   服务在每次内核状态迁移时【已经】`sendSettings()`（0.4 的 `recordKernelState`），
   而 `MainWindow` 的 `settingsReceived` 槽正好收到它、并且已经在存 `kernelConnected` 与
   `kernelStatus`；`ToastNotifier::showInfo(heading, detail, lifetimeMs)` 也早就存在。
   所以 K2 只是「在那个槽里认出状态发生了变化」——**零新增 IPC 表面、零新增消息号、
   不碰 `IpcMessageType.h`**，改动全在 `MainWindow.cpp` 一处。
   三点做对了才有用：① 只在**迁移**时提示（不比较前值的话，无内核的机器每次设置推送都弹，
   几分钟后用户就学会无视它，等于把通知作废）；② **首次收到设置不提示**（那是启动时的既有
   状态，不是刚发生的变化，否则每次开 UI 都弹一条假「刚刚降级」）；③ 文案带 `kernelStatus`，
   它现在装的是 2.5 的能力矩阵摘要，所以用户看到的是**还剩什么、少了什么**，
   而不是干巴巴一句「驱动掉了」。降级那一侧给 12 秒、恢复给 6 秒。
   刻意不看静默模式：静默的语义是「不要为决策打扰我」，这是告知能力变化、不是提问。
5. 3.5 的 apply 路径未在真实恶意样本上端到端跑过（ACL 机制本身已单独实测）。
6. 2.4 的诱饵清理豁免护栏已实现，但两轮验证里都没被触发到（诱饵未进清理集）。
7. ~~3.3 / 3.4 的 apply 没有 UI 入口~~ —— **已补，用配置开关作为确认入口**。
   新增 `ApplyLsaRunAsPpl` / `ApplySelfServiceDacl`，默认 false。
   关键认识：**「用户确认」不必须是一次点击**。把这个键从 false 改成 true 本身就是一次
   显式、留痕、可回退的确认，而且它比弹窗更适合这两件事 —— 它们改的是跨重启的机器状态，
   本该由管理配置的人决定，而不是由碰巧坐在这台机器前的人点一下。
   两项都在每次启动时**先看只读体检的结论**，已达标就跳过并记一行，不重复写系统。
   （`RunAsPPL` 的值恒为 2，代码层面不接受 1。）
8. 3.2 的 `denyRegistryWrite` 现在有调用方了（`applyRegHardening` 的用户态补位），
   但还没在真实的「恶意自建独占键」上触发过 —— 本机测试里 `hardenedRegTargets` 全是
   Run 下的值，都走了 3.1 回滚那一支。

---

## 复现用的脚本

全部在 `%TEMP%\bw_nodrv\probe\`：

目录下共约 60 个 `.py`，下面列的是**产出过本文件引用的证据**的那些；其余是被它们调起的
一次性辅助件（`job_victim.py` `g2_racer.py` `g1_trigger.py` 之类的靶子进程）与作废的探针。

- 探针（先量后写）：`rt_probe.py`（ETW ThreadStart 语义）、`lock_probe.py` `lock_probe2.py`
  （share-mode-0；`lock_probe3/4` **已作废**，结论被 `lock_probe5.py` 推翻）、
  `occupy_probe2.py`（备份特权只对错误 5 有效）、`job_probe.py`（Job 断子五问）、
  `harden_probe.py`（文件 DENY 执行）、`reg_probe3.py`（注册表 DENY；第一轮 `harden_probe`
  里那半**整条作废**，句柄没带 `ChangePermissions`）、`kf_probe.py`（Kernel-File 频率）
- 构建：`build2.py`（只编 service + ctest + 拷 exe —— **不拷 appsettings**）、
  `build3.py`（service + **ui** + snapshot 三个目标 + 部署两个 exe —— 改了 `cpp/ui` 就必须用它，
  用 build2 会把 UI 留在旧二进制上，与教训 9 同一类假绿；它的部署段包 try 并在失败时列出占用者，
  因为第一版让异常逃出去，日志从 ctest 直接跳到收尾而 `build_ok` 仍说 True）、
  `snap6b.py`（编 `bulwark_snapshot` + verify A/B/record/verify C + ctest）
- 验证：`verify0b.py` `verify_nodrv.py` `verify_k1.py` `verify05.py` `close05.py`
  `verify11b.py` `verify12.py` `verify14.py` `verify2.py` `verify2b.py` `verify3.py`
  `verify_hkcu.py`（C1）、`verify_caps.py`（能力表两相状态）、
  `verify_k2.py`（K2 —— toast 是窗口，故用「UI 进程可见顶层窗口数 +1」做结构性断言，
  比截图可靠；同时分析 5 个遗留配置键的中性）、
  `verify_final.py`（诱饵去重 + 3.3/3.4 确认闸）
- 门禁：`gate0.py` `gate1.py` `gate2.py` `gate3.py` + `check6b.py`（6b 三例裁决）
- 自检与杂项：`stale.py`（扫「X 不存在／未修」这类会过期的断言）、
  `doccheck.py`（查本文件编号顺序 + 实测配置漂移 + 脚本清单对账）、
  `leftover.py`（从 git 与并行 spec 读出真实剩余项）、`final.py`（收尾状态）、
  `noload28.py`（清 FileNoLoad 探针残留）、`scan2.py`（处置代码盘点）、
  `mergekeys.py`（把本项目 9 个配置键合入 live appsettings —— **这个脚本改过系统状态**，
  备份在 `dist_appsettings.premerge.bak`）、
  `mergelegacy.py`（再合入 5 个此前就缺的键，**逐键证明与内置默认相等**，证不了就拒绝 ——
  同样改过系统状态，备份在 `dist_appsettings.prelegacy.bak`）、
  `gs.py`（中文路径下的 grep 替代）、`driftdiag.ps1`（ASCII-only 的漂移检查复测）

### 构建与验证的环境事实

- 服务实际跑的是 `cpp\dist\bulwark_service.exe`；只 `cmake --build` 不生效。
- **`build2.py` 只编 `bulwark_service`** → 用它验证快照类改动会得到**假绿**
  （`bulwark_snapshot.exe` 没重编，跑的是旧工具+旧语料）。
- 运行 `bulwark_snapshot.exe` 前必须把 `C:\Qt\6.8.3\msvc2022_64\bin` 加进 PATH，否则 0xC0000135。
- git 必须 `git -c safe.directory=*`。
- **驱动加载时测试脚本无法写入 `C:\ProgramData\Bulwark` 与 `cpp\dist`**（内核 SelfGuard）
  → 要改配置必须先停服务 + `fltmc unload Bulwark`。
- `service.log` 是 **UTF-8**（不是 GBK），按字节偏移增量读。
- dist `appsettings.json` 的设置项**在一个根对象下**，不在顶层 —— 按顶层 key 找会得到
  「没有这个块」这种与文件内容矛盾的结论。

### 写测试脚本的教训

1. 路径含 `$` 或中文一律 **argv 直传**（`-Command` 字符串会把 `$Bulwark_` 展开成空）。
2. `cmd /c` 与 `.bat` 都过不了中文路径 → 要写文件就用 Python 直接写。
3. 「写入是否真的发生」必须查 size/mtime，不能只看退出码。
4. ctypes 调 Win32 必须显式设 `restype`/`argtypes`（`GetCurrentProcess()` 未设 restype →
   x64 上 -1 伪句柄被截成 32 位 → winerr 6）。
5. 用真 `.exe` 做「必须存活」的断言会被本产品自己隔离掉 → 改用 `.txt` 断言「读被拒」。
6. 同一脚本不要 `execute_pwsh` + 后台进程各起一份（并发抢服务、日志互相覆写）。
7. C++ 里局部变量**不能叫 `slots`**：Qt 的 `qobjectdefs.h` 把它定义成空宏，
   `std::vector<T> slots;` 会被展开成 `std::vector<T> ;`，报出一串看不出所以然的 C2059。
