# 在线推送更新系统 v2 · 设计

> 现状与缺陷见 `requirements.md`,任务拆解见 `tasks.md`。
> 本文用 **U1-U10** 编号,`tasks.md` 按这些编号挂接。

---

## 0. 全景

```
                     发布机(私钥只在这里)
                  publish-release.ps1
                      │
     ┌────────────────┼─────────────────┐
     │ release.json   │ release.json.sig│  blobs/<sha256>
     └────────────────┴─────────────────┘
                      │ scp(blob 先、清单最后)
                      ▼
         bulwark-intel(只分发,不签、不改、不算)
         GET /v2/update/manifest  → 原样回签名清单
         GET /v2/update/watch     → 长轮询,只回 {changed, sequence}
         GET /v2/update/file/<sha256>
         POST /v2/update/report   → 发布健康度(无机器标识)
                      │
                      ▼
        bulwark_service.exe(SYSTEM,SelfGuard 放行的那个主体)
         UpdateCoordinator  ── 调度:watch / 抖动轮询 / 退避
         ReleaseManifest    ── Ed25519 验签 + 序号 + 过期 + 灰度
         PayloadFetcher     ── 内容寻址下载 + 续传 + 解压上限
         AppInstaller       ── 安装目录 + System32\drivers 双落点
         ContentInstaller   ── %ProgramData%\Bulwark\content,热生效
         UpdateStateStore   ── update-state.json,崩溃可恢复
         RestartOrchestrator ─ 自重启 + 自验证 + 自回滚
                      │ IPC(旧消息照发,新消息追加)
                      ▼
         bulwark_ui.exe ── UpdateDialog(读状态,不做决策)
         bulwark_guard.exe ── 看守:只在应用期间存在
```

**不变量**:服务器只是镜像。它既不持有签名私钥,也不决定灰度比例,也不再重算哈希。
把它整台拿下,最多做到「不给更新」—— 而那一点由客户端的序号单调性 + 清单过期时间察觉。
这是现状唯一真正缺的那块(`requirements.md` 2.3),其余判据照搬。

---

## U1 · 签名发布清单

### 1.1 文件

```
release.json       规范化 JSON:UTF-8 无 BOM、键名字典序、分隔符 ","/":"、无多余空白、\n 行尾
release.json.sig   Ed25519 分离签名,base64,签的是 release.json 的【原始字节】
```

签原始字节而不是重新序列化后的对象:任何「解析再比较」的方案都会在解析器差异上出问题,
而这里的解析器两端不同(PowerShell 出、Qt 入)。客户端先验字节、再解析。

### 1.2 结构

```jsonc
{
  "schema": 2,
  "sequence": 42,                       // 单调递增,每次发布(含急停/召回)都 +1
  "channel": "stable",                  // canary | beta | stable
  "issuedUtc":  "2026-10-01T04:00:00Z",
  "expiresUtc": "2026-10-15T04:00:00Z", // 到期即不可信,发布机定期重签
  "version": "1.0.4",
  "label": "1.0.4",
  "notes": "…",                         // markdown 子集,见 1.5
  "rollout": { "percent": 5 },          // 0..100,签在清单里
  "rollbackTo": null,                   // 非空 = 这是一次召回,见 U4.4
  "app": {
    "requiresDriverProtocol": 7,        // 这组 exe 需要的内核协议版本
    "driverProtocol": 7,                // 随包 .sys 提供的协议版本
    "files": [
      { "path": "bulwark_service.exe",      "action": "replace",
        "size": 2495224, "sha256": "c32b…", "pe": true },
      { "path": "platforms/qwindows.dll",   "action": "replace",
        "size": 1522176, "sha256": "9a01…", "pe": true },
      { "path": "Bulwark.sys",              "action": "replace",
        "size": 52600,   "sha256": "4f5b…", "pe": true, "kernel": true },
      { "path": "networkinformation/qnetworklistmanager.dll", "action": "add",
        "size": 31232,   "sha256": "77ae…", "pe": true },
      { "path": "legacy_helper.dll",        "action": "remove" }
    ]
  },
  "content": {
    "files": [
      { "path": "rules/builtin-950.pack", "action": "replace",
        "size": 182400, "sha256": "11bb…",
        "encoding": "zstd", "plainSize": 806912, "plainSha256": "22cc…" }
    ]
  }
}
```

### 1.3 钉死的公钥

`UpdateTrust.h` 加一组 Ed25519 公钥,与指纹**同一套规矩**:编译期钉死,
配置里的 `Update.AllowedSigningKeys` 只能**追加**(证书/密钥轮换期同时接受新旧两把),
永远替换不掉内置项。原因与指纹那条一字不差:做成可替换等于改一行配置就能换掉整条信任链,
而配置文件是攻击者拿到本机写权限后最容易改的东西。

```cpp
// 两把:current 在用,next 预置。轮换时先发一版同时被两把都认的客户端,再切签名密钥。
#define BULWARK_RELEASE_KEY_CURRENT "base64(32B ed25519 pub)"
#define BULWARK_RELEASE_KEY_NEXT    "base64(32B ed25519 pub)"
```

实现用 Qt 以外的最小依赖:Windows 10+ 的 BCrypt 不直接给 Ed25519,所以带一份
**公开域 ref10/TweetNaCl 风格的 `crypto_sign_verify_detached`**(约 400 行 C,无堆分配、无依赖)。
刻意不引 OpenSSL / libsodium:为一个验签函数给安全产品加一条新的供应链依赖不划算,
而只验签不签名的那一半代码量小到可以逐行审。

### 1.4 验签顺序(任一不过即整份放弃)

1. HTTPS(非 https 一律拒,回环例外仍按 `QUrl::host()` **精确比较**,不用 `contains` ——
   这个坑 `UpdateService.cpp:95` 已经踩过一次,别回退);
2. `release.json.sig` 对 `release.json` 原始字节验签,公钥命中钉死集合;
3. `schema` 必须是已知值(未知 schema 当不可信,不猜字段);
4. `sequence > lastSeenSequence`(持久化在 `update-state.json`),**等于**也拒 ——
   等于说明有人把旧清单重放了一次;
5. `expiresUtc` 未过期。过期时的措辞必须指向原因:
   「更新元数据已于 X 过期 —— 服务器可能长期未发布,也可能有人把你冻结在旧版本」;
6. `channel` 等于本机配置的通道;
7. 每个 `files[].path` 过路径策略(U3.2);`sha256` 必须是 64 位十六进制、`size > 0`;
8. 版本比较:`app` 段非空时 `version` 必须比本机新(沿用 `version::isNewerThanCurrent`),
   **除非** `rollbackTo` 非空且等于目标版本(U4.4)。

第 4、5 条是现状完全没有的两道,也是「冻结攻击」唯一的发现手段。
第 5 条要求**发布机定期重签**:即使没有新版本,每 ≤14 天也要生成一份新的
`release.json`(只改 `issuedUtc`/`expiresUtc`/`sequence`)。这件事**不能**让服务器做 ——
服务器没有私钥,这正是我们要的。

### 1.5 notes 的渲染

清单签名之后 `notes` 已经可信,但**仍然**:
- `QTextBrowser::setOpenExternalLinks(false)`(现状是 `true`);
- markdown 只保留标题/列表/强调/行内代码,链接一律降级为纯文本。

理由:这块区域是给用户读「这次改了什么」用的,它在一次会替换内核驱动的操作旁边。
可点击外链在这里没有任何正当用途,而它恰好是最好用的社工入口。少一个能力就少一类问题。

---

## U2 · 推送:长轮询 + 抖动保底

### 2.1 服务端

```
GET /v2/update/watch?channel=<ch>&have=<sequence>&wait=<秒,≤120>
  → 200 {"changed": true,  "sequence": 43}      有新发布,立刻返回
  → 200 {"changed": false, "sequence": 42}      等到超时
  → 200 {"changed": false, "retryAfterSec": 300, "degraded": true}   闸门满,立刻返回
```

实现直接照搬 `SupportStore.wait_messages`(`app.py:1509`)的形状:
条件变量 + **2 秒一片重查**(通知可能落在「查完」和「开始等」之间,分片让漏掉的通知
最多延迟 2 秒,而不必引入一套带序号的通知簿)+ 并发闸门。

**闸门必须独立于客服那个 `SUP_WAIT`**。`ThreadingHTTPServer` 一个连接一个线程、没有上限,
两者共用一个信号量时,一次更新推送风暴会把客服会话饿死 —— 而客服是用户出问题时唯一的求助通道。
两个独立 semaphore,各自满了各自退化。

发布事件怎么唤醒:`release.json` 落地时由发布脚本 `POST /v2/update/notify`(内网/带令牌)
触发 `notify_all`;收不到也无妨 —— 文件 mtime 轮询兜底(每 5 秒 stat 一次,成本可忽略)。
两条路都有,是因为「发布脚本忘了调」和「内网不通」都会发生,而漏一次通知的代价是
全网晚几小时才知道有更新。

### 2.2 客户端调度(`UpdateCoordinator`)

| 状态 | 行为 |
|---|---|
| 启动 | 延迟 `InitialDelaySeconds`(默认 90,与 `AttackChainEngine` 同值同理由:开机那几分钟最忙、网络常常还没通)|
| 常态 | 持续 `watch`,`wait=90`;返回后立即重连 |
| `changed` | 走 U4 的取包流程,完成后回到常态 |
| 失败 | 指数退避 1m→2m→4m→…→上限 60m,每次乘 0.75~1.25 抖动 |
| 保底 | 无论 watch 是否健康,每 `PollIntervalHours`(默认 6)× 抖动 做一次完整 `manifest` 拉取 |
| 硬上限 | 每小时最多 60 次出网(watch + manifest 合计)。一个 bug 不能变成热循环打自己的服务器 |

**不再等界面**。现状之所以等(`main.cpp:1446`),是因为结论只靠管道推给界面,没界面就白做;
v2 把结论**落盘**到 `update-state.json`,界面连上时读状态即可。于是「用户从不打开界面的机器」
第一次有了更新能力 —— 这正是 `requirements.md` 2.5 要补的洞。

抖动不是美化。没有抖动,所有 09:00 开机的机器会在同一秒敲同一个端点;
服务端是 stdlib 单体,这种同步脉冲比总量更难扛。

### 2.3 限流登记

`watch` 必须进服务端已有的 `IPThrottle`,但预算要单独给:一个挂住的连接按设计就是
90 秒 1 个请求,拿信誉查询的额度去量它必然误杀。建议 `watch` 每 IP 每小时 120、
`manifest` 每小时 30、`file` 每小时 200。超限回 429 + `retryAfterSec`,客户端照退避表走。

---

## U3 · 载荷:内容寻址 + 路径策略

### 3.1 内容寻址

```
GET /v2/update/file/<sha256>
```

不再按 `<channel>/<name>` 取。三个好处:
- 去重。今天 `beta` 与 `stable` 各存一份逐字节相同的三个文件(`requirements.md` 2.6),
  内容寻址之后天然共用;
- 缓存安全。URL 即内容,可以放心长缓存(但更新载荷仍 `Cache-Control: no-store`,
  理由同现状:「更新了却拿到旧文件」是最难查的故障);
- 服务端不再做「名字 → 路径」的拼接,`_serve_update_file` 里那一大段
  正则 + realpath 兜底(`app.py:6971-6995`)整段消失 —— 路径穿越这类问题从结构上没有了。

服务端只需判断:`<sha256>` 是不是**当前已发布清单里列出的**某个 blob。
是就从 `blobs/<sha256>` 流式送出,不是就 404。

### 3.2 路径策略(本设计最危险的一处放宽,必须有单测)

要支持 Qt 插件就必须允许子目录,而一允许子目录,`..` 就成了真实威胁。
写成一个独立函数,只回「拒绝」或「规范化后的相对路径」:

```cpp
// 返回空 = 拒绝。入参按【服务器给的不可信输入】处理。
std::optional<QString> normalizePayloadPath(Kind kind, const QString& raw);
```

逐条判据:
1. 非空、长度 ≤ 128、仅 `[A-Za-z0-9._-]` 与单个 `/` 作分隔;
2. 不含 `\`、`:`、`..`、前导 `/`、连续 `//`、尾随 `/`;
3. 段数 ≤ 2。`app` 类的第一段若存在,必须命中固定集合
   `{platforms, styles, imageformats, tls, networkinformation, generic}`;
   `content` 类必须命中 `{rules, chain, ioc, hashes, ca, engine}`;
4. 文件名必须在**该版本的出厂清单**里(`app` 类,见 U7.2 生成)或符合该 content 子类的扩展名;
5. `app` 类的 `.exe/.dll/.sys` 标 `pe: true` 并走 Authenticode 校验;非 PE 一律拒
   (`app` 类目前没有非 PE 载荷,这一条留作显式表达 —— 将来放开某类非 PE 文件时,
   漏掉签名校验会是静默的,而这里会显式挡住);
6. 拼出绝对路径后 `QFileInfo::canonicalFilePath()` 再确认一次仍在目标根之下。
   第 1-5 条都是语法判据,这一条是语义兜底 —— 两种都要,因为符号链接/junction 不受语法约束。

**永不允许**(原样保留现状禁令):`appsettings.json`、`*.ps1`、`*.bat`、`*.txt`、
`unins000.exe`、任何 `app.ico` 之外的根目录新文件未经出厂清单登记者。
理由不变:配置里有用户自己填的密钥与信任目录;脚本没有签名而它们是提权执行的那一批。

### 3.3 下载

- `curl -C -` 续传;分片校验不做(SHA-256 是全文件的),但落盘大小先对一次,
  不对就从头重下(续传把错误累积下去比重下更糟);
- 每文件 3 次重试,总预算 `DownloadTimeoutSeconds`(默认 180)× 文件数,超了整份放弃;
- 下载前检查暂存卷可用空间 ≥ 3× 总载荷(下载 1 份 + 解压 1 份 + 余量 1 份),
  不够就带着具体数字拒绝,而不是写一半磁盘满;
- 非 200 必须删掉目标文件。curl 没用 `-f`,会把错误响应体写进去,留着就是一个
  长度不对的 exe 躺在暂存目录里(现状已处理,保留);
- 解压(content 的 `encoding: zstd`)**必须**同时校验 `sha256`(压缩态)与
  `plainSha256`(解压态),并以清单里的 `plainSize` 和一个客户端硬上限
  (建议 64MB)双重封顶 —— 这是 zip bomb 的唯一防线。

### 3.4 暂存目录:搬到 ProgramData

现状放 `%LOCALAPPDATA%\Bulwark\update`,注释给的理由是「ProgramData 在 SelfGuard 守护范围内,
非本产品进程写入会被拒」。那个理由属于**上一版的提权脚本方案** —— 现在写入方是服务自己,
而服务正是 SelfGuard 放行的主体。

改到 `%ProgramData%\Bulwark\update\<sequence>\`,并把它纳入 SelfGuard 守护集。
收益是把「校验通过 → 真正取用」之间的 TOCTOU 窗口**从结构上消除**,而不是靠在取用时重验来缓解。
重验仍然保留(双保险,且 `apply` 本来就要重算哈希)。

> 待确认:服务以 LocalSystem 运行时 `%LOCALAPPDATA%` 解析到
> `C:\Windows\System32\config\systemprofile\AppData\Local`,普通用户本就写不进去,
> 所以现状的 TOCTOU 描述可能只对便携包那条提权路径成立。无论结论如何,搬到 ProgramData
> 都更干净,所以不等这个结论。

---

## U4 · 应用:两类载荷、两条路径

### 4.1 content:热生效,不重启

落点 `%ProgramData%\Bulwark\content\<子类>\`,服务加载后立即生效:
规则包 → `RuleEngine` 重建;攻击链组合表 → `AttackChainEngine::applyTable`(已有);
IOC / 哈希集 → 经 `BLW_CMD_CLEAR_KNOWNBAD` / `BLW_CMD_ADD_KNOWNBAD` 下发内核(已有);
CA 包 → `ReputationCurl::ownCaBundlePath` 热切。

**新内容默认先观察再强制**:沿用 `architecture-rewrite` S11 的结论,
规则类内容包带 `enforce: false` 发一轮,只记录不改裁决,确认没冤枉正常软件再发
`enforce: true`。这不是流程洁癖 —— `AttackChainEngine` 的 `DryRun` 默认 true
就是为同一件事存在的,而随包 `appsettings.json` 把它写成了 false,
那是 `requirements.md` 里 2.3 之外的另一处隐患。

content 更新**不**要求用户确认(`AutoApplyContent` 默认 true)。
一个杀毒类产品的特征库要是得等用户点确认,它就没有存在的意义。

### 4.2 app:双落点

```
for each file in app.files:
    target = installDir / path          # 所有文件
    if file.kernel:                     # Bulwark.sys 额外一处
        target2 = %SystemRoot%\System32\drivers\Bulwark.sys
```

**这一条就是 `requirements.md` 2.1 的修复。** 现状只写安装目录,而被加载的是
`System32\drivers`,且 `stageDriverBinary()` 遇到目标存在就直接返回 —— 所以在线更新
从来没能换掉驱动。

两处都用同一套「旧的改名让位 → 新的放到原名」:

```
MoveFileExW(target,  target + ".old-<stamp>", MOVEFILE_REPLACE_EXISTING)
CopyFileW  (staged,  target, FALSE)
```

对**已加载的内核映像**同样成立:Windows 锁的是运行中映像的内容而不是目录项,改名允许。
这与 exe 那边依赖的是同一条性质,现状的注释已经实测记录过。

`action` 语义:
- `replace` —— 上面的流程;
- `add` —— 目标不存在,直接 `CopyFileW`,`parked` 记空(回滚时删掉即可);
- `remove` —— 只改名到 `.old-<stamp>`,不删;验证通过后才真删。
  `remove` 只允许作用于**出厂清单里曾经存在过的**文件名,且由发布工具 diff 生成,
  不许手写(U7.2)。

顺带修掉 `stageDriverBinary()`:不再是「存在就跳过」,而是「**哈希不一致就按上面的流程换掉**」。
它现在的语义会让任何形式的驱动更新(OTA、重装覆盖安装目录、手工替换)都悄悄失效。

### 4.3 驱动激活:默认不碰运行中的筛选器

```
DriverActivation = nextBoot(默认) | liveReload
```

**nextBoot**:文件就位即结束。新驱动下次开机加载,期间防护一秒不断,
minifilter 的装卸一次都不发生。这是默认值,因为卸载路径漏摘一个回调就是蓝屏,
而本项目的既有结论是「minifilter 的装与卸是这个项目里风险最高的动作」。

**liveReload**(用户在弹窗里显式勾选):
```
1. DriverControl::tryStop()
2. 确认真的卸了:fltmc filters 里没有 Bulwark(tryStop 的返回值不够 —— sc stop 可能回成功而筛选器还在)
3. DriverControl::ensureLoaded()
4. 握手:DriverEventSource 连上 \BulwarkPort,协议版本 == requiresDriverProtocol
5. 任一步失败 → 把 .old-<stamp> 改回原名,ensureLoaded() 装回旧驱动,再核对一次握手
6. 旧驱动也装不回来 → 写一条最高级别审计 + UI 立刻红色横幅「本机当前不受内核前拦截保护」,
   并给出一键「重启生效」。绝不静默。
```

与 `protectionFollowsUi` 的交互必须显式处理:那个开关把「界面断开」当待机触发器,
8 秒宽限期(CHANGELOG 里写明宽限期正是为在线更新替换 exe 而留)。
重启流程若跨过 8 秒,会**顺带卸掉驱动**,表现成一次莫名的防护中断。
做法:进入 `applying` 阶段即置一个 `updateInFlight` 标志,
`EventSourceCoordinator` 在该标志下不因界面断开而待机;阶段结束清标志。

### 4.4 版本方向:只许前进,召回是唯一例外

默认保留现状的硬规则:`isNewerThanCurrent` 不成立即拒。降级是一条真实攻击路径 ——
用一个**签名合法**的旧版本把已经修掉的漏洞换回来。

唯一例外:清单里 `rollbackTo` 非空、等于要装的那个版本、且带 `reason`。
因为清单有签名,攻击者造不出这个组合;而它让「发现坏版本后主动召回」变得可能。
召回在 UI 上必须**写明是回退**,并进审计。

### 4.5 整份语义

任一文件任一阶段失败 → 按相反顺序回退全部已动过的文件,`replaced = 0`,`rolledBack = true`。
「新 exe + 旧驱动」是从未测试过的组合,比不更新危险得多 —— 这条现状已有,保留并扩展到
`add`/`remove`/双落点三种新形态。

---

## U5 · 重启、自验证、自回滚

这是现状完全空白的一块(`requirements.md` 2.2)。

### 5.1 落盘状态机

`%ProgramData%\Bulwark\update-state.json`,**唯一**跨重启存活的东西:

```jsonc
{
  "phase": "verifying",          // idle|downloaded|applying|applied|verifying|ok|rollingBack|failed
  "sequence": 43,
  "fromVersion": "1.0.3",
  "toVersion": "1.0.4",
  "lastSeenSequence": 43,
  "startedUtc": "...",
  "deadlineUtc": "...",          // verifying 的看守截止时间
  "rollbackAttempts": 0,
  "steps": [ { "target": "...", "parked": "...", "action": "replace", "placed": true } ],
  "lastError": ""
}
```

每次状态变更**先写盘再动作**(write-ahead)。于是任何时刻被强杀,下一次启动都能据此判断
该继续、该回滚、还是该清理。写盘用「临时文件 + `MoveFileExW(REPLACE_EXISTING)`」,
不原地改 —— 原地改在断电时留下半个 JSON,而这个文件正是用来从断电中恢复的。

### 5.2 看守进程 `bulwark_guard.exe`

应用之前拉起,传 `--watch-update --deadline <秒>`。它做的全部事情:
轮询 `update-state.json`,`phase == ok` 就退出;到截止时间还不是 `ok`,就
① 按 `steps` 反向还原文件 → ② `sc start BulwarkService` → ③ 写审计 → ④ 退出。

为什么需要一个**外部**进程:`verifying` 失败的最坏形态是新服务根本起不来或崩溃循环 ——
那时没有任何「自己」能回滚自己。

为什么**不用**计划任务或 `RunOnce`:本产品自己硬拦 `schtasks.exe`(命令行硬拦名单),
`ThreatRemediator` 还会删 `TaskCache\Tree` 下的键 —— 走任务计划等于和自己的防护对打。
一个随包的小 exe 没有这个问题。

`bulwark_guard.exe` 必须:用同一张钉死证书签名(于是它自然落在既有信任规则与 SelfGuard 范围内)、
进 `app` 出厂清单(于是它自己也能被在线更新)、不常驻(只在应用期间存在,
一个长期运行的「能替换安装目录文件的进程」本身就是攻击目标)。

### 5.3 自重启

重启的主体必须是**产品自己** —— 这是 SelfGuard 唯一放行的主体,
也是上一版提权脚本方案走不通的根本原因。

做法:置 `phase=verifying` + 写 `deadlineUtc` + 拉起看守 → 服务以非零退出码干净退出 →
SCM 的失败恢复策略(`applyFailureActions` 已配置)在数秒后把它拉回来。
新进程启动时读到 `verifying`,知道自己是「待验证的新版本」。

界面另算:服务经 IPC 请界面自己重启(界面是普通用户会话进程,不受 SelfGuard 约束),
但**必须用户同意** —— 界面在用户眼前,替他关掉窗口是无礼的。
用户不同意就留着旧界面跑,旧界面与新服务靠 A2 的消息兼容性共存到下次打开。

### 5.4 自验证清单

新版本起来后在 `verifying` 阶段逐项核对,全过才置 `ok`:

| 项 | 不过的含义 |
|---|---|
| `appsettings.json` 解析通过 | 新版本加了必填键而老配置没有 |
| 数据目录可写 | 权限/磁盘 |
| 控制管道 `\\.\pipe\Bulwark.Control` 监听 | IPC 起不来 = 界面永远连不上 |
| `RuleEngine` 构建成功且规则数 > 0 | 规则包与新引擎不兼容 |
| 事件源启动(Driver 或 Wmi) | 防护实际没跑起来 |
| 驱动握手版本 == `requiresDriverProtocol`,或处于预期的 `nextBoot` 待生效态 | 新旧混版 |
| 自身版本 == `toVersion` | **最关键的一条**:映像其实没换成功 |

最后一条单独说:现状的发布脚本已经在发布前校验 `FileVersion == version`,
理由是「清单说 1.2.0、装上去的 exe 还报 1.1.0」会让客户端无限提示更新。
把同一条判据搬到运行时,就能发现「文件写进去了但进程还是旧的」这种更隐蔽的失败。

任一项不过 → `phase=rollingBack`,自己还原 + 自己重启;`rollbackAttempts >= 2` 则
停在 `failed`,保持旧版本运行,UI 横幅写明「新版本 X 无法启动,已回退到 Y」。
不无限重试 —— 一个安全产品反复重启比停在旧版本危险。

### 5.5 收尾

`ok` 之后:
- 删 `.old-<stamp>`;删不掉的排 `MOVEFILE_DELAY_UNTIL_REBOOT`;
- **每次服务启动**顺带扫一遍安装目录与 `System32\drivers`,清掉 7 天以上的 `*.old-*`
  (现状只靠重启队列,队列没生效就永久堆着,而那里被 SelfGuard 守着别人动不了);
- 改 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Bulwark\DisplayVersion`
  与 `HKLM\SOFTWARE\Bulwark` 的安装痕迹(现状 OTA 后「应用和功能」永远显示安装时的版本);
- `POST /v2/update/report`(U6.2);
- 写审计 + 事件日志,UI 显示「已更新到 X」。

---

## U6 · 灰度、急停、健康度

### 6.1 分组

首次服务启动生成 16 字节随机值存 `%ProgramData%\Bulwark\install-id`(0600,进 SelfGuard),
`cohort = crc32(salt) % 100`。

**刻意不用** MachineGuid / 硬件 ID / 任何可关联的标识:产品对外承诺「不附带任何机器标识」
(威胁情报共享那节的措辞),而 cohort 每次 watch 都会发给服务器。
本地随机盐给出稳定分组,又不构成标识。

客户端判 `available = (cohort < rollout.percent)`。服务端**也**按 cohort 过滤
(5% 的发布不该把载荷 URL 暴露给 100% 的客户端),但**客户端那一道才是有签名的那道** ——
服务器被拿下也不能把比例擅自放大。两侧都做,与现状「下载侧和应用侧各验一遍签名」同一思路。

### 6.2 回报(可选,默认开,无标识)

```
POST /v2/update/report
{ "channel":"stable", "cohort": 37, "sequence": 43,
  "from":"1.0.3", "to":"1.0.4", "phase":"ok|failed|rolledBack",
  "errorCode":"VERIFY_PIPE_TIMEOUT", "driverActivation":"nextBoot" }
```

没有机器标识、没有路径、没有用户名。服务端只聚合计数:
「43 号发布:灰度 5%,上报 812 台,ok 806,rolledBack 6,主要错误 VERIFY_PIPE_TIMEOUT」。
这是「这个版本健康吗」唯一的客观答案;现状一个坏版本在用户来报之前完全不可见。

### 6.3 急停与召回

都只是**发一份新的签名清单并让 `sequence` 递增**:
- 急停:`rollout.percent = 0`。还没装的机器立刻停;已经装好的不动(它们已经验证通过)。
- 召回:`rollbackTo: "1.0.3"` + `app.files` 指向 1.0.3 的 blob + `reason`。

关键性质:因为 `sequence` 单调且签名,**服务器无法把急停回滚掉**。
这是把灰度控制放进签名清单(而不是放在服务端配置里)的全部意义。

---

## U7 · 发布流水线

`scripts/publish-release.ps1`(由 `make-update-package.ps1` 演进,保留它三条拒绝条件)。

### 7.1 版本号单一来源

读 `VersionNumbers.h` 的 `BULWARK_VERSION_STRING`,并**断言**
`packaging/installer/install.ps1` 的 `$Version`、`packaging/installer/bulwark.iss` 的
`AppVersion`、`packaging/portable-scripts/bulwark.ps1`(若有)三处一致,不一致拒绝出包。
现状是三份硬编码的 `1.0.3` 靠人同步。

### 7.2 出厂清单与 diff

从 `cpp/dist` 递归收集**全部**文件(不是写死的三个名字),生成
`releases/<version>/inventory.json`;与上一版 inventory diff 得出:
- 哈希变了 → `replace`
- 新出现 → `add`
- 消失了 → `remove`

`remove` 永远是生成的,不手写 —— 手写 `remove` 是能把一台装好的机器弄残的最短路径。

### 7.3 逐项核验(出包前)

- 每个 PE:有 Authenticode、签名者指纹 == `UpdateTrust.h` 钉死值、`Status != HashMismatch`;
- 每个 exe/我们自己的 dll:`FileVersion == version`;
- `Bulwark.sys` 的 `driverProtocol` 与 `Bulwark.Driver/Protocol.h` 一致,
  且与服务要求的 `requiresDriverProtocol` 匹配;
- `notes` 非空(保留现状:空着等于让用户对替换内核驱动的操作盲签);
- content 包:解压后能被 `bulwark_snapshot --verify-content` 装载。

### 7.4 签名与上传

1. 写规范化 `release.json`;
2. Ed25519 签名。私钥来自离线存储(建议硬件令牌或独立离线机),**不在仓库、不在服务器**;
3. **用客户端编译进去的那个公钥自验一遍** —— 这一步抓的是「换证书/换密钥时漏改一处」,
   现状 `verify_portable.ps1` 对指纹做了同类核对,这里把它扩展到签名密钥;
4. 上传:`blobs/<sha256>` 先、`release.json` + `.sig` **最后**
   (顺序是承重的:清单一旦落地接口立刻对外宣告该版本可用);
5. 回读公开端点确认 `sequence`/`version`/签名可验;
6. rsync `blobs/` + 清单到 node-45(现状更新载荷根本不同步);
7. 追加 `releases/ledger.jsonl` 并入库:谁、何时、发了哪个版本、灰度几成、序号多少。

### 7.5 命令面

```
publish-release.ps1 -Channel beta   -Percent 100
publish-release.ps1 -Channel stable -Percent 5        # 灰度起步
publish-release.ps1 -Channel stable -Percent 50       # 放量(只改 rollout + sequence,blob 不重传)
publish-release.ps1 -Channel stable -Stop             # 急停 = percent 0
publish-release.ps1 -Channel stable -Rollback 1.0.3 -Reason "..."
publish-release.ps1 -Channel stable -Resign           # 只续签 expiresUtc(≤14 天一次,可上 cron)
```

---

## U8 · 配置

```jsonc
"Update": {
  "Enabled": true,
  "BaseUrl": "",                  // 空 => 复用 ReputationProxy 解析出的地址(保留现状取舍)
  "Ring": "stable",               // canary|beta|stable;兼容读旧键 Channel
  "WatchEnabled": true,
  "InitialDelaySeconds": 90,
  "PollIntervalHours": 6,
  "QueryTimeoutSeconds": 15,
  "DownloadTimeoutSeconds": 180,
  "AutoDownloadApp": true,        // 下载可以自动
  "AutoApplyApp": false,          // 【装】不自动 —— 会换内核驱动、可能要重启
  "AutoApplyContent": true,       // 特征库/规则必须自动,否则这个功能没意义
  "DriverActivation": "nextBoot", // nextBoot|liveReload
  "ReportEnabled": true,
  "AllowedThumbprints": [],       // 只能追加
  "AllowedSigningKeys": []        // 只能追加
}
```

默认值的立场:**内容自动流动,二进制等用户按按钮**。
后者沿用现状已经写明的理由 ——「安装要停防护、换内核驱动、可能要求重启,
那必须是用户按下按钮才发生的事」。

缺键时的行为必须是上面这组默认值:配置文件里**今天根本没有 `Update` 段**
(核实:`cpp/service/appsettings.json` 无该段),所以默认值就是现网的真实行为,
改默认值等于给所有机器换行为。

---

## U9 · IPC

全部**追加在枚举末尾**(当前末项 75),并补 `static_assert`。旧消息 62-66/72/73 **继续发**:
更新过程中新服务 + 旧界面是必然出现的组合(现状注释已就 `ReservedJunk*` 占位讲过同一个道理)。

```
UpdateStateRequest   = 76   // UI->服务:要当前更新状态(新接上的界面据此渲染,不必重新检查)
UpdateStateResponse  = 77   // 服务->UI:phase/from/to/sequence/rollout/错误/是否待重启
UpdateActionRequest  = 78   // UI->服务:check|download|apply|restartService|restartUi|rollback(带 sequence 防误点旧状态)
UpdateActionResponse = 79   // 服务->UI:动作受理结果(拒绝原因可直接展示)
UpdateBytesProgress  = 80   // 服务->UI:字节级进度(文件数进度仍走 65,老界面不受影响)
```

`UpdateActionRequest` 带 `sequence`:界面可能停在一个过期的状态上(用户开着弹窗,
期间服务端又发了一版),不带序号就会出现「点的是 A、装的是 B」。

UI 侧 `UpdateDialog` 从「自己驱动流程」改成「渲染服务状态」:
步骤条读 `phase`,按钮按 `phase` + `rollout` 决定,关掉弹窗不影响后台进度
—— 现状关掉弹窗再打开会重新发起一次检查。

---

## U10 · 测试

### 10.1 进 ctest(不需要 VM)

| 用例 | 钉住什么 |
|---|---|
| `release_manifest_verify` | 规范化字节 + Ed25519 验签向量;改一字节必败;非钉死公钥必败 |
| `release_manifest_gates` | 序号倒退/相等、过期、通道不符、schema 未知、版本倒退(含 `rollbackTo` 例外) |
| `payload_path_policy` | U3.2 的六条判据 × 每种攻击形态:`..\..\Windows\System32\x.dll`、`C:\x.dll`、`/etc/x`、`platforms\..\..\x.dll`、`a/b/c/d.dll`、`CON`、超长名、非白名单子目录 |
| `update_state_machine` | 在 8 个 phase 的每个边界「强杀」,断言恢复动作;半截 JSON 可恢复 |
| `rollout_cohort` | 10 万个随机盐的 cohort 分布均匀;同一盐结论稳定 |
| `content_pack_limits` | plainSize 超限、plainSha256 不符、压缩炸弹 |

### 10.2 诊断入口

`bulwark_service.exe --update-dryrun`:走完 检查 → 下载 → 校验 → **模拟**应用(写到临时目录),
把每一步的判据与结论逐行打出来,不碰安装目录、不碰驱动。
和 `--attackchain-check` 的「实机可达性诊断」同一哲学:
自测全绿与真机能用之间的差距,必须有一个工具能量出来。

### 10.3 只能在带快照的 VM 里做

- `liveReload`:卸载/加载循环 ×50、Driver Verifier 全项、卸载期间制造事件风暴;
- 起不来的新版本 → 看守回滚;
- 跨重启:`applying` 阶段断电、`verifying` 阶段断电。

驱动**不能在开发机上加载** —— 内核回调出一点错就是蓝屏,这条规矩项目里已经立过。

---

## 11. 与现有设计文档的关系

- `architecture-rewrite` **S11(签名内容通道)**:本设计是它的具体化与先行实现。
  S11 要求「统一格式 manifest + payload + Ed25519,适用于规则包、组合表、IOC feed、
  内核基线、更新清单」—— U1 就是那个格式,U4.1 就是那些载荷。
  顺带修掉 S11 点名的现状 2.5.1(组合表无签名)。
- `architecture-rewrite` **2.5.6** 评价「更新机制做得扎实,保留」:本设计**保留它列举的每一条判据**,
  补的是它没覆盖的三块 —— 驱动落点、重启验证、清单信任。
- `av-engine`:特征库与模型走 U4.1 的 content 通道,这是那条路线能落地的前提。
- `architecture-rewrite` **S13(服务端拆分)**:本设计只加 4 个端点,
  不动单体结构;拆分时这 4 个端点整体搬到 `edge-api` 即可。

## 12. 分期

| 期 | 内容 | 单独交付的价值 |
|---|---|---|
| **P0** | U4.2 驱动双落点 + `stageDriverBinary` 按哈希覆盖 + U5.1 落盘状态 + `.old-*` 清理 + ARP 版本 | 驱动终于能更新。**这一期不改协议、不动服务端**,可以立刻发 |
| **P1** | U5 全套(看守 / 自重启 / 自验证 / 自回滚) | 更新不再需要用户手动重启,坏版本能自己退回去 |
| **P2** | U1 签名清单 + U3 内容寻址 + U7 流水线 + 服务端 `/v2/manifest`、`/v2/file` | 清单可信;冻结可发现;blob 去重 |
| **P3** | U2 长轮询 + U6 灰度/急停/回报 | 真正的推送与可控发布 |
| **P4** | U4.1 content 通道 + U9 新 IPC + U10.2 诊断 | 规则/特征库可在线下发,为 av-engine 铺路 |

P0 刻意排在最前且自包含:它修的是一个**已经存在于现网**的失效(驱动永远更不上),
而且不需要等签名体系与服务端改造。
