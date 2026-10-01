# 在线推送更新系统 v2 · 需求与现状

> 配套:`design.md`(新架构)、`tasks.md`(分阶段任务)。
> 本文只记**现在是什么样、哪里不够、新系统必须满足什么**。所有「现状」条目都标注了核实出处,
> 可直接跳到那一行复核;没核实的明确写「待确认」。

调研日期:2026-10-01。代码基线:`VersionNumbers.h` = **1.0.3**,已发布通道清单 = **1.0.2**。

---

## 1. 现状(已核实)

### 1.1 协议与端点

| 方向 | 位置 |
|---|---|
| `GET /v1/update/manifest?channel=stable\|beta` | `server/bulwark-intel/app.py:6951`(`_serve_update_manifest`) |
| `GET /v1/update/file/<channel>/<name>` | `app.py:6971`(`_serve_update_file`) |
| 客户端取清单 | `cpp/service/src/UpdateService.cpp:85`(`check()`) |
| 客户端下载 | `UpdateService.cpp:430`(`download()`) |
| 客户端就地应用 | `UpdateService.cpp:287`(`apply()`) |

两个端点刻意放在 `_authed()` 闸门**之前**(`app.py:7135`):发布包里 `ReputationProxy.BearerToken` 是空的,
放到闸门之后等于「只有持令牌的人能检查更新」。这个取舍是对的,v2 保留。

清单字段:`ok / available / channel / version / label / published / notes / files[{name,size,sha256,url}] / totalBytes`。
服务端会用磁盘真实状态**覆盖** `files[]` 的 size/sha256(`_update_manifest_obj`,带 mtime 缓存),
缺任一文件即整份拒绝发布(`"incomplete release"`)。

### 1.2 信任链

唯一的信任锚是**载荷自身的 Authenticode 签名 + 编译期钉死的签名者指纹**
(`cpp/shared/include/bulwark/UpdateTrust.h:39`,`712BA1C841C8D2AA0A48BF89BD076DCD0774E7F5`)。
配套四道校验(`UpdateService::verifyFile`):① 文件名白名单且不含路径成分 → ② 大小 → ③ SHA-256 →
④ 签名存在 + 指纹命中 + 按 `TRUST_E_BAD_DIGEST` 区分「被改动」与「链不受信」。
`apply()` 另有两道:**取用的那一刻重验一遍**、**版本只许前进**(拒同版本与降级)。

这套判据是对的,**v2 全部保留**。清单里的 SHA-256 不是安全边界(服务器自己声明的),这一点
`UpdateTrust.h` 的注释已经写明。

### 1.3 替换机制

`apply()` 对每个文件做「旧映像改名让位 → 新文件放到原名」(`MoveFileExW` + `CopyFileW`),
任一步失败按相反顺序回退;让位的旧映像能删就删,删不掉排进 `MOVEFILE_DELAY_UNTIL_REBOOT`。
由**服务自己**执行,不再拉提权脚本 —— 因为脚本是外部进程,会被本产品自我保护逐项挡下
(写安装目录被内核 SelfGuard 拒、`Stop-Process` 静默失败、`powershell.exe` 被攻击链判成勒索)。

这个结论是对的,**v2 保留并扩展到驱动路径**。

### 1.4 触发时机

- 手动:设置 → 关于与更新 → 检查更新(`cpp/ui/src/pages/SettingsPage.cpp:532`)。
- 自动:**每个服务生命周期只一次**,启动后 `Update.AutoCheckDelayMinutes`(默认 3)分钟,
  且**必须等界面接上**才发起(`cpp/service/src/main.cpp:1446-1471`)。结果只弹一条右下角 toast
  (`MainWindow.cpp:438`,三道抑制:查失败/无新版/弹窗开着/本会话已弹过)。

### 1.5 IPC

序号 62-66 + 72/73(`cpp/shared/include/bulwark/ipc/IpcMessageType.h:96-122`),
负载 `cpp/shared/include/bulwark/ipc/Payloads.h:320-376`。全部异步,服务端在后台线程算完经
`sendUpdateCheck / sendUpdateProgress / sendUpdateDownloadResult / sendUpdateApplyResult` 广播回推。
枚举有 `static_assert` 钉序号,废弃项保留占位(`ReservedJunk*` 67-71)—— 理由是新旧混跑时
序号漂移会串号,这条规矩 v2 必须继续守。

### 1.6 发布流水线

`scripts/make-update-package.ps1`:
版本号单一来源 `VersionNumbers.h` → 读 `UpdateTrust.h` 取钉死指纹 → 从 `cpp/dist` 收集
**写死的三个文件名** → 逐个核验签名/指纹/`FileVersion == version` → 写 `manifest.json` →
`-Publish` 时 scp 到 `/opt/bulwark-intel/update/<channel>/`(**先传载荷、最后传 manifest**)→
回读公开端点确认。三道拒绝条件(未签名/版本号不符/更新说明为空)都对,v2 保留。

### 1.7 部署形态

- 安装版:Inno Setup(`packaging/installer/bulwark.iss`)→ `%ProgramFiles%\Bulwark`,
  系统集成交给 `install.ps1`;驱动 `Copy-Item ... -Force` 到 `System32\drivers\Bulwark.sys`
  (`install.ps1:518`),`sc create Bulwark type= filesys binPath= System32\drivers\Bulwark.sys`。
- 便携版:`packaging/portable-scripts/bulwark.ps1 -ApplyUpdate`(第 947-1270 行是独立的
  提权应用路径,`$UpdateSignerThumbprints` 在第 81 行)+ `更新.bat`。
- 用户态服务 `BulwarkService`,内核服务 `Bulwark`(altitude 385201)。

---

## 2. 缺陷与缺口

按严重度排。每条都给出核实位置。

### 2.1 🔴 在线更新从来没有真正更新过内核驱动

`apply()` 把 `Bulwark.sys` 写到 `QCoreApplication::applicationDirPath()`(`UpdateService.cpp:322`),
也就是**安装目录**。但实际被加载的是 `%SystemRoot%\System32\drivers\Bulwark.sys`:
- `DriverControl::locateSys()` 候选表第一项就是它(`DriverControl.cpp:128`);
- `sc create` 的 `binPath` 写的也是它(`install.ps1:537`、`DriverControl.cpp:68`)。

而服务里唯一往那个路径复制的函数 `stageDriverBinary()`(`main.cpp:2699`)**只在 `--bootstrap` 下调用**
(`main.cpp:2815`),并且开头就是:

```cpp
const QString dst = QDir(sysRoot).filePath(QStringLiteral("System32/drivers/Bulwark.sys"));
if (QFileInfo::exists(dst))
    return; // 已就位
```

→ **目标存在就永不覆盖**。结论:OTA 之后两个 exe 前进了,`.sys` 原地不动,**连重启也不会生效**。
唯一能更新驱动的路径是重跑安装程序或便携包的 `-SetupOnly`。

这个状态产品自己已经能察觉:`main.cpp:988-1011` 会报
「内核驱动协议不一致(请用同源编译的 Bulwark.sys)」—— 但它把原因归给「构建搞错了」,
而真实原因是在线更新结构上做不到。1.0.2 的清单里写着「本次未重建内核驱动二进制」,
所以这个洞至今没咬到人。

### 2.2 🔴 没有重启,也没有验证与回滚

`needsRestart` 恒为真,界面告诉用户「关闭界面后重新双击 启动Bulwark.bat;或者重启一次机器」
(`UpdateDialog.cpp:371`)。但:
- Inno 安装版的安装目录里**没有** `启动Bulwark.bat`(那是便携包的东西),这句指引对安装版是错的;
- 服务不会自己重启,所以新版本实际要等到下一次开机;
- **没有任何自验证**:新版本起不来会怎样,没有代码回答。崩溃循环 = 机器长期无防护,
  而旧版本已经被改名让位了;
- `.old-<stamp>` 只靠重启删除队列清理;队列没生效就永久堆在安装目录里,而那里被 SelfGuard
  守着,别的程序动不了。

### 2.3 🟠 清单无签名,冻结与元数据篡改无从发现

载荷有签名,**清单没有**。服务器被拿下或 TLS 被拆开时攻击者装不进代码(指纹拦住),但可以:
- 永远不告诉客户端有新版本(**冻结攻击**)—— 没有 `expires`、没有序号单调性,客户端分不清
  「真的没有新版」和「有人掐住了」;
- 任意改 `notes`。而 UI 用 `QTextBrowser::setMarkdown` + `setOpenExternalLinks(true)`
  渲染它(`UpdateDialog.cpp:92`、`192`)—— 一个安全产品自己的更新弹窗里出现服务器可控的
  可点击外链,是现成的社工面。

补充:随包 `appsettings.json` 的 `SelfHostedTls.CaBundlePath` 与 `PinnedPublicKeys` **都是空的**
(第 26-27 行),所以 `TlsMode::Pinned` 按 `ReputationCurl.h` 的说明退回公网 CA 完整校验 ——
pinning 其实没生效。这不是漏洞(公网 CA 校验仍然有效),但意味着「清单只靠传输层保护」这句话
在现网的强度低于设计意图。

### 2.4 🟠 只能更新 3 个文件,而且只能替换

`payloadAllowList()` 写死三个 PE(`UpdateTrust.h:85`),且文件名**不得含任何路径分隔符**
(`isAllowedPayloadName`)。后果:
- Qt DLL、`platforms\qwindows.dll` 一类插件、MSVC 运行库、`app.ico` 一个都发不出去;
- 没有「新增文件」和「删除文件」的概念,只能原名替换;
- 数据内容(规则包、攻击链组合表、IOC、已知恶意哈希、CA 包,以及 av-engine 规划里的
  特征库与模型)完全不在通道里。

而 av-engine 的调研结论是「今天一行代码都不看文件内容做定性」(`.kiro/specs/av-engine/handoff.md`),
将来必然要下发特征库 —— 现在这条通道装不下。

### 2.5 🟠 不是推送,是一次性轮询

每个服务生命周期查一次,且**必须有界面连着**。常驻模式下服务开机就起、界面可能很久才打开,
那次检查基本落空;用户不开界面就永远不更新。服务端也没有任何 server→client 通道
—— 虽然同一个进程里已经有一套长轮询(客服会话 `SupportStore.wait_messages`,`app.py:1509`),
现成可以照搬。

### 2.6 🟡 没有分批、没有急停、没有发布健康度

`beta` 与 `stable` 今天就是两个目录,`build_update/{beta,stable}/manifest.json` **内容逐字节相同**
(都是 1.0.2,同样三个哈希)。没有百分比灰度、没有分组、没有「停止发布」开关、
没有任何客户端回报,所以一个坏版本在用户来报之前完全不可见。
对一个会替换内核驱动的产品,一次性全量推送是它做的风险最高的动作。

### 2.7 🟡 版本号三处硬编码

`VersionNumbers.h` = `1.0.3`,但 `install.ps1:64` 是 `$Version = '1.0.3'`、
`bulwark.iss:38` 是 `#define AppVersion "1.0.3"`。三处靠人同步。
另外 OTA 成功后没人改 `HKLM\...\Uninstall\Bulwark` 的 `DisplayVersion`,
「应用和功能」里会永远显示安装时那个版本。

### 2.8 🟡 下载层过于朴素

整文件下载,无 Range 续传、无压缩、无重试、无磁盘空间检查。今天载荷 3.7MB 还行,
加上引擎特征库与模型就不行了。

### 2.9 🟡 发布是半自动单节点

`-Publish` 只 scp 到一台机器。`server/bulwark-intel-backup-node-45` 存在,但更新载荷**不同步**。
没有发布台账,「什么时候发了什么、灰度到几成」答不出来。

---

## 3. 目标

- **G1** 驱动真正能被在线更新,且默认走零风险路径(下次启动生效),实时重载是用户显式选择项。
- **G2** 更新后能自己起来、自己验证、起不来能自己回滚;任何一步崩溃都可从落盘状态恢复。
- **G3** 清单带离线签名 + 单调序号 + 过期时间:服务器被拿下既装不进代码,也冻结不了升级。
- **G4** 通道能装下「二进制」与「数据内容」两类载荷,支持替换/新增/删除;数据内容热生效。
- **G5** 真正的推送:长轮询 + 抖动保底轮询,**不依赖界面在不在**。
- **G6** 分批灰度 + 一键急停 + 可召回,且灰度比例由**签名清单**决定(服务器不能擅自放大)。
- **G7** 发布流水线单一版本源、自动生成文件清单与增删动作、可审计台账、多节点同步。

## 4. 非目标

- 不做 WebSocket / MQTT。理由与客服长轮询同:在公网端口上手写帧解析是为省一次往返而多开一整片
  攻击面(`app.py:1513` 已经论证过一次,结论保持一致)。
- 不做二进制差分(bsdiff/courgette)。先做 Range 续传 + 压缩 + 内容寻址去重;
  差分的收益要等载荷到几十 MB 量级才划算。
- 不改服务端单体结构。那是 `architecture-rewrite` 的 S13,本设计只在它上面**增量加端点**。
- 不碰 `appsettings.json` 的在线下发。里面有用户自己填的密钥与信任目录,覆盖掉等于清用户设置 ——
  这条禁令原样保留。
- 不做强制升级。本产品的立场是「自我保护必须用户可控」,强制替换内核驱动与之冲突。

## 5. 硬约束

- **A1** 载荷 Authenticode + 钉死指纹这一道**永不放宽**,配置项只能追加指纹,不能替换内置项。
- **A2** 新 IPC 消息一律**追加在枚举末尾**并补 `static_assert`;废弃项保留占位。
  更新过程中 UI 与服务**必然**短暂处于不同版本,新服务对旧界面必须仍发旧消息。
- **A3** 任何「装一半」都不允许。整份成功或整份放弃 ——「新 exe + 旧驱动」是从未测试过的组合。
- **A4** minifilter 的装卸是本项目风险最高的动作(卸载路径漏摘一个回调就是蓝屏)。
  默认路径**不卸驱动**;实时重载必须用户按按钮,且失败要能把旧驱动装回来。
- **A5** 不得引入任何机器标识。灰度分组用首次启动生成的本地随机盐,不用 MachineGuid / 硬件 ID ——
  产品对外承诺过「不附带任何机器标识」。
- **A6** 不得让外部进程(脚本 / 计划任务 / `schtasks.exe`)参与替换。本产品会挡下它们,
  而且 `schtasks.exe` 正在产品自己的命令行硬拦名单里。

## 6. 验收标准

### 6.1 驱动(G1)
- OTA 一个**真的改过**的 `Bulwark.sys`,重启后 `fltmc filters` 显示新版本、`sc qc Bulwark` 的
  `binPath` 指向的文件哈希等于清单声明值,且服务不再报「内核驱动协议不一致」。
- 选实时重载:卸载→加载→握手版本一致,全程 UI 如实显示;人为让新驱动加载失败,
  旧驱动被装回且防护恢复,审计里有一条记录。

### 6.2 重启与回滚(G2)
- 在 `applying / applied / verifying` 三个阶段各强杀一次服务,每次都能从 `update-state.json`
  恢复到「旧版本可运行」或「新版本已验证」二者之一,绝不停在中间态。
- 塞一个起不来的新版本:看守进程在 N 分钟内把旧版本换回并拉起,UI 给出明确横幅。
  连续失败 2 次后停止自动回滚(不无限循环)。

### 6.3 清单信任(G3)
- 改签名清单任一字节 → 客户端拒绝,理由写明「清单签名校验失败」。
- 用非钉死的密钥签 → 拒绝。
- 把 `sequence` 调小重发 → 拒绝,理由写明「清单序号倒退」。
- 把 `expires` 置于过去 → 拒绝,理由明确指向「可能被冻结在旧版本」而不是笼统的失败。
- 更新说明里塞 `[x](http://evil)` → 界面不产生可点击外链。

### 6.4 内容通道(G4)
- 发一个含 Qt 插件(`platforms\qwindows.dll`)的 app 包,装得上。
- 发一个 `remove` 动作,目标文件被删且在回滚时被还原。
- 发一个 content 包(规则/组合表),服务**不重启**即生效,落点在 `%ProgramData%\Bulwark\content\`。
- 清单里写 `..\..\Windows\System32\x.dll`、绝对路径、带盘符、`platforms\..\..\x.dll`
  —— 五种形态全部被规范化拒绝,且有单测钉住。

### 6.5 推送与灰度(G5/G6)
- **界面从未打开**的机器,在发布后 2 分钟内拿到通知(长轮询)。
- 长轮询并发闸门打满时退化成短轮询,功能不坏。
- `percent: 5` 的发布,只有 cohort < 5 的机器认为有更新;把服务端改成对所有人放行,
  客户端仍按**签名清单里的比例**拒绝。
- 发 `percent: 0` + 序号递增 → 未安装的机器全部停止。

### 6.6 流水线(G7)
- `VersionNumbers.h` 与 `install.ps1` / `bulwark.iss` 不一致时**拒绝出包**。
- 文件清单从 `cpp/dist` 自动生成,与上一版 diff 得出 replace/add/remove。
- 签名后用**客户端编译进去的那个公钥**自验一遍,通不过就不上传。
- 发布台账 `releases/ledger.jsonl` 入库。
