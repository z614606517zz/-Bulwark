# 在线推送更新系统 v2 · 任务

> 编号对应 `design.md` 的 U1-U10。每期自包含、可单独发布。
> 约定:改 IPC 枚举必须补 `static_assert`;改默认值必须在 `requirements.md` 里记一笔
> (配置文件现在没有 `Update` 段,默认值就是现网行为)。

---

## P0 · 让驱动真的能更新(不改协议、不动服务端)

- [ ] **0.1** `UpdateService::apply()` 对 `Bulwark.sys` 增加第二落点
      `%SystemRoot%\System32\drivers\Bulwark.sys`,与安装目录同一套 park/replace/rollback。
      `SwapStep` 扩成一个 target 可对应多个落点,回退按相反顺序覆盖两处。
- [ ] **0.2** 重写 `main.cpp:stageDriverBinary()`:从「目标存在就 return」改成
      「比对 SHA-256,不一致则 park + copy」。保留「源文件不在程序目录」时的那条 note。
- [ ] **0.3** `UpdateApplyResult` 增加 `driverStaged` / `driverActivation` 两个字段,
      `UpdateApplyResponsePayload` 同步(**追加字段,不改序号**),UI 文案据此如实写
      「内核驱动将在下次启动时生效」而不是笼统的「需要重启」。
- [ ] **0.4** `UpdateDialog::onApplyFinished` 的重启指引按部署形态分支:
      安装版指向开始菜单项 / 重启机器,便携版才提 `启动Bulwark.bat`。
      判据:安装目录里有没有那个 bat。(现状对安装版给的是错的指引。)
- [ ] **0.5** `update-state.json` 最小版(`design.md` U5.1 的字段子集:
      `phase/sequence/steps/lastSeenSequence`),write-ahead + 临时文件原子替换。
      本期只用它做「下次启动清理残留 + 恢复半截 apply」。
- [ ] **0.6** 服务启动时扫 安装目录 + `System32\drivers`,删 7 天以上的 `*.old-*`;
      删不掉的排 `MOVEFILE_DELAY_UNTIL_REBOOT`。
- [ ] **0.7** 应用成功后写 `Uninstall\Bulwark\DisplayVersion` 与 `HKLM\SOFTWARE\Bulwark`
      安装痕迹,让「应用和功能」和 `install.ps1 -Check` / 体检.bat 说真话。
- [ ] **0.8** `updateInFlight` 标志:`EventSourceCoordinator` 在该标志下不因界面断开而待机
      (否则 `protectionFollowsUi` 开着时更新会顺带卸驱动)。
- [ ] **0.9** `UpdateDialog` 的 `notes`:`setOpenExternalLinks(false)`,链接降级为纯文本。
- [ ] **0.10** 验收:用一个**真的改过**的 `Bulwark.sys` 走一遍 OTA,重启后
      `fltmc filters` + `sc qc Bulwark` 指向的文件哈希 == 清单值,且不再报协议不一致。

---

## P1 · 自重启 / 自验证 / 自回滚

- [ ] **1.1** `UpdateStateStore`:`design.md` U5.1 的完整状态机 + 八个 phase 的恢复动作表。
- [ ] **1.2** 新目标 `bulwark_guard.exe`(`cpp/guard/`):`--watch-update --deadline <秒>`,
      只做「等 ok / 到点还原并拉起服务 / 写审计」。进 `app` 出厂清单,用同一张钉死证书签名。
- [ ] **1.3** `RestartOrchestrator`:置 `verifying` + 拉起看守 + 非零码干净退出,
      靠 SCM 失败恢复把自己拉回来。
- [ ] **1.4** 启动期自验证七项(U5.4),含「自身版本 == `toVersion`」那条。
- [ ] **1.5** 回滚:`rollingBack` 实现 + `rollbackAttempts >= 2` 停在 `failed`。
- [ ] **1.6** UI:`failed` 时红色横幅「新版本 X 无法启动,已回退到 Y」+ 一键收集日志。
- [ ] **1.7** 界面自重启:服务经 IPC 请求,**用户同意**才执行。
- [ ] **1.8** `liveReload` 路径(U4.3 六步),默认关。失败必须能把旧驱动装回来。
- [ ] **1.9** ctest `update_state_machine`:八个边界各强杀一次 + 半截 JSON 恢复。
- [ ] **1.10** VM 验收:起不来的新版本被看守回退;`applying` / `verifying` 阶段断电各一次。

---

## P2 · 签名清单 + 内容寻址 + 流水线

- [ ] **2.1** `cpp/shared/src/crypto/Ed25519Verify.c`:公开域 ref10 风格
      `crypto_sign_verify_detached`,只含验签。附 RFC 8032 测试向量。
      **不引 OpenSSL / libsodium**(理由见 `design.md` U1.3)。
- [ ] **2.2** `UpdateTrust.h` 增 `BULWARK_RELEASE_KEY_CURRENT` / `_NEXT` +
      `pinnedReleaseKeys(extraFromConfig)`(只追加,语义与指纹那条完全一致)。
- [ ] **2.3** `ReleaseManifest`:原始字节验签 → 解析 → U1.4 的八道闸门。
      错误信息逐条可直接展示,过期那条必须指向「可能被冻结」。
- [ ] **2.4** `normalizePayloadPath()`(U3.2 六条判据)+ ctest `payload_path_policy`。
      **这是本设计最危险的一处放宽,先写测试再写实现。**
- [ ] **2.5** `PayloadFetcher`:`GET /v2/update/file/<sha256>`、`curl -C -` 续传、
      3 次重试、磁盘空间 ≥ 3× 预检、非 200 删文件。
- [ ] **2.6** 暂存目录迁到 `%ProgramData%\Bulwark\update\<sequence>\` 并纳入 SelfGuard。
- [ ] **2.7** `action` 三态:`replace` / `add` / `remove` 的应用与回退。
- [ ] **2.8** 服务端:`GET /v2/update/manifest`(**原样回字节,不重算哈希**)、
      `GET /v2/update/file/<sha256>`;启动与发布时校验清单里每个 sha256 在 `blobs/` 中存在,
      缺一个就整份不发布(沿用现状 `incomplete release` 的态度)。
      `/v1/update/*` **保留**,老客户端还在用它。
- [ ] **2.9** `scripts/publish-release.ps1`:U7.1-U7.4。含
      「`VersionNumbers.h` 与 `install.ps1` / `bulwark.iss` 不一致则拒绝出包」。
- [ ] **2.10** `releases/ledger.jsonl` 入库;rsync blob + 清单到 node-45。
- [ ] **2.11** ctest `release_manifest_verify` + `release_manifest_gates`。

---

## P3 · 推送与灰度

- [ ] **3.1** 服务端 `GET /v2/update/watch`:条件变量 + 2 秒分片 + **独立于客服的**并发闸门;
      满了立刻回 `{changed:false, degraded:true, retryAfterSec}`。
- [ ] **3.2** 服务端 `POST /v2/update/notify`(内网/令牌)唤醒 + `release.json` mtime 轮询兜底。
- [ ] **3.3** `watch` / `manifest` / `file` 登记进 `IPThrottle`,预算单列(U2.3)。
- [ ] **3.4** `UpdateCoordinator`:watch 常驻 + 指数退避抖动 + 抖动保底轮询 +
      每小时出网硬上限。**不再等界面接入**。
- [ ] **3.5** `install-id` 随机盐 + `cohort`;**不得**使用任何机器标识(硬约束 A5)。
- [ ] **3.6** 灰度判定:客户端按**签名清单里的** `rollout.percent`;服务端同样过滤。
- [ ] **3.7** `POST /v2/update/report` 两侧 + 服务端按 `sequence` 聚合的健康度视图。
- [ ] **3.8** `-Percent` / `-Stop` / `-Rollback` / `-Resign` 四个发布动作。
- [ ] **3.9** `-Resign` 上 cron(≤14 天),否则所有客户端会在 `expiresUtc` 之后集体报过期。
- [ ] **3.10** ctest `rollout_cohort`。

---

## P4 · content 通道与 IPC v2

- [ ] **4.1** `ContentInstaller`:落 `%ProgramData%\Bulwark\content\<子类>\`,
      zstd 解压 + 双哈希 + `plainSize` 与客户端硬上限双封顶。
- [ ] **4.2** 四类热生效接线:规则包 → `RuleEngine` 重建;组合表 → `AttackChainEngine::applyTable`;
      IOC/哈希 → `BLW_CMD_*_KNOWNBAD`;CA 包 → `ReputationCurl::ownCaBundlePath`。
- [ ] **4.3** 内容包 `enforce: false` 观察期语义(与 `AttackChainEngine::DryRun` 同一思路)。
      顺带:随包 `appsettings.json` 把 `AttackChainEngine.DryRun` 写成了 `false`
      而代码默认 `true` —— 一并核对该用哪个。
- [ ] **4.4** IPC 76-80(U9),`static_assert` 补齐;**旧消息 62-66/72/73 继续发**。
- [ ] **4.5** `UpdateDialog` 改为「渲染服务状态」:关掉弹窗不中断后台进度,
      重开弹窗不重新发起检查。
- [ ] **4.6** `bulwark_service.exe --update-dryrun` 诊断入口(U10.2)。
- [ ] **4.7** ctest `content_pack_limits`。
- [ ] **4.8** 把 av-engine 的特征库/模型接到本通道(作为该路线的前置依赖交付)。

---

## 跨期事项

- [ ] **X.1** 密钥管理:Ed25519 私钥放哪、谁能签、怎么轮换、丢了怎么办。
      **这件事要先定,再写 2.1** —— 密钥一旦随第一个客户端发出去就钉住了,
      与钉死证书指纹同一性质。
- [ ] **X.2** `SelfHostedTls.CaBundlePath` / `PinnedPublicKeys` 现网都是空的,
      `TlsMode::Pinned` 实际退回公网 CA。决定要不要配上 —— 不配不是漏洞,
      但「清单只靠传输层保护」在 P2 之前是唯一防线。
- [ ] **X.3** 待确认:服务以 LocalSystem 运行时 `%LOCALAPPDATA%` 的实际解析路径,
      用来复核现状注释里关于暂存目录 TOCTOU 的描述(不阻塞 2.6,搬到 ProgramData 本身更干净)。
- [ ] **X.4** `beta` 与 `stable` 当前内容逐字节相同。P2 的内容寻址会自动去重,
      但要先确认线上两个目录是不是真的该一样。
- [ ] **X.5** `server/bulwark-intel-backup-node-45` 与 `server/bulwark-intel` 线上跑哪份
      (`architecture-rewrite` 现状 2.5.3 也挂着这个问题),定了才能做 2.10。
