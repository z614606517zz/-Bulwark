# 更新记录 (Changelog)

本文件记录磐垒主动防御 (Bulwark) 的主要变更。

> ⚠ **阅读须知:2026-07-02 及更早的条目属 .NET 原型时期**,其中引用的路径(`Bulwark.Core/`、
> `Bulwark.Core.Tests/`、`Bulwark.Service/`、`tools/`)在当前 C++ / Qt 代码树中**已不存在**。
> 这些条目保留作为历史记录,但**不能据此判断当前代码状态**。规则本身已随
> `cpp/shared/src/engine/DefaultRules.cpp` 迁移过来;其中提到的 .NET 规则单元测试没有迁移,
> 当前的自动化测试是 `cpp/tests/` 的四条 ctest(`verdict_snapshot` 裁决快照回归 +
> `builtin_ruleset_ids` 规则 id 唯一性 + `attackchain_regression` 攻击链组合回归 +
> `driver_match_unit` 内核驱动名单匹配单测),用 `ctest --test-dir cpp/build -C Release` 跑。

---

## [未发布]

### 界面 🎨
- **桌面 UI 重新设计**(`cpp/ui/`),与服务之间的 IPC 协议不变:
  - 外壳:侧栏可折叠(窗口窄于 1100 自动收成图标栏),底部「防护状态」卡如实区分四种状态(未知从不显示为受保护);页头放当页操作;仪表盘和检查器里的入口直接跳到对应页面并带上筛选。
  - 「拦截记录」与「活动日志」合并为「事件记录」;列表页统一为分段筛选 + 搜索 + 记录列表 + 右侧检查器,支持批量;进程管理可切换列表 / 进程树。
  - 仪表盘:防护状态区 + 快捷操作、可点开的统计卡、过去 24 小时柱图、「需要关注」。设置改为分类导航,改动即时下发,收到服务回显才显示「已保存」。
  - 弹窗(行为提示、确认框、AI 清理三步向导、更新等)统一为同一套面板;危险操作的确认框写明后果。
  - 新配色「磐石」取代原来的蓝紫渐变:玉墨色侧栏(垒石纹理)、暖石墨工作区(细颗粒)、玉青主色、黄铜点缀;所有文字对比度 ≥ 4.5:1。品牌徽标与 exe 图标同步更新。
- **隔离区加了「批量选择」按钮**(页头)。此前多选只能靠 Ctrl / Shift 点选,界面上没有任何入口。点开后每行前出现复选框,单击(或空格)即勾选、不再打开检查器;底部批量条常驻,可「全选 / 取消全选」,一项没选时「还原 / 永久删除」置灰。✕、Esc、再点一次页头按钮都能退出,提交批量操作后自动退出。服务推来新的隔离列表时已勾选的项按 id 保留(Ctrl 多选同样保留),不再被刷新清空;勾选模式下敲字母不会通过「按首字母跳转」误勾选某一行。列表底部给批量条留出位置,最后一行不再被它盖住。
- **行为提示弹窗移到主屏右下角**(与通知 toast 同一个角,卡片边缘对齐),不再盖在主窗口正中;展开详情时向上长高。弹窗在场时 toast 叠在它上方,不会盖住「拦截 / 放行」按钮。
- **语音播报拦截结果**(「设置 → 防护总控」,默认关):拦截通知弹出时用 Windows 自带语音(SAPI,优先中文语音)念出处置结果;没拦下的念「未能拦截,请手动处理」,不会说成已拦截。询问、放行、攻击链等其它通知不念。与通知共用去重和限流合并,正在念时新到的结果先攒着,念完补一句汇总。开关只存在当前 Windows 用户(不经服务);本机没有中文语音时设置页会提示。

### 移除 🗑
- **AI 研判**整功能移除:UI「AI 研判」页与仪表盘上的「AI 研判」统计卡、双击时的「AI 研判中」进度与结论、灰区 AI 会诊(服务端 `AiDecisionPolicy` 与 AI 判恶意后的补偿处置)、`AiScanRequest` / `AiScanResponse` 消息(序号 28 / 29 保留为占位)、静态特征提取器与 AI 研判历史(`ai_scan_history.json` 不再读写)。设置里去掉「灰区 AI 会诊」和「查杀失败即拦截」—— 后者实际只在 AI 研判不可用时生效,云查杀从未读过它。托盘「立即扫描」改为打开「云信誉」页。**AI 生成规则**与 **AI 清理**不受影响,仍用「设置 → 云查杀与 AI」里的大模型接口;双击云查杀照常。
- **磁盘垃圾清理**与**大文件查找**整功能移除(UI「垃圾清理」页、JunkCleaner / LargeFileScanner、相关 IPC 消息与 DiskCleanup 配置段)。威胁足迹清理(ThreatRemediator / 持久化清理)不受影响。
- 仓库清理(不影响产品):删除 .NET 时期遗留的 `Bulwark.Sandbox/`(沙箱配置原由已不存在的 Bulwark.UI 生成,C++ 代码从未接入);删除失效或重复的构建/部署脚本 `build.bat`、`build_service_v2.ps1`、`cpp/build_ui.bat`、`cpp/.tools/`、`重载v5驱动.bat`(调用的 `__drv_reload.ps1` 不存在)、`tools/bulwark_launcher.cpp` + `build_launcher.bat`、`scripts/_kiro_deploy_service.*` / `_kiro_testload.ps1` / `_kiro_fix_and_load.bat`(指向已不存在的 `cpp\build-fix`);删除 v2.0.x 版本线的过期文档 `SUMMARY.md`、`REAL_TIME_PROTECTION_STATUS.md`、`TESTING_GUIDE.md`、`V2.0.2_TEST_GUIDE.md`、`V2.0.3_RELEASE.md`,以及 `ml/` 下误入库的运行日志和一次性探针脚本。下方旧条目里对这些文件的引用仅作历史记录。

### 新增
- **行为询问弹窗有了「AI 解读」**(右下角那张询问卡;「设置 → 云查杀与 AI → 行为询问 AI 解读」,默认开,只在配置了大模型接口时生效)。证据区下方钉一条紫水晶横幅:建议(拦截 / 放行 / 谨慎)+ 置信度 + 一两句通俗解读 + 耗时与 token,不随证据滚走。
  - **只是一条证据,不是裁决**:结论不回传服务,倒计时、默认处置、强调按钮一概不变。它和已移除的「AI 研判 / 灰区 AI 会诊」是两回事 —— 那条路会改裁决,这条不会。
  - 失败照实写「暂不可用:请求超时 / 接口拒绝了 API Key(HTTP 401)……」,整条退成灰色;引擎已检出硬恶意指标而模型却建议放行时,建议改标琥珀并注明「与引擎结论相左,请以证据为准」。
  - 防提示词注入:事件数据按「不可信、可能由恶意程序构造」交给模型,每个值压成一行、限长、去掉会冒充数据边界的分隔符;模型输出只按纯文本显示。路径里的本机用户名先替换掉再发。
  - 每次询问都会自动花 token,所以有三道闸:同一行为沿用已存下的解读、同一行为的请求在路上时后到的弹窗搭同一趟、每分钟最多 6 个新请求(询问风暴不能变成账单风暴);月度额度守卫同样适用。开关存当前 Windows 用户(不经服务)。
  - **解读会记下来,避免重复调用**:存到 `%ProgramData%\Bulwark\ai_explain_cache.json`(与 token 账本同一目录,内核 SelfGuard 守着),所以界面重启、甚至重装之后,同一行为仍然直接沿用而不再花钱。只存「提示词的 SHA-256 + 解读文本」,从不存提示词本身 —— 路径与命令行不该为了省一次调用再多落一份盘;键里带接口地址与模型名(不带 API Key),换了模型就不会拿旧模型的结论当这一次的结论。
  - 保存期与清理周期都是**一周**:到期的条目既不会被采用(读取时逐条判),也不会在盘上多留一个周期。清理**每周自动跑一次**(界面启动时若已过一周即清,界面长开则在下一次解读落盘时清),顺带封顶 512 条、满了先丢最旧的。界面上如实写出这条解读是「刚才 / 5 分钟前 / 3 天前」拿到的 —— 三天前的结论和刚才的结论,可信度不一样。
- **拦截通知也有了「AI 解读」**(右下角「已拦截危险行为」那张卡;「设置 → 云查杀与 AI → 拦截通知 AI 解读」,默认开,只在配置了大模型接口时生效)。依据下面钉一条紧凑的紫水晶横幅:判断(拦截合理 / 疑似误拦 / 难以判断)+ 置信度 + 一两句通俗解读 + 耗时与 token。
  - 和询问弹窗那条是两套提示词:询问时行为在等裁决,问的是「该不该拦」;通知弹出时引擎已经拦完了,再问一遍只会换来一句「建议拦截」,所以这里问的是「它在做什么、为什么危险、这次拦得站不站得住」。同一行为在两处各存一条解读,互不顶替。
  - 同样只是一条证据:不回传服务、不改变已做的处置。「疑似误拦」一律标琥珀而不是绿 —— 东西已经被拦了,模型这句话的意思是「值得复查」,不是「这是安全的」;引擎检出了硬恶意指标时还会注明与依据相左。
  - 通知只活 8 秒,而慢一点的模型(尤其带推理的)回话可能要十几秒:解读还在路上时倒计时走完也先不关(横幅里写着「正在解读… N 秒」,✕ 随时可关,兜底最多再等 30 秒),到了之后保证至少还能读 10 秒;失败那一句(超时 / 接口拒绝 API Key / 额度用尽……)留 4 秒。悬停暂停照旧。卡片向上长、底边不动,不会压住下面那条。
  - 成本闸沿用询问那几道(同一行为一周内沿用、在途搭车、每分钟总共最多 6 个新请求、月度额度),另加一道:拦截通知最多占其中 3 个 —— 拦截是成批来的,不设份额的话,一阵拦截就能把随后那次需要用户拍板的询问的解读挤成「已跳过」。被去重压掉、被限流合并成摘要的拦截不解读。
  - 横幅从 `PromptDialog.cpp` 挪到 `cpp/ui/src/dialogs/AiInsightPanel.{h,cpp}`,询问弹窗与拦截通知共用(询问弹窗的外观不变)。
- **「退出界面即停止防护」**(「设置 → 防护总控」,**默认关**,`RuntimeSettings::protectionFollowsUi`)。打开后防护只在 `bulwark_ui.exe` 在跑时生效,退出界面即整体待机、再打开即恢复;最小化到托盘仍算在跑。
  - 补的是一个真实的落差:此前关掉界面后**内核驱动仍在拦截与隔离**。那不是缺陷,是刻意的设计 —— 内核那套「自足基线」(禁止执行名单 / 命令行硬拦 / 已知恶意 SHA-256 / 内置凭据 hive 硬拦)本就要求「用户态不在也照样生效」,且跨重启由驱动自己从注册表载回。于是**只要 Bulwark.sys 还在载,拦截就还在发生**,而防护总开关只短路 Worker 的事件处理与兜底扫描,碰不到它。待机因此必须**真的把驱动卸掉**(`DriverControl::tryStop()` —— 这个函数此前从未被调用过),否则「停了」就是假的。
  - 待机做的事:停 ETW 会话与用户态行为源(自启动监视 + 勒索诱饵)、**卸载内核驱动**、放开 `UserModeExecBlock` 的全部独占句柄并**停掉它的重武装定时器**(只放句柄不停表的话,最多 30 秒后它会把刚放开的全部重新锁上,表现成「停了半分钟又自己恢复」)、清掉 WFP 出站封禁、Worker 事件处理与兜底扫描双双短路(兜底扫描是待机期间唯一还会自己动手结束进程+隔离的东西,漏掉它就等于没停)。
  - **刻意不回滚已经落地的东西**:已隔离的文件、已施加的「拒绝执行」ACE、内核写进注册表的基线都保持原样(基线要等驱动下次加载才重新生效)。待机的语义是「不再做新的处置」,不是「撤销做过的」—— 后者会把一次误开关变成不可逆的防护清空。
  - 判据是「有没有已认证的界面连着控制管道」,不是去枚举 `bulwark_ui.exe`:管道的连/断是内核给的事实,而进入 `buffers_` 的连接都过了 `IpcClientAuth`(必须是安装目录下的 `bulwark_ui.exe`),所以冒名进程既连不进来也影响不了判定。断开给 8 秒宽限期(界面重启 / 在线更新替换 exe / 管道抖动都会短暂断开,为此卸一次驱动再装回来是无谓的高风险动作),连上则立刻恢复。
  - **开机后还没打开过界面时直接进待机**,不会先把驱动装上再卸掉 —— minifilter 的装与卸是这个项目里风险最高的动作(卸载路径漏摘一个回调就是蓝屏),不为了少一个分支而多做一次。唤醒走的是完整的 `start()` 路径,含禁止执行名单重放,并**补一次加白对账**:启动即待机那条路上,启动时那次对账跑在名单还没重放的时候等于没跑,不补就会出现「加白了却还是起不来」。
  - 服务进程本身仍然常驻(否则下次打开界面得再弹一次 UAC 才能把服务拉起来),但待机期间不做任何监控与处置。`setKernelEnabled()` 加了待机守卫:待机中的调用只记意图、唤醒时生效 —— `settingsUpdated` 每次都会无条件调它一次,没有这道守卫,用户在待机窗口里改任何一项设置(哪怕一个 API Key)都会把驱动装回来,而待机标志还是真的。
  - 诚实地说出代价,而不是只说便利:设置页说明、开启时的确认框、托盘退出项的文案(按开关状态改写,不再固定写「防护继续运行」)、退出前的确认框都写明 —— 界面没在跑的时段(开机到登录、注销后、界面被结束后)主机**不受本软件保护**,于是「结束 bulwark_ui.exe」这一下就成了关闭整套防护的手段。默认关也是为此:缺键按开处理等于升级一次就把所有机器改成这个形态。
  - 能力矩阵与防护档位一并如实反映:待机时 `protectionCapabilities()` 全报未生效(原先 `umExec` / `umNet` 判的是「对象存不存在」,还有四条直接写死 `true` —— 待机时对象都还在,会照报「用户态拦截生效」),`protectionTier()` 新增独立的 `Standby` 档(并入 `ObserveOnly` 会让「待机」和「有观测无拦截」长得一样)。每次待机 / 唤醒落一条 `ProtectionLifetime` 审计记录:这段空窗是用户自己选的,更需要事后可查。
- 内置规则:从 `DefaultRules.cpp` 拆到 `cpp/shared/src/engine/rules/`(`Rules01`–`Rules08` 共八段),现共 950 条;补遗包括远控工具滥用 / curl·BITS·portproxy 下载隧道 / 凭据窃取 / mimikatz·esentutl·procdump 转储 / cmstp / msdt·forfiles·AMSI 绕过等。
- **内核驱动名单匹配有了自动化测试**(ctest 第 4 条 `driver_match_unit`,88 条断言)。驱动【不能在开发机上加载】——内核回调出一点错就是蓝屏,加载验证只在带快照的测试 VM 里做,所以在此之前匹配语义的任何改动都只有「编译通过」这一级验证,而项目里已有两次实测事故正出在这几个函数上(`C:\temp\Windows\System32\csrss.exe` 白拿关键进程豁免;`\WINDOWS\SYSTEM32\CMD.EXE` 进禁止执行名单把所有 .bat 钉死)。做法:把这些纯函数(不碰全局状态、不取锁、不依赖 IRQL)抽到 `Bulwark.Driver/MatchCore.{h,c}`,用 `BLW_MATCHCORE_HOST` 打开一层不含 `<windows.h>` 的用户态垫片,由 `cpp/tests/DriverMatchTest.c` 原样编译并逐形态钉住判定。两起历史事故各留一条回归哨兵。
- **运行期可以往内核喂已知恶意 SHA-256**(`BLW_CMD_CLEAR_KNOWNBAD` / `BLW_CMD_ADD_KNOWNBAD`)。内核本来就有一套可用的哈希查杀引擎(自带纯 C SHA-256 + 异步 worker,命中即封禁并结束进程),但此前**只能**由注册表 `Policy\KnownBadSha256` 在驱动加载时载入 —— 用户态服务(云信誉 / 兜底扫描 / 情报)哪怕已经确认某个文件恶意也喂不进去,引擎白放着。下发即生效,内核侧自带格式校验与去重。**刻意不持久化**:内核哈希集同样没有「删除单条」,写进跨重启基线,一次误判就是「那个文件永久起不来而且加白无效」;离线情报仍走 `cpp\scripts\set-baseline-policy.ps1`。
- **内核名单支持精确删除单条**(`BLW_CMD_DEL_PATH` / `_FILEHARD` / `_NOLOAD` / `_EXECBLOCK` / `_REGHARD` / `_CMDBLOCK`)。见下方「修复」里那条跨重启撤销漏洞。
- **网络防护补上出站 IPv6**(`FWPM_LAYER_ALE_AUTH_CONNECT_V6`)。此前只有 IPv4 出站一层,一个已被情报确认恶意的进程改走 IPv6 就完全不受阻,而 Windows 上 IPv6 默认启用、很多域名会优先解析到 AAAA。顺带把 WFP 从单例改成**表驱动**(`kBlwWfpLayers`):一个内核 callout 只能绑定一个 WFP 层,覆盖 N 层就得注册 N 个 callout + N 条 filter,而拉起 / 回滚 / 卸载三条路径现在都是同一张表上的循环 —— 拆除路径漏掉一个 callout 就是蓝屏(镜像卸载后 WFP 仍持有指向 classify 函数的指针),对称性比省几行代码重要。IPv6 黑名单(条目结构是 32 位 IPv4,装不下 128 位地址)、入站、监听端口留作下一步。
- **驱动模式下能看见「释放物落地」了**。`IRP_MJ_CREATE` 在遥测开启时额外上报「落地区新建/覆盖出一个可执行或脚本文件」,两层门槛(落地区卷相对锚定前缀 + 24 种可执行/脚本扩展名)把事件量压到与 ETW 那条同量级,本产品自身进程豁免。此前驱动只报 delete-on-close,dropper 把 payload 写出来这一步完全不可见 —— 而无驱动的 ETW 模式反倒有(`kFileCreateNew`),驱动模式不该更瞎。
- **BYOVD 有了「加载之前」的观测点**:注册表回调上报对 `…\Services\<名字>\ImagePath` 的写入。要让 `ZwLoadDriver` 能加载一个驱动必须先写出这个值,所以这是必经前置步骤,且发生在模块进内核之前。**只上报、不拦截**是刻意的——合法的驱动安装(杀软、虚拟化、外设)走同一条路,在内核按路径判「该不该注册驱动」必然误伤,klids.sys 那次误报就是这么来的;定性归用户态(它有签名校验、情报、缓存与弹窗)。

- **脚本宿主要执行的脚本文件,现在会读正文做判据**(`ScriptAnalyzer::analyzeScriptFile`,由 `Worker::scanScriptFileBody` 在富化阶段有界读入)。补的是一处结构性盲区:脚本宿主的命令行里**只有一个文件路径**(`cmd.exe /c "…\x.bat"`),正文一个字节都不在里面 —— 于是一个 1.9MB 的混淆加载器在检测侧和 `echo hello` 完全一样。原有的 `ScriptAnalyzer` 只分析「命令行里抠出来的」脚本文本,实际上只有 `-EncodedCommand` 和 mshta 内联这两种拿得到。
  - **判据是实测筛出来的,不是凭经验列的**。语料:某目录 7 个真实脚本样本(4 个 .bat / 2 个 WSH .js / 1 个 .ps1);良性侧 2733 个文件 = 本仓库自己的 143 个 `.ps1`/`.bat` + Windows 自带 77 个 + Windows 自带 WSH 13 个 + 本机打包 / 压缩后的 JS 2500 个。结果:**恶意 7/7 命中硬指标并落 Block,良性 2733 个文件得分全为 0**(不是「低于阈值」,是一条判据都不碰)。
  - 留下 5 条**行为级**判据(各自单独即可定罪,在全部良性语料上零命中):自复制到常驻目录(T1547)、`certutil -decode` 还原载荷(T1140)、批处理内嵌伪造 PEM 封套(T1027)、批处理空变量逐字拆词混淆(T1027.010)、「解密/解压 + Base64 + 动态执行」完整链(crypter)。
  - **被实测否掉的判据,别再加回来**:①「混用多种互不相关文字系统」—— `mermaid-*.js` 得 29 分、`serverWorkerMain.js` 29 分,而最差的恶意样本只有 15,i18n / locale 表天然混用几十种文字,这条方向是反的;②「单行 ≥64KB」单独用 —— 2500 个打包 JS 里约 90 个命中;③「Base64 连续段 ≥2048」单独用 —— `wasm-*.js` 有一段 622,148 字符;④「`powershell -ep bypass` / `-w hidden`」—— 69 个良性脚本里 23 个命中,**其中 15 个是本仓库自己的脚本**,只能当互证。
  - 两个 WSH JScript 投递器不碰上面任何一条,靠「超大 WSH 脚本 + 互证」覆盖(体积 ≥300KB,Windows 自带最大的 WSH 脚本是 `winrm.vbs` 204,072 与 `slmgr.vbs` 145,712)。**体积单独不定罪**,要一条互证(长 Base64 段 / 超长单行),取法与 `detectSideloadedTamperedModule` 形态 2 的「未签名 + 互证其一」一致。这三个统计量之所以能用,全靠**宿主必须是 WSH** 这个前提 —— wscript / cscript 不会去跑打包 JS,那是 node / 浏览器的活;所以 `wshHosted` 是调用方给的事实,不从扩展名推。实测这个门值 35 个误报:同样 2500 个打包 JS,强行按 WSH 扫就有 35 个命中硬指标。
  - 复用既有关键字表时**封顶 25 分,且只在已有其它判据命中时才计入**。无条件计入的实测后果:本仓库 143 个脚本里 137 个拿到非零分、Windows 77 个里 74 个、打包 JS 2500 个里 1623 个 —— 「脚本里有危险关键字」在真实语料上几乎恒为真,留着只会给每条脚本事件垫底分,把别处触发的 Ask 悄悄顶成 Block。
  - 成本:只在进程创建、且主体是脚本宿主(cmd / powershell / pwsh / wscript / cscript / mshta)时才做;正文只读**前 256KB**(实测 7 个样本的全部行为级判据都落在 7,770 字节以内);按「路径|大小|mtime」缓存结论(同一脚本被计划任务反复拉起是常态);文件被占用就跳过,不为一次评分去走内核强读。**只有**「超大 WSH 脚本」这条罕见路径才会为结构统计把整个文件顺序读一遍(O(1) 内存,不缓冲)——那是因为实测那个 3.6MB 的 JScript,它 1,566,938 字符的超长行**起点在偏移 240,662**,只读 256KB 前缀就只能看到这行的前 15KB,长行判据必然落空。
  - 离线验证入口:`bulwark_snapshot --scan-script [--wsh] [--out 报告] <文件|目录|@清单>`。它读真实文件、跑纯判据,再把结论送进**完整裁决流水线**打印最终动作;**不执行**被扫描的任何文件。之所以不用语料 `corpus.json` 验:`scriptFile*` 与 `tamperedModulePath` / `chainScore` 一样是「运行时标记、不序列化」,语料要经 `SecurityEvent::toJson/fromJson` 往返,这些字段必然在往返中丢掉 —— 照那条路走,命中硬指标的样本最后会落 Allow,因为字段根本没传过去。(`tamperedModulePath` 那条白加黑判据存在同样的未覆盖问题。)

### 变更 🔧
- **内核「禁止执行 / 禁止加载」两份名单的匹配从任意位置子串收紧为锚定匹配**:必须「从目录边界起、到串尾(或备用数据流分隔符 `:`)止」。这两份是**拒绝**语义,误判的代价是「某个程序永久起不来」且名单跨重启续留,判据必须比保护类名单紧。收紧掉的是 `\USERS\U\TEMP\A.EXE` 连带拦下 `a.exe.bak`、以及恰好叫 `a.exe` 的**目录**下任何模块这类误伤;同时保住两种真实用法——用户态下发的去盘符完整路径,以及 `set-baseline-policy.ps1` 文档里的文件名片段写法(`-FileExecBlock '\evil.exe'`)。刻意**不用**更紧的「卷相对锚定前缀」:那会直接废掉文件名片段写法,也会在卷前缀认不出来时(`\Device\Mup\` 网络路径、影子卷)整条失效,等于拿覆盖面换精度。保护类名单(受保护路径 / 文件硬拦 / 自保足迹 / 两份注册表名单)**保持子串语义**——它们里面本来就有 `\START MENU\PROGRAMS\STARTUP\` 这类出现在路径中段的目录片段。
- **就地加密检测的写采样从一个全局计数器改为按 PID 散列的 64 个槽**,并对「同一文件被反复从头覆写」去重。原实现全系统共享一个 1/32 预算:任何写得密的正常进程(编译器写 .obj、浏览器写缓存、数据库刷盘)都会把预算吃掉,而用户态勒索聚合恰恰是按**发起进程**算改写速率的 —— 于是噪声越大越拦不住勒索,这是真实的检出损失而不只是精度问题。分槽后仍然全程无锁(一次 `InterlockedExchange64` + 一次 `InterlockedIncrement`),且每个槽的第一次首块写必报,只改几个文件的样本也能被看见。(顺带:原注释写的是「进程级采样」而代码是全局的,两者本就不符。)
- **内置规则误拦截治理**:会拦正常系统 / 软件行为的内置规则逐条处理,原则是保留检出、降低处置强度 —— 先让签名健康的系统组件豁免(`exemptOs`,LOLBin 与脚本宿主不在豁免之列),再把模式改精确,都做不到才 Block → Ask。例如 Windows 更新(TrustedInstaller / TiWorker)替换辅助功能程序不再被拦;安装器从 %TEMP% 加载未签名 DLL、仍随合法软件分发的 17 个易受攻击驱动、`sc create type= kernel` 改为询问。规则数 955 → 950。

### 修复 🐛
- **「加白撤销内核名单」在一种最常见的情形下会被重启抹掉**。撤销原先是用户态用「清空整表 + 重下发保留项」做的(`Worker::reconcileKernelBlocksAfterTrust`),而内核侧【只持久化 ADD、不持久化 CLEAR】(那是刻意的:否则一次误清或恶意清空就把某维防护关到重启之后,磁盘基线也一起没了)。两者叠在一起有个洞:**当保留项为空——也就是要删的就是全部条目,恰恰是「只钉了一条而且是误判」这个最常见场景——一次 ADD 都不会发生,于是没有任何东西标脏,磁盘基线保持旧内容,重启后被删的条目全部复活**。现在有了精确删除单条(`BLW_CMD_DEL_*`),删除本身就是一次标脏事件,写回必然发生;顺带也不再需要「先清空整表再逐条重推」那一下——那期间该维防护是真空的。
- **带盘符的内核名单条目是永久死条目,而且会吃掉槽位直到新裁决被静默丢弃**。五份文件路径名单匹配的目标恒为 `FLT_FILE_NAME_NORMALIZED` 规范名(`\Device\HarddiskVolumeN\…`),其中不可能出现 `<字母>:\`(数据流名可以带 `:`,但流名里不允许出现 `\`),所以 `C:\…` 这种条目一条都不会命中——却各占 64 槽之一,并被内核写回注册表跨重启续留,而 `reconcileKernelBlocksAfterTrust` 会把注册表条目原样重推,所以它永远不会自己变好。槽位一旦耗尽,此后所有新的恶意裁决都被无声丢弃。现在入口直接拒收并记日志;开机载入时丢弃过死条目的名单会在写回线程就绪后各重写一次,磁盘基线自愈。`CmdHardBlock` / `RegHardBlock` **刻意不套**这条判据:命令行里出现 `C:\` 完全正常,注册表值名也允许含 `:`——套上去会误拒真实条目。
- **「强可信主体直接放行」会把脚本正文的硬指标整个丢掉,裁决落 Allow**。裁决流水线里这一步(`TrustPolicy::isStronglyTrusted`)的注释写明自己是「唯一跳过行为检测的通道」,但它**没有**硬指标检查 —— 而下一档的「健康签名放行」(`isHealthySigned`)开头就有 `if (e.hasThreatIndicator) return {};`。脚本宿主的主体**永远**是 `C:\Windows\System32\cmd.exe` / `wscript.exe` 这类【微软签名 + 系统目录】的正规程序,正好命中该步的「微软签名且位于系统目录」。于是上面那套脚本正文判据接上之后,实测 7 个真实样本**全部**是「硬指标已置、风险分 93~100、最终 Allow」——第 10 步的硬指标闸门根本轮不到。现在该步遇到「脚本正文命中行为级判据」即不再快速放行,7 个样本随之全部落 Block。
  - 刻意**只看 `scriptFileHardIndicator`,不改成笼统的 `hasThreatIndicator`**。为此做了两次测量:①把它换成通用检查后重录黄金裁决,**39 条语料一条都没变** —— 语料完全没覆盖这条路径,黄金测试对这个改动给不出任何证据;②于是另写一份探针语料(微软签名 + System32 主体 + 干净命令行),四种行为各一条,结果是注入与勒索诱饵改写**本来就在这一步之前**已被显式规则 / 时序检测拦下(两种口径下都是 Block),真正的残余缺口**只有一种**:情报确认恶意的主体走在强可信路径上时会被放行。而那一种即便改成通用检查也只到 **Ask**(带实据的云端恶意计 60 分,高危闸门要 ≥80),且生产上已由 `onReputationMalicious` 的补偿链兜住(结束进程树 + 隔离 + 注入 `hardOverride` 哈希规则,而 hardOverride 规则的匹配排在强可信放行**之前**)。收益是一条已被兜住的 Allow→Ask,代价是 System32 事件量级上无法测量的误报面 —— 所以没有动。这处第 7 / 第 9 步的不一致本身仍然值得单独评估,结论记在这里备查。
- **写采样计数器溢出后会让对应槽永久停止上报**:计数器是 `LONG`,长时间运行后溢出成负数,而负数的 `%` 结果落在 `{-31..0}`,再也不会等于命中值。改为无符号 + 位与(采样率是 2 的幂,有 `C_ASSERT` 保证),回绕后节奏依然精确。
- **卡巴斯基的内核驱动 klids.sys 被当成 BYOVD 拦下**:内置规则「从可写目录加载内核驱动」原来不看任何签名、一律 Block + 硬拦截,而卡巴斯基把带 AO Kaspersky Lab 有效签名的 `klids.sys` 装在 `C:\ProgramData\Kaspersky Lab\KES.14.1\Bases\` 下 —— 硬拦截的排序高于「已安装安全软件共存放行」,共存那一层根本轮不到,于是每次加载都报一次「已拦截」。现在按**被加载模块自身**的签名分档:验不出可信签名的仍是 Block + 硬拦截(开着驱动签名强制的机器上这种驱动本来就加载不起来),持有可信签名的改为**询问** —— BYOVD 用的驱动都有合法签名,不能直接放行,但安全软件与硬件厂商把签名驱动放在 ProgramData / Temp 下加载是真实存在的正常形态。已知被滥用的 34 个具名驱动仍按文件名拦,不看签名,处置强度不变。为此给事件补了「目标文件自身签名」一对字段(`targetSigned` / `targetSignatureMismatch`),规则新增 `targetSignedOnly()` / `targetUnsignedOnly()` 两个条件:ImageLoad 的 `actorSigned` 一直是**宿主进程**的签名(内核模块加载时甚至只是个伪串),拿它判模块自己是错的。
- **内核「禁止加载」(FileNoLoad)名单一条都没生效过**:`Worker::enforceBlock` 把带盘符的完整路径(`C:\…`)下发给驱动,而驱动的名单按**去盘符**子串去比对 `\Device\HarddiskVolumeN\…` 形式的规范名,永远匹配不上 —— 旁边的 `blacklistExec`(禁止执行名单)早就做了这一步去盘符,这里漏了。实测本机注册表里 3 条 FileNoLoad 全带盘符、全是死条目,却各占掉 64 个槽位之一并跨重启续留(协议上没有「删除单条」)。现在去盘符后再下发,门槛与 `blacklistExec` 一致(去盘符后子串 < 6 字符放弃)。同时**内核驱动加载不再下发**:驱动映像由内核自己打开(`RequestorMode == KernelMode`),而 minifilter 的 pre-create 回调开头就放行这类打开,对 `.sys` 下发不可能拦住任何东西,只会白占槽位 —— 槽位耗尽后此后所有新的恶意裁决都会被静默丢弃。
- **卡巴斯基被判「签名失配」,引发大面积误报**:验签时带的 `WTD_SAFER_FLAG`(MSDN 标注为不支持)会让 WinVerifyTrust 在「主签名有效、另附一个私有根嵌套签名」的文件上返回 `CERT_E_UNTRUSTEDROOT`。卡巴斯基的 avp.exe / avpsus.exe / avpui.exe 正是这种双签名,于是被当成「疑似篡改或盗用证书」(+45 分硬指标)、共存放行失效:实测约一小时内弹出一万七千余次询问,avpsus.exe 升级时的清理被判成勒索并被结束。去掉该标志后与资源管理器 / signtool 的默认口径一致(只验主签名);本机抽查 407 个可执行文件,结论只在这 3 个文件上变化,被改过字节的文件仍判失配。
- **命中「释放物污点」的拦截此前没有任何执行前拦截,样本每次双击都先跑 1-3 秒**。污点结论刻意不进内核 `FileExecBlock`(只加不减、跨重启由内核独立续拦、协议无「删除单条」),但原实现的后果是这类拦截**只剩事后 kill**。实测(2026-09-30,15 个样本):`lclcache.exe` 被中央服务器确认恶意(21/75)后登记了 19 个释放物 + 31 条污点规则,内核禁止执行名单里却始终只有它自己一条;于是双击其余 14 个样本时,每一个都先启动、释放 DLL、写 Run 项、外联,1-3 秒后才被结束进程,`wps.exe` 更是被成功运行了 4 次。现在改为补一道**可撤销**的执行前拦截(文件 DACL 的「拒绝执行」ACE,受 `FileDenyExecuteEnabled` 约束):按文件不按路径、只拒执行不拒读(不妨碍本产品自己的隔离与取哈希)、由加白对账自动移除。开关关闭时**明确打一行「未做到执行前拦截」**而不是静默 —— 这个现象原本在日志上完全看不出来。
- **隔离退到「计划重启删除」时,日志说「隔离有效」,而文件仍在原地可以被双击**。删除阶梯全部失败后退到 `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`,原文件权限没有任何变化 —— 实测 `wps.exe` 内核强删返回 `0xC0000121` 走到这一支,随后又被成功运行了 3 次,每次都重走一遍「杀进程 + 隔离」。现在这一支会请求补一道拒绝执行 ACE(只拒执行不拒读,不影响已做好的金库副本与重启时的删除),并**按实际结果分别陈述**:加上了就说重启前也起不来,没加上就直接写「【且重启前它仍然可以被双击运行】」并给出原因(开关未开 / 加固器不可用 / 施加失败)。
- **自动足迹清理看的是服务账户的注册表,每用户自启动项一项都清不掉**。`ThreatRemediator` 的自启动键表里有 3 条 `HKEY_CURRENT_USER`,而服务以 LocalSystem 运行 —— HKCU 在这个身份下解析到 S-1-5-18,那里的 Run 键几乎恒为空。于是日志每次都如实打「移除自启动项 0 个」,与「确实没有持久化」长得一模一样。实测:样本往真实用户 hive 写的 `HKU\S-1-5-21-…\…\Run\MicrosoftUpdate`(值 = `conhost.exe --headless "%APPDATA%\Microsoft\Windows.bat"`)在 11 次足迹清理之后依然在注册表里。现在改为每轮重新枚举 `HKEY_USERS` 下**所有已加载的 hive**(跳过 `*_Classes`;`.DEFAULT` 与 S-1-5-18/19/20 刻意保留 —— 往默认用户模板或服务账户 hive 写 Run 项同样是持久化手段),本机实测覆盖面 9 处 → **24 处**。这与 nodriver-hardening 第 11 条是同一个错误,那一次只修了扫描侧。
- **计划任务整类不在自动足迹清理范围内**。`remediate()` 只清 Run / IFEO / 服务三项,`deleteScheduledTask` 只挂在「用户从 UI 点清理某个持久化条目」那条路上。实测:样本把副本落到 `%APPDATA%\Microsoft\Windows\pigggggg.exe` 并注册了登录触发的 `\pigggggg`,载荷被隔离了、任务一直留着。现在扫 `%SystemRoot%\System32\Tasks` 的任务 XML(读前 64KB,取 `<Command>` 与 `<Arguments>`,两者都比对 —— 恶意体常在参数里而 Command 是 cmd.exe / conhost.exe),命中即删除。**删除走 COM `ITaskService::DeleteTask`,不 spawn schtasks.exe**:本产品自带命令行硬拦,起 schtasks 来清持久化既会被自己的检测盯上(日志里就有一条「执行前拦截已跳过…schtasks.exe」),也给「劫持 schtasks.exe」递上一个入口。任务名在 `TaskCache\Tree` 下是它独占的键,一并纳入反重建硬拦。
- **同一个文件的重复拦截事件会把事件流水线堵死数十秒,并在日志里谎报隔离次数**。`QuarantineManager::quarantine` 内部本来就有同路径去重,但调用方在走到它之前已经无条件付了两次全文件开销:`isSafeToRemove` → `WinVerifyTrust`(Authenticode 要把整个 PE 过一遍哈希)与 `tryComputeSha256`。本机实测对那个 233MB 的样本分别是 **1.22 秒**与 **0.45 秒**。后果:样本被 kill 之后它两个已死 PID 还有 20 条事件排在队列里,每条都重跑一遍完整足迹清理 —— 21:19:12 到 21:19:54 整条流水线只在处理这一个文件,其它进程的事件全堵在后面、最后一次性涌出;而这 20 次里有 19 次什么都没做,却照样每次打一行「足迹清理:已隔离恶意释放文件 …」。现在在付出这两次哈希【之前】先问一句「此前是否已隔离且金库副本仍在」,命中就跳过,并且**两侧都不记入报告** —— 于是 `publishRemediation` 的「无动作则不打扰」早退生效,重复事件彻底安静。
- **清理覆盖面变成可观测的**:自启动位置数与计划任务检查数,每个进程生命周期内各报一次 info(之后降 debug)。写成 debug 等于白加(服务默认不落 debug 级),每次清理都 info 会让它自己变成噪声源;而这两个维度恰恰是「没有恶意项」与「这一维根本没跑」唯一的区分依据 —— 上面两条缺陷正是因为缺这行日志才藏了这么久。

---

## [a60397d] - 2026-08-18 (GitHub 同步)

### 修复 🐛
- **控制台诊断输出的中文全是乱码**(`--inspect` / `--attackchain-check` / `--junk-scan` / `--large-files`)。`QTextStream(stdout)` 在 Qt6 里固定按 UTF-8 编码,而中文版 Windows 的控制台默认代码页是 936 —— 一个「给人看的诊断结论」看不懂就等于没有。服务启动时统一 `SetConsoleOutputCP(CP_UTF8)`(实测 `GetConsoleOutputCP` 936 → 65001)。只影响控制台渲染:输出被重定向到文件或管道时拿到的本来就是原始 UTF-8 字节;以服务身份运行时没有控制台,调用失败返回、无副作用

### 性能 ⚡
- **每事件热路径耗时降约 54%**(裁决 `evaluate()`:108.1 → 48.0 µs/event,590 条规则 / 38 条语料事件实测)。这不只是性能:`evaluate()` 与出队、IPC、弹窗超时巡检在同一线程上串行,单条耗时直接决定事件风暴时队列会不会堆到丢弃(等于漏检)
  - `DefenseRule::wildcardMatch`:内层字符折叠加 ASCII 快路径(`QChar::toUpper()` 要查 Unicode 表且是 Qt6Core.dll 的导出函数,不可内联;路径与通配符压倒性是 ASCII),循环改用裸缓冲区指针 —— 单此一项 −43%
  - `RuleEngine` 规则索引:按 `EventType` 分桶 + 信任项单独分桶,消除每事件 588 条全表扫描。行为等价的依据是 `matches()` 第三道判据按类型早退、以及步骤 6 比较器以 id 收尾构成全序(排序结果与枚举顺序无关);顺带收掉「多条信任项同时命中时返回哪条备注随 QHash 随机种子变」这处抖动
  - `ProcessInspector`:新增 `collectForensics()` 一次 stat 取齐签名 / 发布者 / SHA-256 / 证书画像 / 体积(原先一条事件对同一文件 stat 五六遍,即便全部命中缓存);事实缓存从「装满 8192 即整表 clear()」改为两代 hot/cold —— 原实现每次溢出把热集合一起丢掉,而溢出恰好发生在文件事件风暴里,造成周期性的取证雪崩
  - `AuditLog`:缓存当前审计文件路径与字节计数,只在跨天或写满时重解析。原先每写一条都从 `seq=1` 起逐个候选 stat 两次,滚过 N 次即每事件 2N 次 stat,且恰在审计条数最多时被放大。刻意不常驻持有句柄(Qt 在 Windows 不带 `FILE_SHARE_DELETE`,会让当天审计文件删不掉)
- `bulwark_snapshot --bench`:裁决热路径耗时测量(不进 ctest —— 耗时随机器变,不做门禁),用于给性能改动提供改前 / 改后的可比数字

---

## [v2.0.4] - 2026-08-05 (GitHub 同步发布)

### 新增 ✨
- **攻击链组合引擎**(`cpp/service/src/AttackChainEngine.cpp`)
  - 中央服务器从每日采集的真实样本沙箱记录里数出「哪几个动作凑在一起就是病毒」,客户端下载组合表并给每个进程记账,凑齐即定性。**无模型、无训练,纯查表**
  - 补的是「一条事件一条事件单独判」留下的灰区:写 Run 键 / 落个 exe / 加 Defender 排除项各自都不够定性,同时出现在一个进程身上时已足以定性
  - 匹配复用 `DefenseRule`(不写第二套通配逻辑);只喂证据不改裁决流程,信任通道仍在其之前生效
  - 装载期剔除「主体冲突」与「证据重复」的组合(后者会把软信号提拔成处置依据)
  - 贡献走 `SecurityEvent::chainScore` / `chainHardIndicator` 专用字段,由 `ThreatDetector::analyze` 显式并入 —— 直接写 `riskScore` / `hasThreatIndicator` 会被 analyze 无声擦掉(实测:组合表上线后一次都没生效过,而组合自测始终全绿)
  - `--attackchain-check`:组合逻辑自测 + **裁决路径自测**(防上述擦除类回归)+ **实机可达性诊断**(把每个标记判为可达 / 稀疏 / 结构性死路,量化「自测全绿」与「真机能点亮」的差距)
  - 新增「攻击链」页面 + 命中角标通知(**独立于静默模式**,避免「凑齐 N 个动作却被静默放行而用户毫不知情」的盲区);命中落盘 `attackchain_hits.jsonl`
- **控制管道客户端认证**(`cpp/service/src/IpcClientAuth.cpp`)
  - 此前服务对任何连入客户端零校验,**任意本地低权限进程都能一条消息关掉整套防护**;配置里那三个签名相关键虽已解析但代码中从无一处消费,README 宣称的能力实际不存在
  - 强制层(不可关闭):客户端映像须在服务安装目录下且名为 `bulwark_ui.exe`,与内核 SelfGuard(写不进安装目录)+ ObCallbacks(注入不了合法 UI)咬合成立
  - 可选加固层:`EnforceUiClientSignature` + 指纹 / 发布者白名单。取不到 PID 或映像路径时 **fail-closed**
- **威胁情报共享**(`ThreatIntelContribStore` + `ThreatIntelUploader`,**默认关闭**)
  - 云查确认恶意 / 可疑的样本,其「病毒信息 + 行为数据」本机暂存,每天凌晨批量上传 `/v1/intel/contribute`
  - 脱敏在**写盘之前**执行(唯一执行点):剔除本机落地路径、沙箱内完整路径、被扫文件路径与文件名;从不收集文件内容 / 计算机名 / 用户名。关闭开关即清空暂存
- **`server/bulwark-intel/`**:完整情报服务端(信誉聚合 + 攻击链组合挖掘 `engine_build.py` + 情报共享接收 + per-IP 限流 + 网页端 + systemd 单元)。密钥全部读 `/etc/bulwark-intel/config.json`,代码内无任何密钥
- **`cpp/tests/`**:两条 ctest 入库 —— `verdict_snapshot`(裁决快照回归,语料全为合成事件)+ `builtin_ruleset_ids`(规则 id 唯一性)
- **`packaging/`**:便携包制作(空密钥模板 `appsettings.portable.json`、行为规则集、启动 / 卸载脚本)

### 修复 🐛
- **IP 整段封禁误伤共享基础设施**(新增 `IpBlockPolicy.h`,两处生成规则的地方共用同一判据)
  - **实测**(现场 `rules.json`):68 个学到的「C2 地址」里 **48 个是公共基础设施(71%)** —— 8.8.8.8 / 1.1.1.1、23 个 Cloudflare、6 个 Fastly、3 个 Akamai、Telegram、一个内网地址,以及两条非法 IPv6
  - 用户侧表现:装了防护后一堆软件打不开 / 登不上 / 更新不了,且规则落盘、重启依旧
  - 现在私网 / 环回 / CGNAT / 组播、公共 DNS 解析器、共享 CDN 与反代前端段、非 IPv4 一律不生成规则;云厂商**通用计算段**(EC2 / GCE / 通用 Azure)刻意不排除 —— 那些确实常被用来架 C2
- **侧载模块篡改漏检(「白加黑」)**:主体自身签名健康、同目录 DLL 签名后被改过的情形此前完全看不见(白壳在流水线第 10 步就放行,而内核 ImageLoad 只上报 `\Temp\` 与 `\Users\Public\`)。新增 `SecurityEvent::tamperedModulePath`,在富化阶段填写、由 `ThreatDetector` 消费

### 变更 🔧
- **防护链路延迟改为可配**:新增 `EventDrainIntervalMs`(默认 20,原硬编码 150ms)与 `InlineReputationBudgetMs`(默认 800)。后者是热路径同步云查的硬上限 —— 整条链路在同一线程串行,无上限时一次缓存未命中可能等满「代理超时 8s + 本地最慢单源 10~15s」,期间内核事件堆积到丢弃(等于漏检)。超预算不取消查询,迟到结论转由既有补偿处置兜住
- **中央信誉服务新增客户端请求数预算** `RequestsPerMinute` / `RequestsPerHour`:服务端按来源 IP 滑窗限流,超限回 `429` + `retry_after_seconds=3600`,**整整一小时**退回纯本地且状态灯来回跳。这与 `FreshQueriesPerDay` 是两条不同的线(命中服务端共享缓存不计后者,却照样占 IP 名额)
- **`SyncResultsToServer`**:把本机查到、服务器尚无记录的权威结论回传(最有价值的是本机首见文件上传 VT 扫出的结论),只带结论、不含文件内容 / 路径 / 机器标识
- **`TrustedDirectories`**:部署期预置的整目录信任,语义等同 UI 里手动加白文件夹
- 清理若干误入库的命令残片文件(`delete` / `qc` / `queryex` / `stop` / `_alive.txt`),并把本机运行 / 诊断脚本移出版本库

---

## [v2.0.4-dev] - 2026-07-29

### 修复 🐛
- **云查询拦截失效** - 服务器已收录恶意样本但客户端首次执行时不拦截
  - **问题**: 异步查询要求「未签名 + 首见 + 风险分≥50」，导致低分恶意样本漏查
  - **修复**: 放宽为「未签名 + 首见」即查，配额由限流器保护（4次/小时）
  - **增强**: 同步云查新增桌面、下载目录（原只有 Temp/Public/ProgramData）
  - 影响文件: `cpp/service/src/Worker.cpp`, `cpp/service/src/reputation/ReputationManager.cpp`

### 技术细节
**修复后行为**:
- 桌面/下载目录未签名首见文件 → **同步云查**（阻塞式，启动前拦截）✅
- Temp/Public/ProgramData → **同步云查** + 异步兜底 ✅
- 其他目录未签名首见 → **异步云查**（后台，首次可能放行，缓存后拦截）
- 已签名文件 → 异步云查（不阻塞）

---

## [v2.0.3] - 2026-07-29 (GitHub同步发布)

### 发布 🚀
- **源代码已同步至 GitHub** - https://github.com/z614606517zz/-Bulwark
  - 完整的 V2.0.3 版本代码库
  - 190 个文件更新,21903+ 行代码新增
  - 包含驱动、服务、UI、ML训练管道的完整实现

### 主要特性总览 ✨
本次发布整合了以下核心功能模块:

#### 1. 攻击溯源与可视化
- **攻击图构建器** (`cpp/shared/src/engine/AttackGraphBuilder.cpp`)
  - 将孤立事件还原为完整攻击链
  - 进程树关联与时间线重建
  - 节点类型:进程/文件/注册表/网络/服务/计划任务
- **进程启动来源溯源** (`cpp/service/src/monitoring/ProcessOriginResolver.cpp`)
  - 将 svchost.exe 还原为具体服务名
  - 计划任务宿主还原为任务名
  - SCM/COM 权威快照与注册表回退机制
- **取证服务** (`cpp/service/src/ForensicsService.cpp`)
  - 事件时间线查询(按时间窗/类型/PID/关键字)
  - 攻击关系图生成与下发
  - 历史事件深度检索(扫描 events.jsonl)
- **UI 增强**
  - 攻击图窗口 (`cpp/ui/src/dialogs/AttackGraphWindow.cpp`)
  - 进程详情对话框 (`cpp/ui/src/dialogs/ProcessDetailDialog.cpp`)
  - 事件时间线页面(新增)

#### 2. 进程管理与监控
- **进程枚举器** (`cpp/service/src/monitoring/ProcessEnumerator.cpp`)
  - 带取证能力的进程管理视图
  - 启动来源列(服务名/计划任务名)
  - 签名验证与静态风险提示
  - 处置功能:结束/挂起/恢复/隔离/信任
  - 自我保护:拒绝操作自身组件与关键系统进程

#### 3. 主动防护增强
- **内核命令行硬拦截** (`Bulwark.Driver/ProcessMonitor.c` + `Policy.c`)
  - 执行前拦截(零 IPC、零往返)
  - LOLBin 用法检测(vssadmin/wmic/bcdedit/reg等)
  - 内置 13 条反勒索/反凭据窃取基线
  - 持久化到注册表,服务未启动时仍生效
- **注册表防护补齐** (`Bulwark.Driver/RegistryMonitor.c`)
  - 新增 5 类通知覆盖:Rename/SaveKey/SetSecurity/CreateKey/LoadKey
  - 内置凭据 hive 硬拦(SAM/SECURITY 导出零配置拒绝)
  - 修复键改名/ACL 篡改绕过路径型防护的漏洞
- **哈希扫描模块** (`Bulwark.Driver/HashScan.c`)
  - 内核本地已知恶意哈希查杀
  - 独立于用户态服务运行
- **规则作用域修复**
  - 收窄"良性厂商应用"信任通道至仅 NetworkConnect/DnsQuery
  - 修复 IM 客户端规则旁路问题(微信/QQ 群控防护规则现已生效)

#### 4. 云信誉与情报整合
- **代理声誉服务** (`cpp/service/src/reputation/ProxyReputationService.cpp`)
  - 中央信誉服务集成(默认 https://vt.bulwark.icu:8787)
  - 失败时自动回退到直连 VirusTotal
  - 仅发送 SHA-256 摘要,不传输文件内容
- **主动防护规则生成** (`Worker.cpp::buildRulesFromProfile()`)
  - 从 VirusTotal 行为画像自动生成 5 类拦截规则:
    1. 释放文件哈希拦截(ProcessCreate → Block)
    2. C2 IP 拦截(NetworkConnect → Block)
    3. C2 域名拦截(DnsQuery → Block,新增)
    4. 释放文件名监控(FileWrite → Ask)
    5. 注册表持久化拦截(RegistrySetValue → Block,新增)
  - 智能过滤:排除 CDN/云服务商域名,限制规则数量避免误报

#### 5. ML 训练管道
- **数据采集工具** (`ml/tools/`)
  - Collect-BenignPE.ps1 - 良性 PE 样本采集
  - Collect-BenignSamples.ps1 - 通过 winget 采集可信应用
  - Collect-CleanWim.ps1 - 从 Windows WIM 镜像提取系统文件
  - Collect-MalwareBazaar.ps1 - 恶意样本下载与管理
  - github_dl.py - GitHub 热门项目可执行文件下载
- **特征提取与训练** (`ml/train/`)
  - extract_features.py - PE 静态特征提取
  - behavior_runtime_features.py - 运行时行为特征
  - train.py - LightGBM 模型训练主流程
  - vt_enrich.py / vt_behaviours.py - VirusTotal 情报增强
  - mb_enrich.py - MalwareBazaar 元数据集成
- **注意**: 产品不包含已训练模型,检测能力来自规则+启发式+云信誉

#### 6. 部署与工具
- **构建脚本**
  - build.bat / build_service_v2.ps1 - 服务构建
  - cpp/build_ui.bat - UI 构建
  - rebuild_all_for_portable.ps1 - 便携版完整构建
- **部署脚本** (`scripts/`)
  - _kiro_deploy_service.ps1 - 服务部署
  - _kiro_load_now.ps1 - 驱动加载
  - _kiro_restart_svc.ps1 - 服务重启
  - deploy-driver-vm.ps1 - 虚拟机驱动部署
- **启动器与辅助工具** (`tools/`)
  - bulwark_launcher.cpp - 启动器实现
  - auto-allow.ps1 - 自动信任规则生成
- **服务端组件** (`server/bulwark-broker/`)
  - broker.py - 中央信誉代理服务
  - ember_pkg/features.py - EMBER 特征提取

### 文档与配置 📚
- **新增文档**
  - PROACTIVE_DEFENSE.md - 主动防护技术文档
  - REAL_TIME_PROTECTION_STATUS.md - 实时防护状态分析
  - SYSTEM_TOOL_PROTECTION.md - 系统工具保护机制
  - TESTING_GUIDE.md - 综合测试指南
  - V2.0.2_TEST_GUIDE.md - V2.0.2 测试指南
  - V2.0.3_RELEASE.md - V2.0.3 发布说明
  - SUMMARY.md - 项目概要
- **配置完善**
  - cpp/dist/appsettings.json - 运行时配置模板
  - cpp/service/appsettings.json - 服务配置示例
  - cpp/scripts/set-baseline-policy.ps1 - 基线策略设置

### 技术架构变更 🔧
- **协议保持兼容** - IPC 协议版本维持 v9,新旧两端可降级互通
- **事件类型扩展** - 新增 CommandBlocked / RegistryHiveDump 等事件类型
- **数据模型增强**
  - SecurityEvent / ChainEventInfo 新增 origin* 字段
  - ProcessEntry / AttackGraph 模型(新增)
  - ProcessOriginKind 枚举类型(新增)
- **IPC 消息扩展** - IpcMessageType 追加 50-57(时间线/攻击图/进程管理相关)

### 安全与隐私 🔒
- **明确数据外发行为**
  - 默认开启中央信誉服务(仅发送 SHA-256 摘要)
  - README 已说明关闭方法与自建方式
  - 本地 API Key 不会上传到中央服务
- **自我保护增强**
  - 进程管理拒绝操作自身组件
  - 关键系统进程保护(防 0xEF 蓝屏)
  - 驱动独立运行能力(服务停止时仍拦截)

### 已知限制 ⚠️
- **上报逻辑缺陷**: 引擎裁决 Allow 但内核已拦截时,UI 会错误显示为"放行"
  - 影响事件: SelfProtect / MemoryProtect / ImageBlocked / NetworkConnect / CommandBlocked / RegistryHiveDump
  - 原因: `Worker::enforceBlock` 仅在裁决为 Block 时调用
  - 建议: `kernelBlocked=true` 时无条件报告 `KernelBlocked`(待决策)
- **测试覆盖**: C++ 版本无自动化测试(enable_testing() 仍注释状态)
- **模型推理**: 当前版本不包含 ML 模型推理路径,ml/ 仅用于离线训练

### 致谢 🙏
感谢所有参与测试、反馈问题和贡献代码的用户与开发者。

---

## [未发布] - 2026-07-28 (最新)

### 修复 🐛
- **系统工具误删保护** - 添加系统可执行文件白名单，防止清理时误删关键工具
  - 保护列表: cmd.exe, powershell.exe, notepad.exe, taskmgr.exe, regedit.exe 等 21 个系统工具
  - 原因: 用户报告 Visual Studio 开发工具快捷方式（指向 cmd.exe）被清理
  - 修复: 在 `isSafeToRemove()` 中增加**第一优先级**检查，系统工具绝对不删
  - 位置: `cpp/service/src/ThreatRemediator.cpp`
- **文件清理失败问题** - VT 沙箱确认的释放文件现在会绕过签名保护进行清理
  - 问题: 带签名的恶意释放物之前会被跳过，导致"清理失败"提示
  - 修复: `droppedFilePaths` 中的文件即使带签名也会被隔离
  - 位置: `cpp/service/src/ThreatRemediator.cpp`
- **扩展文件清理落地区** - 新增 6 个常见恶意软件落地区
  - 新增: `\users\`（用户根）、`c:\temp\`、`c:\tmp\`、`\music\`、`\videos\`、`\pictures\`
  - 原因: 恶意软件常释放到这些位置，之前被"不在用户可写落地区"跳过

### 技术细节
- **文件清理安全检查优先级**（从高到低）:
  1. ⭐ 系统工具白名单检查（v2.0.3 新增） - 绝对保护 cmd/powershell 等
  2. 系统/安装目录检查 - 保护 System32/Program Files
  3. 落地区检查 - 只清理用户可写区域
  4. 签名保护检查 - 3 种绕过机制（主体异常/哈希匹配/VT 确认）

### 新增 ✨
- **实时注册表写入拦截规则** - 根据 VirusTotal 行为报告自动生成注册表拦截规则
  - 恶意样本尝试写入 VT 报告中的注册表键（自启动/劫持/持久化）时直接拦截
  - 限制 30 条规则，过滤系统关键路径（`\Windows\`）避免误拦
  - 补齐主动防护的最后一环：阻止恶意软件重建持久化
  - 实现位置：`cpp/service/src/Worker.cpp::buildRulesFromProfile()`
- **C2 域名 DNS 阶段拦截** - 在 DNS 解析阶段就拦截恶意域名
  - 比 IP 拦截更早（在 IP 解析之前就阻断）
  - 自动排除合法 CDN/云服务商域名（microsoft/google/amazon/cloudflare/akamai）
  - 限制 50 条域名规则避免误报

### 增强 🔧
- **主动防护规则生成增强** - `buildRulesFromProfile()` 现在生成 5 类规则：
  1. 释放文件哈希拦截（ProcessCreate → Block，精确硬拦）
  2. C2 外联 IP 拦截（NetworkConnect → Block）
  3. C2 外联域名拦截（DnsQuery → Block，新增）
  4. 释放文件名监控（FileWrite → Ask，软提示）
  5. 注册表持久化拦截（RegistrySetValue → Block，新增）
- **日志增强** - 情报行为画像日志现在清晰显示各类 IOC 数量和注入的规则总数
  ```
  情报行为画像[VirusTotal]:释放文件 5、注册表 3、外联IP 2、域名 1;
  已注入主动拦截规则 11 条。
  ```

### 文档 📚
- 新增 `PROACTIVE_DEFENSE.md` - 主动防护完整技术文档（规则类型/工作流程/配置/测试）
- 新增 `REAL_TIME_PROTECTION_STATUS.md` - 实时防护与威胁清理状态分析文档

---

## [未发布] - 2026-07-28 (之前)

### 新增
- **进程启动来源溯源:把 svchost.exe / 任务宿主还原成「具体哪个服务、哪个计划任务」**
  `cpp/service/src/monitoring/ProcessOriginResolver.cpp`(新增)+ `Worker.cpp`(富化接入)
  + `SecurityEvent` / `ChainEventInfo` 新增 `origin*` 字段 + `Enums.h` 新增 `ProcessOriginKind`

  补的是溯源链上一处一直断掉的关键环节。内核 / ETW 的进程事件只给得出「父进程」,而 Windows 上
  两条最常被滥用的启动路径恰好都把父进程抹平成了无区分度的宿主:
  - **服务**:共享型服务全部跑在 `svchost.exe` 里,父进程是 `services.exe`。溯源链上看到
    `services.exe → svchost.exe` 完全不知道是哪个服务,更看不出那是不是攻击者刚装的服务。
  - **计划任务**:Win8+ 由任务计划程序服务(`svchost` 里的 `Schedule`)**直接创建**目标进程,
    父进程就是那个 `svchost.exe`;Win7 是 `taskeng.exe`。溯源到这里就断了。

  于是「持久化 → 落地执行」这条最关键的因果关系在日志上**根本看不见**。现在按逐级降级的策略补回来,
  且每一级都如实标注置信度,不猜完就当事实:
  - 服务:① SCM 权威快照(`EnumServicesStatusEx` + `SERVICE_STATUS_PROCESS.dwProcessId`)直接
    PID → 服务名,共享宿主里的多个服务全部列出;② 父进程是 `services.exe` 但快照里还没有本 PID
    (服务刚创建的竞态)→ 强制刷新一次(带 250ms 节流);③ 仍未命中 → 回退到注册表
    `\CurrentControlSet\Services` 的 `ImagePath` 反查(服务注册**早于**进程启动,所以这条永远拿得到),
    唯一命中记中置信,多个则列候选。
  - 计划任务:① 先判定「是不是任务拉起的」——父进程为 `taskeng.exe`,或父进程是**承载 `Schedule`
    服务**的 `svchost.exe`(用 SCM 快照判定,不靠命令行 `-k` 分组名猜);② 再定名:任务计划程序 COM
    的运行中任务列表按 `EnginePID` 精确匹配;③ COM 不可用 → 扫 `%WINDIR%\System32\Tasks` 的任务 XML
    按映像路径反查候选。
  - **刻意不参与风险评分**:结论只写入事件的 `origin*` 字段并记一条 `Info` 证据(0 分)。
    「由计划任务启动」本身完全合法,不该因此提分;它的价值在于分析时能一眼看到因果 ——
    这与「软信号绝不单独触发处置」的既有原则一致。
  - 敢在事件富化热路径上调 SCM / 任务计划程序这两个 RPC,前提是驱动侧本就是
    fire-and-forget 异步上报(`FltSendMessage` 0 超时),被创建的进程**不会**阻塞等我们的裁决,
    因此不存在「对方在等我们、我们又在等对方」的死锁。即便如此仍加了四层 TTL 缓存
    (SCM 3s / 运行中任务 1.5s / 服务注册表索引 5min / 任务 XML 索引 5min)与「每 PID 结论备忘」
    (60s,键带映像文件名以规避 PID 复用),并且只有「看起来像服务或任务宿主派生」的进程才会
    走 COM 这条重路径。任何一步失败都降级返回,溯源永远不许影响裁决。
  - 溯源链上**每一级**都标出自己的启动来源(`Worker::seedAncestryChain`,限前 6 级封顶开销),
    所以一条链读下来是「计划任务 \Foo → powershell.exe → dropper.exe」而不是
    「svchost.exe → powershell.exe → dropper.exe」——后者根本看不出因果。

- **事件时间线 + 攻击关系图:把孤立记录还原成一次入侵的形状**
  `cpp/shared/src/models/AttackGraph.cpp` / `engine/AttackGraphBuilder.cpp`(新增)
  + `cpp/service/src/ForensicsService.cpp`(新增)+ `EventHistoryStore` 查询能力
  + `cpp/ui/src/dialogs/AttackGraphWindow.cpp`(新增)+ 新页面「事件时间线」

  「活动日志」是实时流水,回答「刚刚发生了什么」;新增的两个视图回答另外两个问题:
  - **事件时间线**(新页面):按时间窗 / 行为类型 / 裁决 / 风险分 / PID(可含整棵进程树)/ 关键字
    检索历史。查询直接扫服务端落盘的 `events.jsonl`(比内存环形缓冲的 500 条深得多),所以能回看
    「昨天下午三点前后那台机器上发生了什么」。表格里专门有一列**启动来源**,`svchost.exe` 那行会
    显示成「服务:Schedule」。
  - **攻击关系图**(弹窗,可从拦截记录 / 活动日志 / 时间线右键、攻击时间线窗口按钮、进程管理页打开):
    以某条事件(或某 PID)为种子,把时间窗内属于同一进程树的事件还原成一张分层有向图 ——
    节点是进程 / 文件 / 注册表键 / 远端地址 / 域名 / 模块 / **服务** / **计划任务**,边是一次具体行为
    (带时间、风险分、裁决与**真实处置结果**)。虚线边表示由父子链或启动来源**推导**出的关系,
    与真实观测到的事件在视觉上严格区分。
  - 关联范围刻意限定为「种子的祖先链(限层)+ 种子自身 + 种子的全部后代」,**不取祖先的兄弟分支** ——
    否则从 `explorer.exe` 往下能把用户开的所有程序都拽进来,图会失去意义。
  - **关联逻辑只有服务端一份**(`AttackGraphBuilder` 在 `bulwark_shared`,由服务调用后整图下发)。
    UI 只负责画,不做任何关联推断 —— 界面上看到的因果与引擎实际依据的因果永远一致,不会出现
    「图上连着、日志里对不上」这种排查事故时最要命的偏差。
  - 时间线查询与建图都可能解析数万条 JSON,故一律在后台线程完成、算完编组回主线程回推
    (与云信誉详情同一套路),并纳入停机等待,不阻塞服务的事件循环。

- **进程管理(新页面)** `cpp/service/src/monitoring/ProcessEnumerator.cpp`(新增)
  + `cpp/ui/src/dialogs/ProcessDetailDialog.cpp`(新增)+ `pages::processes`

  不是任务管理器的复刻,而是「带取证与溯源的进程视图」。三件事是别处看不到的:
  ① **启动来源列**:`svchost.exe` 显示成具体服务名,任务宿主派生的进程显示成具体计划任务名;
  ② **签名与静态提示**:未签名 / 签名失配 / 跑在用户可写目录 / 使用系统进程名但不在系统目录,
     一眼可见,默认按此列降序,打开页面第一眼就落在最值得看的进程上;
  ③ **处置就在手边**:结束 / 结束进程树 / 挂起 / 恢复 / 结束并隔离映像 / 加入信任名单。

  三条红线写进了实现:
  - 所有处置都要用户**显式点击**并二次确认,页面本身不做任何自动动作;静态提示分只用于排序着色,
    **绝不当成判定结论**(详情窗口里也明说了这一点)。
  - **自我保护**:服务端拒绝从这里结束磐垒自身组件(自身 PID + 已连接的 UI PID + 安装目录下的
    `bulwark_service.exe` / `bulwark_ui.exe`),UI 上一并置灰并写明原因。一个能一键结束自家服务的
    进程管理器等于给恶意软件递刀;要停防护有设置里的总开关和正常卸载流程。
  - **关键系统进程**同样拒绝(结束会 `CRITICAL_PROCESS_DIED` 0xEF 蓝屏),复用既有的
    `ProcessInspector::isCriticalProcess` 双重护栏。
  - 处置结果一律弹回执:失败必须说明**为什么没做成**(关键进程 / 自我保护 / 权限不足 / 进程已退出),
    不允许静默成功 —— 与「杜绝假拦截显示」是同一条原则。
  - 首次快照要对几百个映像验签(数秒),故在后台线程完成;验签结果按「路径|大小|修改时间」缓存,
    后续刷新是毫秒级。自动刷新默认**关闭**。

### 变更
- `IpcMessageType` 追加 50–57(时间线请求/响应、攻击图请求/响应、进程列表请求/响应、
  进程处置请求/响应)。序号是冻结的线协议,一律追加在末尾,不复用空洞。
- 左侧导航现已 12 项,放进无边框透明滚动区:窗口高度不足(最小 620)时可滚动,
  而不是把底部的连接状态条挤掉。
- 攻击时间线窗口新增「启动来源」板块与「查看攻击关系图」入口;溯源链每一级都显示启动来源。

## [未发布] - 2026-07-27

### 新增
- **内核「命令行硬拦」:按用法而非按身份的执行前拦截**
  `Bulwark.Driver/ProcessMonitor.c` / `Driver.h` / `Protocol.h` / `Comms.c` / `Policy.c`
  + `cpp/service/src/DriverEventSource.cpp` / `BulwarkOptions.{h,cpp}` / `appsettings.json`

  补的是一处一直存在的能力浪费:LOLBin(`vssadmin` / `wmic` / `bcdedit` / `wbadmin` / `fsutil` /
  `reg` ...)本体位于 System32、签名可信、路径受 WRP 保护 —— 无论怎么按「身份」判定都是可信的,
  威胁完全来自「用法」。原实现为此在内核给 LOLBin 开了个口子(不走可信路径快速放行),把命令行
  交给用户态检测,于是回到「事后 kill」模型。而 `vssadmin delete shadows /all /quiet` 这类命令在
  毫秒级就完成不可逆破坏,等用户态裁决回来卷影早已删干净,结束进程也挽回不了。
  与此同时,`PS_CREATE_NOTIFY_INFO.CommandLine` 在内核回调里【本来就直接可读】,驱动里此前
  一次都没引用过它。

  现在进程创建回调直接读完整命令行做本地查表,命中即 `CreationStatus = STATUS_ACCESS_DENIED`,
  命令**一次都不会执行**。零 IPC、零往返、无竞态。

  - 判定位置刻意放在「可信系统路径快速放行」**之前** —— 目标全部住在可信路径里,放在之后等于不存在;
    唯一护栏仍是「关键系统进程绝不拦」(防 `CRITICAL_PROCESS_DIED` 0xEF)。
  - 模式语法是 `'+'` 分隔的 **token 合取**:每个 token 都必须作为大小写不敏感子串出现,
    因此参数顺序、空格数量、大小写、是否带全路径都绕不过去。若用整串子串匹配,攻击者调换一次
    参数顺序就能绕过。
  - 直接匹配**原始命令行、不截断、不预归一化**:命令行可长达 32767 字符,若先截到 520 字符再匹配,
    在前面填充垫料就能把危险 token 推出截断范围。
  - 名单持久化到 `HKLM\...\Services\Bulwark\Policy\CmdHardBlock`,故**服务未启动 / 被杀 / 刚重启**
    时内核仍独立续拦 —— 反勒索最关键的「删卷影」不再依赖任何用户态进程活着。
  - 内置基线 13 条(反勒索:删卷影 / 压缩卷影存储 / 删备份目录与系统状态备份 / 关恢复环境 /
    关启动失败自动修复 / 删 USN 日志;反凭据窃取:导出 SAM 与 SECURITY hive,根键短/长写法各一条),由
    `CommandHardBlockBaseline` 开关控制,`CommandHardBlocks` 可追加自定义模式。
    选取原则写进了代码注释:**每个 token >= 4 字符** —— token 是纯子串,像 `cl` 这种短 token 会
    命中无关单词造成误报(为此放弃了 `wevtutil cl Security` 这条)。
  - 实机验证时发现并修掉一处自己引入的缺口:`reg save HKEY_LOCAL_MACHINE\SAM` 不含子串
    `HKLM\SAM`,只列短写法时这条命令行模式被直接绕过(当时全靠内核 `SaveKey` 那层兜住,
    纵深防御奏效)。已补上根键长写法。**这暴露了命令行层的固有定位**:它按「字面命令行」判定,
    天然有写法变体的长尾,只能当**可选外层**;真正的兜底必须是内核按「解析后的对象」判定的那一层。
  - 新增事件 `BlwEventCommandBlocked`。主体刻意取**父进程**而非被拒的新 PID:那个 PID 的进程根本
    没起来,按它解析映像只会拿到空值,PID 被复用后还会错误指向无关进程。

- **注册表回调覆盖面补齐五类通知** `Bulwark.Driver/RegistryMonitor.c`

  原实现只挂了 `RegNtPreSetValueKey` / `PreDeleteValueKey` / `PreDeleteKey` 三条,以下四条路
  **完全不设防**:
  - `RegNtPreRenameKey` —— 把受保护键改个名字,即可让所有**基于路径**的匹配(含本驱动硬拦名单
    与用户态规则)整体失效,再从容操作。绕过路径型防护最省事的一招。
  - `RegNtPreSaveKey` —— `reg save HKLM\SAM out.hiv` 导出后离线破解。这条路**不经过 lsass**,
    故现有的凭据反转储(剥 lsass 的 `PROCESS_VM_READ`)对它完全无效。
  - `RegNtPreSetKeySecurity` —— 先把受保护键 ACL 改成谁都能写,后续写入在系统看来完全合法,
    路径型防护被这一步整体解除。
  - `RegNtPreCreateKeyEx` —— 只拦「已存在键的写值」意味着「新建一个持久化键」是放开的
    (IFEO 劫持要新建 `\Image File Execution Options\<exe>` 子键)。
  另加 `RegNtPreLoadKey`(挂载自带 hive 植入持久化配置)。

  实现要点:
  - 新增**内置凭据 hive 硬拦**:`\REGISTRY\MACHINE\SAM` 与 `\REGISTRY\MACHINE\SECURITY` 之下的
    `SaveKey` 一律内核本地拒绝,**零配置、恒生效、不依赖用户态下发任何名单**。刻意不放进通用
    `RegHardBlock`:那会连带拦下对 SAM 的 `SetValue`,而创建用户 / 改密码正是 lsass 走 `SetValue`
    完成的,会直接打死账户管理。前缀判定带边界检查(要求其后是串尾或 `\`),避免同前缀键误命中。
  - `SaveKey` 设为 hardOnly,使 `BlwEventRegistryHiveDump` **只可能由拒绝分支产生** ——
    用户态因此可以无歧义地标记 `kernelBlocked`,不会把真正拦下的 SAM 转储显示成「事后处置」
    并触发无谓补杀。
  - `CreateKeyEx` 只参与硬拦匹配、不做软监控上报:受保护键是 `\Services` 这类宽子串,
    在建键路径上按它上报会形成事件风暴。键此时还不存在,故目标路径由 `RootObject` 路径 +
    `CompleteName` 拼出;只读这两个成员是刻意的 —— `REG_CREATE_KEY_INFORMATION` 与 `_V1`
    在这两个成员上偏移相同,无论系统投递哪个版本都安全。
  - 三级判定(内置 hive → 硬拦名单 → 软监控)抽成单一函数,两种目标构造方式共用,不会日后走偏。

  **刻意未做**:不处理 `RegNtPreLoadKeyEx`。`REG_LOAD_KEY_INFORMATION_V2` 首成员是 `Size` 而非
  `Object`,与 V1 布局不同,合并处理会把一个 `ULONG` 当指针交给 `CmCallbackGetKeyObjectIDEx`
  直接蓝屏。宁可少覆盖一条通知,也不引入这种解引用风险。

  **实机验证**(测试签名 + 驱动加载 + 服务/UI 运行,Win11 26200):命令行硬拦 12/12 用例通过
  (含乱序 / 多余空格 / 大小写混杂的正向,以及缺 token 的负向全部放行);注册表侧 7/7 通过 ——
  SAM hive 导出被拒且内核如实上报 `内核拦截 · 已阻止导出注册表 hive \REGISTRY\MACHINE\SAM`
  (`kernelBlocked=true`),普通 hive 导出与普通建键均不受影响(无回归),
  新建 `...\sethc.exe\Debugger` 键被拒,改名 `\Services\Bulwark` 被拒,`sc config Bulwark` 被拒。

  **已知上报缺陷(本次未改,影响面更大)**:`Worker::enforceBlock` 只在裁决为 `Block` 时才被调用,
  于是当引擎对一个 `kernelBlocked=true` 的事件裁决为 `Allow`(例如主体命中用户信任)时,
  `enforcement` 被记为 `NotApplicable`,UI 会把**内核确实已阻断**的操作显示为「放行」。
  这与项目「绝不谎称拦截」的原则是同一个问题的反面(谎称放行)。本次新增的两类事件让它更容易被看到,
  但它对既有的 `SelfProtect` / `MemoryProtect` / `ImageBlocked` / `NetworkConnect` 同样成立。
  修法很直接(`kernelBlocked` 为真时无条件如实报 `KernelBlocked`),但它改动裁决/处置语义,留待决策。

  协议版本**保持 9**:新命令复用现有 `BLW_CONFIG_MESSAGE`、新事件复用现有 `BLW_EVENT_MESSAGE`,
  三个握手校验结构体大小一个字节都没变;新服务遇旧驱动静默降级,新驱动遇旧服务由 `default`
  分支退化为普通遥测记录。若改为 v10,反而会让已部署的 v9 两端因版本不符而**整体降级为不拦截**。

### 修复
- **收窄「良性厂商应用」信任通道的作用域,修掉一条规则旁路**
  `cpp/shared/src/engine/RuleEngine.cpp`(步骤 2b)+ `cpp/shared/include/bulwark/engine/TrustPolicy.h`

  `TrustPolicy::isTrustedVendorApp` 原先对**全部事件类型**早返回 `Allow` 并置 `userTrusted = true`。
  它的初衷只是压制「IM 客户端周期性心跳保活被信标检测 / IP 情报判成 C2 回连」这一类误报,
  但实际效果是:`qq.exe` / `tim.exe` / `wechat.exe` / `weixin.exe` / `wxwork.exe` 这五个映像名
  一旦持有健康的腾讯签名,它们作为主体的**任何**行为都不再经过 `ThreatDetector`、也不再匹配显式规则,
  并且跳过全部后台扫描(VT / 微步 IP / AI)。

  后果是上面 2026-07-02 那批「银狐微信/QQ 群控防护」规则有一半从未生效——具名 hook 模块
  (`wxhook` / `WeChatSDK` / `vchat` 等)**被 IM 本体加载**这一半,事件主体正是 `WeChat.exe`,
  直接走信任通道放行;`InjectionAnalyzer` 的「可写目录加载未签名模块(DLL 侧载)」检测同样失效。
  攻击者只要把合法签名的 IM 主程序连同恶意 DLL 一起投递,主体就是「签名健康的微信」。

  现在这一档**只对 `NetworkConnect` / `DnsQuery` 生效**,其余维度(进程创建 / 模块加载 / 文件写 /
  注册表写 / 注入)照常走完整流水线。误报抑制效果不变(误报本来只出在外联维度)。
  已知残留:这类主体的外联本身仍被放行,被侧载的 IM 宿主可维持 C2 通道;收掉这一条需要
  模块级(而非进程级)的外联归因,不在本次范围内,但投递阶段的落地 / 加载 / 注入 / 持久化现在都能检测到。

### 移除
- **删除全部已训练模型与训练语料** `ml/`
  移除 `ml/train/behavior_model_v1.txt`、`behavior_runtime_model.txt`、`model_behavior.txt`
  三个 LightGBM 模型产物,以及整个 `ml/data/`(样本语料目录骨架 + VT 哈希清单)。
  产品**不再有「已训练模型」这回事**:当前代码里没有任何模型推理路径,检测能力全部来自
  规则 + 启发式 + 各分析器 + 云信誉。`ml/` 下仅保留离线训练脚本,不参与 C++ 构建。

### 文档
- **修正 README / README.en / steering 与代码不一致处**(逐条核对代码后修改):
  - 新增「中央信誉服务」小节:`ReputationProxy` 在随包配置里**默认开启**,会把本机文件 SHA-256
    发到 `https://vt.bulwark.icu:8787`。此前 README 完全未提及此功能,却写着「情报源全部 opt-in、
    默认关闭」「你填的 Key 只保存在本机」,读者会据此认为不填 Key 即无外发。现已写明外发内容
    (仅摘要,不传文件)、默认值、关闭方法、失败回退行为与自建方式。
  - 澄清「代码默认关」与「随包配置全开」的矛盾:`BulwarkOptions.h` 各源默认 `Enabled = false`,
    但 `cpp/service/appsettings.json` 把 8 项全置为 `true`,配置覆盖代码默认。
  - 修正密钥表述:模板 `cpp/service/appsettings.json` 各 Key 确为空,但 `cpp/dist/`(被 `.gitignore`
    排除的本地运行目录)可能含开发者真实 Key,README 原先把该目录当可分发产物推荐,已加警示。
  - 决策流程补上缺失的第 3 步「已知良性厂商应用」(此前 11 步漏写这一档,正是上面那条旁路
    长期未被发现的原因),并加注「三条信任通道排在显式规则之前,写 Block 规则压不过它们」。
  - 同步修正 `.kiro/steering/product.md` 的 decision priority——原文写作
    「matched rule → threat score → trusted signature → default」,与实际流水线顺序不符。
  - 修正内核 M2 描述:原先只写「遥测 + 启动后结束」,漏掉 `ProcessMonitor.c` 里两条**内核本地
    事前拒绝**(exec-block 名单命中、封禁主体派生子进程 → `STATUS_ACCESS_DENIED`)与
    `HashScan.c` 的内核本地已知恶意哈希查杀,以及「服务不在也拦」的自足基线设计。
  - 驱动源码清单补上 `HashScan.c`、`Policy.c`;解决方案结构补上 `server/`、`Bulwark.Sandbox/`、`ml/`。
  - 配置样例补上 `DefaultAction`(决定弹窗超时后的动作)与 `ReputationProxy`,并列出代码支持
    但样例省略的键(`Etw` 实为 14 个键、`VirusTotal.PriorityDailyReserve`、
    `UiClientAllowedThumbprints` / `UiClientAllowedPublishers` 等)。

---

## [未发布] - 2026-07-02(.NET 原型时期,路径已失效)

### 新增
- **银狐微信/QQ 群控防护(批次 14c)** `Bulwark.Core/Engine/DefaultRules.cs`
  新增 `AddImHarvestAndFrameworkRules`,补齐"银狐控制微信/QQ 群发"链路:
  - 具名群控/hook 模块 DLL 落地与加载(`wxhook`、`WeChatSDK`、`vchat`、
    `WeChatRobotCE`、`wxbotpp`、`WeChatManager`、企业微信 `WeWorkHook`/`wework_api`、
    `wxDump`、`QQHook`)→ **Block**;
  - 微信数据库解密/导出工具命令行(`PyWxDump`、`SharpWxDump`、`wxdump`、
    `WeChatMsg`,群发目标采集前置步骤)→ **Ask**;
  - 补充注入落点:`WeChatOCR.exe`、`WeChatUtility.exe`、`WXWorkWeb.exe`
    (仅未签名注入方命中)→ **Ask**;
  - 企业微信安装目录植入接口 DLL(`WXWork\*\wwapi*.dll`)→ **Ask**。
  - 设计取舍:**不对微信本体正常写库(`MicroMsg.db`/`MSG*.db`)下 FileWrite 规则**,
    避免海量误报,只锁定正常环境不出现的具名外挂特征。
- **规则单元测试** `Bulwark.Core.Tests/SilverFoxImRulesTests.cs`
  把真实内置规则集加载进 `RuleEngine`,以具体事件跑完整决策链验证上述裁决(全部通过)。
- **无害行为测试脚本** `tools/银狐防护测试.ps1`
  复现群控可观测特征(落 `wxhook.dll`、含 `PyWxDump`/`wcferry` 的命令行、向 IM 目录写 DLL)
  用于实机验证监控层+拦截是否生效。脚本不含任何真实群发/窃密逻辑,并自动清理。

### 安全 / 配置
- **停止跟踪 `Bulwark.Service/appsettings.json`**(其中含真实情报源 API 密钥),
  加入 `.gitignore`,改用 **`Bulwark.Service/appsettings.example.json`** 模板(密钥留空)。
  首次使用请复制该模板为 `appsettings.json` 并按下表填入自己的密钥。
- `.gitignore` 补充忽略:`bin_verify_svc/`、`__*.txt`、`ui_out.txt`、`ui_err.txt`、`query` 等调试残留。

---

## 情报源 API 获取地址

各情报源密钥填入 `appsettings.json` 对应节点(`Bulwark:<源>:ApiKey` 或 `AuthKey`)。
以下均为官方申请页面,**请勿将真实密钥提交到仓库**。

| 情报源 | 配置节点 | 申请/获取地址 |
|--------|----------|---------------|
| VirusTotal | `VirusTotal:ApiKey` | https://www.virustotal.com/gui/my-apikey (注册后在个人资料页获取) |
| MalwareBazaar (abuse.ch) | `MalwareBazaar:AuthKey` | https://auth.abuse.ch/ (注册 abuse.ch 账号后生成 Auth-Key) |
| AlienVault OTX | `Otx:ApiKey` | https://otx.alienvault.com/api (登录后在 API 页获取 OTX Key) |
| 微步在线 ThreatBook | `ThreatBook:ApiKey` | https://x.threatbook.com/ (社区版 API Key,个人中心获取) |
| OPSWAT MetaDefender | `MetaDefender:ApiKey` | https://metadefender.opswat.com/ (经 https://id.opswat.com/ 注册获取) |
| Hybrid Analysis (CrowdStrike) | `HybridAnalysis:ApiKey` | https://www.hybrid-analysis.com/apikeys/info (注册后在 API keys 页获取) |
| ThreatFox (abuse.ch) | `ThreatFoxFeed:AuthKey` | https://auth.abuse.ch/ (与 MalwareBazaar 共用 abuse.ch Auth-Key) |

> 提示:各源均可通过 `appsettings.json` 中对应的 `Enabled` 开关单独启停;
> `RequestsPerMinute` / `RequestsPerDay` 为本地限速,请按各源免费额度调整。
