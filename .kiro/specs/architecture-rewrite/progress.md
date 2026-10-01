# 架构重写 · 执行进度与交接

> 配套:`requirements.md`(需求/现状/待定决策)、`design.md`(S0-S14)、`tasks.md`(分阶段任务)。
> 本文件只记**已经做过什么、核实过什么、还卡在哪**。新会话从「下一步」开始接。

最后更新:2026-09-29(第 4 轮)· 阶段 0 批次 1(tasks.md 0.1)。
**01–09 + FP 提交已在本地 `main`(`6137d89..c142146`,领先 origin/main 10 个,未推送)。** 第 4 节决策齐全(4.1-4.7 第 3 轮,4.9 第 4 轮)。
**第 6 节第 1-5 步与 6a 已于第 4 轮完成。下一步是 6b:4.4 的 ImageLoad 签名修复(design B,方案见第 6 步)。**
**⚠ 在 `main` 上直接 `git push` 会把这些提交推到公开仓库;4.1 定的是不推,提交 10 落地后更不能推。**
新会话开场语见第 7 节。

---

## 0. 本机环境(踩过的坑,照做即可)

- **git 拒绝这个仓库**:`.git` 属主 SID 与当前用户不一致(dubious ownership)。
  每条 git 命令都要带 `-c safe.directory=*`。**不要**去改全局 git config。
- **终端不可靠**:PowerShell 回显逐字符重复、中文乱码;`execute_pwsh` 的 `cwd` 参数对中文路径无效
  (shell 会停在上一次的目录,例如 `%TEMP%\bw_sub\shared`);PowerShell 的 `>` 重定向产出 UTF-16,读文件工具读不好。
  **最稳的做法**:Python 脚本放 `%TEMP%\bw_prep\`,脚本里写死 `ROOT = "d:\\新建文件夹 (3)"`,
  subprocess 调 git,结果写成 UTF-8 文件再用读文件工具看。现成脚本见第 2 节。
  提交信息一律 `git commit -F <文件>`,不要在命令行里写 `-m`。
- **git 身份未配置**:仓库与全局都没有 `user.name` / `user.email`。历史提交全部是
  `z614606517zz <z614606517zz@users.noreply.github.com>`。提交时用 `-c user.name=... -c user.email=...`
  传,**不写进 config**(需用户确认身份)。
- `core.autocrlf` 生效:LF 文件会报「LF will be replaced by CRLF」,入库仍是 LF,无害。
- 工具:git 2.55、`cmake`/`ctest`(C:\Program Files\CMake\bin)、python 3.11、VS 2022 Community
  (MSVC 19.44;VS 生成器自己找 cl,**不需要** cl 在 PATH)、Qt 6.8.3(`C:\Qt\6.8.3\msvc2022_64`)。
  **不在 PATH**:`gh`、`ninja`、`cl`、`clang-format`、`clang-tidy`。
- **临时构建配方(已验证)**:
  `cmake -S <tree>\cpp -B <bld> -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH=C:/Qt/6.8.3/msvc2022_64`,
  `cmake --build <bld> --config Release --parallel`,`ctest --test-dir <bld> -C Release`。
  导出源码树时 **`Bulwark.Driver/` 必须和 `cpp/` 放在一起**(服务 `#include` 的是
  `${CMAKE_SOURCE_DIR}/../Bulwark.Driver/Protocol.h`)。全量编译约 5 分钟;MSBuild 重定向输出是 UTF-8,
  `VSLANG=1033` 对它无效。
- 远端:`origin = https://github.com/z614606517zz/-Bulwark.git`,**公开仓库**,11 star / 1 fork,
  `main == origin/main == a60397d`(本轮本地复核,未 fetch),无 stash,无本地其他分支。

---

## 1. 已核实的事实(不用重查)

### 1.1 工作区规模
`git status --porcelain` **227 条**(`-uall` 展开 293 个路径):120 改 / 113 新 / 60 删;
`git diff HEAD --shortstat`:180 files changed, 8152 insertions(+), 14552 deletions(-)。
第 1 轮记的 228 / 294 是 `.gitignore` 忽略 `/_rule_review/` 之前数的(该目录当时算 1 条、2 个文件),
之后又新增了本文件,所以现在是 227 / 293。第 1 轮扫描(01:53)之后,只有 `.gitignore` 与本文件被改过。

### 1.2 60 个删除全部是有意为之
`CHANGELOG.md` 的 `[未发布] / 移除 🗑` 段逐条记录了:垃圾清理整功能、`Bulwark.Sandbox/`、
失效构建脚本、v2.0.x 过期文档、`ml/` 误入库日志。`cpp/*/CMakeLists.txt` 与工作区一致,
没有任何源码 `#include` 已删头文件(只有 `cpp/build/` 下一个陈旧 moc 产物,已 gitignore)。
本轮补查:除 CHANGELOG 的历史条目与本文件外,**没有文件还引用被删的脚本 / 文档**。

### 1.3 敏感内容扫描
脚本 `%TEMP%\bw_scan\scan.py`(本轮经 `%TEMP%\bw_prep\rescan.py` 重跑),报告 `report.txt`,
第 1 轮的报告留在 `report_prev.txt`。两轮结论一致:
- `packaging/redaction-needles.txt` 的 needle #1(令牌)与 #2/#3/#4(三个 IP)零命中;
  #0 是产品域名,9 处(位置见第 4 节 3a),HEAD 里已有 8 个文件含它。
- 通用密钥正则(私钥头/AKIA/gh*_/sk-/AIza/xox*/JWT)零命中;「key 名=字面值」2 条是同一处误报
  (`ml/tools/merge_benign.py:105` 注释里的 `key="vendor+petype"`,以及本文件引用它的一行)。
- `cpp/service/appsettings.json` 三个密钥字段 `VirusTotal.ApiKey` / `ReputationProxy.BearerToken` / `Ai.ApiKey` 均为空(C5)。
- 12 张截图第 1 轮逐张人工看过:全是演示数据,无密钥、无真实域名、无个人信息。

### 1.4 四个组件的改动互相依赖 —— 单独提交编不过
- `cpp/shared` 删掉 `JunkEntry` 与 Junk*/LargeFile* payload,而 HEAD 的 service/ui 还在用;
- `cpp/service/src/main.cpp:786` 调 `DefaultRules::registryWatchFragments()`,只存在于未提交的 shared;
- `cpp/ui/src/pages/RulesPage.cpp` 用 `DefenseRule::requireSigned`,同样只在未提交的 shared 里。
→ shared / service / ui 连续三个提交落地,03、04 两处是红的(静态结论,未实编),05 处为绿(见 1.6)。

### 1.5 提交计划已按字节核对(本轮)
- 路径清单 `.kiro/tmp/commit-plan/NN-*.paths`(UTF-8、NUL 分隔,直接喂 `git add --pathspec-from-file`)。
  293 个路径每个恰好归入一个提交,无遗漏、无重叠。
- 在**临时索引**(`GIT_INDEX_FILE`,不碰真实索引与工作区)里按顺序回放 10 个提交:每一步暂存的集合
  与清单完全一致;最终树 == `git add -A` 的树(两边都带上 07 的 `+x`)。各步树 id 在
  `%TEMP%\bw_prep\trees.json`;01-06 的树不随 spec 编辑变化,05 是构建过的 `488fa9b`,
  10 的树每改一次 spec 就变,以最近一次重跑为准。
  唯一副作用是 `.git/objects` 多了一批松散对象,真正提交时会复用。
- 各提交路径数:01=2、02=9、03=31、04=30、05=126、06=21、07=10、08=39、09=21、10=4
  (第 1 轮写的「driver 11 个文件」不对,是 9 个)。

### 1.6 「05 处构建为绿」已实测(本轮)
提交 05 的树(`488fa9b` = HEAD + 01..05)导出 `cpp/` + `Bulwark.Driver/` 到临时目录,
VS 2022 + Qt 6.8.3 Release 全量编译 **0 错误**,`ctest` **3/3 通过**。临时目录已删,日志留在 `%TEMP%\bw_prep\build05_*.txt`。
06 的 `cpp/CMakeLists.txt` 不影响这个结论:四个目标在 HEAD 里就各自设置了 `/W4 /permissive- /utf-8`,
06 实际新增的只有 `/guard:cf`、`/CETCOMPAT` 等加固项。

### 1.7 内置规则 955 条、ctest 3 条
`bulwark_snapshot.exe --check-ruleset`:「内置规则 955 条,唯一 id 955 个 OK」,与八个 `rules/Rules0*.cpp`
的静态计数一致;`--verify` 对 `corpus.json`/`golden.json` 38 例 0 不匹配。
`cpp/tests/CMakeLists.txt` 定义三条:`verdict_snapshot`、`builtin_ruleset_ids`、`attackchain_regression`
(第三条跑 `bulwark_service --attackchain-selftest`)。spec 里「590 条」「两条 ctest」**本轮已改**。

### 1.8 golden 两例 Ask→Allow:规则按错了字段,不是语料错(本轮,静态阅读,未实跑)
- 驱动 `ImageMonitor.c:179-183` 把被加载模块放进 `TargetPath`(`Driver.h:803` 的 `BlwReportEvent`
  参数顺序是 Type, ActorPid, ParentPid, TargetPath, ImagePath, …);`DriverEventSource.cpp:998-1000`
  把 actorPath 置为 `PID n` 占位、target 置为模块路径;`Worker::enrich` 第 1 步按 PID 把 actorPath
  回填成**宿主进程**映像,第 4 步 `Worker.cpp:878` 的 `actorSigned` 取的是**宿主**的签名。
- `Rules07_Injection.cpp:9-10`(新)与 `InjectionAnalyzer.cpp:148-149`(HEAD 就有)却都假设
  「ImageLoad 的 actorSigned 是被加载模块自身的签名」。
- 所以新的 Temp-DLL 规则(`Rules07_Injection.cpp:72-84`,Block + hard + `unsignedOnly`)实际判的是宿主:
  - 签名宿主 + `%TEMP%` 下未签名 DLL(典型白加黑)**不命中** —— 两例变 Allow 就是这个原因。语料里
    `signed_=true` 表示宿主已签名,恰好正确建模了生产行为;
  - 反过来,未签名宿主从 `%TEMP%` 加载任意 DLL(例如未签名安装包加载自带插件)会被 Block + hardOverride
    —— 疑似误报面,未实测。
- 结论:「改语料重录」会把一个真实漏检藏起来,不能选。

---

## 2. 已做的改动(全部未提交)

- `.gitignore`:新增 `/_rule_review/`(第 1 轮)。
- (第 4 轮)**6.1 脱敏已做**:`ml/tools/github_dl.py` 的 `--out` 默认值 →
  `os.path.join(os.path.expanduser("~"), "Downloads", "github_dl")`(已实测解析到当前用户的 Downloads 下),
  上方注释同步;`server/bulwark-intel/NODE-SETUP.md` 两个私钥文件名 → `<node-access-key>` / `<node-sync-key>`,
  面板端口 → `<dashboard-port>`;`scripts/add-node-sync-key.sh` 第 12、77 行 → `<node-sync-key>`。
  行尾未变(NODE-SETUP.md 与 .sh 为 LF,github_dl.py 工作区为 CRLF,入库 LF);`bash -n` 与 `compile()` 通过。
  `rescan.py`:needle 9 处全是 #0,位置与 4.8 第 3a 项一致;userpath 不再有该 Windows 用户名。
  核对脚本 `%TEMP%\bw_prep\redact_facts.py` / `redact_verify.py`,改前报告另存为 `%TEMP%\bw_scan\report_before_6_1.txt`。
- (第 4 轮)**6.2 已做**:
  - `cpp/shared/include/bulwark/VersionNumbers.h` → 1.0.3(PATCH 3 + STRING "1.0.3",仍纯 ASCII,三数与字符串一致;
    属提交 03,所以 03/04/05 的树 id 都会变,第 4 步必须重跑临时构建)。版本号的唯一源头就是它:
    `Version.h` 有 static_assert,`scripts/make-update-package.ps1` 从它读版本,两个 `app.rc` 用宏。
  - `CHANGELOG.md`(提交 09),共 3 处:
    1. 「新增」条目:不存在的 `addModernAbuseRules` → 实际位置 `cpp/shared/src/engine/rules/`(Rules01–08,现 955 条);
       删掉四项没有规则的(钱包采集、AlwaysInstallElevated、tscon 会话劫持、Telegram·Discord 外传;tscon 只在
       `RemoteControlAnalyzer` 里有检测,a60397d 就有,不是本轮的规则);「凭据与钱包采集」→「凭据窃取」(Rules04 自己的段名)。
    2. **「修复」「性能」两节整体移到新标题 `## [a60397d] - 2026-08-18 (GitHub 同步)` 下**。实测(`git log -S`)两节
       涉及的全部代码(`collectForensics`、`bucketForLocked`、hot/cold 缓存、AuditLog、`--bench`、`SetConsoleOutputCP`)
       和这两节文字本身都是 a60397d 引入的,已在公开 main 上,不是本轮改动(第 3 轮说「两项已在 HEAD」,实际是四项全部 + 修复那条)。
       两节正文与 HEAD **逐字节相同**:588/590 是当时实测的条件,**没有改成 955**(改了等于篡改实测记录);
       修复条目的参数表恢复成 HEAD 原文 `--inspect / --attackchain-check / --junk-scan / --large-files`,
       残句随之消失(CHANGELOG 自己的约定是旧条目里的引用只作历史记录)。
    3. **(清单外,第 4 轮新发现)** 顶部须知「两条 ctest」→「三条」,补上 `attackchain_regression`
       (a60397d 引入第三条后这句就错了)。
  - 局限:1.0.2 是从 HEAD 之后某个未提交的工作区状态出的包,「[未发布]」里有多少其实已随 1.0.2 发出去,
    不做二进制比对就分不清(1.0.2 的 manifest 说明提到了规则集调整、RuleEngine 优先级重写等)。没有处理。
  - 核对脚本 `%TEMP%\bw_prep\changelog_facts.py` / `which_commit.py` / `step2_verify.py`。
- (第 4 轮)`.kiro/tmp/tools/partition.py`:10-spec 的前缀 `.kiro/specs/architecture-rewrite/` → `.kiro/specs/`(4.9b)。
- (第 4 轮)**6.3 已做**,改了 4 份草稿(`.kiro/tmp/commit-msgs/`):
  - `03-shared.txt`:版本一条改为「1.0.0 → 1.0.3」并写明原因;golden 一条去掉「语料标错」的错误归因,
    另起一段 **Known regression**,按 1.8 写清 ImageLoad 的 actorSigned 其实是宿主签名、两例因此变 Allow、
    反方向的疑似误报(注明未实测)、以及紧跟的修复提交。1.8 的几处关键事实本轮重新读代码核对过
    (`DriverEventSource.cpp:994-1005`、`Worker.cpp:772-786,855-878`、`Rules07_Injection.cpp:9-10,72-77`、
    `InjectionAnalyzer.cpp:148-150`)。
  - `08-ml.txt`:`github_dl.py` 默认目录改为 `~/Downloads/github_dl`。
  - `09-docs.txt`:CHANGELOG 一条补上「新增」规则条目、`[a60397d]` 小节的搬移理由、三条 ctest。
  - `10-spec.txt`:标题与正文补上 av-engine / rules-fp-fix 两条线的文档(4.9b)。
  - 01 / 02 / 04 / 05 / 06 / 07 核对后不用改:01 的 `.gitignore` 描述与 diff 一致;06「被删脚本只剩 CHANGELOG
    与 progress 还提到」重新 grep 仍成立(新增的 3 个 spec 文件没提到它们)。
  - 10 份草稿统一检查过:UTF-8、LF、标题 ≤ 72、正文 ≤ 78、无行尾空白、无过时说法与敏感标识
    (`%TEMP%\bw_prep\msg_lint.py`)。
- (第 4 轮)**6.4 流水线已重跑**(4.9e = B):
  - `stage_trees.py` 改写:按 `verified-r3/` 自动算钉住清单(只对 03;其余提交出现外来漂移直接失败)、
    每个提交暂存后用 `git update-index --cacheinfo` 换成已验证 blob、最终树与「`add -A` + 同样的钉住」比对、
    跑完再算一次漂移(期间有变化即失败)、失败时不写 `trees.json` 也不导出。钉住清单写到 `commit-plan/pins.json`。
  - 结果:`partition.py` 296 条全部归属、0 重叠;01-09 的路径清单与第 3 轮**完全相同**,10 = 7 个路径。
    钉住 6 个(均为 rules-fp-fix 的改动):`TrustPolicy.cpp`、`rules/Rules02/03/04/05/07`。
    01、02 的树与第 3 轮相同;**05 的新树 `d70df13` 与第 3 轮构建过的 `488fa9b` 只差 `VersionNumbers.h` 一个文件**;
    最终树 == 工作区(去掉钉住的差异)。新的树 id 见 `%TEMP%\bw_prep\trees.json` / `stage_trees.txt`。
  - 临时构建(树 `d70df13`,全新 build 目录):configure 0、build 0(276 s)、**0 错误**
    (只有 14 行 MSB8029 —— 构建目录在 %TEMP% 下的提示,无害)、**ctest 3/3 通过**、
    `--check-ruleset`「内置规则 955 条,唯一 id 955 个 OK」。产物里 `bulwark_service.exe` / `bulwark_ui.exe`
    都带 1.0.3(ASCII 1 处 + 版本资源 UTF-16 2 处),没有 1.0.2。`tree05/`、`build05/` 已删,日志留在
    `%TEMP%\bw_prep\build05_*.txt`;驱动脚本 `build_all.py`、`verify_and_clean.py`。
  - 04:52 复查(`drift_check.py`):那条线构建期间又改了 Rules02/04/07,并新动了 **Rules06**,外来漂移变成 7 个,
    仍然全在 03 内、01-02 / 04-09 为 0。第 5 步开跑前重跑 `stage_trees.py` 会把 Rules06 一并钉住,05 的树不受影响。
    那条线同时在仓库自己的 `cpp/build` 里编译。
- (第 4 轮)**6.5 已提交 01–09**(`.kiro/tmp/tools/commit_plan.py`,日志 `%TEMP%\bw_prep\commit_log.txt`):

  | # | 提交 | # | 提交 | # | 提交 |
  |---|---|---|---|---|---|
  | 01 | `6137d89` | 04 | `6f93ebe` | 07 | `1e49e24` |
  | 02 | `4edd389` | 05 | `9f99cbb` | 08 | `f0c9bbd` |
  | 03 | `a9c1ca1` | 06 | `41538f9` | 09 | `1b89438` |

  - 开跑前重算的钉住清单是 **8 个**(比第 4 步多了 Rules06、Rules08,都是 rules-fp-fix 在这期间改的),
    01-09 的树与第 4 步构建、测试过的完全相同(05 = `d70df13`)。
  - 每个提交:暂存集合 == 清单、`write-tree` == 计划树、提交后 `HEAD^{tree}` == 计划树、索引复位干净;
    身份 4.2(author = committer);没有 hook,没有 `--no-verify`;单线、无合并。
  - 独立复核 `%TEMP%\bw_prep\verify5.py` 全部 OK:9 个提交的树 / 父提交 / 身份 / 提交信息(与草稿逐字一致)都对;
    工作区只剩 15 项 = 提交 10 的 7 个未跟踪文件 + 8 个钉住文件(`HEAD` 里是已验证内容,工作区保留那条线的改动,
    显示为 ` M`)。那条线要看自己的改动,现在直接 `git diff HEAD -- cpp/shared` 即可。
  - `commit_plan.py` 自己的收尾检查报了一次 MISMATCH,是脚本 bug(`strip()` 吃掉了第一条 ` M` 的前导空格),
    提交本身没问题,已修。`stage_trees.py` / `commit_plan.py` 都以 HEAD = a60397d 为前提,**不要再跑**;
    修复提交、FP 提交、10 要另写脚本。
  - 本机终端的新坑:`execute_pwsh` 经常在命令结束前就返回,后续命令在同一个 shell 里**排队**,
    `Start-Sleep` 也会排队、等不到真正的时间。长任务用 `control_pwsh_process` 起后台进程,轮询结果文件;
    `%TEMP%\bw_prep\run.py <脚本>` 会把异常写进 `run_last.txt`。
- spec 数字(本轮):requirements.md 第 0 节 / 2.1.5 / A0.2 / A1.3 / C2、design.md S11、tasks.md 0.3
  的「590 条」→「955 条」、「两条 ctest」→「三条」。
- 提交信息草稿 **10 份齐了**:`.kiro/tmp/commit-msgs/01-chore.txt` … `10-spec.txt`(UTF-8,英文,已 gitignore)。
  **`03-shared.txt` 最后一段关于两例 ImageLoad 的措辞要按第 4 节第 4 项的决定重写**(现在把原因归到语料上,不准确)。
  若 01/07/08/09 的内容因脱敏或 CHANGELOG 决定而改,对应草稿也要同步。
- 辅助脚本:**副本已存到 `.kiro/tmp/tools/`**(该目录已 gitignore),运行副本即可,无需重写。
  `gitstate.py`(状态快照)、`partition.py`(生成路径清单并校验归属)、`stage_trees.py`(临时索引回放,
  `--export` 时导出 05 的树)、`export_driver.py`、`build05.py`(临时构建 + ctest)、`errs.py`(构建日志摘要)、
  `scan.py` + `rescan.py`(敏感内容扫描)、`dump_diffs.py`。
  **全部脚本把输出写到 `%TEMP%\bw_prep\`,且不会自己建这个目录** —— 若它不存在(重启清过 TEMP),
  先 `New-Item -ItemType Directory -Path "$env:TEMP\bw_prep" -Force`;`rescan.py` 另需
  `$env:TEMP\bw_scan\scan.py`(从 `.kiro/tmp/tools/scan.py` 拷过去)。
  依赖顺序:`partition.py` 读 `gitstate.py` 产出的 `entries.json`;`stage_trees.py` 读 `partition.py`
  产出的 `.paths`;`export_driver.py` / `build05.py` 读 `stage_trees.py` 产出的 `trees.json` 与 `tree05/`。

---

## 3. 提交顺序与执行步骤(10 个提交,不用 `git add -A`)

| # | 提交 | 路径数 | 范围 |
|---|---|---|---|
| 01 | `chore:` | 2 | `.gitignore`、`.kiro/steering/product.md`(加 `inclusion: manual`) |
| 02 | `driver:` | 9 | `Bulwark.Driver/` |
| 03 | `shared:` | 31 | `cpp/shared/`(含新增 `src/engine/rules/` 10 文件)、`cpp/tests/` |
| 04 | `service:` | 30 | `cpp/service/` |
| 05 | `ui:` | 126 | `cpp/ui/`(含 `app.ico`、新增 `src/design/` 等 76 文件) |
| 06 | `build:` | 21 | `cpp/CMakeLists.txt`、`cpp/scripts/dev-all.ps1`、`verify_portable.ps1`、`packaging/redaction-needles.txt.example`,以及删除 `build.bat` / `build_service_v2.ps1` / `cpp/.tools/` / `cpp/build_ui.bat` / `重载v5驱动.bat` / `tools/` 两个 / `scripts/_kiro_*` 四个 / `Bulwark.Sandbox/` |
| 07 | `server:` | 10 | `server/bulwark-intel/` 8 文件 + 新增 `scripts/add-node-sync-key.sh`、`scripts/enable-master-tls.sh` |
| 08 | `ml:` | 39 | `ml/` 改 2 / 删 19 / 新 15 + `scripts/_export_labels.py`、`_export_malicious_list.py`、`_vt_lookup_bulk.py` |
| 09 | `docs:` | 21 | `README.md`、`README.en.md`、`CHANGELOG.md`、`SYSTEM_TOOL_PROTECTION.md`、删 5 个过期文档、`docs/screenshots/`(10 改 + 2 新) |
| 10 | `docs:` | 4 → 7 | `.kiro/specs/`:`architecture-rewrite/`(含本文件)+ `av-engine/handoff.md`、`av-engine/proposal.md` + `rules-fp-fix/progress.md`(4.9b;另两条线还在写,以第 4 步重跑为准) |

**执行顺序(4.9d)**:01–09 → 4.4 的修复提交 → 10。10 必须始终在最顶上,
以后「除 10 以外都公开」只需推 `HEAD~1`,不用改写历史。表中路径数是第 3 轮的,第 4 步重跑 `partition.py` 后以新结果为准。

每个提交的步骤(下一轮写成一个脚本执行,任何一步不符即停):
1. 开始前真实索引必须干净(`git diff --cached --quiet`);
2. `git --literal-pathspecs add --pathspec-from-file=.kiro/tmp/commit-plan/NN-*.paths --pathspec-file-nul`;
   07 另加 `git add --chmod=+x -- scripts/add-node-sync-key.sh scripts/enable-master-tls.sh`
   (两个脚本带 shebang、Usage 按直接执行写;仓库里原有的两个 `.sh` 是 100644,由部署步骤 install,不受影响);
3. `git diff --cached --name-only -z` 必须与清单完全一致;
4. 开工前重跑一次 `stage_trees.py` 刷新 `trees.json` / `pins.json`;逐个提交时 `git write-tree` 必须与之相同
   (03 先按 `pins.json` 换成已验证 blob 再比)。05 的树若已不是 `d70df13`(第 4 轮构建过的;说明 01-05 里有
   钉住之外的文件改过,例如 golden 修复),先用 `stage_trees.py --export` + `build_all.py` 重跑临时构建;
5. `git -c user.name=... -c user.email=... commit -F .kiro/tmp/commit-msgs/NN-*.txt`(不加 `--no-verify`)。
10 提交完(即修复提交之后)`git status --porcelain` 应为空。

---

## 4. 决策(2026-09-29 第 3 轮:已全部拍板)

> 以下 7 条是执行依据,不要再问。原「待拍板」清单原文保留在 4.8 供追溯。

- **4.1 推送目标** = 先本地提交 + `git bundle` 拷到机器外做异地备份。**不推 main,也不推公开分支。**
- **4.2 git 身份** = `z614606517zz <z614606517zz@users.noreply.github.com>`,
  用 `-c user.name=... -c user.email=...` 传入,**不写进 config**。
- **4.3 脱敏**(对应 4.8 第 3 项 a-e):
  - a 生产域名 —— **保留**,不动。
  - b `ml/tools/github_dl.py:14` —— Windows 用户名 + 桌面路径**改成通用默认值**。
  - c `NODE-SETUP.md` / `scripts/add-node-sync-key.sh` —— SSH 私钥**文件名**与节点面板端口**改占位符**。
  - d `ml/` 里本机活样本库绝对路径 —— **保留**。
  - e **提交 10(spec)只放本地 + 进 bundle,不公开**;等其中记录的弱点修掉再考虑公开。
- **4.4 golden 两例** = 方案 **A**。原样提交,03 的提交信息**如实写明这是已知回归**;
  紧跟一个**单独的修复提交**:ImageLoad 富化出**被加载模块自身**的签名,image 规则的 `unsignedOnly` 判它;
  修好后两例应为 Block,**重录 golden**,并重跑 `stage_trees.py --export` + `build05.py`。
- **4.5 CHANGELOG** = **修**,但**只改事实错误**(4.8 第 5 项列的那些),不做润色扩写。
- **4.6 版本号** = **1.0.3**(`VersionNumbers.h`;1.0.2 已于 2026-08-31 发布过,`UpdateService` 拒同版本)。
- **4.7 D1-D7** = 全部采纳 `requirements.md` 第 3 节「我的建议」,**已回填该表**。
- **4.9(第 4 轮,用户:「按照你的建议来」)**,对应 6.1a:
  - a 脱敏范围**维持 4.3c 字面范围**,不扩大:服务端 unit / 代码里的密钥路径与端口是功能性默认值,不动。
  - b `av-engine/handoff.md`、`rules-fp-fix/progress.md` **并入提交 10**(只放本地 + bundle,理由同 4.3e)。
  - c **第 4-5 步期间 rules-fp-fix 暂停改提交 03 的文件**(用户负责协调)。第 4 步开跑前、第 5 步每个提交前
    都核对 03 的树;变了就停,不要把变化带进提交。
  - d **执行顺序 01–09 → 修复提交 → 10**(见第 3 节)。
  - f **第 6 步的顺序**(用户:「我不懂按照你推荐的来」):先把 rules-fp-fix 做完的改动单独提交(FP 提交),
    再在它之上做 4.4 修复,最后提交 10。那条线 13:13 已完成它的批 7(950 条 / 950 id、golden 38 例 0 不一致),
    改动自 04:57 起没再动过。4.4 的修复按 design B 做(见第 6 步)。
  - e **6.2a 选 B**(用户:「按照你的推荐继续就行了」):03 钉在第 3 轮已验证内容 + 本轮自己的改动;
    rules-fp-fix 的改动留在工作区,之后单独提交(排在 10 之前)。钉住清单由 `stage_trees.py` 自动算出并写入
    `.kiro/tmp/commit-plan/pins.json`,参照物是 `.kiro/tmp/commit-plan/verified-r3/`(第 3 轮的 `trees.json` 与 `.paths`)。
    01-02 / 04-09 若出现非本轮自己改动的漂移,**不钉,直接失败**。

### 4.8 原待拍板清单(保留追溯,勿再据此提问)

1. **D1-D7**:两轮都是占位。不阻塞阶段 0,进阶段 1 前填 `requirements.md` 第 3 节即可。 → 见 4.7,已填。
2. **推送目标 + git 身份**。远端是公开仓库;推分支同样公开,所以第 3 项要先定。
   另一条路:先本地提交 + `git bundle` 拷到机器外,满足「异地有一份」,公开推送等脱敏定了再做。
3. **公开仓库脱敏取舍**(进了公开历史就删不掉):
   - a. 生产域名:`server/bulwark-intel/about.html` 新增的 752-766 行、`scripts/enable-master-tls.sh` 的 `DOMAIN` 默认值、
     `ml/tools/export_targets.py:39,244` 的用法示例。HEAD 里已有 8 个文件含它。
   - b. `ml/tools/github_dl.py:14`:Windows 用户名 + 桌面路径(HEAD 里已有,现作 `--out` 默认值)。
   - c. `NODE-SETUP.md` 与 `add-node-sync-key.sh`:SSH 私钥**文件名**(含疑似节点末位八位组的昵称),无密钥内容;
     `NODE-SETUP.md:57` 提到节点面板端口。
   - d. `ml/` 若干脚本里本机活样本库的绝对路径。
   - e. **(本轮新增)提交 10 本身**:spec 逐条写了尚未修复的弱点与绕过方式(`isDevTool` 改名绕过、驱动上报过滤让
     名单外 System32 程序无事件、攻击链组合表无签名且随包 `DryRun: false`、AI 清理执行任意脚本、密钥明文跨进程),
     还有事故细节与开发机工具清单(`~/.claude`、`~/.config/clash` 等)。代码虽公开,但这等于一份现成的攻击清单。
     可选:照推;或提交 10 只放本地分支 + bundle 备份,等对应问题修掉再公开。
4. **golden 两例**(见 1.8):不能「改语料」。可选:
   - A. 原样提交,03 的提交信息如实写明这是已知回归,紧跟一个单独的修复提交(ImageLoad 富化出模块自身的签名,
     image 规则的 `unsignedOnly` 判它;修好后两例应为 Block,重录 golden,重跑临时构建);
   - B. 先修再提交 03。
5. **`CHANGELOG.md` 与代码不符**(09 里修不修):`addModernAbuseRules` 全树不存在;tscon / Telegram·Discord 外传 /
   AlwaysInstallElevated / 钱包采集没有对应规则;「每事件热路径 −54%」两项(RuleEngine 分桶索引、wildcardMatch
   ASCII 快路径)已在 HEAD,不属于本轮;588/590 条规则的数字是旧的(实为 955);「修复」段删 `--junk-scan` /
   `--large-files` 后留下残缺的「`--attackchain-check` / )」。
6. **版本号**:`VersionNumbers.h` 升到 1.0.2,但 `build_update/*/manifest.json` 已于 2026-08-31 发布过 1.0.2;
   `UpdateService` 拒绝同版本,已装 1.0.2 的客户端收不到这一版。

---

## 5. 顺手记下的缺陷(与提交无关,别丢)

- 陈旧注释:`cpp/tests/SnapshotTool.cpp:827-829,865-866`(称 build() 返回空集,实为 955);
  `DefaultRules.cpp:16` 与 `rules/Rules01_SystemMaintenance.cpp:9-10`(称 RuleEngine 步骤 6 阻止内置
  Allow 覆盖硬指标,`RuleEngine.cpp` 里并无此逻辑,`RuleDsl.h:39-42` 自己也这么说);
  `ThreatDetector.cpp:114-118`(称 golden 记的是 Allow)。
- `Rules02_Persistence.cpp:252` 的注释假设 Rules01 的 TrustedInstaller/TiWorker Allow 规则能压过
  `:258` 的辅助功能二进制替换硬规则,但 `ruleTier` 把 hardOverride 排在前面 —— Windows Update
  替换 `sethc.exe` 会被 Block。静态阅读结论,未实跑。
- (本轮)ImageLoad 的 `actorSigned` 语义被误解(见 1.8),`InjectionAnalyzer` 的侧载判据在 HEAD 里就受影响。
- (本轮)`cpp/CMakeLists.txt` 加固段注释说此前「完全跑在 MSVC 默认值上……警告级别也是默认的 /W1」,不准:
  四个目标在 HEAD 里就各自开了 `/W4 /permissive- /utf-8`。
- (本轮)README 说测试是「裁决快照回归 + 内置规则 id 唯一性」两项,实为三项;仍写着
  「manifest 已声明 requireAdministrator」(与 0.8 相关)。
- 空白行:`cpp/ui/src/ipc/IpcClient.h:79` 与 `:123`(`git diff --check` 只报这两处)。
- `cpp/service`:`CMakeLists.txt:59` 遗留空行;`main.cpp:516` 注释过长;`main.cpp:605` 手拼
  `%ProgramData%\Bulwark` 而没走 `programDataDir()`,`BULWARK_DATA_DIR` 覆盖失效;
  `ReputationCurl.cpp:56` 的 `static bool warned` 多线程无同步;`main.cpp:2053,2056` 的
  `fprintf(stderr,...)` 在 SCM 下无处可去。
- UI 每次启动(非 `BULWARK_UI_SMOKE`)都会写 HKCU Run 自启值,开发构建也会。

---

## 6. 下一步

**决策已齐(第 4 节)。第 1-5 步已完成,从第 6 步接着做,每步做完停下来给用户看。**

1. ✅ **(第 4 轮完成)按 4.3 做脱敏改动**,细节见第 2 节。更正:`NODE-SETUP.md` 在
   `server/bulwark-intel/` 下,和 `add-node-sync-key.sh` **同属提交 07**(原文写「09 / 07」不对);
   `github_dl.py` 属 08。所以第 3 步只涉及 07、08 两份草稿(见 6.1a 第 4 条)。

   **6.1a 第 4 轮新发现**(用户已按下列建议拍板,见 4.9;第 2 条对应的 `partition.py` 已改):
   1. **这几个标识早已在公开的 HEAD 里**,本步只是不再新增:`id_bulwark_node245`(HEAD `NODE-SETUP.md:51`)、
      `id_sync23`(HEAD `NODE-SETUP.md:53`、`bulwark-sync.py:20`、`bulwark-sync.service:12,19`、
      `bulwark-benign-push.py:42`、`bulwark-benign-push.service:10,18`)、`8788`(HEAD `dashboard.py:46`、
      `bulwark-dash.service:11`)、Windows 用户名(HEAD `github_dl.py:12`、`gen_intel_rules.py:128-129`、
      `cpp/.tools/` 四个文件,后者由 06 删除)。工作区里上述服务端文件的同名引用**是功能性默认值**
      (unit 的 `Environment=`、代码默认值),超出 4.3c 范围,没改;「node 245」「master (23)」昵称与
      `bulwark-245-sync-to-23` 公钥注释同样到处都是。**结论:4.3c 实际是装饰性的**,真要藏住需要改部署
      (节点上的密钥文件改名 + 重新下发 unit),且历史里仍在。`gen_intel_rules.py` 未改、不在任何提交里。
   2. **多了 2 个未规划路径**(`-uall` 现为 295 条):`.kiro/specs/av-engine/handoff.md`(03:37)、
      `.kiro/specs/rules-fp-fix/progress.md`(03:56)—— 另两条工作线的交接文档,`partition.py` 会报 UNASSIGNED,
      第 5 步末尾「`status` 为空」也不会成立。**第 4 步前要定归属**:建议并入提交 10(同样只放本地 + bundle,
      理由同 4.3e),`partition.py` 里 10 的前缀从 `.kiro/specs/architecture-rewrite/` 放宽到 `.kiro/specs/`。
   3. **rules-fp-fix 工作线正在活动**(其 progress.md 03:56:08 刚写过),按它的计划会逐批改
      `cpp/shared/src/engine/rules/`,也就是提交 03 的文件。此刻 03 的 31 个路径与已验证树 `4039974`
      **逐字节一致**(`%TEMP%\bw_prep\tree03_check.py`;03:46:03 那次 10 个 shared 文件的 mtime 变化只是 touch,
      内容没变)。**第 4-5 步期间那条线要暂停改 03 的文件**,否则会把半成品规则修改混进 03,且 05 的构建结论作废。
   4. 第 3 步要改的草稿:`08-ml.txt` 的「github_dl.py now takes --out」应补一句默认目录已改成按用户的通用路径
      (本机不带 `--out` 跑会下到新目录,旧的 `[have]` 跳过不再生效);`07-server.txt` 不涉及文件名/端口,不用改。
   5. 顺序建议:4.3e 要求 10 不公开,但第 6 步的修复提交排在 10 **之后**,以后想「除 10 以外都公开」就得改写历史。
      建议执行顺序改为 01-09 → 修复提交 → 10(让 10 始终在最顶上),或把 10 放到单独的本地分支。
2. ✅ **(第 4 轮完成)`VersionNumbers.h` → 1.0.3;`CHANGELOG.md` 只修事实错误**,细节与偏离清单之处见第 2 节
   (588/590 没改成 955、修复条目恢复 HEAD 原文、清单外多修了「两条 ctest」)。

   **6.2a 第 2 步期间的新情况(待用户拍板,第 4 步前必须定):**
   1. **04:19 `cpp/shared/src/engine/TrustPolicy.cpp` 被 rules-fp-fix 线改了**(不是本线):`systemDirs()` 加
      `\windows\servicing\`(+11/-1,修的正是第 5 节记的「Windows Update 替换 sethc.exe 会被 Block」)。
      提交 03 的内容因此又变了,且那条线仍在活动。两个做法:
      - A 随 03 一起提交:等那条线做完当前批次再冻结;03 的提交信息补一句;它可能改变裁决,golden 要看第 4 步 ctest。
      - B **03 钉在已验证内容**(建议):第 4-5 步对这类文件用 `git update-index --cacheinfo` 暂存已验证的 blob,
        工作区不动;FP 改动之后由那条线单独提交(排在 10 之前)。历史干净,05 的构建验证的就是实际提交的内容;
        `stage_trees.py` 与提交脚本要加一份「钉住清单」。任何未列入清单的漂移仍按第 3 节规则即停。
   2. 04:12 新增 `.kiro/specs/av-engine/proposal.md`,按 4.9b 的前缀自动归入 10,无需处理。
   3. (第 3 步时补查)那条线**还在改 03 的文件**:04:20:09 `TrustPolicy.cpp` 又改了一次,04:20:35
      `rules/Rules02_Persistence.cpp`、04:21:33 `rules/Rules03_DefenseEvasion.cpp` 也动了。选 B 的话钉住清单
      至少是这三个,取值用已验证树 `4039974` 里的 blob;选 A 的话要等那条线停手,第 4 步重跑
      `--check-ruleset`,955 若变了,CHANGELOG「新增」条目与 03 / 09 草稿里的数字一起改,03 草稿再补一条讲 FP 修改。
3. ✅ **(第 4 轮完成)同步提交信息草稿**,细节见第 2 节。草稿按 6.2a = B 写(03 不含 rules-fp-fix 的改动);
   修复提交与(选 B 时)FP 提交的草稿在第 6 步再写。
4. ✅ **(第 4 轮完成,结果见第 2 节)重跑流水线**(第 1-2 步改动落在 03、07、08、09,必然影响树 id)。
   `gitstate.py` → `partition.py` → `stage_trees.py` → `export_driver.py` → `build05.py`
   (`partition.py` 读 `entries.json`,新增的两个 spec 文件要先经 `gitstate.py` 进 `entries.json`)。
   05 的树必然不再是 `488fa9b`(1.0.3 在 03 里),以这次重跑的结果为准,并确认编译 0 错误 + ctest 3/3。
5. ✅ **(第 4 轮完成,提交号见第 2 节)按第 3 节执行 01–09 共 9 个提交**(脚本化,逐步核对,**任何一步不符即停**)。开跑前先重跑一次
   `stage_trees.py`(不带 `--export`)刷新 `pins.json` / `trees.json`,05 的树若不再是 `d70df13` 就停(说明
   01-05 里出现了钉住之外的变化,需要重新构建)。03 暂存后按 `pins.json` 逐条
   `git update-index --add --cacheinfo`(与 `stage_trees.py` 同一逻辑),再比 `write-tree`。
   身份用 4.2;不用 `git add -A`;不加 `--no-verify`。此时 `status` 只应剩提交 10 的路径
   (若 6.2a 选 B,再加上被钉住、留在工作区的 rules-fp-fix 改动)。
6. **(4.9f)6a FP 提交 → 6b 4.4 修复提交 → 6c 提交 10**。完成后 `git status --porcelain` 应为空。
   - ✅ **6a 已提交 `c142146`**(`rules: cut false positives in the built-in rules, keep detection`,树 `56f7be6`,
     日志 `%TEMP%\bw_prep\fp_commit_log.txt`):临时构建 0 错误(267 s)、ctest 3/3、`--check-ruleset` 950/950、
     `--dump-rules` 与 `rules_after.json` 逐条一致;树 / 身份 / 提交信息 / 索引干净全部核对通过;工作区只剩
     `.kiro/specs/` 下 8 个未跟踪文件(提交 10 的范围)。已在 `rules-fp-fix/progress.md` 第八节记了一行,告诉那条线已代提交。
   - 6a:`.kiro/tmp/tools/fp_commit.py` + 草稿 `commit-msgs/11-rules-fp.txt`。提交 = 8 个 FP 文件 + `CHANGELOG.md`
     (规则数 955 → 950,`[未发布]` 补一条「变更 · 内置规则误拦截治理」)。脚本先在临时目录编译、测试**将要提交的那棵树**
     (ctest 3/3、`--check-ruleset` 950、`--dump-rules` 与那条线的 `.kiro/tmp/rules_after.json` 逐条相同),才动真实索引。
   - ⚠ **6b 的前两小步已被 klids.sys 那条线做掉了(2026-09-30,未提交,见 `rules-fp-fix/progress.md` 第九节)**:
     `SecurityEvent::targetSigned` / `targetSignatureMismatch` 已加并序列化;`DefenseRule` 已有
     `requireTargetUnsigned` / `requireTargetSigned`(DSL:`targetUnsignedOnly()` / `targetSignedOnly()`),
     `Worker::enrich` 已有第 3.9 步对**全部** ImageLoad(含 `actorPid == 0` 的驱动加载)富化模块签名。
     **6b 只剩下「把既有消费点改读模块字段」那部分**:`DefenseRule::matches` 的 `requireUnsigned` /
     `requireSigned`、`InjectionAnalyzer.cpp:148-150`、`RemoteControlAnalyzer.cpp:249`、
     `Worker.cpp:507-512` 的 Ask→放行、`maybeQuarantineOnBlock`、`SnapshotTool` 的 EventSpec + golden 重录。
     那条线刻意**没动**这些(会改裁决快照),并在 `Rules07` 段头写明段 7.3 仍在判宿主、归 6b。
     另:段 7.4 的两组通用 `.sys` 规则已按模块签名分档(7 → 14 条),内置规则总数在工作区里是 977。
   - 6b 修复按 **design B**(context-gatherer 第 4 轮的比较结论:A 会悄悄改掉约 20 处按「宿主」理解
     actorSigned 的消费点,且快照测试看不见):
     - ✅(已做)`SecurityEvent` 新增 `targetSigned` / `targetSignatureMismatch`(被加载模块自身的签名),
       `toJson` / `fromJson` 增加对应键(旧报文缺键 = 未签名,与现状一致)。**实际实现对驱动加载也富化**,
       与原计划「只对 `actorPid > 0` 有意义」不同 —— 段 7.4 的分档正需要驱动自己的签名;
       `actorSigned` 的语义没动,所以 FP 线那批 BYOVD Ask 规则不受影响;
     - `DefenseRule::matches` 的 `requireUnsigned` / `requireSigned`、`InjectionAnalyzer.cpp:148-150`、
       `RemoteControlAnalyzer.cpp:249` 对用户态 ImageLoad 改读模块字段;**`actorPid == 0` 的驱动加载保持原语义**
       (FP 给「仍在用」组 BYOVD 写的 Ask 依赖它);
     - `Worker::enrich` 给用户态 ImageLoad 求模块签名(放在「宿主未解析就返回」之前;事件量小:驱动只报 Temp / Public);
     - `Worker.cpp:507-512` 的「签名主体 Ask→放行」对用户态 ImageLoad 改看模块签名(不改就会把新的 Ask 全部静默放行);
     - `maybeQuarantineOnBlock` 跳过 ImageLoad(宿主不是载荷;否则签名宿主会因加载坏 DLL 被搬进隔离区);
     - 注释:`Rules07_Injection.cpp:9-10`、`AttackChainEngine.cpp:1054-1056`(`moduleSignature` 覆盖位先不翻,
       服务端是否依赖它未核实);
     - `SnapshotTool` 的 `EventSpec` 加模块签名字段,两例保持「模块未签名」,另加一例「签名宿主 + 签名模块」作对照;
       重新生成 corpus、重录 golden。因 FP 已把三条 Temp-DLL 规则降为 Ask,**两例修好后是 Ask(不是 4.4 当时写的 Block)**。
   - 文档里的 955:`requirements.md` 第 0 节 / A1.3 / C2、`design.md` S11、本文件 1.7 仍写 955,FP 提交后实为 950,
     下次动 spec 时一并改(都在提交 10 里)。
   - **又一条并行工作线**:`.kiro/specs/dropped-file-taint/handoff.md`(13 点多新出现,「释放物拦截缺口」,
     状态「一行代码都还没改」)。它把 `Worker.cpp` 当「主战场」(污点登记、用户点阻止时清理、放开 remediateIfMalicious),
     与 6b 改的 `Worker.cpp` 同文件。**6b 做完并提交之前,那条线不要动 Worker.cpp**;它的交接文档里的行号会因 6b 平移。
     该文件按 4.9b 归入提交 10(`fp_commit.py` 已放行 `.kiro/specs/` 下的新文件)。
   **动手前先和 rules-fp-fix 对齐(第 4 轮发现,`%TEMP%\bw_prep\pin_diffs.txt`)**:那条线在工作区(已钉住)里把
   Rules07 的三条 Temp-DLL 规则从 Block+hard 降成 Ask、伪装扩展名去掉 `*.tmp`、BYOVD 名单拆成 Ask(仍在用)/
   Block(仅攻击)两组、`sc create type= kernel` 降成 Ask。影响:
   - 修复提交若基于已提交的 03(Temp-DLL 仍是 Block+hard),修好后两例是 Block;FP 提交落地后会变 Ask,golden 再录一次。
   - 修复若把 ImageLoad 的 `actorSigned` 改成模块自身签名,内核加载 `.sys` 时模块就是驱动(BYOVD 驱动都有合法签名)
     → `actorSigned` 变真。FP 那条线给「仍在用」组写的 Ask 规则,注释里明确依赖「驱动加载时 actorSigned 恒假」
     (引 `DriverEventSource.cpp:994-998`)。修复要么对 `actorPid==0` 的驱动加载保持原语义,要么两边一起改。
   - 两个提交都改 Rules07,先后顺序要和那条线约定。
7. **`git bundle create` 出全仓 bundle,拷到机器外**;确认异地可 `git clone` 校验 → 关掉 A0.1。
   **不推 main、不推公开分支**(4.1)。随后 0.2 异地备份(**尚未盘点数据量**)。
8. 阶段 0 余下:0.3 CI(本机无 gh/ninja/clang-tidy)、0.4 clang-format/tidy、
   0.5 事件录制(**必须尽早跑起来攒一周数据,否则 1.8 没数据**)、0.6 样本隔离、
   0.7 脚本盘点、0.8 查清 UI 实际 UAC 级别。

## 7. 给下一个会话的启动提示(照抄即可)

会话历史一旦膨胀容易触发 Kiro 的「selected model cannot continue this conversation」。
**新会话不要一次读四份 spec**,按下面这句开场:

> 接着 Bulwark 架构重写做。只读 `.kiro/specs/architecture-rewrite/progress.md`,
> 决策已在它第 4 节全部拍板,从第 6 节第一个没打 ✅ 的步骤开始,每批做完停下来给我看。
> 需要 requirements/design/tasks 的细节时再单独读对应小节,不要整份读。
