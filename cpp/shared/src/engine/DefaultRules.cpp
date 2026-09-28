#include "bulwark/engine/DefaultRules.h"
#include "bulwark/engine/EngineCommon.h"
#include "rules/RuleDsl.h"
#include <QSet>
#include <QStringList>
#include <QRegularExpression>

namespace bulwark::engine {

using detail::fileNameLower;

//
// builtInTag() 是内置规则的身份标记,两处依赖它:
//   · main.cpp 启动时把 rules.json 里备注以 "[内置]" 开头的历史副本过滤掉(内置规则以代码为准,
//     否则每次落盘 + 重启都会重复累积);
//   · RuleEngine 步骤 6 据此识别内置规则,执行「内置规则只加强、不削弱」的约束。
//
QString DefaultRules::builtInTag() {
    return QString::fromUtf8("[\xe5\x86\x85\xe7\xbd\xae]"); // "[内置]"
}

namespace {

const QSet<QString>& devToolProcessNames() {
    static const QSet<QString> s = {
        "devenv.exe", "code.exe", "rider64.exe", "idea64.exe", "pycharm64.exe",
        "webstorm64.exe", "clion64.exe", "goland64.exe", "datagrip64.exe",
        "phpstorm64.exe", "rubymine64.exe", "android studio.exe", "notepad++.exe",
        "sublime text.exe", "atom.exe",
        "msbuild.exe", "dotnet.exe", "nuget.exe", "npm.exe", "yarn.exe", "pnpm.exe",
        "node.exe", "python.exe", "pip.exe", "cargo.exe", "gradle.exe", "mvn.exe",
        "ant.exe", "make.exe", "cmake.exe",
        "git.exe", "svn.exe", "hg.exe",
        "docker.exe", "podman.exe", "vagrant.exe",
        "jenkins.exe", "agent.exe", "runner.exe", "buildkite-agent.exe",
        "testhost.exe", "vstest.console.exe", "nunit-console.exe", "xunit.console.exe",
        "jest.exe", "mocha.exe",
        "choco.exe", "scoop.exe", "winget.exe", "installer.exe", "setup.exe",
    };
    return s;
}

const QStringList& devToolPathPatterns() {
    static const QStringList s = {
        "\\microsoft visual studio\\", "\\jetbrains\\", "\\vscode\\",
        "\\visual studio code\\", "\\android studio\\", "\\notepad++\\",
        "\\sublime text\\", "\\atom\\", "\\python\\python", "\\nodejs\\",
        "\\dotnet\\", "\\git\\", "\\docker\\", "\\jenkins\\", "\\gradle\\",
        "\\maven\\", "\\nuget\\", "\\npm\\", "\\yarn\\", "\\.nuget\\", "\\.cargo\\",
        "\\.gradle\\", "\\.m2\\", "\\packages\\", "\\node_modules\\", "\\venv\\",
        "\\env\\", "\\.venv\\", "\\.env\\",
    };
    return s;
}

//
// 内置规则的统一创建时刻。
//
// DefenseRule::createdUtc 默认取构造瞬间的 nowUtc(),同一批内置规则彼此相差几毫秒且每次启动
// 都不同;而 RuleEngine 步骤 6 在「层级 > 具体度 > 动作强度」打平时取较新者 —— 胜出者会随
// 构造先后抖动。固定成一个早于任何用户规则的时刻后:
//   · 内置规则之间打平,落到末级按 id(稳定 UUIDv5)定序,跨启动、跨机器一致;
//   · 与用户规则打平,用户规则恒为「较新」而胜出 —— 用户的显式选择优先于内置默认。
//
QDateTime builtInEpochUtc() {
    static const QDateTime t =
        QDateTime::fromString(QStringLiteral("2020-01-01T00:00:00Z"), Qt::ISODate).toUTC();
    return t;
}

// 按规则的【判别性内容】派生 UUIDv5:同一条内置规则在任何机器、任何一次启动上都是同一个 id。
// loadRules 以 id 为 QHash 键,撞 id = 后者静默顶掉前者;测试 builtin_ruleset_ids 把它钉成失败。
QUuid stableIdFor(const DefenseRule& r) {
    QString key;
    key.reserve(256);
    const QChar sep(0x1f);
    key += r.note;               key += sep;
    key += r.actorPath;          key += sep;
    key += r.actorPattern;       key += sep;
    key += r.targetPattern;      key += sep;
    key += r.commandLinePattern; key += sep;
    key += r.parentPattern;      key += sep;
    key += r.type.has_value() ? QString::number(static_cast<int>(*r.type)) : QStringLiteral("-");
    key += sep;
    key += QString::number(static_cast<int>(r.action));
    key += sep;
    key += r.requireUnsigned ? QLatin1Char('1') : QLatin1Char('0');
    key += r.requireSigned ? QLatin1Char('1') : QLatin1Char('0');
    key += r.hardOverride ? QLatin1Char('1') : QLatin1Char('0');
    key += r.exemptTrustedOsComponent ? QLatin1Char('1') : QLatin1Char('0');
    QStringList hashes(r.actorHashes.cbegin(), r.actorHashes.cend());
    hashes.sort(Qt::CaseInsensitive);
    key += sep;
    key += hashes.join(QLatin1Char(',')).toUpper();
    return QUuid::createUuidV5(QUuid{}, key.toUtf8());
}

} // anonymous namespace

// ---------------------------- 规则段 DSL 实现 ----------------------------

namespace rules {

Segment::Segment(QVector<DefenseRule>& out, const char* category)
    : out_(out),
      prefix_(DefaultRules::builtInTag() + QLatin1Char(' ') + QString::fromUtf8(category) +
              QString::fromUtf8(" \xc2\xb7 ")) // " · "
{
}

RuleRef Segment::add(EventType type, VerdictAction action, const char* note) {
    return add(type, action, QString::fromUtf8(note));
}

RuleRef Segment::add(EventType type, VerdictAction action, const QString& note) {
    DefenseRule r;
    r.type = type;
    r.action = action;
    r.note = prefix_ + note;
    out_.append(r);
    return RuleRef(out_.last());
}

} // namespace rules

//
// ============================== 内置防护规则库 ==============================
//
// 分 8 段编写,每段一个源文件(src/engine/rules/RulesNN_*.cpp),按下列顺序拼接:
//   段 1 系统维护放行   段 2 持久化        段 3 防御规避      段 4 凭据窃取
//   段 5 勒索与破坏     段 6 执行与 LOLBin  段 7 注入/侧载/BYOVD  段 8 横移/远控/C2
//
// 顺序只影响 --dump-rules 的导出顺序,不影响裁决:步骤 6 的排序比较器是全序
// (层级 > 具体度 > 动作强度 > 创建时刻 > id),与候选集的枚举顺序无关。
//
QVector<DefenseRule> DefaultRules::build() {
    QVector<DefenseRule> list;
    // 预留按实际规模给:多段规则是按名单交叉展开的(父进程 x 脚本宿主、安全软件 x 动词),
    // 条数以百计。留不够只是多几次 realloc + 拷贝,但这是每次服务启动都要走一遍的路径。
    list.reserve(900);

    rules::addSystemMaintenanceRules(list);
    rules::addPersistenceRules(list);
    rules::addDefenseEvasionRules(list);
    rules::addCredentialAccessRules(list);
    rules::addImpactRules(list);
    rules::addExecutionRules(list);
    rules::addInjectionRules(list);
    rules::addLateralAndC2Rules(list);

    const QDateTime epoch = builtInEpochUtc();
    for (DefenseRule& r : list) {
        r.createdUtc = epoch;
        r.id = stableIdFor(r);
    }
    return list;
}

//
// 内置注册表规则需要的「受关注键」片段。
//
// 注册表事件只在键命中受关注名单时才产生(驱动 RegistryMonitor 与 ETW Kernel-Registry 同一模型),
// 默认名单(appsettings 的 ProtectedRegistryKeys)只有 Run / RunOnce / Policies\Explorer\Run /
// IFEO / Winlogon / Services。本库在段 2~5 里写的 Defender 策略、UAC、LSA、WDigest、RDP、
// SafeBoot 等规则,键都不在默认名单里 —— 不补片段,这些规则结构性永不命中。
//
// 取片段的三条原则:
//   · 只到【键】这一级:驱动按键路径匹配名单(不含值名),写到值名的片段在驱动侧永远不命中;
//   · 每个片段都指向一件具体的事,不收 \Software\、\Control\ 这类什么都有的宽片段 ——
//     这份名单决定内核上报量,宽片段会把系统组件的高频写全部拉进上报通道;
//   · 仅上报、不拦截:受关注键在驱动里是「上报后放行」,真正的处置由规则裁决后事后补偿。
//
// 片段数受内核名单容量约束(BLW_MAX_PROTECTED = 64,与 appsettings 默认 6 条、攻击链派生
// 至多 24 条共用),本表保持在 26 条以内(6 + 26 + 24 = 56 < 64,仍留余量)。
//
// 【这份名单必须被服务真的用上】它曾经只是「声明 + 定义 + 注释」,没有任何调用点 ——
// 于是段 2 / 段 3 里所有以这些键为 targetPattern 的规则结构性永不命中,而界面与日志里
// 没有任何异常。接线点在 service/src/main.cpp,须在 CoverageProfile::fromOptions 之前完成。
//
QStringList DefaultRules::registryWatchFragments() {
    static const QStringList s = {
        QStringLiteral("\\Windows Defender\\Exclusions"),               // Defender 排除项
        QStringLiteral("\\Policies\\Microsoft\\Windows Defender"),      // Defender 组策略开关
        QStringLiteral("\\CurrentVersion\\Policies\\System"),           // UAC / 任务管理器 / 注册表编辑器
        QStringLiteral("\\CurrentVersion\\SilentProcessExit"),          // 静默退出劫持
        QStringLiteral("\\Windows NT\\CurrentVersion\\Windows"),        // AppInit_DLLs / Load / Run
        QStringLiteral("\\Control\\Lsa"),                               // LSA 安全包 / RunAsPPL
        QStringLiteral("\\Control\\SecurityProviders\\WDigest"),        // WDigest 明文口令缓存
        QStringLiteral("\\Control\\SafeBoot"),                          // 安全模式启动项
        QStringLiteral("\\Control\\Terminal Server"),                   // 远程桌面开关 / 端口
        QStringLiteral("\\Control\\Session Manager\\AppCertDlls"),      // AppCert DLL 注入
        QStringLiteral("\\Control\\Print\\Monitors"),                   // 打印端口监视器持久化
        QStringLiteral("\\Control\\NetworkProvider\\Order"),            // 网络提供程序(NPPSpy 截口令)
        QStringLiteral("\\Microsoft\\Netsh"),                           // netsh 助手 DLL
        QStringLiteral("\\Command Processor"),                          // cmd AutoRun
        QStringLiteral("\\Active Setup\\Installed Components"),         // Active Setup 登录执行
        QStringLiteral("\\Word\\Security"),                             // Word 宏安全 / 受保护视图
        QStringLiteral("\\Excel\\Security"),                            // Excel 宏安全 / VBA 对象模型访问
        QStringLiteral("\\SystemRestore"),                              // 系统还原开关
        QStringLiteral("\\WindowsFirewall"),                            // 防火墙策略
        // --- 以下为段 2 / 段 3 新增规则所需(各自都对应一条具体的持久化或规避手法)---
        QStringLiteral("\\Environment"),                                // 登录脚本 UserInitMprLogonScript
        QStringLiteral("\\Explorer\\User Shell Folders"),               // 重定向「启动」文件夹
        QStringLiteral("\\Explorer\\Shell Folders"),                    // 同上(旧位置)
        QStringLiteral("\\Classes\\ms-settings\\shell"),                // fodhelper 绕 UAC
        QStringLiteral("\\Classes\\exefile\\shell"),                    // 可执行文件关联劫持
        QStringLiteral("\\Windows\\System\\Scripts"),                   // 组策略登录/启动脚本
        QStringLiteral("\\PowerShell\\ScriptBlockLogging"),             // 关脚本块日志
        // 【刻意不收 \Classes\CLSID】COM 劫持(T1546.015)确实值得盯,但这个片段会把「每次安装
        // 软件注册 COM 组件」的全部写入拉进上报通道 —— 那是本机注册表写入量最大的一类。要盯
        // 它得登记具体被劫持的 CLSID,而不是整棵树。
    };
    return s;
}

bool DefaultRules::isDevTool(const QString& processPath) {
    if (processPath.isEmpty()) return false;
    const QString lower = processPath.toLower();
    const QString fileName = fileNameLower(lower);
    if (devToolProcessNames().contains(fileName)) return true;
    for (const QString& pat : devToolPathPatterns())
        if (lower.contains(pat)) return true;
    return false;
}

bool DefaultRules::isCiCdEnvironment() {
    static const char* ciVars[] = {
        "CI", "CONTINUOUS_INTEGRATION", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL",
        "BUILDKITE", "AZURE_PIPELINES", "TRAVIS", "CIRCLECI", "APPVEYOR",
        "TEAMCITY_VERSION", "TF_BUILD", "bamboo_buildKey", "CODEBUILD_BUILD_ID",
    };
    for (const char* v : ciVars)
        if (!qEnvironmentVariable(v).isEmpty()) return true;
    return false;
}

bool DefaultRules::hasLongEncodedContent(const QString& commandLine) {
    if (commandLine.isEmpty()) return false;
    static const QRegularExpression re(QStringLiteral("[A-Za-z0-9+/]{100,}={0,2}"));
    return re.match(commandLine).hasMatch();
}

bool DefaultRules::isTrustedInstaller(const QString& processPath) {
    if (processPath.isEmpty()) return false;
    const QString fileName = fileNameLower(processPath);
    static const QSet<QString> installerNames = {
        "msiexec.exe", "setup.exe", "installer.exe", "install.exe", "update.exe",
        "updater.exe", "winget.exe", "choco.exe", "scoop.exe", "npm.exe", "pip.exe",
        "dotnet.exe", "nuget.exe",
    };
    return installerNames.contains(fileName);
}

} // namespace bulwark::engine
