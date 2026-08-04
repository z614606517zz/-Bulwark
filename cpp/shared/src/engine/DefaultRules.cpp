#include "bulwark/engine/DefaultRules.h"
#include "bulwark/engine/EngineCommon.h"
#include <QSet>
#include <QStringList>
#include <QRegularExpression>

namespace bulwark::engine {

using detail::u;
using detail::fileNameLower;

QString DefaultRules::builtInTag() {
    return QString::fromUtf8("[\xe5\x86\x85\xe7\xbd\xae]"); // "[内置]"
}

namespace {

const QString kTag = QString::fromUtf8("[\xe5\x86\x85\xe7\xbd\xae]");

// note 构造:"[内置] " + reason(reason 为 UTF-8)。
QString note(const char* reason) { return kTag + QLatin1Char(' ') + u(reason); }

// ---- 规则构造辅助(对照 C# Reg/File_/Del/Cmd/Proc/NetActor/UnsignedExec/FakeInstaller)----
void reg(QVector<DefenseRule>& list, const char* target, VerdictAction action, const char* n, bool hardOverride = false) {
    DefenseRule r;
    r.type = EventType::RegistryWrite;
    r.targetPattern = QLatin1String(target);
    r.action = action;
    r.hardOverride = hardOverride;
    r.note = note(n);
    list.append(r);
}

void file_(QVector<DefenseRule>& list, const char* target, VerdictAction action, const char* n, bool hardOverride = false) {
    DefenseRule r;
    r.type = EventType::FileWrite;
    r.targetPattern = QLatin1String(target);
    r.action = action;
    r.hardOverride = hardOverride;
    r.note = note(n);
    list.append(r);
}

void del(QVector<DefenseRule>& list, const char* target, VerdictAction action, const char* n, bool hardOverride = false) {
    DefenseRule r;
    r.type = EventType::FileDelete;
    r.targetPattern = QLatin1String(target);
    r.action = action;
    r.hardOverride = hardOverride;
    r.note = note(n);
    list.append(r);
}

void cmd(QVector<DefenseRule>& list, const char* cmdPattern, VerdictAction action, const char* n) {
    DefenseRule r;
    r.type = EventType::ProcessCreate;
    r.commandLinePattern = QLatin1String(cmdPattern);
    r.action = action;
    r.note = note(n);
    list.append(r);
}

void proc(QVector<DefenseRule>& list, EventType type, const char* target, VerdictAction action, const char* n, bool hardOverride = false) {
    DefenseRule r;
    r.type = type;
    r.targetPattern = QLatin1String(target);
    r.action = action;
    r.hardOverride = hardOverride;
    r.note = note(n);
    list.append(r);
}

void netActor(QVector<DefenseRule>& list, const char* actorPattern, const char* n) {
    DefenseRule r;
    r.type = EventType::NetworkConnect;
    r.actorPattern = QLatin1String(actorPattern);
    r.action = VerdictAction::Ask;   // C# NetActor 固定 Ask
    r.note = note(n);
    list.append(r);
}

void unsignedExec(QVector<DefenseRule>& list, const char* actorPattern, const char* n) {
    DefenseRule r;
    r.type = EventType::ProcessCreate;
    r.actorPattern = QLatin1String(actorPattern);
    r.requireUnsigned = true;
    r.action = VerdictAction::Ask;
    r.note = note(n);
    list.append(r);
}

void fakeInstaller(QVector<DefenseRule>& list, const char* actorPattern, const char* n) {
    DefenseRule r;
    r.type = EventType::ProcessCreate;
    r.actorPattern = QLatin1String(actorPattern);
    r.requireUnsigned = true;
    r.action = VerdictAction::Ask;
    r.note = note(n);
    list.append(r);
}

// IM 注入远程线程(Ask,仅未签名注入方命中)。
void imInjectRemoteThread(QVector<DefenseRule>& list, const char* targetPattern, const char* n) {
    DefenseRule r;
    r.type = EventType::RemoteThread;
    r.targetPattern = QLatin1String(targetPattern);
    r.requireUnsigned = true;
    r.action = VerdictAction::Ask;
    r.note = note(n);
    list.append(r);
}

// IM 从用户可写目录加载未签名 DLL 的侧载规则(AppData + Temp)。
void imUnsignedModuleFromUserDir(QVector<DefenseRule>& list) {
    static const char* actors[] = { "*\\WeChat.exe", "*\\Weixin.exe", "*\\WXWork.exe", "*\\QQ.exe", "*\\TIM.exe" };
    for (const char* actor : actors) {
        DefenseRule a;
        a.type = EventType::ImageLoad;
        a.actorPattern = QLatin1String(actor);
        a.targetPattern = QStringLiteral("*\\AppData\\*.dll");
        a.requireUnsigned = true;
        a.action = VerdictAction::Ask;
        a.note = note("IM \xe4\xbb\x8e\xe7\x94\xa8\xe6\x88\xb7\xe7\x9b\xae\xe5\xbd\x95\xe5\x8a\xa0\xe8\xbd\xbd\xe6\x9c\xaa\xe7\xad\xbe\xe5\x90\x8d DLL\xef\xbc\x88\xe7\x96\x91\xe4\xbc\xbc\xe7\xbe\xa4\xe6\x8e\xa7\xe7\x99\xbd\xe5\x8a\xa0\xe9\xbb\x91\xe4\xbe\xa7\xe8\xbd\xbd\xef\xbc\x89");
        list.append(a);
        DefenseRule b;
        b.type = EventType::ImageLoad;
        b.actorPattern = QLatin1String(actor);
        b.targetPattern = QStringLiteral("*\\Temp\\*.dll");
        b.requireUnsigned = true;
        b.action = VerdictAction::Ask;
        b.note = note("IM \xe4\xbb\x8e Temp \xe5\x8a\xa0\xe8\xbd\xbd\xe6\x9c\xaa\xe7\xad\xbe\xe5\x90\x8d DLL\xef\xbc\x88\xe7\x96\x91\xe4\xbc\xbc\xe7\xbe\xa4\xe6\x8e\xa7\xe7\x99\xbd\xe5\x8a\xa0\xe9\xbb\x91\xe4\xbe\xa7\xe8\xbd\xbd\xef\xbc\x89");
        list.append(b);
    }
}

// ---- 各批次规则填充器(前向声明;定义分批 append 于本 TU 的匿名命名空间)----
void addTrustedSystemRules(QVector<DefenseRule>& list);
void addTrustedSystemRules2(QVector<DefenseRule>& list);
void addTrustedSystemRules3(QVector<DefenseRule>& list);
void addTrustedSystemRules4(QVector<DefenseRule>& list);
void addPersistenceRules(QVector<DefenseRule>& list);
void addDefenseEvasionRules(QVector<DefenseRule>& list);
void addCredentialAccessRules(QVector<DefenseRule>& list);
void addRansomwareRules(QVector<DefenseRule>& list);
void addLolBinRules(QVector<DefenseRule>& list);
void addInjectionRules(QVector<DefenseRule>& list);
void addExecutionRules(QVector<DefenseRule>& list);
void addBootAndBackdoorRules(QVector<DefenseRule>& list);
void addWmiAndLateralRules(QVector<DefenseRule>& list);
void addOfficeMacroRules(QVector<DefenseRule>& list);
void addAntiForensicsRules(QVector<DefenseRule>& list);
void addByovdRules(QVector<DefenseRule>& list);
void addSilverFox2026Rules(QVector<DefenseRule>& list);
void addSilverFoxLatestCampaignRules(QVector<DefenseRule>& list);
void addSilverFoxMsiChainRules(QVector<DefenseRule>& list);
void addImControlRules(QVector<DefenseRule>& list);
void addImMassMessagingRules(QVector<DefenseRule>& list);
void addImHarvestAndFrameworkRules(QVector<DefenseRule>& list);
void addDeepPersistenceRules(QVector<DefenseRule>& list);
void addCmdlineEvasionRules(QVector<DefenseRule>& list);
void addNetworkC2Rules(QVector<DefenseRule>& list);
void addSilverFoxWdacByovdRules(QVector<DefenseRule>& list);

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

} // anonymous namespace

QVector<DefenseRule> DefaultRules::build() {
    QVector<DefenseRule> list;
    addTrustedSystemRules(list);
    addTrustedSystemRules2(list);
    addTrustedSystemRules3(list);
    addTrustedSystemRules4(list);
    addPersistenceRules(list);
    addDefenseEvasionRules(list);
    addCredentialAccessRules(list);
    addRansomwareRules(list);
    addLolBinRules(list);
    addInjectionRules(list);
    addExecutionRules(list);
    addBootAndBackdoorRules(list);
    addWmiAndLateralRules(list);
    addOfficeMacroRules(list);
    addAntiForensicsRules(list);
    addByovdRules(list);
    addSilverFox2026Rules(list);
    addSilverFoxLatestCampaignRules(list);
    addSilverFoxMsiChainRules(list);
    addImControlRules(list);
    addImMassMessagingRules(list);
    addImHarvestAndFrameworkRules(list);
    addDeepPersistenceRules(list);
    addCmdlineEvasionRules(list);
    addNetworkC2Rules(list);
    addSilverFoxWdacByovdRules(list);

    //
    // ============ 给内置规则赋【稳定 id】(必须保留)============
    //
    // DefenseRule::id 的默认值是 QUuid::createUuid() —— 每次进程启动都是全新随机值。
    // 而 RuleEngine 步骤 6 的规则排序在「层级 > 具体度 > 动作强度 > createdUtc」全部打平时
    // 以 id 收尾定序,内置规则的 createdUtc 又都取自同一次 nowUtc() 调用(彼此相同),
    // 于是【两条完全同级的内置规则谁胜出由随机 UUID 决定,每次重启都可能翻转】。
    //
    // 实际后果(裁决快照测试就是这么发现的):同一条 `powershell -w hidden -enc ...` 命令行
    // 同时命中「PowerShell 编码命令」与「隐藏窗口+编码命令组合」两条规则,两者动作相同但
    // 备注不同 —— 用户在 UI / 审计日志里看到的拦截理由每次重启会随机切换。
    //
    // 这里按规则的【判别性内容】派生 UUIDv5:同一条内置规则在任何机器、任何一次启动上都得到
    // 同一个 id。除消除上述抖动外,还让内置规则的身份跨重启稳定(规则存储 / 按 id 删除等
    // 依赖 id 的路径因此才有意义)。
    //
    // 注意:参与派生的字段必须足以区分任意两条内置规则,否则会撞 id。此处把全部匹配条件
    // 连同备注一起纳入 —— 备注本身在内置规则里就是唯一的,已足够,其余字段是冗余保险。
    //
    for (DefenseRule& r : list) {
        QString key;
        key.reserve(256);
        key += r.note;
        key += QLatin1Char('\x1f');
        key += r.actorPath;
        key += QLatin1Char('\x1f');
        key += r.actorPattern;
        key += QLatin1Char('\x1f');
        key += r.targetPattern;
        key += QLatin1Char('\x1f');
        key += r.commandLinePattern;
        key += QLatin1Char('\x1f');
        key += r.parentPattern;
        key += QLatin1Char('\x1f');
        key += r.type.has_value() ? QString::number(static_cast<int>(*r.type))
                                  : QStringLiteral("-");
        key += QLatin1Char('\x1f');
        key += QString::number(static_cast<int>(r.action));
        key += QLatin1Char('\x1f');
        key += r.requireUnsigned ? QLatin1Char('1') : QLatin1Char('0');
        key += r.hardOverride ? QLatin1Char('1') : QLatin1Char('0');
        key += r.exemptTrustedOsComponent ? QLatin1Char('1') : QLatin1Char('0');
        r.id = QUuid::createUuidV5(QUuid{}, key.toUtf8());
    }
    return list;
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

namespace bulwark::engine { namespace {

void addTrustedSystemRules(QVector<DefenseRule>& list) {
    // 系统注册表键放行
    reg(list, "*\\Services\\bam\\*", VerdictAction::Allow, "BAM \xe6\xb3\xa8\xe5\x86\x8c\xe8\xa1\xa8\xe5\x86\x99\xe5\x85\xa5\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f\xe5\x90\x8e\xe5\x8f\xb0\xe6\xb4\xbb\xe5\x8a\xa8\xe7\xae\xa1\xe7\x90\x86\xe5\x99\xa8\xef\xbc\x89");
    reg(list, "*\\UserSettings\\*", VerdictAction::Allow, "\xe7\x94\xa8\xe6\x88\xb7\xe9\x85\x8d\xe7\xbd\xae\xe6\xb3\xa8\xe5\x86\x8c\xe8\xa1\xa8\xe5\x86\x99\xe5\x85\xa5\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f\xe8\x87\xaa\xe5\x8a\xa8\xe6\x9b\xb4\xe6\x96\xb0\xef\xbc\x89");
    reg(list, "*\\Session Manager\\KnownDlls\\*", VerdictAction::Allow, "KnownDlls \xe6\xb3\xa8\xe5\x86\x8c\xe8\xa1\xa8\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f DLL \xe7\xbc\x93\xe5\xad\x98\xef\xbc\x89");

    // 可信系统进程文件/注册表操作
    file_(list, "*\\TrustedInstaller.exe", VerdictAction::Allow, "TrustedInstaller \xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c\xef\xbc\x88Windows Update/\xe7\xb3\xbb\xe7\xbb\x9f\xe7\xbb\xb4\xe6\x8a\xa4\xef\xbc\x89");
    reg(list, "*\\TrustedInstaller.exe", VerdictAction::Allow, "TrustedInstaller \xe6\xb3\xa8\xe5\x86\x8c\xe8\xa1\xa8\xe6\x93\x8d\xe4\xbd\x9c\xef\xbc\x88Windows Update\xef\xbc\x89");

    // svchost:注意此处用 ActorPattern(非 targetPattern)
    {
        DefenseRule r; r.type = EventType::FileWrite; r.actorPattern = QStringLiteral("*\\svchost.exe");
        r.action = VerdictAction::Allow; r.note = note("svchost \xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f\xe6\x9c\x8d\xe5\x8a\xa1\xef\xbc\x89"); list.append(r);
    }
    {
        DefenseRule r; r.type = EventType::RegistryWrite; r.actorPattern = QStringLiteral("*\\svchost.exe");
        r.action = VerdictAction::Allow; r.note = note("svchost \xe6\xb3\xa8\xe5\x86\x8c\xe8\xa1\xa8\xe6\x93\x8d\xe4\xbd\x9c\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f\xe6\x9c\x8d\xe5\x8a\xa1\xef\xbc\x89"); list.append(r);
    }
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addTrustedSystemRules2(QVector<DefenseRule>& list) {
    auto actorAllow = [&](EventType t, const char* actor, const char* n) {
        DefenseRule r; r.type = t; r.actorPattern = QLatin1String(actor);
        r.action = VerdictAction::Allow; r.note = note(n); list.append(r);
    };
    // Windows Update 相关
    actorAllow(EventType::FileWrite, "*\\wuauclt.exe", "Windows Update \xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    actorAllow(EventType::FileWrite, "*\\UsoClient.exe", "Windows Update\xef\xbc\x88UsoClient\xef\xbc\x89\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    actorAllow(EventType::FileWrite, "*\\TiWorker.exe", "Windows Update\xef\xbc\x88TiWorker\xef\xbc\x89\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    // Windows Defender 自维护
    actorAllow(EventType::FileWrite, "*\\MsMpEng.exe", "Windows Defender \xe5\xbc\x95\xe6\x93\x8e\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c\xef\xbc\x88\xe6\x9b\xb4\xe6\x96\xb0/\xe6\x89\xab\xe6\x8f\x8f\xef\xbc\x89");
    actorAllow(EventType::FileWrite, "*\\MpCmdRun.exe", "Windows Defender \xe5\x91\xbd\xe4\xbb\xa4\xe8\xa1\x8c\xe5\xb7\xa5\xe5\x85\xb7\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    actorAllow(EventType::FileWrite, "*\\MpDefenderCoreService.exe", "Windows Defender \xe6\xa0\xb8\xe5\xbf\x83\xe6\x9c\x8d\xe5\x8a\xa1\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    // 系统目录 PowerShell 启动
    actorAllow(EventType::ProcessCreate, "*\\Windows\\System32\\WindowsPowerShell\\*", "\xe7\xb3\xbb\xe7\xbb\x9f\xe7\x9b\xae\xe5\xbd\x95 PowerShell \xe5\x90\xaf\xe5\x8a\xa8\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f\xe7\xae\xa1\xe7\x90\x86\xe4\xbb\xbb\xe5\x8a\xa1\xef\xbc\x89");
    actorAllow(EventType::ProcessCreate, "*\\Windows\\SysWOW64\\WindowsPowerShell\\*", "SysWOW64 PowerShell \xe5\x90\xaf\xe5\x8a\xa8\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f\xe7\xae\xa1\xe7\x90\x86\xe4\xbb\xbb\xe5\x8a\xa1\xef\xbc\x89");
    // Windows Installer
    actorAllow(EventType::FileWrite, "*\\msiexec.exe", "Windows Installer \xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c\xef\xbc\x88\xe5\xae\x89\xe8\xa3\x85\xe8\xbd\xaf\xe4\xbb\xb6\xef\xbc\x89");
    actorAllow(EventType::RegistryWrite, "*\\msiexec.exe", "Windows Installer \xe6\xb3\xa8\xe5\x86\x8c\xe8\xa1\xa8\xe6\x93\x8d\xe4\xbd\x9c\xef\xbc\x88\xe5\xae\x89\xe8\xa3\x85\xe8\xbd\xaf\xe4\xbb\xb6\xef\xbc\x89");
    actorAllow(EventType::ProcessCreate, "*\\msiexec.exe", "Windows Installer \xe5\x88\x9b\xe5\xbb\xba\xe8\xbf\x9b\xe7\xa8\x8b\xef\xbc\x88\xe5\xae\x89\xe8\xa3\x85\xe8\xbd\xaf\xe4\xbb\xb6\xef\xbc\x89");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addTrustedSystemRules3(QVector<DefenseRule>& list) {
    auto act = [&](EventType t, const char* actor, VerdictAction a, const char* n) {
        DefenseRule r; r.type = t; r.actorPattern = QLatin1String(actor);
        r.action = a; r.note = note(n); list.append(r);
    };
    // 安装器(签名软件由 IsHealthySigned 放行,未签名走其他规则)
    act(EventType::FileWrite, "*\\setup.exe", VerdictAction::Ask, "\xe5\xae\x89\xe8\xa3\x85\xe5\x99\xa8\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c\xef\xbc\x88\xe7\xad\xbe\xe5\x90\x8d\xe8\xbd\xaf\xe4\xbb\xb6\xe8\x87\xaa\xe5\x8a\xa8\xe6\x94\xbe\xe8\xa1\x8c\xef\xbc\x89");
    act(EventType::RegistryWrite, "*\\setup.exe", VerdictAction::Ask, "\xe5\xae\x89\xe8\xa3\x85\xe5\x99\xa8\xe6\xb3\xa8\xe5\x86\x8c\xe8\xa1\xa8\xe6\x93\x8d\xe4\xbd\x9c\xef\xbc\x88\xe7\xad\xbe\xe5\x90\x8d\xe8\xbd\xaf\xe4\xbb\xb6\xe8\x87\xaa\xe5\x8a\xa8\xe6\x94\xbe\xe8\xa1\x8c\xef\xbc\x89");
    // 包管理器
    act(EventType::FileWrite, "*\\winget.exe", VerdictAction::Allow, "Windows Package Manager \xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    act(EventType::RegistryWrite, "*\\winget.exe", VerdictAction::Allow, "Windows Package Manager \xe6\xb3\xa8\xe5\x86\x8c\xe8\xa1\xa8\xe6\x93\x8d\xe4\xbd\x9c");
    act(EventType::FileWrite, "*\\choco.exe", VerdictAction::Allow, "Chocolatey \xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    act(EventType::FileWrite, "*\\scoop.exe", VerdictAction::Allow, "Scoop \xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    // 系统维护
    act(EventType::FileWrite, "*\\cleanmgr.exe", VerdictAction::Allow, "\xe7\xa3\x81\xe7\x9b\x98\xe6\xb8\x85\xe7\x90\x86\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    act(EventType::FileWrite, "*\\defrag.exe", VerdictAction::Allow, "\xe7\xa3\x81\xe7\x9b\x98\xe7\xa2\x8e\xe7\x89\x87\xe6\x95\xb4\xe7\x90\x86\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    act(EventType::FileWrite, "*\\SearchIndexer.exe", VerdictAction::Allow, "Windows \xe6\x90\x9c\xe7\xb4\xa2\xe7\xb4\xa2\xe5\xbc\x95\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    act(EventType::FileWrite, "*\\SearchProtocolHost.exe", VerdictAction::Allow, "Windows \xe6\x90\x9c\xe7\xb4\xa2\xe5\x8d\x8f\xe8\xae\xae\xe4\xb8\xbb\xe6\x9c\xba\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    // 浏览器自动更新
    act(EventType::FileWrite, "*\\Google\\Update\\*", VerdictAction::Allow, "Google \xe6\x9b\xb4\xe6\x96\xb0\xe6\x9c\x8d\xe5\x8a\xa1\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    act(EventType::FileWrite, "*\\Microsoft\\EdgeUpdate\\*", VerdictAction::Allow, "Microsoft Edge \xe6\x9b\xb4\xe6\x96\xb0\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    act(EventType::FileWrite, "*\\Mozilla Maintenance Service\\*", VerdictAction::Allow, "Mozilla \xe7\xbb\xb4\xe6\x8a\xa4\xe6\x9c\x8d\xe5\x8a\xa1\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    act(EventType::FileWrite, "*\\updater.exe", VerdictAction::Allow, "\xe6\xb5\x8f\xe8\xa7\x88\xe5\x99\xa8\xe6\x9b\xb4\xe6\x96\xb0\xe5\x99\xa8\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c");
    // 系统进程线程创建(合法)
    act(EventType::RemoteThread, "*\\csrss.exe", VerdictAction::Allow, "csrss \xe7\xba\xbf\xe7\xa8\x8b\xe5\x88\x9b\xe5\xbb\xba\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f\xe5\x90\x88\xe6\xb3\x95\xe8\xa1\x8c\xe4\xb8\xba\xef\xbc\x89");
    act(EventType::RemoteThread, "*\\winlogon.exe", VerdictAction::Allow, "winlogon \xe7\xba\xbf\xe7\xa8\x8b\xe5\x88\x9b\xe5\xbb\xba\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f\xe5\x90\x88\xe6\xb3\x95\xe8\xa1\x8c\xe4\xb8\xba\xef\xbc\x89");
    act(EventType::RemoteThread, "*\\wininit.exe", VerdictAction::Allow, "wininit \xe7\xba\xbf\xe7\xa8\x8b\xe5\x88\x9b\xe5\xbb\xba\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f\xe5\x90\x88\xe6\xb3\x95\xe8\xa1\x8c\xe4\xb8\xba\xef\xbc\x89");
    act(EventType::RemoteThread, "*\\services.exe", VerdictAction::Allow, "services \xe7\xba\xbf\xe7\xa8\x8b\xe5\x88\x9b\xe5\xbb\xba\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f\xe5\x90\x88\xe6\xb3\x95\xe8\xa1\x8c\xe4\xb8\xba\xef\xbc\x89");
    act(EventType::RemoteThread, "*\\lsass.exe", VerdictAction::Allow, "lsass \xe7\xba\xbf\xe7\xa8\x8b\xe5\x88\x9b\xe5\xbb\xba\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f\xe5\x90\x88\xe6\xb3\x95\xe8\xa1\x8c\xe4\xb8\xba\xef\xbc\x89");
    act(EventType::RemoteThread, "*\\lsm.exe", VerdictAction::Allow, "lsm \xe7\xba\xbf\xe7\xa8\x8b\xe5\x88\x9b\xe5\xbb\xba\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f\xe5\x90\x88\xe6\xb3\x95\xe8\xa1\x8c\xe4\xb8\xba\xef\xbc\x89");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addTrustedSystemRules4(QVector<DefenseRule>& list) {
    auto act = [&](EventType t, const char* actor, const char* n) {
        DefenseRule r; r.type = t; r.actorPattern = QLatin1String(actor);
        r.action = VerdictAction::Allow; r.note = note(n); list.append(r);
    };
    // 安全软件自更新(写自己目录)
    static const char* secActors[] = {
        "*\\HipsTray.exe", "*\\HipsDaemon.exe", "*\\360tray.exe", "*\\360sd.exe",
        "*\\ZhuDongFangYu.exe", "*\\kxetray.exe", "*\\KSafeTray.exe", "*\\QQPCRTP.exe",
    };
    for (const char* a : secActors)
        act(EventType::FileWrite, a, "\xe5\xae\x89\xe5\x85\xa8\xe8\xbd\xaf\xe4\xbb\xb6\xe8\x87\xaa\xe8\xba\xab\xe6\x96\x87\xe4\xbb\xb6\xe6\x93\x8d\xe4\xbd\x9c\xef\xbc\x88\xe6\x9b\xb4\xe6\x96\xb0/\xe7\xbb\xb4\xe6\x8a\xa4\xef\xbc\x89");
    // 网络连接:可信系统服务
    act(EventType::NetworkConnect, "*\\svchost.exe", "svchost \xe7\xbd\x91\xe7\xbb\x9c\xe8\xbf\x9e\xe6\x8e\xa5\xef\xbc\x88\xe7\xb3\xbb\xe7\xbb\x9f\xe6\x9c\x8d\xe5\x8a\xa1\xef\xbc\x89");
    act(EventType::NetworkConnect, "*\\System", "System \xe7\xbd\x91\xe7\xbb\x9c\xe8\xbf\x9e\xe6\x8e\xa5\xef\xbc\x88\xe5\x86\x85\xe6\xa0\xb8\xe7\xba\xa7\xe9\x80\x9a\xe4\xbf\xa1\xef\xbc\x89");
    act(EventType::NetworkConnect, "*\\WmiPrvSE.exe", "WMI \xe6\x8f\x90\xe4\xbe\x9b\xe8\x80\x85\xe7\xbd\x91\xe7\xbb\x9c\xe8\xbf\x9e\xe6\x8e\xa5");
    act(EventType::NetworkConnect, "*\\wuauclt.exe", "Windows Update \xe7\xbd\x91\xe7\xbb\x9c\xe8\xbf\x9e\xe6\x8e\xa5");
    act(EventType::NetworkConnect, "*\\UsoClient.exe", "Windows Update\xef\xbc\x88UsoClient\xef\xbc\x89\xe7\xbd\x91\xe7\xbb\x9c\xe8\xbf\x9e\xe6\x8e\xa5");
    act(EventType::NetworkConnect, "*\\MsMpEng.exe", "Windows Defender \xe7\xbd\x91\xe7\xbb\x9c\xe8\xbf\x9e\xe6\x8e\xa5\xef\xbc\x88\xe6\x9b\xb4\xe6\x96\xb0/\xe4\xba\x91\xe4\xbf\x9d\xe6\x8a\xa4\xef\xbc\x89");
    // 浏览器网络连接
    static const char* browsers[] = {
        "*\\chrome.exe", "*\\msedge.exe", "*\\firefox.exe",
        "*\\GoogleUpdate.exe", "*\\MicrosoftEdgeUpdate.exe",
    };
    for (const char* b : browsers)
        act(EventType::NetworkConnect, b, "\xe6\xb5\x8f\xe8\xa7\x88\xe5\x99\xa8\xe7\xbd\x91\xe7\xbb\x9c\xe8\xbf\x9e\xe6\x8e\xa5\xef\xbc\x88\xe6\xad\xa3\xe5\xb8\xb8\xe6\xb5\x8f\xe8\xa7\x88/\xe6\x9b\xb4\xe6\x96\xb0\xef\xbc\x89");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addPersistenceRules(QVector<DefenseRule>& list) {
    // 普通自启动项 -> Ask
    reg(list, "*\\CurrentVersion\\Run\\*", VerdictAction::Ask, "\xe5\x86\x99\xe5\x85\xa5\xe5\xbc\x80\xe6\x9c\xba\xe5\x90\xaf\xe5\x8a\xa8\xe9\xa1\xb9\xef\xbc\x88HKLM/HKCU Run\xef\xbc\x89");
    reg(list, "*\\CurrentVersion\\RunOnce\\*", VerdictAction::Ask, "\xe5\x86\x99\xe5\x85\xa5\xe4\xb8\x80\xe6\xac\xa1\xe6\x80\xa7\xe5\x90\xaf\xe5\x8a\xa8\xe9\xa1\xb9\xef\xbc\x88RunOnce\xef\xbc\x89");
    reg(list, "*\\CurrentVersion\\RunServices\\*", VerdictAction::Ask, "\xe5\x86\x99\xe5\x85\xa5\xe6\x9c\x8d\xe5\x8a\xa1\xe5\x9e\x8b\xe5\x90\xaf\xe5\x8a\xa8\xe9\xa1\xb9\xef\xbc\x88RunServices\xef\xbc\x89");
    reg(list, "*\\CurrentVersion\\Policies\\Explorer\\Run\\*", VerdictAction::Ask, "\xe5\x86\x99\xe5\x85\xa5\xe7\xad\x96\xe7\x95\xa5\xe5\x90\xaf\xe5\x8a\xa8\xe9\xa1\xb9\xef\xbc\x88Policies\\Explorer\\Run\xef\xbc\x89");
    // 登录/初始化挂钩 -> Block
    reg(list, "*\\Winlogon\\Shell*", VerdictAction::Block, "\xe7\xaf\xa1\xe6\x94\xb9 Winlogon Shell\xef\xbc\x88\xe9\xab\x98\xe5\x8d\xb1\xe6\x8c\x81\xe4\xb9\x85\xe5\x8c\x96\xef\xbc\x89");
    reg(list, "*\\Winlogon\\Userinit*", VerdictAction::Block, "\xe7\xaf\xa1\xe6\x94\xb9 Winlogon Userinit\xef\xbc\x88\xe9\xab\x98\xe5\x8d\xb1\xe6\x8c\x81\xe4\xb9\x85\xe5\x8c\x96\xef\xbc\x89");
    reg(list, "*\\Winlogon\\Notify\\*", VerdictAction::Block, "\xe6\xb3\xa8\xe5\x86\x8c Winlogon Notify \xe5\x8c\x85\xef\xbc\x88\xe9\xab\x98\xe5\x8d\xb1\xe6\x8c\x81\xe4\xb9\x85\xe5\x8c\x96\xef\xbc\x89");
    reg(list, "*\\Windows\\CurrentVersion\\Windows\\AppInit_DLLs*", VerdictAction::Block, "\xe8\xae\xbe\xe7\xbd\xae AppInit_DLLs\xef\xbc\x88\xe5\x85\xa8\xe5\xb1\x80 DLL \xe6\xb3\xa8\xe5\x85\xa5\xe6\x8c\x81\xe4\xb9\x85\xe5\x8c\x96\xef\xbc\x89");
    reg(list, "*\\Windows NT\\CurrentVersion\\Windows\\Load*", VerdictAction::Block, "\xe7\xaf\xa1\xe6\x94\xb9 Windows\\Load \xe5\x90\xaf\xe5\x8a\xa8\xe9\x94\xae");
    // 映像劫持 / 静默退出劫持 -> Block
    reg(list, "*\\Image File Execution Options\\*\\Debugger*", VerdictAction::Block, "\xe8\xae\xbe\xe7\xbd\xae\xe6\x98\xa0\xe5\x83\x8f\xe5\x8a\xab\xe6\x8c\x81 Debugger\xef\xbc\x88IFEO\xef\xbc\x89");
    reg(list, "*\\SilentProcessExit\\*", VerdictAction::Block, "\xe9\x85\x8d\xe7\xbd\xae\xe9\x9d\x99\xe9\xbb\x98\xe9\x80\x80\xe5\x87\xba\xe5\x8a\xab\xe6\x8c\x81\xef\xbc\x88SilentProcessExit\xef\xbc\x89");
    // 服务 DLL 持久化
    reg(list, "*\\Services\\*\\ServiceDll*", VerdictAction::Ask, "\xe4\xbf\xae\xe6\x94\xb9\xe6\x9c\x8d\xe5\x8a\xa1 DLL\xef\xbc\x88ServiceDll \xe6\x8c\x81\xe4\xb9\x85\xe5\x8c\x96\xef\xbc\x89");
    reg(list, "*\\Services\\*\\ImagePath*", VerdictAction::Ask, "\xe4\xbf\xae\xe6\x94\xb9\xe6\x9c\x8d\xe5\x8a\xa1\xe5\x8f\xaf\xe6\x89\xa7\xe8\xa1\x8c\xe8\xb7\xaf\xe5\xbe\x84\xef\xbc\x88ImagePath\xef\xbc\x89");
    // COM 劫持
    reg(list, "*\\Classes\\CLSID\\*\\InprocServer32*", VerdictAction::Ask, "\xe6\xb3\xa8\xe5\x86\x8c COM InprocServer32\xef\xbc\x88\xe5\x8f\xaf\xe8\x83\xbd COM \xe5\x8a\xab\xe6\x8c\x81\xef\xbc\x89");
    reg(list, "*\\Classes\\CLSID\\*\\LocalServer32*", VerdictAction::Ask, "\xe6\xb3\xa8\xe5\x86\x8c COM LocalServer32\xef\xbc\x88\xe5\x8f\xaf\xe8\x83\xbd COM \xe5\x8a\xab\xe6\x8c\x81\xef\xbc\x89");
    reg(list, "*\\Classes\\CLSID\\*\\TreatAs*", VerdictAction::Ask, "COM TreatAs \xe5\x8a\xab\xe6\x8c\x81\xef\xbc\x88\xe5\x8f\xaf\xe8\x83\xbd\xe6\x8c\x81\xe4\xb9\x85\xe5\x8c\x96\xef\xbc\x89");
    reg(list, "*\\Classes\\CLSID\\*\\ProgID*", VerdictAction::Ask, "COM ProgID \xe5\x8a\xab\xe6\x8c\x81\xef\xbc\x88\xe5\x8f\xaf\xe8\x83\xbd\xe6\x8c\x81\xe4\xb9\x85\xe5\x8c\x96\xef\xbc\x89");
    // 启动文件夹 / 计划任务文件
    file_(list, "*\\Start Menu\\Programs\\Startup\\*", VerdictAction::Ask, "\xe5\x90\x91\xe5\x90\xaf\xe5\x8a\xa8\xe6\x96\x87\xe4\xbb\xb6\xe5\xa4\xb9\xe5\x86\x99\xe5\x85\xa5\xe7\xa8\x8b\xe5\xba\x8f");
    file_(list, "*\\System32\\Tasks\\*", VerdictAction::Ask, "\xe5\x88\x9b\xe5\xbb\xba/\xe7\xaf\xa1\xe6\x94\xb9\xe8\xae\xa1\xe5\x88\x92\xe4\xbb\xbb\xe5\x8a\xa1\xe6\x96\x87\xe4\xbb\xb6\xef\xbc\x88Tasks\xef\xbc\x89");
    // 屏保持久化
    reg(list, "*\\Control Panel\\Desktop\\SCRNSAVE.EXE*", VerdictAction::Ask, "\xe7\xaf\xa1\xe6\x94\xb9\xe5\xb1\x8f\xe4\xbf\x9d\xe7\xa8\x8b\xe5\xba\x8f\xef\xbc\x88\xe5\x8f\xaf\xe4\xbd\x9c\xe6\x8c\x81\xe4\xb9\x85\xe5\x8c\x96\xef\xbc\x89");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addDefenseEvasionRules(QVector<DefenseRule>& list) {
    // Windows Defender
    reg(list, "*\\Windows Defender\\*DisableAntiSpyware*", VerdictAction::Block, "试图关闭 Windows Defender(DisableAntiSpyware)");
    reg(list, "*\\Windows Defender\\*DisableRealtimeMonitoring*", VerdictAction::Block, "试图关闭 Defender 实时监控");
    reg(list, "*\\Windows Defender\\Exclusions\\*", VerdictAction::Ask, "向 Defender 添加排除项(可能为免杀)");
    reg(list, "*\\Policies\\Microsoft\\Windows Defender\\*", VerdictAction::Ask, "修改 Defender 策略");
    // 系统安全机制
    reg(list, "*\\System\\*EnableLUA*", VerdictAction::Block, "试图关闭 UAC(EnableLUA)");
    {
        DefenseRule r; r.type = EventType::RegistryWrite;
        r.targetPattern = QStringLiteral("*\\System\\*ConsentPromptBehaviorAdmin*");
        r.action = VerdictAction::Ask; r.exemptTrustedOsComponent = true;
        r.note = note("降低 UAC 提权确认级别"); list.append(r);
    }
    reg(list, "*\\Policies\\System\\DisableTaskMgr*", VerdictAction::Block, "试图禁用任务管理器");
    reg(list, "*\\Policies\\System\\DisableRegistryTools*", VerdictAction::Block, "试图禁用注册表编辑器");
    reg(list, "*\\Policies\\System\\DisableCMD*", VerdictAction::Ask, "试图禁用命令提示符");
    // 防火墙
    reg(list, "*\\WindowsFirewall\\*\\EnableFirewall*", VerdictAction::Block, "试图关闭 Windows 防火墙");
    reg(list, "*\\FirewallPolicy\\*\\DisableNotifications*", VerdictAction::Ask, "关闭防火墙通知");
    // SmartScreen / MOTW
    reg(list, "*\\System\\EnableSmartScreen*", VerdictAction::Ask, "试图关闭 SmartScreen");
    reg(list, "*\\Attachments\\SaveZoneInformation*", VerdictAction::Ask, "禁用附件区域标记(绕过 MOTW 警告)");
    // 结束安全软件进程 -> Block
    proc(list, EventType::ProcessTerminate, "*\\MsMpEng.exe", VerdictAction::Block, "试图结束 Defender 引擎(MsMpEng)");
    proc(list, EventType::ProcessTerminate, "*\\MpDefenderCoreService.exe", VerdictAction::Block, "试图结束 Defender 核心服务");
    proc(list, EventType::ProcessTerminate, "*\\360tray.exe", VerdictAction::Block, "试图结束 360 安全卫士");
    proc(list, EventType::ProcessTerminate, "*\\360sd.exe", VerdictAction::Block, "试图结束 360 杀毒");
    proc(list, EventType::ProcessTerminate, "*\\ZhuDongFangYu.exe", VerdictAction::Block, "试图结束 360 主动防御");
    proc(list, EventType::ProcessTerminate, "*\\HipsTray.exe", VerdictAction::Block, "试图结束火绒");
    proc(list, EventType::ProcessTerminate, "*\\QQPCRTP.exe", VerdictAction::Block, "试图结束腾讯电脑管家");
    proc(list, EventType::ProcessTerminate, "*\\kxetray.exe", VerdictAction::Block, "试图结束金山毒霸");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addCredentialAccessRules(QVector<DefenseRule>& list) {
    // LSASS
    proc(list, EventType::RemoteThread, "*\\lsass.exe", VerdictAction::Block, "向 LSASS 注入远程线程(疑似凭据窃取)");
    proc(list, EventType::ProcessTerminate, "*\\lsass.exe", VerdictAction::Block, "试图结束 LSASS(破坏系统/凭据保护)");
    // 敏感凭据存储文件
    file_(list, "*\\Windows\\System32\\config\\SAM", VerdictAction::Block, "访问 SAM 数据库(本地账户哈希)");
    file_(list, "*\\Windows\\System32\\config\\SECURITY", VerdictAction::Block, "访问 SECURITY 配置单元(LSA 机密)");
    file_(list, "*\\Windows\\NTDS\\ntds.dit", VerdictAction::Block, "访问 NTDS.dit(域账户数据库)");
    // 浏览器/凭据管理器 -> Ask
    file_(list, "*\\User Data\\*\\Login Data", VerdictAction::Ask, "读取浏览器保存的登录凭据");
    file_(list, "*\\Mozilla\\Firefox\\Profiles\\*logins.json", VerdictAction::Ask, "读取 Firefox 保存的登录凭据");
    file_(list, "*\\Microsoft\\Credentials\\*", VerdictAction::Ask, "访问 Windows 凭据管理器存储");
    file_(list, "*\\Microsoft\\Protect\\*", VerdictAction::Ask, "访问 DPAPI 主密钥");
}

void addRansomwareRules(QVector<DefenseRule>& list) {
    // 删除卷影副本 / 备份
    cmd(list, "*vssadmin*delete*shadows*", VerdictAction::Block, "删除卷影副本(vssadmin,勒索特征)");
    cmd(list, "*wmic*shadowcopy*delete*", VerdictAction::Block, "删除卷影副本(wmic,勒索特征)");
    cmd(list, "*wbadmin*delete*catalog*", VerdictAction::Block, "删除备份目录(wbadmin,勒索特征)");
    cmd(list, "*delete*systemstatebackup*", VerdictAction::Block, "删除系统状态备份(勒索特征)");
    // 禁用恢复 / 修复
    cmd(list, "*bcdedit*recoveryenabled*no*", VerdictAction::Block, "禁用 Windows 恢复(bcdedit,勒索特征)");
    cmd(list, "*bcdedit*bootstatuspolicy*ignoreallfailures*", VerdictAction::Block, "忽略启动失败策略(bcdedit,勒索特征)");
    reg(list, "*\\SystemRestore\\DisableSR*", VerdictAction::Block, "禁用系统还原(勒索特征)");
    // 删除关键引导/系统文件
    del(list, "*\\Windows\\System32\\winload.exe", VerdictAction::Block, "删除系统引导文件(破坏启动)");
    del(list, "*\\boot\\bcd", VerdictAction::Block, "删除启动配置数据(BCD)");
    // hosts 劫持 / 勒索信 -> Ask
    file_(list, "*\\drivers\\etc\\hosts", VerdictAction::Ask, "修改 hosts 文件(可能劫持域名)");
    file_(list, "*\\*HOW_TO_DECRYPT*", VerdictAction::Ask, "写入疑似勒索说明文件(HOW_TO_DECRYPT)");
    file_(list, "*\\*RECOVER*FILES*", VerdictAction::Ask, "写入疑似勒索说明文件(RECOVER FILES)");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addLolBinRules(QVector<DefenseRule>& list) {
    // PowerShell
    cmd(list, "*powershell*-enc*", VerdictAction::Ask, "PowerShell 编码命令(-EncodedCommand)");
    cmd(list, "*powershell*-e *", VerdictAction::Ask, "PowerShell 编码命令(-e 简写)");
    cmd(list, "*-windowstyle hidden*-enc*", VerdictAction::Ask, "隐藏窗口+编码命令组合(高可疑)");
    cmd(list, "*-w hidden*-enc*", VerdictAction::Ask, "隐藏窗口+编码命令组合(-w 简写,高可疑)");
    cmd(list, "*-windowstyle hidden*", VerdictAction::Ask, "隐藏窗口运行(可疑)");
    cmd(list, "*-w hidden*", VerdictAction::Ask, "隐藏窗口运行(-w 简写,可疑)");
    cmd(list, "*-executionpolicy bypass*", VerdictAction::Ask, "绕过 PowerShell 执行策略");
    cmd(list, "*-ep bypass*", VerdictAction::Ask, "绕过 PowerShell 执行策略(-ep 简写)");
    cmd(list, "*downloadstring*", VerdictAction::Ask, "内存下载执行(DownloadString)");
    cmd(list, "*downloadfile*", VerdictAction::Ask, "远程下载文件(DownloadFile)");
    cmd(list, "*invoke-expression*downloadstring*", VerdictAction::Ask, "下载并执行(IEX+DownloadString组合)");
    cmd(list, "*invoke-expression*", VerdictAction::Ask, "动态执行(Invoke-Expression/IEX)");
    cmd(list, "*iex(*", VerdictAction::Ask, "动态执行(IEX 别名)");
    cmd(list, "*frombase64string*", VerdictAction::Ask, "Base64 解码执行");
    cmd(list, "*[convert]::frombase64string*", VerdictAction::Ask, "Base64 解码(Convert类)");
    // certutil / bitsadmin
    cmd(list, "*certutil*-urlcache*", VerdictAction::Ask, "certutil 远程下载(-urlcache)");
    cmd(list, "*certutil*-urlcache*-split*", VerdictAction::Ask, "certutil 远程下载并分割(-urlcache -split)");
    cmd(list, "*certutil*-decode*", VerdictAction::Ask, "certutil 解码载荷(-decode)");
    cmd(list, "*certutil*-decodehex*", VerdictAction::Ask, "certutil 十六进制解码(-decodehex)");
    cmd(list, "*bitsadmin*/transfer*", VerdictAction::Ask, "BITS 后台下载(bitsadmin)");
    cmd(list, "*start-bitstransfer*", VerdictAction::Ask, "BITS 后台传输(Start-BitsTransfer)");
    // mshta / rundll32 / regsvr32 远程脚本 -> Block
    cmd(list, "*mshta*http*", VerdictAction::Block, "mshta 执行远程脚本");
    cmd(list, "*mshta*javascript:*", VerdictAction::Block, "mshta 执行内联脚本");
    cmd(list, "*regsvr32*/i:http*", VerdictAction::Block, "regsvr32 远程脚本执行(Squiblydoo)");
    cmd(list, "*rundll32*javascript:*", VerdictAction::Block, "rundll32 执行脚本");
    // 其他 LOLBin
    cmd(list, "*msbuild*http*", VerdictAction::Ask, "MSBuild 加载远程项目(代码执行)");
    cmd(list, "*installutil*/logfile=*", VerdictAction::Ask, "InstallUtil 滥用(绕过执行策略)");
    cmd(list, "*wmic*process*call*create*", VerdictAction::Ask, "wmic 创建进程(横向/绕过)");
    cmd(list, "*msiexec*http://*", VerdictAction::Ask, "msiexec 从远程地址安装包(下载执行)");
    cmd(list, "*msiexec*https://*", VerdictAction::Ask, "msiexec 从远程地址安装包(下载执行)");
    // 提权 / 账户
    cmd(list, "*net*localgroup*administrators*/add*", VerdictAction::Ask, "把账户加入管理员组(提权)");
    cmd(list, "*net*user*/add*", VerdictAction::Ask, "新增本地账户(net user /add)");
    cmd(list, "*schtasks*/create*", VerdictAction::Ask, "创建计划任务(可能持久化)");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addInjectionRules(QVector<DefenseRule>& list) {
    // actor+target 组合规则辅助
    auto at = [&](EventType t, const char* actor, const char* target, bool reqUnsigned, VerdictAction a, const char* n) {
        DefenseRule r; r.type = t;
        if (actor) r.actorPattern = QLatin1String(actor);
        if (target) r.targetPattern = QLatin1String(target);
        r.requireUnsigned = reqUnsigned; r.action = a; r.note = note(n); list.append(r);
    };

    // 「注入关键系统进程」类 Block 规则:按【目标】匹配,因此任何发起方都会命中 —— 包括
    // Windows 自己。实测 dwm.exe -> csrss.exe 这类系统内部线程创建被判高危拦截(误报);同理
    // services/winlogon/svchost 之间也存在合法的跨进程线程创建。故给这几条挂上
    // exemptTrustedOsComponent:引擎会在命中后回查 TrustPolicy::isTrustedOsComponent —— 要求
    // 「无硬恶意指标 + 主体不是 LOLBin/脚本宿主 + 微软签名且位于系统目录 + 无危险命令行」,
    // 只有系统自身组件才满足。未签名注入方、Temp 里的同名程序、带危险命令行的主体照旧被拦。
    auto injBlock = [&](const char* target, const char* n) {
        DefenseRule r; r.type = EventType::RemoteThread;
        r.targetPattern = QLatin1String(target);
        r.action = VerdictAction::Block;
        r.exemptTrustedOsComponent = true;
        r.note = note(n); list.append(r);
    };

    injBlock("*\\winlogon.exe", "向 winlogon 注入远程线程(高危)");
    injBlock("*\\svchost.exe", "向 svchost 注入远程线程(高危,排除 services/wininit 发起)");
    at(EventType::RemoteThread, "*\\services.exe", "*\\svchost.exe", false, VerdictAction::Allow, "services.exe 启动 svchost(系统合法行为,放行)");
    at(EventType::RemoteThread, "*\\wininit.exe", "*\\svchost.exe", false, VerdictAction::Allow, "wininit.exe 启动 svchost(系统合法行为,放行)");
    injBlock("*\\services.exe", "向 services 注入远程线程(高危)");
    injBlock("*\\csrss.exe", "向 csrss 注入远程线程(高危)");

    // explorer 注入细化
    at(EventType::RemoteThread, "*\\Windows\\*", "*\\explorer.exe", false, VerdictAction::Ask, "系统进程向explorer注入(可能是Shell扩展)");
    at(EventType::RemoteThread, "*\\Program Files\\*", "*\\explorer.exe", false, VerdictAction::Ask, "程序向explorer注入(可能是Shell扩展)");
    at(EventType::RemoteThread, "*\\AppData\\Local\\Temp\\*", "*\\explorer.exe", false, VerdictAction::Ask, "临时目录进程向explorer注入(高可疑)");
    proc(list, EventType::RemoteThread, "*\\explorer.exe", VerdictAction::Ask, "向 explorer 注入远程线程(Shell扩展可能触发)");

    // 未签名模块 / 侧载
    at(EventType::ImageLoad, nullptr, "*\\Windows\\*", true, VerdictAction::Ask, "未签名模块加载进系统目录进程(疑似 DLL 劫持)");
    at(EventType::ImageLoad, nullptr, "*\\AppData\\Local\\Temp\\*", true, VerdictAction::Ask, "从 Temp 加载未签名模块");
    at(EventType::ImageLoad, nullptr, "*\\AppData\\Local\\Temp\\*.dll", false, VerdictAction::Ask, "从 Temp 加载模块(疑似 DLL 搜索顺序劫持/侧载)");
    at(EventType::ImageLoad, nullptr, "*\\Windows\\Temp\\*.dll", false, VerdictAction::Ask, "从 Windows\\Temp 加载模块(疑似侧载)");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addExecutionRules(QVector<DefenseRule>& list) {
    // 回收站启动 / 双扩展名伪装 -> Block(hardOverride)
    proc(list, EventType::ProcessCreate, "*\\$recycle.bin\\*", VerdictAction::Block, "从回收站启动程序(几乎必为恶意)", true);
    proc(list, EventType::ProcessCreate, "*.pdf.exe", VerdictAction::Block, "双重扩展名伪装(.pdf.exe)", true);
    proc(list, EventType::ProcessCreate, "*.doc?.exe", VerdictAction::Block, "双重扩展名伪装(.doc/.docx.exe)", true);
    proc(list, EventType::ProcessCreate, "*.jpg.exe", VerdictAction::Block, "双重扩展名伪装(.jpg.exe)", true);
    proc(list, EventType::ProcessCreate, "*.txt.exe", VerdictAction::Block, "双重扩展名伪装(.txt.exe)", true);
    // 未签名程序从可疑目录执行 -> Ask
    unsignedExec(list, "*\\AppData\\Local\\Temp\\*", "从 Temp 目录执行未签名程序");
    unsignedExec(list, "*\\Windows\\Temp\\*", "从 Windows\\Temp 执行未签名程序");
    unsignedExec(list, "*\\Users\\Public\\*", "从 Public 目录执行未签名程序");
    unsignedExec(list, "*\\Downloads\\*", "从下载目录执行未签名程序");
    unsignedExec(list, "*\\AppData\\Roaming\\*", "从 Roaming 执行未签名程序");
    unsignedExec(list, "*\\PerfLogs\\*", "从 PerfLogs 执行未签名程序");
    unsignedExec(list, "*\\Desktop\\*", "从桌面执行未签名程序(常见诱饵投放点)");
    unsignedExec(list, "*\\Documents\\*", "从文档目录执行未签名程序");
    unsignedExec(list, "*\\Temp\\7z*", "从压缩包临时解压目录执行未签名程序");
    unsignedExec(list, "*\\Temp\\Rar$*", "从 RAR 临时解压目录执行未签名程序");
    // 屏保
    proc(list, EventType::ProcessCreate, "*.scr", VerdictAction::Ask, "执行屏保程序(.scr,常被用于伪装)");
}

void addBootAndBackdoorRules(QVector<DefenseRule>& list) {
    // 辅助功能映像劫持后门 -> Block(hardOverride)
    file_(list, "*\\System32\\sethc.exe", VerdictAction::Block, "篡改粘滞键程序(sethc.exe,登录后门)", true);
    file_(list, "*\\System32\\utilman.exe", VerdictAction::Block, "篡改辅助工具管理器(utilman.exe,登录后门)", true);
    file_(list, "*\\System32\\osk.exe", VerdictAction::Block, "篡改屏幕键盘(osk.exe,登录后门)", true);
    file_(list, "*\\System32\\Magnify.exe", VerdictAction::Block, "篡改放大镜(Magnify.exe,登录后门)", true);
    file_(list, "*\\System32\\Narrator.exe", VerdictAction::Block, "篡改讲述人(Narrator.exe,登录后门)", true);
    reg(list, "*\\Image File Execution Options\\sethc.exe\\*", VerdictAction::Block, "为粘滞键设置调试器劫持(IFEO 登录后门)");
    reg(list, "*\\Image File Execution Options\\utilman.exe\\*", VerdictAction::Block, "为辅助工具设置调试器劫持(IFEO 登录后门)");
    reg(list, "*\\Image File Execution Options\\osk.exe\\*", VerdictAction::Block, "为屏幕键盘设置调试器劫持(IFEO 登录后门)");
    // 引导配置篡改 -> Block
    cmd(list, "*bcdedit*testsigning*on*", VerdictAction::Ask, "启用测试签名模式(bcdedit,可加载未签名驱动)");
    cmd(list, "*bcdedit*nointegritychecks*on*", VerdictAction::Block, "禁用驱动完整性检查(bcdedit)");
    cmd(list, "*bcdedit*loadoptions*DISABLE_INTEGRITY_CHECKS*", VerdictAction::Block, "禁用内核完整性检查(bcdedit loadoptions)");
    reg(list, "*\\CI\\Policy\\*", VerdictAction::Block, "篡改代码完整性策略(CI)");
    // 安全模式 -> Ask
    cmd(list, "*bcdedit*set*{*}*safeboot*", VerdictAction::Ask, "配置安全模式启动(可能用于绕过防护)");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addWmiAndLateralRules(QVector<DefenseRule>& list) {
    // WMI 事件订阅持久化 -> Block
    cmd(list, "*__EventFilter*", VerdictAction::Block, "创建 WMI 事件过滤器(无文件持久化)");
    cmd(list, "*CommandLineEventConsumer*", VerdictAction::Block, "创建 WMI 命令行消费者(无文件持久化)");
    cmd(list, "*ActiveScriptEventConsumer*", VerdictAction::Block, "创建 WMI 脚本消费者(无文件持久化)");
    cmd(list, "*__FilterToConsumerBinding*", VerdictAction::Block, "绑定 WMI 事件过滤器与消费者(无文件持久化)");
    // 横向移动 -> Ask
    cmd(list, "*wmic*/node:*process*call*create*", VerdictAction::Ask, "wmic 远程创建进程(横向移动)");
    cmd(list, "*Invoke-WmiMethod*-ComputerName*Create*", VerdictAction::Ask, "WMI 远程执行(横向移动)");
    cmd(list, "*Invoke-Command*-ComputerName*", VerdictAction::Ask, "远程执行命令(WinRM,可能横向)");
    cmd(list, "*psexec*-s*", VerdictAction::Ask, "PsExec 以 SYSTEM 远程执行(横向移动)");
    cmd(list, "*psexec*\\\\*", VerdictAction::Ask, "PsExec 远程执行(横向移动)");
    cmd(list, "*sc*\\\\*create*", VerdictAction::Ask, "在远程主机创建服务(横向移动)");
    cmd(list, "*net*use*\\\\*admin$*", VerdictAction::Ask, "连接 ADMIN$ 管理共享(横向移动)");
    cmd(list, "*net*use*\\\\*c$*", VerdictAction::Ask, "连接 C$ 管理共享(横向移动)");
}

void addAntiForensicsRules(QVector<DefenseRule>& list) {
    cmd(list, "*wevtutil*cl*", VerdictAction::Block, "清空事件日志(wevtutil cl,反取证)");
    cmd(list, "*Clear-EventLog*", VerdictAction::Block, "清空事件日志(PowerShell,反取证)");
    cmd(list, "*wevtutil*sl*/e:false*", VerdictAction::Block, "禁用事件日志通道(wevtutil sl,反取证)");
    cmd(list, "*fsutil*usn*deletejournal*", VerdictAction::Block, "删除 USN 变更日志(fsutil,反取证)");
    reg(list, "*\\Services\\eventlog\\*\\Start*", VerdictAction::Ask, "篡改事件日志服务启动配置");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addByovdRules(QVector<DefenseRule>& list) {
    // 已知脆弱驱动文件落地 -> Block
    file_(list, "*\\amsdk.sys", VerdictAction::Block, "BYOVD:投放脆弱驱动 amsdk.sys(WatchDog,用于关杀软)", true);
    file_(list, "*\\Truesight.sys", VerdictAction::Block, "BYOVD:投放脆弱驱动 Truesight.sys(用于关杀软)", true);
    file_(list, "*\\zam64.sys", VerdictAction::Block, "BYOVD:投放 Zemana 脆弱驱动 zam64.sys", true);
    file_(list, "*\\zamguard64.sys", VerdictAction::Block, "BYOVD:投放 Zemana 脆弱驱动 zamguard64.sys", true);
    // 注册为内核服务 -> Block
    reg(list, "*\\Services\\amsdk*", VerdictAction::Block, "BYOVD:注册 amsdk 驱动服务");
    reg(list, "*\\Services\\Truesight*", VerdictAction::Block, "BYOVD:注册 Truesight 驱动服务");
    reg(list, "*\\Services\\zam*", VerdictAction::Block, "BYOVD:注册 Zemana(zam)驱动服务");
    // 从用户可写目录加载内核驱动 -> Block
    {
        DefenseRule r; r.type = EventType::ImageLoad;
        r.targetPattern = QStringLiteral("*.sys"); r.actorPattern = QStringLiteral("*\\AppData\\*");
        r.action = VerdictAction::Block; r.note = note("BYOVD:从 AppData 加载内核驱动(.sys)"); list.append(r);
    }
}

void addOfficeMacroRules(QVector<DefenseRule>& list) {
    // 宏安全级别
    reg(list, "*\\Office\\*\\*\\Security\\VBAWarnings*", VerdictAction::Ask, "降低 Office 宏安全级别(启用所有宏,开发者可能需要)");
    reg(list, "*\\Office\\*\\*\\Security\\VBAWarnings*2*", VerdictAction::Ask, "禁用 Office 宏通知(可疑配置)");
    reg(list, "*\\Office\\*\\*\\Security\\AccessVBOM*", VerdictAction::Ask, "允许程序化访问 VBA 工程对象模型(宏自我复制)");
    // 受保护视图
    reg(list, "*\\Office\\*\\*\\Security\\ProtectedView\\DisableInternetFilesInPV*", VerdictAction::Ask, "关闭网络文件受保护视图(Office,开发者调试)");
    reg(list, "*\\Office\\*\\*\\Security\\ProtectedView\\DisableAttachmentsInPV*", VerdictAction::Ask, "关闭附件受保护视图(Office,开发者调试)");
    reg(list, "*\\Office\\*\\*\\Security\\ProtectedView\\DisableUnsafeLocationsInPV*", VerdictAction::Ask, "关闭不安全位置受保护视图(Office,开发者调试)");
    reg(list, "*\\Office\\*\\*\\Security\\ProtectedView\\DisableAllProtectedView*", VerdictAction::Ask, "禁用所有受保护视图(高可疑配置)");
    // Office 启动目录
    file_(list, "*\\Microsoft\\Word\\STARTUP\\*", VerdictAction::Ask, "向 Word 启动目录写入模板/加载项(持久化)");
    file_(list, "*\\Microsoft\\Excel\\XLSTART\\*", VerdictAction::Ask, "向 Excel 启动目录写入工作簿(持久化)");
    file_(list, "*\\Microsoft\\PowerPoint\\STARTUP\\*", VerdictAction::Ask, "向 PowerPoint 启动目录写入演示文稿(持久化)");
    file_(list, "*\\Microsoft\\Outlook\\STARTUP\\*", VerdictAction::Ask, "向 Outlook 启动目录写入脚本(持久化)");
    // 全局模板
    file_(list, "*\\Microsoft\\Templates\\Normal.dotm", VerdictAction::Ask, "篡改 Word 全局模板 Normal.dotm(宏持久化)");
    file_(list, "*\\Microsoft\\Excel\\XLSTART\\Personal.xlsb", VerdictAction::Ask, "篡改 Excel 个人宏工作簿(宏持久化)");
    // 加载项注册
    reg(list, "*\\Office\\*\\*\\Addins\\*", VerdictAction::Ask, "注册 Office COM 加载项(可能持久化)");
    reg(list, "*\\Office\\*\\*\\WLL\\*", VerdictAction::Ask, "注册 Office VBA 加载项(可能持久化)");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

// ImageLoad(target[+actor][+unsigned])规则辅助,SilverFox 批次复用。
void ilRule(QVector<DefenseRule>& list, const char* target, const char* actor, bool reqUnsigned, VerdictAction a, const char* n) {
    DefenseRule r; r.type = EventType::ImageLoad;
    if (target) r.targetPattern = QLatin1String(target);
    if (actor) r.actorPattern = QLatin1String(actor);
    r.requireUnsigned = reqUnsigned; r.action = a; r.note = note(n); list.append(r);
}

void addSilverFox2026Rules_a(QVector<DefenseRule>& list) {
    file_(list, "*\\amsdk.sys", VerdictAction::Block, "银狐 BYOVD:投放脆弱驱动 amsdk.sys(WatchDog,用于关杀软)", true);
    file_(list, "*\\wamsdk.sys", VerdictAction::Block, "银狐 BYOVD:投放 WatchDog 驱动变体(关杀软)", true);
    file_(list, "*\\ZAM.exe", VerdictAction::Block, "银狐 BYOVD:投放 Zemana 释放器(关杀软)", true);
    ilRule(list, "*.sys", "*\\AppData\\*", false, VerdictAction::Block, "银狐:从 AppData 加载内核驱动(疑似 ValleyRAT Driver Plugin rootkit)");
    ilRule(list, "*.sys", "*\\Users\\Public\\*", false, VerdictAction::Block, "银狐:从 Public 目录加载内核驱动(疑似内核 rootkit)");
    reg(list, "*\\Classes\\.pwn\\*", VerdictAction::Block, "银狐 ValleyRAT:劫持 .pwn 文件关联(持久化)");
    reg(list, "*\\Classes\\pwnfile\\*", VerdictAction::Block, "银狐 ValleyRAT:注册 .pwn 文件类型处理器");
    reg(list, "*\\Services\\AppShellElevationService*", VerdictAction::Block, "银狐:创建 AppShellElevationService 持久化服务");
    file_(list, "*\\login-module.dll*", VerdictAction::Ask, "银狐 ValleyRAT:疑似核心模块 login-module.dll 落地");
    reg(list, "*\\RunOnce\\*Update*", VerdictAction::Block, "银狐 ABCDoor:疑似 Phantom Persistence(伪装更新的重启自运行)");
    cmd(list, "*amsiInitFailed*", VerdictAction::Block, "银狐 PowerChell:AMSI 绕过(amsiInitFailed)");
    cmd(list, "*System.Management.Automation.AmsiUtils*", VerdictAction::Block, "银狐 PowerChell:反射篡改 AmsiUtils(AMSI 绕过)");
    cmd(list, "*EtwEventWrite*", VerdictAction::Block, "银狐 PowerChell:ETW 致盲(EtwEventWrite 补丁)");
    proc(list, EventType::RemoteThread, "*\\WeChat.exe", VerdictAction::Ask, "银狐 AtlasCross:向微信(WeChat)注入远程线程");
    proc(list, EventType::RemoteThread, "*\\WXWork.exe", VerdictAction::Ask, "银狐:向企业微信(WXWork)注入远程线程");
    // 伪装安装包
    fakeInstaller(list, "*\\Surfshark*Setup*.exe", "银狐:仿冒 Surfshark VPN 安装包");
    fakeInstaller(list, "*\\Signal*Setup*.exe", "银狐:仿冒 Signal 安装包");
    fakeInstaller(list, "*\\Telegram*Setup*.exe", "银狐:仿冒 Telegram 安装包");
    fakeInstaller(list, "*\\ZoomInstaller*.exe", "银狐:仿冒 Zoom 安装包");
    fakeInstaller(list, "*\\Teams*Setup*.exe", "银狐:仿冒 Microsoft Teams 安装包");
    fakeInstaller(list, "*\\QuickQ*.exe", "银狐:仿冒 QuickQ VPN 安装包");
    fakeInstaller(list, "*\\UltraViewer*.exe", "银狐:仿冒 UltraViewer 安装包");
    fakeInstaller(list, "*\\LetsVPN*.exe", "银狐:仿冒 LetsVPN 安装包");
    // RustSL 伪装 PDF
    proc(list, EventType::ProcessCreate, "*.pdf.scr", VerdictAction::Block, "银狐 RustSL:伪装 PDF 的可执行体(.pdf.scr)");
    proc(list, EventType::ProcessCreate, "*.pdf.com", VerdictAction::Block, "银狐 RustSL:伪装 PDF 的可执行体(.pdf.com)");
    cmd(list, "*zpaqfranz*", VerdictAction::Ask, "银狐:zpaqfranz 解包(疑似释放载荷)");
    file_(list, "*\\System32\\Tasks\\*Update*", VerdictAction::Ask, "银狐:创建伪装为 Update 的计划任务(持久化)");
    ilRule(list, "*\\AppData\\*.dll", nullptr, true, VerdictAction::Ask, "银狐:疑似 DLL 侧载(合法程序从 AppData 加载未签名 DLL)");
    proc(list, EventType::ProcessTerminate, "*\\usysdiag.exe", VerdictAction::Block, "银狐:试图结束安全分析工具(usysdiag)");
    proc(list, EventType::ProcessTerminate, "*\\KSafeTray.exe", VerdictAction::Block, "银狐:试图结束金山安全");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addSilverFox2026Rules_b(QVector<DefenseRule>& list) {
    // 新增 BYOVD 脆弱驱动
    file_(list, "*\\ntfs.sys.bak", VerdictAction::Block, "银狐 BYOVD:投放 NTFS 驱动备份(用于替换系统驱动)", true);
    file_(list, "*\\WinRing0x64.sys", VerdictAction::Block, "银狐 BYOVD:投放 WinRing0 脆弱驱动(用于关杀软)", true);
    file_(list, "*\\lha.sys", VerdictAction::Block, "银狐 BYOVD:投放 lha 脆弱驱动(用于关杀软)", true);
    file_(list, "*\\procexp.sys", VerdictAction::Block, "银狐 BYOVD:投放 Process Explorer 驱动(滥用用于提权/关杀软)", true);
    // 新增仿冒安装包
    fakeInstaller(list, "*\\WhatsApp*Setup*.exe", "银狐:仿冒 WhatsApp 安装包");
    fakeInstaller(list, "*\\WeChat*Setup*.exe", "银狐:仿冒微信安装包");
    fakeInstaller(list, "*\\QQ*Setup*.exe", "银狐:仿冒 QQ 安装包");
    fakeInstaller(list, "*\\DingTalk*Setup*.exe", "银狐:仿冒钉钉安装包");
    fakeInstaller(list, "*\\Feishu*Setup*.exe", "银狐:仿冒飞书安装包");
    fakeInstaller(list, "*\\WPS*Setup*.exe", "银狐:仿冒 WPS 安装包");
    fakeInstaller(list, "*\\Todesk*Setup*.exe", "银狐:仿冒 ToDesk 安装包");
    fakeInstaller(list, "*\\Sunlogin*Setup*.exe", "银狐:仿冒向日葵安装包");
    fakeInstaller(list, "*\\RustDesk*Setup*.exe", "银狐:仿冒 RustDesk 安装包");
    fakeInstaller(list, "*\\AnyDesk*Setup*.exe", "银狐:仿冒 AnyDesk 安装包");
    fakeInstaller(list, "*\\7z*Setup*.exe", "银狐:仿冒 7-Zip 安装包");
    fakeInstaller(list, "*\\WinRAR*Setup*.exe", "银狐:仿冒 WinRAR 安装包");
    // 新增持久化服务名
    reg(list, "*\\Services\\WindowsDefenderService*", VerdictAction::Block, "银狐:创建仿冒 Defender 的持久化服务");
    reg(list, "*\\Services\\MicrosoftTelemetry*", VerdictAction::Block, "银狐:创建仿冒微软遥测的持久化服务");
    reg(list, "*\\Services\\SystemHelpService*", VerdictAction::Block, "银狐:创建 SystemHelpService 持久化服务");
    reg(list, "*\\Services\\NetworkConnectionService*", VerdictAction::Block, "银狐:创建 NetworkConnectionService 持久化服务");
    reg(list, "*\\Services\\RuntimeBroker*", VerdictAction::Block, "银狐:创建仿冒 RuntimeBroker 的持久化服务(注意:真正的 RuntimeBroker 不是服务)");
    // 新增计划任务持久化
    file_(list, "*\\System32\\Tasks\\*MicrosoftEdge*", VerdictAction::Ask, "银狐:创建仿冒 Edge 更新的计划任务(持久化)");
    file_(list, "*\\System32\\Tasks\\*WindowsDefender*", VerdictAction::Ask, "银狐:创建仿冒 Defender 的计划任务(持久化)");
    file_(list, "*\\System32\\Tasks\\*GoogleUpdate*", VerdictAction::Ask, "银狐:创建仿冒 Google 更新的计划任务(持久化)");
    file_(list, "*\\System32\\Tasks\\*AdobeARM*", VerdictAction::Ask, "银狐:创建仿冒 Adobe 更新的计划任务(持久化)");
    // 仿冒系统 DLL(侧载用)
    file_(list, "*\\gh0st.dll", VerdictAction::Block, "银狐 Gh0st:恶意模块 gh0st.dll 落地");
    file_(list, "*\\gh0st.dat", VerdictAction::Block, "银狐 Gh0st:恶意载荷 gh0st.dat 落地");
    file_(list, "*\\svchost.dll", VerdictAction::Block, "银狐:仿冒 svchost 的恶意 DLL(侧载用)");
    file_(list, "*\\winlogon.dll", VerdictAction::Block, "银狐:仿冒 winlogon 的恶意 DLL(侧载用)");
    file_(list, "*\\explorer.dll", VerdictAction::Block, "银狐:仿冒 explorer 的恶意 DLL(侧载用)");
    file_(list, "*\\RuntimeBroker.dll", VerdictAction::Block, "银狐:仿冒 RuntimeBroker 的恶意 DLL(侧载用)");
    file_(list, "*\\Windows.Media.dll", VerdictAction::Block, "银狐:仿冒 Windows.Media 的恶意 DLL(侧载用)");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addSilverFox2026Rules_c(QVector<DefenseRule>& list) {
    cmd(list, "*-enc*JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA*", VerdictAction::Block, "银狐:PowerShell 编码载荷(ValleyRAT C2 配置注入)");
    cmd(list, "*-enc*SUVYIChOAGUAdwAtAE8AYgBqAGUAYwB0*", VerdictAction::Block, "银狐:PowerShell 编码载荷(IEX 下载执行)");
    ilRule(list, "*\\wps.dll", "*\\AppData\\*", true, VerdictAction::Ask, "银狐:从 AppData 加载 wps.dll(疑似 WPS 侧载)");
    ilRule(list, "*\\qq.exe", "*\\AppData\\*", true, VerdictAction::Ask, "银狐:从 AppData 加载 qq.exe(疑似 QQ 侧载)");
    ilRule(list, "*\\wechat.dll", "*\\AppData\\*", true, VerdictAction::Ask, "银狐:从 AppData 加载 wechat.dll(疑似微信侧载)");
    // IFEO 劫持系统工具
    reg(list, "*\\Image File Execution Options\\cmd.exe\\*", VerdictAction::Block, "银狐:劫持 cmd.exe 的 IFEO(持久化/提权)");
    reg(list, "*\\Image File Execution Options\\powershell.exe\\*", VerdictAction::Block, "银狐:劫持 powershell.exe 的 IFEO(持久化/提权)");
    reg(list, "*\\Image File Execution Options\\conhost.exe\\*", VerdictAction::Block, "银狐:劫持 conhost.exe 的 IFEO(持久化/提权)");
    // AMSI/ETW/Defender 免杀变种
    cmd(list, "*Set-MpPreference*DisableIOAVProtection*$true*", VerdictAction::Block, "银狐:禁用 Defender IOAV 保护(AMSI 绕过变种)");
    cmd(list, "*Set-MpPreference*SubmitSamplesConsent*2*", VerdictAction::Block, "银狐:禁用 Defender 样本提交(规避云检测)");
    cmd(list, "*Set-MpPreference*MAPSReporting*0*", VerdictAction::Block, "银狐:禁用 Defender MAPS 报告(规避云检测)");
    cmd(list, "*Add-MpPreference*ExclusionProcess*", VerdictAction::Block, "银狐:添加 Defender 进程排除(免杀)");
    // 网络 C2 命令行
    cmd(list, "*powershell*Net.Sockets.TCPClient*", VerdictAction::Ask, "银狐:PowerShell TCP 反向连接(疑似 C2)");
    cmd(list, "*powershell*Net.Sockets.Socket*", VerdictAction::Ask, "银狐:PowerShell Socket 通信(疑似 C2)");
    // 文件膨胀 / Temp 载荷
    file_(list, "*\\Windows\\Temp\\*.exe", VerdictAction::Ask, "银狐:从 Windows Temp 释放可执行体(疑似载荷落地)");
    // RDP 劫持
    reg(list, "*\\Terminal Server\\*fSingleSessionPerUser*", VerdictAction::Ask, "银狐:修改 RDP 单会话限制(疑似 RDP 劫持)");
    reg(list, "*\\Terminal Server\\*fDenyTSConnections*", VerdictAction::Block, "银狐:修改 RDP 连接策略(疑似开启远程桌面)");
    // UAC 绕过变种
    reg(list, "*\\Classes\\ms-settings\\shell\\open\\command\\DelegateExecute*", VerdictAction::Block, "银狐:劫持 ms-settings DelegateExecute(UAC 绕过变种)");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addSilverFox2026Rules_d(QVector<DefenseRule>& list) {
    // FileWrite + actor + unsigned 侧载落地辅助
    auto fw = [&](const char* target, const char* actor, VerdictAction a, const char* n) {
        DefenseRule r; r.type = EventType::FileWrite; r.targetPattern = QLatin1String(target);
        r.actorPattern = QLatin1String(actor); r.requireUnsigned = true; r.action = a;
        r.note = note(n); list.append(r);
    };
    // Nidhogg rootkit + 已知恶意加载器
    file_(list, "*\\nidhogg.sys", VerdictAction::Block, "银狐 Nidhogg:投放 Nidhogg rootkit 驱动(隐藏进程/文件)", true);
    file_(list, "*\\nidhogg64.sys", VerdictAction::Block, "银狐 Nidhogg:投放 Nidhogg x64 rootkit 驱动(隐藏进程/文件)", true);
    file_(list, "*\\desk_compositor_x64.dll", VerdictAction::Block, "银狐 ValleyRAT:已知恶意加载器 desk_compositor_x64.dll 落地", true);
    file_(list, "*\\D3D11InstallHelper.dll", VerdictAction::Block, "银狐 ValleyRAT:已知恶意加载器 D3D11InstallHelper.dll 落地");
    // ABCDoor
    file_(list, "*\\AppData\\*\\msimg32.dll", VerdictAction::Block, "银狐 ABCDoor:msimg32.dll 在用户目录落地(已知 IOC)");
    file_(list, "*\\AppData\\Roaming\\Embarcadero\\*.dll", VerdictAction::Ask, "银狐 ABCDoor:疑似 Embarcadero 伪装路径 DLL(后门插件)");
    file_(list, "*\\AppData\\Roaming\\Embarcadero\\*.exe", VerdictAction::Ask, "银狐 ABCDoor:疑似 Embarcadero 伪装路径 EXE(后门持久化)");
    // ValleyRAT 已知组件
    file_(list, "*\\Users\\Public\\*\\funzip.exe", VerdictAction::Block, "银狐 ValleyRAT:已知释放器 funzip.exe(7-Zip 伪装)");
    file_(list, "*\\Users\\Public\\*\\men.exe", VerdictAction::Block, "银狐 ValleyRAT:已知主组件 men.exe 落地");
    file_(list, "*\\Users\\Public\\Downloads\\bb.jpg", VerdictAction::Ask, "银狐 ValleyRAT:Public 下载目录疑似载荷配置(bb.jpg)");
    // WMI 持久化
    cmd(list, "*wmic*__EventFilter*CREATE*", VerdictAction::Ask, "银狐:通过 WMI 创建事件过滤器(疑似持久化)");
    cmd(list, "*wmic*CommandLineEventConsumer*CREATE*", VerdictAction::Ask, "银狐:通过 WMI 创建命令事件消费者(疑似持久化)");
    cmd(list, "*wmic*__FilterToConsumerBinding*CREATE*", VerdictAction::Ask, "银狐:通过 WMI 绑定过滤器与消费者(疑似持久化)");
    // 常用侧载 DLL 名(AppData 落地)
    fw("*\\vulkan-1.dll", "*\\AppData\\*", VerdictAction::Ask, "银狐:AppData 落地 vulkan-1.dll(疑似 Vulkan 侧载)");
    fw("*\\sqlite3.dll", "*\\AppData\\*", VerdictAction::Ask, "银狐:AppData 落地 sqlite3.dll(疑似 SQLite 侧载)");
    fw("*\\libvlc.dll", "*\\AppData\\*", VerdictAction::Ask, "银狐:AppData 落地 libvlc.dll(疑似 VLC 侧载)");
    fw("*\\python311.dll", "*\\AppData\\*", VerdictAction::Ask, "银狐:AppData 落地 python311.dll(疑似 Python 加载器侧载)");
    proc(list, EventType::ProcessCreate, "*\\CleverSoar*", VerdictAction::Ask, "银狐:疑似 CleverSoar 安装器执行(2026 新投递链)");
    // Defender 全面免杀
    cmd(list, "*Add-MpPreference*ExclusionPath*C:\\*", VerdictAction::Block, "银狐 ValleyRAT:添加整个 C 盘到 Defender 排除(全面免杀)");
    cmd(list, "*Set-MpPreference*DisableRealtimeMonitoring*$true*", VerdictAction::Block, "银狐:禁用 Defender 实时监控");
    cmd(list, "*Set-MpPreference*DisableBehaviorMonitoring*$true*", VerdictAction::Block, "银狐:禁用 Defender 行为监控");
    cmd(list, "*Set-MpPreference*DisableBlockAtFirstSeen*$true*", VerdictAction::Block, "银狐:禁用 Defender 首次看见时阻止(规避云检测)");
    // 更多仿冒安装包
    fakeInstaller(list, "*\\DeepSeek*Setup*.exe", "银狐:仿冒 DeepSeek AI 安装包");
    fakeInstaller(list, "*\\DeepSeek*.exe", "银狐:仿冒 DeepSeek 安装包");
    fakeInstaller(list, "*\\SogouInput*Setup*.exe", "银狐:仿冒搜狗输入法安装包");
    fakeInstaller(list, "*\\SogouPinyin*.exe", "银狐:仿冒搜狗拼音安装包");
    fakeInstaller(list, "*\\Chrome*Setup*.exe", "银狐:仿冒谷歌浏览器安装包");
    fakeInstaller(list, "*\\WinSCP*Setup*.exe", "银狐:仿冒 WinSCP 安装包");
    fakeInstaller(list, "*\\GoogleTranslate*.exe", "银狐:仿冒谷歌翻译安装包");
    // 更多持久化服务
    reg(list, "*\\Services\\SessionEnv", VerdictAction::Block, "银狐:创建仿冒 SessionEnv 持久化服务");
    reg(list, "*\\Services\\PlugPlay", VerdictAction::Block, "银狐:创建仿冒 PlugPlay 持久化服务");
    reg(list, "*\\Services\\SysMain", VerdictAction::Block, "银狐:创建仿冒 SysMain 持久化服务");
    // C2 端口
    cmd(list, "*:22011*", VerdictAction::Ask, "银狐:疑似 ValleyRAT C2 通信(非标准端口 22011)");
    cmd(list, "*:23156*", VerdictAction::Ask, "银狐:疑似 ValleyRAT C2 通信(非标准端口 23156)");
    cmd(list, "*:6666*", VerdictAction::Ask, "银狐:疑似 ValleyRAT C2 通信(非标准端口 6666)");
    cmd(list, "*:8888*", VerdictAction::Ask, "银狐:疑似 ValleyRAT C2 通信(非标准端口 8888)");
    reg(list, "*\\COR_PROFILER*", VerdictAction::Ask, "银狐:设置 COR_PROFILER 环境变量(疑似 .NET 探测/持久化)");
}

// 分派器:定义在所有 _a.._d 之后,可直接调用它们。
void addSilverFox2026Rules(QVector<DefenseRule>& list) {
    addSilverFox2026Rules_a(list);
    addSilverFox2026Rules_b(list);
    addSilverFox2026Rules_c(list);
    addSilverFox2026Rules_d(list);
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

// 银狐 2025 下半年最新战役规则(依据 Fortinet / Zscaler / Seqrite 2025-08~2025-10 公开报告):
//   HoldingHands RAT(Gh0stBins)、Operation Silk Lure、HiddenGh0st SEO 投毒、kkRAT。
// 策略:具名恶意 IOC = 硬指标(Block);投放点/侧载位置/双用途工具 = 询问(Ask);
// 仿冒安装包用 requireUnsigned 门控(签名正版自动放行)。遵循"软信号不单独定罪"。
void addSilverFoxLatestCampaignRules(QVector<DefenseRule>& list) {
    // ---- HoldingHands RAT / Gh0stBins(2025-10,扩散至日本/马来西亚/中国)----
    // 提权到 TrustedInstaller 后向 System32 释放的多阶段载荷特征文件。
    file_(list, "*\\Windows\\System32\\msvchost.dat", VerdictAction::Block,
          "银狐 HoldingHands：System32 释放 msvchost.dat（加密 shellcode，已知 IOC）", true);
    file_(list, "*\\Windows\\System32\\svchost.ini", VerdictAction::Block,
          "银狐 HoldingHands：System32 释放 svchost.ini（VirtualAlloc RVA 配置，已知 IOC）");
    file_(list, "*\\BrokerClientCallback.dll", VerdictAction::Ask,
          "银狐 HoldingHands：生成 BrokerClientCallback.dll（TimeBrokerClient 改名侧载）");

    // ---- Operation Silk Lure(LNK 伪装简历投递 ValleyRAT/Winos 4.0)----
    file_(list, "*\\CreateHiddenTask.vbs", VerdictAction::Block,
          "银狐 Silk Lure：释放 CreateHiddenTask.vbs（隐藏计划任务创建脚本）");
    file_(list, "*\\AppData\\Roaming\\Security\\*.exe", VerdictAction::Ask,
          "银狐 Silk Lure：向 Roaming\\Security 写入可执行体（ValleyRAT 三载荷投放点）");
    file_(list, "*\\AppData\\Roaming\\Security\\*.dll", VerdictAction::Ask,
          "银狐 Silk Lure：向 Roaming\\Security 写入 DLL（疑似侧载模块）");
    ilRule(list, "*\\AppData\\Roaming\\Security\\*.dll", nullptr, false, VerdictAction::Ask,
           "银狐 Silk Lure：从 Roaming\\Security 加载 DLL（keytool.exe 白加黑侧载 Winos）");

    // ---- HiddenGh0st / Winos SEO 投毒(2025-08,伪装 DeepL/Chrome/Telegram 等)----
    proc(list, EventType::ProcessCreate, "*\\insalivation.exe", VerdictAction::Block,
         "银狐 HiddenGh0st：执行 insalivation.exe（已知恶意载荷）");
    file_(list, "*\\insalivation.exe", VerdictAction::Block,
          "银狐 HiddenGh0st：insalivation.exe 落地（已知恶意载荷）");
    file_(list, "*\\EnumW.dll", VerdictAction::Block,
          "银狐 HiddenGh0st：EnumW.dll 落地（反分析恶意模块）");
    ilRule(list, "*\\EnumW.dll", nullptr, false, VerdictAction::Block,
           "银狐 HiddenGh0st：加载 EnumW.dll（反分析恶意模块）");
    ilRule(list, "*\\AppData\\*\\AIDE.dll", nullptr, false, VerdictAction::Ask,
           "银狐 HiddenGh0st：从 AppData 加载 AIDE.dll（C2/心跳/监控侧载模块）");
    reg(list, "*\\Classes\\TypeLib\\*\\win32\\*", VerdictAction::Ask,
        "银狐 HiddenGh0st：TypeLib COM 劫持（win32 键脚本持久化）");

    // ---- kkRAT(Zscaler,2025-05 起经 GitHub Pages 伪装 DingTalk 等投递)----
    file_(list, "*\\longlq.cl", VerdictAction::Block,
          "银狐 kkRAT：longlq.cl 加密最终载荷落地（已知 IOC）", true);
    cmd(list, "*RealBlindingEDR*", VerdictAction::Block,
        "银狐 kkRAT：调用 RealBlindingEDR 关闭杀软（BYOVD 关防护）");
    proc(list, EventType::ProcessCreate, "*\\GotoHTTP*", VerdictAction::Ask,
         "银狐 kkRAT：部署远控工具 GotoHTTP（合法 RMM，疑似被滥用）");
    cmd(list, "*GotoHTTP*", VerdictAction::Ask,
        "银狐 kkRAT：命令行部署 GotoHTTP 远控（疑似被滥用）");
    cmd(list, "*Disable-NetAdapter*", VerdictAction::Ask,
        "银狐 kkRAT：禁用网络适配器（临时断网以干扰杀软联网/云查）");
    cmd(list, "*netsh*interface*set*interface*disable*", VerdictAction::Ask,
        "银狐 kkRAT：netsh 禁用网络接口（临时断网以干扰杀软联网/云查）");

    // ---- 关杀软:结束更多安全软件进程(各战役共有,均为硬指标 -> Block)----
    proc(list, EventType::ProcessTerminate, "*\\AvastUI.exe", VerdictAction::Block, "银狐：试图结束 Avast 界面");
    proc(list, EventType::ProcessTerminate, "*\\AvastSvc.exe", VerdictAction::Block, "银狐：试图结束 Avast 服务");
    proc(list, EventType::ProcessTerminate, "*\\avp.exe", VerdictAction::Block, "银狐：试图结束卡巴斯基（avp）");
    proc(list, EventType::ProcessTerminate, "*\\avpui.exe", VerdictAction::Block, "银狐：试图结束卡巴斯基界面（avpui）");
    proc(list, EventType::ProcessTerminate, "*\\NortonSecurity.exe", VerdictAction::Block, "银狐：试图结束诺顿安全");
    proc(list, EventType::ProcessTerminate, "*\\kxescore.exe", VerdictAction::Block, "银狐：试图结束金山毒霸核心（kxescore）");
    proc(list, EventType::ProcessTerminate, "*\\HipsDaemon.exe", VerdictAction::Block, "银狐：试图结束火绒服务进程（HipsDaemon）");
    proc(list, EventType::ProcessTerminate, "*\\QQPCTray.exe", VerdictAction::Block, "银狐：试图结束腾讯电脑管家（QQPCTray）");

    // ---- 新增仿冒软件安装包(SEO 投毒伪装站;requireUnsigned + Ask,签名正版自动放行)----
    fakeInstaller(list, "*\\DeepL*Setup*.exe", "银狐：仿冒 DeepL 翻译安装包");
    fakeInstaller(list, "*\\DeepLSetup*.exe", "银狐：仿冒 DeepL 翻译安装包");
    fakeInstaller(list, "*\\Youdao*Setup*.exe", "银狐：仿冒有道词典安装包");
    fakeInstaller(list, "*\\YoudaoDict*.exe", "银狐：仿冒有道词典安装包");
    fakeInstaller(list, "*\\Sogou*Setup*.exe", "银狐：仿冒搜狗软件安装包");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

// 银狐 MSI/安装包投递链补强(针对本轮 intsoft.msi 逃逸暴露的通用 TTP)。
// 原则:未签名 + 用户暂存目录 + 远程线程注入 = 确定性 shellcode 注入(几乎不见于正常软件),
// 提为 Block —— 这样即使开启静默模式也照拦(静默只降级「询问」,不降级「拦截」)。侧载/派生
// 载荷等中等置信留 Ask,靠落盘即扫(FileWrite→VT)与静默模式硬指标升级兜底,避免误报。
void addSilverFoxMsiChainRules(QVector<DefenseRule>& list) {
    // 1) 未签名的用户暂存目录进程发起远程线程注入 -> Block(shellcode 注入,穿透静默)。
    auto injectFromDir = [&](const char* actorDir, const char* n) {
        DefenseRule r; r.type = EventType::RemoteThread;
        r.actorPattern = QLatin1String(actorDir);
        r.requireUnsigned = true;               // 仅未签名注入方命中(签名的更新器/系统进程不误伤)
        r.action = VerdictAction::Block;
        r.note = note(n);
        list.append(r);
    };
    injectFromDir("*\\AppData\\Local\\Temp\\*", "银狐:Temp 未签名进程注入远程线程(shellcode 注入,高危)");
    injectFromDir("*\\Windows\\Temp\\*",        "银狐:Windows\\Temp 未签名进程注入远程线程(shellcode 注入,高危)");
    injectFromDir("*\\Users\\Public\\*",        "银狐:Public 目录未签名进程注入远程线程(shellcode 注入,高危)");
    injectFromDir("*\\ProgramData\\*",          "银狐:ProgramData 未签名进程注入远程线程(shellcode 注入,高危)");
    injectFromDir("*\\AppData\\Roaming\\*",     "银狐:Roaming 未签名进程注入远程线程(shellcode 注入,高危)");
    injectFromDir("*\\Downloads\\*",            "银狐:下载目录未签名进程注入远程线程(shellcode 注入,高危)");

    // 2) 从 ProgramData / Public 加载未签名 DLL(补齐现有 AppData/Temp 侧载覆盖)-> Ask(白加黑侧载暂存点)。
    ilRule(list, "*\\ProgramData\\*.dll", nullptr, true, VerdictAction::Ask, "银狐:从 ProgramData 加载未签名 DLL(疑似白加黑侧载)");
    ilRule(list, "*\\Users\\Public\\*.dll", nullptr, true, VerdictAction::Ask, "银狐:从 Public 加载未签名 DLL(疑似白加黑侧载)");

    // 3) 安装宿主 msiexec 派生「用户目录的未签名程序」-> Ask(银狐 MSI 释放并运行载荷的典型链)。
    //    正规安装器偶尔也从 Temp 跑未签名辅助程序,故留 Ask(非 Block),配合落盘即扫兜底。
    auto msiSpawn = [&](const char* childDir, const char* n) {
        DefenseRule r; r.type = EventType::ProcessCreate;
        r.parentPattern = QStringLiteral("*\\msiexec.exe");
        r.actorPattern = QLatin1String(childDir);
        r.requireUnsigned = true;
        r.action = VerdictAction::Ask;
        r.note = note(n);
        list.append(r);
    };
    msiSpawn("*\\AppData\\*",             "银狐:msiexec 派生 AppData 未签名程序(疑似 MSI 投递载荷)");
    msiSpawn("*\\Users\\Public\\*",       "银狐:msiexec 派生 Public 未签名程序(疑似 MSI 投递载荷)");
    msiSpawn("*\\ProgramData\\*",         "银狐:msiexec 派生 ProgramData 未签名程序(疑似 MSI 投递载荷)");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addImControlRules(QVector<DefenseRule>& list) {
    // 向 IM 进程注入远程线程(仅未签名注入方命中)
    imInjectRemoteThread(list, "*\\Weixin.exe", "向微信(Weixin)注入远程线程(疑似群发/盗号控制)");
    imInjectRemoteThread(list, "*\\WeChatApp.exe", "向微信小程序宿主注入远程线程(疑似控制)");
    imInjectRemoteThread(list, "*\\QQ.exe", "向 QQ 注入远程线程(疑似群发/盗号控制)");
    imInjectRemoteThread(list, "*\\TIM.exe", "向 TIM 注入远程线程(疑似群发/盗号控制)");
    imInjectRemoteThread(list, "*\\QQExternal.exe", "向 QQ 外部模块注入远程线程(疑似控制)");
    // IM 从用户可写目录加载未签名 DLL(白加黑侧载)
    imUnsignedModuleFromUserDir(list);
    // 向 IM 安装目录植入 DLL
    file_(list, "*\\Tencent\\WeChat\\*.dll", VerdictAction::Ask, "向微信安装目录写入 DLL(疑似植入群控/外挂模块)");
    file_(list, "*\\Tencent\\Weixin\\*.dll", VerdictAction::Ask, "向微信(Weixin)安装目录写入 DLL(疑似植入群控模块)");
    file_(list, "*\\Tencent\\WXWork\\*.dll", VerdictAction::Ask, "向企业微信安装目录写入 DLL(疑似植入群控模块)");
    file_(list, "*\\Tencent\\*\\QQ\\*.dll", VerdictAction::Ask, "向 QQ 安装目录写入 DLL(疑似植入群控模块)");
    // 已知群控外挂模块落地 -> Block
    file_(list, "*\\wxhelper.dll", VerdictAction::Block, "微信群控外挂模块 wxhelper.dll 落地");
    file_(list, "*\\WeChatHelper*.dll", VerdictAction::Block, "微信群控外挂模块 WeChatHelper 落地");
    file_(list, "*\\wxauto*.dll", VerdictAction::Block, "微信自动化群发模块 wxauto 落地");
    file_(list, "*\\ComWeChatRobot*.dll", VerdictAction::Block, "微信机器人群控模块 ComWeChatRobot 落地");
    file_(list, "*\\wxrobot*.dll", VerdictAction::Block, "微信群发机器人模块 wxrobot 落地");
    file_(list, "*\\qqhelper*.dll", VerdictAction::Block, "QQ 群控外挂模块 qqhelper 落地");
    // 已知群控模块被加载 -> Block
    ilRule(list, "*\\wxhelper.dll", nullptr, false, VerdictAction::Block, "加载微信群控外挂模块 wxhelper.dll(群发/自动化)");
    ilRule(list, "*\\wxauto*.dll", nullptr, false, VerdictAction::Block, "加载微信自动化群发模块 wxauto(群发)");
    // 命令行群发框架
    cmd(list, "*wxauto*", VerdictAction::Ask, "命令行调用微信自动化框架 wxauto(疑似群发)");
    cmd(list, "*itchat*", VerdictAction::Ask, "命令行调用微信网页协议库 itchat(疑似群发)");
    cmd(list, "*PyWeChatSpy*", VerdictAction::Ask, "命令行调用微信控制框架 PyWeChatSpy(疑似群发)");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addImMassMessagingRules(QVector<DefenseRule>& list) {
    // 已知群发/群控框架注入模块 DLL 落地 -> Block
    file_(list, "*\\wcf.dll", VerdictAction::Block, "微信群发框架 WeChatFerry 模块 wcf.dll 落地(自动群发/机器人)");
    file_(list, "*\\wcferry*.dll", VerdictAction::Block, "微信群发框架 WeChatFerry 模块落地(自动群发/机器人)");
    file_(list, "*\\WeChatFerry*.dll", VerdictAction::Block, "微信群发框架 WeChatFerry 模块落地(自动群发/机器人)");
    file_(list, "*\\spy.dll", VerdictAction::Block, "微信群发框架注入模块 spy.dll 落地(WeChatFerry/hook 群发)");
    file_(list, "*\\wcprobe.dll", VerdictAction::Block, "微信群控框架 ntchat 模块 wcprobe.dll 落地(群发/hook)");
    file_(list, "*\\WeChatPCAPI*.dll", VerdictAction::Block, "微信群控 SDK WeChatPCAPI 落地(群发/自动化)");
    file_(list, "*\\CWeChatRobot*.dll", VerdictAction::Block, "微信机器人群控模块 CWeChatRobot 落地(群发)");
    file_(list, "*\\wxbot*.dll", VerdictAction::Block, "微信群发机器人模块 wxbot 落地(群发)");
    file_(list, "*\\WeChatSpy*.dll", VerdictAction::Block, "微信监听/群控模块 WeChatSpy 落地(群发/聊天记录窃取)");
    file_(list, "*\\WxSender*.dll", VerdictAction::Block, "微信群发模块 WxSender 落地(批量群发)");
    file_(list, "*\\qqbot*.dll", VerdictAction::Block, "QQ 群发机器人模块 qqbot 落地(群发)");
    file_(list, "*\\QQRobot*.dll", VerdictAction::Block, "QQ 群控机器人模块 QQRobot 落地(群发)");
    file_(list, "*\\TIMHook*.dll", VerdictAction::Block, "TIM 群控 hook 模块 TIMHook 落地(群发)");
    // 上述模块被加载 -> Block
    static const char* mods[] = {
        "*\\wcf.dll", "*\\wcferry*.dll", "*\\WeChatFerry*.dll", "*\\spy.dll",
        "*\\wcprobe.dll", "*\\WeChatPCAPI*.dll", "*\\CWeChatRobot*.dll",
        "*\\wxbot*.dll", "*\\WeChatSpy*.dll", "*\\WxSender*.dll",
        "*\\qqbot*.dll", "*\\QQRobot*.dll", "*\\TIMHook*.dll",
    };
    for (const char* m : mods)
        ilRule(list, m, nullptr, false, VerdictAction::Block, "加载微信/QQ 群发外挂模块(群发/自动化)");
    // 命令行群发框架 -> Ask
    cmd(list, "*wcferry*", VerdictAction::Ask, "命令行调用微信群发框架 WeChatFerry(疑似群发)");
    cmd(list, "*ntchat*", VerdictAction::Ask, "命令行调用微信群控框架 ntchat(疑似群发)");
    cmd(list, "*wechaty*", VerdictAction::Ask, "命令行调用微信机器人框架 wechaty(疑似群发)");
    cmd(list, "*wxpy*", VerdictAction::Ask, "命令行调用微信控制库 wxpy(疑似群发)");
    cmd(list, "*WeChatPCAPI*", VerdictAction::Ask, "命令行调用微信群控 SDK WeChatPCAPI(疑似群发)");
    cmd(list, "*wxpusher*", VerdictAction::Ask, "命令行调用微信推送框架 wxpusher(疑似群发)");
    cmd(list, "*qqbot*", VerdictAction::Ask, "命令行调用 QQ 机器人框架 qqbot(疑似群发)");
    cmd(list, "*uiautomation*wechat*", VerdictAction::Ask, "UI 自动化驱动微信(疑似模拟点击批量群发)");
    cmd(list, "*pyautogui*wechat*", VerdictAction::Ask, "pyautogui 驱动微信(疑似模拟点击批量群发)");
    // 补充注入落点
    imInjectRemoteThread(list, "*\\WXWork.exe", "向企业微信(WXWork)注入远程线程(疑似群发/群控)");
    imInjectRemoteThread(list, "*\\WeChatAppEx.exe", "向微信小程序渲染宿主注入远程线程(疑似控制)");
    imInjectRemoteThread(list, "*\\QQExternal.exe", "向 QQ 外部模块注入远程线程(疑似群发/群控)");
    // IM 从 Public / ProgramData 加载未签名 DLL
    static const char* imActors[] = { "*\\WeChat.exe", "*\\Weixin.exe", "*\\WXWork.exe", "*\\QQ.exe", "*\\TIM.exe" };
    for (const char* actor : imActors) {
        ilRule(list, "*\\Users\\Public\\*.dll", actor, true, VerdictAction::Ask, "IM 从 Public 目录加载未签名 DLL(疑似群发白加黑侧载)");
        ilRule(list, "*\\ProgramData\\*.dll", actor, true, VerdictAction::Ask, "IM 从 ProgramData 加载未签名 DLL(疑似群发白加黑侧载)");
    }
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addImHarvestAndFrameworkRules(QVector<DefenseRule>& list) {
    // 具名群控/hook 模块:落地(FileWrite Block)+ 被加载(ImageLoad Block)
    auto modRule = [&](const char* pattern, const char* moduleNote) {
        DefenseRule f; f.type = EventType::FileWrite; f.targetPattern = QLatin1String(pattern);
        f.action = VerdictAction::Block;
        f.note = kTag + QLatin1Char(' ') + u(moduleNote) + u(" 落地(群发/群控外挂)");
        list.append(f);
        DefenseRule i; i.type = EventType::ImageLoad; i.targetPattern = QLatin1String(pattern);
        i.action = VerdictAction::Block;
        i.note = kTag + QLatin1Char(' ') + u("加载") + u(moduleNote) + u("(群发/群控外挂)");
        list.append(i);
    };
    modRule("*\\wxhook.dll", "微信 hook 群控模块 wxhook.dll");
    modRule("*\\WeChatHook*.dll", "微信 hook 群控模块 WeChatHook");
    modRule("*\\WeChatSDK*.dll", "第三方微信群控 SDK WeChatSDK");
    modRule("*\\vchat*.dll", "微信群控框架 vchat 模块");
    modRule("*\\WeChatRobotCE*.dll", "微信机器人群控模块 WeChatRobotCE");
    modRule("*\\wxbotpp*.dll", "微信群发机器人模块 wxbotpp");
    modRule("*\\WeChatManager*.dll", "微信多开/群控管理模块 WeChatManager");
    modRule("*\\WeWorkHook*.dll", "企业微信 hook 群控模块 WeWorkHook");
    modRule("*\\wework_api*.dll", "企业微信群发接口模块 wework_api");
    modRule("*\\wxDump*.dll", "微信数据库导出模块 wxDump");
    modRule("*\\QQHook*.dll", "QQ hook 群控模块 QQHook");
    // 微信数据库解密/导出工具(采集群发目标)-> Ask
    cmd(list, "*PyWxDump*", VerdictAction::Ask, "命令行调用微信取证工具 PyWxDump(解密导出通讯录/聊天库,疑似采集群发目标)");
    cmd(list, "*SharpWxDump*", VerdictAction::Ask, "命令行调用微信取证工具 SharpWxDump(导出账号/密钥,疑似采集群发目标)");
    cmd(list, "*wxdump*", VerdictAction::Ask, "命令行调用微信数据库导出工具 wxdump(疑似采集群发目标)");
    cmd(list, "*WeChatMsg*", VerdictAction::Ask, "命令行调用微信聊天记录导出工具 WeChatMsg(疑似采集群发目标)");
    cmd(list, "*wxhook*", VerdictAction::Ask, "命令行调用微信 hook 群控框架 wxhook(疑似群发)");
    cmd(list, "*vchat*", VerdictAction::Ask, "命令行调用微信群控框架 vchat(疑似群发)");
    // 补充注入落点
    imInjectRemoteThread(list, "*\\WeChatOCR.exe", "向微信 OCR 子进程注入远程线程(疑似群控挂载)");
    imInjectRemoteThread(list, "*\\WeChatUtility.exe", "向微信工具子进程注入远程线程(疑似群控挂载)");
    imInjectRemoteThread(list, "*\\WXWorkWeb.exe", "向企业微信 Web 宿主注入远程线程(疑似群发/群控)");
    file_(list, "*\\WXWork\\*\\wwapi*.dll", VerdictAction::Ask, "向企业微信安装目录写入接口 DLL(疑似植入群发模块)");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addDeepPersistenceRules(QVector<DefenseRule>& list) {
    // LSA 安全包 / 认证包注入 -> Block
    reg(list, "*\\Control\\Lsa\\Security Packages*", VerdictAction::Block, "注册 LSA 安全包(Security Packages,SYSTEM 级持久化)");
    reg(list, "*\\Control\\Lsa\\Authentication Packages*", VerdictAction::Block, "注册 LSA 认证包(Authentication Packages,凭据劫持)");
    reg(list, "*\\Control\\Lsa\\Notification Packages*", VerdictAction::Block, "注册 LSA 通知包(密码变更监听,凭据窃取)");
    reg(list, "*\\SecurityProviders\\*", VerdictAction::Block, "篡改 SecurityProviders(SSP 注入持久化)");
    // AppCertDLLs / BootExecute / KnownDLLs
    reg(list, "*\\Control\\Session Manager\\AppCertDlls*", VerdictAction::Block, "设置 AppCertDLLs(全局进程注入持久化)");
    reg(list, "*\\Control\\Session Manager\\BootExecute*", VerdictAction::Block, "篡改 BootExecute(开机最早期执行,Rootkit 持久化)");
    reg(list, "*\\Control\\Session Manager\\KnownDLLs\\*", VerdictAction::Block, "篡改 KnownDLLs(系统 DLL 劫持)");
    // COR_PROFILER
    reg(list, "*\\Environment\\COR_PROFILER_PATH*", VerdictAction::Block, "设置 COR_PROFILER 路径(.NET 分析器注入持久化)");
    reg(list, "*\\Classes\\CLSID\\*\\InprocServer32*COR_PROFILER*", VerdictAction::Block, "注册 COR_PROFILER COM 分析器(注入持久化)");
    // netsh helper / 打印监视器 / 时间提供程序
    reg(list, "*\\Microsoft\\NetSh\\*", VerdictAction::Block, "注册 netsh helper DLL(持久化)");
    reg(list, "*\\Control\\Print\\Monitors\\*\\Driver*", VerdictAction::Block, "注册打印监视器 DLL(spoolsv SYSTEM 持久化)");
    reg(list, "*\\W32Time\\TimeProviders\\*\\DllName*", VerdictAction::Block, "注册时间提供程序 DLL(SYSTEM 持久化)");
    // Shell 扩展 / 加载点 -> Ask
    reg(list, "*\\ShellServiceObjectDelayLoad\\*", VerdictAction::Ask, "注册 Shell 服务对象延迟加载(可能持久化)");
    reg(list, "*\\Explorer\\Browser Helper Objects\\*", VerdictAction::Ask, "注册浏览器辅助对象 BHO(可能持久化/劫持)");
    reg(list, "*\\Windows NT\\CurrentVersion\\Drivers32\\*", VerdictAction::Ask, "篡改 Drivers32 多媒体驱动映射(可能持久化)");
}

void addCmdlineEvasionRules(QVector<DefenseRule>& list) {
    // 命令行停安全服务 -> Block
    cmd(list, "*net*stop*windefend*", VerdictAction::Block, "命令行停止 Defender 服务(WinDefend)");
    cmd(list, "*sc*stop*windefend*", VerdictAction::Block, "命令行停止 Defender 服务(sc stop WinDefend)");
    cmd(list, "*sc*config*windefend*start=*disabled*", VerdictAction::Block, "命令行禁用 Defender 服务启动");
    cmd(list, "*net*stop*360*", VerdictAction::Block, "命令行停止 360 服务");
    cmd(list, "*net*stop*huorong*", VerdictAction::Block, "命令行停止火绒服务");
    cmd(list, "*taskkill*/im*MsMpEng*", VerdictAction::Block, "命令行强杀 Defender 引擎(taskkill MsMpEng)");
    cmd(list, "*Set-MpPreference*DisableRealtimeMonitoring*$true*", VerdictAction::Block, "PowerShell 关闭 Defender 实时监控(Set-MpPreference)");
    cmd(list, "*Add-MpPreference*ExclusionPath*", VerdictAction::Ask, "PowerShell 添加 Defender 排除路径(可能免杀)");
    // 命令行擦数据 / 格式化 -> Block
    cmd(list, "*cipher*/w:*", VerdictAction::Block, "命令行擦除磁盘空闲空间(cipher /w,反取证/破坏)");
    cmd(list, "*format*/y*/q*", VerdictAction::Block, "命令行快速格式化磁盘(format /y,破坏)");
    cmd(list, "*fsutil*file*setzerodata*", VerdictAction::Block, "命令行清零文件数据(fsutil,破坏)");
    // 命令行关防火墙 -> Block
    cmd(list, "*netsh*advfirewall*set*allprofiles*state*off*", VerdictAction::Block, "命令行关闭全部防火墙配置(netsh advfirewall off)");
    cmd(list, "*netsh*firewall*set*opmode*disable*", VerdictAction::Block, "命令行关闭防火墙(netsh firewall disable)");
    // UAC 绕过 auto-elevate 程序 -> Ask
    cmd(list, "*fodhelper*", VerdictAction::Ask, "fodhelper 启动(常被用于 UAC 绕过)");
    cmd(list, "*computerdefaults*", VerdictAction::Ask, "computerdefaults 启动(常被用于 UAC 绕过)");
    cmd(list, "*eventvwr*", VerdictAction::Ask, "eventvwr 启动(常被用于 UAC 绕过)");
    cmd(list, "*sdclt*", VerdictAction::Ask, "sdclt 启动(常被用于 UAC 绕过)");
    // UAC 绕过劫持注册表键 -> Block
    reg(list, "*\\Classes\\ms-settings\\shell\\open\\command*", VerdictAction::Block, "劫持 ms-settings 协议命令(fodhelper UAC 绕过)");
    reg(list, "*\\Classes\\exefile\\shell\\open\\command*", VerdictAction::Block, "劫持 exefile 打开命令(UAC 绕过/劫持)");
    reg(list, "*\\Classes\\mscfile\\shell\\open\\command*", VerdictAction::Block, "劫持 mscfile 打开命令(eventvwr UAC 绕过)");
    reg(list, "*\\Classes\\Folder\\shell\\open\\command*", VerdictAction::Block, "劫持 Folder 打开命令(sdclt UAC 绕过)");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

void addNetworkC2Rules(QVector<DefenseRule>& list) {
    auto net = [&](const char* actor, const char* cmdline, bool unsignedOnly, const char* n) {
        DefenseRule r; r.type = EventType::NetworkConnect; r.actorPattern = QLatin1String(actor);
        if (cmdline) r.commandLinePattern = QLatin1String(cmdline);
        r.requireUnsigned = unsignedOnly; r.action = VerdictAction::Ask; r.note = note(n); list.append(r);
    };
    // 脚本解释器外联
    netActor(list, "*\\powershell.exe", "PowerShell 发起网络外联(可能 C2)");
    netActor(list, "*\\pwsh.exe", "PowerShell Core 发起网络外联(可能 C2)");
    net("*\\powershell.exe", "*downloadstring*", false, "PowerShell 下载并执行(高可疑 C2)");
    netActor(list, "*\\mshta.exe", "mshta 发起网络外联(可能 C2)");
    netActor(list, "*\\wscript.exe", "wscript 发起网络外联(可能 C2)");
    netActor(list, "*\\cscript.exe", "cscript 发起网络外联(可能 C2)");
    // LOLBin 下载器
    netActor(list, "*\\rundll32.exe", "rundll32 发起网络外联(可能 C2)");
    netActor(list, "*\\regsvr32.exe", "regsvr32 发起网络外联(可能 C2)");
    netActor(list, "*\\certutil.exe", "certutil 发起网络外联(可能下载器)");
    netActor(list, "*\\bitsadmin.exe", "bitsadmin 发起网络外联(可能下载器)");
    // 从可疑目录运行的未签名程序外联
    net("*\\AppData\\Local\\Temp\\*", nullptr, true, "从 Temp 运行的未签名程序发起外联(疑似 C2)");
    net("*\\Users\\Public\\*", nullptr, true, "从 Public 目录运行的未签名程序发起外联(疑似 C2)");
    net("*\\Downloads\\*", nullptr, true, "从 Downloads 运行的未签名程序发起外联");
    // 开发工具外联
    netActor(list, "*\\devenv.exe", "Visual Studio 发起网络外联(开发工具)");
    netActor(list, "*\\code.exe", "VS Code 发起网络外联(开发工具)");
    netActor(list, "*\\node.exe", "Node.js 发起网络外联(开发工具)");
    netActor(list, "*\\python.exe", "Python 发起网络外联(开发工具)");
    netActor(list, "*\\git.exe", "Git 发起网络外联(版本控制)");
    netActor(list, "*\\docker.exe", "Docker 发起网络外联(容器工具)");
    netActor(list, "*\\npm.exe", "npm 发起网络外联(包管理器)");
    netActor(list, "*\\yarn.exe", "yarn 发起网络外联(包管理器)");
}

}} // namespace bulwark::engine :: anonymous

namespace bulwark::engine { namespace {

// 本机实捕的银狐(SilverFox/ValleyRAT)战役规则:补齐本轮攻击暴露的盲区——BYOVD 驱动改名 .jpg
// 放 \Windows\Temp\ 规避"仅.sys"旧规则、用 WDAC 策略瘫痪安全软件、32 位 svchost 伪装。
// 精确 IOC 哈希 / "图片文件被当模块加载" / "SysWOW64 svchost" = 硬指标 Block;
// WDAC 策略写入用可信 OS 组件豁免,避免误伤 Windows 自身维护。
void addSilverFoxWdacByovdRules(QVector<DefenseRule>& list) {
    // 1) 精确 IOC:本机实捕样本哈希(任意事件类型命中即硬拦,大小写各存一份以防匹配端大小写差异)
    auto hashBlock = [&](const char* sha256, const char* n) {
        DefenseRule r;
        const QString h = QString::fromLatin1(sha256);
        r.actorHashes.insert(h.toUpper());
        r.actorHashes.insert(h.toLower());
        r.action = VerdictAction::Block;
        r.hardOverride = true;
        r.note = note(n);
        list.append(r);
    };
    hashBlock("EB605363DED7B7798921E76BD2421DD8EF8FC9DF14D3C515F23633D91FBDD86E",
              "\xe9\x93\xb6\xe7\x8b\x90 BYOVD:Adlice/TrueSight \xe9\xa9\xb1\xe5\x8a\xa8(\xe6\x9c\xac\xe6\x9c\xba\xe5\xae\x9e\xe6\x8d\x95 ranchserv.jpg,\xe5\x85\xb3\xe6\x9d\x80\xe8\xbd\xaf)");
    hashBlock("62736A42086961DDBCD329CC48E656EEE20ECF518658DB5EA36465F42F210889",
              "\xe9\x93\xb6\xe7\x8b\x90:\xe9\x87\x8a\xe6\x94\xbe\xe5\x99\xa8/\xe8\xbd\xbd\xe8\x8d\xb7(\xe6\x9c\xac\xe6\x9c\xba\xe5\xae\x9e\xe6\x8d\x95 ProgramData \xe9\x9a\x8f\xe6\x9c\xba\xe7\x9b\xae\xe5\xbd\x95 bzSTJXfc.exe)");
    hashBlock("BEF9D2E205BB36349CAF2279C11E0604C4C67D02FF2CEF80696529D26A58461B",
              "\xe9\x93\xb6\xe7\x8b\x90:\xe7\x99\xbd\xe5\x8a\xa0\xe9\xbb\x91\xe4\xbe\xa7\xe8\xbd\xbd\xe6\x81\xb6\xe6\x84\x8f\xe6\xa8\xa1\xe5\x9d\x97 log.dll(\xe6\x9c\xac\xe6\x9c\xba\xe5\xae\x9e\xe6\x8d\x95,hotaj \xe9\xa1\xba\xe7\xbd\x91\xe7\xad\xbe\xe5\x90\x8d\xe5\xae\xbf\xe4\xb8\xbb\xe6\x97\x81)");
    hashBlock("8FA14771A5971D2A14C8F5BB392136C83F22A6B4A5880E2BF910D359AEB2FF80",
              "\xe9\x93\xb6\xe7\x8b\x90:\xe4\xbc\xaa\xe8\xa3\x85 MicrosoftEdgeUpdate \xe7\x9a\x84\xe8\xbd\xbd\xe8\x8d\xb7(\xe6\x9c\xac\xe6\x9c\xba\xe5\xae\x9e\xe6\x8d\x95,Windows Sidebar \xe7\x9b\xae\xe5\xbd\x95)");

    // 2) 图片/数据扩展名的文件被当作模块/驱动加载 = 必恶意(如 ranchserv.jpg 改名规避)。
    static const char* kDisguisedModulePaths[] = {
        "*\\Temp\\*.jpg", "*\\Temp\\*.png", "*\\Temp\\*.gif", "*\\Temp\\*.bmp",
        "*\\Temp\\*.dat", "*\\Temp\\*.tmp", "*\\Temp\\*.log", "*\\Temp\\*.ico",
        "*\\Users\\Public\\*.jpg", "*\\Users\\Public\\*.png", "*\\Users\\Public\\*.dat",
        "*\\ProgramData\\*.jpg", "*\\ProgramData\\*.dat", "*\\AppData\\*.jpg",
    };
    for (const char* p : kDisguisedModulePaths) {
        DefenseRule r; r.type = EventType::ImageLoad; r.targetPattern = QLatin1String(p);
        r.action = VerdictAction::Block; r.hardOverride = true;
        r.note = note("\xe9\x93\xb6\xe7\x8b\x90:\xe5\x8a\xa0\xe8\xbd\xbd\xe4\xbc\xaa\xe8\xa3\x85\xe6\x88\x90\xe5\x9b\xbe\xe7\x89\x87/\xe6\x95\xb0\xe6\x8d\xae\xe6\x96\x87\xe4\xbb\xb6\xe7\x9a\x84\xe5\x8f\xaf\xe6\x89\xa7\xe8\xa1\x8c\xe6\xa8\xa1\xe5\x9d\x97(\xe5\xae\x9e\xe4\xb8\xba PE \xe9\xa9\xb1\xe5\x8a\xa8/DLL,\xe5\xa6\x82 ranchserv.jpg)");
        list.append(r);
    }
    // 从 \Windows\Temp\ 加载内核驱动(.sys)——补齐旧规则仅覆盖 AppData/Public 的盲区。
    ilRule(list, "*\\Windows\\Temp\\*.sys", nullptr, false, VerdictAction::Block,
           "\xe9\x93\xb6\xe7\x8b\x90 BYOVD:\xe4\xbb\x8e Windows\\Temp \xe5\x8a\xa0\xe8\xbd\xbd\xe5\x86\x85\xe6\xa0\xb8\xe9\xa9\xb1\xe5\x8a\xa8(.sys)");

    // 3) 32 位 SysWOW64\svchost.exe 运行 = 必恶意(真 svchost 只在 System32);actorPattern 匹配被创建进程。
    {
        DefenseRule r; r.type = EventType::ProcessCreate;
        r.actorPattern = QStringLiteral("*\\SysWOW64\\svchost.exe");
        r.action = VerdictAction::Block; r.hardOverride = true;
        r.note = note("\xe9\x93\xb6\xe7\x8b\x90:\xe4\xbb\x8e SysWOW64 \xe8\xbf\x90\xe8\xa1\x8c svchost(32 \xe4\xbd\x8d svchost \xe5\xbf\x85\xe4\xb8\xba\xe4\xbc\xaa\xe8\xa3\x85,\xe5\xa6\x82 -k netcssv \xe5\x81\x87\xe6\x9c\x8d\xe5\x8a\xa1\xe7\xbb\x84)");
        list.append(r);
    }

    // 4) 用 WDAC 应用程序控制策略瘫痪安全软件(本轮攻击手法);可信 OS 组件豁免,避免误伤系统维护。
    {
        DefenseRule r; r.type = EventType::FileWrite;
        r.targetPattern = QStringLiteral("*\\CodeIntegrity\\SiPolicy.p7b");
        r.action = VerdictAction::Block; r.exemptTrustedOsComponent = true;
        r.note = note("\xe9\x93\xb6\xe7\x8b\x90:\xe9\x83\xa8\xe7\xbd\xb2 WDAC \xe7\xad\x96\xe7\x95\xa5 SiPolicy.p7b(\xe7\x94\xa8\xe5\xba\x94\xe7\x94\xa8\xe7\xa8\x8b\xe5\xba\x8f\xe6\x8e\xa7\xe5\x88\xb6\xe7\x98\xab\xe7\x97\xaa\xe6\x9d\x80\xe8\xbd\xaf/EDR/\xe6\x9c\xac\xe6\x9c\xba\xe9\x98\xb2\xe6\x8a\xa4)");
        list.append(r);
    }
    {
        DefenseRule r; r.type = EventType::FileWrite;
        r.targetPattern = QStringLiteral("*\\CodeIntegrity\\CiPolicies\\Active\\*");
        r.action = VerdictAction::Block; r.exemptTrustedOsComponent = true;
        r.note = note("\xe9\x93\xb6\xe7\x8b\x90:\xe5\x86\x99\xe5\x85\xa5 WDAC \xe5\xa4\x9a\xe7\xad\x96\xe7\x95\xa5(CiPolicies\\Active,\xe7\x98\xab\xe7\x97\xaa\xe5\xae\x89\xe5\x85\xa8\xe8\xbd\xaf\xe4\xbb\xb6\xe7\x9a\x84\xe5\xba\x94\xe7\x94\xa8\xe7\xa8\x8b\xe5\xba\x8f\xe6\x8e\xa7\xe5\x88\xb6)");
        list.append(r);
    }
    cmd(list, "*CiTool*update-policy*", VerdictAction::Ask,
        "\xe7\x96\x91\xe4\xbc\xbc\xe9\x83\xa8\xe7\xbd\xb2 WDAC \xe7\xad\x96\xe7\x95\xa5(CiTool update-policy,\xe5\x8f\xaf\xe8\x83\xbd\xe7\x98\xab\xe7\x97\xaa\xe5\xae\x89\xe5\x85\xa8\xe8\xbd\xaf\xe4\xbb\xb6)");

    // 5) 伪装系统服务名 + 已知计划任务(本机实捕)。
    reg(list, "*\\Services\\DnsCache SstpSvc*", VerdictAction::Block,
        "\xe9\x93\xb6\xe7\x8b\x90:\xe5\x88\x9b\xe5\xbb\xba\xe4\xbc\xaa\xe8\xa3\x85\xe7\xb3\xbb\xe7\xbb\x9f\xe6\x9c\x8d\xe5\x8a\xa1\xe5\x90\x8d 'DnsCache SstpSvc' \xe7\x9a\x84\xe6\x8c\x81\xe4\xb9\x85\xe5\x8c\x96\xe6\x9c\x8d\xe5\x8a\xa1(\xe6\x9c\xac\xe6\x9c\xba\xe5\xae\x9e\xe6\x8d\x95)");
    reg(list, "*\\Services\\RacMan*", VerdictAction::Block,
        "\xe9\x93\xb6\xe7\x8b\x90:\xe5\x88\x9b\xe5\xbb\xba\xe4\xbc\xaa\xe8\xa3\x85 RasMan \xe7\x9a\x84 'RacMan' \xe6\x8c\x81\xe4\xb9\x85\xe5\x8c\x96\xe6\x9c\x8d\xe5\x8a\xa1(\xe6\x9c\xac\xe6\x9c\xba\xe5\xae\x9e\xe6\x8d\x95,\xe6\x8c\x87\xe5\x90\x91 hotaj)");
    file_(list, "*\\System32\\Tasks\\LDStM", VerdictAction::Block,
          "\xe9\x93\xb6\xe7\x8b\x90:\xe5\x88\x9b\xe5\xbb\xba\xe8\xae\xa1\xe5\x88\x92\xe4\xbb\xbb\xe5\x8a\xa1 \\LDStM(\xe6\x9c\xac\xe6\x9c\xba\xe5\xae\x9e\xe6\x8d\x95,\xe6\x8c\x87\xe5\x90\x91 Public \xe8\xbd\xbd\xe8\x8d\xb7)");
}

}} // namespace bulwark::engine :: anonymous
