#pragma once
//
// ======================== 内置防护规则库 · 编写用 DSL ========================
//
// 仅供 src/engine/rules/ 下各「规则段」源文件使用(内部头,不进 include/)。
// 每个段文件只做一件事:往 QVector<DefenseRule> 里追加一类规则。稳定 id、固定创建时刻、
// 注册表受关注键这些横切逻辑统一在 DefaultRules.cpp 里做,段文件里不要各写一份。
//
// 【写规则前必须知道的事件语义】(与 DriverEventSource / EtwProcessEventSource /
// Worker::enrich 的实际填充一致;写错了不会报错,只会永远不命中):
//
//   ProcessCreate  actorPath = 新进程映像(盘符路径),target 同 actorPath,
//                  commandLine = 新进程命令行,parentPath = 父进程映像。
//                  驱动对 \Windows\System32\、\Program Files\ 等可信目录下的映像【不上报】,
//                  只有内核 LOLBin 名单例外(powershell/pwsh/cmd/wscript/cscript/mshta/
//                  rundll32/regsvr32/certutil/bitsadmin/wmic/vssadmin/bcdedit/wbadmin/
//                  schtasks/at/msbuild/installutil/regsvcs/regasm/mavinject/cmstp/msdt/hh/
//                  forfiles/pcalua/scriptrunner/netsh)。reg.exe / sc.exe / net.exe 这类
//                  不在名单里的系统程序,要么按它落到的注册表/文件维度写,要么按
//                  「cmd /c ... 」「powershell ...」这层外壳的命令行写。
//   其它类型        actorPath = 发起进程映像,commandLine = 发起进程自己的命令行,
//                  parentPath = 发起进程的父进程映像。
//   RegistryWrite  target = 键路径 + "\" + 值名。真实事件是 \REGISTRY\MACHINE\... /
//                  \REGISTRY\USER\<SID>\...,测试语料里是 HKLM\...,所以模式一律以 "*\" 开头,
//                  绝不锚定根键。只有命中受关注键名单的键才会产生事件(见
//                  DefaultRules::registryWatchFragments)。
//   FileWrite      删除/改名全量遥测;普通写入是全局 1/32 采样;ETW 新建文件只覆盖受保护路径
//                  与「用户可写目录里新建可执行体/脚本」。写入类规则只对这几种情形可靠。
//   FileDelete     全量遥测(fire-and-forget)。
//   ImageLoad      用户态模块只上报 \Temp\ 与 \Users\Public\;驱动(.sys)只上报用户可写目录,
//                  此时 actorPath 为「内核(驱动加载)」。
//                  target = 被加载的模块路径。**actorSigned 是宿主(或那个伪串)的签名,不是
//                  模块自己的** —— 要判模块自身签名用 targetUnsignedOnly() / targetSignedOnly()
//                  (Worker::enrich 只对本类型事件富化 targetSigned / targetSignatureMismatch)。
//   RemoteThread / ProcessTerminate   actor = 发起方,target = 受害进程映像。
//   NetworkConnect target = "ip:port"(ETW 只上报非可信签名主体)。
//
// 【三条硬约束】
//   1) Allow 规则必须锚定路径或 requireSigned —— 否则 RuleEngine::isUnsafeAllowRule 拒载。
//   2) ProcessCreate 的 Block 会结束新进程,并把主体映像钉进内核「禁止执行」名单
//      (Worker::enforceBlock -> blacklistExec)。那份名单只有 64 槽、只加不减、由内核写回
//      注册表跨重启续拦、协议上没有「删除单条」—— 下发的代价极不对称,所以必须知道它的护栏
//      到底拦住了什么:
//        · 【是】系统目录护栏:isSweepExemptPath 覆盖 System32 / SysWOW64 / WinSxS 与本产品
//          目录(按真实路径前缀)。所以按命令行判的规则命中 cmd.exe / powershell.exe /
//          netsh.exe / sc.exe 这类「拦用法不拦文件」的情形时,只结束进程、不下发。
//        · 【不是】签名护栏。blacklistExec 里【没有任何签名判断】(只有「已加白」、
//          「系统目录/本产品目录」、「去盘符后子串 >= 6 字符」三道闸)。
//      这个区别会直接吃掉一个人:别写「只按 commandLinePattern 匹配的 ProcessCreate Block
//      规则」去拦某个框架/库的用法 —— 那类命令行的主体通常是 python.exe / node.exe /
//      pip.exe,它们【不在】System32 下,于是会被按完整路径永久禁运,整台机器再也起不了
//      Python。真要覆盖这类判据,改用 FileWrite(拦落地)或交给启发式打分,别用
//      ProcessCreate + Block。段 7.6b 的「不写命令行维度」就是按这一条决定的。
//   3) 【Ask 规则一定要写窄】。这一条原先写的是「内置规则只加强、不削弱……Ask 可以放心写宽」,
//      与代码实际行为不符,照着写会造成漏防,故据实改写:
//        · RuleEngine 步骤 6 里【没有】任何按 builtInTag() 区分内置规则的逻辑。命中即
//          `return Verdict::forEvent(e, hit.action, ...)`,直接跳过步骤 10 的启发式处置 ——
//          所以一条宽 Ask 规则会把 riskScore 95 + 硬指标的事件降级成「询问」。
//        · 步骤 6 还有 `if (hit.action == Ask && DefaultRules::isDevTool(e.actorPath))
//          -> Allow`,而 isDevTool 是【纯文件名】匹配,名单里有 setup.exe / installer.exe /
//          node.exe / python.exe / agent.exe / runner.exe。样本改名成 setup.exe 即可让所有
//          Ask 规则失效。
//      结论:Ask 只用在「正常软件确实也会做这件事」的地方(此时被 devTool 放行不算损失);
//      凡是改名即可规避会造成实质漏防的判据,一律 Block。
//
// 备注里写 ATT&CK 编号(如 T1547.001):AttackAnnotator 会从命中证据里抽出来打技战术标签。
//
#include <QString>
#include <QVector>
#include "bulwark/models/DefenseRule.h"

namespace bulwark::engine::rules {

using bulwark::DefenseRule;
using bulwark::EventType;
using bulwark::VerdictAction;

inline constexpr VerdictAction Allow = VerdictAction::Allow;
inline constexpr VerdictAction Ask   = VerdictAction::Ask;
inline constexpr VerdictAction Block = VerdictAction::Block;

// 链式修饰器。持有容器内元素的指针,只能在同一条构造表达式里使用
// (下一次 add 可能让容器扩容,旧指针随之失效)。
class RuleRef {
public:
    explicit RuleRef(DefenseRule& r) : r_(&r) {}

    RuleRef& actor(const char* pattern)  { r_->actorPattern = QString::fromUtf8(pattern); return *this; }
    RuleRef& target(const char* pattern) { r_->targetPattern = QString::fromUtf8(pattern); return *this; }
    RuleRef& cmd(const char* pattern)    { r_->commandLinePattern = QString::fromUtf8(pattern); return *this; }
    RuleRef& parent(const char* pattern) { r_->parentPattern = QString::fromUtf8(pattern); return *this; }

    // QString 重载:供「按名单交叉展开」的规则组使用(父进程 x 脚本宿主、安全软件进程名 x
    // 动词……)。字面量仍走上面的 const char* 重载 —— 数组到指针是精确匹配,优于 QString 需要的
    // 用户定义转换,故不存在歧义。
    RuleRef& actor(const QString& pattern)  { r_->actorPattern = pattern; return *this; }
    RuleRef& target(const QString& pattern) { r_->targetPattern = pattern; return *this; }
    RuleRef& cmd(const QString& pattern)    { r_->commandLinePattern = pattern; return *this; }
    RuleRef& parent(const QString& pattern) { r_->parentPattern = pattern; return *this; }

    // 【主体】签名条件:读 SecurityEvent::actorSigned,也就是发起方。
    RuleRef& unsignedOnly()              { r_->requireUnsigned = true; return *this; }
    RuleRef& signedOnly()                { r_->requireSigned = true; return *this; }
    // 【目标文件自身】签名条件:读 targetSigned / targetSignatureMismatch。
    // 只有 ImageLoad 事件会被富化出这两个字段(见下方事件语义表),别用在其它类型上。
    RuleRef& targetUnsignedOnly()        { r_->requireTargetUnsigned = true; return *this; }
    RuleRef& targetSignedOnly()          { r_->requireTargetSigned = true; return *this; }
    RuleRef& exemptOs()                  { r_->exemptTrustedOsComponent = true; return *this; }
    RuleRef& hard()                      { r_->hardOverride = true; return *this; }

private:
    DefenseRule* r_;
};

// 一个规则段。备注统一生成为 "[内置] <分类> · <说明>"。
class Segment {
public:
    Segment(QVector<DefenseRule>& out, const char* category);

    RuleRef add(EventType type, VerdictAction action, const char* note);
    // QString 重载。备注【必须逐条不同】:DefaultRules::build() 末尾按「备注 + 全部匹配条件」
    // 派生 UUIDv5,撞 id 会让后者静默顶掉前者(检测能力凭空消失),builtin_ruleset_ids 会红。
    // 按名单展开的规则组因此要把区分词(进程名 / 目录名 / 值名)拼进备注。
    RuleRef add(EventType type, VerdictAction action, const QString& note);

    RuleRef proc(VerdictAction a, const char* n)   { return add(EventType::ProcessCreate, a, n); }
    RuleRef reg(VerdictAction a, const char* n)    { return add(EventType::RegistryWrite, a, n); }
    RuleRef file(VerdictAction a, const char* n)   { return add(EventType::FileWrite, a, n); }
    RuleRef del(VerdictAction a, const char* n)    { return add(EventType::FileDelete, a, n); }
    RuleRef image(VerdictAction a, const char* n)  { return add(EventType::ImageLoad, a, n); }
    RuleRef thread(VerdictAction a, const char* n) { return add(EventType::RemoteThread, a, n); }
    RuleRef kill(VerdictAction a, const char* n)   { return add(EventType::ProcessTerminate, a, n); }
    RuleRef net(VerdictAction a, const char* n)    { return add(EventType::NetworkConnect, a, n); }
    RuleRef dns(VerdictAction a, const char* n)    { return add(EventType::DnsQuery, a, n); }

    RuleRef proc(VerdictAction a, const QString& n)   { return add(EventType::ProcessCreate, a, n); }
    RuleRef reg(VerdictAction a, const QString& n)    { return add(EventType::RegistryWrite, a, n); }
    RuleRef file(VerdictAction a, const QString& n)   { return add(EventType::FileWrite, a, n); }
    RuleRef del(VerdictAction a, const QString& n)    { return add(EventType::FileDelete, a, n); }
    RuleRef image(VerdictAction a, const QString& n)  { return add(EventType::ImageLoad, a, n); }
    RuleRef thread(VerdictAction a, const QString& n) { return add(EventType::RemoteThread, a, n); }
    RuleRef kill(VerdictAction a, const QString& n)   { return add(EventType::ProcessTerminate, a, n); }
    RuleRef net(VerdictAction a, const QString& n)    { return add(EventType::NetworkConnect, a, n); }
    RuleRef dns(VerdictAction a, const QString& n)    { return add(EventType::DnsQuery, a, n); }

private:
    QVector<DefenseRule>& out_;
    QString prefix_;
};

// ---- 段文件共用的名单(定义在 RulesCommon.cpp)----
//
// 这些名单被多个段交叉引用(脚本宿主既是段 2 的「谁在写 Run 键」,也是段 7 的「谁在注入」),
// 各段各抄一份必然会漂移,故集中一处。
const QStringList& scriptHostActors();      // 脚本宿主/LOLBin 主体通配 "*\powershell.exe" ...
const QStringList& dropDirFragments();      // 投递型可写目录片段 "\appdata\local\temp\" ...
const QStringList& securityImageNames();    // 安全软件映像名(不含通配) "msmpeng.exe" ...
// 从 "*\xxx.exe" 形态的通配里取出映像名,用于拼唯一备注。
QString imageNameOf(const QString& pattern);

// ---- 各规则段(每段一个源文件,build() 按下列顺序拼接)----
void addSystemMaintenanceRules(QVector<DefenseRule>& out);   // 段 1 Rules01_SystemMaintenance.cpp
void addPersistenceRules(QVector<DefenseRule>& out);         // 段 2 Rules02_Persistence.cpp
void addDefenseEvasionRules(QVector<DefenseRule>& out);      // 段 3 Rules03_DefenseEvasion.cpp
void addCredentialAccessRules(QVector<DefenseRule>& out);    // 段 4 Rules04_CredentialAccess.cpp
void addImpactRules(QVector<DefenseRule>& out);              // 段 5 Rules05_Impact.cpp
void addExecutionRules(QVector<DefenseRule>& out);           // 段 6 Rules06_Execution.cpp
void addInjectionRules(QVector<DefenseRule>& out);           // 段 7 Rules07_Injection.cpp
void addLateralAndC2Rules(QVector<DefenseRule>& out);        // 段 8 Rules08_LateralC2.cpp

} // namespace bulwark::engine::rules
