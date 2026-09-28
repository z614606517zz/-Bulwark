#include "bulwark/engine/RuleEngine.h"
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/engine/DgaDomainAnalyzer.h"
#include "bulwark/engine/AttackAnnotator.h"
#include "bulwark/engine/DefaultRules.h"
#include <QStringList>
#include <algorithm>

namespace bulwark::engine {

using detail::u;
using detail::fileNameLower;

namespace {
// 本软件自身组件进程映像名(小写)。须与 CMake 构建产物名(下划线)一致——早期沿用
// .NET 程序集名(点号 bulwark.service.exe)导致永不匹配真实的 bulwark_service.exe。
//
// 【这份名单【只能】与安装目录前缀合取使用,绝不可单独判定】
//
// 原实现里 matchesSelf 先查这份名单,命中就直接 return true,而注释写的是「按名匹配可被
// 同名程序冒用,故仅作快速通道,真正的稳妥判定靠安装目录前缀」—— 但代码里它就是终局判据,
// 没有第二道。后果:把样本命名成 bulwark_ui.exe 放到任意目录(如 %TEMP%),它在
// evaluateInternal 的第 ① 步就拿到「本软件自身组件,无条件放行」,跳过全部检测,连勒索蜜罐
// 和硬指标都不处置。这是整条管线上最短的一条绕过路径。
//
// 现在名字只用来【剪掉绝大多数无关路径】(避免对每个事件都去遍历目录集合),命中之后仍必须
// 通过目录前缀。见 matchesSelf。
const QSet<QString>& selfImageNames() {
    static const QSet<QString> s = {
        "bulwark_service.exe", "bulwark_ui.exe",
    };
    return s;
}

// 按 Windows 命令行规则把命令行切成 argv:双引号内的空白不断词,"" 表示一个字面引号。
//
// 为什么维护脚本通道【必须】按词比对而不是按子串:contains() 判定只要求那几个字样
// 在命令行里【出现过】,不要求它们真的是被执行的东西。于是
//     powershell.exe -enc <base64 载荷>  # C:\Program Files\Bulwark\bulwark.ps1
// 就同时满足「命令行里有安装目录」「命令行里有 bulwark.ps1」两条,拿到一次
// 【规则匹配之前】的无条件放行 —— 写 Block 规则也盖不住。注释原本说这条通道的强度
// 来自内核 SelfGuard 对安装目录的写保护,但 SelfGuard 保护的是文件内容,管不了
// 命令行文本,所以那份强度对这个判定不成立。
QStringList tokenizeCommandLine(const QString& cmd) {
    QStringList out;
    QString cur;
    bool inQuotes = false;
    bool started = false;   // 空词也要能产出(如 "" ),故单独记「本词已开始」
    for (int i = 0; i < cmd.size(); ++i) {
        const QChar c = cmd.at(i);
        if (c == QLatin1Char('"')) {
            if (inQuotes && i + 1 < cmd.size() && cmd.at(i + 1) == QLatin1Char('"')) {
                cur += QLatin1Char('"');
                ++i;
            } else {
                inQuotes = !inQuotes;
            }
            started = true;
            continue;
        }
        if (!inQuotes && c.isSpace()) {
            if (started) { out << cur; cur.clear(); started = false; }
            continue;
        }
        cur += c;
        started = true;
    }
    if (started) out << cur;
    return out;
}

QString normalizePathToken(const QString& token) {
    QString t = token.trimmed().toLower();
    t.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return t;
}

// 能让解释器执行【行内代码】的开关。命中任何一个就不是「执行安装目录里的脚本」,
// 一律不给这条通道。用精确词表而不是前缀匹配:合法调用里有 -ExecutionPolicy,
// 若按 "-e" 前缀去拒就会把正常的维护调用一起拒掉。
bool isInlineCodeSwitch(const QString& tokenLower) {
    static const QSet<QString> s = {
        QStringLiteral("-command"),   QStringLiteral("/command"),
        QStringLiteral("-c"),         QStringLiteral("/c:"),
        QStringLiteral("-encodedcommand"), QStringLiteral("-encoded"),
        QStringLiteral("-enc"),       QStringLiteral("-e"),
        QStringLiteral("-ec"),        QStringLiteral("-encodedarguments"),
    };
    return s.contains(tokenLower);
}

// 可能把第二条命令串进去的元字符。-File 之后 PowerShell 不解释它们,但这条通道的
// 代价太高,宁可严一点。
bool hasCommandChaining(const QString& token) {
    static const char* kBad[] = { ";", "&", "|", "`", "$(", "%0a", "\n", "\r" };
    for (const char* b : kBad)
        if (token.contains(QLatin1String(b))) return true;
    return false;
}
} // namespace

void RuleEngine::addSelfDirectory(const QString& dir) {
    if (dir.trimmed().isEmpty()) return;
    QString norm = dir.trimmed().toLower();
    norm.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!norm.endsWith(QLatin1Char('\\'))) norm += QLatin1Char('\\');
    QMutexLocker locker(&selfDirLock_);
    selfDirectories_.insert(norm);
}

bool RuleEngine::matchesSelf(const QString& path) const {
    if (path.isEmpty()) return false;

    //
    // 判据 = 「映像名在自身组件名单里」【且】「路径落在已登记的安装目录下」。
    //
    // 两个条件必须【合取】。原实现是析取(名字命中即 return true),于是 %TEMP%\bulwark_ui.exe
    // 就获得了无条件放行 —— 见 selfImageNames() 上方的说明。
    //
    // 目录集合为空(服务尚未调用 addSelfDirectory)时一律返回 false,不猜:宁可让自身组件走一遍
    // 正常检测(它们带健康签名,会被后面的信任层放行),也不能在还不知道安装目录的时候按名字发
    // 通行证。
    //
    const QString name = fileNameLower(path);
    if (name.isEmpty() || !selfImageNames().contains(name)) return false;

    QMutexLocker locker(&selfDirLock_);
    if (selfDirectories_.isEmpty()) return false;
    QString pathLower = path.toLower();
    pathLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    for (const QString& d : selfDirectories_)
        if (pathLower.startsWith(d)) return true;
    return false;
}

bool RuleEngine::isSelfComponent(const SecurityEvent& e) const {
    return matchesSelf(e.actorPath) || matchesSelf(e.parentPath);
}

bool RuleEngine::isSanctionedMaintenanceActor(const SecurityEvent& e) const {
    // 三个条件必须【同时】成立,少任何一个都不放行。
    //
    // 1) 发起者是系统自带解释器,且映像位于 %SystemRoot% 下。
    //    只比文件名会被「把自己命名为 powershell.exe 放到别处」冒用,所以要求路径前缀。
    const QString actorName = fileNameLower(e.actorPath);
    if (actorName != QLatin1String("powershell.exe") && actorName != QLatin1String("cmd.exe"))
        return false;
    QString actorLower = e.actorPath.toLower();
    actorLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    QString sysRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows")).toLower();
    sysRoot.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!sysRoot.endsWith(QLatin1Char('\\'))) sysRoot += QLatin1Char('\\');
    if (!actorLower.startsWith(sysRoot)) return false;

    // 2) + 3) 命令行必须【真的在执行】安装目录内的我方脚本。
    //
    //    按词解析,不按子串包含(理由见 tokenizeCommandLine 的说明:子串包含可被一句
    //    注释伪造出无条件放行)。要同时满足:
    //      · 存在一个词是【绝对路径】,前缀落在已登记的安装目录内,文件名在脚本白名单里;
    //      · 该词的前一个词是 -File(PowerShell 唯一的「执行脚本文件」入口,可缩写),
    //        也就是这个路径确实处在被执行的位置上,而不是出现在注释/参数/无关文本里;
    //      · 没有任何词是行内代码开关(-Command / -EncodedCommand / -enc ...);
    //      · 没有任何词带命令串接元字符。
    //
    //    目录前缀这一条的强度来自内核 SelfGuard:安装目录「仅放行本产品自身进程写入,
    //    其余进程写/删/改名一律拒绝」,所以攻击者没法把自己的脚本放进去,也没法替换
    //    bulwark.ps1。注意这份强度只覆盖「脚本文件的内容」,所以上面必须先把「该路径
    //    确实被当作脚本执行」这件事验证掉,才轮得到它。
    const QString cmd = e.commandLine;
    if (cmd.isEmpty()) return false;

    QSet<QString> selfDirs;
    {
        QMutexLocker locker(&selfDirLock_);
        if (selfDirectories_.isEmpty()) return false;   // 目录还没登记时不猜,直接不放行
        selfDirs = selfDirectories_;
    }

    static const QSet<QString> kScripts = { QStringLiteral("bulwark.ps1") };

    const QStringList tokens = tokenizeCommandLine(cmd);
    if (tokens.size() < 2) return false;

    bool sanctioned = false;
    for (int i = 0; i < tokens.size(); ++i) {
        const QString tokenLower = tokens.at(i).toLower();
        if (isInlineCodeSwitch(tokenLower)) return false;
        if (hasCommandChaining(tokens.at(i))) return false;

        const QString norm = normalizePathToken(tokens.at(i));
        const int slash = norm.lastIndexOf(QLatin1Char('\\'));
        if (slash < 0) continue;                        // 不是路径形态的词
        if (!kScripts.contains(norm.mid(slash + 1))) continue;

        // -File 必须紧邻在前(PowerShell 允许参数名缩写,故按前缀认 -f/-fi/-fil/-file)。
        if (i == 0) continue;
        const QString prev = tokens.at(i - 1).toLower();
        if (!prev.startsWith(QLatin1Char('-')) || prev.size() < 2
            || !QStringLiteral("-file").startsWith(prev)) {
            continue;
        }

        bool underSelfDir = false;
        for (const QString& d : selfDirs)
            if (norm.startsWith(d)) { underSelfDir = true; break; }
        if (underSelfDir)
            sanctioned = true;                          // 继续扫完,确保后面没有行内代码开关
    }
    return sanctioned;
}

std::optional<QString> RuleEngine::trustNoteForPath(const QString& path) const {
    QString p = path.trimmed();
    if (p.isEmpty()) return std::nullopt;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));

    // 占位符路径:内核源在解析不出映像时会填 "PID 1234"(见 Worker::blacklistExec 的同名护栏)。
    // 这种事件无法判定主体身份 —— 宁可不豁免,绝不能因为一个占位符把真实的恶意处置放过去。
    if (p.startsWith(QLatin1String("PID "), Qt::CaseInsensitive)) return std::nullopt;

    // 本软件自身组件:任何情况下都不该被自己的内核名单钉死(否则一次误判即自锁,且跨重启)。
    if (matchesSelf(p)) return QStringLiteral("本软件自身组件");

    const QDateTime now = nowUtc();
    QReadLocker locker(&rulesLock_);
    // 只扫信任项索引:候选集与原先「全表扫 + 过滤 Allow/enabled/未过期/isTrustEntry」完全一致
    // (索引按 action==Allow && isTrustEntry() 建立,enabled / 到期仍在下面逐条判)。
    for (const DefenseRule& r : trustEntries_) {
        if (!r.enabled || r.isExpired(now))
            continue;
        // 文件信任 = actorPath 精确(大小写不敏感);目录信任 = actorPattern 通配("<目录>\*")。
        const bool hitFile = !r.actorPath.isEmpty() && r.actorPath.compare(p, Qt::CaseInsensitive) == 0;
        const bool hitDir  = !r.actorPattern.isEmpty() && DefenseRule::wildcardMatch(r.actorPattern, p);
        if (hitFile || hitDir)
            return r.note.isEmpty() ? QStringLiteral("用户信任") : r.note;
    }
    return std::nullopt;
}

std::optional<QString> RuleEngine::matchedUserTrust(const SecurityEvent& e) const {
    QReadLocker locker(&rulesLock_);
    // 同上,只扫信任项索引。顺带把一处既有的不确定性收掉:原先遍历的是 QHash,而 Qt6 的
    // QHash 每进程随机化种子 —— 多条信任项同时命中时,返回【哪一条的备注】每次重启都可能变。
    // 索引是按 rules_ 装载顺序建立的 QVector,同一份规则集下顺序稳定。命中与否不受影响(只要
    // 有任一信任项命中就放行,这一点两种写法一致),变的只是提示语里显示哪一条备注。
    for (const DefenseRule& r : trustEntries_) {
        // 仅「文件信任中心」生成的 Allow 信任项(文件精确 actorPath 或目录通配 actorPattern)。
        if (r.matches(e))
            return r.note.isEmpty() ? QStringLiteral("用户信任") : r.note;
    }
    return std::nullopt;
}

int RuleEngine::ruleTier(const DefenseRule& r) {
    const bool exactActor = !r.actorPath.isEmpty() || !r.actorHashes.isEmpty();
    if (exactActor) return 2;
    if (r.hardOverride) return 1;
    return 0;
}

int RuleEngine::rulePriority(VerdictAction a) {
    switch (a) {
        case VerdictAction::Block: return 2;
        case VerdictAction::Ask:   return 1;
        default:                   return 0;
    }
}

// ---------------------- 规则索引维护(见头文件里的等价性说明)----------------------

void RuleEngine::rebuildIndexLocked() {
    byType_.clear();
    typeAgnostic_.clear();
    trustEntries_.clear();
    // 按 rules_ 的迭代序重建。桶内顺序不影响裁决(步骤 6 的比较器是全序),这里只需要保证
    // 「同一份规则集重建两次得到同样的桶内容」,而内容与顺序无关的部分由 sort 兜住。
    for (auto it = rules_.constBegin(); it != rules_.constEnd(); ++it) {
        const DefenseRule& r = it.value();
        if (r.type.has_value())
            byType_[static_cast<int>(*r.type)].append(r);
        else
            typeAgnostic_.append(r);
        if (r.action == VerdictAction::Allow && r.isTrustEntry())
            trustEntries_.append(r);
    }
}

void RuleEngine::indexInsertLocked(const DefenseRule& r) {
    if (r.type.has_value())
        byType_[static_cast<int>(*r.type)].append(r);
    else
        typeAgnostic_.append(r);
    if (r.action == VerdictAction::Allow && r.isTrustEntry())
        trustEntries_.append(r);
}

const QVector<DefenseRule>& RuleEngine::bucketForLocked(EventType t) const {
    static const QVector<DefenseRule> kEmpty;
    const auto it = byType_.constFind(static_cast<int>(t));
    return it == byType_.constEnd() ? kEmpty : it.value();
}

//
// ===================== Allow 规则的准入校验(防复发护栏)=====================
//
// 【为什么必须是代码里的一道闸,而不是「注意别这么写」】
//
// 规则集里曾经有一大批 Allow 规则的 actorPattern 只写了文件名,例如 "*\svchost.exe"。
// DefenseRule::wildcardMatch 是纯通配,'*' 吃掉任意前缀,所以这类规则的真实语义是
// 【任何位置、任何一个同名程序】—— 把样本改名成 svchost.exe 丢进 Temp,它的全部文件写入
// 与注册表写入就都被无条件放行了。而且它还会赢:ruleTier 给它 0,但
// specificity = actorPattern(2) + type(1) = 3,高于「写 Run 键 -> Ask」那条(=2)。
//
// 这种错误的特点是【写起来自然、读起来无害、后果隐蔽】:它不会让任何测试失败,只会让某一类
// 样本静默通过。所以靠 review 守不住,必须在加载时机械地拒掉。
//
// 判据(精确,不过度):action == Allow 且 actorPattern 形如「'*' 或 '*\' 之后只剩一个文件名」
// 且【没有】requireSigned 兜底 —— 也就是既不限定位置、也不限定签名。命中即拒绝该规则并记日志。
//   "*\svchost.exe"                     -> 拒绝(不限位置、不限签名)
//   "*\chrome.exe" + requireSigned      -> 放行(冒名者拿不到厂商签名)
//   "?:\Windows\System32\svchost.exe"   -> 放行(位置锚定)
//   "*\Google\Update\*"                 -> 放行(不是「只剩一个文件名」)
// Block / Ask 规则不受此限:它们过宽只会带来更多审查,不会造成放行。
//
static bool isFilenameOnlyActorPattern(const QString& pattern) {
    if (pattern.isEmpty()) return false;
    // 取最后一个路径分隔符之后的部分;之前的部分必须只由通配构成才算「不限定位置」。
    const int slash = pattern.lastIndexOf(QLatin1Char('\\'));
    const QString head = slash < 0 ? QString() : pattern.left(slash);
    const QString tail = slash < 0 ? pattern : pattern.mid(slash + 1);
    // 头部只允许是空、"*" 这两种(其余形式说明写了真实目录成分)。
    if (!(head.isEmpty() || head == QStringLiteral("*"))) return false;
    // 尾部必须是一个具体文件名:非空、不含通配。含 '*' 的尾部(如 "*") 属于「放行整个目录」,
    // 那是另一类问题,不在本护栏判据内。
    if (tail.isEmpty() || tail.contains(QLatin1Char('*')) || tail.contains(QLatin1Char('?')))
        return false;
    return true;
}

bool RuleEngine::isUnsafeAllowRule(const DefenseRule& r, QString* whyOut) {
    if (r.action != VerdictAction::Allow) return false;
    if (r.requireUnsigned && r.requireSigned) {
        if (whyOut) *whyOut = u("同时要求已签名与未签名,永不命中(配置矛盾)");
        return true;
    }
    // 哈希精确匹配已经把主体钉死到具体文件内容,不受改名影响,无需再限定位置或签名。
    if (!r.actorHashes.isEmpty()) return false;
    // actorPath 是精确全路径匹配,同样已限定位置。
    if (!r.actorPath.isEmpty()) return false;
    if (r.requireSigned) return false;
    if (isFilenameOnlyActorPattern(r.actorPattern)) {
        if (whyOut)
            *whyOut = u("Allow 规则的主体通配只写了文件名(") + r.actorPattern +
                      u("),等于放行任何位置的同名程序;请锚定路径或加 requireSigned");
        return true;
    }
    return false;
}

void RuleEngine::loadRules(const QVector<DefenseRule>& rules) {
    QHash<QUuid, DefenseRule> fresh;
    int rejected = 0;
    for (const DefenseRule& r : rules) {
        QString why;
        if (isUnsafeAllowRule(r, &why)) {
            ++rejected;
            qWarning("[RuleEngine] 拒绝加载不安全的 Allow 规则:%s | note=%s",
                     qUtf8Printable(why), qUtf8Printable(r.note));
            continue;
        }
        fresh.insert(r.id, r);
    }
    if (rejected > 0)
        qWarning("[RuleEngine] 共拒绝 %d 条不安全的 Allow 规则(见上方逐条说明)。", rejected);
    QWriteLocker locker(&rulesLock_);
    rules_ = std::move(fresh);
    rebuildIndexLocked();
}

QVector<DefenseRule> RuleEngine::getRules() const {
    const QDateTime now = nowUtc();
    QReadLocker locker(&rulesLock_);
    QVector<DefenseRule> out;
    out.reserve(rules_.size());
    for (auto it = rules_.constBegin(); it != rules_.constEnd(); ++it)
        if (!it.value().isExpired(now)) out.append(it.value());
    return out;
}

int RuleEngine::pruneExpired() {
    const QDateTime now = nowUtc();
    QWriteLocker locker(&rulesLock_);
    int removed = 0;
    for (auto it = rules_.begin(); it != rules_.end(); ) {
        if (it.value().isExpired(now)) { it = rules_.erase(it); ++removed; }
        else ++it;
    }
    if (removed > 0) rebuildIndexLocked();
    return removed;
}

void RuleEngine::addRule(const DefenseRule& rule) {
    // 同一道护栏也要覆盖【单条新增】:规则不只从内置集合来,还从 UI 的「添加规则」、
    // 情报行为规则注入、以及更新包下发进来。只在 loadRules 里拦等于只拦住了内置那一条路。
    // 用户「记住我的选择」产生的规则带精确 actorPath,不受影响(见 createRuleFrom)。
    {
        QString why;
        if (isUnsafeAllowRule(rule, &why)) {
            qWarning("[RuleEngine] 拒绝新增不安全的 Allow 规则:%s | note=%s",
                     qUtf8Printable(why), qUtf8Printable(rule.note));
            return;
        }
    }
    QWriteLocker locker(&rulesLock_);
    // 覆盖同 id 的旧规则时不能只往索引里追加,否则桶里会同时留着新旧两份 ——
    // 两者 id 相同,排序比较器分不出高下,胜出者变回不确定。这种情况整体重建。
    const bool replacing = rules_.contains(rule.id);
    rules_.insert(rule.id, rule);
    if (replacing) rebuildIndexLocked();
    else indexInsertLocked(rule);
}

bool RuleEngine::removeRule(const QUuid& id) {
    QWriteLocker locker(&rulesLock_);
    const bool removed = static_cast<bool>(rules_.remove(id));
    if (removed) rebuildIndexLocked();
    return removed;
}

void RuleEngine::appendDecisionEvidence(SecurityEvent& e, const Verdict& v) {
    QString action;
    switch (v.action) {
        case VerdictAction::Block: action = u("阻止"); break;
        case VerdictAction::Ask:   action = u("询问用户"); break;
        default:                   action = u("放行"); break;
    }
    QString source;
    switch (v.source) {
        case VerdictSource::Rule:          source = u("命中规则"); break;
        case VerdictSource::Heuristic:     source = u("行为研判"); break;
        case VerdictSource::TrustedSigner: source = u("可信放行"); break;
        case VerdictSource::UserPrompt:    source = u("用户裁决"); break;
        case VerdictSource::Timeout:       source = u("超时按默认策略"); break;
        default:                           source = u("默认策略"); break;
    }
    e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Decision,
        u("最终裁决:") + action + u("(依据:") + source + u(";风险分 ") +
        QString::number(e.riskScore) + u(")"), 0, false);
}

Verdict RuleEngine::evaluate(SecurityEvent& e) {
    const Verdict verdict = evaluateInternal(e);
    appendDecisionEvidence(e, verdict);
    AttackAnnotator::annotate(e);
    return verdict;
}

DefenseRule RuleEngine::createRuleFrom(SecurityEvent& e, VerdictAction action,
                                       std::optional<QDateTime> expiresUtc, bool sessionOnly) {
    DefenseRule rule;
    rule.actorPath = e.actorPath;
    rule.type = e.type;
    rule.targetPattern = e.target.isEmpty() ? QString() : e.target;
    rule.action = action;
    rule.expiresUtc = expiresUtc;
    rule.sessionOnly = sessionOnly;
    addRule(rule);
    return rule;
}

Verdict RuleEngine::evaluateInternal(SecurityEvent& e) {
    // 1) 无条件放行通道(放在最前,早于威胁检测与勒索/信标等时序早退):
    //    a. 本软件自身组件;b. 用户明确信任的文件/文件夹。用户信任即「完全跳过一切检测」——
    //    即便命中勒索蜜罐/硬指标也不处置,因为这是用户明确的白名单选择。
    if (isSelfComponent(e)) {
        e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Trust, u("本软件自身组件,无条件放行"), 0, false);
        return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
    }
    // a2) 本产品自己的维护脚本(安装 / 卸载 / 更新 / 收集日志)。
    //     发起者是 cmd.exe / powershell.exe,所以上面那条按映像判定的自身组件通道认不出它,
    //     而这些脚本必然要开测试签名(bcdedit)并以 -ExecutionPolicy Bypass 运行 ——
    //     那正是攻击链检测里「破坏影响 + 防御规避」的最强组合。不认这一类的后果是本产品
    //     把自己的脚本判成勒索软件并内核封禁,实测发生过(收集日志.bat,riskScore 100)。
    //
    //     ⚠ 这是一条【规则匹配之前】的无条件放行通道,写 Block 规则盖不住它 ——
    //     与自身组件、用户信任同级。所以它的三个前置条件一个都不能松:见
    //     isSanctionedMaintenanceActor() 的说明,其强度最终来自内核 SelfGuard 对安装目录
    //     的写保护(攻击者无法把脚本放进去或替换掉 bulwark.ps1)。
    if (isSanctionedMaintenanceActor(e)) {
        e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Trust,
                      u("本软件自身的维护脚本(安装目录内),无条件放行"), 0, false);
        return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
    }
    if (const std::optional<QString> trustNote = matchedUserTrust(e)) {
        e.userTrusted = true; // 通知 Worker 跳过全部后台扫描(VT/IP/AI)
        e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Trust,
                      u("用户信任放行,已跳过全部检测:") + *trustNote, 0, false);
        return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::Rule);
    }

    // 2) 已安装的知名安全软件:共存放行
    {
        const TrustDecision sec = TrustPolicy::isTrustedSecurityProduct(e);
        if (sec.ok) {
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, sec.reason, 0, false);
            return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
        }
    }

    // 2b) 已知良性厂商应用(QQ/微信/企业微信/TIM 等即时通讯):正常存在大量周期性心跳保活外联,
    //     极易被信标检测 / 微步 IP 情报 / ThreatFox IP 规则误判为 C2 回连而被结束进程。要求持有
    //     健康的厂商签名(防同名冒充)后,对【外联与 DNS 事件】在时序检测与规则匹配之前放行,并置
    //     userTrusted 让 Worker 跳过该事件的后台情报查询,避免正常保活被情报链路误伤。
    //
    //     【作用域必须锁死在网络维度】此前这里对【全部事件类型】早返回 Allow,后果是这五个映像名
    //     一旦签名健康,它们作为主体的任何行为都不再经过 ThreatDetector、也不再匹配规则 —— 于是
    //     专门为「银狐」IM 群控加的那批规则(wxhook / WeChatSDK / vchat 等具名 hook 模块【被加载】、
    //     向 IM 安装目录植入接口 DLL)全部失效,DLL 侧载检测(可写目录加载未签名模块)同样失效:
    //     攻击者只要把合法签名的 WeChat.exe 连同恶意 DLL 一起投递,主体就是「签名健康的微信」。
    //     误报本来只出在「周期性外联被判 C2」这一处,不该用全维度豁免去换。
    //
    //     残留风险(已知、有意保留):这类主体的外联本身仍被放行,故被侧载的 IM 宿主可以维持 C2
    //     通道。要收掉这一条需要模块级(而非进程级)的外联归因,不在本次改动范围内;但投递阶段的
    //     落地、加载、注入、持久化现在都会被正常检测到。
    if (e.type == EventType::NetworkConnect || e.type == EventType::DnsQuery) {
        const TrustDecision app = TrustPolicy::isTrustedVendorApp(e);
        if (app.ok) {
            e.userTrusted = true; // 仅跳过本条外联/DNS 事件的后台情报查询(微步 IP / 哈希信誉)
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust,
                          app.reason + u("(仅外联/DNS 维度)"), 0, false);
            return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
        }
    }

    // 3) 威胁检测,填充 RiskScore / 硬指标
    ThreatDetector::analyze(e);

    // 4) 有状态时序检测:勒索批量改写 / C2 信标 / 外联速率
    if (e.type == EventType::FileWrite || e.type == EventType::FileDelete) {
        const RansomwareBehaviorMonitor::Result rm = ransomware_.observe(e);
        if (rm.score > 0) {
            e.riskScore = qMin(100, e.riskScore + rm.score);
            bool first = true;
            for (const QString& r : rm.reasons) {
                e.addEvidence(QStringLiteral("RansomwareBehaviorMonitor"),
                    (rm.canaryHit || rm.hardSignal) ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                    r, first ? rm.score : 0);
                first = false;
            }
            if (rm.canaryHit) {
                e.hasThreatIndicator = true;
                return Verdict::forEvent(e, VerdictAction::Block, VerdictSource::Heuristic);
            }
            //
            // 签名健康判定【必须与 hasThreatIndicator 解耦】。
            //
            // isHealthySigned / isCleanSigned 开头都有 `if (e.hasThreatIndicator) return {};`,
            // 而上面第 3 步的 ThreatDetector::analyze 早已跑过。于是只要该事件在【任何别的维度】
            // 上置了一个硬指标,这里的「签名健康 -> 勒索特征按误报抑制」就整体失效 —— 一个与
            // 勒索毫无关系的指标,级联决定了「要不要把批量写文件当成加密」。
            //
            // 实测这条级联真的发生了:MSBuild.exe(.NET 签名)编译时短时间内改写十几个文件,
            // 而同一事件上有一条「威胁情报:0/0 个引擎判为可疑」(零实据却被登记为硬指标,已在
            // ThreatDetector 第 9 节修掉)。硬指标一置,签名抑制失效,82 分直接拦 —— 编译器被
            // 当成勒索。构建工具、打包器、解压程序天生就是短时间写大量文件,这类误伤只能靠
            // 「主体签名健康」来兜。
            //
            // 所以这里直接读签名字段,不经过那两个带耦合的判定。安全性由蜜罐兜底:真正的勒索
            // 一旦触到诱饵文件,上面 rm.canaryHit 那条无条件 Block,不受本抑制影响 —— 这也正是
            // 原注释「未触蜜罐诱饵」想表达的取舍,只是原实现被那层耦合弄丢了。
            //
            const bool signatureHealthy = e.actorSigned && !e.signatureMismatch &&
                                          !e.certRevoked && !e.signedAfterCertExpiry;
            const bool trustedActor =
                signatureHealthy ||
                TrustPolicy::isStronglyTrusted(e).ok ||
                TrustPolicy::isHealthySigned(e).ok ||
                (e.actorSigned && TrustPolicy::isBenignSigner(e).ok);
            if (rm.hardSignal) {
                if (trustedActor) {
                    e.addEvidence(QStringLiteral("RansomwareBehaviorMonitor"), EvidenceKind::Trust,
                        u("主体签名健康,勒索行为特征按误报抑制(未触蜜罐诱饵)"), 0, false);
                } else {
                    e.hasThreatIndicator = true;
                    if (rm.score >= ThreatDetector::Suspicious)
                        return Verdict::forEvent(e, VerdictAction::Block, VerdictSource::Heuristic);
                }
            } else {
                if (!trustedActor) {
                    e.hasThreatIndicator = true;
                    if (rm.score >= ThreatDetector::Suspicious)
                        return Verdict::forEvent(e, VerdictAction::Ask, VerdictSource::Heuristic);
                }
            }
        }
    }
    else if (e.type == EventType::NetworkConnect) {
        const ScoreResult b = beacon_.observe(e);
        const bool beaconHit = b.score > 0;
        // 信标检测分两档(见 BeaconDetector):CV ≤ kCvRegular 抖动极低(几乎只有程序化回连才有
        // 这种规律)-> 硬指标;CV ≤ kCvSemiRegular 「近周期性」-> 仅软信号,因为正常软件的定时轮询
        // 几乎必然落在这一档(代理客户端拉订阅、更新器查版本、云盘同步;实测 clash-win64 每 ≈160s
        // 拉一次订阅即被判 C2 回连)。
        //
        // 【必须读 hardSignal,不能再用 `b.score >= 55` 推档位】BeaconDetector 在给出档位基线分
        // (55 / 35)之后还会按「未签名 +15」「脚本宿主 +20」继续加分,所以最终分数区分不了档位:
        // 近周期档 35 + 脚本宿主 20 = 55,与低抖动档基线分撞在一起。按分数判断的话,任何脚本宿主
        // (powershell / cmd / rundll32 / mshta / certutil ...)的准周期轮询都会被误升格为硬指标 ——
        // 而计划任务里的 PowerShell 巡检脚本正是这种形态,在真实系统上极常见。档位由唯一知道 CV 的
        // BeaconDetector 显式上报。
        const bool beaconHard = b.hardSignal;
        if (beaconHit) {
            e.riskScore = qMin(100, e.riskScore + b.score);
            bool first = true;
            for (const QString& r : b.reasons) {
                e.addEvidence(QStringLiteral("BeaconDetector"),
                              beaconHard ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal,
                              r, first ? b.score : 0);
                first = false;
            }
            if (beaconHard) e.hasThreatIndicator = true;
        }
        const ScoreResult d = DgaDomainAnalyzer::analyze(e.target);
        const bool dgaSuspicious = d.score >= 40;
        if (d.score > 0) {
            e.riskScore = qMin(100, e.riskScore + d.score);
            // 互证条件里原先含 `!e.actorSigned` —— 用「未签名」这个【软信号】去升格另一个软信号,
            // 与本项目「软信号只加分、需与硬指标互证」的原则相冲突,实际效果是「任何未签名程序连
            // 一个随机域名就定罪」。改为只认高置信信标档。
            const bool corroborated = beaconHard;
            bool first = true;
            for (const QString& r : d.reasons) {
                e.addEvidence(QStringLiteral("DgaDomainAnalyzer"),
                    corroborated ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal, r, first ? d.score : 0);
                first = false;
            }
            if (corroborated) {
                e.hasThreatIndicator = true;
                e.addEvidence(QStringLiteral("DgaDomainAnalyzer"), EvidenceKind::Corroboration,
                    u("DGA 随机域名与其它恶意指标互证(升格为硬指标)"), 0, false);
            }
        }
        const ScoreResult eg = egress_.observe(e);
        if (eg.score > 0) {
            e.riskScore = qMin(100, e.riskScore + eg.score);
            // 同上:原先 `|| !e.actorSigned` 让「未签名」单独就能把外联速率/扇出升格成硬指标。
            // 代理 / VPN / P2P / BT 客户端天然向大量节点扇出(实测 UniClashCore「10 秒内连向 38 个
            // 不同目标」被判横移扫描,14 次误报),而它们恰恰常常没有签名 —— 这条互证等于没有互证。
            const bool corroborated = beaconHard || dgaSuspicious;
            const bool escalated = corroborated && eg.score >= 50;
            bool first = true;
            for (const QString& r : eg.reasons) {
                e.addEvidence(QStringLiteral("EgressRateMonitor"),
                    escalated ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal, r, first ? eg.score : 0);
                first = false;
            }
            if (escalated) {
                e.hasThreatIndicator = true;
                e.addEvidence(QStringLiteral("EgressRateMonitor"), EvidenceKind::Corroboration,
                    u("异常外联速率/扇出与其它恶意指标互证(升格为硬指标)"), 0, false);
            }
        }
    }
    else if (e.type == EventType::DnsQuery) {
        const ScoreResult d = DgaDomainAnalyzer::analyze(e.target);
        if (d.score > 0) {
            e.riskScore = qMin(100, e.riskScore + d.score);
            bool first = true;
            for (const QString& r : d.reasons) {
                e.addEvidence(QStringLiteral("DgaDomainAnalyzer"), EvidenceKind::SoftSignal, r, first ? d.score : 0);
                first = false;
            }
        }
    }

    // 5) 行为基线偏离(软信号,仅互证升格)
    if (enableBaseline) {
        const BaselineAnalyzer::Result bl = baseline_.observe(e);
        if (bl.score > 0 && bl.deviation) {
            e.riskScore = qMin(100, e.riskScore + bl.score);
            const bool corroborated = e.hasThreatIndicator;
            bool first = true;
            for (const QString& r : bl.reasons) {
                e.addEvidence(QStringLiteral("BaselineAnalyzer"),
                    corroborated ? EvidenceKind::Corroboration : EvidenceKind::SoftSignal, r, first ? bl.score : 0);
                first = false;
            }
            if (corroborated)
                e.addEvidence(QStringLiteral("BaselineAnalyzer"), EvidenceKind::Corroboration,
                    u("行为偏离自身历史基线,与其它恶意指标互证"), 0, false);
        }
    }

    // 6) 显式规则优先(层级 > 具体度 > 动作强度 > 最近创建)
    {
        QVector<DefenseRule> matches;
        {
            QReadLocker locker(&rulesLock_);
            // 候选集 = 本事件类型的桶 + 类型无关桶。这与「扫全表」等价:matches() 的第三道
            // 判据就是类型不符即不命中,所以其它类型桶里的规则一条都不可能命中本事件。
            // 详见 RuleEngine.h 里索引那段说明(含「为什么胜出者也不会变」)。
            for (const DefenseRule& r : bucketForLocked(e.type))
                if (r.matches(e)) matches.append(r);
            for (const DefenseRule& r : typeAgnostic_)
                if (r.matches(e)) matches.append(r);
        }
        if (!matches.isEmpty()) {
            std::sort(matches.begin(), matches.end(), [](const DefenseRule& a, const DefenseRule& b) {
                const int ta = ruleTier(a), tb = ruleTier(b);
                if (ta != tb) return ta > tb;
                const int sa = specificity(a), sb = specificity(b);
                if (sa != sb) return sa > sb;
                const int pa = rulePriority(a.action), pb = rulePriority(b.action);
                if (pa != pb) return pa > pb;
                if (a.createdUtc != b.createdUtc) return a.createdUtc > b.createdUtc;
                // 兜底:按 id 定序,使本比较成为【全序】。
                //
                // 原先到 createdUtc 就结束了,于是两条在「层级/具体度/动作强度/创建时刻」上
                // 全部打平的规则之间,胜出者由 std::sort(不稳定)在 QHash 的迭代顺序上任意挑选;
                // 而 Qt 6 的 QHash 每进程随机化种子 —— 结果是【同一条事件在两次运行里可能得到
                // 不同裁决】。内置规则集里同类规则常常只差 targetPattern,打平并不罕见。
                //
                // 加上这一级之后选择变得确定:同一份规则集 + 同一条事件恒定产出同一个裁决。
                // 这既是裁决快照测试可成立的前提,也消除了生产环境里一个真实的抖动来源。
                return a.id < b.id;
            });
            const DefenseRule hit = matches.first();

            // 强可信 OS 组件豁免。原先这里排除了 Block 规则(`hit.action != Block`),导致三条
            // 显式标了 exemptTrustedOsComponent 的规则里有两条(WDAC 的 SiPolicy.p7b /
            // CiPolicies\Active\*)的豁免意图从未生效 —— Windows 自己部署 WDAC 策略照样被拦。
            // 现在对 Block 规则同样尊重该标记,但**只**认 isTrustedOsComponent,它本身已经很严:
            //   · e.hasThreatIndicator 为真 -> 不豁免(硬指标永远压过豁免);
            //   · 主体是 LOLBin / 脚本宿主(powershell/rundll32/mshta…)-> 不豁免;
            //   · 还必须通过 isStronglyTrusted(微软签名 + 系统目录 + 无危险命令行 + 无异常父子链)。
            // 因此只有「签名健康的系统自身组件在做它本职的敏感操作」才会被放行;未签名注入方、
            // 落在 Temp 的同名程序、带危险命令行的主体一律照旧拦截。该标记仅由内置规则显式设置,
            // 用户规则默认为 false,不受影响。
            if (hit.exemptTrustedOsComponent) {
                const TrustDecision os = TrustPolicy::isTrustedOsComponent(e);
                if (os.ok) {
                    e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, os.reason);
                    return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
                }
            }
            if (hit.action == VerdictAction::Ask && DefaultRules::isDevTool(e.actorPath)) {
                e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Trust, u("开发工具自动放行(白名单)"));
                return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
            }
            e.matchedRuleNote = hit.note;
            const QString actionName = hit.action == VerdictAction::Block ? QStringLiteral("Block")
                                     : hit.action == VerdictAction::Ask ? QStringLiteral("Ask")
                                     : QStringLiteral("Allow");
            e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Rule,
                u("命中规则:") + (hit.note.isEmpty() ? actionName : hit.note), 0, false);
            return Verdict::forEvent(e, hit.action, VerdictSource::Rule);
        }
    }

    // 7) 强可信主体直接放行(唯一跳过行为检测的通道)
    if (trustSignedActors) {
        const TrustDecision t = TrustPolicy::isStronglyTrusted(e);
        if (t.ok) {
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, t.reason);
            return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
        }
    }

    // 8) 签名异常(吊销 / 过期后签名)-> Block
    if (e.certRevoked || e.signedAfterCertExpiry)
        return Verdict::forEvent(e, VerdictAction::Block, VerdictSource::Heuristic);

    // 9) 健康签名直接放行
    if (trustSignedActors) {
        const TrustDecision h = TrustPolicy::isHealthySigned(e);
        if (h.ok) {
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, h.reason);
            return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
        }
    }

    // 10) 仅当存在硬恶意指标才处置:高危拦截,其余询问
    if (e.hasThreatIndicator) {
        return e.riskScore >= ThreatDetector::HighRisk
            ? Verdict::forEvent(e, VerdictAction::Block, VerdictSource::Heuristic)
            : Verdict::forEvent(e, VerdictAction::Ask, VerdictSource::Heuristic);
    }

    // 11) 无硬指标:一律放行(仅记录)
    if (e.actorSigned) {
        const TrustDecision bn = TrustPolicy::isBenignSigner(e);
        if (bn.ok)
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, bn.reason);
        else if (e.riskScore > 0)
            e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Info, u("无恶意行为特征(默认放行)"));
    } else if (e.riskScore > 0) {
        e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Info, u("无恶意行为特征(默认放行)"));
    }

    return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::DefaultPolicy);
}

} // namespace bulwark::engine
