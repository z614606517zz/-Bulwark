#pragma once
#include <QColor>
#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QRegularExpression>
#include <QString>
#include <QStringList>

#include "bulwark/engine/DefaultRules.h"  // builtInTag():内置规则备注的前缀(威胁类型按它取分类)
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"
#include "design/Identity.h"
#include "design/Theme.h"

// The single source of truth for how security events read in the UI — type
// names, glyphs, risk levels, verdicts and dispositions, one-line summaries.
// The behavior prompt, toasts, every list page, the dashboard and the attack
// timeline all format through here, so the same event never reads two ways.
// (These used to be copied three times — TablePages, DashboardPage and here —
// and had already drifted: "远程线程" vs "远程线程注入", "映像加载" vs "模块 / 驱动加载".)
namespace evtfmt {

inline QString u(const char* s) { return QString::fromUtf8(s); }

struct Badge {
    QString text;
    QColor color;
};

// ---- event types --------------------------------------------------------------

inline QString typeLabel(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return u("进程创建");
    case E::ProcessTerminate: return u("结束进程");
    case E::RemoteThread:     return u("远程线程注入");
    case E::ImageLoad:        return u("模块 / 驱动加载");
    case E::FileWrite:        return u("文件写入");
    case E::FileDelete:       return u("文件删除");
    case E::RegistryWrite:    return u("注册表写入");
    case E::NetworkConnect:   return u("网络外联");
    case E::SelfProtect:      return u("自我保护");
    case E::DnsQuery:         return u("DNS 解析");
    }
    return u("行为");
}

// Compact label for chips, filter menus and rule sentences.
inline QString typeShort(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::RemoteThread: return u("远程线程");
    case E::ImageLoad:    return u("模块加载");
    default:              return typeLabel(t);
    }
}

// One glyph per behaviour family, so a list can be scanned by shape.
inline QString typeGlyph(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return QStringLiteral("target");
    case E::ProcessTerminate: return QStringLiteral("power");
    case E::RemoteThread:     return QStringLiteral("zap");
    case E::ImageLoad:        return QStringLiteral("layers");
    case E::FileWrite:
    case E::FileDelete:       return QStringLiteral("file");
    case E::RegistryWrite:    return QStringLiteral("sliders");
    case E::NetworkConnect:
    case E::DnsQuery:         return QStringLiteral("globe");
    case E::SelfProtect:      return QStringLiteral("shield");
    }
    return QStringLiteral("activity");
}

// ...and one hue per family (design/Identity.h), so it can be scanned by colour
// too. Only for events with nothing to say about risk: see glyphColor().
inline identity::Kind typeKind(bulwark::EventType t) {
    using E = bulwark::EventType;
    using K = identity::Kind;
    switch (t) {
    case E::ProcessCreate:
    case E::ProcessTerminate: return K::Process;
    case E::RemoteThread:     return K::Injection;
    case E::ImageLoad:        return K::Module;
    case E::FileWrite:
    case E::FileDelete:       return K::File;
    case E::RegistryWrite:    return K::Registry;
    case E::NetworkConnect:
    case E::DnsQuery:         return K::Network;
    case E::SelfProtect:      break; // neutral, like processes: records never wear the brand jade
    }
    return K::Neutral;
}

inline QColor typeColor(bulwark::EventType t) { return identity::kind(typeKind(t)); }

inline QString verb(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return u("尝试创建进程");
    case E::ProcessTerminate: return u("尝试结束进程");
    case E::RemoteThread:     return u("尝试注入远程线程");
    case E::ImageLoad:        return u("尝试加载模块 / 驱动");
    case E::FileWrite:        return u("尝试写入 / 修改文件");
    case E::FileDelete:       return u("尝试删除文件");
    case E::RegistryWrite:    return u("尝试写入注册表");
    case E::NetworkConnect:   return u("尝试网络外联");
    case E::SelfProtect:      return u("触发自我保护");
    case E::DnsQuery:         return u("发起 DNS 解析");
    }
    return u("敏感行为");
}

// The action itself, as a short verb phrase ("注入远程线程").
inline QString action(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return u("启动进程");
    case E::ProcessTerminate: return u("结束进程");
    case E::RemoteThread:     return u("注入远程线程");
    case E::ImageLoad:        return u("加载模块");
    case E::FileWrite:        return u("写入文件");
    case E::FileDelete:       return u("删除文件");
    case E::RegistryWrite:    return u("写入注册表");
    case E::NetworkConnect:   return u("网络外联");
    case E::SelfProtect:      return u("触发自我保护");
    case E::DnsQuery:         return u("解析域名");
    }
    return u("敏感行为");
}

inline QString actorName(const QString& path) {
    const QString n = QFileInfo(path).fileName();
    return n.isEmpty() ? (path.isEmpty() ? u("未知程序") : path) : n;
}

// One sentence saying what happened. present=true for a live question
// ("powershell.exe 正试图向 explorer.exe (PID 2204) 注入远程线程"), false for
// a record ("powershell.exe 向 explorer.exe (PID 2204) 注入远程线程").
inline QString sentence(const bulwark::SecurityEvent& e, bool present) {
    using E = bulwark::EventType;
    const QString a = actorName(e.actorPath);
    const QString t = e.target.trimmed();
    const QString tense = present ? u("正试图") : QString();
    if (t.isEmpty())
        return a + u(" ") + (present ? verb(e.type) : action(e.type));
    switch (e.type) {
    case E::RemoteThread:     return u("%1 %2向 %3 注入远程线程").arg(a, tense, t);
    case E::ProcessCreate:    return u("%1 %2启动 %3").arg(a, tense, t);
    case E::ProcessTerminate: return u("%1 %2结束 %3").arg(a, tense, t);
    case E::ImageLoad:        return u("%1 %2加载 %3").arg(a, tense, t);
    case E::FileWrite:        return u("%1 %2写入 %3").arg(a, tense, t);
    case E::FileDelete:       return u("%1 %2删除 %3").arg(a, tense, t);
    case E::RegistryWrite:    return u("%1 %2修改注册表 %3").arg(a, tense, t);
    case E::NetworkConnect:   return u("%1 %2连接 %3").arg(a, tense, t);
    case E::SelfProtect:      return u("%1 触发自我保护:%2").arg(a, t);
    case E::DnsQuery:         return u("%1 %2解析域名 %3").arg(a, present ? u("正在") : QString(), t);
    }
    return a + u(" ") + action(e.type);
}

// Toast one-liner: "powershell.exe 注入远程线程 → explorer.exe".
inline QString arrowLine(const bulwark::SecurityEvent& e) {
    const QString a = actorName(e.actorPath);
    const QString t = e.target.trimmed();
    return t.isEmpty() ? a + u(" ") + action(e.type)
                       : u("%1 %2 → %3").arg(a, action(e.type), t);
}

// ---- risk -----------------------------------------------------------------------

inline QColor riskColor(int score) {
    if (score >= 80) return theme::danger();
    if (score >= 50) return theme::warning();
    return theme::success();
}

inline QString riskLevel(int score) {
    if (score >= 80) return u("高危");
    if (score >= 50) return u("可疑");
    return u("正常");
}

// The colour of an event's glyph (list rows, inspector header): its risk when
// that is worth showing (>= 50) — status always wins — otherwise the hue of its
// behaviour family. Below 50 the score itself still reads green / as a number.
inline QColor glyphColor(const bulwark::SecurityEvent& e) {
    return e.riskScore >= 50 ? riskColor(e.riskScore) : typeColor(e.type);
}

// ---- verdicts & dispositions -------------------------------------------------------

// A decision (rule action): 拦截 / 询问 / 放行.
inline Badge verdict(bulwark::VerdictAction a) {
    switch (a) {
    case bulwark::VerdictAction::Block: return {u("拦截"), theme::danger()};
    case bulwark::VerdictAction::Ask:   return {u("询问"), theme::warning()};
    case bulwark::VerdictAction::Allow: break;
    }
    return {u("放行"), theme::success()};
}

// What was actually DONE about an event. For Block this follows the real
// enforcement outcome, never the verdict alone — a Block that nothing enforced
// must not read "已拦截" (the no-fake-block rule). Only a kernel pre-block, a
// terminated process tree or a module blacklisting count as a real block;
// alert-only and failed enforcement say so.
inline Badge disposition(bulwark::VerdictAction act, bulwark::EnforcementOutcome enf) {
    if (act != bulwark::VerdictAction::Block) {
        if (act == bulwark::VerdictAction::Ask)
            return {u("已询问"), theme::warning()};
        return {u("已放行"), theme::success()};
    }
    using EO = bulwark::EnforcementOutcome;
    switch (enf) {
    case EO::KernelBlocked:     return {u("已拦截"), theme::danger()};        // 内核前拦
    case EO::Terminated:        return {u("已结束进程"), theme::danger()};    // 事后杀成功
    case EO::ModuleBlacklisted: return {u("已禁止加载"), theme::danger()};    // 下次前拦
    case EO::ExecDenied:        return {u("已禁止启动"), theme::danger()};    // 下次启动直接失败
    case EO::ActorAlreadyGone:  return {u("主体已结束"), theme::danger()};    // 此前的处置已把它杀掉
    case EO::AlertedOnly:       return {u("仅告警·未拦截"), theme::warning()}; // 未实际拦截
    case EO::Failed:            return {u("拦截失败"), theme::warning()};
    case EO::NotApplicable:     break;
    }
    return {u("已拦截"), theme::danger()}; // 历史记录兜底(旧记录没有处置字段)
}

// Which part of the pipeline produced the verdict.
inline QString verdictSourceLabel(bulwark::VerdictSource s) {
    using S = bulwark::VerdictSource;
    switch (s) {
    case S::Rule:          return u("命中规则");
    case S::Heuristic:     return u("启发式评分");
    case S::TrustedSigner: return u("受信签名放行");
    case S::UserPrompt:    return u("用户裁决");
    case S::Timeout:       return u("询问超时,按默认处理");
    case S::DefaultPolicy: return u("默认策略");
    }
    return u("—");
}

// Counts toward "拦截" totals only when something really stopped the action.
//
// ActorAlreadyGone 刻意【不】计入:那条事件的主体是被【之前那一次处置】杀掉的,而那一次
// 已经计过一次拦截。把它也算上,一个 kill 会被排队事件放大成好几次「已拦截」,总数就虚高了。
// ExecDenied 计入,理由与 ModuleBlacklisted 一致:确实产生了一次真实的前拦(下次启动会失败)。
inline bool isRealBlock(bulwark::VerdictAction act, bulwark::EnforcementOutcome enf) {
    using EO = bulwark::EnforcementOutcome;
    return act == bulwark::VerdictAction::Block
        && (enf == EO::KernelBlocked || enf == EO::Terminated || enf == EO::ModuleBlacklisted
            || enf == EO::ExecDenied || enf == EO::NotApplicable);
}

// 是否「需要用户自己动手」。只有真的什么都没拦住才算 —— 通知抬头、语音、查毒卡片、
// 检查器提示全都按这一条决定措辞,避免每处各写一遍判断而互相走样。
inline bool needsManualAction(bulwark::EnforcementOutcome enf) {
    using EO = bulwark::EnforcementOutcome;
    return enf == EO::AlertedOnly || enf == EO::Failed;
}

// One sentence explaining the disposition (inspector / attack timeline).
inline QString dispositionDetail(bulwark::VerdictAction act, bulwark::EnforcementOutcome enf) {
    if (act == bulwark::VerdictAction::Ask)
        return u("该行为交由用户裁决。");
    if (act != bulwark::VerdictAction::Block)
        return u("该行为已放行。");
    using EO = bulwark::EnforcementOutcome;
    switch (enf) {
    case EO::KernelBlocked:     return u("内核在操作发生前将其阻断,动作没有发生。");
    case EO::Terminated:        return u("动作已经发生,发起它的进程树已被结束。");
    case EO::ModuleBlacklisted: return u("这次加载没能拦下;该模块已加入内核禁止加载名单,下次加载会在发生前被阻断。");
    case EO::ExecDenied:        return u("这次没有可结束的进程(它已经退出);该程序已被禁止启动,再次双击会直接失败。撤销入口是在界面把它加白。");
    case EO::ActorAlreadyGone:  return u("这条是发起进程退出【之前】排队的动作;那个进程已在本次之前被结束,不需要再处置。");
    case EO::AlertedOnly:       return u("仅告警:内核无法前拦且没有可结束的进程,未做任何实际阻断,需要人工关注。");
    case EO::Failed:            return u("尝试处置但没有成功(进程已退出、受保护或为关键进程)。");
    case EO::NotApplicable:     break;
    }
    return u("裁决为拦截;这条历史记录没有保存实际处置结果。");
}

// ---- evidence -----------------------------------------------------------------------

inline QString evidenceKindLabel(bulwark::EvidenceKind k) {
    using K = bulwark::EvidenceKind;
    switch (k) {
    case K::Info:          return u("上下文");
    case K::SoftSignal:    return u("软信号");
    case K::HardIndicator: return u("硬指标");
    case K::Corroboration: return u("互证");
    case K::Trust:         return u("信任");
    case K::Rule:          return u("规则");
    case K::Decision:      return u("裁决");
    }
    return u("证据");
}

inline QColor evidenceKindColor(bulwark::EvidenceKind k) {
    using K = bulwark::EvidenceKind;
    switch (k) {
    case K::HardIndicator: return theme::danger();
    case K::SoftSignal:    return theme::warning();
    case K::Corroboration: return theme::warning();
    case K::Trust:         return theme::success();
    case K::Rule:          return theme::info();
    case K::Decision:      return theme::accent();
    case K::Info:          return theme::textMuted();
    }
    return theme::textMuted();
}

// ---- threat type ------------------------------------------------------------------------
//
// 「拦下的是什么」—— 拦截通知、云查卡片与拦截记录检查器共用的「威胁类型」。
//
// 拦截通知原先只有「已拦截危险行为」加一行依据,而依据取的是 riskReasons.first();
// ThreatDetector 最先登记的恰好是「无可信数字签名」这条 Info 级上下文,于是大多数启发式拦截的
// 通知读起来都是「依据:无可信数字签名」—— 既不是拦它的理由,也说不出拦下的是什么。
//
// 定性按确定性从高到低,取第一个说得清的来源;类别、具名威胁与依据出自【同一个】来源,
// 读起来是「它是 X,因为 Y」,而不是两件不相干的事:
//   1. 云端情报判恶意且带实据(引擎计数或威胁名 —— 零实据不算,与 ThreatDetector 第 9 节
//      同一口径):威胁名原样保留,按其中的类别词归入中文大类(trojan.mint/phil -> 木马);
//   2. 命中的规则:内置规则备注「[内置] <分类> · <说明>」取 <分类>(规则段本来就按威胁划分);
//      释放物污点 / 情报规则各有固定说法;
//   3. 启发式:分值最高、且归得了类的那条【硬指标】证据;
//   4. 云端判「可疑」(带实据)—— 排在规则与硬指标之后:没坐实的结论不该盖过具体的行为;
//      其后是判恶意但没给实据的云端结论(服务端照样据此处置了,只是说不出是哪一类);
//   5. 事件本身就说明了性质的(内核内存防护 / 自我保护);
//   6. 用户自建规则:如实写「自定义规则」。
// 都说不清时 category 为空,调用方就不显示这一项 —— 编一个「恶意行为」出来,不如不说。
struct Threat {
    QString category; // 威胁类型(中文大类)
    QString name;     // 具名威胁(云端给的威胁名),可空
    QString basis;    // 定性所依据的那条证据原文(拦截通知的「依据」行),可空

    bool isEmpty() const { return category.isEmpty(); }
    // 「木马 · trojan.mint/phil」
    QString text() const { return name.isEmpty() ? category : category + u(" · ") + name; }
};

namespace threat_detail {

// 情报来源的展示名,与服务端 Worker.cpp 的 intelSourceDisplayName 同一口径:
// "Proxy:X" 是「中央服务器转来的 X 的结论」,"Proxy:" 这个前缀本身对用户没有意义。
inline QString intelSourceName(const QString& raw) {
    const QString s = raw.trimmed();
    if (s.startsWith(QLatin1String("Proxy:"), Qt::CaseInsensitive)) {
        const QString under = s.mid(6).trimmed();
        return under.isEmpty() ? u("中央服务器") : u("中央服务器·") + under;
    }
    if (s.compare(QLatin1String("Proxy"), Qt::CaseInsensitive) == 0)
        return u("中央服务器");
    return s;
}

// 云端威胁名 -> 中文大类。威胁名的惯用写法是「类别词 + 家族」:VirusTotal 的 trojan.mint/phil、
// 卡巴斯基式的 Trojan-Ransom.Win32.X、ThreatFox 的 win.cobalt_strike、MalwareBazaar 的
// AgentTesla / AsyncRAT。顺序即优先级 —— 具体类别先于泛称(Trojan-Ransom 是勒索、TrojanSpy
// 是窃密),最后才落到「木马」;一个类别词都认不出时按结论写「恶意程序 / 可疑程序」,不硬套。
inline QString cloudCategory(const QString& label, bool malicious) {
    const QString l = label.toLower();
    static const QRegularExpression sep(QStringLiteral("[^a-z0-9]+"));
    const QStringList tokens = l.split(sep, Qt::SkipEmptyParts);
    const auto has = [&l](const char* s) { return l.contains(QLatin1String(s)); };
    const auto zh = [&label](const char* s) { return label.contains(u(s)); };
    const auto token = [&tokens](const char* s) { return tokens.contains(QLatin1String(s)); };
    // 「…rat」结尾的家族名:AsyncRAT / njRAT / ValleyRAT(银狐)/ Gh0stRAT …
    const auto ratFamily = [&tokens] {
        for (const QString& t : tokens)
            if (t == QLatin1String("rat") || (t.size() > 4 && t.endsWith(QLatin1String("rat"))))
                return true;
        return false;
    };
    // 「本身不算恶意」的标记先认:not-a-virus:RiskTool.BitMiner 是挖矿工具,不是挖矿木马。
    if (has("not-a-virus") || token("pua") || token("pup") || has("riskware") || has("risktool")
        || has("grayware") || has("unwanted"))
        return u("风险软件");
    if (has("ransom") || has("lockbit") || has("wannacry") || zh("勒索"))
        return u("勒索软件");
    if (has("miner") || has("xmrig") || zh("挖矿"))
        return u("挖矿木马");
    if (has("banker") || has("banking"))
        return u("网银木马");
    if (has("stealer") || has("spy") || has("keylog") || token("pws") || zh("窃密") || zh("盗号"))
        return u("窃密木马");
    if (has("backdoor") || ratFamily() || has("cobalt") || zh("远控") || zh("后门"))
        return u("远控木马");
    if (has("rootkit") || has("bootkit"))
        return u("Rootkit");
    if (has("worm") || zh("蠕虫"))
        return u("蠕虫");
    if (has("exploit") || zh("漏洞"))
        return u("漏洞利用");
    if (has("downloader"))
        return u("木马下载器");
    if (has("dropper"))
        return u("木马释放器");
    if (has("loader"))
        return u("木马加载器");
    if (has("adware") || zh("广告"))
        return u("广告软件");
    if (has("hacktool") || token("hktl") || zh("黑客工具"))
        return u("黑客工具");
    if (has("phish") || zh("钓鱼"))
        return u("钓鱼");
    if (token("bot") || has("botnet") || zh("僵尸"))
        return u("僵尸网络");
    if (has("webshell"))
        return u("WebShell");
    if (token("virus") || has("infector") || has("virut") || has("sality") || zh("感染"))
        return u("感染型病毒");
    if (has("trojan") || token("troj") || token("trj") || zh("木马"))
        return u("木马");
    return malicious ? u("恶意程序") : u("可疑程序");
}

// ATT&CK 编号(按主编号:T1574.002 -> T1574)-> 威胁类型。只收引擎证据与内置规则里实际出现的。
inline QString techniqueCategory(const QString& id) {
    static const QHash<QString, QString> table = [] {
        QHash<QString, QString> t;
        const auto add = [&t](std::initializer_list<const char*> ids, const char* category) {
            for (const char* tech : ids)
                t.insert(QString::fromLatin1(tech), u(category));
        };
        add({"T1003", "T1555", "T1552", "T1558"}, "凭据窃取");
        add({"T1055"}, "进程注入");
        add({"T1574"}, "DLL 侧载");
        add({"T1036"}, "伪装");
        add({"T1564"}, "隐藏载荷");
        add({"T1027", "T1140", "T1620"}, "混淆载荷");
        add({"T1105", "T1197"}, "下载执行");
        add({"T1059"}, "恶意脚本");
        add({"T1486"}, "勒索加密");
        add({"T1490", "T1485", "T1565"}, "勒索与破坏");
        add({"T1547", "T1546", "T1543", "T1053", "T1136"}, "持久化");
        add({"T1562", "T1070", "T1553", "T1112"}, "防御规避");
        add({"T1548", "T1068"}, "权限提升");
        add({"T1218", "T1127", "T1202", "T1216", "T1047"}, "执行与 LOLBin");
        add({"T1566", "T1204"}, "钓鱼诱导");
        add({"T1071", "T1568", "T1573", "T1090"}, "C2 通信");
        add({"T1219", "T1563"}, "远程控制");
        add({"T1021", "T1570"}, "横向移动");
        return t;
    }();
    return table.value(id.trimmed().left(5).toUpper());
}

// 证据的 ATT&CK 编号:AttackAnnotator 已规范化写回的优先,否则从描述里抽第一个。
inline QString techniqueOf(const bulwark::Evidence& ev) {
    if (!ev.technique.isEmpty())
        return ev.technique;
    static const QRegularExpression re(QStringLiteral("T\\d{4}(?:\\.\\d{3})?"));
    const QRegularExpressionMatch m = re.match(ev.description);
    return m.hasMatch() ? m.captured(0) : QString();
}

// 攻击链类的「元证据」:说的是「好几个动作凑在了一起」,而不是这一下是什么。
inline bool isMetaEvidence(const bulwark::Evidence& ev) {
    return ev.source == QLatin1String("KillChainAnalyzer") || ev.source == QLatin1String("AttackChain");
}

// 一条证据 -> 威胁类型。专项分析器的「主题」就是威胁本身,直接按来源归类;通用的
// ThreatDetector 与按手法组织的分析器先看 ATT&CK 编号 —— 编号说的是意图:LolbinAnalyzer 的
// 「rundll32 经 comsvcs 转储 LSASS」是凭据窃取,不只是「滥用了系统工具」—— 再按来源兜底。
// 来源名即 SecurityEvent::addEvidence 的 source 参数(引擎各分析器 + 服务端的异步确认)。
inline QString evidenceCategory(const bulwark::Evidence& ev) {
    const QString& d = ev.description;
    const auto is = [&ev](const char* name) { return ev.source == QLatin1String(name); };
    if (is("RansomwareBehaviorMonitor"))                return u("勒索加密");
    if (is("BeaconDetector") || is("DgaDomainAnalyzer")) return u("C2 通信");
    if (is("EgressRateMonitor"))                        return u("异常外联");
    if (is("RemoteControlAnalyzer"))                    return u("远程控制");
    if (is("CommandObfuscationAnalyzer"))               return u("混淆载荷");
    if (is("ScriptAnalyzer") || is("ScriptFileAnalyzer")) return u("恶意脚本");
    if (is("PersistenceAnalyzer"))                      return u("持久化");
    if (is("KillChainAnalyzer"))                        return u("攻击链");
    if (is("AttackChain"))                              return u("攻击链组合");
    if (is("Reputation"))                               return u("已知恶意文件"); // 无信誉对象时:兜底扫描复查等
    if (is("IpReputation"))                             return u("恶意外联");
    if (is("LaunchingParent"))                          return u("恶意发起方");
    if (is("ThreatDetector")) {
        // 这几条没有 ATT&CK 编号,或编号说不到点子上(签名壳侧载也标 T1574,但它是「白加黑」)。
        if (d.contains(u("白加黑")) || d.contains(u("签名壳")))   return u("白加黑侧载");
        if (d.contains(u("证书")) || d.contains(u("签名校验失败"))) return u("签名异常");
        if (d.contains(u("膨胀")))                               return u("文件膨胀规避");
        if (d.contains(u("宏病毒")) || d.contains(u("钓鱼")))     return u("钓鱼诱导");
        if (d.contains(u("隐藏窗口")))                            return u("隐蔽执行");
    }
    const QString byTechnique = techniqueCategory(techniqueOf(ev));
    if (!byTechnique.isEmpty())
        return byTechnique;
    if (is("InjectionAnalyzer"))        return u("进程注入");
    if (is("CredentialAccessAnalyzer")) return u("凭据窃取");
    if (is("DefenseEvasionAnalyzer"))   return u("防御规避");
    if (is("LolbinAnalyzer"))           return u("执行与 LOLBin");
    if (is("ThreatDetector") && d.contains(u("脚本")))
        return u("恶意脚本");
    return QString();
}

// 1) / 4):云端结论。requireEvidence = 只认带实据的(引擎计数或威胁名)。
inline bool cloudThreat(const bulwark::SecurityEvent& e, bulwark::ReputationVerdict want,
                        bool requireEvidence, Threat* out) {
    if (!e.reputation.has_value() || e.reputation->verdict != want)
        return false;
    const bulwark::FileReputation& rep = *e.reputation;
    const QString label = rep.threatLabel.trimmed();
    const bool counts = rep.totalEngines > 0 && rep.malicious > 0;
    if (requireEvidence && !counts && label.isEmpty())
        return false;
    // "ThreatBook:high" 是严重度而不是威胁名(微步没给家族 / 研判时 ThreatBookClient 这样兜底)。
    const QString name = label.startsWith(QLatin1String("ThreatBook:"), Qt::CaseInsensitive) ? QString() : label;
    const bool malicious = want == bulwark::ReputationVerdict::Malicious;
    out->category = cloudCategory(name, malicious);
    out->name = name;
    const QString src = intelSourceName(rep.source);
    out->basis = (src.isEmpty() ? u("云端情报") : u("云端情报[") + src + u("]"))
               + (malicious ? u(" 判为恶意") : u(" 判为可疑"))
               + (counts ? u("(%1/%2 个引擎)").arg(rep.malicious).arg(rep.totalEngines) : QString());
    return true;
}

// 2):命中规则的分类。内置规则备注由 rules::Segment 统一生成为「[内置] <分类> · <说明>」;
// 释放物污点与情报规则的标签分别见服务端 Worker::taintRuleTag() 与 onReputationMalicious /
// buildRulesFromProfile。用户自建规则不在这里认领(留到 6),先看有没有更具体的硬指标)。
inline bool ruleThreat(const bulwark::SecurityEvent& e, Threat* out) {
    const QString note = e.matchedRuleNote.trimmed();
    if (note.isEmpty())
        return false;
    const QString dot = u(" · ");
    const QString builtin = bulwark::engine::DefaultRules::builtInTag();
    if (note.startsWith(builtin)) {
        const QString rest = note.mid(builtin.size()).trimmed();
        const int at = rest.indexOf(dot);
        if (at <= 0)
            return false; // 不是分段规则的形态:不猜
        out->category = rest.left(at).trimmed();
        out->basis = rest.mid(at + dot.size()).trimmed();
        return !out->category.isEmpty();
    }
    const QString taint = u("[污点-释放物]");
    if (note.startsWith(taint)) {
        // 「禁止运行/加载」= 释放它的那一个已被确认恶意;「运行/加载前询问」= 只是和一次拦截有关联。
        out->category = note.contains(u("询问")) ? u("可疑释放物") : u("恶意释放物");
        out->basis = note.mid(taint.size()).trimmed();
        return true;
    }
    const QString intelHash = u("[情报-恶意]");
    if (note.startsWith(intelHash)) {
        out->category = u("已知恶意文件");
        out->basis = note.mid(intelHash.size()).trimmed();
        return true;
    }
    const QString intelProfile = u("[情报-行为]");
    if (note.startsWith(intelProfile)) {
        out->category = note.contains(QLatin1String("C2")) ? u("C2 通信")
                      : note.contains(u("持久化"))          ? u("持久化")
                      : note.contains(u("释放"))            ? u("恶意释放物")
                                                            : u("已知恶意行为");
        out->basis = note.mid(intelProfile.size()).trimmed();
        return true;
    }
    return false;
}

// 3):启发式定性 —— 分值最高、且归得了类的那条硬指标。攻击链类的元证据只在没有更具体的
// 硬指标时才用:「勒索加密」比「攻击链」更说明拦下的是什么。
inline bool evidenceThreat(const bulwark::SecurityEvent& e, Threat* out) {
    for (int pass = 0; pass < 2; ++pass) {
        const bulwark::Evidence* best = nullptr;
        QString bestCategory;
        for (const bulwark::Evidence& ev : e.evidenceChain) {
            if (ev.kind != bulwark::EvidenceKind::HardIndicator)
                continue;
            // 有信誉对象时,云端结论由 1) / 4) 按判定档位处理,这里不重复认领。
            if (e.reputation.has_value() && ev.source == QLatin1String("Reputation"))
                continue;
            if (isMetaEvidence(ev) != (pass == 1))
                continue;
            const QString c = evidenceCategory(ev);
            if (!c.isEmpty() && (!best || ev.scoreDelta > best->scoreDelta)) {
                best = &ev;
                bestCategory = c;
            }
        }
        if (best) {
            out->category = bestCategory;
            out->basis = best->description.trimmed();
            return true;
        }
    }
    return false;
}

// 命中过规则(含备注为空的用户规则:RuleEngine 为每次命中登记一条 Rule 证据)。
inline bool hitRule(const bulwark::SecurityEvent& e) {
    if (!e.matchedRuleNote.trimmed().isEmpty())
        return true;
    for (const bulwark::Evidence& ev : e.evidenceChain)
        if (ev.kind == bulwark::EvidenceKind::Rule)
            return true;
    return false;
}

} // namespace threat_detail

inline Threat threatOf(const bulwark::SecurityEvent& e) {
    using namespace threat_detail;
    using RV = bulwark::ReputationVerdict;
    Threat t;
    if (cloudThreat(e, RV::Malicious, /*requireEvidence=*/true, &t))
        return t;
    if (ruleThreat(e, &t))
        return t;
    if (evidenceThreat(e, &t))
        return t;
    if (cloudThreat(e, RV::Suspicious, /*requireEvidence=*/true, &t)
        || cloudThreat(e, RV::Malicious, /*requireEvidence=*/false, &t))
        return t;
    if (e.memoryInjection) {
        t.category = u("进程注入");
        t.basis = e.detail.trimmed();
        return t;
    }
    if (e.type == bulwark::EventType::SelfProtect) {
        t.category = u("对抗安全软件");
        t.basis = e.detail.trimmed();
        return t;
    }
    if (hitRule(e)) {
        t.category = u("自定义规则");
        t.basis = e.matchedRuleNote.trimmed().isEmpty() ? u("命中你设置的规则") : e.matchedRuleNote.trimmed();
    }
    return t;
}

// 没能定性时「依据」的兜底:证据链里分值最高的那条判据(硬指标 > 互证 > 软信号)。
// 「无可信数字签名」这类 Info 级上下文不算 —— 它从来不是拦截的理由。证据链为空的旧记录
// 才退回规则备注 / riskReasons。
inline QString strongestReason(const bulwark::SecurityEvent& e) {
    using K = bulwark::EvidenceKind;
    for (const K kind : {K::HardIndicator, K::Corroboration, K::SoftSignal}) {
        const bulwark::Evidence* best = nullptr;
        for (const bulwark::Evidence& ev : e.evidenceChain)
            if (ev.kind == kind && !ev.description.trimmed().isEmpty()
                && (!best || ev.scoreDelta > best->scoreDelta))
                best = &ev;
        if (best)
            return best->description.trimmed();
    }
    if (!e.matchedRuleNote.trimmed().isEmpty())
        return e.matchedRuleNote.trimmed();
    return e.riskReasons.isEmpty() ? QString() : e.riskReasons.first().trimmed();
}

// ---- process origin ---------------------------------------------------------------------

inline QString originKindLabel(bulwark::ProcessOriginKind k) {
    using O = bulwark::ProcessOriginKind;
    switch (k) {
    case O::Interactive:    return u("交互式启动");
    case O::Service:        return u("服务");
    case O::ScheduledTask:  return u("计划任务");
    case O::WmiProvider:    return u("WMI 提供者");
    case O::LogonAutostart: return u("登录自启动");
    case O::SystemBoot:     return u("系统启动");
    case O::Unknown:        break;
    }
    return u("未知");
}

// Who launched a process, as a hue (design/Identity.h) and a glyph — the same
// kinds as the attack graph's service / scheduled-task nodes and the autostart
// categories, so "服务" reads orchid and "计划任务" rose wherever it appears.
inline identity::Kind originKindOf(bulwark::ProcessOriginKind k) {
    using O = bulwark::ProcessOriginKind;
    using K = identity::Kind;
    switch (k) {
    case O::Interactive:    return K::Process;
    case O::Service:        return K::Service;
    case O::ScheduledTask:  return K::Task;
    case O::WmiProvider:    return K::Network;
    case O::LogonAutostart: return K::Registry;
    case O::SystemBoot:
    case O::Unknown:        break;
    }
    return K::Neutral;
}

inline QColor originColor(bulwark::ProcessOriginKind k) { return identity::kind(originKindOf(k)); }

inline QString originGlyph(bulwark::ProcessOriginKind k) {
    using O = bulwark::ProcessOriginKind;
    switch (k) {
    case O::Service:        return QStringLiteral("server");
    case O::ScheduledTask:  return QStringLiteral("clock");
    case O::WmiProvider:    return QStringLiteral("zap");
    case O::LogonAutostart: return QStringLiteral("power");
    case O::SystemBoot:     return QStringLiteral("cpu");
    case O::Interactive:
    case O::Unknown:        break;
    }
    return QStringLiteral("target");
}

inline QString nativePath(const QString& p) { return QDir::toNativeSeparators(p); }

} // namespace evtfmt
