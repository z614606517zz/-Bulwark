#include "bulwark/engine/AttackGraphBuilder.h"

#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QSet>

#include <algorithm>

namespace bulwark::engine {

using bulwark::AttackGraph;
using bulwark::AttackGraphEdge;
using bulwark::AttackGraphNode;
using bulwark::AttackNodeKind;
using bulwark::EnforcementOutcome;
using bulwark::EventType;
using bulwark::SecurityEvent;
using bulwark::VerdictAction;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

QString normalizeKey(const QString& s)
{
    QString n = s.trimmed();
    n.replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (n.endsWith(QLatin1Char('\\')))
        n.chop(1);
    return n.toLower();
}

bool isPlaceholderPath(const QString& p)
{
    return p.isEmpty() || p.startsWith(QLatin1String("PID "), Qt::CaseInsensitive);
}

QString shortLabel(const QString& path)
{
    if (path.isEmpty())
        return QString();
    const QString name = QFileInfo(path).fileName();
    return name.isEmpty() ? path : name;
}

QString truncate(const QString& s, int max)
{
    return (s.size() <= max) ? s : (s.left(max) + u("…"));
}

// 行为措辞:与 UI 的 evtfmt::verb 同源语义,但图上要更短。
QString edgeLabel(EventType t)
{
    switch (t) {
        case EventType::ProcessCreate:    return u("创建进程");
        case EventType::ProcessTerminate: return u("结束进程");
        case EventType::RemoteThread:     return u("远程线程注入");
        case EventType::ImageLoad:        return u("加载模块");
        case EventType::FileWrite:        return u("写入文件");
        case EventType::FileDelete:       return u("删除文件");
        case EventType::RegistryWrite:    return u("写注册表");
        case EventType::NetworkConnect:   return u("网络外联");
        case EventType::SelfProtect:      return u("触碰自我保护");
        case EventType::DnsQuery:         return u("DNS 解析");
    }
    return u("行为");
}

// 事件目标该落在哪一类节点上。ProcessCreate / ProcessTerminate / RemoteThread 的目标是进程,
// 由调用处单独处理(目标进程可能有 PID),这里只给「非进程」目标定类。
AttackNodeKind targetKind(EventType t)
{
    switch (t) {
        case EventType::FileWrite:
        case EventType::FileDelete:      return AttackNodeKind::File;
        case EventType::RegistryWrite:   return AttackNodeKind::Registry;
        case EventType::NetworkConnect:  return AttackNodeKind::Network;
        case EventType::DnsQuery:        return AttackNodeKind::Domain;
        case EventType::ImageLoad:       return AttackNodeKind::Module;
        default:                         return AttackNodeKind::Process;
    }
}

bool blockedForReal(EnforcementOutcome o)
{
    return o == EnforcementOutcome::KernelBlocked || o == EnforcementOutcome::Terminated;
}

// 合并同一 (起点,终点,类型) 的多次行为:保留最严重的那次。
bool moreSevere(const AttackGraphEdge& a, const AttackGraphEdge& b)
{
    if (a.riskScore != b.riskScore) return a.riskScore > b.riskScore;
    const int sa = (a.action == VerdictAction::Block) ? 2 : (a.action == VerdictAction::Ask ? 1 : 0);
    const int sb = (b.action == VerdictAction::Block) ? 2 : (b.action == VerdictAction::Ask ? 1 : 0);
    if (sa != sb) return sa > sb;
    if (a.hasThreatIndicator != b.hasThreatIndicator) return a.hasThreatIndicator;
    return a.timestampUtc > b.timestampUtc;
}

QString processNodeId(int pid) { return QStringLiteral("p:") + QString::number(pid); }

// 图构建的可变状态。
struct Builder {
    AttackGraph g;
    QHash<QString, int> index;                 // nodeId -> nodes[] 下标
    QHash<QString, int> edgeIndex;             // "from|to|type" -> edges[] 下标
    int maxNodes = 160;
    int maxEdges = 320;

    AttackGraphNode* node(const QString& id)
    {
        auto it = index.constFind(id);
        return it == index.constEnd() ? nullptr : &g.nodes[it.value()];
    }

    // 取或建节点;超上限返回 nullptr(并标记截断)。
    AttackGraphNode* ensure(const QString& id, AttackNodeKind kind, const QString& label,
                           const QString& detail = QString())
    {
        if (id.isEmpty())
            return nullptr;
        if (AttackGraphNode* existing = node(id)) {
            if (existing->label.isEmpty()) existing->label = label;
            if (existing->detail.isEmpty()) existing->detail = detail;
            return existing;
        }
        if (g.nodes.size() >= maxNodes) {
            g.truncated = true;
            return nullptr;
        }
        AttackGraphNode n;
        n.id = id;
        n.kind = kind;
        n.label = label;
        n.detail = detail;
        index.insert(id, g.nodes.size());
        g.nodes.append(n);
        return &g.nodes.last();
    }

    void touch(AttackGraphNode* n, const QDateTime& ts, int risk, bool blocked)
    {
        if (!n) return;
        if (ts.isValid()) {
            if (!n->firstSeenUtc.isValid() || ts < n->firstSeenUtc) n->firstSeenUtc = ts;
            if (!n->lastSeenUtc.isValid() || ts > n->lastSeenUtc) n->lastSeenUtc = ts;
        }
        n->riskScore = std::max(n->riskScore, risk);
        n->blocked = n->blocked || blocked;
    }

    void addEdge(const AttackGraphEdge& e)
    {
        if (e.fromId.isEmpty() || e.toId.isEmpty() || e.fromId == e.toId)
            return;
        const QString key = e.fromId + QLatin1Char('|') + e.toId + QLatin1Char('|')
                          + QString::number(static_cast<int>(e.type))
                          + (e.inferred ? QLatin1String("|i") : QLatin1String(""));
        auto it = edgeIndex.constFind(key);
        if (it != edgeIndex.constEnd()) {
            AttackGraphEdge& cur = g.edges[it.value()];
            if (moreSevere(e, cur)) {
                const QStringList keepTech = cur.techniques;
                cur = e;
                for (const QString& t : keepTech)
                    if (!cur.techniques.contains(t)) cur.techniques << t;
            } else {
                for (const QString& t : e.techniques)
                    if (!cur.techniques.contains(t)) cur.techniques << t;
            }
            return;
        }
        if (g.edges.size() >= maxEdges) {
            g.truncated = true;
            return;
        }
        edgeIndex.insert(key, g.edges.size());
        g.edges.append(e);
    }
};

// 进程节点的属性补齐(来自一条以它为主体的事件)。
void fillProcess(AttackGraphNode* n, const SecurityEvent& e)
{
    if (!n) return;
    n->pid = e.actorPid;
    if (n->parentPid <= 0 && e.parentPid > 0) n->parentPid = e.parentPid;
    if (n->path.isEmpty() && !isPlaceholderPath(e.actorPath)) {
        n->path = e.actorPath;
        n->detail = e.actorPath;
        if (n->label.isEmpty() || n->label.startsWith(QLatin1String("PID ")))
            n->label = shortLabel(e.actorPath);
    }
    if (n->commandLine.isEmpty() && !e.commandLine.isEmpty())
        n->commandLine = truncate(e.commandLine, 512);
    if (e.actorSigned) n->signedActor = true;
    if (n->publisher.isEmpty()) n->publisher = e.actorPublisher;
    if (n->originKind == bulwark::ProcessOriginKind::Unknown
        && e.originKind != bulwark::ProcessOriginKind::Unknown) {
        n->originKind = e.originKind;
        n->originLabel = e.originLabel();
    }
    ++n->eventCount;
}

// 从链上下文快照补齐一个祖先进程节点(没有以它为主体的事件时的兜底)。
void fillFromChain(AttackGraphNode* n, const bulwark::ChainEventInfo& c)
{
    if (!n) return;
    n->pid = c.actorPid;
    if (n->parentPid <= 0 && c.parentPid > 0) n->parentPid = c.parentPid;
    if (n->path.isEmpty() && !isPlaceholderPath(c.actorPath)) {
        n->path = c.actorPath;
        n->detail = c.actorPath;
        if (n->label.isEmpty() || n->label.startsWith(QLatin1String("PID ")))
            n->label = shortLabel(c.actorPath);
    }
    if (n->commandLine.isEmpty() && !c.commandLine.isEmpty())
        n->commandLine = truncate(c.commandLine, 512);
    if (n->originKind == bulwark::ProcessOriginKind::Unknown
        && c.originKind != bulwark::ProcessOriginKind::Unknown) {
        n->originKind = c.originKind;
        n->originLabel = c.originLabel;
    }
}

} // namespace

AttackGraph AttackGraphBuilder::build(const QList<Input>& events, const QUuid& seedEventId,
                                      int rootPid, const Options& opt)
{
    Builder b;
    b.maxNodes = std::max(8, opt.maxNodes);
    b.maxEdges = std::max(8, opt.maxEdges);

    if (events.isEmpty())
        return b.g;

    // ---- 1) 父子关系:优先取「进程创建」记录(最权威),其次取任意事件的 parentPid,
    //         最后并入链上下文快照(富化阶段用 OS API 回溯出来的祖先链)。 -------------
    QHash<int, int> parentOf;
    QHash<int, bulwark::ChainEventInfo> chainByPid;
    auto learnParent = [&parentOf](int child, int parent, bool authoritative) {
        if (child <= 0 || parent <= 0 || child == parent)
            return;
        if (authoritative || !parentOf.contains(child))
            parentOf.insert(child, parent);
    };
    for (const Input& in : events) {
        const SecurityEvent& e = in.event;
        learnParent(e.actorPid, e.parentPid, e.type == EventType::ProcessCreate);
        for (const bulwark::ChainEventInfo& c : e.chainContext) {
            learnParent(c.actorPid, c.parentPid, false);
            if (c.actorPid > 0 && !chainByPid.contains(c.actorPid))
                chainByPid.insert(c.actorPid, c);
        }
    }

    // ---- 2) 定位种子 -----------------------------------------------------------
    const Input* seed = nullptr;
    if (!seedEventId.isNull()) {
        for (const Input& in : events)
            if (in.event.id == seedEventId) { seed = &in; break; }
    }
    if (!seed && rootPid > 0) {
        for (const Input& in : events)
            if (in.event.actorPid == rootPid
                && (!seed || in.event.timestampUtc > seed->event.timestampUtc))
                seed = &in;
    }
    if (!seed)
        return b.g;

    const int seedPid = seed->event.actorPid > 0 ? seed->event.actorPid : rootPid;
    b.g.seedEventId = seed->event.id;

    // ---- 3) 关联范围:祖先链(限层)+ 自身 + 全部后代 ---------------------------
    QList<int> ancestors;    // 由近到远
    {
        QSet<int> guard;
        int cur = seedPid;
        guard.insert(cur);
        for (int depth = 0; depth < std::max(0, opt.maxAncestorDepth); ++depth) {
            const int p = parentOf.value(cur, 0);
            if (p <= 0 || guard.contains(p))
                break;
            ancestors.append(p);
            guard.insert(p);
            cur = p;
        }
    }

    QHash<int, QList<int>> childrenOf;
    for (auto it = parentOf.constBegin(); it != parentOf.constEnd(); ++it)
        childrenOf[it.value()].append(it.key());

    QSet<int> family;
    family.insert(seedPid);
    for (int a : ancestors)
        family.insert(a);
    {
        QList<int> stack{seedPid};
        while (!stack.isEmpty()) {
            const int pid = stack.takeLast();
            for (int child : childrenOf.value(pid)) {
                if (family.contains(child))
                    continue;
                family.insert(child);
                stack.append(child);
                if (family.size() > b.maxNodes) { b.g.truncated = true; break; }
            }
            if (family.size() > b.maxNodes) { b.g.truncated = true; break; }
        }
    }

    const int graphRootPid = ancestors.isEmpty() ? seedPid : ancestors.last();
    b.g.rootPid = graphRootPid;

    // ---- 4) 先把进程骨架建起来(祖先链自上而下,保证层序稳定)------------------
    for (int i = ancestors.size() - 1; i >= 0; --i) {
        const int pid = ancestors[i];
        AttackGraphNode* n = b.ensure(processNodeId(pid), AttackNodeKind::Process,
                                      QStringLiteral("PID %1").arg(pid));
        if (n) {
            n->pid = pid;
            n->parentPid = parentOf.value(pid, 0);
            if (chainByPid.contains(pid)) fillFromChain(n, chainByPid.value(pid));
        }
    }
    if (AttackGraphNode* sn = b.ensure(processNodeId(seedPid), AttackNodeKind::Process,
                                       QStringLiteral("PID %1").arg(seedPid))) {
        sn->pid = seedPid;
        sn->isSeed = true;
        sn->parentPid = parentOf.value(seedPid, 0);
        if (chainByPid.contains(seedPid)) fillFromChain(sn, chainByPid.value(seedPid));
    }

    // ---- 5) 逐事件建边 --------------------------------------------------------
    QSet<QString> explicitCreate; // "parentId>childId":已有真实 ProcessCreate 事件,无需再推导虚边
    int included = 0;
    for (const Input& in : events) {
        const SecurityEvent& e = in.event;
        if (e.actorPid > 0 && !family.contains(e.actorPid))
            continue;
        ++included;

        const bool blocked = blockedForReal(in.enforcement);
        AttackGraphNode* actor = b.ensure(processNodeId(e.actorPid), AttackNodeKind::Process,
                                          shortLabel(e.actorPath).isEmpty()
                                              ? QStringLiteral("PID %1").arg(e.actorPid)
                                              : shortLabel(e.actorPath),
                                          e.actorPath);
        fillProcess(actor, e);
        b.touch(actor, e.timestampUtc, e.riskScore, blocked);

        for (const QString& t : e.techniques)
            if (!b.g.techniques.contains(t)) b.g.techniques << t;
        b.g.maxRiskScore = std::max(b.g.maxRiskScore, e.riskScore);
        if (e.timestampUtc.isValid()) {
            if (!b.g.firstUtc.isValid() || e.timestampUtc < b.g.firstUtc) b.g.firstUtc = e.timestampUtc;
            if (!b.g.lastUtc.isValid() || e.timestampUtc > b.g.lastUtc) b.g.lastUtc = e.timestampUtc;
        }

        AttackGraphEdge edge;
        edge.eventId = e.id;
        edge.type = e.type;
        edge.label = edgeLabel(e.type);
        edge.detail = e.detail;
        edge.timestampUtc = e.timestampUtc;
        edge.riskScore = e.riskScore;
        edge.action = in.action;
        edge.enforcement = in.enforcement;
        edge.hasThreatIndicator = e.hasThreatIndicator;
        edge.techniques = e.techniques;

        if (e.type == EventType::ProcessCreate) {
            // 主体是【新进程】,父进程才是发起方 —— 边的方向是 父 -> 子。
            const int creator = e.parentPid;
            if (creator > 0) {
                AttackGraphNode* pn = b.ensure(processNodeId(creator), AttackNodeKind::Process,
                                               shortLabel(e.parentPath).isEmpty()
                                                   ? QStringLiteral("PID %1").arg(creator)
                                                   : shortLabel(e.parentPath),
                                               e.parentPath);
                if (pn) {
                    pn->pid = creator;
                    if (pn->path.isEmpty() && !isPlaceholderPath(e.parentPath)) {
                        pn->path = e.parentPath;
                        pn->detail = e.parentPath;
                    }
                    b.touch(pn, e.timestampUtc, 0, false);
                }
                edge.fromId = processNodeId(creator);
                edge.toId = processNodeId(e.actorPid);
                edge.detail = e.commandLine.isEmpty() ? e.detail : truncate(e.commandLine, 256);
                explicitCreate.insert(edge.fromId + QLatin1Char('>') + edge.toId);
                b.addEdge(edge);
            }
        } else if (e.type == EventType::RemoteThread || e.type == EventType::ProcessTerminate) {
            // 目标是另一个进程:目标串多为路径或 "PID n",尽力解析成进程节点,否则退化成实体节点。
            QString targetId;
            const QString target = e.target.trimmed();
            bool ok = false;
            int tpid = 0;
            if (target.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
                tpid = target.mid(4).trimmed().section(QLatin1Char(' '), 0, 0).toInt(&ok);
            if (ok && tpid > 0) {
                targetId = processNodeId(tpid);
                AttackGraphNode* tn = b.ensure(targetId, AttackNodeKind::Process,
                                               QStringLiteral("PID %1").arg(tpid));
                if (tn) { tn->pid = tpid; b.touch(tn, e.timestampUtc, e.riskScore, blocked); }
            } else if (!target.isEmpty()) {
                targetId = QStringLiteral("p:t:") + normalizeKey(target);
                AttackGraphNode* tn = b.ensure(targetId, AttackNodeKind::Process,
                                               shortLabel(target).isEmpty() ? target : shortLabel(target),
                                               target);
                b.touch(tn, e.timestampUtc, e.riskScore, blocked);
            }
            edge.fromId = processNodeId(e.actorPid);
            edge.toId = targetId;
            b.addEdge(edge);
        } else {
            const QString target = e.target.trimmed();
            if (!target.isEmpty()) {
                const AttackNodeKind kind = targetKind(e.type);
                QString prefix;
                switch (kind) {
                    case AttackNodeKind::File:     prefix = QStringLiteral("f:"); break;
                    case AttackNodeKind::Registry: prefix = QStringLiteral("r:"); break;
                    case AttackNodeKind::Network:  prefix = QStringLiteral("n:"); break;
                    case AttackNodeKind::Domain:   prefix = QStringLiteral("d:"); break;
                    case AttackNodeKind::Module:   prefix = QStringLiteral("m:"); break;
                    default:                       prefix = QStringLiteral("x:"); break;
                }
                const QString id = prefix + normalizeKey(target);
                QString label = target;
                if (kind == AttackNodeKind::File || kind == AttackNodeKind::Module)
                    label = shortLabel(target).isEmpty() ? target : shortLabel(target);
                else if (kind == AttackNodeKind::Registry)
                    label = target.section(QLatin1Char('\\'), -2);
                AttackGraphNode* tn = b.ensure(id, kind, label, target);
                b.touch(tn, e.timestampUtc, e.riskScore, blocked);
                edge.fromId = processNodeId(e.actorPid);
                edge.toId = id;
                b.addEdge(edge);
            }
        }

        // RPC 代理写入(如创建服务经 services.exe 代写):把真凶补成一条虚边,
        // 否则图上只看到 services.exe 在写注册表,看不到是谁让它写的。
        if (e.originatorPid > 0 && e.originatorPid != e.actorPid) {
            AttackGraphNode* on = b.ensure(processNodeId(e.originatorPid), AttackNodeKind::Process,
                                           shortLabel(e.originatorPath).isEmpty()
                                               ? QStringLiteral("PID %1").arg(e.originatorPid)
                                               : shortLabel(e.originatorPath),
                                           e.originatorPath);
            if (on) {
                on->pid = e.originatorPid;
                if (on->path.isEmpty() && !isPlaceholderPath(e.originatorPath)) {
                    on->path = e.originatorPath;
                    on->detail = e.originatorPath;
                }
                b.touch(on, e.timestampUtc, e.riskScore, blocked);
            }
            AttackGraphEdge rpc;
            rpc.eventId = e.id;
            rpc.fromId = processNodeId(e.originatorPid);
            rpc.toId = processNodeId(e.actorPid);
            rpc.type = e.type;
            rpc.label = u("经 RPC 代理");
            rpc.timestampUtc = e.timestampUtc;
            rpc.riskScore = e.riskScore;
            rpc.action = in.action;
            rpc.enforcement = in.enforcement;
            rpc.inferred = true;
            b.addEdge(rpc);
        }
    }
    b.g.eventCount = included;

    // ---- 6) 补齐进程树的推导边(有父子关系但没观测到创建事件的情况)---------------
    for (int i = 0; i < b.g.nodes.size(); ++i) {
        const AttackGraphNode& n = b.g.nodes[i];
        if (n.kind != AttackNodeKind::Process || n.pid <= 0)
            continue;
        const int parent = parentOf.value(n.pid, n.parentPid);
        if (parent <= 0 || parent == n.pid || !b.index.contains(processNodeId(parent)))
            continue;
        const QString key = processNodeId(parent) + QLatin1Char('>') + n.id;
        if (explicitCreate.contains(key))
            continue;
        AttackGraphEdge e;
        e.fromId = processNodeId(parent);
        e.toId = n.id;
        e.type = EventType::ProcessCreate;
        e.label = u("派生");
        e.timestampUtc = n.firstSeenUtc;
        e.inferred = true;
        b.addEdge(e);
    }

    // ---- 7) 启动来源节点:服务 / 计划任务 -> 进程。这是把 svchost.exe 这类宿主还原成
    //         「具体是哪个服务 / 哪个任务」的地方,溯源到此才算闭环。 -------------------
    {
        const int existing = b.g.nodes.size();
        for (int i = 0; i < existing; ++i) {
            const AttackGraphNode n = b.g.nodes[i]; // 拷贝:下面会往 nodes 里追加
            if (n.kind != AttackNodeKind::Process)
                continue;
            QString originId;
            AttackNodeKind kind = AttackNodeKind::Service;
            QString label, detail;
            if (n.originKind == bulwark::ProcessOriginKind::Service && !n.originLabel.isEmpty()) {
                originId = QStringLiteral("svc:") + normalizeKey(n.originLabel);
                label = n.originLabel;
                detail = u("Windows 服务");
            } else if (n.originKind == bulwark::ProcessOriginKind::ScheduledTask
                       && !n.originLabel.isEmpty()) {
                originId = QStringLiteral("task:") + normalizeKey(n.originLabel);
                kind = AttackNodeKind::ScheduledTask;
                label = n.originLabel;
                detail = u("计划任务");
            }
            if (originId.isEmpty())
                continue;
            AttackGraphNode* on = b.ensure(originId, kind, label, detail);
            if (!on)
                continue;
            b.touch(on, n.firstSeenUtc, n.riskScore, false);
            AttackGraphEdge e;
            e.fromId = originId;
            e.toId = n.id;
            e.type = EventType::ProcessCreate;
            e.label = (kind == AttackNodeKind::Service) ? u("服务启动") : u("计划任务启动");
            e.timestampUtc = n.firstSeenUtc;
            e.inferred = true;
            b.addEdge(e);
        }
    }

    // ---- 8) 层号(供 UI 分层布局):进程按父子链定层,实体节点挂在其主体的下一层 ------
    {
        QHash<QString, int> depth;
        depth.insert(processNodeId(graphRootPid), 0);
        bool changed = true;
        for (int pass = 0; pass < 24 && changed; ++pass) {
            changed = false;
            for (const AttackGraphEdge& e : b.g.edges) {
                if (!depth.contains(e.fromId))
                    continue;
                const int want = depth.value(e.fromId) + 1;
                if (!depth.contains(e.toId) || depth.value(e.toId) < want) {
                    // 只允许向下加深一次性收敛(避免环导致无限增长)。
                    if (!depth.contains(e.toId)) { depth.insert(e.toId, want); changed = true; }
                }
            }
        }
        // 起点未定层的(例如服务/任务节点)放到其唯一后继之上。
        for (const AttackGraphEdge& e : b.g.edges) {
            if (!depth.contains(e.fromId) && depth.contains(e.toId))
                depth.insert(e.fromId, std::max(0, depth.value(e.toId) - 1));
        }
        for (AttackGraphNode& n : b.g.nodes) {
            n.depth = depth.value(n.id, 0);
            n.isRoot = (n.kind == AttackNodeKind::Process && n.pid == graphRootPid);
        }
    }

    if (const AttackGraphNode* root = b.node(processNodeId(graphRootPid)))
        b.g.rootLabel = root->label.isEmpty() ? QStringLiteral("PID %1").arg(graphRootPid) : root->label;

    // ---- 9) 概述 ---------------------------------------------------------------
    int procCount = 0, blockedCount = 0;
    for (const AttackGraphNode& n : b.g.nodes)
        if (n.kind == AttackNodeKind::Process) ++procCount;
    for (const AttackGraphEdge& e : b.g.edges)
        if (!e.inferred && blockedForReal(e.enforcement)) ++blockedCount;
    QStringList parts;
    parts << u("%1 个进程").arg(procCount);
    parts << u("%1 次行为").arg(b.g.eventCount);
    if (blockedCount > 0) parts << u("已拦截 %1 次").arg(blockedCount);
    if (b.g.maxRiskScore > 0) parts << u("最高风险 %1").arg(b.g.maxRiskScore);
    if (b.g.truncated) parts << u("已截断");
    b.g.summary = parts.join(u("  ·  "));

    return b.g;
}

} // namespace bulwark::engine
