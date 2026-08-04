#include "bulwark/engine/EcsAlertFormatter.h"
#include "bulwark/engine/AttackCatalog.h"
#include "bulwark/json/JsonSupport.h"

#include <QDateTime>
#include <QFileInfo>
#include <QJsonArray>
#include <QSet>

namespace bulwark::engine {
namespace {

using bulwark::EventType;
using bulwark::SecurityEvent;
using bulwark::Verdict;
using bulwark::VerdictAction;

// File name of a path (empty for empty input); mirrors Path.GetFileName.
QString safeName(const QString& path) {
    if (path.isEmpty()) return QString();
    return QFileInfo(path).fileName();
}

// Lightweight IPAddress.TryParse stand-in (shared lib links Qt6::Core only, so
// no QHostAddress): IPv4 dotted-quad, or anything containing ':' as IPv6-ish.
bool isLikelyIp(const QString& host) {
    if (host.contains(QLatin1Char(':'))) return true;
    const QStringList parts = host.split(QLatin1Char('.'));
    if (parts.size() != 4) return false;
    for (const QString& p : parts) {
        bool ok = false;
        const int n = p.toInt(&ok);
        if (!ok || n < 0 || n > 255) return false;
    }
    return true;
}

// ECS event.severity: coarse 4-level mapping by risk score.
int severityOf(int risk) {
    if (risk >= 80) return 3;
    if (risk >= 50) return 2;
    if (risk > 0) return 1;
    return 0;
}

QString signatureStatus(const SecurityEvent& e) {
    if (!e.actorSigned && !e.signatureMismatch) return QStringLiteral("unsigned");
    if (e.signatureMismatch) return QStringLiteral("tampered");
    if (e.certRevoked) return QStringLiteral("revoked");
    if (e.signedAfterCertExpiry) return QStringLiteral("expired");
    return QStringLiteral("valid");
}

QString eventTypeToEcs(EventType t) {
    switch (t) {
        case EventType::ProcessCreate:    return QStringLiteral("start");
        case EventType::ProcessTerminate: return QStringLiteral("end");
        case EventType::NetworkConnect:   return QStringLiteral("connection");
        case EventType::FileWrite:        return QStringLiteral("change");
        case EventType::FileDelete:       return QStringLiteral("deletion");
        case EventType::RegistryWrite:    return QStringLiteral("change");
        case EventType::ImageLoad:        return QStringLiteral("info");
        case EventType::RemoteThread:     return QStringLiteral("access");
        case EventType::DnsQuery:         return QStringLiteral("protocol");
        default:                          return QStringLiteral("info");
    }
}

QJsonObject buildEvent(const SecurityEvent& e, const Verdict& v) {
    const QString action = v.action == VerdictAction::Block ? QStringLiteral("blocked")
                         : v.action == VerdictAction::Ask   ? QStringLiteral("prompted")
                                                            : QStringLiteral("allowed");
    QJsonArray categories;
    if (e.hasThreatIndicator || v.action == VerdictAction::Block)
        categories.append(QStringLiteral("intrusion_detection"));
    categories.append((e.type == EventType::NetworkConnect || e.type == EventType::DnsQuery)
                          ? QStringLiteral("network") : QStringLiteral("process"));

    QJsonArray typeArr;
    typeArr.append(eventTypeToEcs(e.type));

    QJsonObject ev;
    ev[QStringLiteral("kind")] =
        (e.hasThreatIndicator || v.action == VerdictAction::Block) ? QStringLiteral("alert")
                                                                   : QStringLiteral("event");
    ev[QStringLiteral("category")] = categories;
    ev[QStringLiteral("action")] = action;
    ev[QStringLiteral("type")] = typeArr;
    ev[QStringLiteral("outcome")] = QStringLiteral("success");
    ev[QStringLiteral("risk_score")] = e.riskScore;
    ev[QStringLiteral("severity")] = severityOf(e.riskScore);
    ev[QStringLiteral("provider")] = QStringLiteral("Bulwark");
    ev[QStringLiteral("module")] = bulwark::eventTypeToString(e.type);
    ev[QStringLiteral("reason")] = bulwark::verdictSourceToString(v.source);
    return ev;
}

QJsonObject buildProcess(const SecurityEvent& e) {
    QJsonObject proc;
    proc[QStringLiteral("executable")] = e.actorPath;
    proc[QStringLiteral("name")] = safeName(e.actorPath);
    proc[QStringLiteral("pid")] = e.actorPid;
    if (!e.commandLine.isEmpty()) proc[QStringLiteral("command_line")] = e.commandLine;
    if (!e.actorHash.isEmpty()) {
        QJsonObject h;
        h[QStringLiteral("sha256")] = e.actorHash;
        proc[QStringLiteral("hash")] = h;
    }
    QJsonObject sig;
    sig[QStringLiteral("exists")] = e.actorSigned || e.signatureMismatch;
    sig[QStringLiteral("trusted")] =
        e.actorSigned && !e.signatureMismatch && !e.certRevoked && !e.signedAfterCertExpiry;
    sig[QStringLiteral("valid")] = e.actorSigned && !e.signatureMismatch;
    sig[QStringLiteral("subject_name")] = e.actorPublisher;
    sig[QStringLiteral("status")] = signatureStatus(e);
    proc[QStringLiteral("code_signature")] = sig;

    if (e.parentPid != 0 || !e.parentPath.isEmpty()) {
        QJsonObject parent;
        parent[QStringLiteral("executable")] = e.parentPath;
        parent[QStringLiteral("name")] = safeName(e.parentPath);
        parent[QStringLiteral("pid")] = e.parentPid;
        proc[QStringLiteral("parent")] = parent;
    }
    return proc;
}

QJsonObject buildDestination(const QString& target) {
    QJsonObject dest;
    QString host = target;
    const int colon = target.lastIndexOf(QLatin1Char(':'));
    if (colon > 0 && colon < target.size() - 1) {
        const QString suffix = target.mid(colon + 1);
        bool allDigits = !suffix.isEmpty();
        for (const QChar& c : suffix)
            if (!c.isDigit()) { allDigits = false; break; }
        if (allDigits) {
            host = target.left(colon);
            bool ok = false;
            const int port = suffix.toInt(&ok);
            if (ok) dest[QStringLiteral("port")] = port;
        }
    }
    dest[QStringLiteral("address")] = host;
    if (isLikelyIp(host)) dest[QStringLiteral("ip")] = host;
    else dest[QStringLiteral("domain")] = host;
    return dest;
}

} // namespace
} // namespace bulwark::engine

namespace bulwark::engine {
namespace {

// Distinct annotated ATT&CK techniques from the evidence chain -> threat.*.
QJsonObject buildThreat(const SecurityEvent& e, bool& hasAny) {
    QStringList techIds;
    QSet<QString> seen;
    for (const auto& ev : e.evidenceChain) {
        if (ev.technique.isEmpty()) continue;
        const QString low = ev.technique.toLower();
        if (!seen.contains(low)) { seen.insert(low); techIds << ev.technique; }
    }
    hasAny = !techIds.isEmpty();
    if (!hasAny) return QJsonObject();

    QJsonArray techniques, tactics;
    QSet<QString> tacticSeen;
    for (const QString& id : techIds) {
        const auto t = AttackCatalog::lookup(id);
        QJsonObject tech;
        tech[QStringLiteral("id")] = id;
        tech[QStringLiteral("name")] = t.has_value() ? t->name : id;
        techniques.append(tech);
        if (t.has_value() && !tacticSeen.contains(t->tactic.toLower())) {
            tacticSeen.insert(t->tactic.toLower());
            QJsonObject tac;
            tac[QStringLiteral("name")] = t->tactic;
            tactics.append(tac);
        }
    }
    QJsonObject threat;
    threat[QStringLiteral("framework")] = QStringLiteral("MITRE ATT&CK");
    threat[QStringLiteral("technique")] = techniques;
    threat[QStringLiteral("tactic")] = tactics;
    return threat;
}

// bulwark.* extension namespace: verdict + full evidence chain.
QJsonObject buildBulwark(const SecurityEvent& e, const Verdict& v) {
    QJsonObject b;
    b[QStringLiteral("event_id")] = bulwark::json::guidToString(e.id);
    b[QStringLiteral("verdict")] = bulwark::verdictActionToString(v.action);
    b[QStringLiteral("verdict_source")] = bulwark::verdictSourceToString(v.source);
    b[QStringLiteral("has_threat_indicator")] = e.hasThreatIndicator;
    b[QStringLiteral("user_mode_observed")] = e.userModeObserved;
    b[QStringLiteral("reasons")] = QJsonArray::fromStringList(e.riskReasons);
    b[QStringLiteral("techniques")] = QJsonArray::fromStringList(e.techniques);
    QJsonArray evidence;
    for (const auto& ev : e.evidenceChain) {
        QJsonObject o;
        o[QStringLiteral("source")] = ev.source;
        o[QStringLiteral("kind")] = bulwark::evidenceKindToString(ev.kind);
        o[QStringLiteral("description")] = ev.description;
        o[QStringLiteral("score_delta")] = ev.scoreDelta;
        if (!ev.technique.isEmpty()) o[QStringLiteral("technique")] = ev.technique;
        evidence.append(o);
    }
    b[QStringLiteral("evidence")] = evidence;
    return b;
}

QString buildMessage(const SecurityEvent& e, const Verdict& v) {
    const QString act = v.action == VerdictAction::Block ? QString::fromUtf8("\xE6\x8B\xA6\xE6\x88\xAA")   // 拦截
                      : v.action == VerdictAction::Ask   ? QString::fromUtf8("\xE8\xAF\xA2\xE9\x97\xAE")   // 询问
                                                          : QString::fromUtf8("\xE6\x94\xBE\xE8\xA1\x8C"); // 放行
    return QString::fromUtf8("[%1] %2 %3(pid=%4) -> %5 (\xE9\xA3\x8E\xE9\x99\xA9 %6)") // 风险
        .arg(act, bulwark::eventTypeToString(e.type), safeName(e.actorPath))
        .arg(e.actorPid)
        .arg(e.target)
        .arg(e.riskScore);
}

} // namespace

QJsonObject EcsAlertFormatter::format(const bulwark::SecurityEvent& e, const bulwark::Verdict& v) {
    const QDateTime ts = e.timestampUtc.isValid() ? e.timestampUtc.toUTC()
                                                  : nowUtc();
    QJsonObject doc;
    doc[QStringLiteral("@timestamp")] =
        ts.toString(QStringLiteral("yyyy-MM-ddTHH:mm:ss.zzz")) + QStringLiteral("Z");
    QJsonObject ecs;
    ecs[QStringLiteral("version")] = QString::fromLatin1(EcsVersion);
    doc[QStringLiteral("ecs")] = ecs;
    doc[QStringLiteral("event")] = buildEvent(e, v);
    doc[QStringLiteral("message")] = buildMessage(e, v);
    doc[QStringLiteral("process")] = buildProcess(e);

    if (e.type == EventType::NetworkConnect && !e.target.isEmpty())
        doc[QStringLiteral("destination")] = buildDestination(e.target);

    if (e.type == EventType::DnsQuery && !e.target.isEmpty()) {
        QJsonObject question;
        question[QStringLiteral("name")] = e.target;
        QJsonObject dns;
        dns[QStringLiteral("type")] = QStringLiteral("query");
        dns[QStringLiteral("question")] = question;
        doc[QStringLiteral("dns")] = dns;
    }

    if (!e.matchedRuleNote.isEmpty()) {
        QJsonObject rule;
        rule[QStringLiteral("name")] = e.matchedRuleNote;
        doc[QStringLiteral("rule")] = rule;
    }

    bool hasThreat = false;
    const QJsonObject threat = buildThreat(e, hasThreat);
    if (hasThreat) doc[QStringLiteral("threat")] = threat;

    doc[QStringLiteral("bulwark")] = buildBulwark(e, v);
    return doc;
}

} // namespace bulwark::engine
