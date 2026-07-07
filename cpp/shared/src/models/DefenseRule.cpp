#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/json/JsonSupport.h"
#include <QJsonArray>

namespace bulwark {
using namespace bulwark::json;

QString DefenseRule::trustNoteTag() {
    return QStringLiteral("[\u4fe1\u4efb]"); // "[信任]" —— 与 .NET DefenseRule.TrustNoteTag 一致
}

bool DefenseRule::matches(const SecurityEvent& e) const {
    if (!enabled) return false;
    // 到期规则视为失效(存储侧也会清理,这里是运行时兜底)。
    if (expiresUtc.has_value() && *expiresUtc <= QDateTime::currentDateTimeUtc()) return false;

    if (type.has_value() && *type != e.type) return false;

    if (requireUnsigned && e.actorSigned) return false;

    if (!actorHashes.isEmpty()) {
        if (e.actorHash.isEmpty()) return false;
        const QString h = e.actorHash.toUpper();
        bool found = false;
        for (const QString& x : actorHashes) {
            if (x.toUpper() == h) { found = true; break; }
        }
        if (!found) return false;
    }

    if (!actorPath.isEmpty() &&
        actorPath.compare(e.actorPath, Qt::CaseInsensitive) != 0)
        return false;

    if (!actorPattern.isEmpty() && !wildcardMatch(actorPattern, e.actorPath))
        return false;

    if (!commandLinePattern.isEmpty() && !wildcardMatch(commandLinePattern, e.commandLine))
        return false;

    if (!parentPattern.isEmpty() && !wildcardMatch(parentPattern, e.parentPath))
        return false;

    if (!targetPattern.isEmpty()) {
        const bool matchTarget = wildcardMatch(targetPattern, e.target);
        // 仅 ProcessCreate 允许 TargetPattern 回退匹配主体路径(Target 常只是进程名)。
        // 对 RemoteThread/ProcessTerminate 绝不回退,避免按受害进程写的规则误伤发起方。
        const bool allowActorFallback = (e.type == EventType::ProcessCreate);
        const bool matchActor = allowActorFallback && !e.actorPath.isEmpty() &&
                                wildcardMatch(targetPattern, e.actorPath);
        if (!matchTarget && !matchActor) return false;
    }

    return true;
}

int DefenseRule::specificityScore() const {
    int s = 0;
    if (!actorPath.isEmpty()) s += 3;
    if (!actorPattern.isEmpty()) s += 2;
    if (!commandLinePattern.isEmpty()) s += 2;
    if (!parentPattern.isEmpty()) s += 2;
    if (!targetPattern.isEmpty()) s += 1;
    if (type.has_value()) s += 1;
    if (requireUnsigned) s += 1;
    if (!actorHashes.isEmpty()) s += 4; // 哈希精确匹配,最具体
    return s;
}

DefenseRule DefenseRule::createTrust(const QString& actorPath, const QString& note) {
    DefenseRule r;
    r.actorPath = actorPath.trimmed();
    r.type = std::nullopt;
    r.action = VerdictAction::Allow;
    const QString n = note.trimmed();
    r.note = n.isEmpty() ? (trustNoteTag() + QStringLiteral(" \u6587\u4ef6\u4fe1\u4efb\u4e2d\u5fc3"))
                         : (trustNoteTag() + QStringLiteral(" ") + n);
    return r;
}

DefenseRule DefenseRule::createTrustDirectory(const QString& dirPath, const QString& note) {
    DefenseRule r;
    QString d = dirPath.trimmed();
    while (d.endsWith(QLatin1Char('\\')) || d.endsWith(QLatin1Char('/'))) d.chop(1);
    r.actorPattern = d + QStringLiteral("\\*"); // 目录下所有主体
    r.type = std::nullopt;
    r.action = VerdictAction::Allow;
    const QString n = note.trimmed();
    r.note = n.isEmpty() ? (trustNoteTag() + QStringLiteral(" \u76ee\u5f55\u4fe1\u4efb: ") + d)
                         : (trustNoteTag() + QStringLiteral(" ") + n);
    return r;
}

bool DefenseRule::wildcardMatch(const QString& pattern, const QString& input) {
    if (pattern.isEmpty()) return true;
    const int pl = pattern.size();
    const int sl = input.size();
    int p = 0, s = 0, star = -1, mark = 0;
    while (s < sl) {
        if (p < pl && (pattern[p] == QLatin1Char('?') ||
                       pattern[p].toUpper() == input[s].toUpper())) {
            ++p; ++s;
        } else if (p < pl && pattern[p] == QLatin1Char('*')) {
            star = p++; mark = s;
        } else if (star != -1) {
            p = star + 1; s = ++mark;
        } else {
            return false;
        }
    }
    while (p < pl && pattern[p] == QLatin1Char('*')) ++p;
    return p == pl;
}

QJsonObject DefenseRule::toJson() const {
    QJsonObject o;
    o["id"] = guidToString(id);
    o["actorPath"] = actorPath;
    o["actorPattern"] = actorPattern;
    o["type"] = type.has_value() ? QJsonValue(static_cast<int>(*type))
                                 : QJsonValue(QJsonValue::Null);
    o["targetPattern"] = targetPattern;
    o["commandLinePattern"] = commandLinePattern;
    o["parentPattern"] = parentPattern;
    o["requireUnsigned"] = requireUnsigned;
    o["exemptTrustedOsComponent"] = exemptTrustedOsComponent;
    o["hardOverride"] = hardOverride;
    QJsonArray hashes;
    for (const QString& h : actorHashes) hashes.append(h);
    o["actorHashes"] = hashes;
    o["action"] = static_cast<int>(action);
    o["note"] = note;
    o["createdUtc"] = dateTimeToIso(createdUtc);
    o["expiresUtc"] = optDateToJson(expiresUtc);
    o["sessionOnly"] = sessionOnly;
    o["enabled"] = enabled;
    return o;
}

DefenseRule DefenseRule::fromJson(const QJsonObject& o) {
    DefenseRule r;
    const QUuid parsedId = guidFromString(getStr(o, "id"));
    if (!parsedId.isNull()) r.id = parsedId;
    r.actorPath = getStr(o, "actorPath");
    r.actorPattern = getStr(o, "actorPattern");
    const QJsonValue tv = o.value(QLatin1String("type"));
    r.type = tv.isDouble() ? std::optional<EventType>(static_cast<EventType>(tv.toInt()))
                           : std::nullopt;
    r.targetPattern = getStr(o, "targetPattern");
    r.commandLinePattern = getStr(o, "commandLinePattern");
    r.parentPattern = getStr(o, "parentPattern");
    r.requireUnsigned = getBool(o, "requireUnsigned");
    r.exemptTrustedOsComponent = getBool(o, "exemptTrustedOsComponent");
    r.hardOverride = getBool(o, "hardOverride");
    r.actorHashes.clear();
    const QJsonArray hashes = o.value(QLatin1String("actorHashes")).toArray();
    for (const QJsonValue& v : hashes) {
        const QString h = v.toString();
        if (!h.isEmpty()) r.actorHashes.insert(h);
    }
    r.action = static_cast<VerdictAction>(getInt(o, "action"));
    r.note = getStr(o, "note");
    const QDateTime c = dateTimeFromIso(getStr(o, "createdUtc"));
    if (c.isValid()) r.createdUtc = c;
    r.expiresUtc = optDateFromJson(o.value(QLatin1String("expiresUtc")));
    r.sessionOnly = getBool(o, "sessionOnly");
    r.enabled = getBool(o, "enabled", true);
    return r;
}

} // namespace bulwark
