#include "bulwark/service/BulwarkOptions.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>

namespace bulwark::service {
namespace {

// Case-insensitive key lookup, matching .NET's Configuration binding, which is
// case-insensitive. Exact match first, then a linear case-insensitive scan.
QJsonValue jval(const QJsonObject& o, const char* key) {
    const auto it = o.constFind(QLatin1String(key));
    if (it != o.constEnd()) return it.value();
    const QString k = QString::fromLatin1(key);
    for (auto i = o.constBegin(); i != o.constEnd(); ++i)
        if (i.key().compare(k, Qt::CaseInsensitive) == 0) return i.value();
    return QJsonValue(QJsonValue::Undefined);
}

// Each binder overrides the field ONLY when the key is present (matches Bind:
// absent keys keep their default). Values are read tolerantly because .NET
// configuration models everything as strings and converts on demand.
void bindStr(const QJsonObject& o, const char* key, QString& f) {
    const QJsonValue v = jval(o, key);
    if (v.isString()) f = v.toString();
}

void bindBool(const QJsonObject& o, const char* key, bool& f) {
    const QJsonValue v = jval(o, key);
    if (v.isBool()) {
        f = v.toBool();
    } else if (v.isString()) {
        const QString s = v.toString().trimmed();
        if (s.compare(QLatin1String("true"), Qt::CaseInsensitive) == 0) f = true;
        else if (s.compare(QLatin1String("false"), Qt::CaseInsensitive) == 0) f = false;
    }
}

void bindInt(const QJsonObject& o, const char* key, int& f) {
    const QJsonValue v = jval(o, key);
    if (v.isDouble()) {
        f = v.toInt();
    } else if (v.isString()) {
        bool ok = false;
        const int n = v.toString().trimmed().toInt(&ok);
        if (ok) f = n;
    }
}

void bindStrList(const QJsonObject& o, const char* key, QStringList& f) {
    const QJsonValue v = jval(o, key);
    if (!v.isArray()) return;
    QStringList out;
    const QJsonArray a = v.toArray();
    out.reserve(a.size());
    for (const QJsonValue& e : a)
        if (e.isString()) out << e.toString();
    f = out;
}

void bindVerdictAction(const QJsonObject& o, const char* key, VerdictAction& f) {
    const QJsonValue v = jval(o, key);
    if (v.isString()) {
        const QString s = v.toString().trimmed();
        if (s.compare(QLatin1String("Allow"), Qt::CaseInsensitive) == 0) f = VerdictAction::Allow;
        else if (s.compare(QLatin1String("Block"), Qt::CaseInsensitive) == 0) f = VerdictAction::Block;
        else if (s.compare(QLatin1String("Ask"), Qt::CaseInsensitive) == 0) f = VerdictAction::Ask;
    } else if (v.isDouble()) {
        const int n = v.toInt();
        if (n >= 0 && n <= 2) f = static_cast<VerdictAction>(n);
    }
}

} // namespace

QString AiOptions::resolveApiKey() const {
    const QString env = qEnvironmentVariable(ApiKeyEnvVar).trimmed();
    if (!env.isEmpty()) return env;
    return ApiKey.trimmed();
}

QString ThreatFoxFeedOptions::resolveAuthKey(const QString& malwareBazaarFallback) const {
    const QString env = qEnvironmentVariable(AuthKeyEnvVar).trimmed();
    if (!env.isEmpty()) return env;
    const QString self = AuthKey.trimmed();
    if (!self.isEmpty()) return self;
    return malwareBazaarFallback.trimmed();
}

QString ReputationProxyOptions::resolveToken() const {
    const QString env = qEnvironmentVariable(TokenEnvVar).trimmed();
    if (!env.isEmpty()) return env;
    return BearerToken.trimmed();
}

namespace {
// Fixed XOR key for endpoint obfuscation. This is NOT encryption (the key ships in the
// binary); it only keeps the server URL out of plaintext in shipped/portable appsettings so
// it can't be grepped/edited casually, matching the "hidden endpoint" intent. The real
// access control is the server-side token, never the URL's secrecy.
const QByteArray& obfKey() {
    static const QByteArray k = QByteArrayLiteral(
        "\x42\x75\x6C\x77\x61\x72\x6B\x2D\x52\x65\x70\x50\x72\x6F\x78\x79"
        "\x2D\x4F\x62\x66\x2D\x76\x31\x2D\xA5\x5A\xC3\x3C\x9E\x71\x08\xE4");
    return k;
}

QByteArray xorWithKey(const QByteArray& in) {
    const QByteArray& k = obfKey();
    QByteArray out(in.size(), Qt::Uninitialized);
    for (int i = 0; i < in.size(); ++i)
        out[i] = static_cast<char>(in[i] ^ k[i % k.size()]);
    return out;
}
} // namespace

QString ReputationProxyOptions::obfuscateUrl(const QString& plain) {
    const QString s = plain.trimmed();
    if (s.isEmpty()) return QString();
    return QString::fromLatin1(xorWithKey(s.toUtf8()).toBase64());
}

QString ReputationProxyOptions::deobfuscateUrl(const QString& obfuscated) {
    const QString s = obfuscated.trimmed();
    if (s.isEmpty()) return QString();
    const QByteArray raw = QByteArray::fromBase64(s.toLatin1());
    if (raw.isEmpty()) return QString();
    return QString::fromUtf8(xorWithKey(raw)).trimmed();
}

QString ReputationProxyOptions::resolveBaseUrl() const {
    const QString env = qEnvironmentVariable(UrlEnvVar).trimmed();
    if (!env.isEmpty()) return env;
    const QString plain = BaseUrl.trimmed();
    if (!plain.isEmpty()) return plain;
    return deobfuscateUrl(BaseUrlObfuscated);
}

QString ReputationProxyOptions::maskUrl(const QString& url) {
    const QString u = url.trimmed();
    if (u.isEmpty()) return QStringLiteral("(none)");
    // Keep scheme + optional :port, replace the host with *** so logs never leak the endpoint.
    int schemeEnd = u.indexOf(QStringLiteral("://"));
    const QString scheme = schemeEnd > 0 ? u.left(schemeEnd) : QString();
    QString rest = schemeEnd > 0 ? u.mid(schemeEnd + 3) : u;
    // rest = host[:port][/path...]; drop any path, keep :port if present.
    const int slash = rest.indexOf(QLatin1Char('/'));
    if (slash >= 0) rest = rest.left(slash);
    QString port;
    const int colon = rest.lastIndexOf(QLatin1Char(':'));
    if (colon >= 0) port = rest.mid(colon); // includes ':'
    const QString masked = QStringLiteral("***") + port;
    return scheme.isEmpty() ? masked : (scheme + QStringLiteral("://") + masked);
}

} // namespace bulwark::service

namespace bulwark::service {
namespace {

void bindEtw(const QJsonObject& o, EtwOptions& e) {
    bindBool(o, "Enabled", e.Enabled);
    bindBool(o, "DnsClient", e.DnsClient);
    bindBool(o, "KernelNetwork", e.KernelNetwork);
    bindBool(o, "NetworkUntrustedOnly", e.NetworkUntrustedOnly);
    bindInt(o, "PerProcessNetPerMinute", e.PerProcessNetPerMinute);
    bindBool(o, "SuspiciousOnly", e.SuspiciousOnly);
    bindStr(o, "SessionName", e.SessionName);
    bindInt(o, "RawChannelCapacity", e.RawChannelCapacity);
    bindInt(o, "PerProcessDnsPerMinute", e.PerProcessDnsPerMinute);
    bindInt(o, "DedupWindowSeconds", e.DedupWindowSeconds);
}

void bindAi(const QJsonObject& o, AiOptions& a) {
    bindStr(o, "BaseUrl", a.BaseUrl);
    bindStr(o, "ApiKey", a.ApiKey);
    bindStr(o, "Model", a.Model);
}

void bindMalwareBazaar(const QJsonObject& o, MalwareBazaarOptions& m) {
    bindStr(o, "BaseUrl", m.BaseUrl);
    bindBool(o, "Enabled", m.Enabled);
    bindStr(o, "AuthKey", m.AuthKey);
    bindInt(o, "RequestsPerMinute", m.RequestsPerMinute);
    bindInt(o, "RequestsPerDay", m.RequestsPerDay);
    bindInt(o, "QueryTimeoutSeconds", m.QueryTimeoutSeconds);
}

void bindOtx(const QJsonObject& o, OtxOptions& x) {
    bindStr(o, "BaseUrl", x.BaseUrl);
    bindBool(o, "Enabled", x.Enabled);
    bindStr(o, "ApiKey", x.ApiKey);
    bindInt(o, "RequestsPerMinute", x.RequestsPerMinute);
    bindInt(o, "RequestsPerDay", x.RequestsPerDay);
    bindInt(o, "QueryTimeoutSeconds", x.QueryTimeoutSeconds);
    bindInt(o, "MaliciousPulseThreshold", x.MaliciousPulseThreshold);
}

void bindThreatBook(const QJsonObject& o, ThreatBookOptions& t) {
    bindStr(o, "BaseUrl", t.BaseUrl);
    bindStr(o, "IpIntelBaseUrl", t.IpIntelBaseUrl);
    bindBool(o, "Enabled", t.Enabled);
    bindStr(o, "ApiKey", t.ApiKey);
    bindInt(o, "RequestsPerMinute", t.RequestsPerMinute);
    bindInt(o, "RequestsPerDay", t.RequestsPerDay);
    bindInt(o, "SceneRequestsPerMonth", t.SceneRequestsPerMonth);
    bindBool(o, "NetworkIntelEnabled", t.NetworkIntelEnabled);
    bindInt(o, "QueryTimeoutSeconds", t.QueryTimeoutSeconds);
}

void bindMetaDefender(const QJsonObject& o, MetaDefenderOptions& m) {
    bindStr(o, "BaseUrl", m.BaseUrl);
    bindBool(o, "Enabled", m.Enabled);
    bindStr(o, "ApiKey", m.ApiKey);
    bindInt(o, "RequestsPerMinute", m.RequestsPerMinute);
    bindInt(o, "RequestsPerDay", m.RequestsPerDay);
    bindInt(o, "QueryTimeoutSeconds", m.QueryTimeoutSeconds);
    bindInt(o, "MaliciousThreshold", m.MaliciousThreshold);
}

void bindHybridAnalysis(const QJsonObject& o, HybridAnalysisOptions& h) {
    bindStr(o, "BaseUrl", h.BaseUrl);
    bindBool(o, "Enabled", h.Enabled);
    bindStr(o, "ApiKey", h.ApiKey);
    bindInt(o, "RequestsPerMinute", h.RequestsPerMinute);
    bindInt(o, "RequestsPerDay", h.RequestsPerDay);
    bindInt(o, "QueryTimeoutSeconds", h.QueryTimeoutSeconds);
    bindInt(o, "MaliciousThreatScore", h.MaliciousThreatScore);
}

void bindVirusTotal(const QJsonObject& o, VirusTotalOptions& v) {
    bindStr(o, "BaseUrl", v.BaseUrl);
    bindStr(o, "UploadUrl", v.UploadUrl);
    bindStr(o, "BigUploadUrlEndpoint", v.BigUploadUrlEndpoint);
    bindStr(o, "AnalysesUrl", v.AnalysesUrl);
    bindBool(o, "Enabled", v.Enabled);
    bindStr(o, "ApiKey", v.ApiKey);
    bindInt(o, "RequestsPerMinute", v.RequestsPerMinute);
    bindInt(o, "RequestsPerDay", v.RequestsPerDay);
    bindInt(o, "PriorityDailyReserve", v.PriorityDailyReserve);
    bindInt(o, "QueryTimeoutSeconds", v.QueryTimeoutSeconds);
    bindInt(o, "MaliciousThreshold", v.MaliciousThreshold);
    bindInt(o, "CleanCacheTtlDays", v.CleanCacheTtlDays);
    bindInt(o, "SuspiciousCacheTtlHours", v.SuspiciousCacheTtlHours);
    bindInt(o, "UnknownCacheTtlHours", v.UnknownCacheTtlHours);
}

void bindThreatFox(const QJsonObject& o, ThreatFoxFeedOptions& t) {
    bindStr(o, "BaseUrl", t.BaseUrl);
    bindBool(o, "Enabled", t.Enabled);
    bindStr(o, "AuthKey", t.AuthKey);
    bindInt(o, "Days", t.Days);
    bindInt(o, "MinConfidence", t.MinConfidence);
    bindInt(o, "MaxRules", t.MaxRules);
    bindInt(o, "RuleTtlDays", t.RuleTtlDays);
    bindBool(o, "GenerateHashRules", t.GenerateHashRules);
    bindBool(o, "GenerateIpRules", t.GenerateIpRules);
    bindBool(o, "GenerateDomainRules", t.GenerateDomainRules);
    bindInt(o, "InitialDelaySeconds", t.InitialDelaySeconds);
    bindInt(o, "RefreshIntervalHours", t.RefreshIntervalHours);
    bindInt(o, "QueryTimeoutSeconds", t.QueryTimeoutSeconds);
}

void bindAttackChain(const QJsonObject& o, AttackChainOptions& a) {
    bindBool(o, "Enabled", a.Enabled);
    bindBool(o, "DryRun", a.DryRun);
    bindStr(o, "BaseUrl", a.BaseUrl);
    bindInt(o, "InitialDelaySeconds", a.InitialDelaySeconds);
    bindInt(o, "DailyUpdateHour", a.DailyUpdateHour);
    bindInt(o, "RefreshIntervalHours", a.RefreshIntervalHours);
    bindInt(o, "QueryTimeoutSeconds", a.QueryTimeoutSeconds);
    bindInt(o, "LedgerRetentionMinutes", a.LedgerRetentionMinutes);
    bindInt(o, "LedgerMaxProcesses", a.LedgerMaxProcesses);
    bindStr(o, "MinGrade", a.MinGrade);
}

void bindReputationProxy(const QJsonObject& o, ReputationProxyOptions& p) {
    bindStr(o, "BaseUrl", p.BaseUrl);
    bindStr(o, "BaseUrlObfuscated", p.BaseUrlObfuscated);
    bindStr(o, "BearerToken", p.BearerToken);
    bindBool(o, "Enabled", p.Enabled);
    bindInt(o, "QueryTimeoutSeconds", p.QueryTimeoutSeconds);
    bindInt(o, "RequestsPerMinute", p.RequestsPerMinute);
    bindInt(o, "RequestsPerHour", p.RequestsPerHour);
    bindInt(o, "FreshQueriesPerDay", p.FreshQueriesPerDay);
    bindBool(o, "SyncResultsToServer", p.SyncResultsToServer);
    bindInt(o, "ContributionUploadHour", p.ContributionUploadHour);
}

} // namespace

bool BulwarkOptions::loadFromFile(const QString& appsettingsPath) {
    QFile f(appsettingsPath);
    if (!f.open(QIODevice::ReadOnly)) return true; // missing file -> keep defaults (not an error)
    const QByteArray raw = f.readAll();
    f.close();
    if (raw.trimmed().isEmpty()) return true;

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return false;

    // Top-level "Bulwark" section (case-insensitive); absent -> keep defaults.
    const QJsonValue sec = jval(doc.object(), SectionName);
    if (!sec.isObject()) return true;
    const QJsonObject o = sec.toObject();

    bindStr(o, "EventSource", EventSource);
    bindBool(o, "KernelDriverEnabled", KernelDriverEnabled);
    bindBool(o, "TrustSignedActors", TrustSignedActors);
    bindVerdictAction(o, "DefaultAction", DefaultAction);
    bindInt(o, "PromptTimeoutSeconds", PromptTimeoutSeconds);
    bindBool(o, "ExportEcsAlerts", ExportEcsAlerts);
    bindBool(o, "EnforceUiClientSignature", EnforceUiClientSignature);
    bindStrList(o, "UiClientAllowedThumbprints", UiClientAllowedThumbprints);
    bindStrList(o, "UiClientAllowedPublishers", UiClientAllowedPublishers);
    bindBool(o, "OnlineCertRevocationCheck", OnlineCertRevocationCheck);
    bindInt(o, "EventDrainIntervalMs", EventDrainIntervalMs);
    bindInt(o, "InlineReputationBudgetMs", InlineReputationBudgetMs);
    bindStrList(o, "ProtectedPaths", ProtectedPaths);
    bindStrList(o, "FileHardBlocks", FileHardBlocks);
    bindStrList(o, "ProtectedRegistryKeys", ProtectedRegistryKeys);
    bindStrList(o, "RegistryHardBlocks", RegistryHardBlocks);
    bindStrList(o, "CommandHardBlocks", CommandHardBlocks);
    bindBool(o, "CommandHardBlockBaseline", CommandHardBlockBaseline);
    bindStrList(o, "MemoryProtectionTargets", MemoryProtectionTargets);
    bindInt(o, "MemoryProtectionVtVerifyPerHour", MemoryProtectionVtVerifyPerHour);
    bindStrList(o, "BlockedRemoteEndpoints", BlockedRemoteEndpoints);
    bindStr(o, "ProxyUrl", ProxyUrl);
    bindStrList(o, "TrustedDirectories", TrustedDirectories);

    // Nested sections (case-insensitive object lookup; absent -> empty -> keep defaults).
    const auto sub = [&](const char* key) -> QJsonObject {
        const QJsonValue v = jval(o, key);
        return v.isObject() ? v.toObject() : QJsonObject();
    };
    bindVirusTotal(sub("VirusTotal"), VirusTotal);
    bindMalwareBazaar(sub("MalwareBazaar"), MalwareBazaar);
    bindOtx(sub("Otx"), Otx);
    bindThreatBook(sub("ThreatBook"), ThreatBook);
    bindMetaDefender(sub("MetaDefender"), MetaDefender);
    bindHybridAnalysis(sub("HybridAnalysis"), HybridAnalysis);
    bindThreatFox(sub("ThreatFoxFeed"), ThreatFoxFeed);
    bindReputationProxy(sub("ReputationProxy"), ReputationProxy);
    bindAttackChain(sub("AttackChainEngine"), AttackChainEngine);
    bindAi(sub("Ai"), Ai);
    bindEtw(sub("Etw"), Etw);
    return true;
}

} // namespace bulwark::service
