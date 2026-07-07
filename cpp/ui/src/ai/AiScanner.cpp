#include "ai/AiScanner.h"

#include "ai/StaticFeatureExtractor.h"
#include "bulwark/json/JsonSupport.h"
#include "bulwark/models/Enums.h"

#include <QElapsedTimer>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>

// ── AiScanResult JSON (persisted history round-trip) ────────────────────────
QJsonObject AiScanResult::toJson() const
{
    using namespace bulwark::json;
    QJsonObject o;
    o["eventId"] = guidToString(eventId);
    o["fileName"] = fileName;
    o["filePath"] = filePath;
    o["available"] = available;
    o["malicious"] = malicious;
    o["recommendation"] = static_cast<int>(recommendation);
    o["confidence"] = confidence;
    o["summary"] = summary;
    o["tokens"] = tokens;
    o["elapsedMs"] = elapsedMs;
    o["timestampUtc"] = dateTimeToIso(timestampUtc);
    o["source"] = source;
    return o;
}

AiScanResult AiScanResult::fromJson(const QJsonObject& o)
{
    using namespace bulwark::json;
    AiScanResult r;
    r.eventId = guidFromString(getStr(o, "eventId"));
    r.fileName = getStr(o, "fileName");
    r.filePath = getStr(o, "filePath");
    r.available = getBool(o, "available");
    r.malicious = getBool(o, "malicious");
    r.recommendation = static_cast<bulwark::VerdictAction>(getInt(o, "recommendation", 0));
    r.confidence = getStr(o, "confidence");
    r.summary = getStr(o, "summary");
    r.tokens = getInt(o, "tokens", 0);
    r.elapsedMs = getI64(o, "elapsedMs", 0);
    const QDateTime ts = dateTimeFromIso(getStr(o, "timestampUtc"));
    if (ts.isValid()) r.timestampUtc = ts;
    r.source = getStr(o, "source");
    return r;
}

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

QString eventTypeLabel(bulwark::EventType t)
{
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return u("进程创建");
    case E::ProcessTerminate: return u("结束进程");
    case E::RemoteThread:     return u("远程线程注入");
    case E::ImageLoad:        return u("模块加载");
    case E::FileWrite:        return u("文件写入");
    case E::FileDelete:       return u("文件删除");
    case E::RegistryWrite:    return u("注册表写入");
    case E::NetworkConnect:   return u("网络外联");
    case E::SelfProtect:      return u("自我保护");
    case E::DnsQuery:         return u("DNS 解析");
    }
    return u("行为");
}

// Map an English EventType member name to the enum (for AI-suggested rules).
// Empty / "所有" / "all" / unknown => nullopt (any type).
std::optional<bulwark::EventType> parseEventType(const QString& s)
{
    const QString t = s.trimmed();
    using E = bulwark::EventType;
    if (t.compare(QLatin1String("ProcessCreate"), Qt::CaseInsensitive) == 0)    return E::ProcessCreate;
    if (t.compare(QLatin1String("ProcessTerminate"), Qt::CaseInsensitive) == 0) return E::ProcessTerminate;
    if (t.compare(QLatin1String("RemoteThread"), Qt::CaseInsensitive) == 0)     return E::RemoteThread;
    if (t.compare(QLatin1String("ImageLoad"), Qt::CaseInsensitive) == 0)        return E::ImageLoad;
    if (t.compare(QLatin1String("FileWrite"), Qt::CaseInsensitive) == 0)        return E::FileWrite;
    if (t.compare(QLatin1String("FileDelete"), Qt::CaseInsensitive) == 0)       return E::FileDelete;
    if (t.compare(QLatin1String("RegistryWrite"), Qt::CaseInsensitive) == 0)    return E::RegistryWrite;
    if (t.compare(QLatin1String("NetworkConnect"), Qt::CaseInsensitive) == 0)   return E::NetworkConnect;
    if (t.compare(QLatin1String("SelfProtect"), Qt::CaseInsensitive) == 0)      return E::SelfProtect;
    if (t.compare(QLatin1String("DnsQuery"), Qt::CaseInsensitive) == 0)         return E::DnsQuery;
    return std::nullopt;
}

const char* kScanSystemPrompt =
    "你是一名资深恶意软件分析师,只做【静态】研判,绝不执行样本。\n"
    "\n"
    "【最重要的判定原则,必须严格遵守】\n"
    "「缺乏良性证据」不等于「存在恶意证据」。以下均为【软信号】,无论单独还是组合出现,"
    "都【绝不能】作为判定恶意的依据——大量正常的自编译程序、绿色/便携软件、内部工具都是这样:\n"
    "- 无数字签名 / 签名无效 / 无发行商;\n"
    "- 从桌面 / 下载 / Temp / AppData 等用户目录运行;\n"
    "- 本机首见 / 文件体积小 / 无版本或图标信息。\n"
    "只有当【静态内容特征】里出现明确的【硬指标】时,才可判为恶意,例如:\n"
    "- 进程注入 API 组合(如 VirtualAllocEx + WriteProcessMemory + CreateRemoteThread);\n"
    "- 加壳/高熵节区且伴随注入或反分析能力;\n"
    "- 勒索特征:批量加密 API + 删除卷影(vssadmin/bcdedit/wbadmin);\n"
    "- 键盘记录钩子、凭据/LSASS 访问(mimikatz/sekurlsa);\n"
    "- 硬编码的 C2 URL/IP、可疑下载执行;\n"
    "- 脚本混淆(-enc / IEX / FromBase64String 下载执行 等)。\n"
    "\n"
    "【判定规则】\n"
    "- 若只有软信号、静态内容特征里没有任何硬指标 → malicious=false,confidence=\"低\","
    "summary 说明「仅有软信号,未见明确恶意特征,疑似正常的未签名程序」;\n"
    "- 若存在硬指标 → 按其数量与强度给出 malicious=true 及相应 confidence;\n"
    "- summary 必须【引用你实际依据的具体特征】(命中的 API / URL / 高熵节区 / 脚本片段等),"
    "不得仅以「无签名 / 可疑目录 / 本机首见」作为恶意理由。\n"
    "\n"
    "只输出一个严格 JSON 对象,不要输出任何多余文字或代码块围栏,格式:\n"
    "{\"malicious\": true/false, \"confidence\": \"高/中/低\", \"summary\": \"一句话中文理由,须引用具体静态特征\"}";

const char* kRuleSystemPrompt =
    "你是磐垒 HIPS 的规则助手。把用户的自然语言安全意图转成 1~5 条防护规则。"
    "只输出一个严格 JSON 数组,不要输出任何多余文字或代码块围栏。每个元素:"
    "{\"actor\":\"主体(完整路径 / 含*的通配 / 裸文件名)\","
    "\"type\":\"ProcessCreate|ProcessTerminate|RemoteThread|ImageLoad|FileWrite|FileDelete|RegistryWrite|NetworkConnect|所有\","
    "\"target\":\"目标通配(可空)\",\"action\":\"Block|Allow\",\"note\":\"简短中文说明\"}。"
    "尽量精确、低误报;拿不准就少给几条。";

QString extractJsonObject(const QString& content)
{
    const int start = content.indexOf(QLatin1Char('{'));
    const int end = content.lastIndexOf(QLatin1Char('}'));
    if (start >= 0 && end > start)
        return content.mid(start, end - start + 1);
    return QString();
}

// Extract the first balanced [...] JSON array from arbitrary model text.
QString extractJsonArray(const QString& content)
{
    const int start = content.indexOf(QLatin1Char('['));
    const int end = content.lastIndexOf(QLatin1Char(']'));
    if (start >= 0 && end > start)
        return content.mid(start, end - start + 1);
    return QString();
}

} // namespace

AiScanner::AiScanner(QObject* parent) : QObject(parent), m_net(new QNetworkAccessManager(this)) {}

void AiScanner::setConfig(const QString& baseUrl, const QString& apiKey, const QString& model)
{
    m_base = baseUrl.trimmed();
    m_key = apiKey.trimmed();
    m_model = model.trimmed();
}

bool AiScanner::isConfigured() const
{
    return !m_base.isEmpty() && !m_key.isEmpty();
}

QString AiScanner::endpoint() const
{
    QString url = m_base;
    while (url.endsWith(QLatin1Char('/')))
        url.chop(1);
    if (!url.endsWith(QLatin1String("/chat/completions"), Qt::CaseInsensitive))
        url += QStringLiteral("/chat/completions");
    return url;
}

void AiScanner::postChat(const QString& systemPrompt, const QString& userPrompt,
                         std::function<void(bool, const QString&, int)> onDone)
{
    QJsonObject sys{ {QStringLiteral("role"), QStringLiteral("system")},
                     {QStringLiteral("content"), systemPrompt} };
    QJsonObject usr{ {QStringLiteral("role"), QStringLiteral("user")},
                     {QStringLiteral("content"), userPrompt} };
    QJsonObject body{
        {QStringLiteral("model"), m_model.isEmpty() ? QStringLiteral("gpt-3.5-turbo") : m_model},
        {QStringLiteral("temperature"), 0},
        {QStringLiteral("stream"), false},
        {QStringLiteral("messages"), QJsonArray{ sys, usr }},
    };

    QNetworkRequest req{ QUrl(endpoint()) };
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    req.setRawHeader("Authorization", ("Bearer " + m_key).toUtf8());
    QNetworkReply* reply = m_net->post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));

    // Hard timeout so a hung endpoint never wedges the flow (fail-open).
    auto* timeout = new QTimer(reply);
    timeout->setSingleShot(true);
    timeout->setInterval(60000);
    connect(timeout, &QTimer::timeout, reply, [reply] { if (reply->isRunning()) reply->abort(); });
    timeout->start();

    connect(reply, &QNetworkReply::finished, this, [reply, onDone]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            onDone(false, reply->errorString(), 0);
            return;
        }
        const QJsonObject root = QJsonDocument::fromJson(reply->readAll()).object();
        const QJsonArray choices = root.value(QStringLiteral("choices")).toArray();
        const int tokens = root.value(QStringLiteral("usage")).toObject()
                               .value(QStringLiteral("total_tokens")).toInt();
        QString content;
        if (!choices.isEmpty())
            content = choices.at(0).toObject().value(QStringLiteral("message"))
                          .toObject().value(QStringLiteral("content")).toString();
        onDone(!content.trimmed().isEmpty(), content, tokens);
    });
}

QString AiScanner::buildUserPrompt(const bulwark::SecurityEvent& e) const
{
    QStringList lines;
    lines << u("请对以下程序做静态恶意性研判。");
    lines << u("务必以【静态内容特征】为主要依据;【环境信息】属软信号,仅供参考,"
               "不得作为判定恶意的唯一/主要理由。");
    lines << QString();

    lines << u("== 环境信息(软信号,仅供参考,单独不构成恶意证据) ==");
    if (!e.actorPath.isEmpty())     lines << u("程序路径: ") + e.actorPath;
    lines << u("文件名: ") + QFileInfo(e.actorPath).fileName();
    lines << u("行为类型: ") + eventTypeLabel(e.type);
    lines << u("数字签名: ") + (e.actorSigned ? u("有") : u("无 / 无效"));
    if (!e.actorPublisher.isEmpty()) lines << u("发行商: ") + e.actorPublisher;
    if (e.signatureMismatch)         lines << u("签名失配: 是(内嵌签名但校验不通过)");
    if (e.isFirstSeen)               lines << u("本机首见: 是");
    if (e.actorFileSize > 0)         lines << u("文件大小: ") + QString::number(e.actorFileSize) + u(" 字节");
    if (!e.actorHash.isEmpty())      lines << u("SHA-256: ") + e.actorHash;
    if (!e.commandLine.isEmpty())    lines << u("命令行: ") + e.commandLine;
    if (!e.target.isEmpty())         lines << u("操作目标: ") + e.target;
    if (!e.parentPath.isEmpty())     lines << u("父进程: ") + e.parentPath;
    if (!e.techniques.isEmpty())     lines << u("命中 ATT&CK: ") + e.techniques.join(QStringLiteral(", "));
    if (!e.riskReasons.isEmpty())    lines << u("启发式线索: ") + e.riskReasons.join(QStringLiteral("; "));

    lines << QString();
    lines << u("== 静态内容特征(研判的主要依据) ==");
    // Real static evidence extracted from the file itself (PE header / section
    // entropy / dangerous API names / URLs·IPs / suspicious tokens · script src).
    lines << extractStaticFeatures(e.actorPath).toPromptText();

    return lines.join(QLatin1Char('\n'));
}

void AiScanner::scan(const bulwark::SecurityEvent& e, const QString& source)
{
    AiScanResult base;
    base.eventId = e.id;
    base.filePath = e.actorPath;
    base.fileName = QFileInfo(e.actorPath).fileName();
    base.source = source;

    if (!isConfigured()) {
        base.available = false;
        base.summary = u("未配置大模型(接口地址 / API Key)");
        emit finished(base);
        return;
    }

    auto* timer = new QElapsedTimer;
    timer->start();
    postChat(QString::fromUtf8(kScanSystemPrompt), buildUserPrompt(e),
             [this, base, timer](bool ok, const QString& content, int tokens) mutable {
        base.elapsedMs = timer->elapsed();
        delete timer;
        base.tokens = tokens;
        if (!ok) {
            base.available = false;
            base.summary = content.isEmpty() ? u("AI 返回为空") : (u("AI 请求失败: ") + content);
            emit finished(base);
            return;
        }
        base.available = true;
        // Prefer a strict JSON verdict; fall back to keyword heuristics (as .NET does).
        const QJsonObject verdict = QJsonDocument::fromJson(extractJsonObject(content).toUtf8()).object();
        if (!verdict.isEmpty() && verdict.contains(QStringLiteral("malicious"))) {
            base.malicious = verdict.value(QStringLiteral("malicious")).toBool();
            base.confidence = verdict.value(QStringLiteral("confidence")).toString();
            base.summary = verdict.value(QStringLiteral("summary")).toString();
        } else {
            const QString lower = content.toLower();
            base.malicious = lower.contains(u("恶意")) || lower.contains(QStringLiteral("malware"))
                             || lower.contains(QStringLiteral("virus")) || lower.contains(QStringLiteral("trojan"));
            base.summary = content.left(200);
            base.confidence = base.malicious ? u("高") : u("中");
        }
        if (base.confidence.isEmpty())
            base.confidence = u("中");
        base.recommendation = base.malicious ? bulwark::VerdictAction::Block
                                             : bulwark::VerdictAction::Allow;
        emit finished(base);
    });
}

void AiScanner::scanFile(const QString& path, const QString& source)
{
    bulwark::SecurityEvent e;
    e.id = QUuid(); // null id => manual scan; IpcClient won't echo an AiScanResponse to the service
    e.type = bulwark::EventType::ProcessCreate;
    e.actorPath = path;
    const QFileInfo fi(path);
    if (fi.exists() && fi.isFile())
        e.actorFileSize = fi.size();
    scan(e, source);
}

void AiScanner::generateRules(const QString& request)
{
    if (!isConfigured() || request.trimmed().isEmpty()) {
        emit rulesSuggested({});
        return;
    }
    postChat(QString::fromUtf8(kRuleSystemPrompt),
             u("请把下面的安全意图转成防护规则:\n") + request.trimmed(),
             [this](bool ok, const QString& content, int) {
        if (!ok) {
            emit rulesSuggested({});
            return;
        }
        const QJsonArray arr = QJsonDocument::fromJson(extractJsonArray(content).toUtf8()).array();
        QList<AiSuggestedRule> out;
        for (const QJsonValue& v : arr) {
            if (!v.isObject()) continue;
            const QJsonObject o = v.toObject();
            const QString actor = o.value(QStringLiteral("actor")).toString().trimmed();
            if (actor.isEmpty()) continue;
            AiSuggestedRule r;
            r.payload.actorPath = actor; // service smart-parses exact path / wildcard / bare name
            r.payload.type = parseEventType(o.value(QStringLiteral("type")).toString());
            r.payload.targetPattern = o.value(QStringLiteral("target")).toString().trimmed();
            r.payload.action = o.value(QStringLiteral("action")).toString()
                                       .compare(QLatin1String("Block"), Qt::CaseInsensitive) == 0
                                   ? bulwark::VerdictAction::Block
                                   : bulwark::VerdictAction::Allow;
            r.note = o.value(QStringLiteral("note")).toString().trimmed();
            out.append(r);
            if (out.size() >= 5) break; // cap per the product spec (1..5)
        }
        emit rulesSuggested(out);
    });
}
