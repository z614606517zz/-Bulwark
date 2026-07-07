#include "bulwark/service/reputation/VirusTotalClient.h"
#include "bulwark/service/reputation/ReputationCurl.h"

#include <QDateTime>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QSet>
#include <QTimeZone>

#include <algorithm>
#include <chrono>
#include <thread>

// VirusTotal v3 哈希信誉 + 文件上传扫描客户端。网络经系统 curl.exe(ReputationCurl),
// 自带限流(令牌桶 + 每日配额,含优先请求保留额),任何失败一律 fail-open 返回 Unknown。
// 对应 .NET VirusTotalClient.cs(QueryAsync + UploadAndScanAsync)。
namespace bulwark::service::reputation {
namespace {

// EICAR 测试样本 SHA-256(用于连接/密钥探测)。
const QString kEicar = QStringLiteral("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

// 直传上限:>32MB 需先取一次性专用上传 URL。上传扫描可处理的最大文件(保守 200MB)。
constexpr qint64 kDirectUploadMaxBytes = 32LL * 1024 * 1024;
constexpr qint64 kMaxUploadBytes       = 200LL * 1024 * 1024;

int jInt(const QJsonObject& o, const char* k) {
    const QJsonValue v = o.value(QLatin1String(k));
    return v.isDouble() ? v.toInt() : 0;
}

QString vtBase(const VirusTotalOptions& opt) {
    return opt.BaseUrl.isEmpty() ? QStringLiteral("https://www.virustotal.com/api/v3/files/") : opt.BaseUrl;
}

QString vtUploadUrl(const VirusTotalOptions& opt) {
    return opt.UploadUrl.isEmpty() ? QStringLiteral("https://www.virustotal.com/api/v3/files") : opt.UploadUrl;
}

QString vtBigUploadEndpoint(const VirusTotalOptions& opt) {
    return opt.BigUploadUrlEndpoint.isEmpty()
               ? QStringLiteral("https://www.virustotal.com/api/v3/files/upload_url")
               : opt.BigUploadUrlEndpoint;
}

QString vtAnalysesUrl(const VirusTotalOptions& opt) {
    return opt.AnalysesUrl.isEmpty() ? QStringLiteral("https://www.virustotal.com/api/v3/analyses/")
                                     : opt.AnalysesUrl;
}

} // namespace

QString VirusTotalClient::builtInApiKey() {
    // 出于安全考虑,源码与版本库中不保留任何密钥。
    // 如需“开箱即用”的内置 Key,可在构建时注入(CMake: -DBULWARK_VT_BUILTIN_KEY="<key>");
    // 未注入时返回空 —— 此时请通过环境变量(VirusTotalOptions::ApiKeyEnvVar)或配置文件提供 Key,
    // 否则 VirusTotal 查询自动禁用(fail-open,返回 Unknown)。
#ifdef BULWARK_VT_BUILTIN_KEY
    return QStringLiteral(BULWARK_VT_BUILTIN_KEY);
#else
    return QString();
#endif
}

VirusTotalClient::VirusTotalClient(const BulwarkOptions& options)
    : opt_(options.VirusTotal),
      bucket_(std::max(1, options.VirusTotal.RequestsPerMinute), 60000),
      daily_(std::max(1, options.VirusTotal.RequestsPerDay), options.VirusTotal.PriorityDailyReserve),
      log_(QStringLiteral("VirusTotal")) {
    const QString env = qEnvironmentVariable(VirusTotalOptions::ApiKeyEnvVar).trimmed();
    apiKey_ = !env.isEmpty()                     ? env
            : !opt_.ApiKey.trimmed().isEmpty()   ? opt_.ApiKey.trimmed()
                                                 : builtInApiKey();
    enabled_ = !apiKey_.isEmpty();
    const QString keySource = !env.isEmpty()                   ? QStringLiteral("环境变量 Key")
                            : !opt_.ApiKey.trimmed().isEmpty() ? QStringLiteral("配置文件 Key")
                            : !apiKey_.isEmpty()               ? QStringLiteral("内置 Key")
                                                              : QStringLiteral("未配置 Key,查询禁用");
    log_.info(QStringLiteral("VirusTotal 信誉查询就绪(经 curl,限流 %1/min, %2/day,%3);"
                             "是否参与查询由运行时开关控制。")
                  .arg(opt_.RequestsPerMinute)
                  .arg(opt_.RequestsPerDay)
                  .arg(keySource));
}

QString VirusTotalClient::apiKey() const {
    QMutexLocker lk(&keyMutex_);
    return apiKey_;
}

void VirusTotalClient::setApiKey(const QString& key) {
    // 空 Key -> 回退内置(构建期可注入,默认空 = 禁用);非空则用用户 Key。
    const QString k = key.trimmed().isEmpty() ? builtInApiKey() : key.trimmed();
    { QMutexLocker lk(&keyMutex_); apiKey_ = k; }
    enabled_ = !k.isEmpty();
}

void VirusTotalClient::diag(const QString& line) {
    QFile f(programDataDir() + QStringLiteral("/vt_diag.log"));
    if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
        const QString entry =
            QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")) + QLatin1Char(' ') + line + QLatin1Char('\n');
        f.write(entry.toUtf8());
        f.close();
    }
}

bulwark::FileReputation VirusTotalClient::query(const QString& sha256, bool priority) {
    bulwark::FileReputation unknown;
    unknown.sha256 = sha256;
    unknown.verdict = bulwark::ReputationVerdict::Unknown;
    if (!enabled_ || sha256.isEmpty())
        return unknown;

    if (!daily_.tryConsume(priority)) {
        log_.debug(QStringLiteral("VirusTotal 日配额已用尽,跳过查询 ") + sha256.left(12));
        return unknown;
    }
    bucket_.wait(priority);

    const QStringList headers{ QStringLiteral("x-apikey: ") + apiKey() };
    const auto res = ReputationCurl::get(vtBase(opt_) + sha256, headers, opt_.QueryTimeoutSeconds);
    const int code = res.first;
    const QString tag = sha256.left(12);

    if (code == 404) {
        // 未收录:权威负结果(可缓存,避免反复查)。
        diag(QStringLiteral("query %1 => 404 NotFound").arg(tag));
        bulwark::FileReputation r = unknown;
        r.querySucceeded = true;
        return r;
    }
    if (code == 401 || code == 403) {
        log_.warning(QStringLiteral("VirusTotal 鉴权失败(%1),请检查 API Key。").arg(code));
        diag(QStringLiteral("query %1 => AUTH FAIL %2").arg(tag).arg(code));
        return unknown;
    }
    if (code == 429) {
        log_.warning(QStringLiteral("VirusTotal 触发限流(429),本次跳过。"));
        diag(QStringLiteral("query %1 => 429 RateLimit").arg(tag));
        return unknown;
    }
    if (code != 200) {
        diag(QStringLiteral("query %1 => HTTP %2").arg(tag).arg(code));
        return unknown;
    }

    const bulwark::FileReputation parsed = parse(sha256, res.second);
    diag(QStringLiteral("query %1 => OK v%2 %3/%4")
             .arg(tag).arg(static_cast<int>(parsed.verdict)).arg(parsed.malicious).arg(parsed.totalEngines));
    return parsed;
}

bulwark::FileReputation VirusTotalClient::parse(const QString& sha256, const QString& json) const {
    bulwark::FileReputation rep;
    rep.sha256 = sha256;
    rep.verdict = bulwark::ReputationVerdict::Unknown;

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return rep;
    const QJsonObject attr =
        doc.object().value(QLatin1String("data")).toObject().value(QLatin1String("attributes")).toObject();
    if (attr.isEmpty())
        return rep;

    int malicious = 0, suspicious = 0, total = 0;
    const QJsonObject stats = attr.value(QLatin1String("last_analysis_stats")).toObject();
    if (!stats.isEmpty()) {
        malicious = jInt(stats, "malicious");
        suspicious = jInt(stats, "suspicious");
        total = malicious + suspicious + jInt(stats, "undetected") + jInt(stats, "harmless")
              + jInt(stats, "timeout") + jInt(stats, "failure") + jInt(stats, "type-unsupported");
    }
    rep.malicious = malicious;
    rep.totalEngines = total;

    const QJsonValue lbl = attr.value(QLatin1String("suggested_threat_label"));
    if (lbl.isString()) {
        rep.threatLabel = lbl.toString();
    } else {
        const QJsonObject ptc = attr.value(QLatin1String("popular_threat_classification")).toObject();
        const QJsonValue lbl2 = ptc.value(QLatin1String("suggested_threat_label"));
        if (lbl2.isString())
            rep.threatLabel = lbl2.toString();
    }

    const QJsonValue lad = attr.value(QLatin1String("last_analysis_date"));
    if (lad.isDouble())
        rep.lastAnalysisUtc = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(lad.toDouble()), QTimeZone::UTC);

    if (malicious >= opt_.MaliciousThreshold)
        rep.verdict = bulwark::ReputationVerdict::Malicious;
    else if (malicious + suspicious >= 1)
        rep.verdict = bulwark::ReputationVerdict::Suspicious;
    else
        rep.verdict = bulwark::ReputationVerdict::Clean;
    rep.querySucceeded = true;
    return rep;
}

bulwark::FileReputation VirusTotalClient::uploadAndScan(const QString& filePath, const QString& sha256,
                                                        const ProgressFn& progress) {
    bulwark::FileReputation unknown;
    unknown.sha256 = sha256;
    unknown.verdict = bulwark::ReputationVerdict::Unknown;
    if (!enabled_)
        return unknown;

    const QFileInfo fi(filePath);
    if (!fi.exists() || !fi.isFile()) {
        diag(QStringLiteral("上传扫描跳过:文件不存在 ") + filePath);
        return unknown;
    }
    const qint64 size = fi.size();
    if (size > kMaxUploadBytes) {
        diag(QStringLiteral("上传扫描跳过:文件过大 %1 字节").arg(size));
        return unknown;
    }
    if (!daily_.tryConsume(false)) {
        diag(QStringLiteral("上传扫描跳过:VT 日配额已用尽"));
        return unknown;
    }

    const QStringList headers{ QStringLiteral("x-apikey: ") + apiKey() };
    const QString name = fi.fileName();

    // 一次令牌覆盖(大文件的)取上传 URL + 上传本体,与 .NET 行为一致。
    bucket_.wait();
    if (progress)
        progress(bulwark::VtScanStage::Uploading, 0);

    // 大文件(>32MB):先取一次性专用上传 URL。
    QString target = vtUploadUrl(opt_);
    if (size > kDirectUploadMaxBytes) {
        const auto ur = ReputationCurl::get(vtBigUploadEndpoint(opt_), headers, opt_.QueryTimeoutSeconds);
        if (ur.first == 200) {
            const QJsonValue dv =
                QJsonDocument::fromJson(ur.second.toUtf8()).object().value(QLatin1String("data"));
            if (dv.isString() && !dv.toString().isEmpty())
                target = dv.toString();
        }
    }

    // 上传文件(curl -F file=@path);postFile 内部给足超时(含上传 + 服务端入队)。
    const auto up = ReputationCurl::postFile(target, fi.absoluteFilePath(), headers,
                                             std::max(300, opt_.QueryTimeoutSeconds));
    if (up.first != 200) {
        diag(QStringLiteral("上传 %1 => HTTP %2").arg(name).arg(up.first));
        return unknown;
    }

    QString analysisId;
    {
        const QJsonObject data =
            QJsonDocument::fromJson(up.second.toUtf8()).object().value(QLatin1String("data")).toObject();
        const QJsonValue id = data.value(QLatin1String("id"));
        if (id.isString())
            analysisId = id.toString();
    }
    if (analysisId.isEmpty()) {
        diag(QStringLiteral("上传 %1:未返回分析 id").arg(name));
        return unknown;
    }
    diag(QStringLiteral("上传 %1 => 分析 id %2").arg(name, analysisId));

    // 轮询分析结果(最长约 4 分钟),完成后按解析出的 SHA-256 拉完整报告。
    if (progress)
        progress(bulwark::VtScanStage::Analyzing, 100);
    QString resolvedSha = sha256;
    const qint64 deadline = QDateTime::currentMSecsSinceEpoch() + 4LL * 60 * 1000;
    while (QDateTime::currentMSecsSinceEpoch() < deadline) {
        std::this_thread::sleep_for(std::chrono::seconds(15));
        bucket_.wait();

        const auto pr = ReputationCurl::get(vtAnalysesUrl(opt_) + analysisId, headers, opt_.QueryTimeoutSeconds);
        if (pr.first != 200) {
            diag(QStringLiteral("轮询 %1 => HTTP %2").arg(analysisId).arg(pr.first));
            continue;
        }
        const QJsonObject root = QJsonDocument::fromJson(pr.second.toUtf8()).object();
        const QJsonValue sh = root.value(QLatin1String("meta")).toObject()
                                  .value(QLatin1String("file_info")).toObject()
                                  .value(QLatin1String("sha256"));
        if (sh.isString() && !sh.toString().isEmpty())
            resolvedSha = sh.toString();
        const QString status = root.value(QLatin1String("data")).toObject()
                                   .value(QLatin1String("attributes")).toObject()
                                   .value(QLatin1String("status")).toString();
        if (status.compare(QLatin1String("completed"), Qt::CaseInsensitive) == 0) {
            diag(QStringLiteral("轮询 %1 => 已完成").arg(analysisId));
            break;
        }
    }

    if (!resolvedSha.isEmpty()) {
        bulwark::FileReputation rep = query(resolvedSha, false); // 复用查询路径(自带 daily+bucket)
        rep.sha256 = resolvedSha;
        if (progress)
            progress(bulwark::VtScanStage::Completed, 100);
        return rep;
    }
    return unknown;
}

bulwark::ThreatBehaviorProfile VirusTotalClient::fetchBehaviorProfile(const QString& sha256) {
    bulwark::ThreatBehaviorProfile prof;
    prof.sha256 = sha256;
    prof.source = name();
    if (!enabled_ || sha256.isEmpty())
        return prof;

    // 与哈希查询共用限流:行为报告只在「确认恶意」后拉取,频次很低。
    if (!daily_.tryConsume(false)) {
        diag(QStringLiteral("behaviour %1 => 跳过(日配额已用尽)").arg(sha256.left(12)));
        return prof;
    }
    bucket_.wait(false);

    const QStringList headers{ QStringLiteral("x-apikey: ") + apiKey() };
    const QString url = vtBase(opt_) + sha256 + QStringLiteral("/behaviour_summary");
    const auto res = ReputationCurl::get(url, headers, opt_.QueryTimeoutSeconds);
    if (res.first != 200) {
        diag(QStringLiteral("behaviour %1 => HTTP %2").arg(sha256.left(12)).arg(res.first));
        return prof; // 404(无沙箱数据)/ 401 / 429 等一律 fail-open
    }
    parseBehaviour(res.second, prof);
    diag(QStringLiteral("behaviour %1 => OK 释放文件%2 哈希%3 注册表%4 IP%5 域名%6 服务%7")
             .arg(sha256.left(12))
             .arg(prof.droppedFileNames.size()).arg(prof.droppedFileHashes.size())
             .arg(prof.registryKeysSet.size()).arg(prof.contactedIps.size())
             .arg(prof.contactedDomains.size()).arg(prof.serviceNames.size()));
    return prof;
}

void VirusTotalClient::parseBehaviour(const QString& json, bulwark::ThreatBehaviorProfile& prof) const {
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return;
    // behaviour_summary 把各沙箱结果合并到 data 下的一组数组字段。
    const QJsonObject data = doc.object().value(QLatin1String("data")).toObject();
    if (data.isEmpty())
        return;

    // 取路径的 basename(小写),路径分隔符归一化为反斜杠。
    auto baseName = [](const QString& path) -> QString {
        QString p = path;
        p.replace(QLatin1Char('/'), QLatin1Char('\\'));
        const int i = p.lastIndexOf(QLatin1Char('\\'));
        return (i >= 0 ? p.mid(i + 1) : p).trimmed().toLower();
    };
    // 从命令行取首个 token(可执行体),兼容带引号的路径。
    auto firstToken = [](const QString& cmd) -> QString {
        const QString c = cmd.trimmed();
        if (c.startsWith(QLatin1Char('"'))) {
            const int end = c.indexOf(QLatin1Char('"'), 1);
            return end > 1 ? c.mid(1, end - 1) : c.mid(1);
        }
        const int sp = c.indexOf(QLatin1Char(' '));
        return sp > 0 ? c.left(sp) : c;
    };

    QSet<QString> nameSet, hashSet, regSet, procSet, ipSet, domSet, svcSet, mtxSet;
    QStringList pathList; // 原始沙箱完整路径(保序,后续去重+截断),清理时翻译到本机
    const auto arrOf = [&](const char* key) { return data.value(QLatin1String(key)).toArray(); };
    const auto addPath = [&](const QString& raw) {
        const QString p = raw.trimmed();
        if (p.size() >= 4 && (p.contains(QLatin1Char('\\')) || p.contains(QLatin1Char('/')))
            && pathList.size() < 100)
            pathList << p;
    };

    // 释放文件:[{path, sha256}]
    for (const QJsonValue& v : arrOf("files_dropped")) {
        const QJsonObject o = v.toObject();
        const QString path = o.value(QLatin1String("path")).toString();
        const QString bn = baseName(path);
        if (!bn.isEmpty()) nameSet.insert(bn);
        addPath(path);
        const QString h = o.value(QLatin1String("sha256")).toString().toLower();
        if (h.size() == 64) hashSet.insert(h);
    }
    // 写入 / 删除文件:字符串路径
    for (const char* k : { "files_written", "files_deleted" })
        for (const QJsonValue& v : arrOf(k)) {
            const QString path = v.toString();
            const QString bn = baseName(path);
            if (!bn.isEmpty()) nameSet.insert(bn);
            if (qstrcmp(k, "files_written") == 0) addPath(path);
        }
    // 写注册表:[{key, value}] 或纯字符串
    for (const QJsonValue& v : arrOf("registry_keys_set")) {
        QString key = v.isObject() ? v.toObject().value(QLatin1String("key")).toString() : v.toString();
        key = key.trimmed();
        if (!key.isEmpty()) regSet.insert(key);
    }
    // 创建进程 / 命令执行:字符串命令行 -> 取可执行名(仅收 *.exe)
    for (const char* k : { "processes_created", "command_executions" })
        for (const QJsonValue& v : arrOf(k)) {
            const QString bn = baseName(firstToken(v.toString()));
            if (bn.endsWith(QLatin1String(".exe"))) procSet.insert(bn);
        }
    // 外联 IP:[{destination_ip, destination_port}]
    for (const QJsonValue& v : arrOf("ip_traffic")) {
        const QJsonObject o = v.toObject();
        const QString ip = o.value(QLatin1String("destination_ip")).toString().trimmed();
        if (ip.isEmpty()) continue;
        const int port = o.value(QLatin1String("destination_port")).toInt();
        ipSet.insert(port > 0 ? (ip + QLatin1Char(':') + QString::number(port)) : ip);
    }
    // DNS 查询:[{hostname, resolved_ips}]
    for (const QJsonValue& v : arrOf("dns_lookups")) {
        const QString host = v.toObject().value(QLatin1String("hostname")).toString().trimmed().toLower();
        if (!host.isEmpty()) domSet.insert(host);
    }
    // 创建 / 启动服务:字符串
    for (const char* k : { "services_created", "services_started" })
        for (const QJsonValue& v : arrOf(k)) {
            const QString s = v.toString().trimmed();
            if (!s.isEmpty()) svcSet.insert(s);
        }
    // 互斥体:字符串
    for (const QJsonValue& v : arrOf("mutexes_created")) {
        const QString s = v.toString().trimmed();
        if (!s.isEmpty()) mtxSet.insert(s);
    }

    // 每类上限 100,避免异常巨大的报告拖垮清理 / 规则生成。
    auto toList = [](const QSet<QString>& s) {
        QStringList l(s.begin(), s.end());
        if (l.size() > 100) l = l.mid(0, 100);
        return l;
    };
    prof.droppedFileNames = toList(nameSet);
    pathList.removeDuplicates();
    prof.droppedFilePaths = pathList;
    prof.droppedFileHashes = toList(hashSet);
    prof.registryKeysSet = toList(regSet);
    prof.processNames = toList(procSet);
    prof.contactedIps = toList(ipSet);
    prof.contactedDomains = toList(domSet);
    prof.serviceNames = toList(svcSet);
    prof.mutexes = toList(mtxSet);
    prof.fetched = true;
}

bulwark::ipc::VtDetailResponsePayload VirusTotalClient::fetchDetailReport(const QString& sha256) {
    bulwark::ipc::VtDetailResponsePayload d;
    d.sha256 = sha256;
    if (!enabled_ || sha256.isEmpty()) {
        d.message = QStringLiteral("VirusTotal 未启用或哈希为空");
        return d;
    }
    if (!daily_.tryConsume(false)) {
        d.message = QStringLiteral("VirusTotal 日配额已用尽,稍后再试");
        return d;
    }
    bucket_.wait(false);
    const QStringList headers{ QStringLiteral("x-apikey: ") + apiKey() };
    const auto res = ReputationCurl::get(vtBase(opt_) + sha256, headers, opt_.QueryTimeoutSeconds);
    if (res.first == 404) { d.message = QStringLiteral("VirusTotal 未收录该文件"); return d; }
    if (res.first == 401 || res.first == 403) { d.message = QStringLiteral("VirusTotal 鉴权失败,请检查 API Key"); return d; }
    if (res.first == 429) { d.message = QStringLiteral("VirusTotal 触发限流(429),稍后再试"); return d; }
    if (res.first != 200) { d.message = QStringLiteral("VirusTotal 查询失败(HTTP %1)").arg(res.first); return d; }
    parseDetail(res.second, d);
    d.success = true;
    return d;
}

void VirusTotalClient::parseDetail(const QString& json, bulwark::ipc::VtDetailResponsePayload& d) const {
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return;
    const QJsonObject attr =
        doc.object().value(QLatin1String("data")).toObject().value(QLatin1String("attributes")).toObject();
    if (attr.isEmpty())
        return;

    d.typeDescription = attr.value(QLatin1String("type_description")).toString();
    d.sizeBytes = static_cast<qint64>(attr.value(QLatin1String("size")).toDouble());
    d.timesSubmitted = jInt(attr, "times_submitted");
    d.reputation = jInt(attr, "reputation");

    const QJsonValue fsd = attr.value(QLatin1String("first_submission_date"));
    if (fsd.isDouble())
        d.firstSubmissionUtc = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(fsd.toDouble()), QTimeZone::UTC);
    const QJsonValue lad = attr.value(QLatin1String("last_analysis_date"));
    if (lad.isDouble())
        d.lastAnalysisUtc = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(lad.toDouble()), QTimeZone::UTC);

    // 建议威胁名。
    const QJsonValue lbl = attr.value(QLatin1String("suggested_threat_label"));
    if (lbl.isString()) {
        d.threatLabel = lbl.toString();
    } else {
        const QJsonObject ptc = attr.value(QLatin1String("popular_threat_classification")).toObject();
        d.threatLabel = ptc.value(QLatin1String("suggested_threat_label")).toString();
    }

    // 检出统计。
    const QJsonObject stats = attr.value(QLatin1String("last_analysis_stats")).toObject();
    const int mal = jInt(stats, "malicious");
    const int susp = jInt(stats, "suspicious");
    d.malicious = mal;
    d.totalEngines = mal + susp + jInt(stats, "undetected") + jInt(stats, "harmless")
                   + jInt(stats, "timeout") + jInt(stats, "failure") + jInt(stats, "type-unsupported");

    // 已知别名 / 标签(各截断,避免过长)。
    for (const QJsonValue& v : attr.value(QLatin1String("names")).toArray()) {
        const QString s = v.toString().trimmed();
        if (!s.isEmpty() && d.knownNames.size() < 15 && !d.knownNames.contains(s, Qt::CaseInsensitive))
            d.knownNames << s;
    }
    for (const QJsonValue& v : attr.value(QLatin1String("tags")).toArray()) {
        const QString s = v.toString().trimmed();
        if (!s.isEmpty() && d.tags.size() < 20) d.tags << s;
    }

    // 每引擎检出:仅取判为 malicious / suspicious 的,格式「引擎名: 检出名」。
    const QJsonObject results = attr.value(QLatin1String("last_analysis_results")).toObject();
    for (auto it = results.constBegin(); it != results.constEnd(); ++it) {
        const QJsonObject r = it.value().toObject();
        const QString cat = r.value(QLatin1String("category")).toString();
        const QString result = r.value(QLatin1String("result")).toString().trimmed();
        const QString engine = it.key();
        if (cat == QLatin1String("malicious"))
            d.maliciousDetections << (engine + QStringLiteral(": ")
                                      + (result.isEmpty() ? QStringLiteral("(恶意)") : result));
        else if (cat == QLatin1String("suspicious"))
            d.suspiciousDetections << (engine + QStringLiteral(": ")
                                       + (result.isEmpty() ? QStringLiteral("(可疑)") : result));
    }
    d.maliciousDetections.sort(Qt::CaseInsensitive);
    d.suspiciousDetections.sort(Qt::CaseInsensitive);
}

bulwark::ReputationUsage VirusTotalClient::getUsage() {
    const auto snap = daily_.snapshot();
    bulwark::ReputationUsage u;
    u.source = QStringLiteral("VirusTotal");
    u.enabled = enabled_;
    u.usedToday = snap.first;
    u.dailyLimit = snap.second;
    u.perMinuteLimit = opt_.RequestsPerMinute;
    return u;
}

std::pair<bool, QString> VirusTotalClient::testConnection() {
    if (apiKey_.isEmpty())
        return { false, QStringLiteral("未配置 API 密钥") };
    bucket_.wait();
    const auto res = ReputationCurl::get(vtBase(opt_) + kEicar,
                                         { QStringLiteral("x-apikey: ") + apiKey() }, opt_.QueryTimeoutSeconds);
    switch (res.first) {
        case 200: return { true,  QStringLiteral("连接成功,API 密钥有效") };
        case 401: return { false, QStringLiteral("API 密钥无效(401)") };
        case 403: return { false, QStringLiteral("API 密钥无权限(403)") };
        case 429: return { true,  QStringLiteral("密钥有效,但当前已触发限流(429)") };
        case 404: return { true,  QStringLiteral("连接成功(测试样本未收录,密钥有效)") };
        case 0:   return { false, QStringLiteral("连接失败(curl 不可用或网络不通)") };
        default:  return { false, QStringLiteral("返回异常状态:") + QString::number(res.first) };
    }
}

} // namespace bulwark::service::reputation
