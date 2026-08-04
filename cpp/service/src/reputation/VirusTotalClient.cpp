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

// 直传上限:>32MB 需先取一次性专用上传 URL。上传扫描可处理的最大文件(VT 大文件上限 650MB,
// 与中央代理 max_upload_mb 对齐)。
constexpr qint64 kDirectUploadMaxBytes = 32LL * 1024 * 1024;
constexpr qint64 kMaxUploadBytes       = 650LL * 1024 * 1024;

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
    : opt_(options.VirusTotal), log_(QStringLiteral("VirusTotal")) {
    // 多 Key 来源:环境变量 > 配置文件 > 内置 Key。各来源均可逗号分隔多 Key,
    // 每个可选标注 "KEY:RPD:RPM"(不标注则用 opt_ 默认,即 VT 免费档 500/天、4/分)。
    const QString env = qEnvironmentVariable(VirusTotalOptions::ApiKeyEnvVar).trimmed();
    QString raw;
    QString keySource;
    if (!env.isEmpty()) {
        raw = env;
        keySource = QStringLiteral("环境变量 Key");
    } else if (!opt_.ApiKey.trimmed().isEmpty()) {
        raw = opt_.ApiKey.trimmed();
        keySource = QStringLiteral("配置文件 Key");
    } else {
        raw = builtInApiKey();
        keySource = raw.isEmpty() ? QStringLiteral("未配置 Key,查询禁用") : QStringLiteral("内置 Key");
    }
    rebuildPool(raw); // 设置 keys_ + enabled_

    // 汇总总额度(各 Key 相加),让日志直观反映「多 Key 真正叠加」。
    int totalRpm = 0, totalRpd = 0;
    { QMutexLocker lk(&keyMutex_);
      for (const auto& ks : keys_) { totalRpm += ks->rpm; totalRpd += ks->rpd; } }
    log_.info(QStringLiteral("VirusTotal 信誉查询就绪(经 curl,%1 个 Key,合计限流 %2/min、%3/day,来源:%4);"
                             "每 Key 独立计账,是否参与查询由运行时开关控制。")
                  .arg(keyCount()).arg(totalRpm).arg(totalRpd).arg(keySource));
}

void VirusTotalClient::rebuildPool(const QString& raw) {
    std::vector<std::shared_ptr<KeyState>> pool;
    for (const QString& entry : raw.split(QLatin1Char(','), Qt::SkipEmptyParts)) {
        // 每条形如 KEY 或 KEY:RPD 或 KEY:RPD:RPM(VT Key 为 64 位十六进制,不含冒号,分隔安全)。
        const QStringList parts = entry.split(QLatin1Char(':'));
        const QString key = parts.value(0).trimmed();
        if (key.isEmpty()) continue;
        bool okRpd = false, okRpm = false;
        int rpd = parts.value(1).trimmed().toInt(&okRpd);
        int rpm = parts.value(2).trimmed().toInt(&okRpm);
        if (!okRpd || rpd <= 0) rpd = std::max(1, opt_.RequestsPerDay);   // 默认 VT 免费档
        if (!okRpm || rpm <= 0) rpm = std::max(1, opt_.RequestsPerMinute);
        const int reserve = std::max(0, std::min(opt_.PriorityDailyReserve, rpd - 1));
        pool.push_back(std::make_shared<KeyState>(key, rpm, rpd, reserve));
    }
    QMutexLocker lk(&keyMutex_);
    keys_ = std::move(pool);
    rrCursor_ = 0;
    enabled_ = !keys_.empty();
}

int VirusTotalClient::keyCount() const {
    QMutexLocker lk(&keyMutex_);
    return static_cast<int>(keys_.size());
}

std::shared_ptr<VirusTotalClient::KeyState> VirusTotalClient::acquireKey(bool priority) {
    std::vector<std::shared_ptr<KeyState>> snap;
    int start = 0;
    { QMutexLocker lk(&keyMutex_);
      if (keys_.empty()) return nullptr;
      snap = keys_;                                     // 持有一份快照,请求全程不怕 setApiKey 重建
      start = rrCursor_;
      rrCursor_ = (rrCursor_ + 1) % static_cast<int>(keys_.size()); }

    const int n = static_cast<int>(snap.size());
    const QDateTime nowUtc = QDateTime::currentDateTimeUtc();
    std::shared_ptr<KeyState> chosen;
    for (int i = 0; i < n; ++i) {
        const auto& ks = snap[(start + i) % n];
        { QMutexLocker sl(&ks->stateMx);
          if (ks->disabledUntilUtc.isValid() && nowUtc < ks->disabledUntilUtc)
              continue; } // 冷却中(429/鉴权失败),跳过该 Key
        if (ks->daily.tryConsume(priority)) { chosen = ks; break; } // 占用该 Key 的日配额
    }
    if (!chosen)
        return nullptr;             // 所有 Key 日配额耗尽 / 冷却中 -> 调用方 fail-open
    chosen->bucket.wait(priority);  // 已占日配额,等该 Key 的分钟令牌(4/min,很快补充)
    return chosen;
}

std::shared_ptr<VirusTotalClient::KeyState> VirusTotalClient::acquireProbeKey() {
    QMutexLocker lk(&keyMutex_);
    if (keys_.empty()) return nullptr;
    const int idx = rrCursor_ % static_cast<int>(keys_.size());
    rrCursor_ = (idx + 1) % static_cast<int>(keys_.size());
    return keys_[idx];
}

void VirusTotalClient::noteHttpResult(const std::shared_ptr<KeyState>& ks, int httpCode) {
    if (!ks) return;
    QMutexLocker sl(&ks->stateMx);
    if (httpCode == 429)
        ks->disabledUntilUtc = QDateTime::currentDateTimeUtc().addSecs(60);       // 限流:冷却 60s
    else if (httpCode == 401 || httpCode == 403)
        ks->disabledUntilUtc = QDateTime::currentDateTimeUtc().addSecs(6 * 3600);  // 鉴权失败:长冷却 6h
    else if (httpCode == 200 || httpCode == 404)
        ks->disabledUntilUtc = QDateTime();                                        // 正常:清除冷却
}

void VirusTotalClient::setApiKey(const QString& key) {
    const QString k = key.trimmed();
    rebuildPool(k.isEmpty() ? builtInApiKey() : k);
    log_.info(QStringLiteral("setApiKey: key.len=%1, pool=%2, enabled=%3")
                  .arg(key.length()).arg(keyCount()).arg(enabled_.load()));
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

    auto ks = acquireKey(priority);
    if (!ks) {
        log_.debug(QStringLiteral("VirusTotal 日配额已用尽(所有 Key),跳过查询 ") + sha256.left(12));
        return unknown;
    }

    const QStringList headers{ QStringLiteral("x-apikey: ") + ks->key };
    const auto res = ReputationCurl::get(vtBase(opt_) + sha256, headers, opt_.QueryTimeoutSeconds);
    noteHttpResult(ks, res.first);
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
    auto ks = acquireKey(false);
    if (!ks) {
        diag(QStringLiteral("上传扫描跳过:VT 日配额已用尽(所有 Key)"));
        return unknown;
    }

    const QStringList headers{ QStringLiteral("x-apikey: ") + ks->key };
    const QString name = fi.fileName();

    // acquireKey 已占该 Key 一枚令牌,覆盖(大文件的)取上传 URL + 上传本体,与 .NET 行为一致。
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
        noteHttpResult(ks, up.first);
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
    // 自适应轮询节奏:VT 分析常在数秒内就绪(尤其近期已被他人分析过的样本),故先用递增的
    // 短间隔快速轮询,再退避到稳态间隔。旧实现固定「先睡 15s 再轮询」——哪怕分析 3s 就完成,
    // 用户也要干等满 15s 才看到「双击云扫描」结论;首个短间隔把这段无谓等待直接砍掉。
    // 关键:bucket.wait() 仍是配额闸门。启动时令牌桶已备有若干分钟令牌(acquireKey 只取走一枚),
    // 早期几轮加速轮询消耗的正是这些余量;令牌耗尽后 wait() 自动把节奏压回每分钟预算内(约 15s/次),
    // 故加速轮询绝不超配额,也不改变结论(仅缩短时延)。
    static constexpr int kPollBackoffSecs[] = { 3, 5, 8, 12 };
    static constexpr int kPollBackoffCount = static_cast<int>(sizeof(kPollBackoffSecs) / sizeof(kPollBackoffSecs[0]));
    static constexpr int kPollSteadySecs = 15; // 稳态间隔(与 4/min 免费档令牌补充节奏对齐)
    int pollRound = 0;
    while (QDateTime::currentMSecsSinceEpoch() < deadline) {
        const int waitSecs = pollRound < kPollBackoffCount ? kPollBackoffSecs[pollRound] : kPollSteadySecs;
        ++pollRound;
        std::this_thread::sleep_for(std::chrono::seconds(waitSecs));
        ks->bucket.wait();

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

    // 每 Key 独立计账:行为报告只在「确认恶意」后拉取,频次很低。
    auto ks = acquireKey(false);
    if (!ks) {
        diag(QStringLiteral("behaviour %1 => 跳过(所有 Key 日配额已用尽)").arg(sha256.left(12)));
        return prof;
    }

    const QStringList headers{ QStringLiteral("x-apikey: ") + ks->key };
    const QString url = vtBase(opt_) + sha256 + QStringLiteral("/behaviour_summary");
    const auto res = ReputationCurl::get(url, headers, opt_.QueryTimeoutSeconds);
    noteHttpResult(ks, res.first);
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
    auto ks = acquireKey(false);
    if (!ks) {
        d.message = QStringLiteral("VirusTotal 日配额已用尽(所有 Key),稍后再试");
        return d;
    }
    const QStringList headers{ QStringLiteral("x-apikey: ") + ks->key };
    const auto res = ReputationCurl::get(vtBase(opt_) + sha256, headers, opt_.QueryTimeoutSeconds);
    noteHttpResult(ks, res.first);
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
    bulwark::ReputationUsage u;
    u.source = QStringLiteral("VirusTotal");
    u.enabled = enabled_;
    // 跨所有 Key 汇总(今日已用 / 每日上限 / 每分钟上限),反映多 Key 叠加后的总额度。
    std::vector<std::shared_ptr<KeyState>> snap;
    { QMutexLocker lk(&keyMutex_); snap = keys_; }
    for (const auto& ks : snap) {
        const auto s = ks->daily.snapshot();
        u.usedToday += s.first;
        u.dailyLimit += s.second;
        u.perMinuteLimit += ks->rpm;
    }
    return u;
}

std::pair<bool, QString> VirusTotalClient::testConnection() {
    auto ks = acquireProbeKey();
    if (!ks)
        return { false, QStringLiteral("未配置 API 密钥") };
    ks->bucket.wait();
    const auto res = ReputationCurl::get(vtBase(opt_) + kEicar,
                                         { QStringLiteral("x-apikey: ") + ks->key }, opt_.QueryTimeoutSeconds);
    noteHttpResult(ks, res.first);
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
