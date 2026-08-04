#include "bulwark/service/ThreatIntelContribStore.h"
#include "bulwark/service/Logger.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QMutexLocker>
#include <QSet>

namespace bulwark::service {
namespace {

// 去重 + 截断 + 去空白。所有进入记录的 IOC 列表都过这一道。
QStringList tidy(const QStringList& in, int cap) {
    QStringList out;
    QSet<QString> seen;
    for (const QString& raw : in) {
        const QString s = raw.trimmed();
        if (s.isEmpty())
            continue;
        if (seen.contains(s))
            continue;
        seen.insert(s);
        out << s;
        if (out.size() >= cap)
            break;
    }
    return out;
}

QJsonArray toArr(const QStringList& l) {
    QJsonArray a;
    for (const QString& s : l)
        a.append(s);
    return a;
}

QStringList fromArr(const QJsonValue& v) {
    QStringList l;
    const QJsonArray a = v.toArray();
    for (const QJsonValue& e : a)
        if (e.isString())
            l << e.toString();
    return l;
}

} // namespace

QJsonObject ThreatIntelContribStore::Record::toJson() const {
    QJsonObject o;
    o[QStringLiteral("sha256")] = sha256;
    o[QStringLiteral("verdict")] = verdict;
    o[QStringLiteral("malicious")] = malicious;
    o[QStringLiteral("totalEngines")] = totalEngines;
    o[QStringLiteral("threatLabel")] = threatLabel;
    o[QStringLiteral("source")] = source;
    o[QStringLiteral("scannedAtUtc")] = scannedUtc.toUTC().toString(Qt::ISODate);
    o[QStringLiteral("hasBehavior")] = hasBehavior;
    // 行为 IOC 收在 behavior 子对象里,让服务端一眼能分清「判定」与「行为」两类数据。
    QJsonObject b;
    b[QStringLiteral("droppedFileNames")] = toArr(droppedFileNames);
    b[QStringLiteral("droppedFileHashes")] = toArr(droppedFileHashes);
    b[QStringLiteral("registryKeysSet")] = toArr(registryKeysSet);
    b[QStringLiteral("processNames")] = toArr(processNames);
    b[QStringLiteral("contactedIps")] = toArr(contactedIps);
    b[QStringLiteral("contactedDomains")] = toArr(contactedDomains);
    b[QStringLiteral("serviceNames")] = toArr(serviceNames);
    b[QStringLiteral("mutexes")] = toArr(mutexes);
    o[QStringLiteral("behavior")] = b;
    return o;
}

ThreatIntelContribStore::Record
ThreatIntelContribStore::Record::fromJson(const QJsonObject& o) {
    Record r;
    r.sha256 = o.value(QStringLiteral("sha256")).toString();
    r.verdict = o.value(QStringLiteral("verdict")).toString();
    r.malicious = o.value(QStringLiteral("malicious")).toInt();
    r.totalEngines = o.value(QStringLiteral("totalEngines")).toInt();
    r.threatLabel = o.value(QStringLiteral("threatLabel")).toString();
    r.source = o.value(QStringLiteral("source")).toString();
    r.scannedUtc = QDateTime::fromString(o.value(QStringLiteral("scannedAtUtc")).toString(),
                                         Qt::ISODate);
    r.hasBehavior = o.value(QStringLiteral("hasBehavior")).toBool();
    const QJsonObject b = o.value(QStringLiteral("behavior")).toObject();
    r.droppedFileNames = fromArr(b.value(QStringLiteral("droppedFileNames")));
    r.droppedFileHashes = fromArr(b.value(QStringLiteral("droppedFileHashes")));
    r.registryKeysSet = fromArr(b.value(QStringLiteral("registryKeysSet")));
    r.processNames = fromArr(b.value(QStringLiteral("processNames")));
    r.contactedIps = fromArr(b.value(QStringLiteral("contactedIps")));
    r.contactedDomains = fromArr(b.value(QStringLiteral("contactedDomains")));
    r.serviceNames = fromArr(b.value(QStringLiteral("serviceNames")));
    r.mutexes = fromArr(b.value(QStringLiteral("mutexes")));
    return r;
}

ThreatIntelContribStore::ThreatIntelContribStore() {
    path_ = QDir(programDataDir()).filePath(QStringLiteral("pending_intel_upload.jsonl"));
    load();
}

bool ThreatIntelContribStore::fromScan(const bulwark::FileReputation& rep,
                                       const bulwark::ThreatBehaviorProfile& profile,
                                       Record* out) {
    if (!out)
        return false;
    if (rep.sha256.size() != 64 || !rep.querySucceeded)
        return false;
    // 只收集「威胁」:恶意 / 可疑。干净与未收录既不是病毒信息,也没有行为数据可言,
    // 收集它们只会白占磁盘与带宽,也让「只上传病毒信息」这句话不再成立。
    QString verdict;
    if (rep.verdict == bulwark::ReputationVerdict::Malicious)
        verdict = QStringLiteral("malicious");
    else if (rep.verdict == bulwark::ReputationVerdict::Suspicious)
        verdict = QStringLiteral("suspicious");
    else
        return false;

    Record r;
    r.sha256 = rep.sha256.toLower();
    r.verdict = verdict;
    r.malicious = std::max(0, rep.malicious);
    r.totalEngines = std::max(0, rep.totalEngines);
    r.threatLabel = rep.threatLabel.trimmed().left(256);
    r.source = rep.source.trimmed().left(64);
    r.scannedUtc = QDateTime::currentDateTimeUtc();

    // ---- 脱敏:只取 IOC 类字段 --------------------------------------------------
    // 刻意不取 profile.locatedLocalPaths(本机实际路径)与 profile.droppedFilePaths
    // (沙箱完整路径),理由见头文件的隐私边界说明。这里是唯一的取字段处,漏不掉。
    r.hasBehavior = profile.fetched;
    r.droppedFileNames  = tidy(profile.droppedFileNames,  kMaxPerList);
    r.droppedFileHashes = tidy(profile.droppedFileHashes, kMaxPerList);
    r.registryKeysSet   = tidy(profile.registryKeysSet,   kMaxPerList);
    r.processNames      = tidy(profile.processNames,      kMaxPerList);
    r.contactedIps      = tidy(profile.contactedIps,      kMaxPerList);
    r.contactedDomains  = tidy(profile.contactedDomains,  kMaxPerList);
    r.serviceNames      = tidy(profile.serviceNames,      kMaxPerList);
    r.mutexes           = tidy(profile.mutexes,           kMaxPerList);

    *out = r;
    return true;
}

void ThreatIntelContribStore::load() {
    QFile f(path_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly | QIODevice::Text))
        return;
    records_.clear();
    while (!f.atEnd()) {
        const QByteArray line = f.readLine().trimmed();
        if (line.isEmpty())
            continue;
        QJsonParseError err{};
        const QJsonDocument doc = QJsonDocument::fromJson(line, &err);
        if (err.error != QJsonParseError::NoError || !doc.isObject())
            continue; // 容错:跳过坏行(断电写一半),不让整个队列失效
        const Record r = Record::fromJson(doc.object());
        if (r.sha256.size() == 64)
            records_.append(r);
    }
    f.close();
    if (records_.size() > kMaxRecords)
        records_.remove(0, records_.size() - kMaxRecords);
}

void ThreatIntelContribStore::save() {
    // 调用方已持锁。JSONL 全量重写:队列上限 500 条,重写成本可忽略,换来删除逻辑简单。
    QFile f(path_);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
        return; // 写不进去不是致命错:内存队列仍在,下次再试
    for (const Record& r : records_) {
        f.write(QJsonDocument(r.toJson()).toJson(QJsonDocument::Compact));
        f.write("\n");
    }
    f.close();
}

void ThreatIntelContribStore::append(const Record& rec) {
    if (rec.sha256.size() != 64)
        return;
    QMutexLocker lk(&lock_);
    // 同一样本已排队 -> 用新记录替换(判定可能更新、行为画像可能这次才拉到),不重复排队。
    for (int i = 0; i < records_.size(); ++i) {
        if (records_.at(i).sha256.compare(rec.sha256, Qt::CaseInsensitive) == 0) {
            records_[i] = rec;
            save();
            return;
        }
    }
    records_.append(rec);
    if (records_.size() > kMaxRecords)
        records_.remove(0, records_.size() - kMaxRecords); // 丢最旧的
    save();
}

QVector<ThreatIntelContribStore::Record> ThreatIntelContribStore::snapshot() const {
    QMutexLocker lk(&lock_);
    return records_;
}

int ThreatIntelContribStore::removeUploaded(const QStringList& sha256List) {
    if (sha256List.isEmpty())
        return 0;
    QSet<QString> done;
    for (const QString& s : sha256List)
        done.insert(s.toLower());

    QMutexLocker lk(&lock_);
    int before = records_.size();
    QVector<Record> keep;
    keep.reserve(records_.size());
    for (const Record& r : records_)
        if (!done.contains(r.sha256.toLower()))
            keep.append(r);
    const int removed = before - keep.size();
    if (removed > 0) {
        records_ = keep;
        save();
    }
    return removed;
}

int ThreatIntelContribStore::purgeAll() {
    QMutexLocker lk(&lock_);
    const int had = records_.size();
    records_.clear();
    // 直接删文件,而不是写一个空文件 —— 用户关掉共享后,磁盘上不该再留下这个文件。
    QFile::remove(path_);
    return had;
}

int ThreatIntelContribStore::count() const {
    QMutexLocker lk(&lock_);
    return records_.size();
}

} // namespace bulwark::service
