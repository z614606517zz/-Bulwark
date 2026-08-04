#include "bulwark/service/reputation/AggregateReputationService.h"

#include <QDateTime>
#include <QMutexLocker>
#include <QStringList>

#include <future>
#include <vector>

namespace bulwark::service::reputation {
namespace {
inline QString u(const char* s) { return QString::fromUtf8(s); }
} // namespace

AggregateReputationService::AggregateReputationService(
    std::vector<std::unique_ptr<IHashReputationService>> sources)
    : sources_(std::move(sources)) {
    QStringList enabled;
    for (const auto& s : sources_)
        if (s && s->isEnabled())
            enabled << s->name();
    log_.info(u("信誉聚合器就绪,已启用源:")
              + (enabled.isEmpty() ? u("(无)") : enabled.join(QStringLiteral(", "))));
}

bool AggregateReputationService::isActive(IHashReputationService* s) const {
    if (!s || !s->isEnabled())
        return false;
    QMutexLocker lk(&runtimeLock_);
    const auto it = runtimeEnabled_.constFind(s->name());
    return it == runtimeEnabled_.constEnd() || it.value();
}

bool AggregateReputationService::isEnabled() const {
    for (const auto& s : sources_)
        if (isActive(s.get()))
            return true;
    return false;
}

int AggregateReputationService::rank(bulwark::ReputationVerdict v) {
    switch (v) {
        case bulwark::ReputationVerdict::Malicious:  return 3;
        case bulwark::ReputationVerdict::Suspicious: return 2;
        case bulwark::ReputationVerdict::Clean:      return 1;
        default:                                     return 0;
    }
}

bulwark::FileReputation AggregateReputationService::merge(
    const QString& sha256, const QVector<bulwark::FileReputation>& results) {
    bool anySucceeded = false;
    const bulwark::FileReputation* best = nullptr;
    for (const bulwark::FileReputation& r : results) {
        if (r.querySucceeded)
            anySucceeded = true;
        if (best == nullptr || rank(r.verdict) > rank(best->verdict))
            best = &r;
    }
    bulwark::FileReputation merged;
    merged.sha256 = sha256;
    if (best != nullptr) {
        merged.verdict = best->verdict;
        merged.malicious = best->malicious;
        merged.totalEngines = best->totalEngines;
        merged.threatLabel = best->threatLabel;
        merged.lastAnalysisUtc = best->lastAnalysisUtc;
        merged.source = best->source; // 携带胜出源名(如 MalwareBazaar),供 UI/记录标注
    }
    merged.fetchedUtc = QDateTime::currentDateTimeUtc();
    merged.querySucceeded = anySucceeded;
    return merged;
}

bulwark::FileReputation AggregateReputationService::query(const QString& sha256) {
    return query(sha256, false);
}

bulwark::FileReputation AggregateReputationService::query(const QString& sha256, bool priority) {
    return queryFiltered(sha256, priority, QString());
}

bulwark::FileReputation AggregateReputationService::queryExcluding(const QString& sha256, bool priority,
                                                                   const QString& excludeSource) {
    return queryFiltered(sha256, priority, excludeSource);
}

bulwark::FileReputation AggregateReputationService::queryFiltered(const QString& sha256, bool priority,
                                                                  const QString& excludeSource) {
    bulwark::FileReputation unknown;
    unknown.sha256 = sha256;
    if (sha256.isEmpty())
        return unknown;

    // 先取当前活跃源快照(isActive 持锁读运行时开关),后续查询不再持锁。
    // excludeSource 非空时跳过同名源(不区分大小写),供分级链路「只查其他源」。
    std::vector<IHashReputationService*> active;
    active.reserve(sources_.size());
    for (const auto& s : sources_) {
        if (!isActive(s.get()))
            continue;
        if (!excludeSource.isEmpty() && s->name().compare(excludeSource, Qt::CaseInsensitive) == 0)
            continue;
        active.push_back(s.get());
    }
    if (active.empty())
        return unknown;

    // 单个源查询(fail-open + 记录命中源名)。priority 透传给各源:VT 会据此占用预留的优先级
    // 配额(供内存防护/反注入验证低延迟命中,尽量不被双击查杀等普通查询挤占);不支持优先级的
    // 源忽略该参数。并发路径下任何异常都在此吞掉并降级为 Unknown,绝不跨线程逸出。
    const auto queryOne = [sha256, priority](IHashReputationService* s) -> bulwark::FileReputation {
        try {
            bulwark::FileReputation r = s->query(sha256, priority);
            if (r.source.isEmpty())
                r.source = s->name(); // 记录该结论来自哪个源,供合并后标注命中来源
            return r;
        } catch (...) {
            bulwark::FileReputation r;
            r.sha256 = sha256;
            r.source = s->name();
            return r; // Unknown / querySucceeded=false
        }
    };

    QVector<bulwark::FileReputation> results;
    results.reserve(static_cast<int>(active.size()));

    if (active.size() == 1) {
        // 只有一个活跃源(常见默认:仅 VirusTotal)——直接查,免去起线程的无谓开销。
        results.append(queryOne(active.front()));
    } else {
        // 并行查询各活跃源。串行时总延迟是「各源之和」,最慢一路(超时源)会把「双击云扫描」
        // 在 VT 未收录、需回退多源时的等待拖成数十秒;并行后总延迟收敛到「最慢的单源」。
        // 各客户端自身 fail-open、各自独立限流且线程安全(VT 已被多个后台 worker 并发调用),
        // 彼此无共享可变态;merge 取「最强可信结论」,与完成顺序无关,故并行只改时延不改结论。
        std::vector<std::future<bulwark::FileReputation>> futures;
        futures.reserve(active.size());
        for (IHashReputationService* s : active)
            futures.push_back(std::async(std::launch::async, queryOne, s));
        for (auto& f : futures)
            results.append(f.get()); // get() 逐个等待;queryOne 已吞异常,这里不会抛
    }

    return merge(sha256, results);
}

bulwark::ThreatBehaviorProfile AggregateReputationService::fetchBehaviorProfile(const QString& sha256) {
    bulwark::ThreatBehaviorProfile merged;
    merged.sha256 = sha256;
    if (sha256.isEmpty())
        return merged;

    QStringList srcNames;
    for (const auto& s : sources_) {
        if (!isActive(s.get()))
            continue;
        const bulwark::ThreatBehaviorProfile p = s->fetchBehaviorProfile(sha256);
        if (!p.fetched || p.isEmpty())
            continue;
        srcNames << s->name();
        merged.fetched = true;
        merged.droppedFileNames  += p.droppedFileNames;
        merged.droppedFileHashes += p.droppedFileHashes;
        merged.registryKeysSet   += p.registryKeysSet;
        merged.processNames      += p.processNames;
        merged.contactedIps      += p.contactedIps;
        merged.contactedDomains  += p.contactedDomains;
        merged.serviceNames      += p.serviceNames;
        merged.mutexes           += p.mutexes;
    }
    // 多源并集去重。
    merged.droppedFileNames.removeDuplicates();
    merged.droppedFileHashes.removeDuplicates();
    merged.registryKeysSet.removeDuplicates();
    merged.processNames.removeDuplicates();
    merged.contactedIps.removeDuplicates();
    merged.contactedDomains.removeDuplicates();
    merged.serviceNames.removeDuplicates();
    merged.mutexes.removeDuplicates();
    merged.source = srcNames.join(QStringLiteral(", "));
    return merged;
}

std::pair<bool, QString> AggregateReputationService::testConnection() {
    QStringList parts;
    bool anyOk = false;
    int activeCount = 0;
    for (const auto& s : sources_) {
        if (!isActive(s.get()))
            continue;
        ++activeCount;
        const auto r = s->testConnection();
        if (r.first)
            anyOk = true;
        parts << (s->name() + QStringLiteral(": ")
                  + (r.first ? QStringLiteral("OK ") : QStringLiteral("X ")) + r.second);
    }
    if (activeCount == 0)
        return { false, u("未启用任何信誉源") };
    return { anyOk, parts.join(QStringLiteral(" | ")) };
}

std::pair<bool, QString> AggregateReputationService::testConnection(const QString& source) {
    for (const auto& s : sources_) {
        if (s->name().compare(source, Qt::CaseInsensitive) != 0)
            continue;
        if (!s->isEnabled())
            return { false, source + u(" 未配置或不可用(检查开关与 API Key)") };
        return s->testConnection();
    }
    return { false, u("未找到信誉源:") + source };
}

bulwark::ReputationUsage AggregateReputationService::getUsage() {
    bulwark::ReputationUsage u2;
    u2.source = QStringLiteral("Aggregate");
    u2.enabled = isEnabled();
    return u2;
}

QVector<bulwark::ReputationUsage> AggregateReputationService::getUsages() {
    QVector<bulwark::ReputationUsage> list;
    for (const auto& s : sources_) {
        bulwark::ReputationUsage usage = s->getUsage();
        usage.enabled = isActive(s.get());
        list.append(usage);
    }
    return list;
}

void AggregateReputationService::setRuntimeEnabled(bool virusTotal, bool malwareBazaar, bool otx,
                                                   bool threatBook, bool metaDefender,
                                                   bool hybridAnalysis) {
    QMutexLocker lk(&runtimeLock_);
    runtimeEnabled_[QStringLiteral("VirusTotal")]     = virusTotal;
    runtimeEnabled_[QStringLiteral("MalwareBazaar")]  = malwareBazaar;
    runtimeEnabled_[QStringLiteral("OTX")]            = otx;
    runtimeEnabled_[QStringLiteral("ThreatBook")]     = threatBook;
    runtimeEnabled_[QStringLiteral("MetaDefender")]   = metaDefender;
    runtimeEnabled_[QStringLiteral("HybridAnalysis")] = hybridAnalysis;
}

void AggregateReputationService::setApiKey(const QString& sourceName, const QString& key) {
    for (const auto& s : sources_)
        if (s && s->name().compare(sourceName, Qt::CaseInsensitive) == 0)
            s->setApiKey(key);
}

} // namespace bulwark::service::reputation
