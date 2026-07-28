#include "bulwark/service/EventHistoryStore.h"
#include "bulwark/service/Logger.h" // programDataDir()

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>

#include <QJsonParseError>
#include <QSet>

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>

namespace bulwark::service {

using bulwark::ipc::EventLogPayload;

struct EventHistoryStore::Impl {
    static constexpr int kMaxRecords = 500;              // memory + readback cap
    static constexpr qint64 kMaxFileBytes = 24LL * 1024 * 1024;
    static constexpr size_t kQueueCapacity = 20000;
    static constexpr int kMaxBatch = 512;

    QString path;
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<QString> queue;             // serialized lines pending disk write
    std::deque<EventLogPayload> buffer;    // recent records for fast readback
    std::thread worker;
    bool disposed = false;
    bool clearRequested = false;           // clear() 请求;由写线程截断文件(单线程持有文件)

    Impl() {
        const QString dir = QDir(programDataDir()).filePath(QStringLiteral("history"));
        QDir().mkpath(dir);
        path = QDir(dir).filePath(QStringLiteral("events.jsonl"));
        load();
        worker = std::thread([this] { writeLoop(); });
    }

    ~Impl() {
        {
            std::lock_guard<std::mutex> lk(mutex);
            disposed = true;
        }
        cv.notify_all();
        if (worker.joinable()) worker.join();
    }

    // Read back the most recent kMaxRecords lines so restart preserves history.
    void load() {
        QFile f(path);
        if (!f.exists() || !f.open(QIODevice::ReadOnly)) return;
        const QByteArray raw = f.readAll();
        f.close();
        const QList<QByteArray> lines = raw.split('\n');
        const int start = std::max<int>(0, static_cast<int>(lines.size()) - kMaxRecords);
        for (int i = start; i < lines.size(); ++i) {
            const QByteArray line = lines[i].trimmed();
            if (line.isEmpty()) continue;
            QJsonParseError err{};
            const QJsonDocument doc = QJsonDocument::fromJson(line, &err);
            if (err.error == QJsonParseError::NoError && doc.isObject())
                buffer.push_back(EventLogPayload::fromJson(doc.object()));
        }
    }

    QString serialize(const EventLogPayload& p) const {
        return QString::fromUtf8(QJsonDocument(p.toJson()).toJson(QJsonDocument::Compact));
    }

    void add(const EventLogPayload& payload) {
        const QString line = serialize(payload);
        {
            std::lock_guard<std::mutex> lk(mutex);
            buffer.push_back(payload);
            while (static_cast<int>(buffer.size()) > kMaxRecords) buffer.pop_front();
            if (queue.size() < kQueueCapacity) queue.push_back(line); // else drop newest
        }
        cv.notify_one();
    }

    QList<EventLogPayload> getRecent() {
        std::lock_guard<std::mutex> lk(mutex);
        QList<EventLogPayload> out;
        out.reserve(static_cast<int>(buffer.size()));
        for (const EventLogPayload& p : buffer) out.append(p);
        return out;
    }

    // 清空:立即清内存(缓冲 + 待写队列),并请求写线程截断落盘文件。文件仅由写线程
    // 触碰,因此无需在此做文件 I/O,避免与 writeLoop 的追加写产生竞态。
    void clear() {
        {
            std::lock_guard<std::mutex> lk(mutex);
            buffer.clear();
            queue.clear();
            clearRequested = true;
        }
        cv.notify_one();
    }

    void writeLoop() {
        for (;;) {
            QByteArray batch;
            bool doClear = false;
            {
                std::unique_lock<std::mutex> lk(mutex);
                cv.wait(lk, [this] { return disposed || !queue.empty() || clearRequested; });
                if (clearRequested) { clearRequested = false; doClear = true; }
                int count = 0;
                while (count < kMaxBatch && !queue.empty()) {
                    batch += queue.front().toUtf8();
                    batch += '\n';
                    queue.pop_front();
                    ++count;
                }
                if (batch.isEmpty() && !doClear) {
                    if (disposed) return;
                    continue;
                }
            }
            // 先截断(清空请求),再写本批 —— 清空后到达的新事件仍能正确落盘。
            if (doClear) {
                QFile f(path);
                if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) f.close();
            }
            if (!batch.isEmpty()) {
                QFile f(path);
                if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
                    f.write(batch);
                    f.close();
                }
            }
            compact();
        }
    }

    // When the file exceeds the cap, rewrite it from the current buffer snapshot
    // to bound growth (keeps only the most recent kMaxRecords records).
    void compact() {
        if (QFileInfo(path).size() < kMaxFileBytes) return;
        QByteArray out;
        {
            std::lock_guard<std::mutex> lk(mutex);
            for (const EventLogPayload& p : buffer) {
                out += serialize(p).toUtf8();
                out += '\n';
            }
        }
        QFile f(path);
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            f.write(out);
            f.close();
        }
    }
};

// ============================ 取证查询(只读扫落盘) ============================
namespace {

constexpr int kMaxScanLines = 40000;   // 单次查询最多回看多少条(护栏:防病态大文件卡死)
constexpr int kHardLimit = 5000;       // 单次返回硬上限

// 倒序遍历 JSONL:从最新一条往回走。历史是追加写的,时间基本单调,所以倒序能尽早停下来。
// visit 返回 false 表示「不必再往回看了」。
void scanBackwards(const QString& path, int maxLines,
                   const std::function<bool(const QByteArray& line)>& visit)
{
    QFile f(path);
    if (!f.exists() || !f.open(QIODevice::ReadOnly))
        return;
    const QByteArray raw = f.readAll();
    f.close();
    if (raw.isEmpty())
        return;

    int end = raw.size();
    int scanned = 0;
    while (end > 0 && scanned < maxLines) {
        int start = raw.lastIndexOf('\n', end - 1);
        const int from = start + 1;
        const QByteArray line = raw.mid(from, end - from).trimmed();
        end = start; // 下一轮找上一行(start<0 时 end=-1,循环结束)
        if (line.isEmpty())
            continue;
        ++scanned;
        if (!visit(line))
            return;
    }
}

std::optional<bulwark::ipc::EventLogPayload> parseLine(const QByteArray& line)
{
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(line, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return std::nullopt;
    return bulwark::ipc::EventLogPayload::fromJson(doc.object());
}

// 历史里最早一条的时间(只解析第一行,便宜)。UI 据此显示「可回溯到什么时候」。
QDateTime earliestTimestamp(const QString& path)
{
    QFile f(path);
    if (!f.exists() || !f.open(QIODevice::ReadOnly))
        return QDateTime();
    const QByteArray line = f.readLine(64 * 1024).trimmed();
    f.close();
    if (const auto p = parseLine(line))
        return p->event.timestampUtc;
    return QDateTime();
}

// 进程树归属:后代事件的 chainContext 里一定带着祖先 PID(富化阶段用 OS API 种入),
// 所以不需要全局父子表,逐条本地判断即可。
bool belongsToProcess(const bulwark::ipc::EventLogPayload& p, int pid, bool includeTree)
{
    const bulwark::SecurityEvent& e = p.event;
    if (e.actorPid == pid)
        return true;
    if (!includeTree)
        return false;
    if (e.parentPid == pid || e.originatorPid == pid)
        return true;
    for (const bulwark::ChainEventInfo& c : e.chainContext)
        if (c.actorPid == pid)
            return true;
    return false;
}

bool matchesText(const bulwark::ipc::EventLogPayload& p, const QString& text)
{
    if (text.isEmpty())
        return true;
    const bulwark::SecurityEvent& e = p.event;
    const Qt::CaseSensitivity ci = Qt::CaseInsensitive;
    return e.actorPath.contains(text, ci) || e.target.contains(text, ci)
        || e.commandLine.contains(text, ci) || e.actorPublisher.contains(text, ci)
        || e.detail.contains(text, ci) || e.matchedRuleNote.contains(text, ci)
        || e.originService.contains(text, ci) || e.originTask.contains(text, ci);
}

} // namespace

EventHistoryStore::EventHistoryStore() : d_(std::make_unique<Impl>()) {}
EventHistoryStore::~EventHistoryStore() = default;

void EventHistoryStore::add(const bulwark::ipc::EventLogPayload& payload) { d_->add(payload); }
QList<bulwark::ipc::EventLogPayload> EventHistoryStore::getRecent() { return d_->getRecent(); }
void EventHistoryStore::clear() { d_->clear(); }

bulwark::ipc::TimelineResponsePayload
EventHistoryStore::query(const bulwark::ipc::TimelineRequestPayload& req)
{
    bulwark::ipc::TimelineResponsePayload res;
    res.requestId = req.requestId;
    res.earliestUtc = earliestTimestamp(d_->path);

    const int limit = std::clamp(req.limit <= 0 ? 500 : req.limit, 1, kHardLimit);
    const QSet<int> types(req.types.begin(), req.types.end());
    const QSet<int> actions(req.actions.begin(), req.actions.end());
    const QString text = req.text.trimmed();

    QList<bulwark::ipc::EventLogPayload> hits; // 倒序收集(新 -> 旧)
    int scanned = 0;
    int matched = 0;
    int belowWindow = 0; // 连续落在时间窗下界之外的条数(容忍少量乱序后即停)

    // 关键字预筛用的小写 UTF-8 形态:QByteArray::toLower 只折叠 ASCII,对中文字节原样保留,
    // 因此「ASCII 大小写不敏感 + 非 ASCII 精确匹配」正好是一个保守筛子 —— 只会多留、不会漏掉,
    // 真正的判定仍由下面的 matchesText 完成。
    const QByteArray textNeedle = text.toUtf8().toLower();

    scanBackwards(d_->path, kMaxScanLines, [&](const QByteArray& line) {
        ++scanned;
        // 便宜的原始文本预筛:关键字连原始字节里都没有,就不必解析这行 JSON。
        if (!textNeedle.isEmpty() && !line.toLower().contains(textNeedle))
            return true;
        const auto parsed = parseLine(line);
        if (!parsed)
            return true;
        const bulwark::SecurityEvent& e = parsed->event;

        if (req.fromUtc.isValid() && e.timestampUtc.isValid() && e.timestampUtc < req.fromUtc) {
            if (++belowWindow > 200)
                return false; // 已稳定越过下界,再往回都是更早的,停
            return true;
        }
        belowWindow = 0;
        if (req.toUtc.isValid() && e.timestampUtc.isValid() && e.timestampUtc > req.toUtc)
            return true;
        if (!types.isEmpty() && !types.contains(static_cast<int>(e.type)))
            return true;
        if (!actions.isEmpty() && !actions.contains(static_cast<int>(parsed->action)))
            return true;
        if (e.riskScore < req.minRiskScore)
            return true;
        if (req.pid > 0 && !belongsToProcess(*parsed, req.pid, req.includeProcessTree))
            return true;
        if (!matchesText(*parsed, text))
            return true;

        ++matched;
        if (hits.size() < limit)
            hits.append(*parsed);
        else
            res.truncated = true;
        return true;
    });

    res.scanned = scanned;
    res.matched = matched;
    // 收集时是「新 -> 旧」,对外统一按时间升序(与实时推送一致)。
    std::reverse(hits.begin(), hits.end());
    res.events = hits;
    res.message = res.truncated
        ? QStringLiteral("扫描 %1 条,命中 %2 条,已按上限返回最近 %3 条")
              .arg(scanned).arg(matched).arg(hits.size())
        : QStringLiteral("扫描 %1 条,命中 %2 条").arg(scanned).arg(matched);
    return res;
}

QList<bulwark::ipc::EventLogPayload>
EventHistoryStore::eventsInWindow(const QDateTime& fromUtc, const QDateTime& toUtc, int maxEvents)
{
    QList<bulwark::ipc::EventLogPayload> out;
    const int cap = std::clamp(maxEvents <= 0 ? 2000 : maxEvents, 1, kHardLimit);
    int belowWindow = 0;

    scanBackwards(d_->path, kMaxScanLines, [&](const QByteArray& line) {
        const auto parsed = parseLine(line);
        if (!parsed)
            return true;
        const QDateTime ts = parsed->event.timestampUtc;
        if (fromUtc.isValid() && ts.isValid() && ts < fromUtc)
            return ++belowWindow <= 200;
        belowWindow = 0;
        if (toUtc.isValid() && ts.isValid() && ts > toUtc)
            return true;
        out.append(*parsed);
        return out.size() < cap;
    });

    std::reverse(out.begin(), out.end());
    return out;
}

std::optional<bulwark::ipc::EventLogPayload> EventHistoryStore::findById(const QUuid& id)
{
    if (id.isNull())
        return std::nullopt;
    // 先查内存缓冲:刚发生的事件(用户刚在日志里双击的那条)几乎总在这里。
    for (const bulwark::ipc::EventLogPayload& p : d_->getRecent())
        if (p.event.id == id)
            return p;

    std::optional<bulwark::ipc::EventLogPayload> found;
    scanBackwards(d_->path, kMaxScanLines, [&](const QByteArray& line) {
        // 便宜预筛:id 的文本形态一定出现在这一行里。
        if (!line.contains(id.toString(QUuid::WithoutBraces).toUtf8()))
            return true;
        const auto parsed = parseLine(line);
        if (parsed && parsed->event.id == id) {
            found = parsed;
            return false;
        }
        return true;
    });
    return found;
}

} // namespace bulwark::service
