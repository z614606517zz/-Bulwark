#include "bulwark/service/EventHistoryStore.h"
#include "bulwark/service/Logger.h" // programDataDir()

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <mutex>
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

EventHistoryStore::EventHistoryStore() : d_(std::make_unique<Impl>()) {}
EventHistoryStore::~EventHistoryStore() = default;

void EventHistoryStore::add(const bulwark::ipc::EventLogPayload& payload) { d_->add(payload); }
QList<bulwark::ipc::EventLogPayload> EventHistoryStore::getRecent() { return d_->getRecent(); }
void EventHistoryStore::clear() { d_->clear(); }

} // namespace bulwark::service
