#include "bulwark/service/Logger.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

namespace bulwark::service {
namespace {

// Single background sink: serializes all writes on one thread, matching the
// .NET provider's BlockingCollection + worker-thread design.
class FileLogSink {
public:
    void start() {
        std::lock_guard<std::mutex> lk(mutex_);
        if (running_) return;
        path_ = logFilePath();
        disposed_ = false;
        running_ = true;
        worker_ = std::thread([this] { writeLoop(); });
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (!running_) return;
            disposed_ = true;
        }
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
        // running_ 是 std::atomic。原先它是普通 bool:这一句在【锁外】写,而 enqueue()
        // 在持锁状态下读它 —— 无保护的并发读写,正是数据竞争的定义。全服务十几个线程都
        // 在写日志,停服务时必然与之重叠。
        //
        // 刻意保留「join 之后才清 running_」的顺序:若提前在锁内清掉,一个并发的 start()
        // 就会看到 running_==false 并对仍处于 joinable 状态的 worker_ 赋值 —— 那是
        // std::terminate。顺序不动,只把类型换成原子的。
        running_ = false;
    }

    void enqueue(const QString& line) {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (disposed_ || !running_) return;
            if (queue_.size() >= kMaxQueue) return; // full -> drop (TryAdd semantics)
            queue_.push_back(line);
        }
        cv_.notify_one();
    }

private:
    // 批量取、批量写。
    //
    // 原实现每轮只取【一行】,而 writeOne 对每一行都做一次 QFileInfo stat + open + write +
    // close。防护事件是突发的(本项目自己的注释就描述过「几秒钟写满 5MB 日志」的场景),
    // 那等于每秒几万次开关文件句柄 —— 磁盘 IO 全花在文件系统元数据上,日志线程追不上队列,
    // 队列到 8192 就开始丢日志。改成一次排空队列、一次开文件写完整批,轮转检查也只做一次。
    void writeLoop() {
        for (;;) {
            QByteArray batch;
            {
                std::unique_lock<std::mutex> lk(mutex_);
                cv_.wait(lk, [this] { return disposed_ || !queue_.empty(); });
                if (queue_.empty()) {
                    if (disposed_) return;
                    continue;
                }
                int count = 0;
                while (!queue_.empty() && count < kMaxBatch) {
                    batch += queue_.front().toUtf8();
                    queue_.pop_front();
                    ++count;
                }
            }
            if (!batch.isEmpty())
                writeBatch(batch);
        }
    }

    void writeBatch(const QByteArray& bytes) {
        // Roll to .1 when the file grows past ~5 MB, to bound disk usage.
        QFileInfo fi(path_);
        if (fi.exists() && fi.size() > kMaxLogBytes) {
            const QString bak = path_ + ".1";
            QFile::remove(bak);
            QFile::rename(path_, bak); // failure here is non-fatal
        }
        QFile f(path_);
        if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
            f.write(bytes);
            f.close();
        }
        // A failed write must never disturb the business logic -> swallow.
    }

    static constexpr size_t kMaxQueue   = 8192;
    static constexpr int    kMaxBatch   = 512;                 // 一次最多攒多少行再落盘
    static constexpr qint64 kMaxLogBytes = 5LL * 1024 * 1024;  // 轮转阈值(原先是裸字面量)
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<QString> queue_;
    std::thread worker_;
    std::atomic<bool> running_{false};   // 见 stop():最后一次写在锁外,故必须是原子的
    bool disposed_ = false;              // 只在 mutex_ 保护下访问
    QString path_;
};

FileLogSink& sink() {
    static FileLogSink s;
    return s;
}

const char* levelTag(LogLevel level) {
    switch (level) {
        case LogLevel::Trace:       return "trce";
        case LogLevel::Debug:       return "dbug";
        case LogLevel::Information: return "info";
        case LogLevel::Warning:     return "warn";
        case LogLevel::Error:       return "fail";
        case LogLevel::Critical:    return "crit";
    }
    return "info";
}

} // namespace

QString programDataDir() {
    // BULWARK_DATA_DIR 覆盖数据/日志目录:支持便携运行、无管理员调试、多实例/冒烟测试
    // (默认 %ProgramData%\Bulwark 目录常由 SYSTEM/管理员的服务创建,非管理员进程无法写入)。
    QString dir = qEnvironmentVariable("BULWARK_DATA_DIR").trimmed();
    if (dir.isEmpty()) {
        QString base = qEnvironmentVariable("ProgramData");
        if (base.isEmpty()) base = QStringLiteral("C:/ProgramData");
        dir = base + QStringLiteral("/Bulwark");
    }
    QDir().mkpath(dir);
    return dir;
}

QString logFilePath() {
    return programDataDir() + QStringLiteral("/service.log");
}

void startFileLog() { sink().start(); }
void stopFileLog() { sink().stop(); }

void writeCrashLog(const QString& phase, const QString& detail) {
    // Mirrors Program.cs WriteCrash: full record to crash.log, never throws.
    const QString line = QStringLiteral("==== %1 [%2] PID=%3 ====\n%4\n\n")
        .arg(QDateTime::currentDateTime().toString(Qt::ISODateWithMs),
             phase,
             QString::number(QCoreApplication::applicationPid()),
             detail);
    QFile f(programDataDir() + QStringLiteral("/crash.log"));
    if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
        f.write(line.toUtf8());
        f.close();
    }
}

Logger::Logger(const QString& category) {
    // Keep only the short (last dotted segment) name, like the .NET logger.
    const int idx = category.lastIndexOf(QLatin1Char('.'));
    category_ = idx >= 0 ? category.mid(idx + 1) : category;
}

void Logger::write(LogLevel level, const QString& msg) const {
    if (!isEnabled(level)) return;
    const QString line = QStringLiteral("%1 %2 [%3] %4\n")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")),
             QLatin1String(levelTag(level)),
             category_,
             msg);
    sink().enqueue(line);
}

void Logger::error(const QString& msg, const QString& detail) const {
    if (!isEnabled(LogLevel::Error)) return;
    QString line = QStringLiteral("%1 %2 [%3] %4")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")),
             QLatin1String(levelTag(LogLevel::Error)),
             category_,
             msg);
    if (!detail.isEmpty()) line += QStringLiteral("\n") + detail;
    line += QStringLiteral("\n");
    sink().enqueue(line);
}

} // namespace bulwark::service
