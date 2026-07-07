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
    void writeLoop() {
        for (;;) {
            QString line;
            {
                std::unique_lock<std::mutex> lk(mutex_);
                cv_.wait(lk, [this] { return disposed_ || !queue_.empty(); });
                if (queue_.empty()) {
                    if (disposed_) return;
                    continue;
                }
                line = queue_.front();
                queue_.pop_front();
            }
            writeOne(line);
        }
    }

    void writeOne(const QString& line) {
        // Roll to .1 when the file grows past ~5 MB, to bound disk usage.
        QFileInfo fi(path_);
        if (fi.exists() && fi.size() > 5LL * 1024 * 1024) {
            const QString bak = path_ + ".1";
            QFile::remove(bak);
            QFile::rename(path_, bak); // failure here is non-fatal
        }
        QFile f(path_);
        if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
            f.write(line.toUtf8());
            f.close();
        }
        // A failed write must never disturb the business logic -> swallow.
    }

    static constexpr size_t kMaxQueue = 8192;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<QString> queue_;
    std::thread worker_;
    bool running_ = false;
    bool disposed_ = false;
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
