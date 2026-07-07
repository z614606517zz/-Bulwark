#pragma once
#include <QString>

// 轻量文件日志(后台单线程写入,滚动到 .1),等价 .NET FileLogger + Program.cs 崩溃日志。
// 日志与崩溃日志落在 C:\ProgramData\Bulwark\。注:原 C++ 头已丢失,此处按 Logger.cpp 用法重建。
namespace bulwark::service {

enum class LogLevel { Trace, Debug, Information, Warning, Error, Critical };

QString programDataDir();                 // C:\ProgramData\Bulwark(自动创建)
QString logFilePath();                    // <programData>\service.log
void startFileLog();                      // 启动后台写入线程
void stopFileLog();                       // 停止并 flush
void writeCrashLog(const QString& phase, const QString& detail);

// 分类日志器。类别只保留最后一段(与 .NET ILogger 短名一致)。
class Logger {
public:
    explicit Logger(const QString& category);

    bool isEnabled(LogLevel level) const { return level >= minLevel_; }
    void write(LogLevel level, const QString& msg) const;
    void error(const QString& msg, const QString& detail = QString()) const;

    void trace(const QString& m) const { write(LogLevel::Trace, m); }
    void debug(const QString& m) const { write(LogLevel::Debug, m); }
    void info(const QString& m) const { write(LogLevel::Information, m); }
    void warning(const QString& m) const { write(LogLevel::Warning, m); }
    void critical(const QString& m) const { write(LogLevel::Critical, m); }

private:
    QString category_;
    LogLevel minLevel_ = LogLevel::Information;
};

} // namespace bulwark::service
