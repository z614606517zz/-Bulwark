using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Bulwark.Service;

/// <summary>
/// 极简文件日志 provider。把日志按行追加到 %ProgramData%\Bulwark\service.log,
/// 便于在无控制台(作为服务 / 提权后台运行)时排查内核驱动连接、重连等行为。
/// 单后台线程串行落盘,带容量滚动(超过 ~5MB 截断重写),绝不抛断业务。
/// </summary>
public sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly string _path;
    private readonly BlockingCollection<string> _queue = new(8192);
    private readonly Thread _worker;
    private volatile bool _disposed;

    public FileLoggerProvider()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bulwark");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "service.log");

        _worker = new Thread(WriteLoop) { IsBackground = true, Name = "BulwarkFileLog" };
        _worker.Start();
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(categoryName, Enqueue);

    private void Enqueue(string line)
    {
        if (_disposed) return;
        try { _queue.TryAdd(line); } catch { /* 队列关闭/满,丢弃即可 */ }
    }

    private void WriteLoop()
    {
        foreach (var line in _queue.GetConsumingEnumerable())
        {
            try
            {
                // 简单滚动:超过 5MB 时归档为 .1 再重开,防止无限增长。
                var fi = new FileInfo(_path);
                if (fi.Exists && fi.Length > 5 * 1024 * 1024)
                {
                    var bak = _path + ".1";
                    try { if (File.Exists(bak)) File.Delete(bak); File.Move(_path, bak); }
                    catch { /* 滚动失败不致命 */ }
                }
                File.AppendAllText(_path, line, Encoding.UTF8);
            }
            catch { /* 落盘失败绝不影响业务 */ }
        }
    }

    public void Dispose()
    {
        _disposed = true;
        _queue.CompleteAdding();
        try { _worker.Join(2000); } catch { }
        _queue.Dispose();
    }

    private sealed class FileLogger : ILogger
    {
        private readonly string _category;
        private readonly Action<string> _sink;

        public FileLogger(string category, Action<string> sink)
        {
            // 只保留短类名,日志更紧凑
            var idx = category.LastIndexOf('.');
            _category = idx >= 0 ? category[(idx + 1)..] : category;
            _sink = sink;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            var msg = formatter(state, exception);
            var lvl = logLevel switch
            {
                LogLevel.Trace => "trce",
                LogLevel.Debug => "dbug",
                LogLevel.Information => "info",
                LogLevel.Warning => "warn",
                LogLevel.Error => "fail",
                LogLevel.Critical => "crit",
                _ => "info"
            };
            var line = $"{DateTime.Now:HH:mm:ss.fff} {lvl} [{_category}] {msg}";
            if (exception is not null) line += Environment.NewLine + exception;
            _sink(line + Environment.NewLine);
        }
    }
}
