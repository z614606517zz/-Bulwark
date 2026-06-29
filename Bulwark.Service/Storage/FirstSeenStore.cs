using System.Collections.Concurrent;

namespace Bulwark.Service.Storage;

/// <summary>
/// 「首见」哈希记录。用于判定某个可执行文件是否在本机首次出现(按 SHA-256)。
/// 带签名 + 首见 + 新证书的组合,是识别"空壳公司骗取证书"类签名木马的关键信号。
///
/// 持久化于 %ProgramData%\Bulwark\seen_hashes.txt(每行一个哈希)。
/// 线程安全;内存集合 + 追加写盘,避免高频全量序列化。
/// </summary>
public sealed class FirstSeenStore
{
    private readonly string _path;
    private readonly ConcurrentDictionary<string, byte> _seen = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _writeLock = new();

    public FirstSeenStore()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Bulwark");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "seen_hashes.txt");
        Load();
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_path)) return;
            foreach (var line in File.ReadLines(_path))
            {
                var h = line.Trim();
                if (h.Length > 0) _seen.TryAdd(h, 0);
            }
        }
        catch { /* 首次运行 / 读取失败:视为空 */ }
    }

    /// <summary>
    /// 记录并返回该哈希是否为"首次出现"。首见返回 true(同时落盘),后续返回 false。
    /// hash 为空时返回 false(无法判定,保守不当作首见以免噪音)。
    /// </summary>
    public bool MarkAndCheckFirstSeen(string? hash)
    {
        if (string.IsNullOrEmpty(hash)) return false;

        // TryAdd 成功 => 之前不存在 => 首见。
        if (!_seen.TryAdd(hash, 0)) return false;

        try
        {
            lock (_writeLock)
            {
                File.AppendAllText(_path, hash + Environment.NewLine);
            }
        }
        catch { /* 落盘失败不影响判定结果 */ }
        return true;
    }
}
