using System.Text.Json;
using Bulwark.Core.Models;

namespace Bulwark.Service.Storage;

/// <summary>
/// VirusTotal 扫描历史的持久化存储(JSON 文件,%ProgramData%\Bulwark\vt_scan_history.json)。
///
/// 两个职责:
///  1) 去重记忆:<see cref="TryGetFinishedByHash"/> 按 SHA-256 返回最近一次「已完成且有确定结论」
///     的记录,使「已经扫过的不重复扫」。
///  2) 持久展示:<see cref="GetAll"/> 给「VT 查询记录」视图提供完整历史(按时间倒序)。
///
/// 线程安全;按 <see cref="VtScanRecord.Id"/> upsert(同一次扫描随阶段更新同一条);容量上限裁剪。
/// </summary>
public sealed class VtScanHistoryStore
{
    private const int MaxRecords = 1000;

    private readonly string _path;
    private readonly object _lock = new();
    private readonly List<VtScanRecord> _records = new();
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };

    public VtScanHistoryStore()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bulwark");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "vt_scan_history.json");
        Load();
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_path)) return;
            var json = File.ReadAllText(_path);
            var list = JsonSerializer.Deserialize<List<VtScanRecord>>(json, Options);
            if (list is not null)
            {
                lock (_lock)
                {
                    _records.Clear();
                    _records.AddRange(list);
                }
            }
        }
        catch { /* 历史损坏不致命,忽略 */ }
    }

    /// <summary>
    /// 按 SHA-256 取最近一次「已完成」记录用于去重。
    ///  · 确定性结论(干净/可疑/恶意)恒算「已扫过」(永久去重);
    ///  · 「未收录/无明确结论(Unknown)」仅当在 <paramref name="unknownTtl"/> 时间窗内才算「已扫过」
    ///    (过期后允许重扫,以便 VT 之后可能已收录);<paramref name="unknownTtl"/> 为 null 时不去重 Unknown。
    ///  · 查询失败(Error)/ 未完成(Pending)永不算「已扫过」,以便重扫。
    /// </summary>
    public VtScanRecord? TryGetFinishedByHash(string? sha256, TimeSpan? unknownTtl = null)
    {
        if (string.IsNullOrEmpty(sha256)) return null;
        lock (_lock)
        {
            VtScanRecord? best = null;
            foreach (var r in _records)
            {
                if (!string.Equals(r.Sha256, sha256, StringComparison.OrdinalIgnoreCase)) continue;
                if (r.Stage != VtScanStage.Completed) continue;

                bool conclusive = r.Outcome is VtScanOutcome.Clean or VtScanOutcome.Suspicious or VtScanOutcome.Malicious;
                bool unknown = r.Outcome == VtScanOutcome.Unknown;
                if (!conclusive && !unknown) continue;

                // 未收录/无结论:仅在 TTL 内算「已扫过」。
                if (unknown)
                {
                    if (unknownTtl is null) continue;
                    if (DateTime.UtcNow - r.TimestampUtc > unknownTtl.Value) continue;
                }

                if (best is null || r.TimestampUtc > best.TimestampUtc) best = r;
            }
            return best?.Clone();
        }
    }

    /// <summary>新增或按 Id 更新一条记录,并异步持久化。</summary>
    public void Upsert(VtScanRecord record)
    {
        lock (_lock)
        {
            int idx = _records.FindIndex(r => r.Id == record.Id);
            if (idx >= 0) _records[idx] = record.Clone();
            else _records.Add(record.Clone());

            // 容量裁剪:超出则按时间删除最旧的。
            if (_records.Count > MaxRecords)
            {
                _records.Sort((a, b) => a.TimestampUtc.CompareTo(b.TimestampUtc));
                _records.RemoveRange(0, _records.Count - MaxRecords);
            }
        }
        _ = SaveAsync();
    }

    /// <summary>取全部历史记录(按时间倒序,最近在前)。</summary>
    public List<VtScanRecord> GetAll()
    {
        lock (_lock)
        {
            return _records
                .OrderByDescending(r => r.TimestampUtc)
                .Select(r => r.Clone())
                .ToList();
        }
    }

    private async Task SaveAsync()
    {
        List<VtScanRecord> snapshot;
        lock (_lock) { snapshot = _records.Select(r => r.Clone()).ToList(); }
        try
        {
            var json = JsonSerializer.Serialize(snapshot, Options);
            await File.WriteAllTextAsync(_path, json);
        }
        catch { /* 持久化失败不影响功能 */ }
    }
}
