using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Bulwark.Service.Storage;

/// <summary>
/// 隔离区中一个条目的元数据(可序列化,供 UI 展示与还原使用)。
/// </summary>
public sealed class QuarantineEntry
{
    /// <summary>条目唯一 Id(同时作为隔离仓库内的文件名)。</summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>被隔离文件的原始完整路径(用于还原)。</summary>
    public string OriginalPath { get; set; } = string.Empty;

    /// <summary>原始文件名(便于 UI 直观显示)。</summary>
    public string FileName { get; set; } = string.Empty;

    /// <summary>隔离时间(UTC)。</summary>
    public DateTime QuarantinedUtc { get; set; } = DateTime.UtcNow;

    /// <summary>文件大小(字节)。</summary>
    public long Size { get; set; }

    /// <summary>原文件 SHA-256(隔离前计算,用于核对与情报联动)。</summary>
    public string? Sha256 { get; set; }

    /// <summary>隔离原因(裁决来源 / 命中规则 / 风险原因等,人类可读)。</summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>触发隔离的进程 PID(若有)。</summary>
    public int ActorPid { get; set; }
}

/// <summary>
/// 恶意文件隔离区。负责把磁盘上的恶意文件「安全失活并移入受保护仓库」,
/// 保留完整还原信息,支持列出 / 还原 / 永久删除。
///
/// 设计要点:
///  · 仓库目录 %ProgramData%\Bulwark\quarantine\,文件以条目 Id 命名,无原扩展名,
///    避免被双击直接执行;
///  · 隔离时对文件内容做逐字节 XOR(0x5A)「中和」,使其无法再作为可执行体被加载/运行,
///    同时完全可逆(还原时再 XOR 回去),不损失取证完整性;
///  · 元数据单独存为 index.json,即使服务重启也能列出/还原历史隔离项;
///  · 所有操作尽量「不抛断」—— 隔离失败不应让主防御流程崩溃,但会返回失败结果供上层记录。
/// </summary>
public sealed class QuarantineManager
{
    private const byte XorKey = 0x5A;

    private readonly string _dir;
    private readonly string _indexPath;
    private readonly SemaphoreSlim _io = new(1, 1);
    private readonly List<QuarantineEntry> _entries = new();
    private bool _loaded;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public QuarantineManager()
    {
        _dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Bulwark", "quarantine");
        _indexPath = Path.Combine(_dir, "index.json");
        try { Directory.CreateDirectory(_dir); } catch { /* ignore */ }
    }

    /// <summary>
    /// 把指定文件移入隔离区。成功返回隔离条目,失败返回 null(原因记入 <paramref name="error"/>)。
    /// </summary>
    public async Task<QuarantineEntry?> QuarantineAsync(
        string filePath, string reason, int actorPid, string? sha256,
        CancellationToken token = default)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return null;
        }

        await _io.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await EnsureLoadedNoLockAsync(token).ConfigureAwait(false);

            if (!File.Exists(filePath))
                return null;

            // 已隔离过同一原路径且文件仍在仓库 -> 不重复隔离。
            var dup = _entries.FirstOrDefault(x =>
                string.Equals(x.OriginalPath, filePath, StringComparison.OrdinalIgnoreCase)
                && File.Exists(Path.Combine(_dir, x.Id.ToString("N"))));
            if (dup is not null)
                return dup;

            var fi = new FileInfo(filePath);
            var entry = new QuarantineEntry
            {
                OriginalPath = filePath,
                FileName = fi.Name,
                Size = fi.Length,
                Sha256 = sha256,
                Reason = reason,
                ActorPid = actorPid
            };

            var dest = Path.Combine(_dir, entry.Id.ToString("N"));

            // 读原文件 -> XOR 中和 -> 写入仓库 -> 删除原文件。
            // 用流式处理避免大文件一次性载入内存。
            await NeutralizeCopyAsync(filePath, dest, token).ConfigureAwait(false);

            // 仓库副本写成功后,删除原始恶意文件(失活在磁盘上的载荷)。
            try { File.Delete(filePath); }
            catch
            {
                // 原文件删除失败(被占用/权限):回滚仓库副本,视为隔离失败。
                try { File.Delete(dest); } catch { /* ignore */ }
                return null;
            }

            _entries.Add(entry);
            await SaveIndexNoLockAsync(token).ConfigureAwait(false);
            return entry;
        }
        catch
        {
            return null;
        }
        finally { _io.Release(); }
    }

    /// <summary>列出当前隔离区所有条目(按隔离时间倒序)。</summary>
    public async Task<IReadOnlyList<QuarantineEntry>> ListAsync(CancellationToken token = default)
    {
        await _io.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await EnsureLoadedNoLockAsync(token).ConfigureAwait(false);
            return _entries.OrderByDescending(x => x.QuarantinedUtc).ToArray();
        }
        finally { _io.Release(); }
    }

    /// <summary>
    /// 还原一个隔离条目到其原始路径(XOR 逆向恢复原始内容)。
    /// 成功返回 true。若原路径已存在文件则还原到「原名.restored」避免覆盖。
    /// </summary>
    public async Task<bool> RestoreAsync(Guid id, CancellationToken token = default)
    {
        await _io.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await EnsureLoadedNoLockAsync(token).ConfigureAwait(false);
            var entry = _entries.FirstOrDefault(x => x.Id == id);
            if (entry is null) return false;

            var src = Path.Combine(_dir, entry.Id.ToString("N"));
            if (!File.Exists(src)) return false;

            var target = entry.OriginalPath;
            try
            {
                var parent = Path.GetDirectoryName(target);
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                if (File.Exists(target))
                    target = target + ".restored";
            }
            catch { /* 目录创建失败则尝试直接写 */ }

            await NeutralizeCopyAsync(src, target, token).ConfigureAwait(false); // XOR 可逆,再异或即还原

            try { File.Delete(src); } catch { /* ignore */ }
            _entries.Remove(entry);
            await SaveIndexNoLockAsync(token).ConfigureAwait(false);
            return true;
        }
        catch
        {
            return false;
        }
        finally { _io.Release(); }
    }

    /// <summary>永久删除一个隔离条目(仓库副本 + 元数据)。成功返回 true。</summary>
    public async Task<bool> DeleteAsync(Guid id, CancellationToken token = default)
    {
        await _io.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await EnsureLoadedNoLockAsync(token).ConfigureAwait(false);
            var entry = _entries.FirstOrDefault(x => x.Id == id);
            if (entry is null) return false;

            var src = Path.Combine(_dir, entry.Id.ToString("N"));
            try { if (File.Exists(src)) File.Delete(src); } catch { /* ignore */ }
            _entries.Remove(entry);
            await SaveIndexNoLockAsync(token).ConfigureAwait(false);
            return true;
        }
        catch { return false; }
        finally { _io.Release(); }
    }

    // ── 内部实现 ───────────────────────────────────────────────

    /// <summary>流式读取 <paramref name="src"/>,逐字节 XOR 后写入 <paramref name="dest"/>。</summary>
    private static async Task NeutralizeCopyAsync(string src, string dest, CancellationToken token)
    {
        const int BufSize = 1 << 16; // 64KB
        var buffer = new byte[BufSize];
        await using var inStream = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read);
        await using var outStream = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None);
        int read;
        while ((read = await inStream.ReadAsync(buffer.AsMemory(0, BufSize), token).ConfigureAwait(false)) > 0)
        {
            for (int i = 0; i < read; i++) buffer[i] ^= XorKey;
            await outStream.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
        }
    }

    private async Task EnsureLoadedNoLockAsync(CancellationToken token)
    {
        if (_loaded) return;
        try
        {
            if (File.Exists(_indexPath))
            {
                var bytes = await File.ReadAllBytesAsync(_indexPath, token).ConfigureAwait(false);
                var list = JsonSerializer.Deserialize<List<QuarantineEntry>>(bytes, Json);
                if (list is not null) { _entries.Clear(); _entries.AddRange(list); }
            }
        }
        catch { /* 索引损坏时以空列表起步,不阻断 */ }
        finally { _loaded = true; }
    }

    private async Task SaveIndexNoLockAsync(CancellationToken token)
    {
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(_entries, Json);
            // 原子写:先写临时文件再替换,避免半写损坏索引。
            var tmp = _indexPath + ".tmp";
            await File.WriteAllBytesAsync(tmp, bytes, token).ConfigureAwait(false);
            File.Copy(tmp, _indexPath, overwrite: true);
            try { File.Delete(tmp); } catch { /* ignore */ }
        }
        catch { /* 索引写失败不致命 */ }
    }

    /// <summary>计算文件 SHA-256(隔离前留存),失败返回 null。</summary>
    public static string? TryComputeSha256(string path)
    {
        try
        {
            using var sha = SHA256.Create();
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var hash = sha.ComputeHash(fs);
            var sb = new StringBuilder(hash.Length * 2);
            foreach (var b in hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
        catch { return null; }
    }
}
