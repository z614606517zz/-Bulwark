using System.Text.Json;
using Bulwark.Core.Engine;

namespace Bulwark.Service.Storage;

/// <summary>
/// 行为基线画像持久化(JSON 文件)。存放于 %ProgramData%\Bulwark\baseline.json。
///
/// 行为基线的价值在于「跨重启长期积累」—— 程序的正常行为画像越完整,偏离检测越准、误报越低。
/// 因此服务启动时载入快照恢复画像,运行中按防抖节流落盘,停止时再做一次最终保存。
/// 读取失败 / 文件损坏一律降级为空画像(重新学习),绝不影响实时防护。
/// 线程安全:单信号量串行化磁盘读写。
/// </summary>
public sealed class BaselineStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _io = new(1, 1);
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };

    public BaselineStore()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Bulwark");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "baseline.json");
    }

    /// <summary>载入快照;不存在 / 损坏时返回 null(由调用方视为空画像)。</summary>
    public async Task<BaselineSnapshot?> LoadAsync(CancellationToken token = default)
    {
        await _io.WaitAsync(token);
        try
        {
            if (!File.Exists(_path)) return null;
            await using var fs = File.OpenRead(_path);
            return await JsonSerializer.DeserializeAsync<BaselineSnapshot>(fs, Options, token);
        }
        catch
        {
            return null;
        }
        finally { _io.Release(); }
    }

    /// <summary>原子保存快照(先写临时文件再替换,避免中途崩溃留下半截文件)。</summary>
    public async Task SaveAsync(BaselineSnapshot snapshot, CancellationToken token = default)
    {
        await _io.WaitAsync(token);
        try
        {
            var tmp = _path + ".tmp";
            await using (var fs = File.Create(tmp))
            {
                await JsonSerializer.SerializeAsync(fs, snapshot, Options, token);
            }
            File.Copy(tmp, _path, overwrite: true);
            try { File.Delete(tmp); } catch { /* 临时文件清理失败可忽略 */ }
        }
        catch
        {
            /* 落盘失败不影响内存画像与实时防护 */
        }
        finally { _io.Release(); }
    }
}
