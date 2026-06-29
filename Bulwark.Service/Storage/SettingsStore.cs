using System.Text.Json;
using Bulwark.Core.Models;

namespace Bulwark.Service.Storage;

/// <summary>
/// 运行时设置持久化(JSON 文件)。存放于 %ProgramData%\Bulwark\settings.json。
/// 不存在时返回 null,由调用方用默认值(来自 appsettings.json)初始化。
/// </summary>
public sealed class SettingsStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _io = new(1, 1);
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public SettingsStore()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Bulwark");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "settings.json");
    }

    public async Task<RuntimeSettings?> LoadAsync(CancellationToken token = default)
    {
        await _io.WaitAsync(token);
        try
        {
            if (!File.Exists(_path)) return null;
            await using var fs = File.OpenRead(_path);
            return await JsonSerializer.DeserializeAsync<RuntimeSettings>(fs, Options, token);
        }
        catch
        {
            return null;
        }
        finally { _io.Release(); }
    }

    public async Task SaveAsync(RuntimeSettings settings, CancellationToken token = default)
    {
        await _io.WaitAsync(token);
        try
        {
            await using var fs = File.Create(_path);
            await JsonSerializer.SerializeAsync(fs, settings, Options, token);
        }
        finally { _io.Release(); }
    }
}
