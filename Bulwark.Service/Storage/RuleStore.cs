using System.Text.Json;
using Bulwark.Core.Models;

namespace Bulwark.Service.Storage;

/// <summary>
/// 规则持久化(JSON 文件)。存放于 %ProgramData%\Bulwark\rules.json。
/// 后续可替换为 SQLite,接口不变。
/// </summary>
public sealed class RuleStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _io = new(1, 1);
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public RuleStore()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Bulwark");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "rules.json");
    }

    public async Task<List<DefenseRule>> LoadAsync(CancellationToken token = default)
    {
        await _io.WaitAsync(token);
        try
        {
            if (!File.Exists(_path)) return new List<DefenseRule>();
            await using var fs = File.OpenRead(_path);
            var loaded = await JsonSerializer.DeserializeAsync<List<DefenseRule>>(fs, Options, token)
                         ?? new List<DefenseRule>();
            // 加载时丢弃已到期规则(避免过期规则长期堆积)。会话规则本就不落盘,无需处理。
            var now = DateTime.UtcNow;
            return loaded.Where(r => !r.IsExpired(now)).ToList();
        }
        catch
        {
            return new List<DefenseRule>();
        }
        finally { _io.Release(); }
    }

    public async Task SaveAsync(IEnumerable<DefenseRule> rules, CancellationToken token = default)
    {
        await _io.WaitAsync(token);
        try
        {
            // 仅持久化「非会话且未到期」的规则:会话规则随重启失效,到期规则不再保留。
            var now = DateTime.UtcNow;
            var persistable = rules.Where(r => !r.SessionOnly && !r.IsExpired(now)).ToList();
            await using var fs = File.Create(_path);
            await JsonSerializer.SerializeAsync(fs, persistable, Options, token);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            // 环境性写入失败(权限不足 / 文件被占用)绝不应让整个防御服务崩溃退出。
            // 规则本次不落盘(内存中的规则仍生效),仅吞掉异常保活。
            // 典型场景:非管理员运行,而 %ProgramData%\Bulwark\rules.json 由此前的
            // 管理员/LocalSystem 会话创建,普通权限无法覆盖 —— 应以管理员运行服务。
        }
        finally { _io.Release(); }
    }
}
