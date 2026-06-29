using System.Text;
using System.Text.Json;

namespace Bulwark.Service.Storage;

/// <summary>
/// 安全事件审计日志(落盘)。无论 UI 是否在线,所有处置结果都会追加写入
/// %ProgramData%\Bulwark\audit\audit-yyyyMMdd.jsonl(每行一条 JSON)。
///
/// 目的:UI 不在线时仍保留可追溯的安全审计记录(原实现仅推送 UI,离线即丢失)。
/// 设计:单线程串行写入(SemaphoreSlim),按天滚动,带简单的大小上限保护。
/// </summary>
public sealed class AuditLog
{
    private readonly string _dir;
    private readonly SemaphoreSlim _io = new(1, 1);
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>单个日志文件大小上限(超过则滚动到带序号的新文件)。</summary>
    private const long MaxFileBytes = 16 * 1024 * 1024;

    public AuditLog()
    {
        _dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Bulwark", "audit");
        try { Directory.CreateDirectory(_dir); } catch { /* ignore */ }
    }

    /// <summary>追加一条审计记录。绝不抛出(审计失败不应影响主防御流程)。</summary>
    public async Task WriteAsync(object record, CancellationToken token = default)
    {
        string line;
        try { line = JsonSerializer.Serialize(record, Options); }
        catch { return; }

        await _io.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var path = CurrentFilePath();
            await File.AppendAllTextAsync(path, line + Environment.NewLine, Encoding.UTF8, token)
                .ConfigureAwait(false);
        }
        catch
        {
            // 审计写入失败(磁盘满/权限)绝不影响主流程。
        }
        finally { _io.Release(); }
    }

    private string CurrentFilePath()
    {
        var baseName = $"audit-{DateTime.Now:yyyyMMdd}";
        var path = Path.Combine(_dir, baseName + ".jsonl");
        try
        {
            int seq = 1;
            while (File.Exists(path) && new FileInfo(path).Length >= MaxFileBytes)
            {
                path = Path.Combine(_dir, $"{baseName}.{seq++}.jsonl");
            }
        }
        catch { /* ignore，回退到基础文件名 */ }
        return path;
    }
}
