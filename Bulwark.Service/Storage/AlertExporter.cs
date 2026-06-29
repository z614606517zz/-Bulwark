using System.Text;
using System.Text.Json;
using Bulwark.Core.Engine;
using Bulwark.Core.Models;

namespace Bulwark.Service.Storage;

/// <summary>
/// 结构化告警导出器:把事件 + 裁决格式化为 ECS(Elastic Common Schema)JSON-lines,
/// 追加写入 %ProgramData%\Bulwark\alerts\alerts-yyyyMMdd.jsonl,供 SIEM(Elastic/Splunk/
/// OpenSearch 等)采集。受配置开关控制,默认关闭。
///
/// 与 <see cref="AuditLog"/> 互补:AuditLog 是磐垒自有的精简审计;本导出器产出的是
/// 行业标准 ECS 文档(含证据链与 ATT&CK 技战术),便于无缝接入既有日志管道。
/// 单线程串行写入,按天滚动,绝不抛出(导出失败不影响主防御)。
/// </summary>
public sealed class AlertExporter
{
    private readonly bool _enabled;
    private readonly string _dir;
    private readonly SemaphoreSlim _io = new(1, 1);
    private static readonly JsonSerializerOptions Options = new()
    {
        // ECS 字段名已是规范形式,原样输出(不改大小写)。
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private const long MaxFileBytes = 32 * 1024 * 1024;

    public AlertExporter(bool enabled)
    {
        _enabled = enabled;
        _dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Bulwark", "alerts");
        if (_enabled)
        {
            try { Directory.CreateDirectory(_dir); } catch { /* ignore */ }
        }
    }

    /// <summary>导出一条 ECS 告警。未启用时直接返回。绝不抛出。</summary>
    public async Task ExportAsync(SecurityEvent e, Verdict v, CancellationToken token = default)
    {
        if (!_enabled) return;

        string line;
        try
        {
            var doc = EcsAlertFormatter.Format(e, v);
            line = JsonSerializer.Serialize(doc, Options);
        }
        catch { return; }

        await _io.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await File.AppendAllTextAsync(CurrentFilePath(), line + "\n", Encoding.UTF8, token)
                .ConfigureAwait(false);
        }
        catch { /* 导出失败不影响主防御 */ }
        finally { _io.Release(); }
    }

    private string CurrentFilePath()
    {
        var baseName = $"alerts-{DateTime.Now:yyyyMMdd}";
        var path = Path.Combine(_dir, baseName + ".jsonl");
        try
        {
            int seq = 1;
            while (File.Exists(path) && new FileInfo(path).Length >= MaxFileBytes)
                path = Path.Combine(_dir, $"{baseName}.{seq++}.jsonl");
        }
        catch { /* ignore */ }
        return path;
    }
}
