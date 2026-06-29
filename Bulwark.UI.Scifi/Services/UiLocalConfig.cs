using System;
using System.IO;
using System.Text.Json;

namespace Bulwark.UI.Services;

/// <summary>
/// UI 本地配置(不经服务端、不进 ProgramData)。用于存放只与 UI 展示相关、
/// 且包含会话敏感信息的设置 —— 当前是「官方用量」的开关与控制台 Cookie。
///
/// 这样设计的原因:
///  1) 官方用量纯展示,服务端不需要也不应持有它,避免为此重建/重启服务;
///  2) Cookie 是会话密钥,留在 UI 用户本地(%LocalAppData%\Bulwark\ui_local.json),
///     不随运行时设置经 IPC 推送到服务、不落 ProgramData,更安全。
///
/// 线程安全:简单单锁。读写失败一律降级为默认值,不影响功能。
/// </summary>
public static class UiLocalConfig
{
    private static readonly object _gate = new();
    private static readonly string _path;

    static UiLocalConfig()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bulwark");
        try { Directory.CreateDirectory(dir); } catch { /* 忽略 */ }
        _path = Path.Combine(dir, "ui_local.json");
    }

    public sealed class Data
    {
        public bool MimoUsageEnabled { get; set; }
        public string MimoUsageCookie { get; set; } = string.Empty;
    }

    public static Data Load()
    {
        lock (_gate)
        {
            try
            {
                if (!File.Exists(_path)) return new Data();
                var json = File.ReadAllText(_path);
                return JsonSerializer.Deserialize<Data>(json) ?? new Data();
            }
            catch { return new Data(); }
        }
    }

    public static void Save(Data data)
    {
        lock (_gate)
        {
            try
            {
                var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_path, json);
            }
            catch { /* 落盘失败不影响功能 */ }
        }
    }
}
