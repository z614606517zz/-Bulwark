using Bulwark.Core.Models;

namespace Bulwark.UI.Scifi.Services;

/// <summary>
/// 事件类型 -> 面向用户的展示文案的「单一事实来源」。
///
/// 此前 BlockNotifyWindow / InterceptLogViewModel / BehaviorReportWindow 各自维护了一份
/// EventType -> 中文/图标的 switch,彼此措辞不一且新增事件类型要改多处。这里集中为一处:
///   · <see cref="Noun"/>   —— 短名词(时间线/徽标):如「文件写入」;
///   · <see cref="Action"/> —— 行为短语(拦截通知/日志):如「尝试写入/修改文件」;
///   · <see cref="Badge"/>  —— 类别徽标:如「文件」;
///   · <see cref="Icon"/>   —— 列表图标(emoji)。
/// 新增 <see cref="EventType"/> 只需在此补一处。
/// </summary>
public static class EventTypeDisplay
{
    /// <summary>短名词(用于时间线、标题):进程创建 / 文件写入 …</summary>
    public static string Noun(EventType type) => type switch
    {
        EventType.ProcessCreate => "进程创建",
        EventType.ProcessTerminate => "结束进程",
        EventType.RemoteThread => "远程注入",
        EventType.ImageLoad => "模块加载",
        EventType.FileWrite => "文件写入",
        EventType.FileDelete => "文件删除",
        EventType.RegistryWrite => "注册表",
        EventType.NetworkConnect => "网络外联",
        EventType.SelfProtect => "自我保护",
        _ => type.ToString()
    };

    /// <summary>行为短语(用于拦截通知 / 日志):尝试启动新进程 / 尝试写入/修改文件 …</summary>
    public static string Action(EventType type) => type switch
    {
        EventType.ProcessCreate => "尝试启动新进程",
        EventType.ProcessTerminate => "尝试结束进程",
        EventType.RemoteThread => "尝试注入远程线程",
        EventType.ImageLoad => "尝试加载模块/驱动",
        EventType.FileWrite => "尝试写入/修改文件",
        EventType.FileDelete => "尝试删除文件",
        EventType.RegistryWrite => "尝试修改注册表",
        EventType.NetworkConnect => "尝试外联网络",
        EventType.SelfProtect => "尝试操作磐垒自身",
        _ => type.ToString()
    };

    /// <summary>类别徽标:进程 / 注入 / 模块 / 文件 / 注册表 / 网络 / 自保护。</summary>
    public static string Badge(EventType type) => type switch
    {
        EventType.ProcessCreate or EventType.ProcessTerminate => "进程",
        EventType.RemoteThread => "注入",
        EventType.ImageLoad => "模块",
        EventType.FileWrite or EventType.FileDelete => "文件",
        EventType.RegistryWrite => "注册表",
        EventType.NetworkConnect => "网络",
        EventType.SelfProtect => "自保护",
        _ => "其他"
    };

    /// <summary>列表图标(emoji)。</summary>
    public static string Icon(EventType type) => type switch
    {
        EventType.ProcessCreate or EventType.ProcessTerminate => "⚙",
        EventType.RemoteThread => "💉",
        EventType.ImageLoad => "📦",
        EventType.FileWrite => "📝",
        EventType.FileDelete => "🗑",
        EventType.RegistryWrite => "🧩",
        EventType.NetworkConnect => "🌐",
        EventType.SelfProtect => "🛡",
        _ => "🚫"
    };

    /// <summary>主体显示名(仅文件名;无路径时回退为 PID)。</summary>
    public static string ActorName(SecurityEvent e)
        => string.IsNullOrEmpty(e.ActorPath)
            ? $"PID {e.ActorPid}"
            : System.IO.Path.GetFileName(e.ActorPath);

    /// <summary>主体显示名 + PID(无路径时回退为 PID)。</summary>
    public static string ActorNameWithPid(SecurityEvent e)
        => string.IsNullOrEmpty(e.ActorPath)
            ? $"PID {e.ActorPid}"
            : $"{System.IO.Path.GetFileName(e.ActorPath)} (PID {e.ActorPid})";
}
