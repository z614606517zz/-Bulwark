using Bulwark.Core.Models;

namespace Bulwark.Service.Monitoring;

/// <summary>
/// 安全事件来源抽象。
/// M1 阶段用模拟实现;后续接入内核驱动(通过 Minifilter 通信端口 / DeviceIoControl)时,
/// 只需提供一个从驱动读取事件的实现,服务其余逻辑不变。
/// </summary>
public interface IEventSource
{
    /// <summary>持续产出安全事件,直到取消。</summary>
    IAsyncEnumerable<SecurityEvent> ReadEventsAsync(CancellationToken token);
}
