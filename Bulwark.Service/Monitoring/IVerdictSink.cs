using Bulwark.Core.Models;

namespace Bulwark.Service.Monitoring;

/// <summary>
/// 可回写裁决的事件源实现此接口。对于内核驱动事件源,裁决需要通过
/// FilterReplyMessage 回传内核以放行/阻止;对于纯观测源(WMI/模拟)无需实现。
/// </summary>
public interface IVerdictSink
{
    /// <summary>把某事件的最终裁决回写给来源(如内核驱动)。</summary>
    void SubmitVerdict(SecurityEvent e, VerdictAction action);
}

/// <summary>
/// 支持「禁止加载」处置的事件源(内核驱动)实现此接口。
/// 把已确认恶意的模块文件路径下发内核,使其无法再被任何进程加载/映射执行(专治白加黑)。
/// 纯观测源(WMI/模拟)无内核能力,不实现此接口。
/// </summary>
public interface IModuleBlockSink
{
    /// <summary>把一个模块文件路径加入内核「禁止加载」名单。成功下发返回 true。</summary>
    bool BlockModuleLoad(string modulePath);
}
