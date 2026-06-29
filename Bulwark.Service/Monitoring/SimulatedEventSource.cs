using System.Runtime.CompilerServices;
using Bulwark.Core.Models;

namespace Bulwark.Service.Monitoring;

/// <summary>
/// 模拟事件源(M1 用于打通 R3 <-> UI 链路,无需驱动即可演示完整流程)。
/// 周期性产生一些有代表性的敏感行为事件。
/// </summary>
public sealed class SimulatedEventSource : IEventSource
{
    private static readonly SecurityEvent[] Samples =
    {
        new() { Type = EventType.ProcessCreate, ActorPid = 4321,
                ActorPath = @"C:\Users\Public\unknown.exe", ActorSigned = false,
                Target = @"C:\Windows\System32\cmd.exe", Detail = "尝试启动命令行" },
        new() { Type = EventType.RegistryWrite, ActorPid = 4321,
                ActorPath = @"C:\Users\Public\unknown.exe", ActorSigned = false,
                Target = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Backdoor",
                Detail = "写入开机启动项" },
        new() { Type = EventType.RemoteThread, ActorPid = 4321,
                ActorPath = @"C:\Users\Public\unknown.exe", ActorSigned = false,
                Target = @"C:\Windows\explorer.exe", Detail = "向 explorer 注入远程线程" },
        new() { Type = EventType.FileWrite, ActorPid = 8800,
                ActorPath = @"C:\Program Files\Editor\editor.exe", ActorSigned = true,
                Target = @"C:\Users\Me\Documents\note.txt", Detail = "保存文档" },
        new() { Type = EventType.NetworkConnect, ActorPid = 4321,
                ActorPath = @"C:\Users\Public\unknown.exe", ActorSigned = false,
                Target = "203.0.113.66:443", Detail = "外联可疑地址" },
    };

    public async IAsyncEnumerable<SecurityEvent> ReadEventsAsync(
        [EnumeratorCancellation] CancellationToken token)
    {
        int i = 0;
        while (!token.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(8), token);

            var sample = Samples[i++ % Samples.Length];
            // 克隆出新事件(新 Id / 时间戳),避免复用同一实例
            yield return new SecurityEvent
            {
                Type = sample.Type,
                ActorPid = sample.ActorPid,
                ActorPath = sample.ActorPath,
                ActorSigned = sample.ActorSigned,
                ActorHash = sample.ActorHash,
                CommandLine = sample.CommandLine,
                Target = sample.Target,
                Detail = sample.Detail
            };
        }
    }
}
