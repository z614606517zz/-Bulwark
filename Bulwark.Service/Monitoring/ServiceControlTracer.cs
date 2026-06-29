using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Bulwark.Service.Monitoring;

/// <summary>
/// 服务创建「真凶」追溯器。
///
/// 背景:在 Windows 上创建服务(sc create / CreateService / 直接 RCreateService RPC)时,
/// 调用方并不会自己去写注册表,而是通过 RPC 把请求交给 services.exe(服务控制管理器 SCM),
/// 由 SCM 在自己的进程上下文里写入 <c>HKLM\SYSTEM\CurrentControlSet\Services\&lt;名&gt;</c>。
/// 因此内核注册表回调(CmRegisterCallbackEx)是在 services.exe 线程上下文中触发的,
/// <c>PsGetCurrentProcessId()</c> 永远返回 services.exe 的 PID,而非真正发起者。
///
/// 这是 Windows 的架构性限制:微软只允许「用户态 RPC 服务端」查询 RPC 客户端身份,
/// 内核注册表回调无法拿到。参见 Elastic Security Labs "Misbehaving Modalities"。
///
/// 追溯思路(无需 ETW):内核注册表回调是**同步**的——SCM 的写注册表线程此刻正阻塞
/// 等待本软件用户态返回裁决。而发起者用 RPC 同步调用 SCM,其发起线程此刻也正阻塞在
/// 等待 SCM 的 LPC 回复上(KWAIT_REASON = WrLpcReply)。于是在这一瞬间对全系统线程
/// 做快照,找出「正阻塞在 LPC 回复、且不是 SCM/系统空闲/自身」的进程,即为候选发起者。
///
/// 置信度策略(本追溯用于主动防御处置路径,务必保守):
///  - 恰好 1 个候选:高置信,作为发起者返回;
///  - 0 或多个候选:返回所有候选供展示,但不"指认"单一发起者,
///    由调用方继续把 services.exe 作为主体(绝不据此结束 services.exe,会蓝屏)。
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ServiceControlTracer
{
    /// <summary>KWAIT_REASON.WrLpcReply —— 线程正等待 LPC 调用的回复(同步 RPC 客户端的典型状态)。</summary>
    private const uint WrLpcReply = 17;

    /// <summary>追溯结果。</summary>
    internal sealed class TraceResult
    {
        /// <summary>高置信发起者 PID(0 表示未唯一确定)。</summary>
        public int OriginatorPid { get; set; }

        /// <summary>高置信发起者映像路径(可空)。</summary>
        public string? OriginatorPath { get; set; }

        /// <summary>全部候选(PID, 路径),用于展示与排障。</summary>
        public List<(int Pid, string Path)> Candidates { get; } = new();

        /// <summary>是否唯一确定了发起者。</summary>
        public bool HighConfidence => OriginatorPid > 0;
    }

    /// <summary>
    /// 判断目标路径是否为服务数据库键(<c>...\CurrentControlSet\Services\...</c> 或
    /// <c>ControlSet001\Services</c> 等),仅这类写入才值得做 RPC 调用方追溯。
    /// </summary>
    internal static bool IsServiceDatabaseKey(string? targetPath)
    {
        if (string.IsNullOrEmpty(targetPath)) return false;
        return targetPath.Contains(@"\Services\", StringComparison.OrdinalIgnoreCase) ||
               targetPath.EndsWith(@"\Services", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>给定本次注册表操作被内核归因到的 PID(应为 services.exe),追溯真正的 RPC 发起者。</summary>
    internal static TraceResult Trace(int scmPid)
    {
        var result = new TraceResult();
        if (!OperatingSystem.IsWindows()) return result;

        int selfPid = Environment.ProcessId;

        foreach (var (pid, _) in EnumerateLpcReplyWaiters())
        {
            // 排除:系统空闲(0)/System(4)、SCM 自身、本服务自身。
            if (pid <= 4 || pid == scmPid || pid == selfPid) continue;

            // services.exe 之外的 svchost 等系统进程也可能恰好在等 LPC,
            // 但创建服务的"真凶"通常是用户/攻击者进程;这里不做白名单过滤,
            // 而是把候选都收集起来,由置信度策略决定是否指认。
            var path = ProcessInspector.TryGetProcessImagePath(pid) ?? $"PID {pid}";

            // 去重(同一进程多个线程都在等 LPC)
            if (result.Candidates.Exists(c => c.Pid == pid)) continue;
            result.Candidates.Add((pid, path));
        }

        if (result.Candidates.Count == 1)
        {
            result.OriginatorPid = result.Candidates[0].Pid;
            result.OriginatorPath = result.Candidates[0].Path;
        }

        return result;
    }

    /// <summary>
    /// 枚举当前所有「至少有一个线程处于 WrLpcReply 等待」的进程及其 PID。
    /// 通过 NtQuerySystemInformation(SystemProcessInformation) 一次快照获取。
    /// </summary>
    private static IEnumerable<(int Pid, int WaiterThreads)> EnumerateLpcReplyWaiters()
    {
        var list = new List<(int, int)>();

        int len = 0x100000; // 1MB 起步,不足时按返回长度扩容
        IntPtr buffer = IntPtr.Zero;
        try
        {
            for (int attempt = 0; attempt < 5; attempt++)
            {
                buffer = Marshal.AllocHGlobal(len);
                int status = NtQuerySystemInformation(
                    SystemProcessInformation, buffer, len, out int needed);

                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                    len = needed > 0 ? needed + 0x10000 : len * 2;
                    continue;
                }
                if (status != 0) return list; // 失败:返回空候选,调用方保守处理

                ParseSnapshot(buffer, list);
                return list;
            }
            return list;
        }
        catch
        {
            return list;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
    }

    private static void ParseSnapshot(IntPtr buffer, List<(int, int)> list)
    {
        // x64 SYSTEM_PROCESS_INFORMATION 关键偏移:
        //   0x00 NextEntryOffset, 0x04 NumberOfThreads, 0x50 UniqueProcessId
        //   线程数组起始 0x100,每个 SYSTEM_THREAD_INFORMATION 0x50 字节,WaitReason 在 +0x48。
        if (IntPtr.Size != 8) return; // 仅支持 64 位宿主(本服务即 64 位)

        const int ThreadArrayOffset = 0x100;
        const int ThreadEntrySize = 0x50;
        const int WaitReasonOffset = 0x48;

        long baseAddr = buffer.ToInt64();
        long offset = 0;

        while (true)
        {
            IntPtr entry = (IntPtr)(baseAddr + offset);
            int nextOffset = Marshal.ReadInt32(entry, 0x00);
            int threadCount = Marshal.ReadInt32(entry, 0x04);
            long pid = Marshal.ReadIntPtr(entry, 0x50).ToInt64();

            if (pid > 4 && threadCount > 0 && threadCount < 100000)
            {
                int waiters = 0;
                for (int i = 0; i < threadCount; i++)
                {
                    long threadEntry = baseAddr + offset + ThreadArrayOffset + (long)i * ThreadEntrySize;
                    uint waitReason = (uint)Marshal.ReadInt32((IntPtr)threadEntry, WaitReasonOffset);
                    if (waitReason == WrLpcReply) waiters++;
                }
                if (waiters > 0)
                    list.Add(((int)pid, waiters));
            }

            if (nextOffset == 0) break;
            offset += nextOffset;
        }
    }

    private const int SystemProcessInformation = 5;
    private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int systemInformationClass, IntPtr systemInformation,
        int systemInformationLength, out int returnLength);
}
