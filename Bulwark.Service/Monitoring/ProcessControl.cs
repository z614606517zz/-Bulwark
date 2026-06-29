using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Bulwark.Service.Monitoring;

/// <summary>
/// 进程挂起/恢复工具。用于 AI 研判期间冻结目标进程,出结论前不让其真正运行
/// (判定安全则恢复,判定恶意则由处置逻辑结束)。基于 ntdll 的进程级挂起,
/// 一次性冻结/解冻进程内全部线程,即使后续创建新线程也保持挂起状态。
/// </summary>
[SupportedOSPlatform("windows")]
public static class ProcessControl
{
    private const uint PROCESS_SUSPEND_RESUME = 0x0800;

    [DllImport("ntdll.dll")]
    private static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    private static extern int NtResumeProcess(IntPtr processHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    /// <summary>挂起指定进程的所有线程。成功返回 true。</summary>
    public static bool TrySuspend(int pid)
    {
        if (pid <= 0) return false;
        IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return NtSuspendProcess(h) == 0; }
        catch { return false; }
        finally { CloseHandle(h); }
    }

    /// <summary>恢复(解冻)此前被挂起的进程。成功返回 true。</summary>
    public static bool TryResume(int pid)
    {
        if (pid <= 0) return false;
        IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return NtResumeProcess(h) == 0; }
        catch { return false; }
        finally { CloseHandle(h); }
    }
}
