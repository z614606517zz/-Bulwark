using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Bulwark.Service.Driver;

/// <summary>
/// fltlib.dll P/Invoke 封装:连接 Minifilter 通信端口、收发消息。
/// 对应内核侧 FltCreateCommunicationPort / FltSendMessage。
/// </summary>
[SupportedOSPlatform("windows")]
internal static class FilterApi
{
    public const string PortName = @"\BulwarkPort";

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int FilterConnectCommunicationPort(
        string lpPortName,
        uint dwOptions,
        IntPtr lpContext,
        ushort wSizeOfContext,
        IntPtr lpSecurityAttributes,
        out SafeFilterPortHandle hPort);

    [DllImport("fltlib.dll", SetLastError = true)]
    public static extern int FilterGetMessage(
        SafeFilterPortHandle hPort,
        IntPtr lpMessageBuffer,
        int dwMessageBufferSize,
        IntPtr lpOverlapped);

    [DllImport("fltlib.dll", SetLastError = true)]
    public static extern int FilterReplyMessage(
        SafeFilterPortHandle hPort,
        IntPtr lpReplyBuffer,
        int dwReplyBufferSize);

    [DllImport("fltlib.dll", SetLastError = true)]
    public static extern int FilterSendMessage(
        SafeFilterPortHandle hPort,
        IntPtr lpInBuffer,
        int dwInBufferSize,
        IntPtr lpOutBuffer,
        int dwOutBufferSize,
        out int lpBytesReturned);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}

/// <summary>通信端口安全句柄。</summary>
[SupportedOSPlatform("windows")]
internal sealed class SafeFilterPortHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeFilterPortHandle() : base(true) { }

    protected override bool ReleaseHandle() => FilterApi.CloseHandle(handle);
}
