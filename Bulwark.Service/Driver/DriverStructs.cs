using System.Runtime.InteropServices;

namespace Bulwark.Service.Driver;

// 对应内核 Protocol.h 的常量
internal static class DriverConst
{
    public const int BlwMaxPath = 520;
    public const uint BlwEventProcessCreate = 0;
    public const uint BlwEventProcessTerminate = 1;
    public const uint BlwEventFileDelete = 2;
    public const uint BlwEventFileRename = 3;
    public const uint BlwEventRegistrySetValue = 4;
    public const uint BlwEventRegistryDeleteValue = 5;
    public const uint BlwEventRegistryDeleteKey = 6;
    public const uint BlwEventSelfProtect = 7;
    public const uint BlwEventNetworkConnect = 8;
    public const uint BlwEventImageLoad = 9;
    public const uint BlwEventRemoteThread = 10;
    public const uint BlwEventMemoryProtect = 11;
    public const uint BlwEventImageBlocked = 12;
    public const uint BlwEventFileModify = 13;
    public const uint BlwVerdictAllow = 0;
    public const uint BlwVerdictBlock = 1;

    // 配置命令
    public const uint BlwCmdClearPaths = 1;
    public const uint BlwCmdAddPath = 2;
    public const uint BlwCmdClearRegKeys = 3;
    public const uint BlwCmdAddRegKey = 4;
    public const uint BlwCmdClearPids = 5;
    public const uint BlwCmdAddPid = 6;
    public const uint BlwCmdClearBlockIp = 7;
    public const uint BlwCmdAddBlockIp = 8;
    public const uint BlwCmdHandshake = 9;
    public const uint BlwCmdClearRegHard = 10;
    public const uint BlwCmdAddRegHard = 11;
    public const uint BlwCmdClearFileHard = 12;
    public const uint BlwCmdAddFileHard = 13;
    public const uint BlwCmdClearMemProt = 14;
    public const uint BlwCmdAddMemProt = 15;
    public const uint BlwCmdClearNoLoad = 16;
    public const uint BlwCmdAddNoLoad = 17;
    public const uint BlwCmdSetFileTelemetry = 18;

    /// <summary>协议版本号,必须与内核 Protocol.h 的 BLW_PROTOCOL_VERSION 一致。</summary>
    public const uint BlwProtocolVersion = 4;
}

/// <summary>对应内核 BLW_HANDSHAKE_REPLY(协议握手应答)。</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct BlwHandshakeReply
{
    public uint ProtocolVersion;
    public uint EventMessageSize;
    public uint ConfigMessageSize;
    public uint VerdictReplySize;
}

/// <summary>FILTER_MESSAGE_HEADER(由 Filter Manager 加在消息前)。</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct FilterMessageHeader
{
    public uint ReplyLength;
    public ulong MessageId;
}

/// <summary>FILTER_REPLY_HEADER。</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct FilterReplyHeader
{
    public int Status;       // NTSTATUS
    public ulong MessageId;  // 必须与收到的 MessageId 一致
}

/// <summary>
/// 对应内核 BLW_EVENT_MESSAGE。内存布局必须与 Protocol.h 完全一致。
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct BlwEventMessage
{
    public ulong EventId;
    public uint Type;
    public uint ActorPid;
    public uint ParentPid;
    public ushort ImagePathLength;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverConst.BlwMaxPath)]
    public string ImagePath;
    public ushort TargetPathLength;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverConst.BlwMaxPath)]
    public string TargetPath;
    public uint RemoteIpV4;
    public ushort RemotePort;
}

/// <summary>对应内核 BLW_CONFIG_MESSAGE(下发受保护路径)。</summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct BlwConfigMessage
{
    public uint Command;
    public uint Pid;
    public uint BlockIpV4;
    public ushort BlockPort;
    public ushort PathLength;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DriverConst.BlwMaxPath)]
    public string Path;
}

/// <summary>对应内核 BLW_VERDICT_REPLY。</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct BlwVerdictReply
{
    public ulong EventId;
    public uint Verdict;
}

/// <summary>FilterGetMessage 实际收到的:头 + 事件体。</summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct BlwGetMessage
{
    public FilterMessageHeader Header;
    public BlwEventMessage Event;
}

/// <summary>FilterReplyMessage 发送的:头 + 裁决体。</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct BlwReplyMessage
{
    public FilterReplyHeader Header;
    public BlwVerdictReply Reply;
}
