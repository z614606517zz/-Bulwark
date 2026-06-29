using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace Bulwark.Service.Storage;

/// <summary>
/// 注册表「强力删除」工具:用于清理被 ACL 保护(TrustedInstaller 所有 / Defender 篡改保护)的
/// 恶意持久化项 —— 这类键即便以管理员/LocalSystem 身份也会在写入时抛 SecurityException。
///
/// 流程:启用 SeTakeOwnership/SeRestore 特权 → 夺取键的所有权给 Administrators →
/// 授予 Administrators 完全控制 → 删除指定值(或整个子键)。
/// 仅对「已确认指向恶意文件」的项调用,属定向清障,不做泛化提权操作。
/// </summary>
[SupportedOSPlatform("windows")]
internal static class RegSurgery
{
    /// <summary>
    /// 夺取所有权后删除某键下的一个值。成功返回 true。常规删除已失败时才调用本方法。
    /// </summary>
    public static bool ForceDeleteValue(RegistryHive hive, string subKey, string valueName, RegistryView view)
    {
        EnablePrivilege("SeTakeOwnershipPrivilege");
        EnablePrivilege("SeRestorePrivilege");

        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        // 1) 夺取所有权
        try
        {
            using var k = RegistryKey.OpenBaseKey(hive, view)
                .OpenSubKey(subKey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership);
            if (k is null) return false;
            var sec = k.GetAccessControl(AccessControlSections.Owner);
            sec.SetOwner(admins);
            k.SetAccessControl(sec);
        }
        catch { /* 夺取失败仍尝试后续(可能本就有权) */ }

        // 2) 授予 Administrators 完全控制
        try
        {
            using var k = RegistryKey.OpenBaseKey(hive, view)
                .OpenSubKey(subKey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions);
            if (k is not null)
            {
                var sec = k.GetAccessControl(AccessControlSections.Access);
                sec.AddAccessRule(new RegistryAccessRule(
                    admins, RegistryRights.FullControl, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
                k.SetAccessControl(sec);
            }
        }
        catch { /* 授权失败仍尝试删除 */ }

        // 3) 删除值
        try
        {
            using var k = RegistryKey.OpenBaseKey(hive, view).OpenSubKey(subKey, writable: true);
            if (k is null) return false;
            k.DeleteValue(valueName, throwOnMissingValue: false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 夺取所有权后删除整个子键树(用于恶意服务键)。成功返回 true。
    /// <paramref name="parentSubKey"/> 为父键路径,<paramref name="childName"/> 为要删除的子键名。
    /// </summary>
    public static bool ForceDeleteSubKeyTree(RegistryHive hive, string parentSubKey, string childName, RegistryView view)
    {
        EnablePrivilege("SeTakeOwnershipPrivilege");
        EnablePrivilege("SeRestorePrivilege");

        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        string childPath = parentSubKey + "\\" + childName;

        try
        {
            using var ck = RegistryKey.OpenBaseKey(hive, view)
                .OpenSubKey(childPath, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership);
            if (ck is not null)
            {
                var sec = ck.GetAccessControl(AccessControlSections.Owner);
                sec.SetOwner(admins);
                ck.SetAccessControl(sec);
            }
        }
        catch { }

        try
        {
            using var ck = RegistryKey.OpenBaseKey(hive, view)
                .OpenSubKey(childPath, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions);
            if (ck is not null)
            {
                var sec = ck.GetAccessControl(AccessControlSections.Access);
                sec.AddAccessRule(new RegistryAccessRule(
                    admins, RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
                ck.SetAccessControl(sec);
            }
        }
        catch { }

        try
        {
            using var parent = RegistryKey.OpenBaseKey(hive, view).OpenSubKey(parentSubKey, writable: true);
            if (parent is null) return false;
            parent.DeleteSubKeyTree(childName, throwOnMissingSubKey: false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ── 特权启用(advapi32) ─────────────────────────────────────

    private const int SE_PRIVILEGE_ENABLED = 0x00000002;
    private const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const int TOKEN_QUERY = 0x0008;

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES { public int PrivilegeCount; public LUID Luid; public int Attributes; }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    /// <summary>启用当前进程令牌中的指定特权(若进程持有该特权)。失败静默返回。</summary>
    private static void EnablePrivilege(string privilege)
    {
        IntPtr token = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
                return;
            if (!LookupPrivilegeValue(null, privilege, out var luid))
                return;
            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SE_PRIVILEGE_ENABLED
            };
            AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }
        catch { /* 尽力而为 */ }
        finally { if (token != IntPtr.Zero) CloseHandle(token); }
    }
}
