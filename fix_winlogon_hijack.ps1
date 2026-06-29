# =====================================================================
#  Userinit 登录劫持清除脚本  (C:\Windows\Sub\RuntimeBroker.exe)
#  用法:在【安全模式】下,以【管理员】运行的 PowerShell 里执行:
#     powershell -NoProfile -ExecutionPolicy Bypass -File "fix_winlogon_hijack.ps1"
#  说明:正常模式下 360 主动防御驱动会拦截对 Winlogon\Userinit 的写入,
#        必须进安全模式(360 驱动不加载)才能改动成功。
# =====================================================================
$ErrorActionPreference = 'Stop'
function W($m){ Write-Output $m }

# 1) 启用夺取所有权/恢复特权(应对键 ACL 被改)
Add-Type -Namespace Priv -Name Tok -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct TP { public int Count; public long Luid; public int Attr; }
[DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)] public static extern bool LookupPrivilegeValue(string host, string name, out long luid);
[DllImport("advapi32.dll", SetLastError=true)] public static extern bool AdjustTokenPrivileges(IntPtr tok, bool dis, ref TP newp, uint len, IntPtr prev, IntPtr relen);
[DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
public static void Enable(string priv){
  IntPtr tok; OpenProcessToken(GetCurrentProcess(), 0x28, out tok);
  long luid; LookupPrivilegeValue(null, priv, out luid);
  TP tp = new TP(); tp.Count = 1; tp.Luid = luid; tp.Attr = 0x2;
  AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
}
'@
[Priv.Tok]::Enable('SeTakeOwnershipPrivilege')
[Priv.Tok]::Enable('SeRestorePrivilege')

$path   = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$RR     = [System.Security.AccessControl.RegistryRights]
$PC     = [Microsoft.Win32.RegistryKeyPermissionCheck]
$ACS    = [System.Security.AccessControl.AccessControlSections]

# 2) 夺取所有权 + 授予 Administrators 完全控制
try {
  $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $PC::ReadWriteSubTree, $RR::TakeOwnership)
  $acl = $k.GetAccessControl($ACS::None); $acl.SetOwner($admins); $k.SetAccessControl($acl); $k.Close()
  $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $PC::ReadWriteSubTree, $RR::ChangePermissions)
  $acl = $k.GetAccessControl($ACS::Access); [void]$acl.PurgeAccessRules($admins)
  $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admins,'FullControl','ContainerInherit','None','Allow')
  $acl.AddAccessRule($rule); $k.SetAccessControl($acl); $k.Close()
  W "[ok] ownership + ACL fixed"
} catch { W ("[warn] acl step: " + $_.Exception.Message) }

# 3) 备份并写入干净值
$k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $true)
$before = $k.GetValue('Userinit')
W ("[info] BEFORE = [" + $before + "]")
$bak = Join-Path $PSScriptRoot ("userinit_backup_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
Set-Content -LiteralPath $bak -Value $before -Encoding utf8
W ("[info] backup -> " + $bak)
$k.SetValue('Userinit', 'C:\Windows\System32\userinit.exe,', [Microsoft.Win32.RegistryValueKind]::String)
$after = $k.GetValue('Userinit'); $k.Close()
W ("[info] AFTER  = [" + $after + "]")

# 4) 校验 + 清理残留目录
if ($after -match '\\Sub\\') { W "[FAIL] malicious segment still present (still blocked - confirm Safe Mode)" }
elseif ($after -match '(?i)System32\\userinit') { W "[OK] Userinit hijack removed" }
else { W "[WARN] check manually against backup" }

foreach ($p in @('C:\Windows\Sub')) {
  if (Test-Path -LiteralPath $p) {
    try { takeown /f $p /a /r /d y *> $null; icacls $p /grant *S-1-5-32-544:F /t /c *> $null; Remove-Item -LiteralPath $p -Recurse -Force; W ("[ok] removed residual " + $p) }
    catch { W ("[warn] residual " + $p + " : " + $_.Exception.Message) }
  } else { W ("[info] residual " + $p + " not present") }
}
W "[done]"
