# Back up the ONLY copies of the live API keys.
# ASCII only (PowerShell 5.1 reads BOM-less .ps1 as ANSI).
#
# Why this is needed:
#   The real credentials live in exactly two files under %ProgramData%\Bulwark:
#     appsettings.json  -- 6 credential fields with values (service-side config)
#     settings.json     -- 6 API keys with values (runtime settings the UI writes)
#   Neither has a backup. Both are rewritten by the running service:
#     * settings.json on every SettingsUpdate from the UI;
#     * appsettings.json is read-only to the service, but a reinstall overwrites it.
#   A single bad write loses keys that must then be re-obtained from six vendors.
#
# The backup goes OUTSIDE the git repo working tree on purpose -- these are
# credentials and must never be at risk of being committed.
$ErrorActionPreference = 'Stop'
$src = Join-Path $env:ProgramData 'Bulwark'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$dst = Join-Path $env:LOCALAPPDATA ('Bulwark-key-backup\' + $stamp)
$log = Join-Path $PSScriptRoot 'backup-keys.txt'
$out = @()

New-Item -ItemType Directory -Path $dst -Force | Out-Null

foreach ($name in @('appsettings.json', 'settings.json')) {
    $p = Join-Path $src $name
    if (Test-Path $p) {
        Copy-Item $p (Join-Path $dst $name) -Force
        $fi = Get-Item (Join-Path $dst $name)
        $out += ('copied {0,-20} {1,7} B' -f $name, $fi.Length)
    } else {
        $out += ('MISSING {0}' -f $name)
    }
}

# Lock the backup down to the current user only. These are credentials; the
# default ACL on %LOCALAPPDATA% is already user-scoped, but inheritance is
# removed explicitly so a later ACL change upstream cannot widen it.
$acl = Get-Acl $dst
$acl.SetAccessRuleProtection($true, $false)
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $me, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.SetAccessRule($rule)
Set-Acl $dst $acl
$out += ('acl restricted to {0}' -f $me)

$out += ''
$out += ('backup dir: ' + $dst)
$out += 'NOTE: contains plaintext credentials. Do not move it into the git repo.'
$out | Set-Content $log -Encoding UTF8
