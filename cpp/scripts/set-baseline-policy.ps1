<#
  set-baseline-policy.ps1  --  Seed Bulwark kernel-driver "self-sufficient baseline" (admin required)

  ASCII-only on purpose: a Chinese Windows PowerShell host reads .ps1 without a BOM as GBK,
  and UTF-8 multibyte comments/strings then corrupt parsing. Keep this file ASCII.

  WHAT IT DOES
    Writes a static protection baseline into the driver service's Policy subkey:
        HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Policy
    The driver reads these REG_MULTI_SZ values at DriverEntry and fills its local lists, so on the
    very first boot -- before the user-mode service starts -- the kernel already enforces a local
    "pre-action" baseline. Protection no longer depends on a killable user-mode process.

  WHY THIS SCRIPT (and why run it while the driver is UNLOADED)
    When running, the service adds "\Services\Bulwark" to the kernel registry hard-block (self-
    protection). Once the driver is loaded, user mode (including this script) can no longer write
    its own Policy subkey. So the static baseline must be written while the driver is unloaded /
    before its first load. Afterwards, verdicts the service learns at runtime (exec-block / no-load /
    anti-rebuild / protected items) are written back to the same Policy key by the kernel itself
    (KernelMode is exempt from the hard-block), so this script is only the "first fill".

  USAGE (admin PowerShell)
    # Safe default (only self-protect our own service key):
    powershell -ExecutionPolicy Bypass -File set-baseline-policy.ps1
    # Add recommended high-value anti-tamper entries (may interfere with Windows servicing -- test first):
    powershell ... -File set-baseline-policy.ps1 -Recommended
    # Custom:
    powershell ... -File set-baseline-policy.ps1 -FileExecBlock '\evil.exe' -KnownBadSha256 '<64-hex>'
    # If the driver is already loaded, unload it first to write, then it must be reloaded:
    powershell ... -File set-baseline-policy.ps1 -ForceUnload
#>
[CmdletBinding()]
param(
  [string]   $ServiceName      = 'Bulwark',
  [string[]] $ProtectedPaths   = @(),
  [string[]] $FileHardBlock    = @(),
  [string[]] $FileNoLoad       = @(),
  [string[]] $FileExecBlock    = @(),
  [string[]] $ProtectedRegKeys = @(),
  [string[]] $RegHardBlock     = @('\Services\Bulwark'),   # default: self-protect our own service key only
  [string[]] $BlockIps         = @(),
  [string[]] $KnownBadSha256   = @(),
  [string]   $SysPath          = "$env:SystemRoot\System32\drivers\Bulwark.sys",
  [switch]   $Recommended,     # append high-value anti-tamper entries (see below; may affect servicing)
  [switch]   $ForceUnload      # if driver is loaded, unload before writing (protection briefly drops)
)
$ErrorActionPreference = 'Stop'

# --- require admin ---
$idn = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($idn)).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Please run this script as Administrator.'
}

# --- recommended set (opt-in): classic anti-tamper / anti-backdoor targets ---
# WARNING: a file hard-block denies write/delete/rename/overwrite-open (read + execute still allowed).
# Hard-blocking system files MAY interfere with Windows Update / servicing (TrustedInstaller writes are
# user-mode too). Validate in a test environment before using -Recommended in production.
if ($Recommended) {
  $FileHardBlock += @(
    '\System32\drivers\etc\hosts',   # anti-tamper hosts (DNS hijack / block security sites)
    '\System32\sethc.exe',           # sticky-keys backdoor (replaced with cmd.exe)
    '\System32\utilman.exe',         # accessibility backdoor
    '\System32\Magnify.exe',
    '\System32\osk.exe',
    '\System32\config\SAM'           # anti offline SAM tamper
  )
  $RegHardBlock += @(
    '\Winlogon\Shell',               # prevent logon Shell hijack (persistence)
    '\Winlogon\Userinit'             # prevent Userinit hijack (persistence)
  )
  Write-Warning '-Recommended enabled: includes system file/registry hard-blocks that may interfere with Windows Update and legitimate admin. Test first.'
}

# --- validate/clean KnownBadSha256 (kernel requires exactly 64 hex chars) ---
$KnownBadSha256 = @($KnownBadSha256 | ForEach-Object {
  $h = "$_".Trim()
  if ($h -match '^[0-9a-fA-F]{64}$') { $h.ToLower() }
  elseif ($h -ne '') { Write-Warning "Ignoring invalid SHA-256 (need 64 hex chars): $h"; $null }
} | Where-Object { $_ })

$svcKey    = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$policyKey = "$svcKey\Policy"

# --- is the driver service registered? ---
$q = & sc.exe query $ServiceName 2>&1
$registered = -not ($q -match '1060' -or ($q -match 'does not exist'))

if (-not $registered) {
  if (Test-Path $SysPath) {
    # Register the minifilter service (mirrors DriverControl::ensureRegistered) so we do not create a
    # dangling key with no service values (which would make a later 'sc create' fail with 1073).
    Write-Host "== Registering kernel minifilter service $ServiceName ($SysPath) ==" -ForegroundColor Cyan
    $create = & sc.exe create $ServiceName type= filesys binPath= "$SysPath" start= demand depend= FltMgr group= "FSFilter Activity Monitor" 2>&1
    if ($LASTEXITCODE -ne 0 -and ($create -notmatch '1073')) {
      throw "Failed to register driver service (sc create): $create"
    }
    $instances = "$svcKey\Instances"
    & reg.exe add "$instances" /v DefaultInstance /t REG_SZ /d 'Bulwark Instance' /f | Out-Null
    & reg.exe add "$instances\Bulwark Instance" /v Altitude /t REG_SZ /d '385201' /f | Out-Null
    & reg.exe add "$instances\Bulwark Instance" /v Flags /t REG_DWORD /d 0 /f | Out-Null
  } else {
    throw "Driver service $ServiceName is not registered and $SysPath was not found. Deploy Bulwark.sys and pass -SysPath, or run the user-mode service once (it auto-registers the driver), then re-run this script."
  }
}

# --- if the driver is loaded, self-protection blocks writes: warn / optionally unload ---
$filters = & fltmc.exe filters 2>&1
$loaded = ($filters -match [regex]::Escape($ServiceName))
if ($loaded) {
  if ($ForceUnload) {
    Write-Host "Driver is loaded; -ForceUnload: unloading to write baseline (protection briefly drops)..." -ForegroundColor Yellow
    & fltmc.exe unload $ServiceName 2>&1 | Out-Host
    Start-Sleep -Milliseconds 500
  } else {
    Write-Warning "Driver is currently loaded; self-protection (\Services\Bulwark hard-block) will block writing Policy. Run 'fltmc unload $ServiceName' first, or re-run with -ForceUnload."
  }
}

# --- write Policy baseline (REG_MULTI_SZ) ---
New-Item -Path $policyKey -Force | Out-Null

function Set-MultiSz([string]$Name, [string[]]$Vals) {
  $clean = @($Vals | ForEach-Object { "$_".Trim() } | Where-Object { $_ -ne '' } | Select-Object -Unique)
  try {
    New-ItemProperty -Path $policyKey -Name $Name -PropertyType MultiString -Value $clean -Force | Out-Null
    Write-Host ("  {0,-16} = {1} entrie(s)" -f $Name, $clean.Count) -ForegroundColor Green
  } catch {
    Write-Warning "Failed to write ${Name} (driver self-protection may be active; unload the driver or use -ForceUnload): $($_.Exception.Message)"
  }
}

Write-Host "== Writing self-sufficient baseline to $policyKey ==" -ForegroundColor Cyan
Set-MultiSz 'ProtectedPaths'   $ProtectedPaths
Set-MultiSz 'FileHardBlock'    $FileHardBlock
Set-MultiSz 'FileNoLoad'       $FileNoLoad
Set-MultiSz 'FileExecBlock'    $FileExecBlock
Set-MultiSz 'ProtectedRegKeys' $ProtectedRegKeys
Set-MultiSz 'RegHardBlock'     $RegHardBlock
Set-MultiSz 'BlockIps'         $BlockIps
Set-MultiSz 'KnownBadSha256'   $KnownBadSha256

Write-Host "`nDone. On next driver load (fltmc load $ServiceName) or reboot, the kernel enforces this baseline before the user-mode service starts." -ForegroundColor Green
Write-Host "Note: verdicts learned later at runtime are written back to the same Policy key by the kernel itself; no need to re-run this script." -ForegroundColor DarkGray
