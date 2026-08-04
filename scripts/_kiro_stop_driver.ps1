# =====================================================================
#  Stop / unload ONLY the Bulwark minifilter driver.
#
#  Nothing is deleted and nothing is re-registered: the service entry,
#  its persisted Policy baseline and System32\drivers\Bulwark.sys all
#  stay exactly as they are, so "fltmc load Bulwark" (or
#  scripts\_kiro_load_now.ps1) brings the driver straight back.
#
#  Order is the project-sanctioned one:
#    1) user mode first  - SelfGuard clears on disconnect
#    2) fltmc unload     - removes the callbacks
#    3) sc stop          - drops the service to STOPPED
#
#  NOTE: this is a .ps1 and NOT a .bat on purpose. The kernel baseline
#  keeps \WINDOWS\SYSTEM32\CMD.EXE in FileExecBlock, so while the driver
#  is loaded no cmd.exe / .bat can start at all.
#
#  ASCII-ONLY ON PURPOSE: Windows PowerShell 5.1 reads UTF-8-without-BOM
#  .ps1 as ANSI/GBK on a Chinese Windows. Nothing non-ASCII is hardcoded.
# =====================================================================

# 64-bit host required: fltmc.exe / sc.exe live in System32 and get
# WOW64-redirected away under a 32-bit host.
if (-not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }
}

$ErrorActionPreference = 'Continue'
$env:Path = "$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0;$env:Path"

$log    = Join-Path $env:TEMP 'blw_stop_driver.log'
$drvSvc = 'Bulwark'
$umSvc  = 'BulwarkService'

function W($m) { Add-Content -Path $log -Value $m }

Set-Content -Path $log -Value '==== stop bulwark driver ===='

$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
W ("admin   = " + $isAdmin)
W ("is64bit = " + [Environment]::Is64BitProcess)
if (-not $isAdmin) {
    W 'NOT ELEVATED - aborting before touching anything.'
    W 'SENTINEL_STOP_DONE'
    exit 1
}

W ''
W '[1/4] stop user mode (UI watchdog + service)'
Get-Process -Name bulwark_ui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
W ((& sc.exe stop $umSvc 2>&1 | Out-String).Trim())
Start-Sleep -Seconds 1
Get-Process -Name bulwark_service -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

W ''
W '[2/4] fltmc unload Bulwark'
W ((& fltmc.exe unload $drvSvc 2>&1 | Out-String).Trim())

W ''
W '[3/4] sc stop Bulwark'
W ((& sc.exe stop $drvSvc 2>&1 | Out-String).Trim())
for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 1
    if ((& sc.exe query $drvSvc 2>&1 | Out-String) -match 'STOPPED') { break }
}
W ("waited " + $i + "s for STOPPED")

W ''
W '[4/4] post state'
W ((& sc.exe query $drvSvc 2>&1 | Out-String).Trim())
$filters = (& fltmc.exe filters 2>&1 | Out-String)
W $filters
W ("bulwark_still_in_filter_list = " + [bool]($filters -match '(?im)^\s*Bulwark\s'))
W 'SENTINEL_STOP_DONE'
exit 0
