# =====================================================================
#  Kiro helper: redeploy the rebuilt user-mode service (adds the long-form
#  root-key patterns HKEY_LOCAL_MACHINE\SAM|SECURITY to the command-line
#  hard-block baseline), restart it, relaunch the UI, and re-verify.
#
#  The kernel driver is NOT touched - this is a user-mode-only cycle.
#  ASCII-ONLY (PowerShell 5.1 reads UTF-8-without-BOM .ps1 as GBK here).
# =====================================================================

if (-not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) { & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath; exit $LASTEXITCODE }
}
$ErrorActionPreference = 'Continue'
$env:Path = "$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0;$env:Path"

$log = Join-Path $env:TEMP 'blw_redeploy.log'
Start-Transcript -Path $log -Force | Out-Null

$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "NOT ELEVATED - aborting."; Write-Host "SENTINEL_REDEPLOY_DONE"; Stop-Transcript | Out-Null; exit 1
}

$root   = Split-Path -Parent $PSScriptRoot
$newSvc = Join-Path $root 'cpp\build\service\Release\bulwark_service.exe'
$dist   = Join-Path $root 'cpp\dist'
$dstSvc = Join-Path $dist 'bulwark_service.exe'
$uiExe  = Join-Path $dist 'bulwark_ui.exe'

Write-Host "=== STEP 1 - stop UI + service (this also clears kernel SelfGuard on the install dir) ==="
Get-Process bulwark_ui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
& sc.exe stop BulwarkService 2>&1 | Out-Host
Start-Sleep -Seconds 3
Get-Process bulwark_service -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Host ""
Write-Host "=== STEP 2 - deploy the rebuilt exe ==="
if (-not (Test-Path $newSvc)) { Write-Host ("MISSING " + $newSvc); Write-Host "SENTINEL_REDEPLOY_DONE"; Stop-Transcript | Out-Null; exit 1 }
$copied = $false
for ($i = 0; $i -lt 5 -and -not $copied; $i++) {
    try { Copy-Item $newSvc $dstSvc -Force -ErrorAction Stop; $copied = $true }
    catch { Write-Host ("  copy attempt " + ($i+1) + " failed: " + $_.Exception.Message); Start-Sleep -Seconds 2 }
}
if (-not $copied) { Write-Host "  copy FAILED"; Write-Host "SENTINEL_REDEPLOY_DONE"; Stop-Transcript | Out-Null; exit 1 }
$a = Get-Item $newSvc; $b = Get-Item $dstSvc
Write-Host ("  deployed " + $b.Length + " bytes  " + $b.LastWriteTime + "  (source " + $a.Length + ")")

Write-Host ""
Write-Host "=== STEP 3 - start the service + relaunch the UI ==="
& sc.exe start BulwarkService 2>&1 | Out-Host
Start-Sleep -Seconds 8
& sc.exe query BulwarkService 2>&1 | Select-String -SimpleMatch 'STATE' | ForEach-Object { Write-Host ("  " + $_.Line.Trim()) }
Start-Process -FilePath $uiExe -WorkingDirectory $dist
Start-Sleep -Seconds 5
Get-Process bulwark_service, bulwark_ui -ErrorAction SilentlyContinue | ForEach-Object { Write-Host ("  PROC " + $_.ProcessName + " pid=" + $_.Id) }

Write-Host ""
Write-Host "=== STEP 4 - kernel CmdHardBlock after the push ==="
$polKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bulwark\Policy'
$cmdList = @()
if (Test-Path $polKey) {
    $v = (Get-ItemProperty $polKey -Name CmdHardBlock -ErrorAction SilentlyContinue).CmdHardBlock
    if ($v) { $cmdList = @($v | Where-Object { $_ -ne '' }) }
}
Write-Host ("  entries = " + $cmdList.Count)
$cmdList | ForEach-Object { Write-Host ("    " + $_) }
$hasLong = ($cmdList -contains 'SAVE+HKEY_LOCAL_MACHINE\SAM')
Write-Host ("  long-form root-key pattern present = " + $hasLong)

Write-Host ""
Write-Host "=== STEP 5 - re-test the bypass that was found earlier ==="
Write-Host "  payloads are harmless (cmd /c echo ...), only the command line matters"
$cmd = "$env:SystemRoot\System32\cmd.exe"
function T([string]$label, [string]$cmdline, [string]$expect) {
    try {
        $p = Start-Process -FilePath $cmd -ArgumentList $cmdline -PassThru -Wait -WindowStyle Hidden -ErrorAction Stop
        $got = 'ALLOWED'
    } catch { $got = 'DENIED' }
    $ok = if ($got -eq $expect) { 'PASS' } else { '**FAIL**' }
    Write-Host ("  {0}  {1,-52} expect={2,-8} got={3}" -f $ok, $label, $expect, $got)
}
T 'short form  reg save HKLM\SAM'                 '/c echo reg save HKLM\SAM out.hiv'                 'DENIED'
T 'LONG form   reg save HKEY_LOCAL_MACHINE\SAM'   '/c echo reg save HKEY_LOCAL_MACHINE\SAM out.hiv'   'DENIED'
T 'LONG form   reg save HKEY_LOCAL_MACHINE\SECURITY' '/c echo reg save HKEY_LOCAL_MACHINE\SECURITY o.hiv' 'DENIED'
T 'negative    reg query HKEY_LOCAL_MACHINE\SAM'  '/c echo reg query HKEY_LOCAL_MACHINE\SAM'          'ALLOWED'
T 'negative    reg save a benign key'             '/c echo reg save HKLM\SOFTWARE\Foo out.hiv'        'ALLOWED'

Write-Host ""
Write-Host "SENTINEL_REDEPLOY_DONE"
Stop-Transcript | Out-Null
