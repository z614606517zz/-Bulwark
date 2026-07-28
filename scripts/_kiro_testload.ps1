# Kiro helper: run deploy-driver-vm.ps1 (test-sign + deploy + load my rebuilt Bulwark.sys),
# capturing everything to a log Kiro can read. ASCII-only (Chinese Windows PS reads .ps1 as GBK).

# Must run 64-bit: bcdedit/fltmc/sc/signtool live in System32; under a 32-bit (SysWOW64) PowerShell
# host they get WOW64-redirected away (bcdedit "not recognized"), which aborts the deploy. If we are
# 32-bit, relaunch this same script under the native 64-bit PowerShell (inherits the elevated token).
if (-not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        Write-Host "[wrapper] 32-bit host detected; relaunching under 64-bit PowerShell..."
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }
}

$ErrorActionPreference = 'Continue'

# Belt-and-suspenders: ensure core system dirs are on PATH. Some special PowerShell hosts (e.g. the
# Appx "Debuggable Package Manager") start with a trimmed PATH missing System32 -> bcdedit "not found".
$env:Path = "$env:SystemRoot\System32;$env:SystemRoot\System32\Wbem;$env:SystemRoot\System32\WindowsPowerShell\v1.0;$env:Path"

$log = Join-Path $env:USERPROFILE 'bulwark_deploy.log'
Start-Transcript -Path $log -Force | Out-Null
Write-Host "=== Bulwark test-load (Kiro wrapper) ==="

# --- (A) Deploy the rebuilt user-mode SERVICE (adds: cloud-intel-confirmed -> push ban to driver) ---
# The exe must be unlocked first: stop the service + kill its processes. The installed service path
# is derived from 'sc qc' at runtime (avoids hardcoding the non-ASCII install path in this script).
$newSvc = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\cpp\build-fix\service\Release\bulwark_service.exe'))
Write-Host "[svc] stopping BulwarkService + bulwark_service/ui ..."
& sc.exe stop BulwarkService 2>&1 | Out-Null
Get-Process bulwark_service,bulwark_ui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
$qc = (& sc.exe qc BulwarkService 2>&1 | Out-String)
$svcExe = $null
if ($qc -match 'BINARY_PATH_NAME\s*:\s*"?([^"\r\n]+\.exe)') { $svcExe = $Matches[1].Trim() }
if ((Test-Path $newSvc) -and $svcExe) {
    try { Copy-Item $newSvc $svcExe -Force; Write-Host "[svc] deployed new service -> $svcExe" }
    catch { Write-Host "[svc] copy FAILED (still locked? end bulwark_service/ui in Task Manager): $($_.Exception.Message)" }
} else {
    Write-Host "[svc] skip service update (new exe missing or install path not found; new=$newSvc svc=$svcExe)"
}

# --- (B) Test-sign + deploy + load the rebuilt DRIVER (banned-PID enforcement + auto-ban) ---
try {
    & "$PSScriptRoot\deploy-driver-vm.ps1" -Configuration Debug
} catch {
    Write-Host ("WRAPPER-ERR: " + $_.Exception.Message)
}

# --- (C) Start the (new) service so it reconnects to the driver (handshake v9) ---
Write-Host "[svc] starting BulwarkService ..."
& sc.exe start BulwarkService 2>&1 | Out-Host

Write-Host "=== post-state ==="
& fltmc.exe filters 2>&1 | Out-Host
& sc.exe query Bulwark 2>&1 | Out-Host
$t = Join-Path $env:SystemRoot 'System32\drivers\Bulwark.sys'
if (Test-Path $t) {
    $i = Get-Item $t
    Write-Host ("deployed sys: {0} bytes  sig={1}" -f $i.Length, (Get-AuthenticodeSignature $t).Status)
}
Write-Host "SENTINEL_DEPLOY_DONE"
Stop-Transcript | Out-Null
