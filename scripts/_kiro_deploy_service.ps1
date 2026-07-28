# Kiro helper: redeploy the rebuilt user-mode SERVICE ONLY (adds the catch-all malicious sweep).
# Does NOT touch the driver (Bulwark.sys is already loaded and enforcing). ASCII-only, since a
# Chinese Windows PowerShell host reads .ps1 as GBK -> never hardcode the non-ASCII install path;
# it is derived at runtime from 'sc qc'. Run elevated: right-click _kiro_deploy_service.bat -> Run as administrator.

# Prefer 64-bit host so sc.exe et al. are not WOW64-redirected. Relaunch self under 64-bit PS if needed.
if (-not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        Write-Host "[wrapper] 32-bit host detected; relaunching under 64-bit PowerShell..."
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }
}

$ErrorActionPreference = 'Continue'
$env:Path = "$env:SystemRoot\System32;$env:SystemRoot\System32\Wbem;$env:SystemRoot\System32\WindowsPowerShell\v1.0;$env:Path"

$log = Join-Path $env:USERPROFILE 'bulwark_deploy_service.log'
Start-Transcript -Path $log -Force | Out-Null
Write-Host "=== Bulwark SERVICE-only redeploy (catch-all malicious sweep) ==="

# New service exe produced by the build (build-fix / VS2022 Release).
$newSvc = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\cpp\build-fix\service\Release\bulwark_service.exe'))
if (-not (Test-Path $newSvc)) {
    Write-Host "[svc] ERROR: new exe missing: $newSvc"
    Write-Host "SENTINEL_DEPLOY_DONE"; Stop-Transcript | Out-Null; exit 1
}
$srcLen = (Get-Item $newSvc).Length
Write-Host ("[svc] new exe: {0} ({1} bytes)" -f $newSvc, $srcLen)

# Unlock the installed exe: stop the UI (watchdog) first, then the service, then hard-kill leftovers.
Write-Host "[svc] stopping bulwark_ui (watchdog) + BulwarkService + bulwark_service ..."
Get-Process bulwark_ui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
& sc.exe stop BulwarkService 2>&1 | Out-Null
Start-Sleep -Seconds 1
Get-Process bulwark_service -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Derive the installed path from 'sc qc' (quoted-regex; avoids the greedy '.*:' that ate the D: drive letter).
$qc = (& sc.exe qc BulwarkService 2>&1 | Out-String)
$svcExe = $null
if ($qc -match 'BINARY_PATH_NAME\s*:\s*"?([^"\r\n]+\.exe)') { $svcExe = $Matches[1].Trim() }
if (-not $svcExe) {
    Write-Host "[svc] ERROR: could not derive install path from 'sc qc'."
    Write-Host $qc
    Write-Host "SENTINEL_DEPLOY_DONE"; Stop-Transcript | Out-Null; exit 1
}
Write-Host "[svc] install path: $svcExe"

# Copy the new exe over the installed one; retry a few times in case a watchdog re-locks it.
$copied = $false
for ($i = 0; $i -lt 5 -and -not $copied; $i++) {
    try { Copy-Item $newSvc $svcExe -Force -ErrorAction Stop; $copied = $true }
    catch {
        Write-Host ("[svc] copy attempt {0} failed (locked?): {1}" -f ($i + 1), $_.Exception.Message)
        Get-Process bulwark_service, bulwark_ui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
}
if (-not $copied) {
    Write-Host "[svc] ERROR: copy failed. End bulwark_service.exe + bulwark_ui.exe in Task Manager, then re-run."
    Write-Host "SENTINEL_DEPLOY_DONE"; Stop-Transcript | Out-Null; exit 1
}
Write-Host "[svc] deployed new service -> $svcExe"

# Start the service; it reconnects to the already-loaded driver (handshake v9) and starts the sweep.
Write-Host "[svc] starting BulwarkService ..."
& sc.exe start BulwarkService 2>&1 | Out-Host
Start-Sleep -Seconds 3

Write-Host "=== post-state ==="
$dstLen = (Get-Item $svcExe).Length
Write-Host ("deployed exe: {0} bytes  (source {1} bytes)  match={2}" -f $dstLen, $srcLen, ($dstLen -eq $srcLen))
$state = (& sc.exe query BulwarkService 2>&1 | Out-String)
if ($state -match 'RUNNING') { Write-Host "service state: RUNNING (OK)" } else { Write-Host ("service state: NOT RUNNING`n" + $state) }
Write-Host "SENTINEL_DEPLOY_DONE"
Stop-Transcript | Out-Null
