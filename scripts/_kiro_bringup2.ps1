# =====================================================================
#  Kiro helper - STEP 2 of bring-up: get the user-mode service registered,
#  started, and the UI up. The kernel driver is already loaded by
#  _kiro_bringup.ps1.
#
#  ASCII-ONLY ON PURPOSE (Windows PowerShell 5.1 reads UTF-8-without-BOM
#  .ps1 as GBK on Chinese Windows and would corrupt non-ASCII paths).
#  All paths derived at runtime from $PSScriptRoot.
#
#  Why the extra work: SCM reports 1060 "service not installed" for
#  BulwarkService, yet HKLM\...\Services\BulwarkService still exists with a
#  valid ImagePath - i.e. a residual key from an earlier `sc delete` that SCM
#  no longer tracks. CreateService would then fail with 1072/1073, so the
#  stale key is removed first and the exe re-registers itself via --install.
#
#  ORDER MATTERS: install BEFORE starting. Once the service connects it pushes
#  "\Services\Bulwark" into the kernel registry hard-block list (a substring
#  that also covers "BulwarkService"), after which user-mode writes to that key
#  are denied by design - so registration has to happen first.
# =====================================================================

if (-not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) { & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath; exit $LASTEXITCODE }
}

$ErrorActionPreference = 'Continue'
$env:Path = "$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0;$env:Path"

$log = Join-Path $env:TEMP 'blw_bringup2.log'
Start-Transcript -Path $log -Force | Out-Null

$root   = Split-Path -Parent $PSScriptRoot
$dist   = Join-Path $root 'cpp\dist'
$svcExe = Join-Path $dist 'bulwark_service.exe'
$uiExe  = Join-Path $dist 'bulwark_ui.exe'
$umSvc  = 'BulwarkService'
$regKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$umSvc"

function Head($t) { Write-Host ""; Write-Host ("=== " + $t + " ===") }

Head 'STEP 1 - preconditions'
$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "NOT ELEVATED - aborting."; Write-Host "SENTINEL_BRINGUP2_DONE"; Stop-Transcript | Out-Null; exit 1
}
Write-Host ("admin  = True   is64 = " + [Environment]::Is64BitProcess)
Write-Host ("dist   = " + $dist)
foreach ($f in @($svcExe, $uiExe)) {
    if (Test-Path $f) { $i = Get-Item $f; Write-Host ("OK   " + $i.Name + "  " + $i.Length + " bytes  " + $i.LastWriteTime) }
    else { Write-Host ("MISSING " + $f); Write-Host "SENTINEL_BRINGUP2_DONE"; Stop-Transcript | Out-Null; exit 1 }
}

Head 'STEP 2 - clear the stale service registration'
Write-Host "current registry state of the key:"
if (Test-Path $regKey) {
    $p = Get-ItemProperty $regKey
    foreach ($n in (Get-Item $regKey).Property) { Write-Host ("  " + $n + " = " + $p.$n) }
} else { Write-Host "  (key absent)" }

& sc.exe stop $umSvc   2>&1 | Out-Null
& sc.exe delete $umSvc 2>&1 | Out-Host
Start-Sleep -Seconds 1
if (Test-Path $regKey) {
    Write-Host "key still present after sc delete -> removing it directly (residual key)"
    try { Remove-Item $regKey -Recurse -Force -ErrorAction Stop; Write-Host "  removed" }
    catch { Write-Host ("  remove FAILED: " + $_.Exception.Message) }
} else {
    Write-Host "key gone"
}
Start-Sleep -Seconds 1

Head 'STEP 3 - register via the exe self-install (--install)'
$out = (& $svcExe --install 2>&1 | Out-String)
Write-Host $out
Start-Sleep -Seconds 1
& sc.exe qc $umSvc 2>&1 | Out-Host

Head 'STEP 4 - start the service'
& sc.exe start $umSvc 2>&1 | Out-Host
# The service connects to \BulwarkPort, does the v9 handshake, pushes config, and the
# kernel debounces the policy write-back by 300ms. Give it room.
Start-Sleep -Seconds 8
& sc.exe query $umSvc 2>&1 | Out-Host

Head 'STEP 5 - launch the UI'
$running = (& sc.exe query $umSvc 2>&1 | Out-String) -match 'RUNNING'
if (-not $running) {
    Write-Host "service is not RUNNING - launching the UI anyway so its bootstrap path can report why."
}
Start-Process -FilePath $uiExe -WorkingDirectory $dist
Start-Sleep -Seconds 6
Get-Process bulwark_service, bulwark_ui -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host ("PROC " + $_.ProcessName + " pid=" + $_.Id) }

Head 'STEP 6 - kernel policy baseline (proves the config push landed)'
$polKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bulwark\Policy'
if (Test-Path $polKey) {
    $pol = Get-ItemProperty $polKey
    foreach ($name in (Get-Item $polKey).Property) {
        $v = $pol.$name
        if ($v -is [array]) {
            Write-Host ($name + "  (" + ($v | Where-Object { $_ -ne '' }).Count + " entries)")
            $v | ForEach-Object { if ($_ -ne '') { Write-Host ("    " + $_) } }
        } else { Write-Host ($name + " = " + $v) }
    }
    if ((Get-Item $polKey).Property -contains 'CmdHardBlock') {
        Write-Host ""
        Write-Host "OK: CmdHardBlock present -> command-line hard block is live AND persisted"
        Write-Host "    (user-mode push -> kernel list -> debounced registry write-back)."
    } else {
        Write-Host ""
        Write-Host "WARN: CmdHardBlock missing - service may not have connected, or handshake failed."
    }
} else {
    Write-Host "no Policy subkey - the service did not push config to the driver."
}

Head 'STEP 7 - service log tail'
$logDir = Join-Path $env:ProgramData 'Bulwark\logs'
if (Test-Path $logDir) {
    $latest = Get-ChildItem $logDir -Filter *.log -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
        Write-Host ("file: " + $latest.FullName)
        Get-Content $latest.FullName -Tail 60 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host ("  " + $_) }
    } else { Write-Host ("no .log under " + $logDir) }
} else { Write-Host ("no log dir " + $logDir) }

Write-Host ""
Write-Host "SENTINEL_BRINGUP2_DONE"
Stop-Transcript | Out-Null
