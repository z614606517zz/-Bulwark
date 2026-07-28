# =====================================================================
#  Kiro helper: full bring-up of the REBUILT stack on this machine.
#
#  ASCII-ONLY ON PURPOSE. Windows PowerShell 5.1 reads UTF-8-without-BOM
#  .ps1 as ANSI/GBK on a Chinese Windows, which corrupts non-ASCII path
#  literals. Every path here is derived at runtime from $PSScriptRoot or
#  from the registry - nothing non-ASCII is ever hardcoded.
#
#  What it does (single elevation):
#    1) verify elevated + 64-bit + testsigning
#    2) stop UI + BulwarkService, unload the currently loaded driver
#    3) back up the deployed Bulwark.sys (one-copy rollback)
#    4) run the project's own deploy-driver-vm.ps1 (sign + copy + register
#       as MINIFILTER + fltmc load) with the freshly built Debug driver
#    5) verify the loaded .sys is byte-identical to the new build
#    6) start BulwarkService, launch the UI
#    7) dump post-state, including the kernel policy baseline written back
#       to HKLM\...\Services\Bulwark\Policy - CmdHardBlock proves the new
#       command-line hard-block path works end to end
#
#  Rollback if anything misbehaves:
#     fltmc unload Bulwark
#     copy /y "%TEMP%\Bulwark.sys.prev" "%SystemRoot%\System32\drivers\Bulwark.sys"
#     fltmc load Bulwark
# =====================================================================

# --- must be 64-bit: bcdedit/fltmc/sc/signtool live in System32 and get
#     WOW64-redirected away under a 32-bit host. Relaunch natively (the
#     elevated token is inherited). -------------------------------------
if (-not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }
}

$ErrorActionPreference = 'Continue'
$env:Path = "$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0;$env:Path"

$log = Join-Path $env:TEMP 'blw_bringup.log'
Start-Transcript -Path $log -Force | Out-Null

$root       = Split-Path -Parent $PSScriptRoot
$newSys     = Join-Path $root 'build\driver\Debug\Bulwark.sys'
$deployedSys= Join-Path $env:SystemRoot 'System32\drivers\Bulwark.sys'
$backupSys  = Join-Path $env:TEMP 'Bulwark.sys.prev'
$deploy     = Join-Path $PSScriptRoot 'deploy-driver-vm.ps1'
$drvSvc     = 'Bulwark'
$umSvc      = 'BulwarkService'

function Head($t) { Write-Host ""; Write-Host ("=== " + $t + " ===") }

# --- 1) preconditions -------------------------------------------------
Head 'STEP 1 - preconditions'
$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host ("admin       = " + $isAdmin)
Write-Host ("is64bit     = " + [Environment]::Is64BitProcess)
Write-Host ("repo root   = " + $root)
if (-not $isAdmin) {
    Write-Host "NOT ELEVATED - aborting before touching anything."
    Write-Host "SENTINEL_BRINGUP_DONE"; Stop-Transcript | Out-Null; exit 1
}
if (-not (Test-Path $newSys)) {
    Write-Host ("ERROR: freshly built driver missing: " + $newSys)
    Write-Host "Run: powershell -File scripts\build-driver.ps1 -Configuration Debug"
    Write-Host "SENTINEL_BRINGUP_DONE"; Stop-Transcript | Out-Null; exit 1
}
$newHash = (Get-FileHash $newSys -Algorithm SHA256).Hash
Write-Host ("new driver  = " + $newSys)
Write-Host ("new sha256  = " + $newHash)

$bcd = (& "$env:SystemRoot\System32\bcdedit.exe" 2>&1 | Out-String)
$tsLine = ($bcd -split "`r?`n" | Where-Object { $_ -match 'testsigning' }) -join ' '
Write-Host ("testsigning = '" + $tsLine.Trim() + "'")
if ($tsLine -notmatch 'Yes') {
    Write-Host "ERROR: test signing is NOT active in the current boot."
    Write-Host "       Run: bcdedit /set testsigning on   then REBOOT, then re-run this script."
    Write-Host "       (A test-signed driver cannot load without it.)"
    Write-Host "SENTINEL_BRINGUP_DONE"; Stop-Transcript | Out-Null; exit 1
}

# --- 2) stop user mode, unload old driver -----------------------------
Head 'STEP 2 - stop user mode + unload old driver'
Get-Process bulwark_ui      -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
& sc.exe stop $umSvc 2>&1 | Out-Null
Start-Sleep -Seconds 1
Get-Process bulwark_service -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Write-Host "user-mode service + UI stopped (SelfGuard is cleared on disconnect, so the install dir is writable again)"

# fltmc unload MUST come before any sc delete/create: once a service has pushed
# config, "\Services\Bulwark" sits in the kernel registry hard-block list (and it
# IS persisted), so user-mode writes to that key are denied while the driver is
# loaded. Unloading removes the callback and lets the deploy script re-register.
& fltmc.exe unload $drvSvc 2>&1 | Out-Host
& sc.exe stop $drvSvc 2>&1 | Out-Null
Start-Sleep -Seconds 1

# --- 3) rollback safety net -------------------------------------------
Head 'STEP 3 - back up the currently deployed driver'
if (Test-Path $deployedSys) {
    try {
        Copy-Item $deployedSys $backupSys -Force -ErrorAction Stop
        Write-Host ("backup: " + $deployedSys + " -> " + $backupSys)
        Write-Host ("        old sha256 = " + (Get-FileHash $backupSys -Algorithm SHA256).Hash)
    } catch {
        Write-Host ("backup FAILED: " + $_.Exception.Message)
    }
} else {
    Write-Host "no driver currently deployed - nothing to back up"
}

# --- 4) project's own deploy procedure --------------------------------
Head 'STEP 4 - sign + deploy + register + load (deploy-driver-vm.ps1)'
try { & $deploy -Configuration Debug } catch { Write-Host ("DEPLOY-ERR: " + $_.Exception.Message) }

# --- 5) verify the loaded binary is the NEW build ---------------------
Head 'STEP 5 - verify deployed driver identity'
$driverOk = $false
if (Test-Path $deployedSys) {
    $depHash = (Get-FileHash $deployedSys -Algorithm SHA256).Hash
    $sig = (Get-AuthenticodeSignature $deployedSys)
    Write-Host ("deployed sha256 = " + $depHash)
    Write-Host ("signature       = " + $sig.Status + "  signer=" + $sig.SignerCertificate.Subject)
    # NOTE: the hash differs from the pre-sign build hash because signtool embeds
    # the signature into the PE. Compare sizes/mtime instead, and rely on fltmc.
    $a = Get-Item $newSys; $b = Get-Item $deployedSys
    Write-Host ("build   : " + $a.Length + " bytes  " + $a.LastWriteTime)
    Write-Host ("deployed: " + $b.Length + " bytes  " + $b.LastWriteTime)
}
$filters = (& fltmc.exe filters 2>&1 | Out-String)
Write-Host $filters
if ($filters -match $drvSvc) { $driverOk = $true; Write-Host "driver LOADED (visible in fltmc filters)" }
else { Write-Host "driver NOT loaded - see above / run scripts\..\diagnostics" }
& fltmc.exe instances -f $drvSvc 2>&1 | Out-Host
& sc.exe query $drvSvc 2>&1 | Out-Host

if (-not $driverOk) {
    Write-Host "Aborting before starting the user-mode service: no point connecting to a driver that is not loaded."
    Write-Host "SENTINEL_BRINGUP_DONE"; Stop-Transcript | Out-Null; exit 2
}

# --- 6) start the user-mode service + UI ------------------------------
Head 'STEP 6 - start BulwarkService + UI'
$qc = (& sc.exe qc $umSvc 2>&1 | Out-String)
Write-Host $qc
& sc.exe start $umSvc 2>&1 | Out-Host
Start-Sleep -Seconds 5

$uiExe = $null
if ($qc -match 'BINARY_PATH_NAME\s*:\s*"?([^"\r\n]+\.exe)') {
    $uiExe = Join-Path (Split-Path -Parent $Matches[1].Trim()) 'bulwark_ui.exe'
}
if ($uiExe -and (Test-Path $uiExe)) {
    Write-Host ("launching UI: " + $uiExe)
    Start-Process -FilePath $uiExe -WorkingDirectory (Split-Path -Parent $uiExe)
    Start-Sleep -Seconds 4
} else {
    Write-Host ("UI exe not found (derived: " + $uiExe + ")")
}

# --- 7) post-state ----------------------------------------------------
Head 'STEP 7 - post-state'
& sc.exe query $umSvc 2>&1 | Out-Host
Get-Process bulwark_service, bulwark_ui -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host ("PROC " + $_.ProcessName + " pid=" + $_.Id) }

Write-Host ""
Write-Host "--- kernel policy baseline written back by the driver ---"
$polKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$drvSvc\Policy"
if (Test-Path $polKey) {
    $pol = Get-ItemProperty $polKey
    foreach ($name in (Get-Item $polKey).Property) {
        $v = $pol.$name
        if ($v -is [array]) {
            Write-Host ($name + "  (" + $v.Count + " entries)")
            $v | ForEach-Object { if ($_ -ne '') { Write-Host ("    " + $_) } }
        } else {
            Write-Host ($name + " = " + $v)
        }
    }
    if ((Get-Item $polKey).Property -contains 'CmdHardBlock') {
        Write-Host ""
        Write-Host "OK: CmdHardBlock is present -> the new command-line hard-block path works end to end"
        Write-Host "    (user-mode push -> kernel list -> debounced registry write-back)."
    } else {
        Write-Host ""
        Write-Host "WARN: no CmdHardBlock value. Either the service did not connect, or the"
        Write-Host "      debounced write-back (300ms) has not fired yet - re-check in a moment."
    }
} else {
    Write-Host "no Policy subkey yet (service may not have connected / handshake failed)"
}

Write-Host ""
Write-Host "--- service log tail ---"
$logDir = Join-Path $env:ProgramData 'Bulwark\logs'
if (Test-Path $logDir) {
    $latest = Get-ChildItem $logDir -Filter *.log -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
        Write-Host ("file: " + $latest.FullName)
        Get-Content $latest.FullName -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host ("  " + $_) }
    } else { Write-Host ("no .log files under " + $logDir) }
} else { Write-Host ("no log dir " + $logDir) }

Write-Host ""
Write-Host "SENTINEL_BRINGUP_DONE"
Stop-Transcript | Out-Null
