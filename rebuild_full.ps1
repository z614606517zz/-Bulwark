# =====================================================================
#  Full rebuild + redeploy of Bulwark, with protection restored no
#  matter how the build ends.
#
#  WHY THE DRIVER MUST GO DOWN FIRST:
#    The kernel baseline keeps \WINDOWS\SYSTEM32\CMD.EXE in FileExecBlock.
#    MSBuild shells out to cmd.exe for custom build steps (Qt autogen), so
#    while the minifilter is loaded the project cannot be built at all
#    (error MSB6003 / Win32Exception 0x80004005 Access denied).
#
#  ASCII-ONLY ON PURPOSE: Windows PowerShell 5.1 reads UTF-8-without-BOM
#  .ps1 as ANSI/GBK on a Chinese Windows, which corrupts non-ASCII string
#  literals. Same reason scripts\_kiro_stop_driver.ps1 is ASCII-only.
#
#  The driver is left RUNNING again in the finally block even if the
#  build throws, so the protection window stays as short as possible.
# =====================================================================
$ErrorActionPreference = 'Continue'

$Root     = 'D:\xxx'                      # placeholder, replaced below
$Root     = $PSScriptRoot
$BuildDir = Join-Path $Root 'cpp\build'
$DistDir  = Join-Path $Root 'cpp\dist'
$StopDrv  = Join-Path $Root 'scripts\_kiro_stop_driver.ps1'
$LogPath  = Join-Path $env:TEMP 'blw_rebuild_full.log'

try { Stop-Transcript | Out-Null } catch { }
Start-Transcript -Path $LogPath -Force | Out-Null

function Step($n, $m) { Write-Host "[$n] $m" -ForegroundColor Cyan }
function DriverState {
    if ((& sc.exe query Bulwark 2>&1 | Out-String) -match 'RUNNING') { 'RUNNING' }
    elseif ((& sc.exe query Bulwark 2>&1 | Out-String) -match 'STOPPED') { 'STOPPED' }
    else { 'UNKNOWN' }
}
function CmdRunnable {
    try {
        $p = Start-Process cmd.exe -ArgumentList '/c','exit' -PassThru -WindowStyle Hidden -ErrorAction Stop
        $p.WaitForExit(5000) | Out-Null
        return $true
    } catch { return $false }
}

$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole(
          [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'NOT ELEVATED - aborting.' -ForegroundColor Red
    Stop-Transcript | Out-Null
    exit 1
}

Write-Host '=== Bulwark full rebuild ===' -ForegroundColor Yellow
Write-Host ("driver before = " + (DriverState))
$buildOk  = $false
$builtExe = Join-Path $BuildDir 'service\Release\bulwark_service.exe'
$builtUi  = Join-Path $BuildDir 'ui\Release\bulwark_ui.exe'

try {
    # ---- 1. drop user mode + unload the minifilter -------------------
    Step 1 'stopping UI / service / driver (project-sanctioned order)'
    if (Test-Path $StopDrv) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $StopDrv
        Write-Host ('  stop script exit = ' + $LASTEXITCODE)
    } else {
        Write-Host '  stop script missing - doing it inline' -ForegroundColor Yellow
        Get-Process bulwark_ui -ErrorAction SilentlyContinue | Stop-Process -Force
        & sc.exe stop BulwarkService | Out-Null
        Start-Sleep 2
        Get-Process bulwark_service -ErrorAction SilentlyContinue | Stop-Process -Force
        & fltmc.exe unload Bulwark  | Out-Null
        & sc.exe   stop   Bulwark   | Out-Null
        Start-Sleep 3
    }
    Write-Host ("  driver now = " + (DriverState))

    # ---- 2. the build is impossible unless cmd.exe is runnable -------
    Step 2 'verifying cmd.exe is runnable (MSBuild needs it)'
    if (-not (CmdRunnable)) {
        throw 'cmd.exe still blocked - the minifilter did not unload; aborting before wasting a build.'
    }
    Write-Host '  cmd.exe OK' -ForegroundColor Green

    # ---- 3. full build ----------------------------------------------
    Step 3 'cmake --build (all targets, Release)'
    Push-Location $BuildDir
    & cmake --build . --config Release 2>&1 | Tee-Object -Variable buildOut | Out-Null
    $code = $LASTEXITCODE
    Pop-Location
    Write-Host ("  cmake exit = " + $code)

    $errLines = @($buildOut | Where-Object { $_ -match 'error [A-Z]+\d+|MSB\d+|FAILED' })
    if ($errLines.Count) {
        Write-Host '  --- build errors ---' -ForegroundColor Red
        $errLines | Select-Object -First 25 | ForEach-Object { Write-Host ("  " + $_) }
    }
    $warn = @($buildOut | Where-Object { $_ -match 'warning [A-Z]+\d+' })
    Write-Host ("  warnings = " + $warn.Count)

    if ($code -eq 0 -and (Test-Path $builtExe)) { $buildOk = $true }

    # ---- 4. deploy ---------------------------------------------------
    if ($buildOk) {
        Step 4 'deploying to cpp\dist'
        Copy-Item $builtExe (Join-Path $DistDir 'bulwark_service.exe') -Force
        Write-Host ('  bulwark_service.exe -> dist  ' +
                    (Get-Item (Join-Path $DistDir 'bulwark_service.exe')).LastWriteTime)
        if (Test-Path $builtUi) {
            Copy-Item $builtUi (Join-Path $DistDir 'bulwark_ui.exe') -Force
            Write-Host ('  bulwark_ui.exe      -> dist  ' +
                        (Get-Item (Join-Path $DistDir 'bulwark_ui.exe')).LastWriteTime)
        } else {
            Write-Host '  bulwark_ui.exe not built (service-only change) - dist copy kept' -ForegroundColor Gray
        }
    } else {
        Step 4 'SKIPPED deploy - build did not succeed; dist left untouched'
    }
}
finally {
    # ---- 5. protection back up, build outcome regardless ------------
    Step 5 'restarting service (this reloads the minifilter)'
    & sc.exe start BulwarkService | Out-Null
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        if ((Get-Service BulwarkService).Status -eq 'Running') { break }
    }
    Start-Sleep -Seconds 4
    $svc = (Get-Service BulwarkService).Status
    $drv = DriverState
    Write-Host ''
    Write-Host '=== final state ===' -ForegroundColor Yellow
    Write-Host ("  build succeeded = " + $buildOk)
    Write-Host ("  BulwarkService  = " + $svc)
    Write-Host ("  Bulwark driver  = " + $drv)
    Write-Host ("  cmd.exe blocked again = " + (-not (CmdRunnable)))
    if ($svc -ne 'Running' -or $drv -ne 'RUNNING') {
        Write-Host '  WARNING: protection is NOT fully back up - investigate.' -ForegroundColor Red
    } else {
        Write-Host '  protection restored.' -ForegroundColor Green
    }
    Stop-Transcript | Out-Null
}
