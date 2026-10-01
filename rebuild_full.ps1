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

        # ---- 4b. appsettings drift check --------------------------------
        #
        # Only the two .exe files are deployed here, on purpose: cpp\dist\appsettings.json
        # is the LIVE config of the installed service and overwriting it would silently
        # discard whatever the operator tuned there.
        #
        # But silence has its own cost, and it already bit us: dist's appsettings.json was
        # six weeks stale and had no "Etw" section at all, so every ETW option had been
        # running on struct defaults -- and a newly added switch simply could not be turned
        # on from the source file no matter how it was edited. The build looked perfectly
        # healthy the whole time. So: do not copy, but do say which keys the freshly built
        # binary knows about that the live config has never heard of.
        $srcCfg  = Join-Path $BuildDir 'service\Release\appsettings.json'
        $liveCfg = Join-Path $DistDir  'appsettings.json'
        if ((Test-Path $srcCfg) -and (Test-Path $liveCfg)) {
            try {
                $a = (Get-Content $srcCfg  -Raw -Encoding UTF8 | ConvertFrom-Json).Bulwark
                $b = (Get-Content $liveCfg -Raw -Encoding UTF8 | ConvertFrom-Json).Bulwark
                $an = @($a.PSObject.Properties.Name | Where-Object { $_ -notlike '_comment*' })
                $bn = @($b.PSObject.Properties.Name)
                $missing = @($an | Where-Object { $bn -notcontains $_ })
                if ($missing.Count) {
                    Write-Host ('  WARNING: cpp\dist\appsettings.json is missing ' +
                                $missing.Count + ' key(s) the new binary reads:') -ForegroundColor Yellow
                    Write-Host ('           ' + ($missing -join ', ')) -ForegroundColor Yellow
                    Write-Host ('           Those fall back to built-in defaults. Merge them by hand' +
                                ' (reference: ' + $srcCfg + ').') -ForegroundColor Yellow
                    Write-Host '           NOTE: the driver self-protects cpp\dist - stop the service and unload the driver before editing.' -ForegroundColor Yellow
                } else {
                    Write-Host '  appsettings: live config knows every key the binary reads' -ForegroundColor Green
                }
            } catch {
                Write-Host ('  appsettings drift check skipped (parse failed): ' + $_.Exception.Message) -ForegroundColor Yellow
            }
        } else {
            Write-Host '  appsettings drift check skipped (one of the files is absent)' -ForegroundColor Gray
        }
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
