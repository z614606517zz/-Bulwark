# =====================================================================
#  Bulwark one-click dev launcher:
#    compile (service + ui + kernel driver) -> deploy to cpp\dist
#    -> install & start BulwarkService -> load the kernel driver -> open the UI
#
#  Self-elevates (service install + driver load need admin). Run it via the
#  repo-root "一键启动.bat" or:
#     powershell -ExecutionPolicy Bypass -File cpp\scripts\dev-all.ps1
#
#  Options:
#    -SkipDriver     don't build/load the kernel driver (user-mode ETW only)
#    -SkipBuild      skip compiling; just (re)deploy + start what's in build_pkg
#    -Configuration  Release (default) | Debug   (service/ui)
#
#  NOTE: messages are intentionally ASCII-only. PowerShell 5.1 misreads a
#  non-BOM UTF-8 script as GBK and can corrupt string/path literals (see the
#  warning in cpp\.tools\build.ps1). All paths are derived at runtime.
#
#  WARNING: loading the kernel driver flips test-signing ON (needs one reboot)
#  and loads Bulwark.sys. A faulty kernel callback can BSOD. Prefer a VM with a
#  snapshot for first runs. Use -SkipDriver to stay in safe user-mode mode.
# =====================================================================
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')] [string]$Configuration = 'Release',
    [ValidateSet('Debug', 'Release')] [string]$DriverConfiguration = 'Debug',
    [switch]$SkipDriver,
    [switch]$SkipBuild,
    [string]$QtDir = 'C:\Qt\6.8.3\msvc2022_64',
    [string]$CMake = 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
)
$ErrorActionPreference = 'Stop'

function Step($n, $msg) { Write-Host "`n==== [$n/6] $msg ====" -ForegroundColor Cyan }
function Warn($msg)      { Write-Host "  ! $msg" -ForegroundColor Yellow }
function Info($msg)      { Write-Host "  - $msg" -ForegroundColor DarkGray }

# ---- resolve repo layout from the script's own location --------------------
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$cppDir  = Split-Path -Parent $scriptDir          # <repo>\cpp
$repo    = Split-Path -Parent $cppDir             # <repo>
$distDir = Join-Path $cppDir 'dist'
$svcName = 'BulwarkService'

# ---- self-elevate (needs admin for service install + driver load) ----------
$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host 'Elevating (service install / driver load need admin)...' -ForegroundColor Yellow
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
        '-Configuration', $Configuration, '-DriverConfiguration', $DriverConfiguration)
    if ($SkipDriver) { $a += '-SkipDriver' }
    if ($SkipBuild) { $a += '-SkipBuild' }
    Start-Process powershell -Verb RunAs -ArgumentList $a
    return
}

Write-Host "Bulwark dev launcher  (config=$Configuration  driver=$DriverConfiguration  skipDriver=$SkipDriver)" -ForegroundColor White
$realBuildDir = Join-Path $cppDir 'build_pkg'
$svcExe = Join-Path $realBuildDir "service\$Configuration\bulwark_service.exe"
$uiExe  = Join-Path $realBuildDir "ui\$Configuration\bulwark_ui.exe"

try {
    # ================= 1) COMPILE service + ui =================
    if ($SkipBuild) {
        Step 1 'Compile service + ui  (SKIPPED)'
    }
    else {
        Step 1 "Compile service + ui ($Configuration)"
        # CMake crashes when reconfiguring under a non-ASCII path; map the repo to
        # a free ASCII drive and build through it (as cpp\scripts\package.ps1 does).
        $srcCpp = $cppDir
        $mapped = $null
        if ($repo -match '[^\u0000-\u007F]') {
            $letter = @('X:', 'Y:', 'W:', 'V:', 'T:', 'B:') | Where-Object { -not (Test-Path $_) } | Select-Object -First 1
            if (-not $letter) { throw 'No free drive letter available for subst.' }
            subst $letter $repo | Out-Null
            $mapped = $letter
            $srcCpp = Join-Path $letter (Split-Path -Leaf $cppDir)
            Info "Mapped $letter -> $repo (ASCII build path)"
        }
        try {
            $bd = Join-Path $srcCpp 'build_pkg'
            $pfx = "-DCMAKE_PREFIX_PATH=$($QtDir -replace '\\','/')"
            & $CMake -G 'Visual Studio 17 2022' -A x64 -S $srcCpp -B $bd $pfx
            if ($LASTEXITCODE -ne 0) {
                Warn 'Configure failed (likely the in-place reconfigure crash); wiping and retrying clean.'
                Remove-Item -Recurse -Force $bd -ErrorAction SilentlyContinue
                & $CMake -G 'Visual Studio 17 2022' -A x64 -S $srcCpp -B $bd $pfx
                if ($LASTEXITCODE -ne 0) { throw "CMake configure failed ($LASTEXITCODE)" }
            }
            & $CMake --build $bd --config $Configuration --target bulwark_service bulwark_ui
            if ($LASTEXITCODE -ne 0) { throw "Build failed ($LASTEXITCODE)" }
        }
        finally {
            if ($mapped) { subst $mapped /d | Out-Null; Info "Unmapped $mapped" }
        }
    }
    if (-not (Test-Path $svcExe)) { throw "Missing build output: $svcExe (run without -SkipBuild)" }
    if (-not (Test-Path $uiExe))  { throw "Missing build output: $uiExe (run without -SkipBuild)" }

    # ================= 2) COMPILE kernel driver (best-effort) =================
    $sysPath = Join-Path $repo "build\driver\$DriverConfiguration\Bulwark.sys"
    if ($SkipDriver) {
        Step 2 'Compile kernel driver  (SKIPPED -SkipDriver)'
    }
    else {
        Step 2 "Compile kernel driver ($DriverConfiguration, needs WDK)"
        try {
            & (Join-Path $repo 'scripts\build-driver.ps1') -Configuration $DriverConfiguration
            if ($LASTEXITCODE -ne 0) { throw "MSBuild returned $LASTEXITCODE" }
        }
        catch {
            Warn "Driver build skipped/failed: $($_.Exception.Message)"
            Info 'Normal if WDK is absent. The app still runs via user-mode ETW.'
        }
    }

    # ================= 3) DEPLOY to dist =================
    Step 3 'Deploy to cpp\dist (stop UI/service -> copy exes -> keep config + Qt)'
    Get-Process bulwark_ui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $svc = Get-Service $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        & sc.exe stop $svcName | Out-Null
        for ($i = 0; $i -lt 30; $i++) {
            if ((sc.exe query $svcName | Out-String) -match 'STOPPED') { break }
            Start-Sleep -Milliseconds 500
        }
    }
    Get-Process bulwark_service -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800

    New-Item -ItemType Directory -Force -Path $distDir | Out-Null
    Copy-Item $svcExe $distDir -Force
    Copy-Item $uiExe  $distDir -Force
    Info 'Copied bulwark_service.exe + bulwark_ui.exe'

    # Keep dist's appsettings.json (holds the user's API keys); seed only if absent.
    $distSettings = Join-Path $distDir 'appsettings.json'
    if (-not (Test-Path $distSettings)) {
        Copy-Item (Join-Path $cppDir 'service\appsettings.json') $distSettings -Force
        Info 'Seeded appsettings.json from cpp\service (no keys)'
    }
    else { Info 'Preserved existing dist\appsettings.json (API keys kept)' }

    # Qt runtime: only run windeployqt if it isn't already there.
    if (-not (Test-Path (Join-Path $distDir 'Qt6Core.dll'))) {
        $wd = Join-Path $QtDir 'bin\windeployqt.exe'
        if (Test-Path $wd) {
            Info 'Collecting Qt runtime via windeployqt...'
            $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
            & $wd --release --no-translations (Join-Path $distDir 'bulwark_service.exe') 2>&1 | Out-Null
            & $wd --release --no-translations (Join-Path $distDir 'bulwark_ui.exe') 2>&1 | Out-Null
            $ErrorActionPreference = $prev
        }
        else { Warn "windeployqt not found and dist has no Qt runtime; the UI may fail to start." }
    }
    else { Info 'Qt runtime already present in dist' }

    # ================= 4) INSTALL + START service =================
    Step 4 "Install + start $svcName"
    $svc = Get-Service $svcName -ErrorAction SilentlyContinue
    if (-not $svc) {
        & (Join-Path $distDir 'bulwark_service.exe') --install | Out-Host
        Start-Sleep -Seconds 1
    }
    & sc.exe start $svcName | Out-Null
    Start-Sleep -Milliseconds 800
    $state = (sc.exe query $svcName | Select-String 'STATE').Line.Trim()
    Info "Service: $state"

    # ================= 5) LOAD kernel driver =================
    if ($SkipDriver) {
        Step 5 'Load kernel driver  (SKIPPED -SkipDriver)'
    }
    else {
        Step 5 'Load kernel driver (test-sign + register minifilter + load)'
        Write-Host '  ! WARNING: a faulty kernel callback can BSOD. Prefer a snapshotted VM.' -ForegroundColor Red
        if (Test-Path $sysPath) {
            # deploy-driver-vm.ps1 checks test-signing (enables + asks for a reboot
            # if off), makes/trusts a test cert, signs, registers the minifilter,
            # and loads it. If it enables test-signing it returns asking to reboot;
            # the service/UI still run in ETW mode until then.
            & (Join-Path $repo 'scripts\deploy-driver-vm.ps1') -Configuration $DriverConfiguration
        }
        else {
            Warn "Bulwark.sys not found ($sysPath); skipping driver load. Running user-mode ETW."
        }
    }

    # ================= 6) LAUNCH UI =================
    Step 6 'Launch UI'
    Start-Process -FilePath (Join-Path $distDir 'bulwark_ui.exe') -WorkingDirectory $distDir
    Info 'UI launched (already elevated, no extra UAC).'

    Write-Host "`nDone. Service + UI are up." -ForegroundColor Green
    if (-not $SkipDriver) {
        Write-Host 'If the driver step asked for a reboot, reboot once and re-run to load Bulwark.sys.' -ForegroundColor DarkGray
    }
}
catch {
    Write-Host "`nFAILED: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    Write-Host ''
    Read-Host 'Press Enter to close this window'
}
