# ASCII-only on purpose: Windows PowerShell reads UTF-8-without-BOM scripts as ANSI, which
# corrupts non-ASCII path literals. All paths are derived at runtime from $PSScriptRoot.
#
# Elevated helper:
#   1) back up the currently deployed (known-good) Bulwark.sys so rollback is one copy
#   2) run the project's own deploy-driver-vm.ps1 (test-sign + copy + register as MINIFILTER + load)
#   3) dump post-state so it can be verified
# Everything is transcripted to an ASCII log path.

# Must run 64-bit: bcdedit/fltmc/sc/signtool live in System32 and get WOW64-redirected away under a
# 32-bit host. Relaunch under native 64-bit PowerShell (inherits the elevated token) if needed.
if (-not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }
}

$ErrorActionPreference = 'Continue'
$env:Path = "$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0;$env:Path"

$log = 'C:\Users\111\AppData\Local\Temp\blw_load.log'
Start-Transcript -Path $log -Force | Out-Null

$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "=== PRE ==="
Write-Host ("admin = " + $isAdmin + "   is64 = " + [Environment]::Is64BitProcess)
if (-not $isAdmin) {
    Write-Host "NOT ELEVATED - aborting before touching anything."
    Write-Host "SENTINEL_LOAD_DONE"
    Stop-Transcript | Out-Null
    exit 1
}

# --- 1) Back up the currently deployed driver (rollback safety net) ---------------------
$dst = Join-Path $env:SystemRoot 'System32\drivers\Bulwark.sys'
$bak = 'C:\Users\111\AppData\Local\Temp\Bulwark.sys.prev'
if (Test-Path $dst) {
    try {
        Copy-Item $dst $bak -Force
        Write-Host ("[backup] " + $dst + " -> " + $bak + " (" + (Get-Item $bak).Length + " bytes)")
    } catch {
        Write-Host ("[backup] FAILED: " + $_.Exception.Message)
    }
} else {
    Write-Host "[backup] no driver currently deployed"
}

# --- 2) Project's own procedure -------------------------------------------------------
$deploy = Join-Path $PSScriptRoot 'deploy-driver-vm.ps1'
Write-Host ("=== running " + $deploy + " -Configuration Debug ===")
try {
    & $deploy -Configuration Debug
} catch {
    Write-Host ("DEPLOY-ERR: " + $_.Exception.Message)
}

# --- 3) Post-state --------------------------------------------------------------------
Write-Host "=== POST-STATE ==="
& fltmc.exe filters   2>&1 | Out-Host
& fltmc.exe instances -f Bulwark 2>&1 | Out-Host
& sc.exe query Bulwark 2>&1 | Out-Host
if (Test-Path $dst) {
    $i = Get-Item $dst
    Write-Host ("deployed: " + $i.Length + " bytes  mtime=" + $i.LastWriteTime +
                "  sig=" + (Get-AuthenticodeSignature $dst).Status)
}
Write-Host "SENTINEL_LOAD_DONE"
Stop-Transcript | Out-Null
