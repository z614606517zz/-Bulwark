# =====================================================================
#  Kiro helper: restart the user-mode service only. The kernel driver stays
#  loaded and keeps enforcing throughout (its persisted baseline in
#  \Services\Bulwark\Policy is what makes the gap harmless).
#
#  ASCII-ONLY (PowerShell 5.1 reads UTF-8-without-BOM .ps1 as GBK here).
#  All paths derived at runtime from $PSScriptRoot.
#
#  The UI is deliberately NOT killed: it is in the kernel self-protection PID
#  set, so a Stop-Process from a non-protected caller gets its terminate right
#  stripped anyway. It notices the pipe drop and reconnects on its own within a
#  few seconds, at which point the service re-registers its PID.
# =====================================================================

if (-not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) { & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath; exit $LASTEXITCODE }
}
$ErrorActionPreference = 'Continue'
$env:Path = "$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0;$env:Path"

$log = Join-Path $env:TEMP 'blw_restart.log'
Start-Transcript -Path $log -Force | Out-Null

$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "NOT ELEVATED - aborting."; Write-Host "SENTINEL_RESTART_DONE"; Stop-Transcript | Out-Null; exit 1
}

$root    = Split-Path -Parent $PSScriptRoot
$buildSvc= Join-Path $root 'cpp\build\service\Release\bulwark_service.exe'
$dist    = Join-Path $root 'cpp\dist'
$distSvc = Join-Path $dist 'bulwark_service.exe'
$svcLog  = Join-Path $env:ProgramData 'Bulwark\service.log'
$polKey  = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bulwark\Policy'

function Head($t) { Write-Host ""; Write-Host ("=== " + $t + " ===") }

Head 'STEP 1 - is there a newer build to deploy?'
$needCopy = $false
if (Test-Path $buildSvc) {
    $hb = (Get-FileHash $buildSvc -Algorithm SHA256).Hash
    $hd = if (Test-Path $distSvc) { (Get-FileHash $distSvc -Algorithm SHA256).Hash } else { '(absent)' }
    Write-Host ("  build sha256 = " + $hb)
    Write-Host ("  dist  sha256 = " + $hd)
    $needCopy = ($hb -ne $hd)
    Write-Host ("  deploy needed = " + $needCopy)
} else {
    Write-Host ("  build output missing (" + $buildSvc + ") - restarting the deployed exe as is")
}

Head 'STEP 2 - note the log position so we only read what the restart produces'
$logMarkLines = 0
if (Test-Path $svcLog) {
    $sr = New-Object IO.StreamReader($svcLog, [Text.Encoding]::GetEncoding(936))
    while (-not $sr.EndOfStream) { $null = $sr.ReadLine(); $logMarkLines++ }
    $sr.Close()
}
Write-Host ("  service.log currently has " + $logMarkLines + " lines")

Head 'STEP 3 - stop the service'
& sc.exe stop BulwarkService 2>&1 | Select-String -SimpleMatch 'STATE' | ForEach-Object { Write-Host ("  " + $_.Line.Trim()) }
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 1
    if (((& sc.exe query BulwarkService 2>&1 | Out-String) -match 'STOPPED')) { break }
}
Write-Host ("  waited " + $i + "s")
Get-Process bulwark_service -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host ("  process still alive (pid " + $_.Id + ") - forcing")
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2
& sc.exe query BulwarkService 2>&1 | Select-String -SimpleMatch 'STATE' | ForEach-Object { Write-Host ("  " + $_.Line.Trim()) }
Write-Host "  (kernel SelfGuard is now cleared by design; the driver's persisted"
Write-Host "   baseline - exec-block / no-load / file+reg+cmd hard blocks - stays in force)"

if ($needCopy) {
    Head 'STEP 3b - deploy the newer build (install dir is writable now that the service is down)'
    $ok = $false
    for ($i = 0; $i -lt 5 -and -not $ok; $i++) {
        try { Copy-Item $buildSvc $distSvc -Force -ErrorAction Stop; $ok = $true }
        catch { Write-Host ("  attempt " + ($i+1) + " failed: " + $_.Exception.Message); Start-Sleep -Seconds 2 }
    }
    Write-Host ("  copied = " + $ok)
}

Head 'STEP 4 - start the service'
& sc.exe start BulwarkService 2>&1 | Select-String -SimpleMatch 'STATE' | ForEach-Object { Write-Host ("  " + $_.Line.Trim()) }
Start-Sleep -Seconds 10
$q = (& sc.exe query BulwarkService 2>&1 | Out-String)
$running = $q -match 'RUNNING'
$q -split "`r?`n" | Where-Object { $_ -match 'STATE|PID' } | ForEach-Object { Write-Host ("  " + $_.Trim()) }

Head 'STEP 5 - what the restart logged (driver handshake + config push)'
if (Test-Path $svcLog) {
    $new = @()
    $n = 0
    $sr = New-Object IO.StreamReader($svcLog, [Text.Encoding]::GetEncoding(936))
    while (-not $sr.EndOfStream) { $line = $sr.ReadLine(); $n++; if ($n -gt $logMarkLines) { $new += $line } }
    $sr.Close()
    Write-Host ("  new log lines: " + $new.Count)
    $keep = $new | Where-Object { $_ -match 'Driver|Coordinator|Main|IpcServer|Behavior' }
    $keep | Select-Object -First 30 | ForEach-Object { Write-Host ("  " + $_) }
} else {
    Write-Host ("  no service log at " + $svcLog)
}

Head 'STEP 6 - kernel policy baseline still/again in place'
$cmdList = @()
if (Test-Path $polKey) {
    $v = (Get-ItemProperty $polKey -Name CmdHardBlock -ErrorAction SilentlyContinue).CmdHardBlock
    if ($v) { $cmdList = @($v | Where-Object { $_ -ne '' }) }
}
Write-Host ("  CmdHardBlock entries = " + $cmdList.Count)
$cmdList | ForEach-Object { Write-Host ("    " + $_) }

Head 'STEP 7 - post-state'
& fltmc.exe filters 2>&1 | Select-String -SimpleMatch 'Bulwark' | ForEach-Object { Write-Host ("  fltmc: " + $_.Line.Trim()) }
Get-Process bulwark_service, bulwark_ui -ErrorAction SilentlyContinue |
    Sort-Object ProcessName | ForEach-Object { Write-Host ("  PROC " + $_.ProcessName + " pid=" + $_.Id) }
Write-Host ("  service RUNNING = " + $running)

Head 'STEP 8 - quick smoke test: command-line hard block still enforcing'
$cmd = "$env:SystemRoot\System32\cmd.exe"
function T([string]$label, [string]$cmdline, [string]$expect) {
    try { $null = Start-Process -FilePath $cmd -ArgumentList $cmdline -PassThru -Wait -WindowStyle Hidden -ErrorAction Stop; $got = 'ALLOWED' }
    catch { $got = 'DENIED' }
    $ok = if ($got -eq $expect) { 'PASS' } else { '**FAIL**' }
    Write-Host ("  {0}  {1,-42} expect={2,-8} got={3}" -f $ok, $label, $expect, $got)
}
T 'vssadmin delete shadows'      '/c echo vssadmin delete shadows'    'DENIED'
T 'reg save HKEY_LOCAL_MACHINE\SAM' '/c echo reg save HKEY_LOCAL_MACHINE\SAM x.hiv' 'DENIED'
T 'negative: hello world'        '/c echo hello world'               'ALLOWED'

Write-Host ""
Write-Host "SENTINEL_RESTART_DONE"
Stop-Transcript | Out-Null
