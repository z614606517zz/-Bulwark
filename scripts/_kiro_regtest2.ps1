# =====================================================================
#  Kiro helper: RE-RUN of the registry cases that the first pass got wrong.
#  ASCII-ONLY (PowerShell 5.1 reads UTF-8-without-BOM .ps1 as GBK here).
#
#  Why a re-run: pass 1 fed reg.exe an -ArgumentList ARRAY whose elements
#  contain spaces ("...\Windows NT\..."). PowerShell 5.1 joins the array with
#  spaces and does NOT quote the elements, so reg.exe received a truncated key
#  path and answered "invalid syntax" / "key not found". Those cases therefore
#  proved nothing - two of them scored a FALSE PASS. Here the whole argument
#  string is built by hand with explicit quotes.
#
#  Cases:
#    B  save a benign hive          -> must be ALLOWED (regression)
#    C  create ...\sethc.exe\Debugger KEY -> must be DENIED (new CreateKeyEx)
#    D  set Winlogon\Shell          -> must be DENIED (pre-existing hard block)
#    H  confirm case A was really the kernel: look for the HiveDump event
#
#  All side effects are undone in the same run.
# =====================================================================

if (-not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) { & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath; exit $LASTEXITCODE }
}
$ErrorActionPreference = 'Continue'
$env:Path = "$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0;$env:Path"

$log = Join-Path $env:TEMP 'blw_regtest2.log'
Start-Transcript -Path $log -Force | Out-Null

$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "NOT ELEVATED - aborting."; Write-Host "SENTINEL_REGTEST2_DONE"; Stop-Transcript | Out-Null; exit 1
}

$results = @()
function Rec($id, $what, $expect, $got) {
    $ok = if ($expect -eq $got) { 'PASS' } else { '**FAIL**' }
    $script:results += ("{0}  {1}  {2,-50} expect={3,-7} got={4}" -f $ok, $id, $what, $expect, $got)
}

# Run reg.exe with a hand-quoted single argument string (cmd /c so we get the
# exit code and the message no matter how reg parses it).
function RunReg([string]$argLine) {
    $so = Join-Path $env:TEMP ('_blw2_' + [Guid]::NewGuid().ToString('N') + '.txt')
    $p = Start-Process -FilePath "$env:SystemRoot\System32\reg.exe" -ArgumentList $argLine `
                       -Wait -PassThru -NoNewWindow -RedirectStandardOutput $so -RedirectStandardError ($so + '.err')
    $txt = ''
    foreach ($f in @($so, ($so + '.err'))) {
        if (Test-Path $f) { $txt += (Get-Content $f -Raw -ErrorAction SilentlyContinue); Remove-Item $f -Force -ErrorAction SilentlyContinue }
    }
    return @{ Code = $p.ExitCode; Text = ($txt -replace "`r?`n", ' ').Trim() }
}

$ntVer   = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$ntVerPS = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

Write-Host "=== B) save a BENIGN hive - must still be allowed (regression) ==="
$benign = Join-Path $env:TEMP '_blwtest_benign.hiv'
Remove-Item $benign -Force -ErrorAction SilentlyContinue
# Quote both the key path (has a space) and the output path.
$r = RunReg ('save "' + $ntVer + '\Fonts" "' + $benign + '" /y')
$made = (Test-Path $benign)
Write-Host ("  exit=" + $r.Code + "  file_created=" + $made + "  msg=" + $r.Text)
Rec 'B' 'reg save a benign key (must NOT be blocked)' 'ALLOWED' $(if ($r.Code -eq 0) { 'ALLOWED' } else { 'DENIED' })
Remove-Item $benign -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== C) create ...\Image File Execution Options\sethc.exe\Debugger as a KEY ==="
$ifeoParentPS = $ntVerPS + '\Image File Execution Options\sethc.exe'
$parentPreexisted = Test-Path $ifeoParentPS
Write-Host ("  sethc.exe IFEO key existed beforehand = " + $parentPreexisted)
$dbgKey = $ntVer + '\Image File Execution Options\sethc.exe\Debugger'
$r = RunReg ('add "' + $dbgKey + '" /f')
$dbgExists = Test-Path ($ifeoParentPS + '\Debugger')
Write-Host ("  exit=" + $r.Code + "  Debugger_key_exists=" + $dbgExists + "  msg=" + $r.Text)
Rec 'C' 'create KEY ...sethc.exe\Debugger (new CreateKeyEx)' 'DENIED' $(if ($r.Code -eq 0 -and $dbgExists) { 'ALLOWED' } else { 'DENIED' })
if ($dbgExists) {
    Write-Host "  cleanup: removing the Debugger key that got created"
    RunReg ('delete "' + $dbgKey + '" /f') | Out-Null
}
if (-not $parentPreexisted -and (Test-Path $ifeoParentPS)) {
    Write-Host "  cleanup: removing the sethc.exe IFEO key we created as a side effect"
    RunReg ('delete "' + $ntVer + '\Image File Execution Options\sethc.exe" /f') | Out-Null
}

Write-Host ""
Write-Host "=== D) set Winlogon\Shell (writing back the value it already has) ==="
$cur = (Get-ItemProperty ($ntVerPS + '\Winlogon') -Name Shell -ErrorAction SilentlyContinue).Shell
Write-Host ("  current Shell value = '" + $cur + "'")
$val = if ([string]::IsNullOrEmpty($cur)) { 'explorer.exe' } else { $cur }
$r = RunReg ('add "' + $ntVer + '\Winlogon" /v Shell /t REG_SZ /d "' + $val + '" /f')
Write-Host ("  exit=" + $r.Code + "  msg=" + $r.Text)
Rec 'D' 'set Winlogon\Shell (pre-existing hard block)' 'DENIED' $(if ($r.Code -eq 0) { 'ALLOWED' } else { 'DENIED' })
$after = (Get-ItemProperty ($ntVerPS + '\Winlogon') -Name Shell -ErrorAction SilentlyContinue).Shell
Write-Host ("  Shell value after  = '" + $after + "'  (unchanged=" + ($after -eq $cur) + ")")

Write-Host ""
Write-Host "=== H) was case A really the kernel? look for the HiveDump event ==="
$hist = Join-Path $env:ProgramData 'Bulwark\history\events.jsonl'
if (Test-Path $hist) {
    $hits = @()
    $sr = New-Object IO.StreamReader($hist, [Text.Encoding]::UTF8)
    while (-not $sr.EndOfStream) {
        $line = $sr.ReadLine()
        if ($line -and $line.Contains('hive')) { $hits += $line }
    }
    $sr.Close()
    Write-Host ("  matching history records: " + $hits.Count)
    foreach ($h in ($hits | Select-Object -Last 2)) {
        try {
            $j = $h | ConvertFrom-Json
            Write-Host ("    detail        = " + $j.event.detail)
            Write-Host ("    target        = " + $j.event.target)
            Write-Host ("    actorPath     = " + $j.event.actorPath)
            Write-Host ("    kernelBlocked = " + $j.event.kernelBlocked)
            Write-Host ("    type          = " + $j.event.type)
        } catch { Write-Host ("    (unparsable) " + $h.Substring(0, [Math]::Min(200, $h.Length))) }
    }
    Rec 'H' 'kernel reported a HiveDump block event' 'FOUND' $(if ($hits.Count -gt 0) { 'FOUND' } else { 'MISSING' })
} else {
    Write-Host ("  no history file at " + $hist)
    Rec 'H' 'kernel reported a HiveDump block event' 'FOUND' 'MISSING'
}

Write-Host ""
Write-Host "==================== SUMMARY (re-run) ===================="
$results | ForEach-Object { Write-Host $_ }
Write-Host ("passed " + (@($results | Where-Object { $_.StartsWith('PASS') }).Count) + " / " + $results.Count)

Write-Host ""
Write-Host "SENTINEL_REGTEST2_DONE"
Stop-Transcript | Out-Null
