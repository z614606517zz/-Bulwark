<#
================================================================================
  Bulwark harmless self-test sample
================================================================================

  PURPOSE
  -------
  Verify, against the LIVE running Bulwark service on this machine, that the
  detection chain actually works end to end:
    ETW observe -> enrich (signature / command line) -> rule engine match
    -> verdict -> enforcement -> persisted audit log.

  This is NOT malware. Everything it does is harmless:
    * It launches a batch of DISPOSABLE child processes whose COMMAND LINE
      contains the signature strings of known attack tools/commands
      (mimikatz / cobaltstrike / sharphound ...). Those strings are only
      printed by `echo`; they are never executed. Echoing text has no effect.
    * It creates a 0-byte file %TEMP%\amsdk.sys (a vulnerable-driver name that
      Bulwark blocks). An empty file is harmless.
    * It writes ONE reversible test value under HKCU Run, then deletes it.

  Every trigger runs as its OWN top-level process, so when the service kills a
  trigger's process tree it only touches that disposable process -- never this
  script or anything else. Command-line triggers are hosted by signed cmd.exe,
  which the rules only terminate (not kernel-blocklist), so it is repeatable.

  It cleans up every artifact afterwards (empty file / registry value) and
  prints a table: each trigger -> actual verdict -> matched rule -> PASS/MISS.

  USAGE
  -----
    powershell -ExecutionPolicy Bypass -File .\Invoke-BulwarkSelfTest.ps1
    powershell ... -File .\Invoke-BulwarkSelfTest.ps1 -SettleSeconds 12 -KeepArtifacts

  PARAMETERS
  ----------
    -SettleSeconds : seconds to wait after firing for the service to persist
                     verdicts (default 10).
    -KeepArtifacts : do not clean up produced artifacts (for manual review).
    -DataDir       : override for %ProgramData%\Bulwark.

  NOTE: This is a defensive self-test tool. Run it only on a machine you own or
  are authorized to test that has Bulwark installed.
================================================================================
#>

[CmdletBinding()]
param(
    [int]    $SettleSeconds = 10,
    [switch] $KeepArtifacts,
    [string] $DataDir = (Join-Path $env:ProgramData 'Bulwark')
)

$ErrorActionPreference = 'Stop'
$script:RunId = 'BWST-' + (Get-Date -Format 'yyyyMMdd-HHmmss')

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

# Read a file that the service may hold open for append, using shared read.
function Read-LockedText([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
            try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
        } finally { $fs.Dispose() }
    } catch { return '' }
}

# Collect all audit verdicts recorded since $StartUtc (action/type/actorPid/target/reasons).
function Get-AuditSince([datetime]$StartUtc) {
    $auditDir = Join-Path $DataDir 'audit'
    $out = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $auditDir)) { return $out }
    $files = Get-ChildItem -LiteralPath $auditDir -Filter 'audit-*.jsonl' | Where-Object { $_.LastWriteTime -ge $StartUtc.ToLocalTime().AddMinutes(-5) }
    foreach ($f in $files) {
        $text = Read-LockedText $f.FullName
        if (-not $text) { continue }
        foreach ($line in ($text -split "`r?`n")) {
            if ($line.Trim().Length -eq 0) { continue }
            try { $o = $line | ConvertFrom-Json } catch { continue }
            if (-not $o.timestampUtc) { continue }
            $ts = $null
            try { $ts = [datetimeoffset]::Parse($o.timestampUtc).UtcDateTime } catch { continue }
            if ($ts -ge $StartUtc.AddSeconds(-2)) { $out.Add($o) }
        }
    }
    return $out
}

# A trigger definition. Token is the detected signature string; it is only
# echoed/commented, never executed.
function New-Case($Id,$Category,$Technique,$Expected,$Kind,$Token) {
    [pscustomobject]@{
        Id=$Id; Category=$Category; Technique=$Technique; Expected=$Expected
        Kind=$Kind; Token=$Token; Pid=$null; Detected='None'; Rule=''; Pass=$false
    }
}

# ---- Trigger list: 6 tactic categories, 3 event dimensions (proc/file/reg) ----
$cases = @(
    # Credential access (Rules04) -- command-line signature, printed by echo, not run
    (New-Case  1 'CredAccess'  'T1003.001' 'Block' 'proc' 'invoke-mimikatz'),
    (New-Case  2 'CredAccess'  'T1003.001' 'Block' 'proc' 'sekurlsa logonpasswords'),
    (New-Case  3 'CredAccess'  'T1003.001' 'Block' 'proc' 'comsvcs.dll MiniDump lsass'),
    (New-Case  4 'CredAccess'  'T1003.006' 'Block' 'proc' 'dcsync'),
    # Lateral movement / remote control / C2 (Rules08)
    (New-Case  5 'C2'          'T1219'     'Block' 'proc' 'cobaltstrike beacon'),
    (New-Case  6 'Recon'       'T1087'     'Block' 'proc' 'sharphound'),
    (New-Case  7 'RevShell'    'T1059.001' 'Block' 'proc' 'net.sockets.tcpclient'),
    (New-Case  8 'Recon'       'T1018'     'Ask'   'proc' 'nltest /dclist'),
    # Defense evasion (Rules03)
    (New-Case  9 'DefEvasion'  'T1562.001' 'Block' 'proc' 'set-mppreference -disablerealtimemonitoring'),
    (New-Case 10 'DefEvasion'  'T1562.001' 'Block' 'proc' 'amsiscanbuffer patch'),
    # Execution / download (Rules06)
    (New-Case 11 'Download'    'T1105'     'Block' 'proc' 'certutil -urlcache -f http://127.0.0.1/x'),
    (New-Case 12 'LOLBin'      'T1218.010' 'Block' 'proc' 'regsvr32 /i:http://127.0.0.1/a.sct scrobj.dll'),
    # File dimension: vulnerable-driver name drop (Rules07 + ProtectedPaths) -- empty file, harmless
    (New-Case 13 'BYOVD'       'T1211'     'Block' 'file' 'amsdk.sys'),
    # Registry dimension: script host writes Run autostart (Rules02) -- reversible, auto-removed
    (New-Case 14 'Persist'     'T1547.001' 'Block' 'reg'  'BulwarkSelfTest')
)

$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$ps  = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$amsdkPath = Join-Path $env:TEMP 'amsdk.sys'
$runKey    = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

# Launch a disposable process that performs one harmless trigger and stays alive
# ~5s (so the service has time to observe + enrich + decide; in user-mode ETW the
# command line is back-filled by reading the PEB, which fails for instant-exit
# processes). Returns its PID.
function Start-ProcTrigger([string]$Token,[string]$Marker) {
    # echo just prints the signature string; & ping loops loopback ~5s to stay alive. No side effects.
    $inner = "echo $Token $Marker & ping -n 6 127.0.0.1 > nul"
    $p = Start-Process -FilePath $cmd -ArgumentList "/c `"$inner`"" -WindowStyle Hidden -PassThru
    return $p.Id
}
function Start-FileTrigger([string]$Marker) {
    # Create a 0-byte amsdk.sys in %TEMP% (empty file, harmless), then stay alive.
    # %TEMP% has no spaces, so no inner quotes are needed (avoids nested quoting under /c).
    $inner = "type nul > $amsdkPath & echo $Marker & ping -n 6 127.0.0.1 > nul"
    $p = Start-Process -FilePath $cmd -ArgumentList "/c `"$inner`"" -WindowStyle Hidden -PassThru
    return $p.Id
}
function Start-RegTrigger([string]$Marker) {
    # Script host (powershell) writes a reversible test value under Run, then stays alive.
    # $runKey / $Marker are passed as barewords (start with a letter, no spaces).
    $psInner = "New-ItemProperty -Path $runKey -Name BulwarkSelfTest -Value $Marker -PropertyType String -Force | Out-Null; Start-Sleep -Seconds 5"
    $p = Start-Process -FilePath $ps -ArgumentList @('-NoProfile','-NonInteractive','-Command',$psInner) -WindowStyle Hidden -PassThru
    return $p.Id
}

Write-Section "Bulwark harmless self-test  RunId=$script:RunId"
Write-Host "Data dir  : $DataDir"
Write-Host "Triggers  : $($cases.Count)  (process / file / registry dimensions)"
Write-Host "Note      : all triggers are harmless -- signature strings are only printed; the empty file and registry value are cleaned up." -ForegroundColor Yellow

$svc = Get-Service -Name 'BulwarkService' -ErrorAction SilentlyContinue
if (-not $svc) { $svc = Get-Service -Name '*bulwark*' -ErrorAction SilentlyContinue | Select-Object -First 1 }
if ($svc) { Write-Host "Service   : $($svc.Name) = $($svc.Status)" -ForegroundColor Green }
else      { Write-Host "Service   : no Bulwark service found -- results will all be 'not detected'." -ForegroundColor Red }

$startUtc = [datetime]::UtcNow

Write-Section 'Firing triggers'
foreach ($c in $cases) {
    $marker = "$script:RunId-C$($c.Id)"
    switch ($c.Kind) {
        'proc' { $c.Pid = Start-ProcTrigger $c.Token $marker }
        'file' { $c.Pid = Start-FileTrigger $marker }
        'reg'  { $c.Pid = Start-RegTrigger  $marker }
    }
    Write-Host ("  [{0,2}] {1,-11} {2,-11} pid={3,-6} {4}" -f $c.Id, $c.Category, $c.Technique, $c.Pid, $c.Token)
    Start-Sleep -Milliseconds 600
}

Write-Host ''
Write-Host "Waiting $SettleSeconds s for the service to observe and persist verdicts ..." -ForegroundColor DarkGray
Start-Sleep -Seconds $SettleSeconds

Write-Section 'Reading audit verdicts and correlating'
$audit = Get-AuditSince $startUtc
Write-Host "Audit rows in window: $($audit.Count)"

function Resolve-Detection($Case,$AuditRows) {
    switch ($Case.Kind) {
        'proc' { $rows = $AuditRows | Where-Object { $_.type -eq 'ProcessCreate' -and $_.actorPid -eq $Case.Pid } }
        'file' { $rows = $AuditRows | Where-Object { ($_.type -eq 'FileWrite' -or $_.type -eq 'FileDelete') -and "$($_.target)" -match 'amsdk\.sys' } }
        'reg'  { $rows = $AuditRows | Where-Object { $_.type -eq 'RegistryWrite' -and "$($_.target)" -match 'BulwarkSelfTest' } }
    }
    $act = 'None'; $rule = ''
    if ($rows) {
        if     ($rows.action -contains 'Block') { $act = 'Block' }
        elseif ($rows.action -contains 'Ask')   { $act = 'Ask' }
        elseif ($rows.action -contains 'Allow') { $act = 'Allow' }
        $best = $rows | Where-Object { $_.action -eq $act } | Select-Object -First 1
        if ($best -and $best.reasons) {
            $rule = (($best.reasons | Where-Object { $_ -match 'T1\d|rule|hit' }) -join ' / ')
            if (-not $rule) { $rule = ($best.reasons -join ' / ') }
        }
    }
    return [pscustomobject]@{ Action=$act; Rule=$rule }
}

$sev = @{ 'None'=0; 'Allow'=0; 'Ask'=1; 'Block'=2 }
foreach ($c in $cases) {
    $r = Resolve-Detection $c $audit
    $c.Detected = $r.Action
    $c.Rule     = $r.Rule
    $need = if ($c.Expected -eq 'Ask') { 1 } else { 2 }
    $c.Pass = ($sev[$c.Detected] -ge $need)
    if ($c.Expected -eq 'Ask' -and $c.Detected -eq 'Block') { $c.Pass = $true }
}

Write-Section 'Result matrix'
$fmt = "{0,2}  {1,-11} {2,-11} {3,-6} {4,-6} {5,-5} {6}"
Write-Host ($fmt -f 'ID','Category','Technique','Expect','Actual','Res','Matched rule / reason') -ForegroundColor White
Write-Host ('-' * 96) -ForegroundColor DarkGray
foreach ($c in $cases) {
    $mark = if ($c.Pass) { 'PASS' } else { 'MISS' }
    $color = if ($c.Pass) { 'Green' } else { 'Red' }
    $ruleShort = if ($c.Rule.Length -gt 44) { $c.Rule.Substring(0,44) + '...' } else { $c.Rule }
    Write-Host ($fmt -f $c.Id,$c.Category,$c.Technique,$c.Expected,$c.Detected,$mark,$ruleShort) -ForegroundColor $color
}

$passN = ($cases | Where-Object { $_.Pass }).Count
$detN  = ($cases | Where-Object { $_.Detected -eq 'Block' -or $_.Detected -eq 'Ask' }).Count
Write-Section 'Conclusion'
Write-Host ("Detected (block or ask): {0}/{1}" -f $detN, $cases.Count) -ForegroundColor Cyan
Write-Host ("Met expected severity  : {0}/{1}" -f $passN, $cases.Count) -ForegroundColor Cyan
if ($passN -eq $cases.Count) {
    Write-Host "==> All triggers detected as expected. Detection chain is effective end to end." -ForegroundColor Green
} elseif ($detN -eq $cases.Count) {
    Write-Host "==> All triggers detected, but some severities differ from expected (see table)." -ForegroundColor Yellow
} else {
    Write-Host "==> Some triggers were not detected. Check that category's rules, event-source coverage, or the keep-alive window." -ForegroundColor Red
}

# ---- Cleanup ----
Write-Section 'Cleanup'
if ($KeepArtifacts) {
    Write-Host "Skipped cleanup (-KeepArtifacts). Residual: $amsdkPath and Run\BulwarkSelfTest" -ForegroundColor Yellow
} else {
    foreach ($c in $cases) {
        if (-not $c.Pid) { continue }
        $pr = Get-Process -Id $c.Pid -ErrorAction SilentlyContinue
        # Only kill still-alive processes that are our trigger hosts (cmd/powershell), to avoid PID-reuse harm.
        if ($pr -and ($pr.ProcessName -eq 'cmd' -or $pr.ProcessName -eq 'powershell')) {
            Stop-Process -Id $c.Pid -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 500
    if (Test-Path -LiteralPath $amsdkPath) {
        Remove-Item -LiteralPath $amsdkPath -Force -ErrorAction SilentlyContinue
        Write-Host "Removed empty file: $amsdkPath"
    } else {
        Write-Host "amsdk.sys not at original path (may have been quarantined by the service -- expected)."
    }
    $rv = Get-ItemProperty -Path $runKey -Name 'BulwarkSelfTest' -ErrorAction SilentlyContinue
    if ($rv) {
        Remove-ItemProperty -Path $runKey -Name 'BulwarkSelfTest' -ErrorAction SilentlyContinue
        Write-Host "Removed registry value: $runKey\BulwarkSelfTest"
    } else {
        Write-Host "Registry test value not present (write may have been blocked -- expected)."
    }
}

# Save a report for the record.
$reportPath = Join-Path $PSScriptRoot ("report-{0}.txt" -f $script:RunId)
$lines = @("Bulwark self-test  RunId=$script:RunId  startUtc=$($startUtc.ToString('o'))",
           ("detected={0}/{1}  passed={2}/{1}" -f $detN,$cases.Count,$passN), '')
$lines += $cases | ForEach-Object {
    $m = if ($_.Pass) { 'PASS' } else { 'MISS' }
    "[{0,2}] {1} {2} expect={3} got={4} {5} :: {6}" -f $_.Id,$_.Category,$_.Technique,$_.Expected,$_.Detected,$m,$_.Rule
}
Set-Content -LiteralPath $reportPath -Value $lines -Encoding UTF8
Write-Host ''
Write-Host "Report saved: $reportPath" -ForegroundColor DarkGray
