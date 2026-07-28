# =====================================================================
#  Kiro helper: verify the newly added registry notify-class coverage on a
#  live system. ASCII-ONLY (Windows PowerShell 5.1 reads UTF-8-without-BOM
#  .ps1 as GBK on Chinese Windows).
#
#  Every case is chosen to be HARMLESS whether it is blocked or not, and any
#  side effect is undone in the same run:
#    - the SAM hive save writes to a temp file that is deleted afterwards
#    - the Winlogon Shell write uses the value it already has (explorer.exe)
#    - the sc config uses the start type the service already has (demand)
#    - the rename is reverted immediately if it unexpectedly succeeds
#
#  Note on case A: the command line "HKEY_LOCAL_MACHINE\SAM" deliberately does
#  NOT contain the literal "HKLM\SAM", so the command-line hard block does not
#  fire and the request actually reaches ZwSaveKey. That isolates the kernel
#  RegNtPreSaveKey + built-in credential-hive check, which is the whole point.
# =====================================================================

if (-not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) { & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath; exit $LASTEXITCODE }
}
$ErrorActionPreference = 'Continue'
$env:Path = "$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0;$env:Path"

$log = Join-Path $env:TEMP 'blw_regtest.log'
Start-Transcript -Path $log -Force | Out-Null

$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "NOT ELEVATED - aborting."; Write-Host "SENTINEL_REGTEST_DONE"; Stop-Transcript | Out-Null; exit 1
}

$results = @()
function Rec($id, $what, $expect, $got, $note) {
    $ok = if ($expect -eq $got) { 'PASS' } else { '**FAIL**' }
    $script:results += ("{0}  {1}  {2,-52} expect={3,-7} got={4,-7} {5}" -f $ok, $id, $what, $expect, $got, $note)
}
# Run an exe, return 'DENIED' when it fails with an access-denied style error.
function RunExe($file, $argList) {
    $so = Join-Path $env:TEMP ('_blw_o_' + [Guid]::NewGuid().ToString('N') + '.txt')
    $p = Start-Process -FilePath $file -ArgumentList $argList -Wait -PassThru -NoNewWindow `
                       -RedirectStandardOutput $so -RedirectStandardError ($so + '.err')
    $txt = ''
    foreach ($f in @($so, ($so + '.err'))) {
        if (Test-Path $f) { $txt += (Get-Content $f -Raw -ErrorAction SilentlyContinue); Remove-Item $f -Force -ErrorAction SilentlyContinue }
    }
    return @{ Code = $p.ExitCode; Text = ($txt -replace "`r?`n", ' ').Trim() }
}

$reg = "$env:SystemRoot\System32\reg.exe"
$sc  = "$env:SystemRoot\System32\sc.exe"

Write-Host "=== A) SaveKey on the SAM hive (kernel built-in credential-hive block) ==="
$samOut = Join-Path $env:TEMP '_blwtest_sam.hiv'
Remove-Item $samOut -Force -ErrorAction SilentlyContinue
$r = RunExe $reg @('save', 'HKEY_LOCAL_MACHINE\SAM', $samOut, '/y')
$made = Test-Path $samOut
Write-Host ("  reg exit=" + $r.Code + "  file_created=" + $made + "  out=" + $r.Text)
Rec 'A' 'reg save HKEY_LOCAL_MACHINE\SAM (credential hive)' 'DENIED' $(if ($r.Code -eq 0 -and $made) { 'ALLOWED' } else { 'DENIED' }) ''
if ($made) { Write-Host "  cleaning up the dumped hive"; Remove-Item $samOut -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host "=== B) SaveKey on a benign hive (regression: must still work) ==="
$benign = Join-Path $env:TEMP '_blwtest_benign.hiv'
Remove-Item $benign -Force -ErrorAction SilentlyContinue
$r = RunExe $reg @('save', 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts', $benign, '/y')
$made = Test-Path $benign
Write-Host ("  reg exit=" + $r.Code + "  file_created=" + $made + "  out=" + $r.Text)
Rec 'B' 'reg save a benign key (must NOT be blocked)' 'ALLOWED' $(if ($r.Code -eq 0 -and $made) { 'ALLOWED' } else { 'DENIED' }) ''
Remove-Item $benign -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== C) CreateKeyEx on a hard-blocked key path (IFEO Debugger) ==="
$ifeo = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger'
$r = RunExe $reg @('add', $ifeo, '/f')
$exists = Test-Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger')
Write-Host ("  reg exit=" + $r.Code + "  key_exists=" + $exists + "  out=" + $r.Text)
Rec 'C' 'create KEY ...\sethc.exe\Debugger (new CreateKeyEx)' 'DENIED' $(if ($r.Code -eq 0 -and $exists) { 'ALLOWED' } else { 'DENIED' }) ''
if ($exists) { Write-Host "  cleaning up the created key"; & $reg delete $ifeo /f 2>&1 | Out-Null }

Write-Host ""
Write-Host "=== D) SetValue on a hard-blocked value (Winlogon\Shell; same value it already has) ==="
$r = RunExe $reg @('add', 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', '/v', 'Shell', '/t', 'REG_SZ', '/d', 'explorer.exe', '/f')
Write-Host ("  reg exit=" + $r.Code + "  out=" + $r.Text)
Rec 'D' 'set Winlogon\Shell (pre-existing hard block)' 'DENIED' $(if ($r.Code -eq 0) { 'ALLOWED' } else { 'DENIED' }) ''

Write-Host ""
Write-Host "=== E) Self-protection: sc config Bulwark (same start type it already has) ==="
$r = RunExe $sc @('config', 'Bulwark', 'start=', 'demand')
Write-Host ("  sc exit=" + $r.Code + "  out=" + $r.Text)
Rec 'E' 'sc config Bulwark (self-protection \Services\Bulwark)' 'DENIED' $(if ($r.Code -eq 0) { 'ALLOWED' } else { 'DENIED' }) ''

Write-Host ""
Write-Host "=== F) RenameKey on the driver service key (newly added notify class) ==="
$svcKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bulwark'
$renamed = $false
try {
    Rename-Item -Path $svcKeyPath -NewName 'Bulwark_renametest' -ErrorAction Stop
    $renamed = $true
} catch {
    Write-Host ("  rename failed as expected: " + $_.Exception.Message.Trim())
}
Rec 'F' 'rename \Services\Bulwark (new RegNtPreRenameKey)' 'DENIED' $(if ($renamed) { 'ALLOWED' } else { 'DENIED' }) ''
if ($renamed) {
    Write-Host "  UNEXPECTED: rename succeeded - reverting immediately"
    try { Rename-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Bulwark_renametest' -NewName 'Bulwark' -ErrorAction Stop; Write-Host "  reverted OK" }
    catch { Write-Host ("  REVERT FAILED - fix manually: " + $_.Exception.Message) }
}

Write-Host ""
Write-Host "=== G) CreateKeyEx regression: creating an ordinary key must still work ==="
$tmpKey = 'HKLM\SOFTWARE\_BlwSelfTest\Sub'
$r = RunExe $reg @('add', $tmpKey, '/f')
$exists = Test-Path 'HKLM:\SOFTWARE\_BlwSelfTest\Sub'
Write-Host ("  reg exit=" + $r.Code + "  key_exists=" + $exists + "  out=" + $r.Text)
Rec 'G' 'create an ordinary key (must NOT be blocked)' 'ALLOWED' $(if ($r.Code -eq 0 -and $exists) { 'ALLOWED' } else { 'DENIED' }) ''
& $reg delete 'HKLM\SOFTWARE\_BlwSelfTest' /f 2>&1 | Out-Null

Write-Host ""
Write-Host "==================== SUMMARY ===================="
$results | ForEach-Object { Write-Host $_ }
Write-Host ("passed " + (@($results | Where-Object { $_.StartsWith('PASS') }).Count) + " / " + $results.Count)

Write-Host ""
Write-Host "--- driver still healthy? ---"
& fltmc.exe filters 2>&1 | Select-String -SimpleMatch 'Bulwark' | ForEach-Object { Write-Host ("  " + $_.Line.Trim()) }
& $sc query Bulwark 2>&1 | Select-String -SimpleMatch 'STATE' | ForEach-Object { Write-Host ("  " + $_.Line.Trim()) }
& $sc query BulwarkService 2>&1 | Select-String -SimpleMatch 'STATE' | ForEach-Object { Write-Host ("  " + $_.Line.Trim()) }

Write-Host ""
Write-Host "SENTINEL_REGTEST_DONE"
Stop-Transcript | Out-Null
