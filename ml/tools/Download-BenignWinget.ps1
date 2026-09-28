# Download-BenignWinget.ps1  (ASCII-only: Windows PowerShell 5.1 reads .ps1 as ANSI)
#
# Bulk-download benign installers via "winget download" (downloads only, NEVER installs
# and NEVER executes a sample). Reads package Ids from benign_winget_ids.txt.
#
# Why winget on top of Collect-BenignSamples.ps1: that script curls ~37 hardcoded official
# URLs. This one scales vendor/compiler diversity cheaply -- diversity is what stops the
# model from learning "Microsoft-signed => clean". Target >= 300 distinct signers.
#
# Each package lands in its own subfolder so same-named files (setup.exe) do not collide.
# Idempotent: a package whose folder already holds a >50KB file is skipped, so you can
# re-run after a network drop.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\Download-BenignWinget.ps1 -DlDir "C:\path\to\out"
#   powershell -ExecutionPolicy Bypass -File .\Download-BenignWinget.ps1 -DlDir "..." -IdFile my_ids.txt
param(
    [Parameter(Mandatory = $true)][string]$DlDir,
    [string]$IdFile,
    [int]$TimeoutSec = 420
)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $IdFile) { $IdFile = Join-Path $scriptDir 'benign_winget_ids.txt' }
if (-not (Test-Path -LiteralPath $IdFile)) { Write-Output "missing id file: $IdFile"; exit 1 }

$winget = (Get-Command winget -ErrorAction SilentlyContinue).Source
if (-not $winget) { Write-Output 'winget not found on PATH'; exit 1 }

New-Item -ItemType Directory -Path $DlDir -Force | Out-Null
$log = Join-Path $DlDir '_winget_download_log.csv'
if (-not (Test-Path -LiteralPath $log)) {
    'time,id,result,files,bytes' | Out-File -LiteralPath $log -Encoding utf8
}

$ids = Get-Content -LiteralPath $IdFile -Encoding UTF8 |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith('#') } |
    Select-Object -Unique

Write-Output "==== winget bulk download -> $DlDir ===="
Write-Output ("packages: {0}" -f $ids.Count)

$ok = 0; $skip = 0; $fail = 0; $totalBytes = [long]0; $totalFiles = 0
$i = 0
foreach ($id in $ids) {
    $i++
    # folder name: Id with path-hostile chars flattened
    $safe = ($id -replace '[^A-Za-z0-9\.\-_]', '_')
    $dst = Join-Path $DlDir $safe

    if (Test-Path -LiteralPath $dst) {
        $have = @(Get-ChildItem -LiteralPath $dst -File -Recurse -ErrorAction SilentlyContinue |
                  Where-Object { $_.Length -gt 50000 })
        if ($have.Count -gt 0) {
            Write-Output ("[{0}/{1}] {2} -- already have {3} file(s), skip" -f $i, $ids.Count, $id, $have.Count)
            $skip++
            $totalFiles += $have.Count
            $totalBytes += ($have | Measure-Object -Property Length -Sum).Sum
            continue
        }
    }
    New-Item -ItemType Directory -Path $dst -Force | Out-Null

    Write-Output ("[{0}/{1}] {2}" -f $i, $ids.Count, $id)
    $args = @('download', '--id', $id, '--exact', '--download-directory', $dst,
              '--accept-package-agreements', '--accept-source-agreements',
              '--disable-interactivity')
    try {
        $p = Start-Process -FilePath $winget -ArgumentList $args -NoNewWindow -PassThru `
                           -RedirectStandardOutput (Join-Path $dst '_winget.out') `
                           -RedirectStandardError  (Join-Path $dst '_winget.err')
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            try { $p.Kill() } catch {}
            Write-Output "    timeout ${TimeoutSec}s, killed"
        }
    } catch {
        Write-Output ("    launch failed: {0}" -f $_.Exception.Message)
    }

    $got = @(Get-ChildItem -LiteralPath $dst -File -Recurse -ErrorAction SilentlyContinue |
             Where-Object { $_.Length -gt 50000 -and $_.Extension -notin @('.out', '.err', '.yaml') })
    $bytes = 0
    if ($got.Count -gt 0) { $bytes = ($got | Measure-Object -Property Length -Sum).Sum }

    if ($got.Count -gt 0) {
        $ok++
        $totalFiles += $got.Count
        $totalBytes += $bytes
        foreach ($g in $got) {
            $sig = 'n/a'
            if ($g.Extension -in @('.exe', '.dll', '.msi', '.msix', '.appx')) {
                try { $sig = [string](Get-AuthenticodeSignature -LiteralPath $g.FullName).Status } catch {}
            }
            Write-Output ("    [{0,-9}] {1}  {2:N1}MB" -f $sig, $g.Name, ($g.Length / 1MB))
        }
        $row = '{0},{1},ok,{2},{3}' -f (Get-Date -Format s), $id, $got.Count, $bytes
    } else {
        $fail++
        $err = ''
        $ep = Join-Path $dst '_winget.err'
        if (Test-Path -LiteralPath $ep) { $err = (Get-Content -LiteralPath $ep -Raw -ErrorAction SilentlyContinue) }
        Write-Output ("    no file (winget produced nothing){0}" -f $(if ($err) { ' / ' + $err.Trim() } else { '' }))
        $row = '{0},{1},fail,0,0' -f (Get-Date -Format s), $id
        Remove-Item -LiteralPath $dst -Recurse -Force -ErrorAction SilentlyContinue
    }
    Add-Content -LiteralPath $log -Value $row -Encoding utf8
}

Write-Output '==== done ===='
Write-Output ("ok {0} / skip {1} / fail {2}" -f $ok, $skip, $fail)
Write-Output ("files {0}  total {1:N1} MB" -f $totalFiles, ($totalBytes / 1MB))
Write-Output ("log: {0}" -f $log)
