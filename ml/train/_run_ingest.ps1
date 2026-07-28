$ErrorActionPreference = 'Stop'
$dir = $PSScriptRoot
if (-not $dir) { $dir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$py = Join-Path $dir '.venv\Scripts\python.exe'
$script = Join-Path $dir 'ingest_daily_batches.py'
$zipdir = (Get-Content -LiteralPath (Join-Path $dir '_zipdir.txt') -Encoding UTF8 -Raw).Trim()
$mlroot = Split-Path -Parent $dir
$out = Join-Path $mlroot '_ingest_out.txt'
$err = Join-Path $mlroot '_ingest_err.txt'
if (-not (Test-Path -LiteralPath $zipdir)) { Write-Host ("zip-dir not found: " + $zipdir); exit 1 }
Start-Process -FilePath $py -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err `
    -ArgumentList @('-u', ('"' + $script + '"'), '--zip-dir', ('"' + $zipdir + '"'))
Write-Host ("ingester launched (detached, DELETE-after-extract). zip-dir=" + $zipdir)
Write-Host ("stdout -> " + $out)
