$mlRoot = Split-Path -Parent $PSScriptRoot
$zipDir = Join-Path $mlRoot 'data\malicious\zip'
$manifest = Join-Path $mlRoot 'data\manifests\malicious_manifest.jsonl'
$run = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*Collect-MalwareBazaar*' }).Count
$files = @(Get-ChildItem $zipDir -Recurse -File -ErrorAction SilentlyContinue)
$zips = $files.Count
$mb = if ($zips -gt 0) { [math]::Round(($files | Measure-Object Length -Sum).Sum/1MB,1) } else { 0 }
$man = 0; if (Test-Path $manifest) { $man = @(Get-Content $manifest).Count }
Write-Host ("running=" + $run + "  zips=" + $zips + "  manifest=" + $man + "  zip_MB=" + $mb)
