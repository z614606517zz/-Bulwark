$ErrorActionPreference = 'SilentlyContinue'
$root = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $root 'data\manifests\benign_manifest.jsonl'
$mon = Join-Path $root '_wim_monitor.txt'
$export = 'D:\_bulwark_export_idx1.wim'
$mountChk = 'C:\_bulwark_wimmount\Windows\System32'
Set-Content -LiteralPath $mon -Value ('watch start ' + (Get-Date -Format 'HH:mm:ss'))
for ($i = 0; $i -lt 100; $i++) {
    Start-Sleep -Seconds 30
    $line = (Get-Date -Format 'HH:mm:ss')
    if (Test-Path $export) { $line += ' export=' + [math]::Round((Get-Item $export).Length/1GB,2) + 'GB' } else { $line += ' export=none' }
    if (Test-Path $mountChk) { $line += ' MOUNTED' } else { $line += ' mount=no' }
    if (Test-Path $manifest) { try { $line += ' manifest=' + ([IO.File]::ReadAllLines($manifest)).Count } catch { $line += ' manifest=?' } }
    Add-Content -LiteralPath $mon -Value $line
}
