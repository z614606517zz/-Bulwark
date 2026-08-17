$k = ($env:BULWARK_MB_AUTHKEY).Trim()
$api = 'https://mb-api.abuse.ch/api/v1/'
# 拿一个 PE 家族样本的 hash
$j = (& curl.exe -sS -m 45 -X POST -H ("Auth-Key: " + $k) -d "query=get_siginfo&signature=RedLineStealer&limit=5" $api 2>&1 | Out-String | ConvertFrom-Json)
if (-not $j -or $j.query_status -ne 'ok') { Write-Host 'get_siginfo failed'; exit 1 }
$sample = $j.data | Where-Object { $_.file_type -in @('exe','dll') } | Select-Object -First 1
if (-not $sample) { $sample = $j.data[0] }
$h = $sample.sha256_hash
Write-Host ("test_hash=" + $h + "  family=" + $sample.signature + "  file_type=" + $sample.file_type)
$tmp = Join-Path $env:TEMP ('_mbdl_' + $h.Substring(0,8) + '.bin')
if (Test-Path $tmp) { Remove-Item $tmp -Force }
$code = & curl.exe -s -m 120 -X POST -H ("Auth-Key: " + $k) -d "query=get_file" -d ("sha256_hash=" + $h) -o $tmp -w "%{http_code}" $api 2>$null
Write-Host ("http=" + $code + "  curl_exit=" + $LASTEXITCODE)
if (Test-Path $tmp) {
    $len = (Get-Item $tmp).Length
    $fs = [IO.File]::OpenRead($tmp); $b = New-Object byte[] 2; $n = $fs.Read($b,0,2); $fs.Dispose()
    $isZip = ($n -eq 2 -and $b[0] -eq 0x50 -and $b[1] -eq 0x4B)
    Write-Host ("downloaded_bytes=" + $len + "  isZip_PK=" + $isZip)
    if (-not $isZip -and $len -lt 500) { Write-Host ("response_text=" + ([IO.File]::ReadAllText($tmp))) }
    Remove-Item $tmp -Force
    if ($isZip) { Write-Host 'DOWNLOAD_PATH_OK' }
} else { Write-Host 'NO_FILE_WRITTEN' }
