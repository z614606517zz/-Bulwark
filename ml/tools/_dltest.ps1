$k = ($env:BULWARK_MB_AUTHKEY).Trim()
$api = 'https://mb-api.abuse.ch/api/v1/'
$j = (& curl.exe -sS -m 30 -X POST -H ("Auth-Key: " + $k) -d "query=get_siginfo&signature=RedLineStealer&limit=10" $api 2>&1 | Out-String | ConvertFrom-Json)
if (-not $j -or $j.query_status -ne 'ok') { Write-Host 'query_failed'; exit }
$s = $j.data | Where-Object { $_.file_type -in @('exe','dll') } | Select-Object -First 1
$h = $s.sha256_hash
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$tmp = Join-Path $env:TEMP '_dltest2.bin'
if (Test-Path $tmp) { Remove-Item $tmp -Force }
$code = & curl.exe -s -m 30 -X POST -H ("Auth-Key: " + $k) -d "query=get_file" -d ("sha256_hash=" + $h) -o $tmp -w "%{http_code}" $api 2>$null
$sw.Stop()
$len = 0; $body = ''
if (Test-Path $tmp) { $len = (Get-Item $tmp).Length; if ($len -lt 600) { $body = [IO.File]::ReadAllText($tmp) }; Remove-Item $tmp -Force }
Write-Host ("query=ok  get_file http=" + $code + " curl_exit=" + $LASTEXITCODE + " secs=" + [math]::Round($sw.Elapsed.TotalSeconds,1) + " bytes=" + $len)
Write-Host ("body=" + $body)
