# 对比 curl 与 .NET HttpClient 访问 VirusTotal，定位 SSL 失败根因。
$ErrorActionPreference = 'Continue'
$out = 'D:\新建文件夹 (3)\nettest.txt'
$key = [Environment]::GetEnvironmentVariable('BULWARK_VT_APIKEY','Machine')
$url = 'https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

"=== system proxy ===" | Out-File $out -Encoding UTF8
try {
  $proxy = [System.Net.WebRequest]::GetSystemWebProxy()
  $target = [Uri]$url
  ("proxy for VT: " + $proxy.GetProxy($target)) | Out-File $out -Append -Encoding UTF8
} catch { ("proxy check error: " + $_.Exception.Message) | Out-File $out -Append -Encoding UTF8 }

"=== curl.exe ===" | Out-File $out -Append -Encoding UTF8
try {
  $c = & curl.exe -s -o NUL -w "%{http_code}" -H "x-apikey: $key" $url 2>&1
  ("curl http_code: " + $c) | Out-File $out -Append -Encoding UTF8
} catch { ("curl error: " + $_.Exception.Message) | Out-File $out -Append -Encoding UTF8 }

"=== .NET HttpClient ===" | Out-File $out -Append -Encoding UTF8
try {
  $h = New-Object System.Net.Http.HttpClient
  $h.Timeout = [TimeSpan]::FromSeconds(15)
  $h.DefaultRequestHeaders.Add("x-apikey", $key)
  $resp = $h.GetAsync($url).GetAwaiter().GetResult()
  (".NET status: " + [int]$resp.StatusCode) | Out-File $out -Append -Encoding UTF8
} catch {
  (".NET error: " + $_.Exception.Message) | Out-File $out -Append -Encoding UTF8
  if ($_.Exception.InnerException) {
    (".NET inner: " + $_.Exception.InnerException.Message) | Out-File $out -Append -Encoding UTF8
    if ($_.Exception.InnerException.InnerException) {
      (".NET inner2: " + $_.Exception.InnerException.InnerException.Message) | Out-File $out -Append -Encoding UTF8
    }
  }
}

"=== done ===" | Out-File $out -Append -Encoding UTF8
