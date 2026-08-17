# =====================================================================
#  Unit test for the log-collector redaction in
#  packaging\portable-scripts\bulwark.ps1
#
#  WHY THIS EXISTS
#    The needle list in bulwark.ps1 is shipped as SHA-256 only, so "is it still
#    redacting?" is no longer answerable by reading the file. A hash typo, a
#    tokenizer regex that stops matching, or an accidentally emptied list all
#    look perfectly fine on inspection and silently publish our endpoint the
#    next time a user posts a diagnostic bundle.
#
#  HOW
#    Extracts the region between the "# --- redaction:begin ---" and
#    "# --- redaction:end ---" markers, dot-sources just that region, and runs
#    it over synthetic text. No package, no service, no admin rights needed.
#
#    Negative cases matter as much as positive ones: over-redacting destroys the
#    diagnostic value of the log (a blocked C2 address is exactly what you need
#    to see), so ordinary public IPs, domains and file hashes must survive.
#
#  ASCII-only on purpose: PS 5.1 on a zh-CN box reads a BOM-less .ps1 as GBK.
#  The extracted region does contain CJK, so it is written back out with a BOM.
# =====================================================================
[CmdletBinding()]
param([switch]$KeepTemp)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$src  = Join-Path $root 'packaging\portable-scripts\bulwark.ps1'
$needleFile = Join-Path $root 'packaging\redaction-needles.txt'

if (-not (Test-Path $src)) { throw ("not found: " + $src) }
if (-not (Test-Path $needleFile)) { throw ("not found: " + $needleFile) }

$text = [IO.File]::ReadAllText($src, [Text.Encoding]::UTF8)
$b = $text.IndexOf('# --- redaction:begin ---')
$e = $text.IndexOf('# --- redaction:end ---')
if ($b -lt 0 -or $e -lt 0 -or $e -le $b) { throw "redaction markers not found (or out of order) in bulwark.ps1" }
$region = $text.Substring($b, $e - $b)

$tmp = Join-Path $env:TEMP ('bulwark-redaction-test-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$frag = Join-Path $tmp 'region.ps1'
[IO.File]::WriteAllText($frag, $region, (New-Object Text.UTF8Encoding($true)))

# Initialize-Redaction reads $pkgDir\appsettings.json. Point it at an empty dir so
# the test exercises the hash path only -- config-derived literals are a separate
# mechanism and would mask a broken needle set.
$pkgDir = $tmp
. $frag

$needles = @(Get-Content -LiteralPath $needleFile |
             ForEach-Object { $_.Trim() } |
             Where-Object { $_ -ne '' -and -not $_.StartsWith('#') })

Write-Host ''
Write-Host ('needles from single source : ' + $needles.Count)
Write-Host ('shipped hashes in bulwark.ps1: ' + @($script:RedactNeedleHashes).Count)

Initialize-Redaction

$fail = 0
$pass = 0

# NOTE: do not name the parameter $input -- that is a PowerShell automatic variable
# (the pipeline enumerator). Binding it silently yields an empty string, so every
# positive case "fails" and every negative case "passes" comparing '' to ''.
function Should-Hide([string]$label, [string]$sample) {
    $out = Protect-Text $sample
    # The needle itself must be gone AND something must have been masked.
    $gone = $true
    foreach ($n in $needles) { if ($out.ToLowerInvariant().Contains($n.ToLowerInvariant())) { $gone = $false } }
    if ($gone -and $out -ne $sample) {
        Write-Host ('  PASS  hide   ' + $label) -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host ('  FAIL  hide   ' + $label) -ForegroundColor Red
        Write-Host ('        in : ' + $sample) -ForegroundColor DarkGray
        Write-Host ('        out: ' + $out) -ForegroundColor DarkGray
        $script:fail++
    }
}

function Should-Keep([string]$label, [string]$sample) {
    $out = Protect-Text $sample
    if ($out -eq $sample) {
        Write-Host ('  PASS  keep   ' + $label) -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host ('  FAIL  keep   ' + $label + '  (over-redacted -- destroys diagnostic value)') -ForegroundColor Red
        Write-Host ('        in : ' + $sample) -ForegroundColor DarkGray
        Write-Host ('        out: ' + $out) -ForegroundColor DarkGray
        $script:fail++
    }
}

Write-Host ''
Write-Host '== positive: every needle must be masked =='
$i = 0
foreach ($n in $needles) {
    $i++
    Should-Hide ('needle #' + $i + ' bare')        $n
    Should-Hide ('needle #' + $i + ' in a line')   ('2026-08-09 12:00:01 [info] resolved ' + $n + ' ok rtt=12ms')
}

Write-Host ''
Write-Host '== positive: real-world shapes =='
$dom = @($needles | Where-Object { $_ -match '^[a-z0-9.\-]+$' -and $_ -notmatch '^\d+(\.\d+){3}$' -and $_.Contains('.') })[0]
if ($dom) {
    Should-Hide 'https URL'      ('POST https://' + $dom + '/api/v1/reputation/hash 200 41ms')
    Should-Hide 'subdomain'      ('CNAME edge.cdn.' + $dom + ' -> 1.2.3.4')
    Should-Hide 'uppercased'     ('DNS query for ' + $dom.ToUpperInvariant() + ' type=A')
    Should-Hide 'port suffix'    ('connect ' + $dom + ':443 established')
}
$ip = @($needles | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })[0]
if ($ip) {
    Should-Hide 'ip with port'   ('egress tcp ' + $ip + ':443 pid=4812')
}
$tok = @($needles | Where-Object { $_ -notmatch '\.' })[0]
if ($tok) {
    Should-Hide 'bare token'                 ('Authorization header set (' + $tok + ')')
    # Needle embedded in a longer token: the hash tokenizer cannot see it, the
    # generic Bearer rule must. This is the documented complementary path.
    Should-Hide 'token inside Bearer header' ('Authorization: Bearer ' + $tok + 'AbCdEf123456')
}

Write-Host ''
Write-Host '== positive: generic rules (independent of the needle set) =='
Should-Hide 'json ApiKey field' '"ApiKey": "aaaaaaaabbbbbbbbccccccccdddddddd"'
Should-Hide 'api_key= form'     'GET /v1/x?api_key=aaaaaaaabbbbbbbbcccccccc HTTP/1.1'

Write-Host ''
Write-Host '== negative: ordinary diagnostic content must survive =='
Should-Keep 'public dns ip'   'egress udp 8.8.8.8:53 pid=1234'
Should-Keep 'private ip'      'listen 192.168.1.7:445'
Should-Keep 'unrelated host'  'GET https://example.com/index.html 200'
Should-Keep 'sha256 hex'      'sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
Should-Keep 'windows path'    'C:\Windows\System32\svchost.exe -k netsvcs'
Should-Keep 'plain sentence'  'blocked remote thread injection into explorer.exe pid=5120'

Write-Host ''
Write-Host ('result: ' + $pass + ' passed, ' + $fail + ' failed')
if (-not $KeepTemp) { Remove-Item $tmp -Recurse -Force -EA SilentlyContinue }
if ($fail -gt 0) { exit 1 }
exit 0
