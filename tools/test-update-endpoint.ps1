# =====================================================================
#  在线更新服务端接口的端到端检查。
#
#  为什么值得单独有一个脚本
#    发布一次更新牵动四方:manifest 的编码、载荷的哈希、下载路由的白名单、以及
#    「另一个频道不受影响」。任一处出错的现象都长得像「更新失败」,而分辨它们要靠
#    一组固定的对照。把这组对照写下来,每次发布后跑一遍即可。
#
#  只读:不上传、不改服务器任何东西。
#
#  用法
#      powershell -ExecutionPolicy Bypass -File tools\test-update-endpoint.ps1
#      ... -Channel beta -ExpectVersion 1.1.1
#
#  ASCII-only(PS 5.1 在 zh-CN 上把无 BOM 的 .ps1 按 GBK 读)。需要断言中文时用
#  字符码拼出来,而不是写中文字面量 —— 这样本文件永远不依赖 BOM。
# =====================================================================
[CmdletBinding()]
param(
    [string]$BaseUrl = 'https://vt.bulwark.icu:8787',
    [ValidateSet('stable', 'beta')][string]$Channel = 'beta',
    [string]$ExpectVersion = '',
    # Compare the downloaded payload against this local copy (the one that was published).
    [string]$LocalDist = '',
    # 更新说明里必须出现的字样。刻意做成参数而不是写死:这里曾经硬编码过某一个
    # 版本说明里的「只查收录」,于是每发一版新说明就多一条假失败,而真正要防的
    # (说明被双重编码成乱码)另有一条断言在管。
    [string]$ExpectNotesContain = ''
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
if (-not $LocalDist) { $LocalDist = Join-Path $root 'cpp\dist' }

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok, [string]$detail) {
    if ($ok) { Write-Host ('  PASS  ' + $label) -ForegroundColor Green; $script:pass++ }
    else {
        Write-Host ('  FAIL  ' + $label) -ForegroundColor Red
        if ($detail) { Write-Host ('        ' + $detail) -ForegroundColor DarkGray }
        $script:fail++
    }
}
function Info($m) { Write-Host ('        ' + $m) -ForegroundColor DarkGray }

# 中文断言串,用码位拼出来(见文件头说明)。
$CN_SUMMARY = [string]([char]0x66F4 + [char]0x65B0 + [char]0x6458 + [char]0x8981)  # 更新摘要


Write-Host ''
Write-Host ("=== update endpoint: " + $BaseUrl + "  channel=" + $Channel + " ===") -ForegroundColor Cyan

# ---- 1) manifest -----------------------------------------------------------
# Invoke-RestMethod 按 charset 正确解码 UTF-8。刻意不用 curl 再读 stdout:
# 控制台在 zh-CN 上按 GBK 解码,中文会显示成乱码,让人误以为服务器上的数据坏了
# (实测被这一点骗过一次 —— 当时 manifest 的字节其实与本地完全一致)。
$man = $null
try { $man = Invoke-RestMethod -Uri ($BaseUrl + '/v1/update/manifest?channel=' + $Channel) -TimeoutSec 25 }
catch { Check 'manifest fetch' $false $_.Exception.Message }

if ($man) {
    Check 'manifest ok=true'        ([bool]$man.ok)        ('ok=' + $man.ok)
    Check 'manifest available=true' ([bool]$man.available) ('reason=' + $man.reason)
    if ($ExpectVersion) {
        Check ('version = ' + $ExpectVersion) ($man.version -eq $ExpectVersion) ('got ' + $man.version)
    } else { Info ('version = ' + $man.version) }
    Info ('label = ' + $man.label + '   published = ' + $man.published)
    Info ('files = ' + @($man.files).Count + '   totalBytes = ' + $man.totalBytes)

    # 更新说明必须是可读中文,而不是双重编码后的产物。这一条防的是真实会发生的事故:
    # 清单在某一环被按 GBK 读过一次,弹窗里就会显示一片乱码,而接口本身一切正常。
    Check 'notes decode as readable Chinese' ($man.notes -and $man.notes.Contains($CN_SUMMARY)) `
        ('first 40 chars: ' + $(if ($man.notes) { $man.notes.Substring(0, [Math]::Min(40, $man.notes.Length)) } else { '(empty)' }))
    if ($ExpectNotesContain) {
        Check 'notes contain the expected phrase' ($man.notes -and $man.notes.Contains($ExpectNotesContain)) `
            ('looking for: ' + $ExpectNotesContain)
    } else {
        Info 'notes phrase check skipped (pass -ExpectNotesContain to enable)'
    }

    foreach ($f in @($man.files)) {
        Check ('file entry sane: ' + $f.name) `
            (($f.size -gt 0) -and ($f.sha256 -match '^[0-9a-f]{64}$') -and ($f.url -like ('/v1/update/file/' + $Channel + '/*'))) `
            ('size=' + $f.size + ' url=' + $f.url)
    }

    # ---- 2) 真下载一个文件,三方对哈希 ----------------------------------
    # 服务器声明的 sha256、实际下载到的字节、以及本地发布出去的那份,三者必须一致。
    # 只比其中两个都会漏掉一类故障:比「声明 vs 下载」漏掉「发布时传错文件」,
    # 比「本地 vs 下载」漏掉「清单里的哈希写错」。
    $first = @($man.files)[0]
    if ($first) {
        Write-Host ''
        Write-Host ('--- download ' + $first.name + ' ---') -ForegroundColor Cyan
        $tmp = Join-Path $env:TEMP ('bw-updtest-' + $first.name)
        Remove-Item $tmp -Force -EA SilentlyContinue
        $code = (& curl.exe -s -o $tmp -w '%{http_code}' --max-time 120 ($BaseUrl + $first.url))
        Check 'download HTTP 200' ($code -eq '200') ('http=' + $code)
        if (Test-Path $tmp) {
            $got = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower()
            Check 'size matches manifest' ((Get-Item $tmp).Length -eq $first.size) `
                ('got ' + (Get-Item $tmp).Length + ' want ' + $first.size)
            Check 'sha256 matches manifest' ($got -eq $first.sha256.ToLower()) ('got ' + $got.Substring(0, 16))
            $localFile = Join-Path $LocalDist $first.name
            if (Test-Path $localFile) {
                $loc = (Get-FileHash $localFile -Algorithm SHA256).Hash.ToLower()
                Check 'sha256 matches the local published copy' ($got -eq $loc) ('local ' + $loc.Substring(0, 16))
            } else { Info ('no local copy to compare: ' + $localFile) }

            # 客户端的第四道校验就是这一条。这里先在服务端产物上验一遍:签名者不对的话,
            # 无论清单和哈希多完美,客户端都会(正确地)拒绝安装。
            $sig = Get-AuthenticodeSignature $tmp
            $tp = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint.ToUpper() } else { '' }
            $th = Join-Path $root 'cpp\shared\include\bulwark\UpdateTrust.h'
            $pin = ''
            if (Test-Path $th) {
                $m2 = [regex]::Match((Get-Content -LiteralPath $th -Raw), 'BULWARK_UPDATE_SIGNER_THUMBPRINT\s+"([0-9A-Fa-f]{40})"')
                if ($m2.Success) { $pin = $m2.Groups[1].Value.ToUpper() }
            }
            Check 'downloaded payload signed by the pinned cert' ($pin -ne '' -and $tp -eq $pin) `
                ('signer=' + $tp + ' pinned=' + $pin)
            Info ('authenticode status = ' + $sig.Status +
                  '  (UnknownError just means this box does not trust the self-signed root)')
            Remove-Item $tmp -Force -EA SilentlyContinue
        }
    }
}

# ---- 3) 频道各自独立解析 ---------------------------------------------------
Write-Host ''
Write-Host '--- isolation + hardening ---' -ForegroundColor Cyan
$other = if ($Channel -eq 'beta') { 'stable' } else { 'beta' }
try {
    $o = Invoke-RestMethod -Uri ($BaseUrl + '/v1/update/manifest?channel=' + $other) -TimeoutSec 20
    # 原先这里断言的是 -not $o.available,也就是「另一个频道从未发布过任何东西」。
    # 那只在「只往一个频道发过」的那段时间成立;两个频道都发布之后,它变成一条恒定
    # 的假失败 —— 而假失败会训练人忽略整份报告。
    #
    # 无论发布状态如何都成立的判据是「另一个频道能独立回应且自身自洽」。
    # 同时必须说清楚它测不到什么:两个频道停在同一版本时,「串频道」与「各自独立
    # 但内容恰好相同」在接口外部无法区分。要真正测隔离,得给两个频道发不同版本号。
    Check ($other + ' channel resolves independently') ([bool]$o.ok) `
        ('ok=' + $o.ok + ' available=' + $o.available + ' version=' + $o.version)
    if ($o.available -and $man.version -eq $o.version) {
        Info ('both channels sit at ' + $o.version + ' -- cross-channel bleed is NOT distinguishable from here')
    }
} catch { Check ($other + ' channel reachable') $false $_.Exception.Message }

# ---- 4) 路径穿越 / 非载荷文件 ---------------------------------------------
# 这两条是安全断言,不是形式检查:清单由服务器提供,而文件名会被拼进路径。
$cases = @(
    @{ p = '/v1/update/file/' + $Channel + '/..%2f..%2fapp.py'; want = '400'; why = 'path traversal' },
    @{ p = '/v1/update/file/' + $Channel + '/manifest.json';    want = '404'; why = 'file not in the release' },
    @{ p = '/v1/update/file/' + $Channel;                        want = '400'; why = 'missing file name' },
    @{ p = '/v1/update/manifest?channel=bogus';                  want = '400'; why = 'unknown channel' }
)
foreach ($c in $cases) {
    $code = (& curl.exe -s -o NUL -w '%{http_code}' --max-time 20 ($BaseUrl + $c.p))
    Check ($c.why + ' -> HTTP ' + $c.want) ($code -eq $c.want) ('got ' + $code + ' for ' + $c.p)
}

Write-Host ''
Write-Host ('result: ' + $pass + ' passed, ' + $fail + ' failed') `
    -ForegroundColor $(if ($fail -gt 0) { 'Red' } else { 'Green' })
Write-Host ''
if ($fail -gt 0) { exit 1 }
exit 0
