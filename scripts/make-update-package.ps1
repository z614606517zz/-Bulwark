# =====================================================================
#  生成(并可选发布)一份在线更新载荷。
#
#  产物:<OutDir>\<channel>\
#      manifest.json          版本 / 标题 / 更新说明 / 文件清单
#      bulwark_service.exe    已签名
#      bulwark_ui.exe         已签名
#      Bulwark.sys            已签名
#
#  服务器侧目录:/opt/bulwark-intel/update/<channel>/
#  接口:GET /v1/update/manifest?channel=<channel>
#        GET /v1/update/file/<channel>/<name>
#
#  三道拒绝条件(都不是形式检查,每一条对应一种真实会发生的事故)
#  ------------------------------------------------------------------
#  1) 载荷未签名 / 签名者不是 UpdateTrust.h 里钉死的那张证书
#     -> 客户端第四道校验必然失败,更新永远装不上,而现象只是「更新被拒绝」。
#  2) exe 里的 FileVersion 与要发布的版本号不一致
#     -> 最阴的一种:清单说 1.2.0,装上去的 exe 还报 1.1.0,于是客户端每次检查都
#        认为「还有新版本」,无限循环提示更新。必须在发布前就拦住。
#  3) 更新说明为空
#     -> 弹窗里那块区域就是给用户看「这次改了什么」的。空着等于让用户对一个要替换
#        内核驱动的操作盲签。
#
#  用法
#      powershell -ExecutionPolicy Bypass -File scripts\make-update-package.ps1 `
#          -Channel beta -Label "1.1.1 测试版" -NotesFile notes.md
#      ... -Publish            # 额外 scp 到服务器并回读接口验证
#
#  ⚠ 本文件必须带 UTF-8 BOM。PS 5.1 在 zh-CN 上把无 BOM 的 .ps1 按 GBK 解码,下面这些
#    中文注释里的全角括号/逗号会被误读成别的字节,进而把后面的花括号配对搞断,报出一个
#    指向无关行的「意外的标记 }」。实测踩过两次(test-uninstall.ps1 也是同一个坑)。
# =====================================================================
[CmdletBinding()]
param(
    [ValidateSet('stable', 'beta')][string]$Channel = 'beta',
    [string]$Label = '',
    [string]$NotesFile = '',
    [string]$Notes = '',
    [string]$OutDir = '',
    [switch]$Publish,
    # 同 deploy-release.ps1:不写死地址(公开文件 + 误推风险)。
    [string]$Server = $env:BULWARK_DEPLOY_SERVER,
    [string]$User = 'root',
    [string]$RemoteRoot = '/opt/bulwark-intel/update'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'cpp\dist'
if (-not $OutDir) { $OutDir = Join-Path $root 'build_update' }

function Step($m) { Write-Host ''; Write-Host "== $m ==" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Info($m) { Write-Host "       $m" -ForegroundColor DarkGray }
function Die($m)  { throw $m }

# 只有 -Publish 才需要连服务器。不加 -Publish 时本脚本纯本地产出更新包,
# 此时要求一个地址毫无意义,所以这个检查只在真要上传时生效。
if ($Publish -and [string]::IsNullOrWhiteSpace($Server)) {
    Die ('-Publish 需要目标服务器。用 -Server <主机> 传入,或设置环境变量 ' +
         'BULWARK_DEPLOY_SERVER。')
}

# ---- 1) 要发布的版本号:以 VersionNumbers.h 为唯一来源 ----------------------
Step 'version'
$vh = Join-Path $root 'cpp\shared\include\bulwark\VersionNumbers.h'
$vm = [regex]::Match([IO.File]::ReadAllText($vh), 'BULWARK_VERSION_STRING\s+"([0-9][0-9A-Za-z.\-]*)"')
if (-not $vm.Success) { Die "cannot read BULWARK_VERSION_STRING from $vh" }
$version = $vm.Groups[1].Value
Ok ("publishing version " + $version + "  (channel " + $Channel + ")")

# ---- 2) 钉死的签名者 -------------------------------------------------------
$th = Join-Path $root 'cpp\shared\include\bulwark\UpdateTrust.h'
$tm = [regex]::Match([IO.File]::ReadAllText($th), 'BULWARK_UPDATE_SIGNER_THUMBPRINT\s+"([0-9A-Fa-f]{40})"')
if (-not $tm.Success) { Die "cannot read BULWARK_UPDATE_SIGNER_THUMBPRINT from $th" }
$pin = $tm.Groups[1].Value.ToUpper()
Info ("pinned signer: " + $pin)

# ---- 3) 更新说明 -----------------------------------------------------------
if ($NotesFile) {
    if (-not (Test-Path $NotesFile)) { Die "notes file not found: $NotesFile" }
    $Notes = [IO.File]::ReadAllText($NotesFile, [Text.Encoding]::UTF8)
}
if (-not $Notes.Trim()) {
    Die 'refusing to publish without release notes -- the dialog would ask the user to blind-approve replacing a kernel driver'
}
if (-not $Label) { $Label = $version }

# ---- 4) 收集并校验载荷 -----------------------------------------------------
Step 'payload'
$names = @('bulwark_service.exe', 'bulwark_ui.exe', 'Bulwark.sys')
$dest = Join-Path $OutDir $Channel
if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
New-Item -ItemType Directory -Path $dest -Force | Out-Null

$files = @()
foreach ($n in $names) {
    $src = Join-Path $dist $n
    if (-not (Test-Path $src)) { Die "missing payload: $src" }

    $sig = Get-AuthenticodeSignature $src
    if (-not $sig.SignerCertificate) { Die "$n is UNSIGNED -- run scripts\sign-binaries.ps1 -FromBuild first" }
    $tp = $sig.SignerCertificate.Thumbprint.ToUpper()
    if ($tp -ne $pin) { Die "$n is signed by $tp, not the pinned $pin -- the client would reject it" }
    if ($sig.Status -eq 'HashMismatch') { Die "$n signature does not match its bytes" }

    # exe 的 FileVersion 必须等于要发布的版本号(.sys 没有 VERSIONINFO,跳过)。
    if ($n -like '*.exe') {
        $fv = (Get-Item $src).VersionInfo.FileVersion
        if (-not $fv) { Die "$n carries no FileVersion resource" }
        if ($fv.Trim() -ne $version) {
            Die ("$n reports FileVersion $fv but the release says $version -- publishing this would make " +
                 'every client offer the update forever (it installs, still reports the old version, ' +
                 'and the next check finds "a newer version" again)')
        }
    }

    Copy-Item $src (Join-Path $dest $n) -Force
    $fi = Get-Item (Join-Path $dest $n)
    $sha = (Get-FileHash $fi.FullName -Algorithm SHA256).Hash.ToLower()
    $files += [ordered]@{ name = $n; size = $fi.Length; sha256 = $sha }
    Ok ("{0,-22} {1,9} B  sha={2}  sig ok" -f $n, $fi.Length, $sha.Substring(0, 16))
}

# ---- 5) manifest -----------------------------------------------------------
# 服务器会用磁盘上的真实大小/哈希覆盖这里声明的值(见 app.py 的 _update_manifest_obj),
# 所以清单里的 files[] 主要是「这一份发布包含哪些文件」的白名单;哈希写进来便于本地核对。
Step 'manifest'
$manifest = [ordered]@{
    version   = $version
    label     = $Label
    published = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    notes     = $Notes
    files     = $files
}
$json = $manifest | ConvertTo-Json -Depth 6
# UTF-8 无 BOM:服务器用 json.loads(f.read().decode("utf-8")),BOM 会让它抛 ValueError。
[IO.File]::WriteAllText((Join-Path $dest 'manifest.json'), $json, (New-Object Text.UTF8Encoding($false)))
Ok ('manifest.json written (' + $json.Length + ' chars)')
Info ('out: ' + $dest)

if (-not $Publish) {
    Step 'done (local only -- pass -Publish to upload)'
    return
}

# ---- 6) 发布 ---------------------------------------------------------------
Step 'publish'
$remote = "$RemoteRoot/$Channel"
& ssh -o BatchMode=yes -o ConnectTimeout=20 "$User@$Server" "mkdir -p '$remote'"
if ($LASTEXITCODE -ne 0) { Die "ssh mkdir failed ($LASTEXITCODE)" }

# 先传载荷、最后传 manifest.json。顺序是承重的:manifest 一旦落地,接口立刻开始对外
# 宣告这个版本可用;若此时载荷还没传完,客户端会拿到一份指向不存在文件的清单。
# (服务端对缺文件的情况会整份拒绝发布,但那只是兜底,不该依赖它来掩盖上传顺序错误。)
foreach ($n in $names) {
    & scp -o BatchMode=yes -o ConnectTimeout=20 (Join-Path $dest $n) "$($User)@$($Server):$remote/$n"
    if ($LASTEXITCODE -ne 0) { Die "scp $n failed ($LASTEXITCODE)" }
    Ok ("uploaded " + $n)
}
& scp -o BatchMode=yes -o ConnectTimeout=20 (Join-Path $dest 'manifest.json') "$($User)@$($Server):$remote/manifest.json"
if ($LASTEXITCODE -ne 0) { Die "scp manifest.json failed ($LASTEXITCODE)" }
Ok 'uploaded manifest.json (last, on purpose)'

& ssh -o BatchMode=yes -o ConnectTimeout=20 "$User@$Server" "ls -l '$remote'"

Step 'verify through the public endpoint'
$u = "https://vt.bulwark.icu:8787/v1/update/manifest?channel=$Channel"
$body = (curl.exe -s --max-time 25 $u) -join ''
Info $body
if ($body -notmatch '"available"\s*:\s*true') { Die 'endpoint does not report the release as available' }
if ($body -notmatch [regex]::Escape($version)) { Die 'endpoint manifest does not carry the expected version' }
Ok 'endpoint reports the release'
Write-Host ''
Write-Host "==== published $version to '$Channel' ====" -ForegroundColor Green
Write-Host ''
