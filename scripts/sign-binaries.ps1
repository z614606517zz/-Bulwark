# =====================================================================
#  给 cpp\dist 里的用户态可执行体做 Authenticode 签名。
#
#  为什么这一步是【必需】而不是可选
#  ------------------------------------------------------------------
#  在线更新的本质是「从网上取一段代码,放进安装目录,以 SYSTEM 跑起来」。
#  唯一挡得住「服务器被拿下 / TLS 被中间人拆开」的判据,是每个要装进去的 PE 都带
#  我们的签名,且签名者证书指纹在客户端编译期钉死的名单里(见 UpdateTrust.h)。
#
#  服务器给的 SHA-256 不是判据:哈希是服务器自己声明的,攻击者控制服务器就同时
#  控制文件和哈希。哈希只能证明「下载没坏」。
#
#  在此之前只有 Bulwark.sys 有签名(内核不签根本加载不了),两个 exe 一直是
#  NotSigned —— 于是更新通道要么永远校验失败、要么被迫退化成「只比哈希」。所以
#  打包链路必须先过这一步。
#
#  前提
#    · 证书 CN=BulwarkTestCert 带私钥,装在 LocalMachine\My
#    · 访问 LocalMachine 私钥【需要管理员权限】。不提权时 signtool 只会报
#      "No certificates were found that met all the given criteria",看不出是权限问题。
#    · signtool.exe 来自 Windows SDK
#
#  用法
#      powershell -ExecutionPolicy Bypass -File scripts\sign-binaries.ps1
#      ... -FromBuild        # 先把 cpp\build 的产物同步进 dist,再签
#      ... -WhatIfOnly       # 只体检(证书/工具/当前签名状态),不签
#
#  ASCII-only(PS 5.1 在 zh-CN 上把无 BOM 的 .ps1 按 GBK 读)。
# =====================================================================
[CmdletBinding()]
param(
    [string]$CertSubject = 'BulwarkTestCert',
    [switch]$FromBuild,
    [switch]$WhatIfOnly,
    # Timestamping keeps a signature verifiable after the cert expires. It needs
    # network, so it is attempted and then skipped rather than being fatal.
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'cpp\dist'
$targets = @('bulwark_service.exe', 'bulwark_ui.exe')

function Step($m) { Write-Host ''; Write-Host "== $m ==" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Bad($m)  { Write-Host "  [X]  $m" -ForegroundColor Red }
function Info($m) { Write-Host "       $m" -ForegroundColor DarkGray }
function Die($m)  { throw $m }

# ---- 0) elevation ----------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Step 'preconditions'
if ($isAdmin) { Ok 'running elevated' }
else {
    Bad 'NOT elevated -- the private key lives in LocalMachine\My and cannot be read'
    Info 'signtool would fail with a misleading "no certificates were found" error.'
    if (-not $WhatIfOnly) { Die 'run this from an elevated shell' }
}

# ---- 1) certificate --------------------------------------------------------
$cert = @(Get-ChildItem 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
          Where-Object { $_.Subject -like "*$CertSubject*" -and $_.HasPrivateKey } |
          Sort-Object NotAfter -Descending)
if ($cert.Count -eq 0) { Die "no code-signing cert with a private key matching *$CertSubject* in LocalMachine\My" }
$c = $cert[0]
Ok ("cert: " + $c.Subject)
Info ("thumbprint : " + $c.Thumbprint)
Info ("valid until: " + $c.NotAfter.ToString('yyyy-MM-dd') +
      "  (" + [int]($c.NotAfter - (Get-Date)).TotalDays + " days left)")
if ($c.NotAfter -lt (Get-Date).AddDays(60)) {
    Warn 'cert expires within 60 days -- plan a rotation (UpdateTrust.h + bulwark.ps1 pin both need the new thumbprint)'
}

# ---- 2) the pin invariant --------------------------------------------------
# The whole update trust model is "the shipped binaries are signed by the cert
# whose thumbprint is compiled into the client". If this signing step used a
# different cert than the one pinned, every update would fail signature
# verification on the user's machine -- and the only symptom would be a refused
# update with no obvious cause. Catch it here, at signing time.
Step 'pinned thumbprint must match this cert'
$trustH = Join-Path $root 'cpp\shared\include\bulwark\UpdateTrust.h'
if (-not (Test-Path $trustH)) { Die "missing $trustH" }
$m = [regex]::Match([IO.File]::ReadAllText($trustH),
                    'BULWARK_UPDATE_SIGNER_THUMBPRINT\s+"([0-9A-Fa-f]{40})"')
if (-not $m.Success) { Die 'UpdateTrust.h does not define BULWARK_UPDATE_SIGNER_THUMBPRINT' }
$pinned = $m.Groups[1].Value.ToUpper()
Info ("pinned in UpdateTrust.h : " + $pinned)
if ($pinned -ne $c.Thumbprint.ToUpper()) {
    Bad 'MISMATCH -- signing with this cert would produce updates the client rejects'
    Info ("  signing cert : " + $c.Thumbprint.ToUpper())
    Info ("  pinned       : " + $pinned)
    Die 'update the pin in cpp\shared\include\bulwark\UpdateTrust.h (and bulwark.ps1), then re-run'
}
Ok 'pin matches the signing cert'

# The shipped driver is signed by the same cert; if it is not, the package would
# carry two different signers and the pin could only ever cover one of them.
$sys = Join-Path $dist 'Bulwark.sys'
if (Test-Path $sys) {
    $ds = Get-AuthenticodeSignature $sys
    if ($ds.SignerCertificate) {
        if ($ds.SignerCertificate.Thumbprint.ToUpper() -eq $pinned) { Ok 'dist Bulwark.sys signed by the same cert' }
        else { Warn ('dist Bulwark.sys is signed by a DIFFERENT cert: ' + $ds.SignerCertificate.Thumbprint) }
    } else { Warn 'dist Bulwark.sys carries no signature' }
} else { Warn 'no Bulwark.sys in dist (driver not staged yet)' }

# ---- 3) signtool -----------------------------------------------------------
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe `
              -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } |
            Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { Die 'signtool.exe not found (install the Windows SDK)' }
Ok ('signtool: ' + $signtool.FullName)

# ---- 4) optionally refresh dist from the build tree ------------------------
if ($FromBuild) {
    Step 'sync build output -> dist'
    $map = @{
        'bulwark_service.exe' = Join-Path $root 'cpp\build\service\Release\bulwark_service.exe'
        'bulwark_ui.exe'      = Join-Path $root 'cpp\build\ui\Release\bulwark_ui.exe'
    }
    if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Path $dist -Force | Out-Null }
    foreach ($n in $targets) {
        $src = $map[$n]
        if (-not (Test-Path $src)) { Die "build output missing: $src (build first)" }
        $dst = Join-Path $dist $n
        # Signing is destructive to the previous signature, and dist is what gets
        # packaged. Keep one backup so a bad sign run is recoverable without a rebuild.
        if (Test-Path $dst) {
            Copy-Item $dst ($dst + '.presign.bak') -Force
        }
        Copy-Item $src $dst -Force
        Ok ("{0,-22} {1,9} B  <- build" -f $n, (Get-Item $dst).Length)
    }
}

# ---- 5) state before ------------------------------------------------------
Step 'current signature state'
foreach ($n in $targets) {
    $p = Join-Path $dist $n
    if (-not (Test-Path $p)) { Bad "missing in dist: $n"; continue }
    $s = Get-AuthenticodeSignature $p
    Info ("{0,-22} {1,9} B  {2}" -f $n, (Get-Item $p).Length, $s.Status)
}
if ($WhatIfOnly) { Step 'WhatIfOnly -- nothing signed'; return }

# ---- 6) sign ---------------------------------------------------------------
Step 'sign'
$signed = 0
foreach ($n in $targets) {
    $p = Join-Path $dist $n
    if (-not (Test-Path $p)) { continue }
    # /sm = machine store, /s My, /sha1 <thumbprint> = pick exactly this cert
    # (never "whichever cert happens to match a subject substring").
    $args = @('sign', '/q', '/sm', '/s', 'My', '/sha1', $c.Thumbprint, '/fd', 'sha256')
    $withTs = $args + @('/tr', $TimestampUrl, '/td', 'sha256', $p)
    & $signtool.FullName @withTs 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Warn ("timestamping failed for $n (offline?) -- signing without a timestamp")
        Info 'a signature without a timestamp stops verifying once the cert expires'
        & $signtool.FullName @($args + @($p)) 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Die "signtool failed for $n (exit $LASTEXITCODE)" }
    }
    $signed++
    Ok ("signed $n")
}

# ---- 7) verify ------------------------------------------------------------
# Verify by reading the signature back, not by trusting signtool's exit code.
# Status is expected to be Valid on this machine because the test cert is in the
# local Root store; on a clean box it would be UnknownError, which is fine --
# what matters for the updater is "signed by the pinned thumbprint", and that is
# exactly what the client checks (see UpdateTrust.h).
Step 'verify'
$bad = 0
foreach ($n in $targets) {
    $p = Join-Path $dist $n
    if (-not (Test-Path $p)) { continue }
    $s = Get-AuthenticodeSignature $p
    $tp = if ($s.SignerCertificate) { $s.SignerCertificate.Thumbprint.ToUpper() } else { '(none)' }
    $okSig = ($s.Status -ne 'NotSigned') -and ($tp -eq $pinned)
    if ($okSig) { Ok ("{0,-22} {1,-12} signer={2}" -f $n, $s.Status, $tp) }
    else { Bad ("{0,-22} {1,-12} signer={2}" -f $n, $s.Status, $tp); $bad++ }
    if ($s.TimeStamperCertificate) { Info '  timestamped: yes' } else { Info '  timestamped: no' }
}
Write-Host ''
if ($bad -gt 0) { Die "$bad binary(ies) are not correctly signed" }
Write-Host "==== $signed binary(ies) signed and verified against the pinned thumbprint ====" -ForegroundColor Green
Write-Host ''
