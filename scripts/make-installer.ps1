# =====================================================================
#  Build the Bulwark installer package.
#
#  Output layout (under -Out):
#      Bulwark-<ver>-Setup\            the package the user runs
#          安装.bat                     double-click entry point
#          安装说明.txt
#          install.ps1
#          app\                        everything that lands in the install dir
#              bulwark_service.exe bulwark_ui.exe Bulwark.sys appsettings.json
#              app.ico  Qt6*.dll  msvcp140*.dll  vcruntime140*.dll
#              platforms\ styles\ imageformats\ networkinformation\ tls\
#              bulwark.ps1  卸载.bat  uninstall.ps1  体检.bat  收集日志.bat
#      Bulwark-<ver>-Setup.zip         same tree, for handing over
#      SHA256.txt
#
#  WHY A PLAIN FOLDER AND NOT A SELF-EXTRACTING .EXE
#    Measured on this box, not assumed. Two stubs were tried:
#      * C:\Program Files\7-Zip\7z.sfx and 7zCon.sfx ignore config.txt's
#        RunProgram entirely (that feature lives in 7zS/7zSD.sfx, which ship in
#        the separate "7-Zip Extra" download). The marker file never appeared.
#      * iexpress.exe (built into Windows) worked mechanically -- it extracted to
#        %TEMP%\IXP000.TMP and launched the setup batch -- and then THIS PRODUCT
#        judged the stub malicious and shut it down mid-run: audit recorded
#        ImageLoad risk 80 "unsigned module loaded from a high-risk writable
#        directory (suspected sideloading, T1574.002)" -> Block, followed by a
#        kernel no-load entry, the process being frozen, and setup.bat plus
#        install.ps1 being registered as dropped payloads for 30 days.
#    An installer that the recipient's AV freezes is not an installer. A plain
#    folder has none of those behaviours: nothing self-extracts, no script is
#    written into %TEMP%, no RunOnce cleanup key is planted. It is also
#    inspectable, which matters for something that asks for admin and then loads
#    a kernel driver.
#
#  NEVER WRITE INTO cpp\dist
#    The running service's install directory is guarded by the kernel SelfGuard
#    list (only the product's own processes may write there), so signing in place
#    would fail with an unhelpful access-denied. Binaries are copied to a staging
#    directory first and signed there.
#
#  Usage
#      powershell -ExecutionPolicy Bypass -File scripts\make-installer.ps1 `
#          -Out "C:\Users\1\Desktop\新建文件夹 (2)"
#      ... -NoSign        skip Authenticode signing (produces a package the
#                         installer itself will then REFUSE to install)
#      ... -KeepStaging   leave the staging tree for inspection
#
#  ENCODING
#    This file carries a UTF-8 BOM, which is required: it has to name CJK files
#    (安装.bat, 卸载.bat, 安装说明.txt ...) as string literals. Windows PowerShell
#    5.1 on a Chinese Windows reads a BOM-less UTF-8 .ps1 as GBK, and those
#    literals would turn into paths that never match anything. The repo's other
#    packaging scripts are ASCII-only precisely because they lack a BOM; the ones
#    that carry a BOM (packaging\portable-scripts\bulwark.ps1) are full of CJK and
#    are fine. The gate at step 3 enforces the same rule on everything shipped.
# =====================================================================
[CmdletBinding()]
param(
    [string]$Out = 'C:\Users\1\Desktop\新建文件夹 (2)',
    [switch]$NoSign,
    [switch]$KeepStaging,
    [string]$CertSubject = 'BulwarkTestCert'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'cpp\dist'
$instSrc = Join-Path $root 'packaging\installer'
$portSrc = Join-Path $root 'packaging\portable-scripts'

function Step($m) { Write-Host ''; Write-Host ("== " + $m + " ==") -ForegroundColor Cyan }
function Ok($m)   { Write-Host ("  [OK] " + $m) -ForegroundColor Green }
function Warn($m) { Write-Host ("  [!]  " + $m) -ForegroundColor Yellow }
function Info($m) { Write-Host ("       " + $m) -ForegroundColor DarkGray }
function Die($m)  { throw $m }

$isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---- 0) version + the one pinned thumbprint --------------------------------
Step 'version and the pinned signer'
$vh = Join-Path $root 'cpp\shared\include\bulwark\VersionNumbers.h'
if (-not (Test-Path $vh)) { Die "missing $vh" }
$vm = [regex]::Match([IO.File]::ReadAllText($vh), 'BULWARK_VERSION_STRING\s+"([0-9\.]+)"')
if (-not $vm.Success) { Die 'VersionNumbers.h does not define BULWARK_VERSION_STRING' }
$version = $vm.Groups[1].Value
Ok ("product version : " + $version)

$th = Join-Path $root 'cpp\shared\include\bulwark\UpdateTrust.h'
if (-not (Test-Path $th)) { Die "missing $th" }
$tm = [regex]::Match([IO.File]::ReadAllText($th),
                     'BULWARK_UPDATE_SIGNER_THUMBPRINT\s+"([0-9A-Fa-f]{40})"')
if (-not $tm.Success) { Die 'UpdateTrust.h does not define BULWARK_UPDATE_SIGNER_THUMBPRINT' }
$pinned = $tm.Groups[1].Value.ToUpper()
Ok ("pinned signer   : " + $pinned)

# install.ps1 carries the same thumbprint so it can reject a tampered package
# before touching the target system. If those two ever drift, the installer would
# reject a perfectly good package (or accept a bad one) -- so this is a build gate,
# not a warning.
$instPs1 = Join-Path $instSrc 'install.ps1'
if (-not (Test-Path $instPs1)) { Die "missing $instPs1" }
$im = [regex]::Match([IO.File]::ReadAllText($instPs1, [Text.Encoding]::UTF8),
                     "\`$PinnedThumbprint\s*=\s*'([0-9A-Fa-f]{40})'")
if (-not $im.Success) { Die 'install.ps1 does not define $PinnedThumbprint' }
if ($im.Groups[1].Value.ToUpper() -ne $pinned) {
    Die ("pin mismatch: install.ps1 has " + $im.Groups[1].Value.ToUpper() +
         " but UpdateTrust.h has " + $pinned)
}
Ok 'install.ps1 pin matches UpdateTrust.h'

# install.ps1 also states the version in its banner; a stale number there would
# put the wrong DisplayVersion into Add/Remove Programs.
$ivm = [regex]::Match([IO.File]::ReadAllText($instPs1, [Text.Encoding]::UTF8),
                      "\`$Version\s*=\s*'([0-9\.]+)'")
if (-not $ivm.Success) { Die 'install.ps1 does not define $Version' }
if ($ivm.Groups[1].Value -ne $version) {
    Die ("version mismatch: install.ps1 says " + $ivm.Groups[1].Value + ", sources say " + $version)
}
Ok 'install.ps1 version matches the sources'

# ---- 1) staleness guard ----------------------------------------------------
# A binary older than its own sources looks fine and quietly lacks whatever was
# added since. The driver gets a louder treatment: see the note below.
Step 'staleness guard'
function NewestSrc($dirs, $includes) {
    $existing = @($dirs | Where-Object { Test-Path $_ })
    if ($existing.Count -eq 0) { return $null }
    Get-ChildItem $existing -Recurse -Include $includes -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\build' } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
$checks = @(
    @{ Name = 'bulwark_service.exe'
       Src  = (NewestSrc @((Join-Path $root 'cpp\service'), (Join-Path $root 'cpp\shared')) @('*.cpp','*.h')) },
    @{ Name = 'bulwark_ui.exe'
       Src  = (NewestSrc @((Join-Path $root 'cpp\ui'), (Join-Path $root 'cpp\shared')) @('*.cpp','*.h','*.qrc')) }
)
$stale = @()
foreach ($c in $checks) {
    $bin = Join-Path $dist $c.Name
    if (-not (Test-Path $bin)) { $stale += ($c.Name + ' (missing in dist)'); continue }
    $b = Get-Item $bin
    if ($c.Src -and $c.Src.LastWriteTime -gt $b.LastWriteTime) {
        $stale += ("{0} (built {1}, source {2} is {3})" -f $c.Name,
                   $b.LastWriteTime.ToString('MM-dd HH:mm'), $c.Src.Name,
                   $c.Src.LastWriteTime.ToString('MM-dd HH:mm'))
        Warn ('STALE  ' + $c.Name)
    } else {
        Ok ("{0,-22} built {1}" -f $c.Name, $b.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))
    }
}
if ($stale.Count -gt 0) {
    Write-Host ''
    foreach ($s in $stale) { Warn ('  - ' + $s) }
    Die 'rebuild first: the above artifacts are older than their sources'
}

# The DRIVER is deliberately taken from dist and NOT from build\driver, and it is
# deliberately NOT subject to the source-newer-than-binary check above.
#
# Reason: build\driver holds a freshly changed but UNSIGNED driver whose own
# handover notes (.kiro\specs\driver-hardening\progress.md) state it has never
# been loaded or accepted in a VM -- the riskiest part being the WFP two-layer
# teardown path, where a missed callout is a bugcheck. Shipping that to someone
# else's machine would mean handing over an unvalidated kernel module. dist holds
# the signed driver that is currently loaded and exercised on this box, so that
# is what goes in the package. Swap it deliberately, after a VM run, not by
# accident because a timestamp moved.
$sysSrc = Join-Path $dist 'Bulwark.sys'
if (-not (Test-Path $sysSrc)) { Die "missing $sysSrc" }
$sysSig = Get-AuthenticodeSignature $sysSrc
if (-not $sysSig.SignerCertificate) { Die 'dist Bulwark.sys carries no signature' }
if ($sysSig.Status -eq 'HashMismatch') { Die 'dist Bulwark.sys signature does not match its bytes' }
if ($sysSig.SignerCertificate.Thumbprint.ToUpper() -ne $pinned) {
    Die ('dist Bulwark.sys is signed by an unpinned cert: ' + $sysSig.SignerCertificate.Thumbprint.ToUpper())
}
Ok ("Bulwark.sys            built {0}  sig={1}  signer=pinned" -f
    (Get-Item $sysSrc).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'), $sysSig.Status)
$newerDrv = NewestSrc @((Join-Path $root 'Bulwark.Driver')) @('*.c','*.h')
if ($newerDrv -and $newerDrv.LastWriteTime -gt (Get-Item $sysSrc).LastWriteTime) {
    Warn ('driver sources are newer than the shipped .sys (' + $newerDrv.Name + ' ' +
          $newerDrv.LastWriteTime.ToString('MM-dd HH:mm') + ')')
    Info 'that is intentional here: the newer build is unsigned and not VM-validated.'
    Info 'to ship it, build + sign it, validate it in a snapshot VM, then refresh cpp\dist.'
}

# ---- 2) staging ------------------------------------------------------------
Step 'staging'
$stage = Join-Path $env:TEMP ('bulwark-setup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$app = Join-Path $stage 'app'
New-Item -ItemType Directory -Path $app -Force | Out-Null
Info ('staging: ' + $stage)

$core = @('bulwark_service.exe', 'bulwark_ui.exe', 'Bulwark.sys', 'appsettings.json', 'app.ico')
foreach ($n in $core) {
    $p = Join-Path $dist $n
    if (-not (Test-Path $p)) { Die ("missing in dist: " + $n) }
    Copy-Item $p (Join-Path $app $n) -Force
}
Ok ('core payload: ' + ($core -join ', '))

foreach ($dll in (Get-ChildItem (Join-Path $dist 'Qt6*.dll') -File)) {
    Copy-Item $dll.FullName (Join-Path $app $dll.Name) -Force
}
$crt = @('msvcp140.dll','msvcp140_1.dll','msvcp140_2.dll','vcruntime140.dll','vcruntime140_1.dll')
foreach ($n in $crt) {
    $p = Join-Path $dist $n
    if (-not (Test-Path $p)) { Die ("missing MSVC runtime in dist: " + $n) }
    Copy-Item $p (Join-Path $app $n) -Force
}
Ok ('Qt runtime + MSVC runtime (' + $crt.Count + ' CRT DLLs)')

# Plugin subdirectories. An EMPTY one is worse than an absent one: it reads as
# "the plugin is shipped" to anyone eyeballing the folder while nothing is there,
# which is exactly how a missing TLS backend stayed hidden before.
foreach ($sub in @('platforms','styles','imageformats','networkinformation','tls')) {
    $ss = Join-Path $dist $sub
    if (-not (Test-Path $ss)) { continue }
    $files = @(Get-ChildItem $ss -File -ErrorAction SilentlyContinue)
    if ($files.Count -eq 0) { continue }
    $dd = Join-Path $app $sub
    New-Item -ItemType Directory -Path $dd -Force | Out-Null
    foreach ($f in $files) { Copy-Item $f.FullName (Join-Path $dd $f.Name) -Force }
    Ok ("{0,-20} {1} file(s)" -f ($sub + '\'), $files.Count)
}
foreach ($must in @('platforms\qwindows.dll', 'styles\qmodernwindowsstyle.dll')) {
    if (-not (Test-Path (Join-Path $app $must))) { Die ("missing Qt plugin: " + $must) }
}
if (@(Get-ChildItem (Join-Path $app 'tls') -File -EA SilentlyContinue).Count -eq 0) {
    Die 'no TLS backend plugin staged -- every HTTPS lookup would fail silently'
}

# Scripts that live in the install directory.
#   bulwark.ps1 is shared verbatim with the portable package on purpose: it is
#   the file the rule engine whitelists by name for the maintenance channel
#   (RuleEngine.cpp kScripts), so 体检.bat / 收集日志.bat invoking it via -File
#   from the install directory are not scored as "powershell from a program dir".
#
#   卸载.bat is deliberately NOT shipped. The Setup.exe produced here carries
#   Inno's own uninstaller (registered in Add/Remove Programs), and that is the
#   one path that removes everything. A second, hand-rolled uninstall entry point
#   sitting in the install directory would run a DIFFERENT removal path that
#   knows nothing about Inno's file list or its Add/Remove entry -- a user who
#   double-clicked it would end up with a half-removed product still listed in
#   Windows. One uninstaller, one path.
$appScripts = @(
    @{ From = (Join-Path $portSrc 'bulwark.ps1');    Name = 'bulwark.ps1' },
    @{ From = (Join-Path $portSrc '收集日志.bat');    Name = '收集日志.bat' },
    @{ From = (Join-Path $instSrc 'uninstall.ps1');  Name = 'uninstall.ps1' },
    @{ From = (Join-Path $instSrc '体检.bat');        Name = '体检.bat' }
)
foreach ($s in $appScripts) {
    if (-not (Test-Path $s.From)) { Die ('missing script: ' + $s.From) }
    Copy-Item $s.From (Join-Path $app $s.Name) -Force
    Ok ('app script: ' + $s.Name)
}

# Files the .iss pulls straight from packaging\installer at compile time. They are
# not staged, but they DO end up inside Setup.exe, so they go through the same
# encoding gates below.
$srcSideFiles = @('install.ps1', 'bulwark.iss', '安装说明.txt', '许可与风险须知.txt')
foreach ($n in $srcSideFiles) {
    $p = Join-Path $instSrc $n
    if (-not (Test-Path $p)) { Die ('missing: ' + $p) }
    Ok ('compiled in from source: ' + $n)
}

# ---- 3) encoding gates -----------------------------------------------------
# Every .ps1 must carry a UTF-8 BOM (PS 5.1 on a zh-CN box reads a BOM-less
# .ps1 as GBK and turns every Chinese message into mojibake), and every .bat
# must be pure ASCII (cmd.exe tracks a BYTE offset while decoding with the
# active codepage; multi-byte CJK in a BOM-less batch desynchronises it and cmd
# starts executing the tail of a comment as a command).
Step 'encoding gates'
$gateFiles = @(Get-ChildItem $stage -Recurse -File) +
             @($srcSideFiles | ForEach-Object { Get-Item (Join-Path $instSrc $_) })
foreach ($f in ($gateFiles | Where-Object { $_.Extension -eq '.ps1' })) {
    $b = [IO.File]::ReadAllBytes($f.FullName)
    if ($b.Length -lt 3 -or $b[0] -ne 0xEF -or $b[1] -ne 0xBB -or $b[2] -ne 0xBF) {
        Die ($f.Name + ' lacks a UTF-8 BOM; CJK text would be mangled by PowerShell 5.1')
    }
    Ok ($f.Name + ' has a UTF-8 BOM')
}
foreach ($f in ($gateFiles | Where-Object { $_.Extension -eq '.bat' })) {
    $b = [IO.File]::ReadAllBytes($f.FullName)
    $nonAscii = @($b | Where-Object { $_ -gt 0x7F })
    if ($nonAscii.Count -gt 0) {
        Die ($f.Name + ' contains ' + $nonAscii.Count + ' non-ASCII byte(s); batch files must stay pure ASCII')
    }
    Ok ($f.Name + ' is pure ASCII')
}
# The .iss is read by ISCC, which handles UTF-8 with a BOM. Without the BOM the
# CJK in [Messages] / [Tasks] / the Pascal strings is decoded as the ANSI code
# page and the wizard shows mojibake.
foreach ($f in ($gateFiles | Where-Object { $_.Extension -eq '.iss' })) {
    $b = [IO.File]::ReadAllBytes($f.FullName)
    if ($b.Length -lt 3 -or $b[0] -ne 0xEF -or $b[1] -ne 0xBB -or $b[2] -ne 0xBF) {
        Die ($f.Name + ' lacks a UTF-8 BOM; the wizard text would be mojibake')
    }
    Ok ($f.Name + ' has a UTF-8 BOM')
}
foreach ($f in ($gateFiles | Where-Object { $_.Extension -eq '.txt' })) {
    $b = [IO.File]::ReadAllBytes($f.FullName)
    if ($b.Length -lt 3 -or $b[0] -ne 0xEF -or $b[1] -ne 0xBB -or $b[2] -ne 0xBF) {
        Warn ($f.Name + ' has no UTF-8 BOM; Notepad on a zh-CN box may show mojibake')
    } else { Ok ($f.Name + ' has a UTF-8 BOM') }
}

# ---- 4) config gate --------------------------------------------------------
# A package that ships a real API key or a plaintext endpoint cannot be handed to
# anyone. Checked here rather than trusted, because the source of appsettings.json
# is the live dist config, which a developer may have edited.
Step 'config gate'
$cfgPath = Join-Path $app 'appsettings.json'
$cfg = (Get-Content $cfgPath -Raw -Encoding UTF8) | ConvertFrom-Json
$b = $cfg.Bulwark
$secretPaths = @(
    @('ReputationProxy','BearerToken'), @('VirusTotal','ApiKey'), @('MalwareBazaar','AuthKey'),
    @('Otx','ApiKey'), @('ThreatBook','ApiKey'), @('MetaDefender','ApiKey'),
    @('HybridAnalysis','ApiKey'), @('ThreatFoxFeed','AuthKey'), @('Ai','ApiKey')
)
$leak = @()
foreach ($sp in $secretPaths) {
    $v = $b.($sp[0]).($sp[1])
    if ($v -and $v.ToString().Trim() -ne '') { $leak += ($sp[0] + '.' + $sp[1]) }
}
if ($leak.Count -gt 0) { Die ('config carries ' + $leak.Count + ' secret(s): ' + ($leak -join ', ')) }
Ok 'all 9 secret fields are empty'
$rp = $b.ReputationProxy
if ($rp.BaseUrl -and $rp.BaseUrl.Trim() -ne '') { Die ('config carries a plaintext endpoint: ' + $rp.BaseUrl) }
if (-not $rp.BaseUrlObfuscated) { Warn 'no BaseUrlObfuscated -- cloud lookups will be unavailable' }
else { Ok 'endpoint is obfuscated, not plaintext' }
if ($b.EventSource -ne 'Driver') { Warn ('EventSource = ' + $b.EventSource + ' (expected Driver)') }
else { Ok 'EventSource = Driver' }
# Machine-specific leftovers would pin the package to this box.
$cfgRaw = [IO.File]::ReadAllText($cfgPath, [Text.Encoding]::UTF8)
foreach ($needle in @('C:\Users', 'D:\', 'Desktop')) {
    if ($cfgRaw.Contains($needle)) { Warn ('config mentions "' + $needle + '" -- check it is not machine-specific') }
}

# ---- 5) sign the staged binaries -------------------------------------------
# Signing happens on the STAGED copies, never in cpp\dist: the running service's
# directory is on the kernel SelfGuard list, so writing there is denied.
#
# Why the exes must be signed at all: the in-app updater installs a file only
# when its signer thumbprint equals the pin compiled into the client. An unsigned
# build produces a package that can never be updated, and the failure surfaces
# much later on the user's machine as "update refused" with no visible cause.
# install.ps1 additionally refuses to install an unsigned payload, so this step
# is load-bearing, not cosmetic.
Step 'sign'
if ($NoSign) {
    Warn '-NoSign: skipping. install.ps1 will REFUSE to install the result.'
} else {
    if (-not $isAdmin) { Die 'not elevated: the code-signing private key lives in LocalMachine\My and cannot be read' }
    $cert = @(Get-ChildItem 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
              Where-Object { $_.Subject -like ('*' + $CertSubject + '*') -and $_.HasPrivateKey } |
              Sort-Object NotAfter -Descending)
    if ($cert.Count -eq 0) { Die ("no signing cert with a private key matching *" + $CertSubject + "* in LocalMachine\My") }
    $c = $cert[0]
    if ($c.Thumbprint.ToUpper() -ne $pinned) {
        Die ('the available cert (' + $c.Thumbprint.ToUpper() + ') is not the pinned one (' + $pinned + ')')
    }
    Ok ('cert: ' + $c.Subject + '  valid until ' + $c.NotAfter.ToString('yyyy-MM-dd'))
    if ($c.NotAfter -lt (Get-Date).AddDays(60)) { Warn 'cert expires within 60 days -- plan a rotation' }

    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe `
                  -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\x64\\' } |
                Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { Die 'signtool.exe not found (install the Windows SDK)' }
    Info ('signtool: ' + $signtool.FullName)

    foreach ($n in @('bulwark_service.exe', 'bulwark_ui.exe')) {
        $p = Join-Path $app $n
        $args = @('sign','/q','/sm','/s','My','/sha1',$c.Thumbprint,'/fd','sha256')
        # Timestamping keeps the signature verifiable after the cert expires. It
        # needs network, so it is attempted and then skipped rather than fatal.
        & $signtool.FullName @($args + @('/tr','http://timestamp.digicert.com','/td','sha256',$p)) 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Warn ('timestamping failed for ' + $n + ' (offline?) -- signing without a timestamp')
            & $signtool.FullName @($args + @($p)) 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Die ('signtool failed for ' + $n + ' (exit ' + $LASTEXITCODE + ')') }
        }
        Ok ('signed ' + $n)
    }
}

# ---- 6) verify the payload exactly the way install.ps1 will ----------------
# Reading the signature back rather than trusting signtool's exit code, and using
# the same accept rule the installer uses: signature present, digest intact,
# signer == pin. Status=Valid is NOT required -- the cert is self-signed, so on a
# machine that has not imported it the status is UnknownError, and that is
# precisely the state of a machine that has just received the package.
Step 'verify payload'
$fail = @()
foreach ($n in @('bulwark_service.exe', 'bulwark_ui.exe', 'Bulwark.sys')) {
    $p = Join-Path $app $n
    $s = Get-AuthenticodeSignature $p
    $status = [string]$s.Status
    $tp = ''
    if ($s.SignerCertificate) { $tp = $s.SignerCertificate.Thumbprint.ToUpper() }
    $verdict = 'ok'
    if ($status -eq 'NotSigned' -or -not $s.SignerCertificate) { $verdict = 'NOT SIGNED' }
    elseif ($status -eq 'HashMismatch') { $verdict = 'HASH MISMATCH' }
    elseif (@('Valid','UnknownError') -notcontains $status) { $verdict = ('status ' + $status) }
    elseif ($tp -ne $pinned) { $verdict = ('wrong signer ' + $tp) }
    $ver = (Get-Item $p).VersionInfo.FileVersion
    if ($verdict -eq 'ok') {
        Ok ("{0,-22} {1,9:N0} B  sig={2,-13} ver={3}" -f $n, (Get-Item $p).Length, $status, $ver)
    } else {
        Warn ("{0,-22} {1}" -f $n, $verdict)
        if (-not $NoSign) { $fail += ($n + ': ' + $verdict) }
    }
}
if ($fail.Count -gt 0) { Die ("payload verification failed:`n  " + ($fail -join "`n  ")) }

foreach ($n in @('bulwark_service.exe','bulwark_ui.exe')) {
    $fv = (Get-Item (Join-Path $app $n)).VersionInfo.FileVersion
    if ($fv -and -not $fv.StartsWith($version)) { Die ($n + ' reports version ' + $fv + ', sources say ' + $version) }
}
Ok ('both executables report version ' + $version)

# ---- 7) compile the wizard installer with Inno Setup -----------------------
Step 'Inno Setup'
# ISCC can live in Program Files or, when installed per-user (winget passes
# /CURRENTUSER), under %LOCALAPPDATA%\Programs. Look in both rather than assuming.
$isccCandidates = @(
    'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
    'C:\Program Files\Inno Setup 6\ISCC.exe',
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
    'C:\Program Files (x86)\Inno Setup 7\ISCC.exe',
    'C:\Program Files\Inno Setup 7\ISCC.exe',
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 7\ISCC.exe')
)
$iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    Die ("ISCC.exe not found. Install Inno Setup 6 first:`n" +
         "  winget install --id JRSoftware.InnoSetup -e -s winget`n" +
         "or download innosetup-6.x.exe from https://jrsoftware.org/isdl.php")
}
Ok ('ISCC: ' + $iscc)
$innoDir = Split-Path $iscc -Parent

# Simplified Chinese is not part of a stock Inno install. Without it the wizard
# would be English -- which is a legitimate fallback, but it must be a CONSCIOUS
# fallback: a package whose license page is Chinese and whose buttons are English
# looks broken. So the state is reported, not guessed at.
$cnIsl = Join-Path $innoDir 'Languages\ChineseSimplified.isl'
$hasChinese = '0'
if (Test-Path $cnIsl) {
    $islTxt = [IO.File]::ReadAllText($cnIsl)
    if ($islTxt -match 'LanguageName=' -and $islTxt -match 'LanguageCodePage=') {
        $hasChinese = '1'
        Ok ('Chinese wizard language: ' + $cnIsl)
    } else {
        Warn 'ChineseSimplified.isl exists but does not look like a language file -- falling back to English'
    }
} else {
    Warn 'no ChineseSimplified.isl in the Inno Languages folder -- the wizard will be English only'
    Info 'get it from https://jrsoftware.org/files/istrans/ (third-party translations)'
}

$iss = Join-Path $instSrc 'bulwark.iss'
if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Path $Out -Force | Out-Null }
$setupExe = Join-Path $Out ('Bulwark-Setup-' + $version + '.exe')
if (Test-Path $setupExe) { Remove-Item $setupExe -Force }

$isccLog = Join-Path $env:TEMP 'bulwark-iscc.log'
& $iscc ('/DAppVersion=' + $version) `
        ('/DPayloadDir=' + $app) `
        ('/DSrcDir=' + $instSrc) `
        ('/DOutDir=' + $Out) `
        ('/DHasChinese=' + $hasChinese) `
        $iss 2>&1 | Out-File $isccLog -Encoding utf8
$isccRc = $LASTEXITCODE
if ($isccRc -ne 0) {
    Write-Host ''
    Get-Content $isccLog -Encoding UTF8 | Select-Object -Last 25 | ForEach-Object { Warn $_ }
    Die ('ISCC failed (exit ' + $isccRc + '). Full log: ' + $isccLog)
}
Get-Content $isccLog -Encoding UTF8 |
    Where-Object { $_ -match 'Successful compile|Resulting Setup|warning' } |
    ForEach-Object { Info $_.Trim() }
if (-not (Test-Path $setupExe)) { Die ('ISCC reported success but ' + $setupExe + ' is missing') }
Ok ("{0}  {1:N1} MB" -f (Split-Path $setupExe -Leaf), ((Get-Item $setupExe).Length / 1MB))

# ---- 8) sign Setup.exe itself ----------------------------------------------
# The payload inside is signed, but the thing the user actually double-clicks is
# this outer exe. Leaving it unsigned means the recipient sees a completely
# unattributed binary asking for administrator rights -- and there would be no
# way to tell a tampered copy from the real one before running it.
Step 'sign Setup.exe'
if ($NoSign) {
    Warn '-NoSign: the installer is unsigned'
} else {
    $args = @('sign','/q','/sm','/s','My','/sha1',$c.Thumbprint,'/fd','sha256')
    & $signtool.FullName @($args + @('/tr','http://timestamp.digicert.com','/td','sha256',$setupExe)) 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Warn 'timestamping failed (offline?) -- signing without a timestamp'
        & $signtool.FullName @($args + @($setupExe)) 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Die ('signtool failed for Setup.exe (exit ' + $LASTEXITCODE + ')') }
    }
    $ss = Get-AuthenticodeSignature $setupExe
    $stp = ''
    if ($ss.SignerCertificate) { $stp = $ss.SignerCertificate.Thumbprint.ToUpper() }
    if ($stp -ne $pinned) { Die ('Setup.exe signer is not the pinned cert: ' + $stp) }
    Ok ('signed  status=' + [string]$ss.Status + '  signer=pinned' +
        $(if ($ss.TimeStamperCertificate) { '  timestamped' } else { '  (no timestamp)' }))
}

# ---- 9) checksum manifest ---------------------------------------------------
Step 'manifest'
$sha = New-Object System.Collections.Generic.List[string]
$sha.Add('磐垒主动防御 (Bulwark HIPS) ' + $version + '  SHA-256')
$sha.Add('built ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$sha.Add('')
$sha.Add('安装程序(双击这个):')
$sha.Add('  ' + (Get-FileHash $setupExe -Algorithm SHA256).Hash.ToLower() + '  ' + (Split-Path $setupExe -Leaf))
$sha.Add('')
$sha.Add('安装程序内的载荷(装完后可在安装目录里核对):')
foreach ($n in @('bulwark_service.exe','bulwark_ui.exe','Bulwark.sys','appsettings.json')) {
    $sha.Add('  ' + (Get-FileHash (Join-Path $app $n) -Algorithm SHA256).Hash.ToLower() + '  ' + $n)
}
$sha.Add('')
$sha.Add('三个 PE 的签名者指纹: ' + $pinned)
$sha.Add('  (CN=' + $CertSubject + ',自签证书 —— 在没导入过它的机器上 Windows 会')
$sha.Add('   显示「未知发布者」,这是自签的固有结果,不是文件损坏)')
[IO.File]::WriteAllText((Join-Path $Out 'SHA256.txt'), (($sha -join "`r`n") + "`r`n"),
                        (New-Object Text.UTF8Encoding($true)))
Ok 'SHA256.txt'

# Earlier revisions of this script emitted a loose folder + zip. Now that there is
# a real single-file installer, leaving those behind would just be two more things
# for the recipient to guess between.
foreach ($stale in @((Join-Path $Out ('Bulwark-' + $version + '-Setup')),
                     (Join-Path $Out ('Bulwark-' + $version + '-Setup.zip')),
                     (Join-Path $Out '请先看这里.txt'))) {
    if (Test-Path $stale) {
        Remove-Item $stale -Recurse -Force -ErrorAction SilentlyContinue
        Info ('removed stale artifact: ' + (Split-Path $stale -Leaf))
    }
}

if ($KeepStaging) { Info ('staging kept: ' + $stage) }
else { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ''
Write-Host '==== installer built ====' -ForegroundColor Cyan
Info ('setup  : ' + $setupExe)
Info 'hand over that single file. The recipient double-clicks it and follows the wizard.'
Write-Host ''
