<#
    pack-driver-cab.ps1
    ——把 Bulwark.sys 打成可提交给 Microsoft 硬件开发中心(Partner Center)做 attestation
      签名的 CAB,并在打包【之前】把所有会导致提交被退回的问题就地查出来。

    为什么要有这个脚本(而不是照文档手敲 makecab)
    ------------------------------------------------------------------
    HDC 的提交反馈是【异步且信息极少】的:上传后要等,失败常常只回一句
    "Failed INF validation. INF did not pass Desktop validation (InfVerif /k)" 或者
    "There are files at the root of the cabinet",不告诉你具体哪一行、哪个文件。
    一次来回半天到一天。所以凡是本地能判的,必须在本地判掉:

      · InfVerif /k(Desktop 规则集)+ /h(驱动隔离规则集)—— HDC 两套都跑;
      · Inf2Cat 可签名性测试 —— catalog 生成不了,提交必失败;
      · CAB 结构 —— 根目录不许有裸文件,每个驱动包必须各自在一个子目录里;
      · .sys 本身 —— 架构必须 x64;必须带 Force Integrity 位(否则 ObRegisterCallbacks
        会失败,自保护静默消失,而这种驱动照样能签下来,签完才发现更亏)。

    另外两个只能靠人记住、这里替你记住的点:
      · 提交路径不能是 UNC,目录名不能带特殊字符、不能超过 40 字符。本仓库路径是
        「d:\新建文件夹 (3)」—— 带中文、空格和括号,直接在原地 makecab 是在踩雷。
        故本脚本统一在 %TEMP% 下的短 ASCII 目录里暂存打包,只把成品 CAB 拷回仓库。
      · 微软签名时会【覆盖】.sys 上你自己的嵌入式签名,并重新生成 .cat。所以提交前
        给 .sys 签自己的证书没有意义;而签名回来后 .sys 的签名者变成微软的 WHCP
        Publisher —— 这会打破 UpdateTrust.h 里钉死的指纹校验,升级通道会拒绝更新。
        脚本最后会再提醒一次。

    用法(不需要管理员;EV 证书通常在 CurrentUser\My):
        # 只体检,不打包(还没买证书时就该先跑这个)
        powershell -ExecutionPolicy Bypass -File scripts\pack-driver-cab.ps1 -CheckOnly

        # 打包 + 用 EV 证书签 CAB
        powershell -ExecutionPolicy Bypass -File scripts\pack-driver-cab.ps1 -CertThumbprint <EV证书指纹>

        # 打包但先不签(签名机与开发机分离时)
        powershell -ExecutionPolicy Bypass -File scripts\pack-driver-cab.ps1 -SkipSign

    退出码:0 = 成品可提交(或 -CheckOnly 全绿);非 0 = 有阻断问题,别提交。
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    # 默认按「构建产物优先、便携包兜底」找 .sys。显式传入则完全按你给的走。
    [string]$SysPath,
    [string]$PdbPath,

    # EV 代码签名证书。指纹优先(精确);只给主体名时取最晚过期的那张。
    [string]$CertThumbprint,
    [string]$CertSubject,

    [string]$OutDir,

    # Inf2Cat 的目标 OS 列表(逗号分隔)。attestation 只支持 Win10 及以上桌面版。
    [string]$Os = '10_X64',

    [string]$TimestampUrl = 'http://timestamp.digicert.com',

    # 官方 attestation 文档要求 CAB 里带 .pdb(供微软崩溃分析);但另有一份较新的
    # 打包规则说「CAB 内所有文件都必须被 INF 引用」,而 .pdb 无法被 INF 引用 ——
    # 两处文档互相冲突,社区两种做法都有成功也有被退。默认带上,被退回时用这个开关重试。
    [switch]$NoPdb,

    [switch]$SkipSign,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Step($m) { Write-Host ''; Write-Host "== $m ==" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Bad($m)  { Write-Host "  [X]  $m" -ForegroundColor Red }
function Info($m) { Write-Host "       $m" -ForegroundColor DarkGray }
function Die($m)  { Bad $m; throw $m }

# ---- 0) 工具 ---------------------------------------------------------------
Step 'tools'

function Find-KitTool([string]$relRoot, [string]$name, [string]$archDir) {
    $base = Join-Path "${env:ProgramFiles(x86)}\Windows Kits\10" $relRoot
    if (-not (Test-Path $base)) { return $null }
    Get-ChildItem $base -Recurse -Filter $name -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match [regex]::Escape("\$archDir\") } |
        Sort-Object FullName -Descending | Select-Object -First 1
}

$infverif = Find-KitTool 'tools' 'infverif.exe' 'x64'
$inf2cat  = Find-KitTool 'bin'   'Inf2Cat.exe'  'x86'   # Inf2Cat 只有 x86 版
$signtool = Find-KitTool 'bin'   'signtool.exe' 'x64'
$makecab  = Join-Path $env:SystemRoot 'System32\makecab.exe'
$expand   = Join-Path $env:SystemRoot 'System32\expand.exe'

if (-not $infverif) { Die 'infverif.exe not found (install the WDK)' }
if (-not $inf2cat)  { Die 'Inf2Cat.exe not found (install the WDK)' }
if (-not (Test-Path $makecab)) { Die "makecab.exe not found at $makecab" }
Ok ('infverif : ' + $infverif.FullName)
Ok ('inf2cat  : ' + $inf2cat.FullName)
if ($signtool) { Ok ('signtool : ' + $signtool.FullName) } else { Warn 'signtool.exe not found -- signing will be skipped' }

# ---- 1) 输入文件 -----------------------------------------------------------
Step 'inputs'

$inf = Join-Path $root 'Bulwark.Driver\Bulwark.inf'
if (-not (Test-Path $inf)) { Die "missing INF: $inf" }
Ok ('inf : ' + $inf)

if (-not $SysPath) {
    $candidates = @(
        (Join-Path $root "Bulwark.Driver\build\driver\$Configuration\Bulwark.sys"),
        (Join-Path $root 'cpp\dist\Bulwark.sys')
    )
    $SysPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $SysPath) { Die ("no Bulwark.sys found. looked in:`n  " + ($candidates -join "`n  ")) }
}
if (-not (Test-Path $SysPath)) { Die "missing driver binary: $SysPath" }
$sysItem = Get-Item $SysPath
Ok ('sys : ' + $sysItem.FullName)
Info ('{0} bytes, built {1}' -f $sysItem.Length, $sysItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))

if (-not $PdbPath) {
    $PdbPath = [IO.Path]::ChangeExtension($sysItem.FullName, '.pdb')
}
$havePdb = (-not $NoPdb) -and (Test-Path $PdbPath)
if ($NoPdb)          { Info 'pdb : intentionally excluded (-NoPdb)' }
elseif ($havePdb)    { Ok ('pdb : ' + $PdbPath) }
else                 { Warn "pdb not found next to the .sys ($PdbPath) -- submitting without it" }

# ---- 2) .sys 自检:签下来也没用的两种情况,先在这里拦住 --------------------
# 读 PE 头,不依赖 link.exe / dumpbin。
Step 'driver binary sanity'

$bytes = [IO.File]::ReadAllBytes($sysItem.FullName)
if ($bytes.Length -lt 0x200) { Die 'file is too small to be a PE image' }
$peOff = [BitConverter]::ToInt32($bytes, 0x3C)
if ($peOff -le 0 -or $peOff + 0x100 -ge $bytes.Length) { Die 'not a PE image (bad e_lfanew)' }
if (-not ($bytes[$peOff] -eq 0x50 -and $bytes[$peOff + 1] -eq 0x45)) { Die 'not a PE image (missing PE signature)' }

$machine = [BitConverter]::ToUInt16($bytes, $peOff + 4)
if ($machine -eq 0x8664) { Ok 'architecture: x64' }
else { Die ('architecture is 0x{0:X4}, expected x64 (0x8664). attestation needs every driver folder to be the same arch set.' -f $machine) }

$optOff = $peOff + 24
$magic  = [BitConverter]::ToUInt16($bytes, $optOff)
if ($magic -ne 0x20B) { Die ('optional header magic 0x{0:X} is not PE32+' -f $magic) }
$dllChar = [BitConverter]::ToUInt16($bytes, $optOff + 0x46)
# IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
if ($dllChar -band 0x0080) {
    Ok 'Force Integrity bit set (/INTEGRITYCHECK)'
} else {
    Bad 'Force Integrity bit NOT set -- ObRegisterCallbacks() will fail at runtime'
    Info 'self-protection would silently disappear, yet the driver would still sign fine.'
    Info 'the vcxproj passes /INTEGRITYCHECK to the linker; a .sys without it is not a release build.'
    Die 'refusing to package a driver without /INTEGRITYCHECK'
}

$existing = Get-AuthenticodeSignature $sysItem.FullName
if ($existing.Status -ne 'NotSigned') {
    Info ('current .sys signature: {0} ({1})' -f $existing.Status,
          $(if ($existing.SignerCertificate) { $existing.SignerCertificate.Subject } else { 'unknown signer' }))
    Info 'HDC overwrites this embedded signature -- it is here only for local testing.'
}

# ---- 3) INF 预检:HDC 用的就是这两套规则集 ---------------------------------
Step 'INF validation (the exact rulesets HDC runs)'

foreach ($mode in @('/k', '/h')) {
    $label = if ($mode -eq '/k') { 'Desktop (/k)' } else { 'driver isolation (/h)' }
    $out = & $infverif.FullName $mode $inf 2>&1 | Out-String
    $errLines  = ($out -split "`r?`n") | Where-Object { $_ -match '^ERROR\(' }
    $warnLines = ($out -split "`r?`n") | Where-Object { $_ -match '^WARNING\(' }
    foreach ($w in $warnLines) { Warn $w.Trim() }
    if ($errLines) {
        foreach ($e in $errLines) { Bad $e.Trim() }
        Die "INF fails InfVerif $label -- HDC would reject the submission"
    }
    Ok "passes InfVerif $label"
}

# ---- 4) 暂存目录:短、ASCII、非 UNC ----------------------------------------
# HDC 要求驱动目录名不含特殊字符、短于 40 字符,且不能是 UNC 路径。仓库路径本身
# 不满足(中文 + 空格 + 括号),所以打包一律在 %TEMP% 下做。
Step 'staging'

$stageRoot = Join-Path $env:TEMP 'bulwark-hdc'
$pkgName   = 'Bulwark'                  # CAB 内的子目录名,也是 HDC 看到的驱动文件夹名
if ($pkgName.Length -ge 40) { Die "package folder name '$pkgName' must be shorter than 40 characters" }
if ($stageRoot.StartsWith('\\')) { Die 'staging path is a UNC path; use a mapped drive letter' }
foreach ($ch in $stageRoot.ToCharArray()) {
    if ([int]$ch -gt 127) { Die "staging path contains non-ASCII characters: $stageRoot" }
}

if (Test-Path $stageRoot) { Remove-Item $stageRoot -Recurse -Force }
$pkgDir = Join-Path $stageRoot $pkgName
New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null

Copy-Item $inf                (Join-Path $pkgDir 'Bulwark.inf') -Force
Copy-Item $sysItem.FullName   (Join-Path $pkgDir 'Bulwark.sys') -Force
if ($havePdb) { Copy-Item $PdbPath (Join-Path $pkgDir 'Bulwark.pdb') -Force }
Ok ("staged in $pkgDir")

# ---- 5) Inf2Cat:生成 catalog + 可签名性测试 -------------------------------
# 文档:CAB 里必须有 .cat,HDC 只用它做公司身份核验,签完会重新生成一份替换掉。
Step "Inf2Cat (/os:$Os)"

$catOut = & $inf2cat.FullName "/driver:$pkgDir" "/os:$Os" 2>&1 | Out-String
$catExit = $LASTEXITCODE
$catLines = ($catOut -split "`r?`n") | Where-Object { $_.Trim() -ne '' -and $_ -notmatch '^Testing driver package' }
foreach ($l in $catLines) { Info $l.Trim() }
if ($catExit -ne 0) { Die "Inf2Cat failed (exit $catExit) -- the package is not signable as-is" }

$cat = Get-ChildItem $pkgDir -Filter '*.cat' | Select-Object -First 1
if (-not $cat) { Die 'Inf2Cat reported success but produced no .cat' }
Ok ("catalog: $($cat.Name) ($($cat.Length) bytes)")

# ---- 6) 证书 ---------------------------------------------------------------
Step 'signing certificate'

$cert = $null
if (-not $SkipSign -and $signtool) {
    $stores = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
    foreach ($s in $stores) {
        $found = @(Get-ChildItem $s -ErrorAction SilentlyContinue | Where-Object {
            $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and
            (($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId }) -contains '1.3.6.1.5.5.7.3.3') -and
            (
                ($CertThumbprint -and $_.Thumbprint -eq $CertThumbprint.Replace(' ', '').ToUpper()) -or
                ($CertSubject    -and $_.Subject -like "*$CertSubject*") -or
                (-not $CertThumbprint -and -not $CertSubject)
            )
        } | Sort-Object NotAfter -Descending)
        if ($found.Count -gt 0) {
            $cert = $found[0]
            Ok ("using cert from ${s}: " + $cert.Subject)
            Info ('thumbprint : ' + $cert.Thumbprint)
            Info ('valid until: ' + $cert.NotAfter.ToString('yyyy-MM-dd'))
            if ($s -eq 'Cert:\LocalMachine\My') {
                Info 'LocalMachine private keys need an elevated shell; if signtool later reports'
                Info '"No certificates were found that met all the given criteria", that is why.'
            }
            break
        }
    }
    if (-not $cert) {
        Warn 'no usable code-signing certificate found'
        Info 'HDC requires an EV code signing certificate; the CAB will be produced UNSIGNED.'
        Info 'an unsigned CAB cannot be submitted -- sign it on the machine holding the EV token.'
    }
    if ($cert -and $cert.Subject -like '*BulwarkTestCert*') {
        Warn 'this is the local TEST certificate, not an EV cert -- HDC will reject a CAB signed with it'
        Info 'useful for rehearsing the packaging flow, useless for an actual submission.'
    }
} else {
    Info 'signing skipped by request'
}

# ---- 7) 签 .cat(公司身份核验用的就是它)-----------------------------------
if ($cert -and -not $CheckOnly) {
    Step 'sign catalog'
    $args = @('sign', '/q', '/sha1', $cert.Thumbprint, '/fd', 'sha256')
    & $signtool.FullName @($args + @('/tr', $TimestampUrl, '/td', 'sha256', $cat.FullName)) 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Warn 'timestamping failed (offline?) -- signing the catalog without a timestamp'
        & $signtool.FullName @($args + @($cat.FullName)) 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Die "signtool failed on $($cat.Name) (exit $LASTEXITCODE)" }
    }
    Ok ("signed $($cat.Name)")
}

if ($CheckOnly) {
    Step 'CheckOnly -- nothing packaged'
    Remove-Item $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host '==== all local checks passed; the package is submittable in shape ====' -ForegroundColor Green
    Write-Host ''
    exit 0
}

# ---- 8) makecab ------------------------------------------------------------
# DDF 按官方 attestation 文档的模板写。要点:CAB 根目录不得有文件,每个驱动包各占
# 一个子目录(DestinationDir),否则 HDC 回一句 "There are files at the root of the cabinet"。
Step 'makecab'

$cabName = 'Bulwark.cab'
$ddf = Join-Path $stageRoot 'Bulwark.ddf'
$lines = @(
    ';*** Bulwark.ddf -- generated by scripts\pack-driver-cab.ps1, do not edit by hand',
    '.OPTION EXPLICIT',
    '.Set CabinetFileCountThreshold=0',
    '.Set FolderFileCountThreshold=0',
    '.Set FolderSizeThreshold=0',
    '.Set MaxCabinetSize=0',
    '.Set MaxDiskFileCount=0',
    '.Set MaxDiskSize=0',
    '.Set CompressionType=MSZIP',
    '.Set Cabinet=on',
    '.Set Compress=on',
    ".Set CabinetNameTemplate=$cabName",
    ".Set DestinationDir=$pkgName",
    (Join-Path $pkgDir 'Bulwark.inf'),
    (Join-Path $pkgDir 'Bulwark.sys'),
    $cat.FullName
)
if ($havePdb) { $lines += (Join-Path $pkgDir 'Bulwark.pdb') }
# makecab 自己按 ANSI 读 DDF;暂存路径已保证是 ASCII。
[IO.File]::WriteAllLines($ddf, $lines, [Text.ASCIIEncoding]::new())

Push-Location $stageRoot
try {
    $mcOut = & $makecab '/f' $ddf 2>&1 | Out-String
} finally { Pop-Location }
$cab = Join-Path $stageRoot "Disk1\$cabName"
if (-not (Test-Path $cab)) {
    Info $mcOut
    Die 'makecab did not produce a CAB'
}
$countLine = ($mcOut -split "`r?`n" | Where-Object { $_ -match 'in \d+ files' }) -join ' '
Ok ("$cabName built ($((Get-Item $cab).Length) bytes)")
if ($countLine) { Info $countLine.Trim() }

# ---- 9) 验 CAB 结构(别让"根目录有裸文件"这种事等到 HDC 才发现)----------
# 【为什么是解包验证而不是 expand -D】
#   expand -D 只列文件名,【不显示 CAB 内的目录】—— 在中文系统上它连输出文字都是
#   中文的。拿它的输出做"根目录有没有裸文件"的判断,会因为每行都带着 CAB 自身的
#   路径(里面当然有反斜杠)而永远判"通过",是个看着绿实际没查的假检查。
#   真正可靠的办法是把 CAB 解出来看目录树:那正是 HDC 解包后看到的结构。
Step 'verify CAB layout'

$probe = Join-Path $stageRoot 'verify'
New-Item -ItemType Directory -Path $probe -Force | Out-Null
& $expand $cab '-F:*' $probe 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Die "expand failed to extract the CAB (exit $LASTEXITCODE)" }

$got = @(Get-ChildItem $probe -Recurse -File | ForEach-Object { $_.FullName.Substring($probe.Length + 1) })
if ($got.Count -eq 0) { Die 'the CAB extracted to nothing' }
foreach ($g in $got) { Info $g }

$rootFiles = @($got | Where-Object { $_ -notmatch '\\' })
if ($rootFiles.Count -gt 0) {
    Die ('files at the CAB root -- HDC answers "There are files at the root of the cabinet": ' +
         ($rootFiles -join ', '))
}
$topDirs = @($got | ForEach-Object { ($_ -split '\\')[0] } | Sort-Object -Unique)
if ($topDirs.Count -ne 1 -or $topDirs[0] -ne $pkgName) {
    Die ('expected every file under a single "' + $pkgName + '\" folder, got: ' + ($topDirs -join ', '))
}

$expected = @('Bulwark.inf', 'Bulwark.sys', $cat.Name)
if ($havePdb) { $expected += 'Bulwark.pdb' }
$leaves = @($got | ForEach-Object { Split-Path $_ -Leaf })
$missing = @($expected | Where-Object { $leaves -notcontains $_ })
if ($missing.Count -gt 0) { Die ('missing from the CAB: ' + ($missing -join ', ')) }
$extra = @($leaves | Where-Object { $expected -notcontains $_ })
if ($extra.Count -gt 0) { Warn ('unexpected files in the CAB: ' + ($extra -join ', ')) }

Ok ("layout OK: $($got.Count) file(s), all under $pkgName\, nothing at the root")

# ---- 10) 签 CAB ------------------------------------------------------------
if ($cert) {
    Step 'sign CAB'
    $args = @('sign', '/q', '/sha1', $cert.Thumbprint, '/fd', 'sha256')
    & $signtool.FullName @($args + @('/tr', $TimestampUrl, '/td', 'sha256', $cab)) 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Warn 'timestamping failed (offline?) -- signing the CAB without a timestamp'
        & $signtool.FullName @($args + @($cab)) 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Die "signtool failed on the CAB (exit $LASTEXITCODE)" }
    }
    $cs = Get-AuthenticodeSignature $cab
    if ($cs.Status -eq 'NotSigned') { Die 'CAB still reports NotSigned after signing' }
    Ok ("CAB signed: $($cs.Status), signer=$($cs.SignerCertificate.Subject)")
}

# ---- 11) 出货 --------------------------------------------------------------
Step 'output'

if (-not $OutDir) { $OutDir = Join-Path $root 'build\hdc' }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$final = Join-Path $OutDir ("Bulwark-$stamp.cab")
Copy-Item $cab $final -Force
Ok ("$final")
Remove-Item $stageRoot -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host '==== next steps ====' -ForegroundColor Green
Write-Host '  1) Partner Center -> Hardware -> Submit new hardware, upload this CAB.' -ForegroundColor Gray
Write-Host '     Leave BOTH test-signing options unchecked. Pick the Windows 10/11 x64' -ForegroundColor Gray
Write-Host '     desktop signatures under "Requested Signatures".' -ForegroundColor Gray
Write-Host '  2) Download the signed package and take Bulwark.sys from it.' -ForegroundColor Gray
Write-Host '  3) The returned .sys is signed by Microsoft (WHCP publisher), NOT by your' -ForegroundColor Yellow
Write-Host '     EV cert -- HDC overwrites the embedded signature. Two consequences:' -ForegroundColor Yellow
Write-Host '       - UpdateTrust.h pins one thumbprint and Bulwark.sys is in the update' -ForegroundColor Yellow
Write-Host '         payload allow-list, so online update WILL reject the signed driver' -ForegroundColor Yellow
Write-Host '         until the .sys is given its own signer rule.' -ForegroundColor Yellow
Write-Host '       - scripts\sign-binaries.ps1 only warns about a mismatched .sys signer;' -ForegroundColor Yellow
Write-Host '         it will not stop you from shipping a package that cannot self-update.' -ForegroundColor Yellow
Write-Host '  4) Windows Server does not load attestation-signed filter drivers. Server' -ForegroundColor Gray
Write-Host '     support needs an HLK/WHCP submission instead.' -ForegroundColor Gray
Write-Host ''
