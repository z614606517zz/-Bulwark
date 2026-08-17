# =====================================================================
#  Invoke-ApplyUpdate / Invoke-UpdateRollback 的单元测试
#  (packaging\portable-scripts\bulwark.ps1)
#
#  为什么需要它
#    这是整个产品里最危险的一段代码:它以管理员身份替换安装目录里的三个文件,
#    其中一个会被当作【内核驱动】加载。它同时也几乎没法在真机上反复试 —— 真跑
#    一遍就把驱动换了,失败一次就要重装。历史上「点了下载没反应」那个 bug 已经
#    说明了没被执行过的代码是什么下场,而同样的错误放在这里,后果不是按钮失灵,
#    是一台装了一半、防护静默停止的机器。
#
#  怎么测(刻意【不】mock 签名与版本号)
#    签名校验和版本比对是这段代码的两道安全闸门,mock 掉它们等于不测。所以这里
#    用真实的已签名 PE:
#      旧版(便携包里的 1.1.3)-> 假的安装目录
#      新版(构建目录里的 1.1.4)-> 假的暂存目录
#    Get-AuthenticodeSignature 与 VersionInfo 走真实实现,读的是真文件。
#    只有真正会伤到本机的东西才换成桩:
#      fltmc / sc.exe -> 记录参数的桩 .cmd
#      Ensure-Driver  -> harness 提供,按用例返回 $true/$false 来驱动成功与回滚
#      Get-Process    -> 恒返回空(否则会把本机真在跑的 bulwark_ui 杀掉)
#      $pkgDir        -> 临时目录(真安装目录全程没被碰)
#
#  断言的是什么
#    不是「跑通了」,而是:
#      - 篡改过的载荷【必须】被拒,且安装目录一个字节都没变
#      - 降级【必须】被拒
#      - 缺文件【必须】整份拒,不能装一半
#      - 驱动装不上时【必须】回滚,且文件确实回到旧版
#      - 成功路径里 fltmc unload 必须发生在复制【之前】
#
#  ⚠ 本文件必须带 UTF-8 BOM:PS 5.1 在 zh-CN 上把无 BOM 的 .ps1 按 GBK 读,
#    下面这些中文匹配串会被吃成乱码,连引号配对都会断(实测踩过)。
# =====================================================================
[CmdletBinding()]
param(
    [switch]$KeepTemp,
    [string]$ReportPath = (Join-Path $env:TEMP 'bulwark-update-apply-test-report.txt')
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$src = Join-Path $repoRoot 'packaging\portable-scripts\bulwark.ps1'
if (-not (Test-Path $src)) { throw ("not found: " + $src) }

$text = [IO.File]::ReadAllText($src, [Text.Encoding]::UTF8)
function Get-Region([string]$name) {
    $b = $script:text.IndexOf('# --- ' + $name + ':begin ---')
    $e = $script:text.IndexOf('# --- ' + $name + ':end ---')
    if ($b -lt 0 -or $e -lt 0 -or $e -le $b) { throw ($name + " markers not found (or out of order) in bulwark.ps1") }
    return $script:text.Substring($b, $e - $b)
}
$region = Get-Region 'applyupdate'

$tmpRoot = Join-Path $env:TEMP ('bulwark-update-apply-test-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path $tmpRoot | Out-Null
$frag = Join-Path $tmpRoot 'region.ps1'
[IO.File]::WriteAllText($frag, $region, (New-Object Text.UTF8Encoding($true)))

# ---- 真实的已签名素材 -------------------------------------------------------
# 新版从构建目录取(签名 + FileVersion 都是真的);旧版从便携包取。
$payload = @('bulwark_service.exe', 'bulwark_ui.exe', 'Bulwark.sys')
# 取 build_update\beta\ 而【不是】cpp\build\...\Release\:sign-binaries.ps1 是把
# 构建产物复制到 build_update\<channel>\ 之后再签名的,cpp\build 里的 exe 始终没有
# 签名。这里要的正是「真正发布出去的那三个文件」。
$newSrc = @{}
foreach ($n in $payload) { $newSrc[$n] = Join-Path $repoRoot ('build_update\beta\' + $n) }
$oldPkg = 'C:\Users\1\Desktop\Bulwark'

$missing = @()
foreach ($n in $payload) {
    if (-not (Test-Path -LiteralPath $newSrc[$n])) { $missing += ('new: ' + $newSrc[$n]) }
    if (-not (Test-Path -LiteralPath (Join-Path $oldPkg $n))) { $missing += ('old: ' + (Join-Path $oldPkg $n)) }
}
if ($missing.Count -gt 0) {
    Write-Host 'SKIP: 缺少测试素材(需要已构建并签名的新版 + 一个便携包作为旧版):' -ForegroundColor Yellow
    foreach ($m in $missing) { Write-Host ('  ' + $m) -ForegroundColor DarkGray }
    exit 3
}

# ---- 外部命令的桩 -----------------------------------------------------------
$stubLog = Join-Path $tmpRoot 'calls.log'
$stub = Join-Path $tmpRoot 'stub.cmd'
Set-Content -LiteralPath $stub -Encoding ASCII -Value @'
@echo off
echo %BLW_STUB_NAME% %* >> "%BLW_STUB_LOG%"
exit /b 0
'@
$env:BLW_STUB_LOG = $stubLog
function New-Stub([string]$name) {
    $p = Join-Path $tmpRoot ($name + '.cmd')
    Set-Content -LiteralPath $p -Encoding ASCII -Value (
        "@echo off`r`nset BLW_STUB_NAME=$name`r`ncall `"$stub`" %*`r`nexit /b 0")
    return $p
}

# ---- 输出捕获 ---------------------------------------------------------------
$script:transcript = New-Object System.Collections.Generic.List[string]
$script:report     = New-Object System.Collections.Generic.List[string]
$fail = 0
$pass = 0

function Write-Host {
    param(
        [Parameter(ValueFromRemainingArguments = $true, Position = 0)] $Object,
        $ForegroundColor, $BackgroundColor, [switch]$NoNewline, $Separator
    )
    $s = ($Object -join ' ')
    $script:transcript.Add($s)
    $script:report.Add('        | ' + $s)
}
function Say([string]$s, [string]$color) {
    $script:report.Add($s)
    if ($color) { Microsoft.PowerShell.Utility\Write-Host $s -ForegroundColor $color }
    else { Microsoft.PowerShell.Utility\Write-Host $s }
}
$script:dumped = $false
function Check([string]$label, [bool]$ok, [string]$detail) {
    if ($ok) { Say ('  PASS  ' + $label) 'Green'; $script:pass++ }
    else {
        Say ('  FAIL  ' + $label) 'Red'
        if ($detail) { Say ('        detail: ' + $detail) 'DarkGray' }
        # 断言失败时把被测代码这一轮说过的话原样打出来。没有它就只能看到
        # 「返回了 False」,却不知道是哪一道闸门拒的 —— 那是调不了的。
        if (-not $script:dumped) {
            $script:dumped = $true
            Say '        ---- 被测代码输出 ----' 'DarkGray'
            foreach ($l in $script:transcript) { Say ('        > ' + $l) 'DarkGray' }
            Say '        ----------------------' 'DarkGray'
        }
        $script:fail++
    }
}
function Ok($m)   { $script:transcript.Add('[OK] ' + $m); $script:report.Add('        | [OK] ' + $m) }
function Warn($m) { $script:transcript.Add('[!] '  + $m); $script:report.Add('        | [!]  ' + $m) }
function Bad($m)  { $script:transcript.Add('[X] '  + $m); $script:report.Add('        | [X]  ' + $m) }
function Info($m) { $script:transcript.Add('     ' + $m); $script:report.Add('        |      ' + $m) }
function Step($m) { $script:transcript.Add('== ' + $m + ' =='); $script:report.Add('        | == ' + $m + ' ==') }

# 恒返回空:被测代码会对 bulwark_ui / bulwark_service 调 Stop-Process,
# 不挡住的话会把本机真在跑的实例杀掉。
function Get-Process { return @() }

# Ensure-Driver 由 harness 提供 —— 它是「新驱动能不能加载」这个变量的注入点,
# 成功路径与回滚路径就靠它区分。
$script:ensureResults = @()
$script:ensureCalls = 0
function Ensure-Driver {
    $i = $script:ensureCalls
    $script:ensureCalls++
    $r = $true
    if ($i -lt $script:ensureResults.Count) { $r = $script:ensureResults[$i] }
    $script:transcript.Add('<Ensure-Driver#' + $i + ' -> ' + $r + '>')
    $script:report.Add('        | <Ensure-Driver#' + $i + ' -> ' + $r + '>')
    return $r
}

$fltmc = New-Stub 'fltmc'
$scExe = New-Stub 'sc'
$ServiceName = 'BulwarkTestNoSuchFilter'
$UserService = 'BulwarkTestNoSuchSvc'
$UpdateSignerThumbprints = @('712BA1C841C8D2AA0A48BF89BD076DCD0774E7F5')

. $frag

# ---- 用例装配 ---------------------------------------------------------------
$caseNo = 0
function New-Case([string]$name, [string]$oldFrom, [string]$newFrom) {
    $script:caseNo++
    $root = Join-Path $tmpRoot ('case{0:d2}' -f $script:caseNo)
    $pkg = Join-Path $root 'pkg'
    $stage = Join-Path $root 'stage'
    New-Item -ItemType Directory -Force -Path $pkg, $stage | Out-Null
    foreach ($n in $script:payload) {
        # $oldFrom / $newFrom 取值 'old' 或 'new',用来构造升级与降级两种方向
        $s1 = if ($oldFrom -eq 'new') { $script:newSrc[$n] } else { Join-Path $script:oldPkg $n }
        $s2 = if ($newFrom -eq 'new') { $script:newSrc[$n] } else { Join-Path $script:oldPkg $n }
        Copy-Item -LiteralPath $s1 -Destination (Join-Path $pkg $n) -Force
        Copy-Item -LiteralPath $s2 -Destination (Join-Path $stage $n) -Force
    }
    $script:transcript.Clear()
    $script:ensureCalls = 0
    $script:dumped = $false
    Set-Content -LiteralPath $script:stubLog -Value '' -Encoding ASCII
    Say ''
    Say ('---- ' + $name + ' ----') 'Cyan'
    return @{ Pkg = $pkg; Stage = $stage; Root = $root }
}
function Get-PkgVersion($pkg) {
    return (Get-Item -LiteralPath (Join-Path $pkg 'bulwark_ui.exe')).VersionInfo.FileVersion
}
function Get-Log { if (Test-Path $script:stubLog) { return (Get-Content $script:stubLog -Raw) } return '' }
function In-Transcript([string]$needle) {
    return ($null -ne ($script:transcript | Where-Object { $_ -like ('*' + $needle + '*') }))
}

Say ''
Say '==== Invoke-ApplyUpdate 单元测试 ====' 'Cyan'
Say ("素材:旧版 " + (Get-Item (Join-Path $oldPkg 'bulwark_ui.exe')).VersionInfo.FileVersion +
     "  新版 " + (Get-Item $newSrc['bulwark_ui.exe']).VersionInfo.FileVersion) 'DarkGray'

# ============ 用例 1:正常升级 =========================================
$c = New-Case '1) 正常升级(驱动加载成功)' 'old' 'new'
$pkgDir = $c.Pkg; $UpdateDir = $c.Stage
$verBefore = Get-PkgVersion $pkgDir
$ensureResults = @($true)
$r1 = Invoke-ApplyUpdate
$verAfter = Get-PkgVersion $pkgDir
Check '返回 $true' ($r1 -eq $true) ("got: " + $r1)
Check ('安装目录版本已升级(' + $verBefore + ' -> ' + $verAfter + ')') `
      ((Compare-BulwarkVersion $verAfter $verBefore) -gt 0) $verAfter
foreach ($n in $payload) {
    $h1 = (Get-FileHash -LiteralPath (Join-Path $pkgDir $n)).Hash
    $h2 = (Get-FileHash -LiteralPath $newSrc[$n]).Hash
    Check ("  $n 内容 == 新版") ($h1 -eq $h2) ($h1 + ' vs ' + $h2)
}
$bks = @(Get-ChildItem -LiteralPath $pkgDir -Directory -Filter 'backup-*')
Check '生成了 backup- 备份目录' ($bks.Count -eq 1) ("count=" + $bks.Count)
if ($bks.Count -eq 1) {
    Check '备份里存的是【旧】版本' (
        (Get-Item -LiteralPath (Join-Path $bks[0].FullName 'bulwark_ui.exe')).VersionInfo.FileVersion -eq $verBefore) ''
} else {
    Check '备份里存的是【旧】版本' $false '没有备份目录,跳过内容检查'
}
$log = Get-Log
Check 'fltmc unload 被调用过' ($log -match 'fltmc\s+unload') $log
Check 'sc stop 内核服务被调用过' ($log -match ('sc\s+stop\s+' + $ServiceName)) $log
Check '成功后清掉了暂存目录' (-not (Test-Path -LiteralPath $UpdateDir)) $UpdateDir
Check 'Ensure-Driver 恰好被调 1 次(未走回滚)' ($ensureCalls -eq 1) ("calls=" + $ensureCalls)
Check '打印了「更新完成」' (In-Transcript '更新完成') ''

# ============ 用例 2:载荷被篡改 =======================================
# 这是最重要的一条:模拟「服务校验完 -> 提权应用之间,文件被普通用户权限换掉」。
$c = New-Case '2) 暂存文件被篡改(TOCTOU)' 'old' 'new'
$pkgDir = $c.Pkg; $UpdateDir = $c.Stage
$victim = Join-Path $UpdateDir 'bulwark_ui.exe'
$bytes = [IO.File]::ReadAllBytes($victim)
$bytes[[int]($bytes.Length / 2)] = [byte](($bytes[[int]($bytes.Length / 2)] + 1) % 256)
[IO.File]::WriteAllBytes($victim, $bytes)
$before = @{}; foreach ($n in $payload) { $before[$n] = (Get-FileHash -LiteralPath (Join-Path $pkgDir $n)).Hash }
$ensureResults = @($true)
$r2 = Invoke-ApplyUpdate
Check '返回 $false(拒绝应用)' ($r2 -eq $false) ("got: " + $r2)
$unchanged = $true
foreach ($n in $payload) {
    if ((Get-FileHash -LiteralPath (Join-Path $pkgDir $n)).Hash -ne $before[$n]) { $unchanged = $false }
}
Check '安装目录一个文件都没被改' $unchanged ''
Check '没有停止防护(在校验阶段就拒了)' (-not ((Get-Log) -match 'fltmc\s+unload')) (Get-Log)
Check 'Ensure-Driver 完全没被调用' ($ensureCalls -eq 0) ("calls=" + $ensureCalls)
Check '拒绝原因指向签名' (In-Transcript '签名') ''

# ============ 用例 3:降级 ============================================
$c = New-Case '3) 降级(暂存版本更旧)' 'new' 'old'
$pkgDir = $c.Pkg; $UpdateDir = $c.Stage
$before = (Get-FileHash -LiteralPath (Join-Path $pkgDir 'bulwark_ui.exe')).Hash
$ensureResults = @($true)
$r3 = Invoke-ApplyUpdate
Check '返回 $false(拒绝降级)' ($r3 -eq $false) ("got: " + $r3)
Check '安装目录未改动' ((Get-FileHash -LiteralPath (Join-Path $pkgDir 'bulwark_ui.exe')).Hash -eq $before) ''
Check '拒绝原因说明了不允许降级' (In-Transcript '降级') ''
Check '没有生成备份目录' (@(Get-ChildItem -LiteralPath $pkgDir -Directory -Filter 'backup-*').Count -eq 0) ''

# ============ 用例 4:同版本 ==========================================
$c = New-Case '4) 同版本重装' 'new' 'new'
$pkgDir = $c.Pkg; $UpdateDir = $c.Stage
$ensureResults = @($true)
$r4 = Invoke-ApplyUpdate
Check '返回 $false(同版本也拒)' ($r4 -eq $false) ("got: " + $r4)

# ============ 用例 5:缺文件 ==========================================
$c = New-Case '5) 暂存目录缺一个文件' 'old' 'new'
$pkgDir = $c.Pkg; $UpdateDir = $c.Stage
Remove-Item -LiteralPath (Join-Path $UpdateDir 'Bulwark.sys') -Force
$before = @{}; foreach ($n in $payload) { $before[$n] = (Get-FileHash -LiteralPath (Join-Path $pkgDir $n)).Hash }
$ensureResults = @($true)
$r5 = Invoke-ApplyUpdate
Check '返回 $false(整份拒绝)' ($r5 -eq $false) ("got: " + $r5)
$unchanged = $true
foreach ($n in $payload) {
    if ((Get-FileHash -LiteralPath (Join-Path $pkgDir $n)).Hash -ne $before[$n]) { $unchanged = $false }
}
Check '没有「装了能装的那两个」' $unchanged ''
Check '提示了不完整' (In-Transcript '不完整') ''

# ============ 用例 6:新驱动加载失败 -> 回滚 ==========================
# 第 1 次 Ensure-Driver(装新驱动)返回 $false,第 2 次(回滚里装回旧驱动)返回 $true
$c = New-Case '6) 新驱动加载失败 -> 回滚成功' 'old' 'new'
$pkgDir = $c.Pkg; $UpdateDir = $c.Stage
$verBefore = Get-PkgVersion $pkgDir
$oldHash = @{}; foreach ($n in $payload) { $oldHash[$n] = (Get-FileHash -LiteralPath (Join-Path $pkgDir $n)).Hash }
$ensureResults = @($false, $true)
$r6 = Invoke-ApplyUpdate
Check '返回 $false' ($r6 -eq $false) ("got: " + $r6)
Check 'Ensure-Driver 被调 2 次(装新版 + 回滚重载)' ($ensureCalls -eq 2) ("calls=" + $ensureCalls)
$restored = $true
foreach ($n in $payload) {
    if ((Get-FileHash -LiteralPath (Join-Path $pkgDir $n)).Hash -ne $oldHash[$n]) { $restored = $false }
}
Check '三个文件都回到了旧版内容' $restored ''
Check ('版本回到 ' + $verBefore) ((Get-PkgVersion $pkgDir) -eq $verBefore) (Get-PkgVersion $pkgDir)
Check '打印了「已回滚」' (In-Transcript '已回滚') ''
Check '回滚后明确说防护已恢复' (In-Transcript '防护已恢复') ''
Check '失败时【保留】暂存目录以便重试' (Test-Path -LiteralPath $UpdateDir) $UpdateDir

# ============ 用例 7:回滚时驱动也装不回去 ============================
# 最坏情况。要断言的是「有没有把话说清楚」,而不是它能自愈。
$c = New-Case '7) 回滚后驱动仍加载失败(最坏情况)' 'old' 'new'
$pkgDir = $c.Pkg; $UpdateDir = $c.Stage
$ensureResults = @($false, $false)
$r7 = Invoke-ApplyUpdate
Check '返回 $false' ($r7 -eq $false) ("got: " + $r7)
Check '明确告知防护当前是停止的' (In-Transcript '防护当前处于停止状态') ''
Check '给出了手动恢复的路径(backup- 目录)' (In-Transcript 'backup-') ''
Check '给出了重启建议' (In-Transcript '重启') ''

# ============ 用例 8:暂存目录不存在 ==================================
$c = New-Case '8) 从未下载过(暂存目录不存在)' 'old' 'new'
$pkgDir = $c.Pkg
$UpdateDir = Join-Path $c.Root 'nope'
$ensureResults = @($true)
$r8 = Invoke-ApplyUpdate
Check '返回 $false' ($r8 -eq $false) ("got: " + $r8)
Check '提示先去界面下载' (In-Transcript '检查更新') ''

# ============ 版本比较函数本身 ========================================
Say ''
Say '---- 9) Compare-BulwarkVersion ----' 'Cyan'
Check '1.1.10 > 1.1.9(不是字符串比较)' ((Compare-BulwarkVersion '1.1.10' '1.1.9') -gt 0) ''
Check '1.2.0 > 1.1.99' ((Compare-BulwarkVersion '1.2.0' '1.1.99') -gt 0) ''
Check '相等返回 0' ((Compare-BulwarkVersion '1.1.4' '1.1.4') -eq 0) ''
Check '1.1.3 < 1.1.4' ((Compare-BulwarkVersion '1.1.3' '1.1.4') -lt 0) ''
Check '四段版本号(1.1.4.0 == 1.1.4)' ((Compare-BulwarkVersion '1.1.4.0' '1.1.4') -eq 0) ''
Check '非数字段不抛异常' ((Compare-BulwarkVersion '1.1.x' '1.1.0') -eq 0) ''

# ---- 汇总 -------------------------------------------------------------------
Say ''
if ($fail -eq 0) { Say ("==== 全部通过:$pass 项 ====") 'Green' }
else { Say ("==== $pass 通过,$fail 失败 ====") 'Red' }

[IO.File]::WriteAllText($ReportPath, ($report -join "`r`n"), (New-Object Text.UTF8Encoding($true)))
Microsoft.PowerShell.Utility\Write-Host ("report: " + $ReportPath) -ForegroundColor DarkGray
if (-not $KeepTemp) { Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue }
else { Microsoft.PowerShell.Utility\Write-Host ("temp kept: " + $tmpRoot) -ForegroundColor DarkGray }
if ($fail -gt 0) { exit 1 }
exit 0
