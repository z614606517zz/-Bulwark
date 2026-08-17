# =====================================================================
#  Invoke-Uninstall 的单元测试(packaging\portable-scripts\bulwark.ps1)
#
#  为什么需要它
#    卸载是唯一一条【没法在真机上试】的路径:真跑一遍就把驱动卸了、服务删了、
#    机器踢出测试模式。所以它历来是发出去从没被执行过的代码,而一个笔误
#    (变量名写错、`+` 被当成位置参数吞掉、某个分支静默跳过 bcdedit)只会由
#    用户来发现 —— 那时他机器上已经是个卸了一半的内核驱动。
#
#  怎么测
#    按 begin/end 标记抽出 installmark 与 uninstall 两段,dot-source 进来,
#    把所有对外副作用都改道到无害的地方:
#      fltmc / sc.exe / bcdedit -> 记录参数的桩 .cmd
#      $dstSys                  -> 临时文件
#      $StateKey                -> 临时 HKCU 键(绝不碰真的 HKLM)
#      $env:ProgramData         -> 临时目录(内含假的 quarantine)
#      服务名                    -> 本机不存在的名字
#      证书主题                  -> 匹配不到任何证书的主题
#    真实的驱动、服务、证书存储、启动配置全程没被碰到。
#
#  断言的是什么
#    不是「跑通了」,而是桩日志里有没有那几条确切的命令、数据目录的实际存亡。
#    这里真正要防的失败形态是「某一步被静默跳过」。
#
#  ⚠ 两个必须记住的点:
#    1) 本文件必须带 UTF-8 BOM。PS 5.1 在 zh-CN 上把无 BOM 的 .ps1 按 GBK 读,
#       下面这些中文匹配串会被吃成乱码,连引号配对都会断(实测踩过)。
#    2) Invoke-Uninstall 的结论行(「没有残留」等)是直接 Write-Host 出来的,
#       不走 Ok/Warn/Bad。所以这里把 Write-Host 也接过来,否则断言假失败。
# =====================================================================
[CmdletBinding()]
param(
    [switch]$KeepTemp,
    # 结果另存一份 UTF-8:控制台重定向出来的是 GBK 字节,中文全是乱码,没法看。
    [string]$ReportPath = (Join-Path $env:TEMP 'bulwark-uninstall-test-report.txt')
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
$region     = Get-Region 'uninstall'
$regionMark = Get-Region 'installmark'

$tmpRoot = Join-Path $env:TEMP ('bulwark-uninstall-test-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path $tmpRoot | Out-Null
$frag = Join-Path $tmpRoot 'region.ps1'
[IO.File]::WriteAllText($frag, $region, (New-Object Text.UTF8Encoding($true)))
$fragMark = Join-Path $tmpRoot 'installmark.ps1'
[IO.File]::WriteAllText($fragMark, $regionMark, (New-Object Text.UTF8Encoding($true)))

# ---- 外部命令的桩 -----------------------------------------------------------
# 把自己的名字和参数追加进日志然后返回 0,这样测试可以断言「到底发了哪几条命令」。
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

# 被测代码的 Write-Host 全部收进 transcript(断言用)。
function Write-Host {
    param(
        [Parameter(ValueFromRemainingArguments = $true, Position = 0)] $Object,
        $ForegroundColor, $BackgroundColor, [switch]$NoNewline, $Separator
    )
    $s = ($Object -join ' ')
    $script:transcript.Add($s)
    $script:report.Add('        | ' + $s)
}

# harness 自己的输出走 Say,模块限定调用绕过上面的覆盖,且不进 transcript。
function Say([string]$s, [string]$color) {
    $script:report.Add($s)
    if ($color) { Microsoft.PowerShell.Utility\Write-Host $s -ForegroundColor $color }
    else { Microsoft.PowerShell.Utility\Write-Host $s }
}

function Check([string]$label, [bool]$ok, [string]$detail) {
    if ($ok) { Say ('  PASS  ' + $label) 'Green'; $script:pass++ }
    else {
        Say ('  FAIL  ' + $label) 'Red'
        if ($detail) { Say ('        detail: ' + $detail) 'DarkGray' }
        $script:fail++
    }
}

# Ok/Warn/Bad/Info/Step 定义在抽取区之外,由 harness 补上。
function Ok($m)   { $script:transcript.Add('[OK] ' + $m); $script:report.Add('        | [OK] ' + $m) }
function Warn($m) { $script:transcript.Add('[!] '  + $m); $script:report.Add('        | [!]  ' + $m) }
function Bad($m)  { $script:transcript.Add('[X] '  + $m); $script:report.Add('        | [X]  ' + $m) }
function Info($m) { $script:transcript.Add('     ' + $m); $script:report.Add('        |      ' + $m) }
function Step($m) { $script:transcript.Add('== ' + $m + ' =='); $script:report.Add('        | == ' + $m + ' ==') }

$fltmc   = New-Stub 'fltmc'
$scExe   = New-Stub 'sc'
$bcdedit = New-Stub 'bcdedit'

# 本机不存在的名字:Get-Service / fltmc filters 都返回空,复查才有干净基线。
$ServiceName = 'BulwarkTestNoSuchKernelSvc'
$UserService = 'BulwarkTestNoSuchUserSvc'
$CertSubject = 'BulwarkTestCertNoSuchSubject'
$StateKey    = 'HKCU:\Software\BulwarkUninstallTest'

. $fragMark
. $frag

function Reset-Case([string]$name) {
    $script:transcript.Clear()
    if (Test-Path $stubLog) { Remove-Item $stubLog -Force }
    New-Item -ItemType File -Path $stubLog -Force | Out-Null

    $script:dstSys = Join-Path $tmpRoot ($name + '-Bulwark.sys')
    Set-Content -LiteralPath $script:dstSys -Value 'fake driver bytes' -Encoding ASCII

    $pd = Join-Path $tmpRoot ($name + '-ProgramData')
    $script:dataDirForCase = Join-Path $pd 'Bulwark'
    New-Item -ItemType Directory -Force -Path (Join-Path $script:dataDirForCase 'quarantine') | Out-Null
    Set-Content -LiteralPath (Join-Path $script:dataDirForCase 'rules.json') -Value '{}' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $script:dataDirForCase 'service.log') -Value 'log line' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $script:dataDirForCase 'quarantine\sample.bin') -Value 'X' -Encoding ASCII
    $env:ProgramData = $pd

    if (Test-Path $StateKey) { Remove-Item $StateKey -Recurse -Force }
}

function Get-Calls { if (Test-Path $stubLog) { return (Get-Content -LiteralPath $stubLog -Raw) } return '' }
function Get-Out   { return ($script:transcript -join "`n") }

$realProgramData = $env:ProgramData
Say '' ''
Say ('uninstall region  : ' + $region.Length + ' chars') ''
Say ('installmark region: ' + $regionMark.Length + ' chars') ''
Say ('temp harness      : ' + $tmpRoot) ''

try {
    # =================================================================
    # 真正的默认路径:一个开关都不加。数据目录那一问在非交互环境下读不到输入,
    # 必须走「保留」—— 无人应答时删掉用户的规则和隔离样本是不可接受的。
    Say '' ''
    Say '== case 1: default, no switches, non-interactive stdin ==' 'Cyan'
    Reset-Case 'c1'
    $KeepCert = $false; $KeepTestSigning = $false; $PurgeData = $false; $KeepData = $false
    Invoke-Uninstall
    $calls = Get-Calls
    $out = Get-Out
    Check 'fltmc unload issued'          ($calls -match 'fltmc\s+unload')                     $calls
    Check 'services deleted or absent'   ($calls -match 'sc\s+delete' -or $out -match '未注册') $out
    Check 'staged .sys deleted'          (-not (Test-Path $dstSys))                           $dstSys
    Check 'testsigning off issued'       ($calls -match 'bcdedit\s+/set\s+testsigning\s+off') $calls
    Check 'reboot requirement announced' ($out -match '需要重启')                              $out
    Check 'data dir kept when unattended' (Test-Path $dataDirForCase)                         $dataDirForCase
    Check 'quarantine sample untouched'  (Test-Path (Join-Path $dataDirForCase 'quarantine\sample.bin')) ''
    Check 'residue re-check says clean'  ($out -match '没有残留')                              $out
    Check 'cert step ran'                ($out -match '移除测试证书')                          $out
    Check 'state key removed'            (-not (Test-Path $StateKey))                         $StateKey

    # =================================================================
    Say '' ''
    Say '== case 2: -KeepTestSigning must not touch bcdedit ==' 'Cyan'
    Reset-Case 'c2'
    $KeepCert = $false; $KeepTestSigning = $true; $PurgeData = $false; $KeepData = $true
    Invoke-Uninstall
    $calls = Get-Calls
    $out = Get-Out
    Check 'no bcdedit /set issued'  (-not ($calls -match 'bcdedit\s+/set'))  $calls
    Check 'opt-out explained'       ($out -match 'KeepTestSigning')          $out
    Check 'driver still unloaded'   ($calls -match 'fltmc\s+unload')         $calls

    # =================================================================
    Say '' ''
    Say '== case 3: marker says test signing predates us -> keep it on ==' 'Cyan'
    Reset-Case 'c3'
    [void](Set-InstallMark 'TestSigningEnabledByUs' 0)
    Check 'Set/Get-InstallMark round trip = 0'  ((Get-InstallMark 'TestSigningEnabledByUs') -eq 0)  ''
    $KeepCert = $false; $KeepTestSigning = $false; $PurgeData = $false; $KeepData = $true
    Invoke-Uninstall
    $calls = Get-Calls
    $out = Get-Out
    Check 'no bcdedit /set issued'      (-not ($calls -match 'bcdedit\s+/set'))  $calls
    Check 'explains it predated us'     ($out -match '之前')                     $out
    Check 'prints the manual command'   ($out -match 'testsigning off')          $out
    Check 'state key removed'           (-not (Test-Path $StateKey))             $StateKey

    # =================================================================
    Say '' ''
    Say '== case 4: marker says we enabled it -> turn it off ==' 'Cyan'
    Reset-Case 'c4'
    [void](Set-InstallMark 'TestSigningEnabledByUs' 1)
    Check 'Set/Get-InstallMark round trip = 1'  ((Get-InstallMark 'TestSigningEnabledByUs') -eq 1)  ''
    $KeepCert = $false; $KeepTestSigning = $false; $PurgeData = $false; $KeepData = $true
    Invoke-Uninstall
    $calls = Get-Calls
    Check 'testsigning off issued'  ($calls -match 'bcdedit\s+/set\s+testsigning\s+off')  $calls

    # =================================================================
    Say '' ''
    Say '== case 5: -PurgeData really deletes the data directory ==' 'Cyan'
    Reset-Case 'c5'
    $KeepCert = $false; $KeepTestSigning = $false; $PurgeData = $true; $KeepData = $false
    $hadQuarantine = Test-Path (Join-Path $dataDirForCase 'quarantine\sample.bin')
    Invoke-Uninstall
    $out = Get-Out
    Check 'quarantine existed before'  $hadQuarantine                      ''
    Check 'data dir deleted'           (-not (Test-Path $dataDirForCase))  $dataDirForCase
    Check 'deletion reported'          ($out -match '数据目录已删除')       $out
    Check 'sample count was shown'     ($out -match '隔离区样本')           $out

    # =================================================================
    Say '' ''
    Say '== case 6: -KeepData keeps it without asking ==' 'Cyan'
    Reset-Case 'c6'
    $KeepCert = $false; $KeepTestSigning = $false; $PurgeData = $false; $KeepData = $true
    Invoke-Uninstall
    $out = Get-Out
    Check 'data dir still there'  (Test-Path $dataDirForCase)    $dataDirForCase
    Check 'keep reported'         ($out -match '已保留数据目录')  $out

    # =================================================================
    Say '' ''
    Say '== case 7: -KeepCert leaves the certificate stores alone ==' 'Cyan'
    Reset-Case 'c7'
    $KeepCert = $true; $KeepTestSigning = $false; $PurgeData = $false; $KeepData = $true
    Invoke-Uninstall
    $out = Get-Out
    Check 'KeepCert honoured'  ($out -match 'KeepCert')  $out

    # =================================================================
    Say '' ''
    Say '== case 8: missing data directory must not throw ==' 'Cyan'
    Reset-Case 'c8'
    Remove-Item $dataDirForCase -Recurse -Force
    $KeepCert = $false; $KeepTestSigning = $false; $PurgeData = $false; $KeepData = $false
    Invoke-Uninstall
    $out = Get-Out
    Check 'handled missing data dir'  ($out -match '数据目录不存在')  $out
    Check 'still reaches conclusion'  ($out -match '残留')            $out
}
catch {
    # 一个死了却不说原因的测试没有价值:把异常和位置记成一条 FAIL,
    # 而不是让进程静静退出、报告都不落盘。
    Say '' ''
    Say ('  FAIL  harness threw: ' + $_.Exception.Message) 'Red'
    if ($_.InvocationInfo) {
        Say ('        at line ' + $_.InvocationInfo.ScriptLineNumber + ': ' + $_.InvocationInfo.Line.Trim()) 'DarkGray'
    }
    Say ('        type: ' + $_.Exception.GetType().FullName) 'DarkGray'
    $fail++
}
finally {
    $env:ProgramData = $realProgramData
    if (Test-Path $StateKey) { Remove-Item $StateKey -Recurse -Force -EA SilentlyContinue }
    Remove-Item Env:\BLW_STUB_LOG -EA SilentlyContinue
    if (-not $KeepTemp) { Remove-Item $tmpRoot -Recurse -Force -EA SilentlyContinue }

    Say '' ''
    Say ('result: ' + $pass + ' passed, ' + $fail + ' failed') $(if ($fail -gt 0) { 'Red' } else { 'Green' })
    [IO.File]::WriteAllText($ReportPath, ($script:report -join "`r`n"), (New-Object Text.UTF8Encoding($true)))
    Say ('report: ' + $ReportPath) ''
}

if ($fail -gt 0) { exit 1 }
exit 0
