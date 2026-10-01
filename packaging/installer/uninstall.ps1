# =====================================================================
#  磐垒主动防御 (Bulwark HIPS) —— 卸载程序
#
#  双击安装目录里的 卸载.bat 即可(开始菜单和系统「应用和功能」里的卸载入口
#  最终也是跑这个文件)。
#
#  这是正经安全工具,所以始终保留用户自主卸载的通路,不存在「装上就删不掉」。
#  默认一次做完全套,不用记任何参数:
#
#    1. 停界面 -> 停用户态服务 -> 卸内核驱动(顺序不能反,理由见下)
#    2. 删两个服务注册(Bulwark 内核服务 + BulwarkService 用户态服务)
#    3. 删 System32\drivers\Bulwark.sys
#    4. 移除安装时导入的 BulwarkTestCert(只在【确实是本产品导入的】时才移除)
#    5. 关闭测试签名(只在【确实是本产品开启的】时才关)
#    6. 删快捷方式 / 控制面板卸载项 / 开机自启项 / 安装痕迹
#    7. 问一句要不要删数据目录(默认保留:里面有你的规则、审计日志和隔离的真实样本)
#    8. 删安装目录
#    9. 复查一遍真实状态,有残留就直说是哪几项
#
#  为什么第 1 步的顺序不能反
#    · 驱动在载时本产品自身进程在内核自我保护名单里,外部进程拿不到
#      PROCESS_TERMINATE,Stop-Process 会静默失败;
#    · 内核 SelfGuard 守着安装目录与数据目录(仅放行本产品自身进程写入),
#      服务还活着时删文件会被拒 —— 而且审计日志可能把这次操作记成「放行」,
#      因为内核 SelfGuard 与用户态规则引擎是两条独立的决策路径,生效的是内核那条;
#    · 内核注册表硬拦含 "\Services\Bulwark",驱动在载时 sc delete 会被拦下。
#    先停服务(SelfGuard 随断连清除),再卸驱动(解除注册表硬拦),之后才动文件和注册。
#
#  参数
#    -Dir <路径>          安装目录(默认从 HKLM\SOFTWARE\Bulwark\InstallDir 读)
#    -PurgeData           连数据目录一起删,不询问
#    -KeepData            不询问,直接保留数据目录
#    -KeepCert            保留 BulwarkTestCert 证书
#    -KeepTestSigning     保留测试签名开启状态
#
#  本文件必须带 UTF-8 BOM(PS 5.1 在中文系统上把无 BOM 的 .ps1 按 GBK 读)。
# =====================================================================
#  ── 两种调用方式 ──────────────────────────────────────────────────
#  1) 由 Setup.exe 生成的卸载程序调用,带 -SystemOnly:此时快捷方式、「应用和
#     功能」条目、安装目录里的文件都由 Inno 自己删。本脚本只负责「和系统打交道」
#     的那部分,并且必须跑在 Inno 删文件【之前】(否则驱动还加载着,自我保护会
#     把删除挡下来)。
#  2) 直接运行(不带 -SystemOnly):连快捷方式、卸载项和安装目录一起清掉。
#
[CmdletBinding()]
param(
    [string]$Dir,
    [switch]$SystemOnly,
    [switch]$PurgeData,
    [switch]$KeepData,
    [switch]$KeepCert,
    [switch]$KeepTestSigning
)

# 卸载要尽力做完每一步。中途抛异常留下半套,比任何单步失败都糟。
$ErrorActionPreference = 'Continue'

$ProductShort  = 'Bulwark'
$DriverService = 'Bulwark'
$UserService   = 'BulwarkService'
$CertSubject   = 'BulwarkTestCert'
$StateKey = 'HKLM:\SOFTWARE\Bulwark'
$ArpKey   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Bulwark'

function Say([string]$s, [string]$color) {
    if ($color) { Write-Host $s -ForegroundColor $color } else { Write-Host $s }
}
function Ok($m)   { Say ("  [OK]   " + $m) 'Green' }
function Warn($m) { Say ("  [!]    " + $m) 'Yellow' }
function Bad($m)  { Say ("  [X]    " + $m) 'Red' }
function Info($m) { Say ("         " + $m) 'DarkGray' }
function Step($m) { Say '' ''; Say ("== " + $m + " ==") 'Cyan' }

$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole(
          [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '请以【管理员】身份运行(双击 卸载.bat 会自动提权)。'
}

$sysNative = Join-Path $env:SystemRoot 'Sysnative'
$sysDir = Join-Path $env:SystemRoot 'System32'
if (Test-Path (Join-Path $sysNative 'bcdedit.exe')) { $sysDir = $sysNative }
$bcdedit = Join-Path $sysDir 'bcdedit.exe'
$scExe   = Join-Path $sysDir 'sc.exe'
$fltmc   = Join-Path $sysDir 'fltmc.exe'
$cmdExe  = Join-Path $sysDir 'cmd.exe'
$dstSys  = Join-Path (Join-Path $env:SystemRoot 'System32\drivers') 'Bulwark.sys'
$dataDir = Join-Path $env:ProgramData 'Bulwark'

function Get-Mark([string]$name) {
    try { return (Get-ItemProperty -Path $StateKey -Name $name -ErrorAction Stop).$name } catch { return $null }
}

function Resolve-InstallDir([string]$d) {
    if (-not $d) { return '' }
    $d = $d.Trim().TrimEnd('\')
    if ($d.EndsWith('\.')) { $d = $d.Substring(0, $d.Length - 2) }
    return $d
}

if (-not $Dir -or $Dir.Trim() -eq '') {
    # 本脚本就住在安装目录里,所以「自己在哪」比注册表里记的更可信(目录被整体
    # 搬动过、或上一次卸载只做了一半时,注册表那条可能已经过期或不存在)。
    # 只有当自己所在的目录明显不是安装目录时,才退回注册表记录。
    $self = Resolve-InstallDir $PSScriptRoot
    if ($self -and (Test-Path (Join-Path $self 'bulwark_service.exe'))) {
        $Dir = $self
    } else {
        $Dir = Resolve-InstallDir ([string](Get-Mark 'InstallDir'))
        if (-not $Dir) { $Dir = $self }
    }
} else {
    $Dir = Resolve-InstallDir $Dir
}

Write-Host ''
Write-Host '==== 磐垒主动防御 (Bulwark HIPS) 卸载 ====' -ForegroundColor Cyan
Info ('安装目录:' + $Dir)

$needReboot = $false

# ---- 1) 停用户态 ----------------------------------------------------------
#
# 必须走 SCM 的正常停止,不能直接杀进程:服务配了失败自动恢复(5s/5s/60s 重启),
# 而它区分「用户主动停止」与「异常终止」的依据就是退出码。被 kill 会被判为异常,
# SCM 五秒后把它拉回来,重新武装内核自我保护,于是后面每一步都开始失败 ——
# 对用户来说就是「卸载不干净,而且每次残留的东西还不一样」。
Step '停止界面与后台服务'
Get-Process -Name 'bulwark_ui' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
& $scExe stop $UserService 2>&1 | Out-Null
$stopped = $false
for ($i = 0; $i -lt 30; $i++) {
    $svc = Get-Service -Name $UserService -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -eq 'Stopped') { $stopped = $true; break }
    Start-Sleep -Seconds 1
}
if ($stopped) { Ok '已正常停止(本来没运行时报错属正常)' }
else          { Warn '服务未在 30 秒内停止,后面会强制结束进程' }

# ---- 2) 卸内核驱动 --------------------------------------------------------
# 排在「删服务注册」之前,因为内核注册表硬拦含 "\Services\Bulwark",驱动在载时
# sc delete 会被拦下;也排在「强杀进程」之前,因为驱动在载时本产品进程受内核
# 自我保护,外部拿不到 PROCESS_TERMINATE,Stop-Process 会静默失败。
Step '卸载内核驱动'
& $fltmc unload $DriverService 2>&1 | Out-Null
& $scExe  stop   $DriverService 2>&1 | Out-Null
Start-Sleep -Seconds 1
$stillLoaded = ($null -ne (& $fltmc filters 2>$null | Select-String -SimpleMatch $DriverService))
if ($stillLoaded) {
    Warn ($DriverService + ' 仍在 fltmc filters 中 —— 重启后会彻底卸掉')
    Info '驱动还在的情况下,自我保护会拦住删 .sys、删安装目录和删服务键,下面几步可能失败。'
    $needReboot = $true
} else {
    Ok '驱动已卸载'
}

# ---- 3) 删服务注册 -------------------------------------------------------
# 用户态服务【先删】:只要它的注册还在,SCM 就可能因为刚才的强制结束而把它拉回来。
# 注册删掉之后,那条自愈策略就没有可拉起的目标了。
Step '删除服务注册'
foreach ($svc in @($UserService, $DriverService)) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        & $scExe delete $svc 2>&1 | Out-Null
        Start-Sleep -Milliseconds 500
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Warn ($svc + ' 删除未生效(重启后消失)'); $needReboot = $true
        } else { Ok ($svc + ' 已删除') }
    } else { Ok ($svc + ' 未注册(跳过)') }
}

# 注册没了,现在才轮到「还活着的进程」。这时杀掉也不会被拉回来。
$alive = @()
for ($i = 1; $i -le 10; $i++) {
    $alive = @(Get-Process -Name 'bulwark_service', 'bulwark_ui' -ErrorAction SilentlyContinue)
    if ($alive.Count -eq 0) { break }
    $alive | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}
if ($alive.Count -gt 0) {
    Warn ('以下进程仍在运行:' + (($alive | ForEach-Object { $_.ProcessName + '(' + $_.Id + ')' }) -join '、'))
    $needReboot = $true
}

# ---- 4) 删 System32 里的驱动 ---------------------------------------------
Step '删除 System32\drivers\Bulwark.sys'
if (Test-Path $dstSys) {
    try { Remove-Item $dstSys -Force -ErrorAction Stop; Ok '已删除' }
    catch { Warn '删除失败(驱动可能仍加载中)—— 重启后再运行一次卸载即可'; $needReboot = $true }
} else { Ok '文件不存在(跳过)' }

# ---- 5) 移除测试证书 -----------------------------------------------------
# 只移除【本产品导入的】那一张。安装时记过一笔;没有记录就按「不是我们导入的」
# 处理 —— 别人可能靠这张证书跑别的自签名驱动,多删会把那个一起弄坏,而且没人会
# 想到是卸载干的。
Step '移除驱动签名证书'
$certByUs = Get-Mark 'CertImportedByUs'
if ($KeepCert) {
    Ok ('按 -KeepCert 保留 ' + $CertSubject)
} elseif ($certByUs -ne 1) {
    if ($null -eq $certByUs) { Info '没有导入记录(可能是便携包或旧版本装的)' }
    Ok ($CertSubject + ':不是本次安装导入的,保持不动')
    Info ('确实要删:证书管理器 certlm.msc -> 受信任的根证书颁发机构 / 受信任的发布者 -> ' + $CertSubject)
} else {
    $n = 0
    foreach ($store in @('Root', 'TrustedPublisher')) {
        Get-ChildItem ('Cert:\LocalMachine\' + $store) -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like ('*' + $CertSubject + '*') } |
            ForEach-Object { Remove-Item $_.PSPath -Force -ErrorAction SilentlyContinue; $n++ }
    }
    if ($n -gt 0) { Ok ('已移除 ' + $n + ' 份 ' + $CertSubject + ' 证书') } else { Ok '没有找到需要移除的证书' }
}

# ---- 6) 关闭测试签名 -----------------------------------------------------
# 这是唯一一项动了「别人也可能在用」的机器全局设置的操作,所以判断要讲清楚。
Step '测试签名模式'
$tsByUs = Get-Mark 'TestSigningEnabledByUs'
if ($KeepTestSigning) {
    Ok '按 -KeepTestSigning 保留测试签名开启状态'
} elseif ($tsByUs -ne 1) {
    Ok '测试签名不是本产品开启的,保持不动'
    Info '确实要关(会让其他测试签名驱动一起加载不了):管理员运行 bcdedit /set testsigning off 后重启'
} else {
    $out = (& $bcdedit /set testsigning off 2>&1) -join ' '
    if ($LASTEXITCODE -eq 0) {
        Ok '测试签名已关闭 —— 重启后生效,右下角「测试模式」水印随之消失'
        $needReboot = $true
    } else {
        Bad ('bcdedit /set testsigning off 失败:' + $out)
        Info '常见原因:BitLocker 已启用(需先挂起),或被其他安全软件拦下。'
    }
}

# ---- 7) 快捷方式 / 卸载项 / 自启项 ---------------------------------------
Step '清理快捷方式与注册项'
if ($SystemOnly) {
    Info '快捷方式与「应用和功能」条目由卸载程序自己删(跳过)'
} else {
    $sm = Join-Path $env:ProgramData ('Microsoft\Windows\Start Menu\Programs\' + $ProductShort)
    if (Test-Path $sm) {
        Remove-Item $sm -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $sm) { Warn '开始菜单目录删除失败' } else { Ok '已删除开始菜单项' }
    } else { Ok '开始菜单项不存在(跳过)' }

    $lnkName = '磐垒主动防御.lnk'
    foreach ($d in @([Environment]::GetFolderPath('CommonDesktopDirectory'),
                     [Environment]::GetFolderPath('Desktop'))) {
        if (-not $d) { continue }
        $p = Join-Path $d $lnkName
        if (Test-Path $p) {
            Remove-Item $p -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $p)) { Ok ('已删除 ' + $p) }
        }
    }

    if (Test-Path $ArpKey) {
        Remove-Item $ArpKey -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $ArpKey) { Warn '控制面板卸载项删除失败' } else { Ok '已删除控制面板卸载项' }
    } else { Ok '控制面板卸载项不存在(跳过)' }
}

# 界面会给【每个登录过的用户】写一条 HKCU 开机自启。卸载只清当前用户是不够的:
# 换个账户登录时那条还在,会去启动一个已经被删掉的 exe。所以遍历 HKEY_USERS 下
# 已加载的 hive 一并清掉(未登录用户的 hive 没挂上,清不到 —— 但那条自启动项
# 要到他登录时才会执行,而那时 exe 已经不存在,只是一次静默失败)。
$runCleared = 0
foreach ($hive in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
    if ($hive.PSChildName -like '*_Classes') { continue }
    $runKey = 'Registry::' + $hive.Name + '\Software\Microsoft\Windows\CurrentVersion\Run'
    if (-not (Test-Path $runKey)) { continue }
    $v = Get-ItemProperty -Path $runKey -Name $ProductShort -ErrorAction SilentlyContinue
    if ($v) {
        Remove-ItemProperty -Path $runKey -Name $ProductShort -Force -ErrorAction SilentlyContinue
        if (-not (Get-ItemProperty -Path $runKey -Name $ProductShort -ErrorAction SilentlyContinue)) { $runCleared++ }
    }
}
if ($runCleared -gt 0) { Ok ('已清除 ' + $runCleared + ' 条开机自启项(HKU\...\CurrentVersion\Run\Bulwark)') }
else { Ok '没有需要清除的开机自启项' }

# 便携包留下的「重启后自动继续」(如果对方先试过便携包)一并清掉。
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' `
                    -Name 'BulwarkSetupResume' -ErrorAction SilentlyContinue

# ---- 8) 数据目录 ---------------------------------------------------------
# 这里放的是用户攒下来的规则、审计日志,以及隔离区里的【真实恶意样本】。
# 删掉不可逆,所以不默认删:要么显式加开关,要么当场问一句。
Step '数据目录'
if (-not (Test-Path $dataDir)) {
    Ok '数据目录不存在(跳过)'
} else {
    $files = @(Get-ChildItem $dataDir -Recurse -File -ErrorAction SilentlyContinue)
    $mb = 0
    if ($files.Count -gt 0) { $mb = [math]::Round((($files | Measure-Object -Property Length -Sum).Sum) / 1MB, 1) }
    $qDir = Join-Path $dataDir 'quarantine'
    $qn = 0
    if (Test-Path $qDir) { $qn = @(Get-ChildItem $qDir -Recurse -File -ErrorAction SilentlyContinue).Count }
    Info ('路径:' + $dataDir)
    Info ('内容:' + $files.Count + ' 个文件,约 ' + $mb + ' MB;隔离区样本 ' + $qn + ' 个')

    $doPurge = $false
    if ($PurgeData) { $doPurge = $true }
    elseif ($KeepData) { $doPurge = $false }
    else {
        Write-Host ''
        Write-Host '  这里面有你的自定义规则、审计日志' -NoNewline -ForegroundColor Yellow
        if ($qn -gt 0) { Write-Host ('、以及 ' + $qn + ' 个隔离的真实恶意样本') -NoNewline -ForegroundColor Yellow }
        Write-Host ';删除不可恢复。' -ForegroundColor Yellow
        try {
            $ans = Read-Host '  一并删除数据目录吗?(y/N,默认 N=保留)'
            if ($ans -match '^[Yy]') { $doPurge = $true }
        } catch {
            # 非交互(被别的脚本管道调用)时读不到输入 —— 按保留处理,
            # 绝不在无人应答的情况下删用户数据。
            Info '(非交互环境,按保留处理;需要删除请加 -PurgeData)'
        }
    }
    if (-not $doPurge) {
        Ok '已保留数据目录(需要删除:卸载.bat -PurgeData,或手动删该文件夹)'
    } else {
        Remove-Item $dataDir -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $dataDir) {
            $left = @(Get-ChildItem $dataDir -Recurse -File -ErrorAction SilentlyContinue).Count
            Warn ('数据目录未能完全删除,还剩 ' + $left + ' 个文件')
            if ($stillLoaded) { Info '驱动仍在加载中,自我保护会拦住删除 —— 重启后再删一次即可。' }
            else { Info '可能有文件被占用 —— 重启后手动删除该文件夹即可。' }
        } else { Ok '数据目录已删除' }
    }
}

# ---- 9) 安装目录 ---------------------------------------------------------
# 本脚本自己就在安装目录里,而调用它的 卸载.bat 也还被 cmd.exe 打开着,所以
# 不能在这里同步删除整个目录。做法:先删掉能删的,再交给一个脱离本进程的
# cmd 在几秒后把剩下的清掉 —— 那时 .bat 与 .ps1 的文件句柄都已经释放。
Step '删除安装目录'
if ($SystemOnly) {
    Ok '程序文件由卸载程序自己删(跳过)'
    Info '本脚本此刻还在安装目录里运行,抢着删会让卸载程序随后报「文件缺失」。'
} elseif (-not (Test-Path $Dir)) {
    Ok '安装目录不存在(跳过)'
} else {
    Set-Location $env:SystemRoot   # 别把当前目录留在要删的树里,否则删不掉
    $self = @('卸载.bat', 'uninstall.ps1')
    $left = 0
    foreach ($f in @(Get-ChildItem $Dir -Recurse -File -ErrorAction SilentlyContinue)) {
        if ($self -contains $f.Name) { continue }
        try { Remove-Item $f.FullName -Force -ErrorAction Stop } catch { $left++ }
    }
    if ($left -eq 0) { Ok '程序文件已删除' } else { Warn ('有 ' + [string]$left + ' 个文件删除失败(被占用或被自我保护拦下)') }

    # ping 而不是 timeout:timeout 需要控制台输入句柄,在脱离的进程里会直接报错退出。
    $q = '"' + $Dir + '"'
    Start-Process -FilePath $cmdExe `
                  -ArgumentList ('/c ping -n 5 127.0.0.1 >nul & rd /s /q ' + $q) `
                  -WindowStyle Hidden | Out-Null
    Info ('已安排在几秒后删除目录本身:' + $Dir)
}

# ---- 10) 安装痕迹 --------------------------------------------------------
# 放在最后:上面每一步都要读它(是不是我们开的测试签名、是不是我们导入的证书)。
Step '清理安装痕迹'
if (Test-Path $StateKey) {
    Remove-Item $StateKey -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $StateKey) { Warn ($StateKey + ' 删除失败') } else { Ok '已删除安装痕迹' }
} else { Ok '没有安装痕迹(跳过)' }

# ---- 复查 ----------------------------------------------------------------
# 光打印「卸载完成」是不够的:上面每一步都可能被自我保护、文件占用或 bcdedit
# 拦下。这里把结果重新读一遍,残留了什么就直说。
Step '复查(重新读一遍真实状态)'
$leftover = @()
if ($null -ne (& $fltmc filters 2>$null | Select-String -SimpleMatch $DriverService)) { $leftover += '内核驱动仍处于加载状态' }
foreach ($svc in @($DriverService, $UserService)) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) { $leftover += ('服务 ' + $svc + ' 仍存在') }
}
if (Test-Path $dstSys) { $leftover += 'System32\drivers\Bulwark.sys 仍存在' }
if (@(Get-Process -Name 'bulwark_service', 'bulwark_ui' -ErrorAction SilentlyContinue).Count -gt 0) { $leftover += '本产品进程仍在运行' }
if ((-not $KeepCert) -and $certByUs -eq 1) {
    $cn = 0
    foreach ($store in @('Root', 'TrustedPublisher')) {
        $cn += @(Get-ChildItem ('Cert:\LocalMachine\' + $store) -ErrorAction SilentlyContinue |
                 Where-Object { $_.Subject -like ('*' + $CertSubject + '*') }).Count
    }
    if ($cn -gt 0) { $leftover += ($CertSubject + ' 证书仍有 ' + $cn + ' 份') }
}
if (Test-Path $ArpKey)   { $leftover += '控制面板卸载项仍存在' }
if (Test-Path $StateKey) { $leftover += '安装痕迹键仍存在' }

Write-Host ''
if ($leftover.Count -eq 0) {
    Write-Host '==== 卸载完成:没有残留 ====' -ForegroundColor Green
} else {
    Write-Host '==== 卸载基本完成,但还有残留 ====' -ForegroundColor Yellow
    foreach ($x in $leftover) { Bad $x }
    Write-Host ''
    Info '这些几乎都是「文件/服务还被内核占着」造成的:重启一次,再跑一遍卸载即可清干净。'
}
Write-Host ''
if ($needReboot) { Warn '需要重启一次才能完全生效(彻底卸掉驱动 / 退出测试模式)。' }
Info '数据目录若选择了保留,可随时手动删除:' 
Info ('  ' + $dataDir)
Write-Host ''
