# =====================================================================
#  磐垒主动防御 便携包 —— 唯一入口脚本
#
#  双击 启动Bulwark.bat 就够了。本脚本【全程幂等】:每一步都先查状态,
#  已经就绪的直接跳过。所以第一次运行是「安装 + 启动」,以后每次运行
#  就只是「启动」,不需要记住自己上次做到哪一步。
#
#  完整流程(缺哪步补哪步):
#    1) 信任随包驱动的签名证书(导入 LocalMachine Root + TrustedPublisher)
#    2) Secure Boot / HVCI 体检 —— 这两项开着,测试签名一定无效
#    3) 开启测试签名(bcdedit),需重启一次;可选重启后自动接着装
#    4) 把 Bulwark.sys 复制到 System32\drivers
#    5) 以 Minifilter 语义注册服务(type=filesys + FltMgr +
#       Instances\DefaultInstance + Altitude=385201 + Flags=0)
#    6) fltmc load 加载并验证
#    7) 拉起后台服务 + 界面;关掉界面后自动收摊
#
#  ⚠ 内核回调里出错会直接蓝屏(BSOD)。首次务必在【带快照的测试虚拟机】
#    里验证;真机运行前请先建系统还原点。
#
#  参数(平时都不用加):
#    -Check              只体检,不改动任何东西
#    -Uninstall          卸载驱动、删服务、删 .sys
#      └ -RemoveCert / -DisableTestSigning / -All   卸载时额外清理
#    -SetupOnly          只做安装,不启动服务和界面
#    -BootStart          驱动改为开机随系统加载(消除重启后的防护空窗)
#    -InstallService     把用户态服务也注册成开机自启(防护常驻)
#    -NoAutoResume       开启测试签名后不设置「重启后自动继续」
# =====================================================================
[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Uninstall,
    [switch]$SetupOnly,
    [switch]$BootStart,
    [switch]$InstallService,
    [switch]$RemoveCert,
    [switch]$DisableTestSigning,
    [switch]$All,
    [switch]$NoAutoResume
)

$ErrorActionPreference = 'Stop'

$ServiceName = 'Bulwark'            # 内核 Minifilter 服务名
$UserService = 'BulwarkService'     # 用户态服务名(刻意与内核服务区分,避免冲突)
$Instance    = 'Bulwark Instance'
$Altitude    = '385201'
$CertSubject = 'BulwarkTestCert'

$pkgDir = $PSScriptRoot

function Ok($m)    { Write-Host "  [OK]   $m" -ForegroundColor Green }
function Warn($m)  { Write-Host "  [!]    $m" -ForegroundColor Yellow }
function Bad($m)   { Write-Host "  [X]    $m" -ForegroundColor Red }
function Info($m)  { Write-Host "         $m" -ForegroundColor DarkGray }
function Step($m)  { Write-Host ''; Write-Host "== $m ==" -ForegroundColor Cyan }

# ---- 管理员 ---------------------------------------------------------------
$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $Check) {
    throw '请以【管理员】身份运行(双击 启动Bulwark.bat 会自动提权)。'
}

# ---- 工具路径 -------------------------------------------------------------
# fltmc / sc / bcdedit 只存在于 64 位 System32。32 位宿主访问会被 WOW64
# 重定向到 SysWOW64 然后「找不到文件」,所以按位数解析绝对路径,不靠 PATH。
$sysNative = Join-Path $env:SystemRoot 'Sysnative'
$sysDir = Join-Path $env:SystemRoot 'System32'
if (Test-Path (Join-Path $sysNative 'bcdedit.exe')) { $sysDir = $sysNative }
$bcdedit  = Join-Path $sysDir 'bcdedit.exe'
$scExe    = Join-Path $sysDir 'sc.exe'
$fltmc    = Join-Path $sysDir 'fltmc.exe'
$regExe   = Join-Path $sysDir 'reg.exe'
$shutdown = Join-Path $sysDir 'shutdown.exe'

$srcSys = Join-Path $pkgDir 'Bulwark.sys'
$dstSys = Join-Path (Join-Path $env:SystemRoot 'System32\drivers') 'Bulwark.sys'

# =====================================================================
#  状态探测 —— 安装流程和 -Check 体检共用同一套判据,不会两处逻辑打架
# =====================================================================
function Get-BulwarkState {
    $s = @{}
    $s.HasSrcSys = Test-Path $srcSys
    $s.SigStatus = '-'
    $s.Signer    = $null
    if ($s.HasSrcSys) {
        $sig = Get-AuthenticodeSignature $srcSys
        $s.SigStatus = [string]$sig.Status
        $s.Signer    = $sig.SignerCertificate
    }
    # 证书是否已被本机信任(有 Root 里的同指纹即可建立信任链)
    $s.CertTrusted = $false
    if ($s.Signer) {
        $s.CertTrusted = $null -ne (Get-ChildItem 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue |
                                    Where-Object { $_.Thumbprint -eq $s.Signer.Thumbprint })
    }
    $s.TestSigning = $false
    try {
        $line = ((& $bcdedit) 2>$null | Select-String -SimpleMatch 'testsigning') -join ' '
        $s.TestSigning = ($line -match 'Yes|是')
    } catch { }
    $s.SecureBoot = $false
    try { $s.SecureBoot = [bool](Confirm-SecureBootUEFI) } catch { }
    $s.Hvci = $false
    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
                              -ClassName Win32_DeviceGuard -ErrorAction Stop
        $s.Hvci = ($dg.SecurityServicesRunning -contains 2)
    } catch { }
    $s.Staged     = Test-Path $dstSys
    $s.StagedSize = 0
    if ($s.Staged) { $s.StagedSize = (Get-Item $dstSys).Length }
    $s.SrcSize = 0
    if ($s.HasSrcSys) { $s.SrcSize = (Get-Item $srcSys).Length }
    $s.SvcExists = $null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
    $s.AltitudeOk = $false
    if ($s.SvcExists) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Instances\$Instance"
        $a = (Get-ItemProperty -Path $key -Name Altitude -ErrorAction SilentlyContinue).Altitude
        $s.AltitudeOk = ($a -eq $Altitude)
    }
    $s.Loaded = $false
    try { $s.Loaded = $null -ne (& $fltmc filters 2>$null | Select-String -SimpleMatch $ServiceName) } catch { }
    return $s
}

# =====================================================================
#  体检(只读)
# =====================================================================
function Invoke-Check {
    $s = Get-BulwarkState
    Step '包内文件'
    # Qt 的 platforms\qwindows.dll 缺失 -> 界面根本起不来。
    # tls\ 缺失 -> 所有 HTTPS 情报查询静默失败(TLS 后端是插件,不在 Qt6Network 里)。
    $need = [ordered]@{
        'bulwark_service.exe'            = '后台服务(决策中心)'
        'bulwark_ui.exe'                 = '界面 + 行为询问弹窗'
        'Bulwark.sys'                    = '内核驱动(行为前拦截)'
        'appsettings.json'               = '配置'
        'platforms\qwindows.dll'         = 'Qt 窗口后端(缺则界面起不来)'
        'styles\qmodernwindowsstyle.dll' = 'Qt 样式'
        'Qt6Core.dll'                    = 'Qt 核心'
        'Qt6Gui.dll'                     = 'Qt 图形'
        'Qt6Network.dll'                 = 'Qt 网络'
        'Qt6Widgets.dll'                 = 'Qt 控件'
    }
    foreach ($k in $need.Keys) {
        $p = Join-Path $pkgDir $k
        if (Test-Path $p) { Ok ("{0,-32} {1,12:N0} B" -f $k, (Get-Item $p).Length) }
        else { Bad ("{0,-32} 缺失 - {1}" -f $k, $need[$k]) }
    }
    $tlsDir = Join-Path $pkgDir 'tls'
    $tlsFiles = @()
    if (Test-Path $tlsDir) { $tlsFiles = @(Get-ChildItem $tlsDir -Filter '*.dll' -File -ErrorAction SilentlyContinue) }
    if ($tlsFiles.Count -gt 0) { Ok ("{0,-32} {1}" -f 'tls\ (HTTPS 后端)', (($tlsFiles.Name) -join ', ')) }
    else { Bad ("{0,-32} 缺失 - 所有 HTTPS 云查会静默失败" -f 'tls\ (HTTPS 后端)') }

    # MSVC 运行库。缺了它 exe 在【进入 main 之前】就被系统弹框挡下
    # (「找不到 MSVCP140.dll」),没有日志、没有窗口,从现象上完全看不出
    # 是缺 DLL 还是程序坏了。开发机装过 VC++ 运行时所以永远发现不了。
    $crt = @('msvcp140.dll','msvcp140_1.dll','msvcp140_2.dll','vcruntime140.dll','vcruntime140_1.dll')
    $crtMissing = @($crt | Where-Object { -not (Test-Path (Join-Path $pkgDir $_)) })
    if ($crtMissing.Count -eq 0) { Ok ("{0,-32} {1}" -f 'MSVC 运行库', '5 个 DLL 齐全') }
    else { Bad ("{0,-32} 缺失 {1} - 程序会在启动前被系统挡下" -f 'MSVC 运行库', ($crtMissing -join ', ')) }

    Step '配置 (appsettings.json)'
    $cfg = Join-Path $pkgDir 'appsettings.json'
    if (-not (Test-Path $cfg)) { Bad 'appsettings.json 缺失' }
    else {
        try {
            $b = ((Get-Content $cfg -Raw -Encoding UTF8) | ConvertFrom-Json).Bulwark
            if ($b.EventSource -eq 'Driver') { Ok 'EventSource = Driver(内核前拦截)' }
            else { Warn ("EventSource = " + $b.EventSource + " —— 只做用户态观测,拦不住行为前") }
            $rp = $b.ReputationProxy
            if ($rp.BaseUrl -and $rp.BaseUrl.Trim() -ne '') { Warn ('信誉代理端点为明文:' + $rp.BaseUrl) }
            elseif ($rp.BaseUrlObfuscated) { Ok '信誉代理端点已混淆' }
            else { Warn '信誉代理端点未配置 —— 云查不可用' }
            $secret = @(@('ReputationProxy','BearerToken'),@('VirusTotal','ApiKey'),@('MalwareBazaar','AuthKey'),
                        @('Otx','ApiKey'),@('ThreatBook','ApiKey'),@('MetaDefender','ApiKey'),
                        @('HybridAnalysis','ApiKey'),@('ThreatFoxFeed','AuthKey'),@('Ai','ApiKey'))
            $leak = @()
            foreach ($sp in $secret) { $v = $b.($sp[0]).($sp[1]); if ($v -and $v.ToString().Trim() -ne '') { $leak += ($sp[0]+'.'+$sp[1]) } }
            if ($leak.Count -eq 0) { Ok '密钥字段全部为空(便携包应当如此,用环境变量或界面注入)' }
            else { Warn ('明文密钥:' + ($leak -join ', ')) }
        } catch { Bad ('appsettings.json 解析失败:' + $_.Exception.Message) }
    }

    Step '驱动加载前置条件'
    if ($s.SigStatus -eq 'Valid') { Ok ('驱动签名 Valid —— ' + $s.Signer.Subject) }
    elseif ($s.SigStatus -eq 'NotSigned') { Bad '驱动未签名 —— 内核一定拒载' }
    elseif ($null -ne $s.Signer) { Warn ('驱动签名 ' + $s.SigStatus + ' —— 证书尚未被本机信任(本脚本会自动导入)') }
    else { Bad '驱动签名无法读取' }
    if ($s.TestSigning) { Ok '测试签名已开启' } else { Bad '测试签名未开启 —— 自签名驱动无法加载' }
    if ($s.SecureBoot) { Bad 'Secure Boot 已开启 —— 会让测试签名完全失效,需进 BIOS/UEFI 关闭' }
    else { Ok 'Secure Boot 已关闭' }
    if ($s.Hvci) { Bad 'HVCI/内存完整性 正在运行 —— 会让测试签名失效(安全中心 > 设备安全性 > 内核隔离)' }
    else { Ok 'HVCI/内存完整性 未运行' }

    Step '安装与运行状态'
    if (-not $s.Staged) { Bad 'System32\drivers\Bulwark.sys 未部署' }
    elseif ($s.StagedSize -ne $s.SrcSize) { Warn ('已部署但与包内版本大小不一致(' + $s.StagedSize + ' vs ' + $s.SrcSize + ')—— 加载的可能是旧驱动') }
    else { Ok 'System32\drivers\Bulwark.sys 已部署且与包内一致' }
    if (-not $s.SvcExists) { Bad "内核服务 $ServiceName 未注册" }
    else {
        Ok "内核服务 $ServiceName 已注册"
        if ($s.AltitudeOk) { Ok "  Instances/Altitude = $Altitude" }
        else { Bad '  Instances/Altitude 缺失或不符 —— 驱动不会附加到卷,等于白装' }
    }
    if ($s.Loaded) {
        Ok '驱动已加载'
        (& $fltmc filters 2>$null | Select-String -SimpleMatch $ServiceName) |
            ForEach-Object { Info $_.Line.Trim() }
    } else { Bad '驱动未加载 —— 当前【没有】行为前拦截' }
    if (Get-Service -Name $UserService -ErrorAction SilentlyContinue) {
        Ok "用户态服务 $UserService 已注册(常驻模式)"
    } else { Ok "用户态服务 $UserService 未注册(便携模式,由本脚本直接拉起进程)" }
    foreach ($pn in @('bulwark_service','bulwark_ui')) {
        $p = Get-Process -Name $pn -ErrorAction SilentlyContinue
        if ($p) { Ok ("$pn.exe 运行中,PID " + (($p.Id) -join ',')) } else { Info "$pn.exe 未运行" }
    }
    $dataDir = Join-Path $env:ProgramData 'Bulwark'
    if (Test-Path $dataDir) {
        Ok "数据目录 $dataDir"
        $bs = Join-Path $dataDir 'bootstrap-status.txt'
        # 服务用 toUtf8() 写这个文件。Get-Content 不指定编码时,PS 5.1 在 zh-CN 上按
        # GBK 解码,整段中文变乱码 —— 而这个文件恰恰是「起不来时第一个要看的东西」。
        if (Test-Path $bs) {
            Info '--- 上次自举记录 ---'
            Get-Content $bs -Encoding UTF8 -EA SilentlyContinue | ForEach-Object { Info $_ }
        }
    } else { Info "数据目录尚未创建(服务从未成功启动过)" }

    Write-Host ''
    if ($s.Loaded) { Write-Host '  当前防护形态:内核前拦截(真正的行为前阻断)' -ForegroundColor Green }
    else { Write-Host '  当前防护形态:用户态观测(只能事后终止,拦不住行为前)—— 双击 启动Bulwark.bat 即可自动安装' -ForegroundColor Yellow }
    Write-Host ''
}

# =====================================================================
#  卸载 —— 这是正经安全工具,始终保留用户自主卸载的通路,不做成「删不掉」
# =====================================================================
function Invoke-Uninstall {
    if ($All) { $script:RemoveCert = $true; $script:DisableTestSigning = $true }
    $ErrorActionPreference = 'Continue'   # 卸载要尽力做完每一步,不能中途抛异常留半套

    Step '停止用户态'
    & $scExe stop $UserService 2>&1 | Out-Null
    Get-Process -Name 'bulwark_ui','bulwark_service' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Ok '已停止(未运行时报错属正常)'

    # 顺序必须是「先卸驱动,再删注册」:驱动在载时 .sys 被锁死,而且内核自我
    # 保护会硬拦对 \Services\Bulwark* 的注册表写入,顺序反了两步都会失败。
    Step '卸载内核驱动'
    & $fltmc unload $ServiceName 2>&1 | Out-Null
    & $scExe  stop   $ServiceName 2>&1 | Out-Null
    Start-Sleep -Seconds 1
    if ($null -ne (& $fltmc filters 2>$null | Select-String -SimpleMatch $ServiceName)) {
        Warn "$ServiceName 仍在 fltmc filters 中 —— 重启后会彻底卸掉"
    } else { Ok '驱动已卸载' }

    Step '删除服务注册'
    foreach ($svc in @($ServiceName, $UserService)) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            & $scExe delete $svc 2>&1 | Out-Null
            if (Get-Service -Name $svc -ErrorAction SilentlyContinue) { Warn "$svc 删除未生效(重启后消失)" }
            else { Ok "$svc 已删除" }
        } else { Ok "$svc 未注册(跳过)" }
    }

    Step '删除 System32\drivers\Bulwark.sys'
    if (Test-Path $dstSys) {
        try { Remove-Item $dstSys -Force; Ok '已删除' }
        catch { Warn '删除失败(驱动可能仍加载中)—— 重启后再运行一次即可' }
    } else { Ok '文件不存在(跳过)' }

    Step '可选清理'
    if ($RemoveCert) {
        $n = 0
        foreach ($store in @('Root','TrustedPublisher')) {
            Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -like "*$CertSubject*" } |
                ForEach-Object { Remove-Item $_.PSPath -Force -ErrorAction SilentlyContinue; $n++ }
        }
        Ok "已移除 $n 份 $CertSubject 证书"
    } else { Ok "保留测试证书(加 -RemoveCert 可移除)" }
    if ($DisableTestSigning) {
        & $bcdedit /set testsigning off | Out-Null
        Ok '测试签名已关闭(重启后生效,「测试模式」水印消失)'
    } else { Ok '保留测试签名设置(加 -DisableTestSigning 可关闭)' }
    # 装过「重启后自动继续」就一并清掉,免得卸载后还被拉起来
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' `
                        -Name 'BulwarkSetupResume' -ErrorAction SilentlyContinue

    Write-Host ''
    Write-Host '==== 卸载完成 ====' -ForegroundColor Cyan
    Info '便携包文件夹可以直接删除。'
    Info "规则/日志/隔离区在 $(Join-Path $env:ProgramData 'Bulwark'),需要的话手动删该目录。"
    Write-Host ''
}

# =====================================================================
#  安装 / 确保驱动就绪。返回 $true = 驱动已加载;$null = 需要重启后再来
# =====================================================================
function Ensure-Driver {
    $s = Get-BulwarkState

    if ($s.Loaded -and $s.StagedSize -eq $s.SrcSize) {
        Ok '内核驱动已加载且为最新版本'
        return $true
    }

    if (-not $s.HasSrcSys) {
        Bad "本目录下没有 Bulwark.sys:$pkgDir"
        Info '请确认本脚本与 bulwark_ui.exe 放在同一个文件夹里。'
        return $false
    }

    # ---- 1) 信任签名证书 --------------------------------------------------
    # 便携包里没有私钥,不可能在目标机上重新签名。随包 .sys 已用自签测试证书
    # 签过,所以做法是把它自带的签名者证书提出来导入 Root(建链)+
    # TrustedPublisher(免「是否信任发布者」提示)。
    if ($null -eq $s.Signer) {
        Bad '随包 Bulwark.sys 没有数字签名,无法加载。'
        return $false
    }
    if ($s.CertTrusted) {
        Ok ('签名证书已被信任 —— ' + $s.Signer.Subject)
    } else {
        $cerPath = Join-Path $env:TEMP 'BulwarkDriverSigner.cer'
        [IO.File]::WriteAllBytes($cerPath, $s.Signer.Export('Cert'))
        foreach ($store in @('Root','TrustedPublisher')) {
            $dup = Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue |
                   Where-Object { $_.Thumbprint -eq $s.Signer.Thumbprint }
            if (-not $dup) { Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null }
        }
        Remove-Item $cerPath -Force -ErrorAction SilentlyContinue
        Ok ('已信任签名证书 —— ' + $s.Signer.Subject)
        Info ('指纹 ' + $s.Signer.Thumbprint)
        $now = (Get-AuthenticodeSignature $srcSys).Status
        if ($now -ne 'Valid') { Warn "信任后签名状态仍为 $now,加载可能失败。" }
    }

    # ---- 2) Secure Boot / HVCI ------------------------------------------
    # 这两项开着时 testsigning 是【无效】的。与其让 fltmc 报一个看不懂的错,
    # 不如在这里就明确告诉用户去关哪个开关。
    $blockers = @()
    if ($s.SecureBoot) { $blockers += 'Secure Boot 已开启 —— 需进 BIOS/UEFI 关闭' }
    if ($s.Hvci)       { $blockers += 'HVCI/内存完整性 正在运行 —— 需在「Windows 安全中心 > 设备安全性 > 内核隔离」关闭' }
    if ($blockers.Count -gt 0) {
        foreach ($b in $blockers) { Bad $b }
        Write-Host ''
        Write-Host '  以上项目会让测试签名失效,自签名驱动一定加载不了。' -ForegroundColor Red
        Write-Host '  关闭后再双击 启动Bulwark.bat 即可继续。' -ForegroundColor Yellow
        return $false
    }
    Ok 'Secure Boot / HVCI 均已关闭,测试签名可生效'

    # ---- 3) 测试签名 -----------------------------------------------------
    if (-not $s.TestSigning) {
        Warn '测试签名未开启,正在开启...'
        & $bcdedit /set testsigning on | Out-Null
        if ($LASTEXITCODE -ne 0) { Bad 'bcdedit /set testsigning on 失败。'; return $false }
        Ok '测试签名已开启 —— 需要重启一次才能生效'
        Write-Host ''
        if (-not $NoAutoResume) {
            # RunOnce 是自删除的,不留常驻状态;重启后自动接着把驱动装完,
            # 用户不用记得「我上次做到哪一步」。
            $ans = Read-Host '  重启后自动继续安装并启动?(Y/N,默认 Y)'
            if ($ans -eq '' -or $ans -match '^[Yy]') {
                try {
                    $bat = Join-Path $pkgDir '启动Bulwark.bat'
                    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' `
                                     -Name 'BulwarkSetupResume' -Value ('"' + $bat + '"') -Force
                    Ok '已设置:重启登录后自动继续(会弹一次管理员授权)'
                } catch { Warn '设置自动继续失败,重启后请手动再双击一次 启动Bulwark.bat。' }
            }
        }
        Write-Host ''
        $r = Read-Host '  现在重启吗?(Y/N)'
        if ($r -match '^[Yy]') { & $shutdown /r /t 5; Write-Host '  5 秒后重启...' -ForegroundColor Yellow }
        else { Write-Host '  请稍后手动重启;重启后本流程会继续。' -ForegroundColor Yellow }
        Info '重启后桌面右下角会出现「测试模式」水印,这是正常的。'
        return $null   # 需要重启,不继续
    }
    Ok '测试签名已开启'

    # ---- 4) 停旧实例 + 复制 ---------------------------------------------
    # 复制前必须先卸载:文件被内核加载时是锁死的。注册表写入同理 ——
    # 内核自我保护会硬拦对 \Services\Bulwark* 的改动。
    if ($s.Loaded -or $s.StagedSize -ne $s.SrcSize) {
        & $fltmc unload $ServiceName 2>&1 | Out-Null
        & $scExe  stop   $ServiceName 2>&1 | Out-Null
        Start-Sleep -Seconds 1
    }
    # 与服务里 stageDriverBinary() 的「已存在就不覆盖」不同:这里是显式安装,
    # 包内版本应当覆盖旧的 —— 否则更新了包,加载的还是上一版驱动,
    # 现象是「明明改了却没用」。
    try {
        Copy-Item $srcSys $dstSys -Force
        Ok ("驱动已部署到 System32\drivers({0:N0} B)" -f (Get-Item $dstSys).Length)
    } catch {
        Bad ('复制驱动失败:' + $_.Exception.Message)
        Info '驱动可能仍处于加载状态,重启后再双击 启动Bulwark.bat 即可。'
        return $false
    }

    # ---- 5) 注册 Minifilter ---------------------------------------------
    # 少了 Instances/Altitude 这一步,驱动不会附加到卷,文件和注册表回调
    # 一个都不会触发 —— 服务能连上端口,但什么都拦不到。
    $s2 = Get-BulwarkState
    $startType = 'demand'
    if ($BootStart) { $startType = 'system' }
    $needRegister = -not ($s2.SvcExists -and $s2.AltitudeOk)
    if ($BootStart) { $needRegister = $true }
    if ($needRegister) {
        if ($s2.SvcExists) { & $scExe delete $ServiceName 2>&1 | Out-Null; Start-Sleep -Seconds 1 }
        & $scExe create $ServiceName type= filesys start= $startType `
            binPath= 'System32\drivers\Bulwark.sys' depend= FltMgr `
            group= 'FSFilter Activity Monitor' 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Bad "sc create 失败(退出码 $LASTEXITCODE)"; return $false }
        & $scExe description $ServiceName '磐垒主动防御内核驱动' 2>&1 | Out-Null
        $svcKey = "HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName"
        & $regExe add "$svcKey\Instances" /v DefaultInstance /t REG_SZ /d $Instance /f | Out-Null
        & $regExe add "$svcKey\Instances\$Instance" /v Altitude /t REG_SZ    /d $Altitude /f | Out-Null
        & $regExe add "$svcKey\Instances\$Instance" /v Flags    /t REG_DWORD /d 0 /f | Out-Null
        Ok "已注册 Minifilter:start=$startType altitude=$Altitude instance=`"$Instance`""
    } else {
        Ok '服务注册已正确(跳过,避免无谓写注册表撞上自我保护)'
    }

    # ---- 6) 加载 + 验证 --------------------------------------------------
    & $fltmc load $ServiceName 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { & $scExe start $ServiceName 2>&1 | Out-Null }
    Start-Sleep -Seconds 1
    # fltmc 输出表头是本地化的,但筛选器名一列就是字面 "Bulwark",按串匹配即可。
    if ($null -ne (& $fltmc filters 2>$null | Select-String -SimpleMatch $ServiceName)) {
        Ok '内核驱动已加载 —— 行为前拦截已启用'
        return $true
    }
    Bad '驱动加载失败'
    Info "排查:sc query $ServiceName / 本脚本加 -Check / DebugView(勾 Capture Kernel)"
    return $false
}

# =====================================================================
#  启动运行时
# =====================================================================
function Start-Runtime {
    # 确保用户态走驱动模式,否则驱动装好了也不会被用上
    $cfg = Join-Path $pkgDir 'appsettings.json'
    if (Test-Path $cfg) {
        $json = Get-Content $cfg -Raw -Encoding UTF8
        if ($json -notmatch '"EventSource"\s*:\s*"Driver"') {
            $new = [regex]::Replace($json, '("EventSource"\s*:\s*")[^"]*(")', '${1}Driver${2}')
            [IO.File]::WriteAllText($cfg, $new, (New-Object Text.UTF8Encoding($false)))
            Ok 'appsettings.json 的 EventSource 已改为 Driver'
        }
    }

    if ($InstallService) {
        # 走 exe 自己的 --install:它用 GetModuleFileName 写 ImagePath,天然指向
        # 便携包目录内的 exe。控制管道要求 UI 与服务同目录,手写路径极易把 UI
        # 自己挡在门外。
        $svcExe = Join-Path $pkgDir 'bulwark_service.exe'
        & $svcExe --install 2>&1 | Out-Null
        & $scExe start $UserService 2>&1 | Out-Null
        Ok "$UserService 已注册为开机自启并启动"
        Warn '常驻模式下本脚本不再托管服务;以后直接双击 bulwark_ui.exe 即可。'
        return
    }

    $svcExe = Join-Path $pkgDir 'bulwark_service.exe'
    $uiExe  = Join-Path $pkgDir 'bulwark_ui.exe'
    if (-not (Test-Path $svcExe)) { Bad "本目录没有 bulwark_service.exe"; return }
    if (-not (Test-Path $uiExe))  { Bad "本目录没有 bulwark_ui.exe"; return }

    # 已有实例时不再另起一个 —— 两个实例会抢同一条控制管道,表现是界面时通时不通。
    $existing = Get-Process -Name 'bulwark_service' -ErrorAction SilentlyContinue
    if ($existing) {
        Ok ('后台服务已在运行,PID ' + (($existing.Id) -join ','))
    } else {
        Start-Process -FilePath $svcExe -WorkingDirectory $pkgDir -WindowStyle Hidden
        Start-Sleep -Seconds 3
        if (-not (Get-Process -Name 'bulwark_service' -ErrorAction SilentlyContinue)) {
            Bad '后台服务启动失败'
            Info '常见原因:缺 Qt 运行库、appsettings.json 语法错误、无法写 %ProgramData%\Bulwark。'
            Info '用 启动Bulwark.bat -Check 体检。'
            return
        }
        Ok '后台服务已启动'
    }

    Start-Process -FilePath $uiExe -WorkingDirectory $pkgDir
    Start-Sleep -Seconds 2
    Ok '界面已启动'
    Write-Host ''
    Write-Host '  关闭界面后本窗口会自动停止服务与驱动。' -ForegroundColor DarkGray
    Write-Host '  想让防护常驻(开机自启、关界面也在)请运行一次:' -ForegroundColor DarkGray
    Write-Host '      启动Bulwark.bat -InstallService' -ForegroundColor DarkGray
    Write-Host ''

    while (Get-Process -Name 'bulwark_ui' -ErrorAction SilentlyContinue) { Start-Sleep -Seconds 2 }

    Write-Host '界面已关闭,正在停止服务与驱动...'
    Get-Process -Name 'bulwark_service' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    & $fltmc unload $ServiceName 2>&1 | Out-Null
    & $scExe  stop   $ServiceName 2>&1 | Out-Null
    Ok '已停止'
    Start-Sleep -Seconds 1
}

# =====================================================================
#  入口
# =====================================================================
Write-Host ''
Write-Host '==== 磐垒主动防御 (Bulwark HIPS) ====' -ForegroundColor Cyan

if ($Uninstall) { Invoke-Uninstall; return }
if ($Check)     { Invoke-Check;     return }

Write-Host '⚠ 内核驱动出错会蓝屏。请确认已在测试机上,或已建好系统还原点。' -ForegroundColor Red

Step '内核驱动'
$loaded = Ensure-Driver

if ($null -eq $loaded) {
    # 需要重启,不往下走
    Write-Host ''
    return
}

if (-not $loaded) {
    Write-Host ''
    Warn '驱动未就绪 —— 防护将以用户态观测运行(只能事后终止,拦不住行为前)。'
    Info '详细体检:启动Bulwark.bat -Check'
    Write-Host ''
    $go = Read-Host '  仍然以降级模式启动吗?(Y/N,默认 Y)'
    if ($go -ne '' -and $go -notmatch '^[Yy]') { return }
}

if ($SetupOnly) {
    Write-Host ''
    Ok '安装完成(-SetupOnly,未启动服务与界面)'
    Write-Host ''
    return
}

Step '启动'
Start-Runtime
