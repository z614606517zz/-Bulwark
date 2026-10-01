# =====================================================================
#  磐垒主动防御 (Bulwark HIPS) —— 安装程序
#
#  双击 安装.bat 即可,本文件不需要手动运行。
#
#  做的事(全程幂等,已就绪的步骤直接跳过):
#    1) 体检目标机:64 位 / 管理员 / 载荷完整 / 三个 PE 的签名者是钉死的那张证书
#    2) 停掉本机上已在运行的旧版本(界面 → 服务 → 内核驱动,顺序不能反)
#    3) 把 app\ 里的载荷复制到安装目录(默认 C:\Program Files\Bulwark)
#    4) 内核驱动:总是部署 + 注册,但【只在目标机已处于测试签名模式时才加载】
#    5) 用户态服务注册为开机自启并启动(bulwark_service.exe --install)
#    6) 快捷方式 + 控制面板卸载项 + 安装痕迹(供卸载回滚)
#    7) 以【登录用户】身份拉起界面 —— 装完即用
#
#  ⚠ 为什么驱动要看「测试签名」
#    随包 Bulwark.sys 用自签测试证书 CN=BulwarkTestCert 签名。64 位 Windows 的
#    内核代码签名策略要求内核模块带【受认可的】签名,自签证书不满足,唯一的例外
#    是系统处于测试签名模式(bcdedit /set testsigning on)。所以:
#      · 目标机已在测试模式 -> 自动部署 + 加载,拿到真正的行为前拦截;
#      · 不在测试模式       -> 仍然部署并注册好,但不加载,防护以用户态强制运行。
#        以后任何时候开启测试模式并重启,服务会自己把驱动加载上来,不用重装。
#    要在安装时顺手开启测试签名,加 -EnableTestSigning(会要求重启一次)。
#
#  ⚠ 内核驱动回调里出错就是蓝屏。首次务必在带快照的测试机/虚拟机上验证。
#
#  ── 两种调用方式 ──────────────────────────────────────────────────
#  1) 由 Setup.exe(Inno Setup)调用,带 -SystemOnly:
#     文件已经由 Inno 解压到安装目录了,快捷方式与「应用和功能」条目也由 Inno
#     负责。本脚本此时只做「和系统打交道」的那部分:停旧实例、部署+注册+按条件
#     加载内核驱动、注册并启动后台服务、写安装痕迹。
#  2) 直接运行(不带 -SystemOnly):从本脚本同目录的 app\ 子目录复制载荷,自己
#     建快捷方式和卸载项。这条路留着是为了在没有 Setup.exe 的场合也能装/修复,
#     两条路共用同一套系统集成逻辑,不会出现「向导装出来的和手工装出来的不一样」。
#
#  参数
#    -Dir <路径>            安装目录(默认 C:\Program Files\Bulwark)
#    -Check                 只体检,不改动任何东西
#    -SystemOnly            文件已就位:跳过复制、快捷方式、卸载项(由 Setup.exe 负责)
#    -NoDriver              完全不碰内核驱动,只装用户态防护
#    -EnableTestSigning     为加载驱动而开启测试签名(机器全局设置,需重启一次)
#    -BootStart             驱动改为开机随系统加载(消除重启后的防护空窗)
#    -NoShortcut            不创建桌面/开始菜单快捷方式
#    -NoLaunch              装完不自动打开界面
#
#  本文件必须带 UTF-8 BOM:Windows PowerShell 5.1 在中文系统上把无 BOM 的
#  .ps1 按 GBK 解码,里面每一句中文都会变成乱码。打包脚本会核对这一点。
# =====================================================================
[CmdletBinding()]
param(
    [string]$Dir,
    [switch]$Check,
    [switch]$SystemOnly,
    [switch]$NoDriver,
    [switch]$EnableTestSigning,
    [switch]$BootStart,
    [switch]$NoShortcut,
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'

# ---- 常量 -----------------------------------------------------------------
$ProductName   = '磐垒主动防御 (Bulwark HIPS)'
$ProductShort  = 'Bulwark'
$Version       = '1.0.3'
$DriverService = 'Bulwark'            # 内核 Minifilter 服务名
$UserService   = 'BulwarkService'     # 用户态服务名
$Instance      = 'Bulwark Instance'
$Altitude      = '385201'
$CertSubject   = 'BulwarkTestCert'

# 允许签发本产品 PE 的证书指纹。必须与 cpp\shared\include\bulwark\UpdateTrust.h 的
# BULWARK_UPDATE_SIGNER_THUMBPRINT 一致 —— scripts\make-installer.ps1 会核对这两处,
# 不一致就拒绝出包。装之前用它验一遍载荷,是为了让「包在传输/网盘里被换掉」这件事
# 在【动系统之前】就被发现,而不是等驱动加载失败才去猜。
$PinnedThumbprint = '712BA1C841C8D2AA0A48BF89BD076DCD0774E7F5'

# 安装痕迹。卸载据此回滚,并且刻意与便携包 bulwark.ps1 用同一个键 ——
# 两种安装方式留下的记录可以互相识别,不会各写一套导致卸载漏回滚。
$StateKey = 'HKLM:\SOFTWARE\Bulwark'
$ArpKey   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Bulwark'

if (-not $Dir -or $Dir.Trim() -eq '') {
    $pf = $env:ProgramFiles
    if (-not $pf) { $pf = 'C:\Program Files' }
    $Dir = Join-Path $pf 'Bulwark'
}

$pkgRoot = $PSScriptRoot
# -SystemOnly 时载荷就是安装目录本身(Inno 已经解压完了);否则来自安装包的 app\。
if ($SystemOnly) { $srcApp = $Dir } else { $srcApp = Join-Path $pkgRoot 'app' }

# ---- 输出 -----------------------------------------------------------------
$script:LogLines = New-Object System.Collections.Generic.List[string]
function Say([string]$s, [string]$color) {
    $script:LogLines.Add((Get-Date -Format 'HH:mm:ss') + ' ' + $s)
    if ($color) { Write-Host $s -ForegroundColor $color } else { Write-Host $s }
}
function Ok($m)   { Say ("  [OK]   " + $m) 'Green' }
function Warn($m) { Say ("  [!]    " + $m) 'Yellow' }
function Bad($m)  { Say ("  [X]    " + $m) 'Red' }
function Info($m) { Say ("         " + $m) 'DarkGray' }
function Step($m) { Say '' ''; Say ("== " + $m + " ==") 'Cyan' }

function Save-Log {
    # 落盘位置按可写性依次退让。%ProgramData%\Bulwark 是首选(和服务日志放一起),
    # 但那棵树一旦服务起来就被内核 SelfGuard 守着:只放行本产品自身进程写入,
    # 执行安装的 powershell.exe 会被拒。所以必须有退路,否则「装完之后的那份日志」
    # 恰好总是写不进去 —— 而它正是出问题时第一个要看的东西。
    $head = '==== ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  install.ps1 ' + $Version + ' ===='
    $body = $head + "`r`n" + ($script:LogLines -join "`r`n") + "`r`n"
    # %TEMP% 排在安装包目录【之前】:往安装包里写日志会让交付出去的那个文件夹
    # 跟它的 zip 和校验清单不再一致,下一个人核对哈希时会以为包被动过。
    # 屏幕上会打印实际落盘的完整路径,所以放在 %TEMP% 也不影响取用。
    $candidates = @(
        (Join-Path (Join-Path $env:ProgramData 'Bulwark') 'install.log'),
        (Join-Path $env:TEMP 'bulwark-install.log'),
        (Join-Path $pkgRoot 'install-log.txt')
    )
    foreach ($p in $candidates) {
        try {
            $d = Split-Path $p -Parent
            if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force -EA Stop | Out-Null }
            Add-Content -LiteralPath $p -Value $body -Encoding UTF8 -EA Stop
            Write-Host ('         安装日志:' + $p) -ForegroundColor DarkGray
            return
        } catch { }
    }
}

# ---- 管理员 ---------------------------------------------------------------
$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $Check) {
    throw '请以【管理员】身份运行(双击 安装.bat 会自动提权)。'
}

# ---- 系统工具的绝对路径 ---------------------------------------------------
# fltmc / sc / bcdedit 只存在于 64 位 System32。32 位宿主访问会被 WOW64 重定向到
# SysWOW64 然后「找不到文件」,所以按位数解析绝对路径,不靠 PATH。
$sysNative = Join-Path $env:SystemRoot 'Sysnative'
$sysDir = Join-Path $env:SystemRoot 'System32'
if (Test-Path (Join-Path $sysNative 'bcdedit.exe')) { $sysDir = $sysNative }
$bcdedit  = Join-Path $sysDir 'bcdedit.exe'
$scExe    = Join-Path $sysDir 'sc.exe'
$fltmc    = Join-Path $sysDir 'fltmc.exe'
$regExe   = Join-Path $sysDir 'reg.exe'
$shutdown = Join-Path $sysDir 'shutdown.exe'
$explorer = Join-Path $env:SystemRoot 'explorer.exe'
$dstSys   = Join-Path (Join-Path $env:SystemRoot 'System32\drivers') 'Bulwark.sys'

# 载荷清单。缺任何一项都会在目标机上表现成「装完了但起不来」,而且现象和原因
# 完全对不上(缺 qwindows.dll -> 界面根本不出现;缺 MSVC 运行库 -> 进 main 之前
# 就被系统弹框挡下,没有日志没有窗口),所以在动系统之前先逐项点清。
$RequiredFiles = @(
    'bulwark_service.exe', 'bulwark_ui.exe', 'Bulwark.sys', 'appsettings.json',
    'Qt6Core.dll', 'Qt6Gui.dll', 'Qt6Network.dll', 'Qt6Widgets.dll',
    'msvcp140.dll', 'msvcp140_1.dll', 'msvcp140_2.dll', 'vcruntime140.dll', 'vcruntime140_1.dll',
    'platforms\qwindows.dll', 'styles\qmodernwindowsstyle.dll'
)
# tls\ 缺失不会让程序起不来,但所有 HTTPS 云查会静默失败(TLS 后端是 Qt 插件,
# 不在 Qt6Network.dll 里),属于「看不出来的功能缺失」,所以单独点一次。
$RequiredDirs = @('tls')

# =====================================================================
#  状态探测 —— 安装流程与 -Check 共用同一套判据,不会两处逻辑打架
# =====================================================================
function Get-TargetState {
    $s = @{}

    $s.Is64 = [Environment]::Is64BitOperatingSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $s.OsCaption = $os.Caption
    $s.OsBuild   = [int]$os.BuildNumber

    $s.TestSigning = $false
    try {
        $line = ((& $bcdedit) 2>$null | Select-String -SimpleMatch 'testsigning') -join ' '
        $s.TestSigning = ($line -match 'Yes|是')
    } catch { }

    # 非 UEFI 机器上 Confirm-SecureBootUEFI 直接抛异常,那等于「没开安全启动」。
    $s.SecureBoot = $false
    try { $s.SecureBoot = [bool](Confirm-SecureBootUEFI) } catch { }

    $s.Hvci = $false
    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
                              -ClassName Win32_DeviceGuard -ErrorAction Stop
        $s.Hvci = ($dg.SecurityServicesRunning -contains 2)
    } catch { }

    $s.DriverSvcExists = $null -ne (Get-Service -Name $DriverService -ErrorAction SilentlyContinue)
    $s.UserSvcExists   = $null -ne (Get-Service -Name $UserService   -ErrorAction SilentlyContinue)
    $s.UserSvcPath = ''
    if ($s.UserSvcExists) {
        try {
            $ip = (Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $UserService) -Name ImagePath -EA Stop).ImagePath
            $s.UserSvcPath = [string]$ip
        } catch { }
    }
    $s.DriverLoaded = $false
    try {
        $s.DriverLoaded = $null -ne (& $fltmc filters 2>$null | Select-String -SimpleMatch $DriverService)
    } catch { }
    $s.StagedSys = Test-Path $dstSys

    $s.InstalledDir = ''
    $s.InstalledVersion = ''
    try {
        $p = Get-ItemProperty -Path $StateKey -ErrorAction Stop
        if ($p.PSObject.Properties.Name -contains 'InstallDir') { $s.InstalledDir = [string]$p.InstallDir }
        if ($p.PSObject.Properties.Name -contains 'Version')    { $s.InstalledVersion = [string]$p.Version }
    } catch { }

    # 共存的其他安全软件:不是阻断项,但它是「安装中途被拦」最常见的原因,
    # 事后排查时第一个要知道的就是这台机器上还有谁。
    $s.OtherAv = @()
    try {
        Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -EA Stop |
            ForEach-Object { $s.OtherAv += [string]$_.displayName }
    } catch { }

    return $s
}

function Get-DriverPlan([hashtable]$s) {
    # 返回 @{ Action = 'load' | 'stage-only' | 'skip'; Why = '...' }
    if ($NoDriver) {
        return @{ Action = 'skip'; Why = '按 -NoDriver 完全不安装内核驱动' }
    }
    if ($s.SecureBoot -or $s.Hvci) {
        $b = @()
        if ($s.SecureBoot) { $b += 'Secure Boot 已开启' }
        if ($s.Hvci)       { $b += '内存完整性(HVCI)正在运行' }
        return @{ Action = 'stage-only'
                  Why = ($b -join ' + ') + ' —— 这两项会让测试签名完全失效,驱动一定加载不了' }
    }
    if ($s.TestSigning) {
        return @{ Action = 'load'; Why = '目标机已处于测试签名模式' }
    }
    if ($EnableTestSigning) {
        return @{ Action = 'enable-testsigning'; Why = '按 -EnableTestSigning 开启测试签名(需重启一次)' }
    }
    return @{ Action = 'stage-only'; Why = '目标机未开启测试签名模式' }
}

function Show-State([hashtable]$s) {
    Step '目标机状态'
    Info ('系统      : ' + $s.OsCaption + '  build ' + $s.OsBuild + '  ' + $(if ($s.Is64) { 'x64' } else { '32 位' }))
    Info ('管理员    : ' + $isAdmin)
    Info ('安装目录  : ' + $Dir)
    if ($s.InstalledDir) { Info ('已安装    : ' + $s.InstalledVersion + '  ' + $s.InstalledDir) }
    else                 { Info '已安装    : (没有安装记录)' }
    if ($s.OtherAv.Count -gt 0) { Info ('其他杀软  : ' + ($s.OtherAv -join '、')) }

    Step '内核驱动前置条件'
    if ($s.TestSigning) { Ok '测试签名模式:已开启' } else { Warn '测试签名模式:未开启 —— 自签名内核驱动无法加载' }
    if ($s.SecureBoot)  { Warn 'Secure Boot:已开启 —— 需进 BIOS/UEFI 关闭,否则测试签名无效' } else { Ok 'Secure Boot:已关闭' }
    if ($s.Hvci)        { Warn '内存完整性(HVCI):正在运行 —— 需在「Windows 安全中心 > 设备安全性 > 内核隔离」关闭' } else { Ok '内存完整性(HVCI):未运行' }

    $plan = Get-DriverPlan $s
    switch ($plan.Action) {
        'load'              { Ok   ('驱动处置  : 部署 + 注册 + 立即加载(' + $plan.Why + ')') }
        'enable-testsigning'{ Warn ('驱动处置  : 部署 + 注册 + 开启测试签名后重启生效(' + $plan.Why + ')') }
        'stage-only'        { Warn ('驱动处置  : 只部署 + 注册,不加载(' + $plan.Why + ')')
                              Info '          防护仍然可用,但降级为用户态强制(可事后阻断,拦不住「行为前」)。' 
                              Info '          以后开启测试模式并重启,服务会自己把驱动加载上来,不需要重装。' }
        'skip'              { Warn ('驱动处置  : 跳过(' + $plan.Why + ')') }
    }

    Step '当前运行状态'
    if ($s.DriverLoaded)  { Ok   ('内核筛选器 ' + $DriverService + ' 已加载') } else { Info ('内核筛选器 ' + $DriverService + ' 未加载') }
    if ($s.StagedSys)     { Ok   'System32\drivers\Bulwark.sys 已就位' }        else { Info 'System32\drivers\Bulwark.sys 不存在' }
    if ($s.UserSvcExists) { Ok   ($UserService + ' 已注册:' + $s.UserSvcPath) } else { Info ($UserService + ' 未注册') }
    foreach ($pn in @('bulwark_service', 'bulwark_ui')) {
        $p = Get-Process -Name $pn -ErrorAction SilentlyContinue
        if ($p) { Info ($pn + '.exe 运行中,PID ' + (($p.Id) -join ',')) }
    }
}

# =====================================================================
#  载荷校验 —— 在动系统之前做完
# =====================================================================
function Test-Payload {
    Step '校验安装包'
    if (-not (Test-Path $srcApp)) {
        Bad ('找不到载荷目录:' + $srcApp)
        if ($SystemOnly) { Info '安装目录里没有程序文件 —— 安装程序的解压步骤没有完成。' }
        else { Info '请把整个安装包文件夹解压出来再运行,不要只单独复制 安装.bat。' }
        return $false
    }
    $missing = @()
    foreach ($n in $RequiredFiles) {
        if (-not (Test-Path (Join-Path $srcApp $n))) { $missing += $n }
    }
    foreach ($d in $RequiredDirs) {
        $p = Join-Path $srcApp $d
        if (-not (Test-Path $p) -or @(Get-ChildItem $p -File -EA SilentlyContinue).Count -eq 0) {
            $missing += ($d + '\')
        }
    }
    if ($missing.Count -gt 0) {
        Bad ('安装包不完整,缺 ' + $missing.Count + ' 项:' + ($missing -join ', '))
        Info '这种包装上去会「看起来装好了但起不来」,所以直接拒绝安装。'
        return $false
    }
    Ok ('载荷完整(' + $RequiredFiles.Count + ' 个必需文件 + ' + $RequiredDirs.Count + ' 个插件目录)')

    # 三个 PE 必须由钉死的那张证书签名。
    #
    # 刻意【不要求】Status=Valid:证书是自签的,在一台还没导入过它的机器上,
    # 干净文件的状态就是 UnknownError(根不受信任)—— 而那正是一台刚拿到安装包的
    # 机器的正常状态。要求 Valid 会把所有正常安装拒掉。
    # 真正的判据是两条:① 签名覆盖当前文件内容(排掉 HashMismatch);② 签名者
    # 指纹在钉死名单里。少了第一条,改掉 PE 中间一个字节【不会】破坏嵌入的签名
    # blob,指纹还是我们那张,只有摘要不匹配 —— 光比指纹完全证明不了文件没被动过。
    $badSig = @()
    foreach ($n in @('bulwark_service.exe', 'bulwark_ui.exe', 'Bulwark.sys')) {
        $p = Join-Path $srcApp $n
        $sig = Get-AuthenticodeSignature $p
        $status = [string]$sig.Status
        $tp = ''
        if ($sig.SignerCertificate) { $tp = $sig.SignerCertificate.Thumbprint.ToUpper() }
        if ($status -eq 'NotSigned' -or -not $sig.SignerCertificate) {
            $badSig += ($n + ':没有数字签名'); continue
        }
        if ($status -eq 'HashMismatch') {
            $badSig += ($n + ':签名与文件内容不匹配(下载/传输后被改动过)'); continue
        }
        if (@('Valid', 'UnknownError') -notcontains $status) {
            $badSig += ($n + ':签名状态 ' + $status); continue
        }
        if ($tp -ne $PinnedThumbprint) {
            $badSig += ($n + ':签名者不是本产品的证书(' + $tp + ')'); continue
        }
        Ok ('{0,-22} 签名者正确  {1}' -f $n, $status)
    }
    if ($badSig.Count -gt 0) {
        Bad '载荷签名校验未通过,拒绝安装:'
        foreach ($b in $badSig) { Info ('  - ' + $b) }
        Info '这一步挡的是「包在传输途中被换掉」。请重新获取安装包。'
        return $false
    }

    # 版本对不上不是致命问题,但会让「装完还提示更新」这种怪现象无从解释。
    $uiVer = (Get-Item (Join-Path $srcApp 'bulwark_ui.exe')).VersionInfo.FileVersion
    if ($uiVer -and -not $uiVer.StartsWith($Version)) {
        Warn ('载荷版本 ' + $uiVer + ' 与安装脚本声明的 ' + $Version + ' 不一致')
    } else {
        Ok ('版本 ' + $uiVer)
    }
    return $true
}

# =====================================================================
#  停掉正在运行的旧实例
#
#  顺序是【界面 -> 用户态服务 -> 内核驱动】,不能反:
#   · 驱动在载时,本产品自身进程在内核自我保护名单里,外部进程拿不到
#     PROCESS_TERMINATE,Stop-Process 会静默失败;
#   · 内核 SelfGuard 守着安装目录(仅放行本产品自身进程写入),服务还活着时
#     复制新文件会被拒;
#   · 内核 RegHardBlock 含 "\Services\Bulwark",驱动在载时改/删这两个服务的
#     注册表键会被硬拦。
#  所以要先让服务断连(SelfGuard 随断连清除),再卸驱动(解除 RegHardBlock),
#  之后才动文件和服务注册。
# =====================================================================
function Stop-Existing([hashtable]$s) {
    Step '停止已在运行的旧版本'
    $any = $false

    $ui = Get-Process -Name 'bulwark_ui' -ErrorAction SilentlyContinue
    if ($ui) { $ui | Stop-Process -Force -ErrorAction SilentlyContinue; $any = $true; Ok '界面已退出' }

    # 一定要走 SCM 的正常停止,而不是直接杀进程。
    #
    # 服务注册时配了失败自动恢复(5s/5s/60s 重启),而它区分「用户主动停止」和
    # 「异常终止」的依据就是退出码:sc stop -> 干净退出 -> SCM 不拉起;被 kill ->
    # 非正常终止 -> SCM 五秒后把它拉回来。拉回来的服务会重新武装内核自我保护,
    # 于是后面的复制文件、改服务注册全部开始失败,而现象是「偶发的访问被拒绝」,
    # 极难看出根因。所以这里先请 SCM 停,并且【等到真的 STOPPED】。
    if ($s.UserSvcExists) {
        $any = $true
        & $scExe stop $UserService 2>&1 | Out-Null
        $stopped = $false
        for ($i = 0; $i -lt 30; $i++) {
            $svc = Get-Service -Name $UserService -ErrorAction SilentlyContinue
            if (-not $svc -or $svc.Status -eq 'Stopped') { $stopped = $true; break }
            Start-Sleep -Seconds 1
        }
        if ($stopped) { Ok '后台服务已正常停止' } else { Warn '后台服务未在 30 秒内停止,将强制结束' }
    }

    # 只有正常停止没成功时才强杀。强杀之后必须复核它没有被 SCM 拉回来 ——
    # 被拉回来还继续往下走,就是上面那类「偶发失败」的来源。
    $alive = @()
    for ($i = 1; $i -le 12; $i++) {
        $alive = @(Get-Process -Name 'bulwark_service', 'bulwark_ui' -ErrorAction SilentlyContinue)
        if ($alive.Count -eq 0) { break }
        $alive | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
    if ($alive.Count -eq 0) {
        # 静置一会儿再看一眼:SCM 的第一次重启延迟是 5 秒,不等就看不到复活。
        Start-Sleep -Seconds 6
        $alive = @(Get-Process -Name 'bulwark_service' -ErrorAction SilentlyContinue)
        if ($alive.Count -gt 0) {
            Warn '后台服务被服务控制器自动拉起了(异常终止后的自愈策略),再停一次'
            & $scExe stop $UserService 2>&1 | Out-Null
            Start-Sleep -Seconds 3
            $alive = @(Get-Process -Name 'bulwark_service' -ErrorAction SilentlyContinue)
        }
    }
    if ($alive.Count -gt 0) {
        Bad ('以下进程仍在运行,无法继续:' +
             (($alive | ForEach-Object { $_.ProcessName + '(' + $_.Id + ')' }) -join '、'))
        Info '请重启一次机器后再运行安装。'
        return $false
    }
    if ($any) { Ok '后台服务已停止' }

    if ($s.DriverLoaded) {
        & $fltmc unload $DriverService 2>&1 | Out-Null
        & $scExe  stop   $DriverService 2>&1 | Out-Null
        Start-Sleep -Seconds 1
        $still = $null -ne (& $fltmc filters 2>$null | Select-String -SimpleMatch $DriverService)
        if ($still) {
            Bad '内核驱动仍处于加载状态,无法替换驱动文件与服务注册。'
            Info '请重启一次机器,然后重新运行安装。'
            return $false
        }
        Ok '内核驱动已卸载'
    }
    if (-not $any -and -not $s.DriverLoaded) { Ok '没有正在运行的旧版本' }
    return $true
}

# =====================================================================
#  复制载荷
# =====================================================================
function Copy-Payload {
    if ($SystemOnly) {
        Step '程序文件'
        Ok ('已由安装程序解压到 ' + $Dir + '(跳过复制)')
        return $true
    }
    Step '复制程序文件'
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }

    $files = @(Get-ChildItem $srcApp -Recurse -File)
    $copied = 0
    $failed = @()
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($srcApp.Length).TrimStart('\')
        $dst = Join-Path $Dir $rel
        $dstDir = Split-Path $dst -Parent
        if (-not (Test-Path $dstDir)) { New-Item -ItemType Directory -Path $dstDir -Force | Out-Null }
        $ok = $false
        for ($try = 1; $try -le 3; $try++) {
            try { Copy-Item -LiteralPath $f.FullName -Destination $dst -Force; $ok = $true; break }
            catch { Start-Sleep -Milliseconds 700 }
        }
        if ($ok) { $copied++ } else { $failed += $rel }
    }
    if ($failed.Count -gt 0) {
        Bad ('有 ' + $failed.Count + ' 个文件复制失败:' + (($failed | Select-Object -First 8) -join ', '))
        Info '常见原因:旧版本进程还占着文件,或被其他安全软件拦下。'
        return $false
    }
    Ok ('已复制 ' + $copied + ' 个文件到 ' + $Dir)

    # 复制没报错 != 文件真的对。逐项复核大小,顺手把「复制了一半」这种情况挡掉。
    $bad = @()
    foreach ($n in $RequiredFiles) {
        $a = Join-Path $srcApp $n
        $b = Join-Path $Dir $n
        if (-not (Test-Path $b)) { $bad += ($n + ' 缺失'); continue }
        if ((Get-Item $a).Length -ne (Get-Item $b).Length) { $bad += ($n + ' 大小不一致') }
    }
    if ($bad.Count -gt 0) {
        Bad ('复核未通过:' + ($bad -join ', '))
        return $false
    }
    Ok '复核通过:必需文件全部就位且与包内一致'

    if ($NoDriver) {
        # 明确要求不装驱动时把事件源改成用户态,免得服务每 10 秒重试加载一个
        # 永远加载不上的驱动 —— 那会在日志里刷屏,还每次都起两个子进程。
        $cfg = Join-Path $Dir 'appsettings.json'
        if (Test-Path $cfg) {
            $json = [IO.File]::ReadAllText($cfg, [Text.Encoding]::UTF8)
            $json = [regex]::Replace($json, '("EventSource"\s*:\s*")[^"]*(")', '${1}Wmi${2}')
            $json = [regex]::Replace($json, '("KernelDriverEnabled"\s*:\s*)(true|false)', '${1}false')
            [IO.File]::WriteAllText($cfg, $json, (New-Object Text.UTF8Encoding($false)))
            Ok 'appsettings.json:EventSource=Wmi、KernelDriverEnabled=false(-NoDriver)'
        }
    }
    return $true
}

# =====================================================================
#  内核驱动:部署 + 注册 +(条件满足才)加载
# =====================================================================
function Install-Driver([hashtable]$s, [hashtable]$plan) {
    Step '内核驱动'
    if ($plan.Action -eq 'skip') {
        Warn $plan.Why
        return 'skipped'
    }

    # ---- 1) 复制 .sys 到 System32\drivers -------------------------------
    # 与服务里 stageDriverBinary() 的「已存在就不覆盖」不同:这里是显式安装,
    # 包内版本应当覆盖旧的,否则升级了包、加载的还是上一版驱动,现象是
    # 「明明换了新版却没变化」。
    try {
        Copy-Item (Join-Path $srcApp 'Bulwark.sys') $dstSys -Force
        Ok ("驱动已部署到 System32\drivers({0:N0} B)" -f (Get-Item $dstSys).Length)
    } catch {
        Bad ('复制 Bulwark.sys 失败:' + $_.Exception.Message)
        Info '驱动可能仍处于加载状态;重启一次后重新运行安装即可。'
        return 'failed'
    }

    # ---- 2) 以 Minifilter 语义注册 --------------------------------------
    # 少了 Instances/DefaultInstance + Altitude 这一步,驱动【不会附加到卷】,
    # 文件与注册表回调一个都不会触发 —— 服务能连上内核端口,但什么都拦不到。
    # 这种失败从界面上完全看不出来,所以这一步不能省,也不能只做一半。
    $startType = 'demand'
    if ($BootStart) { $startType = 'system' }
    if ($s.DriverSvcExists) {
        & $scExe delete $DriverService 2>&1 | Out-Null
        Start-Sleep -Seconds 1
    }
    & $scExe create $DriverService type= filesys start= $startType `
        binPath= 'System32\drivers\Bulwark.sys' depend= FltMgr `
        group= 'FSFilter Activity Monitor' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Bad ('sc create ' + $DriverService + ' 失败(退出码 ' + $LASTEXITCODE + ')')
        return 'failed'
    }
    & $scExe description $DriverService '磐垒主动防御内核驱动' 2>&1 | Out-Null
    $svcKey = 'HKLM\SYSTEM\CurrentControlSet\Services\' + $DriverService
    & $regExe add ($svcKey + '\Instances') /v DefaultInstance /t REG_SZ /d $Instance /f | Out-Null
    & $regExe add ($svcKey + '\Instances\' + $Instance) /v Altitude /t REG_SZ    /d $Altitude /f | Out-Null
    & $regExe add ($svcKey + '\Instances\' + $Instance) /v Flags    /t REG_DWORD /d 0 /f | Out-Null
    Ok ('已注册 Minifilter:start=' + $startType + ' altitude=' + $Altitude + ' instance="' + $Instance + '"')

    if ($plan.Action -eq 'stage-only') {
        Warn ('不加载驱动:' + $plan.Why)
        Info '驱动已经装好并注册好了 —— 满足前置条件后重启,服务会自动把它加载上来。'
        return 'staged'
    }

    # ---- 3) 信任签名证书 -------------------------------------------------
    # 包里没有私钥,不可能在目标机上重新签名。做法是把 .sys 自带的签名者证书提出来
    # 导入 Root(建立信任链)+ TrustedPublisher(免「是否信任此发布者」提示)。
    #
    # 严格来说测试签名模式下内核不要求证书链到受信任的根,所以这一步不是加载的
    # 硬前提;但它能让签名状态变成 Valid、让本产品与系统工具对这个驱动的判定一致,
    # 代价是在目标机上新增一个受信任的自签根证书 —— 因此只在【真的要加载驱动】时
    # 才做,并记一笔痕迹,卸载时原样移除。
    $certImported = 0
    $signer = (Get-AuthenticodeSignature (Join-Path $srcApp 'Bulwark.sys')).SignerCertificate
    if ($signer) {
        $already = $null -ne (Get-ChildItem 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue |
                              Where-Object { $_.Thumbprint -eq $signer.Thumbprint })
        if ($already) {
            Ok ('签名证书已被本机信任 —— ' + $signer.Subject)
        } else {
            $cer = Join-Path $env:TEMP 'BulwarkDriverSigner.cer'
            [IO.File]::WriteAllBytes($cer, $signer.Export('Cert'))
            foreach ($store in @('Root', 'TrustedPublisher')) {
                $dup = Get-ChildItem ('Cert:\LocalMachine\' + $store) -ErrorAction SilentlyContinue |
                       Where-Object { $_.Thumbprint -eq $signer.Thumbprint }
                if (-not $dup) {
                    Import-Certificate -FilePath $cer -CertStoreLocation ('Cert:\LocalMachine\' + $store) | Out-Null
                    $certImported = 1
                }
            }
            Remove-Item $cer -Force -ErrorAction SilentlyContinue
            Ok ('已信任驱动签名证书 —— ' + $signer.Subject)
            Info ('指纹 ' + $signer.Thumbprint + '(卸载时会移除)')
        }
    }
    Set-Mark 'CertImportedByUs' $certImported

    # ---- 4) 加载 + 验证 --------------------------------------------------
    & $fltmc load $DriverService 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { & $scExe start $DriverService 2>&1 | Out-Null }
    Start-Sleep -Seconds 1
    # fltmc 的输出表头是本地化的,但筛选器名那一列就是字面 "Bulwark",按串匹配即可。
    if ($null -ne (& $fltmc filters 2>$null | Select-String -SimpleMatch $DriverService)) {
        Ok '内核驱动已加载 —— 行为前拦截已启用'
        (& $fltmc filters 2>$null | Select-String -SimpleMatch $DriverService) |
            ForEach-Object { Info $_.Line.Trim() }
        return 'loaded'
    }
    Bad '驱动加载失败'
    Info ('排查:sc query ' + $DriverService + ' / 安装.bat -Check / DebugView(勾 Capture Kernel)')
    Info '防护仍会以用户态强制运行,但没有行为前拦截。'
    return 'failed'
}

function Enable-TestSigning {
    Step '开启测试签名模式'
    & $bcdedit /set testsigning on | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Bad 'bcdedit /set testsigning on 失败。'
        Info '常见原因:BitLocker 已启用(需先挂起)、Secure Boot 未关、或被其他安全软件拦下。'
        return $false
    }
    # 记下「是本产品开的」,卸载时才敢关回去。用户本来就开着的话绝不动它 ——
    # 那可能是为别的自签名驱动开的,关掉会把别人的东西一起弄坏,而且没人会想到
    # 是卸载干的。
    Set-Mark 'TestSigningEnabledByUs' 1
    Ok '测试签名已开启 —— 需要重启一次才生效'
    Info '重启后桌面右下角会出现「测试模式」水印,这是正常的。'
    Info '重启后服务会自动把内核驱动加载上来,不需要再运行安装程序。'
    return $true
}

# =====================================================================
#  用户态服务
# =====================================================================
function Install-Service([hashtable]$s) {
    Step '后台服务'
    $svcExe = Join-Path $Dir 'bulwark_service.exe'

    # 已注册但指向别的目录(比如对方先试过便携包)时必须先删掉重注册:
    # --install 遇到已存在的服务会直接返回「已存在」,ImagePath 还是旧的那个,
    # 结果是装完之后跑的仍然是老位置的 exe,而界面因为 UI 与服务不同目录连不上。
    if ($s.UserSvcExists) {
        $want = '"' + $svcExe + '" --service'
        if ($s.UserSvcPath.Trim() -ne $want) {
            Info ('已注册的服务指向别处:' + $s.UserSvcPath)
            & $scExe delete $UserService 2>&1 | Out-Null
            Start-Sleep -Seconds 1
            if (Get-Service -Name $UserService -ErrorAction SilentlyContinue) {
                Warn '旧服务注册删除未立即生效,将尝试直接改配置'
            } else {
                Ok '已删除旧的服务注册'
            }
        }
    }

    $out = & $svcExe --install 2>&1
    if ($out) { $out | ForEach-Object { Info ([string]$_) } }
    if (-not (Get-Service -Name $UserService -ErrorAction SilentlyContinue)) {
        Bad ($UserService + ' 注册失败')
        return $false
    }
    Ok ($UserService + ' 已注册为开机自动启动(含异常终止自动恢复)')

    # --install 碰到已存在的服务只会回一句「已存在」,不会去修启动类型。所以这里
    # 补一次:上一轮安装/卸载若把它置成了 demand 或 disabled(例如为了阻止 SCM
    # 把被强杀的服务拉回来),不补这一下就会装出一个「开机不自启」的防护软件,
    # 而且从界面上完全看不出来 —— 直到某次重启后用户发现自己没有防护。
    & $scExe config $UserService start= auto 2>&1 | Out-Null

    & $scExe start $UserService 2>&1 | Out-Null
    $running = $false
    for ($i = 0; $i -lt 60; $i++) {
        $svc = Get-Service -Name $UserService -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') { $running = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $running) {
        Bad ($UserService + ' 未能进入运行状态')
        Info '看 %ProgramData%\Bulwark\service.log 与 bootstrap-status.txt。'
        Info '常见原因:appsettings.json 语法错误、缺 Qt 运行库、无法写 %ProgramData%\Bulwark。'
        return $false
    }
    Ok '后台服务已启动'

    # 服务进 RUNNING 之后控制管道还要一小会儿才监听上。界面正是靠这条管道连服务的,
    # 所以这里等一下,避免装完立刻打开界面却显示「未连接」。
    # 管道名取自 cpp\shared\include\bulwark\ipc\PipeNames.h 的 controlPipe()。
    for ($i = 0; $i -lt 20; $i++) {
        if (Test-Path '\\.\pipe\Bulwark.Control') { Ok '控制管道已就绪'; break }
        Start-Sleep -Milliseconds 500
    }
    return $true
}

# =====================================================================
#  快捷方式 / 卸载项 / 安装痕迹
# =====================================================================
function Set-Mark([string]$name, $value) {
    try {
        if (-not (Test-Path $StateKey)) { New-Item -Path $StateKey -Force | Out-Null }
        if ($value -is [string]) {
            New-ItemProperty -Path $StateKey -Name $name -Value $value -PropertyType String -Force | Out-Null
        } else {
            New-ItemProperty -Path $StateKey -Name $name -Value ([int]$value) -PropertyType DWord -Force | Out-Null
        }
        return $true
    } catch { return $false }
}

function Get-Mark([string]$name) {
    try { return (Get-ItemProperty -Path $StateKey -Name $name -ErrorAction Stop).$name } catch { return $null }
}

function New-Shortcuts {
    Step '快捷方式'
    if ($SystemOnly) { Info '由安装程序负责(跳过)'; return }
    if ($NoShortcut) { Info '按 -NoShortcut 跳过'; return }
    $ui  = Join-Path $Dir 'bulwark_ui.exe'
    $ico = Join-Path $Dir 'app.ico'
    if (-not (Test-Path $ico)) { $ico = $ui }
    $name = '磐垒主动防御.lnk'
    $made = @()
    try {
        $sh = New-Object -ComObject WScript.Shell
        # 开始菜单:全体用户,这样换用户登录也能找到。
        $sm = Join-Path $env:ProgramData ('Microsoft\Windows\Start Menu\Programs\' + $ProductShort)
        if (-not (Test-Path $sm)) { New-Item -ItemType Directory -Path $sm -Force | Out-Null }
        foreach ($target in @((Join-Path $sm $name), (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) $name))) {
            $lnk = $sh.CreateShortcut($target)
            $lnk.TargetPath = $ui
            $lnk.WorkingDirectory = $Dir
            $lnk.IconLocation = $ico
            $lnk.Description = $ProductName
            $lnk.Save()
            $made += $target
        }
        # 卸载入口也放进开始菜单 —— 这是正经安全工具,卸载通路必须显眼。
        $unlnk = $sh.CreateShortcut((Join-Path $sm '卸载 磐垒主动防御.lnk'))
        $unlnk.TargetPath = Join-Path $Dir '卸载.bat'
        $unlnk.WorkingDirectory = $Dir
        $unlnk.IconLocation = $ico
        $unlnk.Description = ('卸载 ' + $ProductName)
        $unlnk.Save()
        $made += $unlnk.FullName
        foreach ($m in $made) { Ok ('已创建 ' + $m) }
    } catch {
        Warn ('创建快捷方式失败(不影响使用):' + $_.Exception.Message)
    }
}

function Set-ArpEntry {
    Step '控制面板卸载项'
    # Inno Setup 自己会登记一条(带它自己的卸载程序)。这里再写一条就会在
    # 「应用和功能」里出现两个磐垒,其中一个点下去走的是不完整的卸载路径。
    if ($SystemOnly) { Info '由安装程序负责(跳过)'; return }
    try {
        if (-not (Test-Path $ArpKey)) { New-Item -Path $ArpKey -Force | Out-Null }
        $ico = Join-Path $Dir 'app.ico'
        if (-not (Test-Path $ico)) { $ico = Join-Path $Dir 'bulwark_ui.exe' }
        $size = 0
        try { $size = [int](((Get-ChildItem $Dir -Recurse -File | Measure-Object Length -Sum).Sum) / 1KB) } catch { }
        $cmd = Join-Path $sysDir 'cmd.exe'
        $unbat = Join-Path $Dir '卸载.bat'
        $props = @{
            DisplayName     = $ProductName
            DisplayVersion  = $Version
            Publisher       = 'Bulwark'
            DisplayIcon     = $ico
            InstallLocation = $Dir
            UninstallString = ($cmd + ' /c "' + $unbat + '"')
            NoModify        = 1
            NoRepair        = 1
            EstimatedSize   = $size
            InstallDate     = (Get-Date -Format 'yyyyMMdd')
        }
        foreach ($k in $props.Keys) {
            $t = 'String'
            if ($props[$k] -is [int]) { $t = 'DWord' }
            New-ItemProperty -Path $ArpKey -Name $k -Value $props[$k] -PropertyType $t -Force | Out-Null
        }
        Ok '已登记到「应用和功能 / 程序和功能」,可从系统里直接卸载'
    } catch {
        Warn ('登记卸载项失败(不影响使用,仍可双击安装目录里的 卸载.bat):' + $_.Exception.Message)
    }
}

function Start-Ui {
    Step '打开界面'
    if ($NoLaunch) { Info '按 -NoLaunch 跳过'; return }
    $ui = Join-Path $Dir 'bulwark_ui.exe'
    # 经 explorer.exe 拉起,让界面以【登录用户】的身份和权限运行。
    # 直接 Start-Process 会让它继承安装程序的管理员令牌 —— 一个常驻托盘的界面
    # 没有理由长期以管理员身份跑,而且那样它写的 HKCU 自启动项会落到执行安装的
    # 那个管理员账户下,而不是当前登录用户。
    try {
        Start-Process -FilePath $explorer -ArgumentList ('"' + $ui + '"') -ErrorAction Stop | Out-Null
        Start-Sleep -Seconds 3
        if (Get-Process -Name 'bulwark_ui' -ErrorAction SilentlyContinue) {
            Ok '界面已打开(关闭窗口不会停止防护,程序驻留在托盘)'
        } else {
            Info '界面未在 3 秒内出现 —— 可从桌面快捷方式手动打开。'
        }
    } catch {
        Warn ('自动打开界面失败:' + $_.Exception.Message)
        Info ('可手动运行:' + $ui)
    }
}

# =====================================================================
#  入口
# =====================================================================
Write-Host ''
Write-Host ('==== ' + $ProductName + ' ' + $Version + ' 安装程序 ====') -ForegroundColor Cyan
$script:LogLines.Add('==== install start ' + $Version + ' ====')

$state = Get-TargetState
Show-State $state

# 载荷校验是纯只读的,所以 -Check 也要做:体检的用处恰恰是「装之前先看一眼」,
# 而「这个包本身是不是完整、有没有被换掉」正是那时最该知道的事。
$payloadOk = Test-Payload

if ($Check) {
    Step '只体检(-Check),没有改动任何东西'
    if (-not $payloadOk) { Bad '安装包本身有问题 —— 见上面的「校验安装包」一节。' }
    Save-Log
    Write-Host ''
    if ($payloadOk) { return } else { exit 2 }
}

if (-not $state.Is64) {
    Bad '本产品只支持 64 位 Windows。'
    Save-Log
    exit 1
}
if ($state.OsBuild -lt 10240) {
    Bad ('系统版本过低(build ' + $state.OsBuild + '),需要 Windows 10 或更高。')
    Save-Log
    exit 1
}

Write-Host ''
Write-Host '⚠ 内核驱动出错会导致蓝屏。请确认这是测试机,或已建好系统还原点。' -ForegroundColor Red

if (-not $payloadOk) { Save-Log; exit 2 }
if (-not (Stop-Existing $state)) { Save-Log; exit 3 }

# 停完之后状态变了(驱动已卸载、服务已停),后面的判断必须用新状态。
$state = Get-TargetState

if (-not (Copy-Payload)) { Save-Log; exit 4 }

$plan = Get-DriverPlan $state
$needReboot = $false
$driverResult = 'skipped'
if ($plan.Action -eq 'enable-testsigning') {
    if (Enable-TestSigning) { $needReboot = $true }
    # 开了测试签名也要把驱动部署 + 注册好,这样重启后服务能直接加载它。
    $plan2 = @{ Action = 'stage-only'; Why = '测试签名要重启后才生效' }
    $driverResult = Install-Driver $state $plan2
} else {
    if ($null -eq (Get-Mark 'TestSigningEnabledByUs')) {
        # 只在【从未记录过】时才记 0:本产品没开过它,卸载就不该去关它。
        Set-Mark 'TestSigningEnabledByUs' 0 | Out-Null
    }
    $driverResult = Install-Driver $state $plan
}

$svcOk = Install-Service $state

Step '安装痕迹'
Set-Mark 'InstallDir' $Dir | Out-Null
Set-Mark 'Version' $Version | Out-Null
Set-Mark 'DriverInstalled' $(if ($driverResult -eq 'skipped') { 0 } else { 1 }) | Out-Null
# 没走到导入证书那一步时也要留一个明确的 0。缺这条记录,卸载就只能靠猜「这张
# 受信任的自签根证书是不是我放进去的」,而猜错任何一边都不可接受:多删会弄坏
# 别人的自签名驱动,少删会在别人机器上留下一个受信任的根证书。
if ($null -eq (Get-Mark 'CertImportedByUs')) { Set-Mark 'CertImportedByUs' 0 | Out-Null }
Ok ('已写入 ' + $StateKey + '(卸载据此回滚)')

New-Shortcuts
Set-ArpEntry

if ($svcOk) { Start-Ui }

# =====================================================================
#  收尾:如实说明当前拿到的是哪一档防护
# =====================================================================
Step '安装结果'
$tier = ''
switch ($driverResult) {
    'loaded'  { $tier = '内核前拦截(完整形态:进程/文件/注册表/自保护/网络的行为前阻断)' }
    'staged'  { $tier = '用户态强制(驱动已装好但未加载,拦不住「行为前」)' }
    'failed'  { $tier = '用户态强制(驱动加载失败,拦不住「行为前」)' }
    'skipped' { $tier = '用户态强制(按要求未安装内核驱动)' }
}
Info ('安装目录  : ' + $Dir)
Info ('后台服务  : ' + $(if ($svcOk) { '已启动,开机自动运行' } else { '未能启动 —— 见上面的排查提示' }))
Info ('防护形态  : ' + $tier)
Info ('数据目录  : ' + (Join-Path $env:ProgramData 'Bulwark') + '(规则 / 日志 / 隔离区)')
if ($SystemOnly) {
    Info '卸载      : 开始菜单里的「卸载」,或系统「设置 > 应用 > 已安装的应用」'
} else {
    Info '卸载      : 开始菜单里的「卸载 磐垒主动防御」,或安装目录里的 卸载.bat,或系统的「应用和功能」'
}

Write-Host ''
if ($svcOk -and $driverResult -eq 'loaded') {
    Write-Host '==== 安装完成:防护已启用(内核前拦截)====' -ForegroundColor Green
} elseif ($svcOk) {
    Write-Host '==== 安装完成:防护已启用(用户态强制)====' -ForegroundColor Yellow
    if ($driverResult -eq 'staged' -and -not $needReboot) {
        Info '想拿到内核前拦截:关闭 Secure Boot 与内存完整性,开启测试签名模式后重启;'
        Info '或者直接运行:安装.bat -EnableTestSigning'
    }
} else {
    Write-Host '==== 安装未完成:后台服务没能启动 ====' -ForegroundColor Red
}
if ($needReboot) {
    Write-Host ''
    Warn '需要重启一次机器,重启后内核驱动会自动加载。'
    if (-not $NoLaunch) {
        try {
            $ans = Read-Host '  现在重启吗?(Y/N,默认 N)'
            if ($ans -match '^[Yy]') { & $shutdown /r /t 5; Write-Host '  5 秒后重启...' -ForegroundColor Yellow }
        } catch { }
    }
}
Write-Host ''
Save-Log
