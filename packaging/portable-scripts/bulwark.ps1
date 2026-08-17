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
#    -CollectLogs        打包一份可直接发给作者的诊断压缩包(自动脱敏)
#    -Uninstall          【完整卸载】卸驱动、删两个服务、删 .sys、移除测试证书、
#                        关闭测试签名(退出测试模式)、清掉重启自动继续
#      └ -KeepTestSigning   保留测试签名开启状态(还有别的测试签名驱动要用)
#      └ -KeepCert          保留 BulwarkTestCert 证书
#      └ -PurgeData         连 %ProgramData%\Bulwark(规则/日志/隔离区)一起删
#      └ -KeepData          不问,直接保留数据目录
#      (-RemoveCert / -DisableTestSigning / -All 现在是默认行为,保留只为兼容旧命令)
#    -SetupOnly          只做安装,不启动服务和界面
#    -BootStart          驱动改为开机随系统加载(消除重启后的防护空窗)
#    -InstallService     把用户态服务也注册成开机自启(防护常驻)
#    -NoAutoResume       开启测试签名后不设置「重启后自动继续」
# =====================================================================
[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$CollectLogs,
    [switch]$Uninstall,
    [switch]$ApplyUpdate,
    # 暂存目录由界面传进来。不在这里写死 %LOCALAPPDATA%\Bulwark\update 的原因:
    # 本脚本是提权跑的,提权后若切到了另一个管理员账户,%LOCALAPPDATA% 就指向
    # 【那个账户】的目录,于是找不到刚下载的文件。留空时才回退到默认值。
    [string]$UpdateDir,
    [switch]$SetupOnly,
    [switch]$BootStart,
    [switch]$InstallService,
    # 卸载现在默认就做全套,这三个开关只为兼容以前写下的命令,留着不报错。
    [switch]$RemoveCert,
    [switch]$DisableTestSigning,
    [switch]$All,
    # 卸载时的退出通道 —— 完整卸载会动两项【机器全局】设置(测试签名、
    # LocalMachine 证书存储),别人可能还靠它们跑别的测试签名驱动。
    [switch]$KeepTestSigning,
    [switch]$KeepCert,
    [switch]$PurgeData,
    [switch]$KeepData,
    [switch]$NoAutoResume
)

$ErrorActionPreference = 'Stop'

$ServiceName = 'Bulwark'            # 内核 Minifilter 服务名
$UserService = 'BulwarkService'     # 用户态服务名(刻意与内核服务区分,避免冲突)
$Instance    = 'Bulwark Instance'
$Altitude    = '385201'
$CertSubject = 'BulwarkTestCert'

# 安装时留下的「我们改了什么」痕迹,卸载据此回滚。
#
# 存在的理由很具体:测试签名是【机器全局】开关。如果用户装本产品之前就为了别的
# 自签名驱动开着它,卸载时一律关掉就等于顺手把别人的东西弄坏了,而且没人会想到
# 是卸载干的。所以安装时记一笔「这是我开的还是本来就开着」,卸载只回滚自己开的那种。
$StateKey = 'HKLM:\SOFTWARE\Bulwark'

# 允许签发更新的证书指纹。必须与 cpp\shared\include\bulwark\UpdateTrust.h 里的
# BULWARK_UPDATE_SIGNER_THUMBPRINT 一致 —— verify_portable.ps1 会核对这两处,
# 不一致就拒绝出包(否则服务端能下完、脚本却拒绝安装,现象极难懂)。
# 换证书时:改 UpdateTrust.h + 这里,然后跑 verify_portable.ps1。
$UpdateSignerThumbprints = @('712BA1C841C8D2AA0A48BF89BD076DCD0774E7F5')

# --- installmark:begin ---（tools\test-uninstall.ps1 抽取本段;刻意不含上面那行
#     $StateKey 赋值,好让测试把它指到临时的 HKCU 键上,绝不碰真的 HKLM）
function Set-InstallMark([string]$name, $value) {
    try {
        if (-not (Test-Path $StateKey)) { New-Item -Path $StateKey -Force | Out-Null }
        New-ItemProperty -Path $StateKey -Name $name -Value $value -PropertyType DWord -Force | Out-Null
        return $true
    } catch { return $false }
}

function Get-InstallMark([string]$name) {
    try {
        $p = Get-ItemProperty -Path $StateKey -Name $name -ErrorAction Stop
        return [int]$p.$name
    } catch { return $null }   # $null = 没记录过(老版本装的,或注册表被清过)
}
# --- installmark:end ---

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
# -Check 与 -CollectLogs 都是只读的,而且恰恰是「什么都起不来、连提权都出问题」
# 时最需要能跑的两个动作 —— 所以不强制管理员,权限不足的部分自己降级。
if (-not $isAdmin -and -not $Check -and -not $CollectLogs) {
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
#  日志采集 —— 出问题时一键打包成一个可以直接发出来的压缩包
#
#  设计上有三条硬约束,都是实测出来的,不是防御性编程:
#
#  1) 必须脱敏。service.log 里实测出现过信誉代理的端点地址(7 处),
#     appsettings.json 在私有测试包里带 6 个真实密钥。如果原样打包,
#     用户把包发到论坛就等于公开这些东西。所有纳入的文本都过一遍
#     Protect-Text。
#  2) 必须限体积。整个 %ProgramData%\Bulwark 实测 110 MB
#     (audit 约 79 MB + history 约 24 MB),没法当附件发。大文件只取
#     尾部 —— 排障要看的本来就是最近发生了什么。
#  3) 绝不打包 quarantine\。那里是【真实恶意样本】。打进去会让用户的
#     压缩包被其他杀软拦下,而且等于在传播样本。只列文件名和大小。
#
#  产物:桌面上一个 zip。里面附 _必读.txt 说明收了什么、脱敏了什么、
#  刻意没收什么 —— 用户能自己判断该不该公开发出来。
# =====================================================================

# --- redaction:begin ---（仓库里的 tools\test-redaction.ps1 按这两个标记抽取本段做单测）
#
# 除了从 appsettings.json 现读出来的端点与密钥,还有一类要盖掉的东西:自家
# 基础设施的特征串(端点域名、令牌、兜底 IP)。它们【不会】出现在配置里
# —— 来自二进制内的兜底地址、DNS 解析日志等 —— 所以配置驱动的脱敏抓不到,
# 必须随包带一份清单。
#
# ⚠ 这里只带 SHA-256,不带明文。原因很实在:本文件是明文脚本,而
#   packaging\portable-scripts\ 会被【原样复制进每个包】。之前这里写的是明文
#   数组,等于发布包里附赠一份「我们的端点、令牌、IP」清单 —— 记事本打开
#   就能读。仓库里的 verify_portable.ps1 正是因此报了 LEAK,那不是误报。
#
#   明文清单的唯一来源是仓库里的 packaging\redaction-needles.txt(不进任何包)。
#   改了那个文件之后跑一次 verify_portable.ps1,它会核对这里的哈希并在不一致时
#   把该粘贴的行直接打印出来。
#
#   诚实说明这么做的边界:SHA-256 只能挡住「顺手一看」和自动扫描,挡不住
#   拿字典或 IPv4 全空间(2^32)去撞的人。但端点本来就是「跑一次抓包就能看到」
#   的东西,从来不是秘密;这一步要防的是用户把诊断包发到公开论坛时【顺带】
#   把它抄出去。令牌那种长随机串撞不出来,是真防住了。
$script:RedactNeedleHashes = @(
    '47d76fa1fd751e5044f1a339c7eb6ee89847a99086879033e672d785c7931a31',
    'ca2c0e58887e21362d933033ebbdbd6cd7f2710cb6e75329cb5f2f85d197a980',
    '17bc9fe8c1cb37ef27321507ad64bc936be334f455c7b7c34f198bba881fa4b7',
    '90519d40a2ddc493eec508d056c5f50ef059a0239991cc7a68f37d869d3def07'
)
$script:RedactLiterals = @()
$script:RedactHashSet  = $null
$script:RedactTokCache = $null
$script:RedactSha      = $null

function Get-RedactHash([string]$s) {
    if ($null -eq $script:RedactSha) { $script:RedactSha = [Security.Cryptography.SHA256]::Create() }
    $b = [Text.Encoding]::UTF8.GetBytes($s.ToLowerInvariant())
    return ([BitConverter]::ToString($script:RedactSha.ComputeHash($b))).Replace('-', '').ToLowerInvariant()
}

# 哈希只能做等值比较,没法像 substring 那样直接在长文本里找。所以反过来做:
# 先按通用形态把文本切成候选片段(IPv4 / 主机名 / 长字母数字串),再逐个算
# 哈希去比对。切分而不是滑动窗口,是因为在 PS 里对几 MB 文本逐字节滑窗算
# SHA-256 要跑几十秒,而诊断采集必须是「点一下就好」的操作。
#
# 代价说清楚:匹配粒度是「整个片段」。特征串若嵌在更长的串里
# (如 Bearer <令牌>xxxx),这里不命中 —— 那种形态由 Protect-Text 里的
# Bearer / api_key= / JSON 密钥字段通用规则兜住,两者互补。
function Hide-KnownNeedles([string]$t) {
    if (-not $script:RedactHashSet -or $script:RedactHashSet.Count -eq 0) { return $t }
    $rx = '(?i)\b(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)+|[a-z0-9]{8,64})\b'
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($t, $rx)) {
        $tok = $m.Value
        if ($script:RedactTokCache.ContainsKey($tok)) {
            if ($script:RedactTokCache[$tok]) { $hits.Add($tok) }
            continue
        }
        # 纯十六进制的 32/40/64 位是文件哈希,日志里满地都是,永远不是特征串;
        # 纯数字是 PID、字节数、时间戳。先筛掉,省下绝大部分哈希计算。
        $skip = ($tok -match '^[0-9]+$') -or
                ($tok -match '^[0-9a-fA-F]+$' -and @(32, 40, 64) -contains $tok.Length)
        $hit = $false
        if (-not $skip) {
            $cands = New-Object System.Collections.Generic.List[string]
            $cands.Add($tok)
            # 子域名:sub.example.com 里的 example.com 也要能命中,否则就比
            # 原来的 substring 匹配弱了。逐级去掉最左标签即可,IPv4 不参与。
            if ($tok.Contains('.') -and $tok -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
                $parts = $tok.Split('.')
                for ($i = 1; $i -lt $parts.Count - 1; $i++) {
                    $cands.Add(($parts[$i..($parts.Count - 1)] -join '.'))
                }
            }
            foreach ($c in $cands) {
                if ($script:RedactHashSet.Contains((Get-RedactHash $c))) { $hit = $true; break }
            }
        }
        $script:RedactTokCache[$tok] = $hit
        if ($hit) { $hits.Add($tok) }
    }
    # 长的先替换:短串先命中会把长串切碎,导致残留
    foreach ($h in ($hits | Sort-Object -Property Length -Descending -Unique)) {
        $t = $t -replace [regex]::Escape($h), '<已脱敏>'
    }
    return $t
}

function Initialize-Redaction {
    $script:RedactHashSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($h in $script:RedactNeedleHashes) {
        if ($h) { [void]$script:RedactHashSet.Add($h.Trim().ToLowerInvariant()) }
    }
    # 片段 -> 是否要盖 的判定结果缓存。Protect-Text 会被调用十来次,日志里同一个
    # 主机名/哈希会重复成千上万次,没有这层缓存就是成千上万次重复的 SHA-256。
    $script:RedactTokCache = New-Object 'System.Collections.Generic.Dictionary[string,bool]'

    $lits = New-Object System.Collections.Generic.List[string]
    $cfg = Join-Path $pkgDir 'appsettings.json'
    if (Test-Path $cfg) {
        try {
            $b = ((Get-Content $cfg -Raw -Encoding UTF8) | ConvertFrom-Json).Bulwark
            # 端点:明文的和混淆的都要盖掉 —— 混淆值泄出去,混淆就白做了
            foreach ($v in @($b.ReputationProxy.BaseUrl, $b.ReputationProxy.BaseUrlObfuscated,
                             $b.AttackChainEngine.BaseUrl)) {
                if ($v -and $v.ToString().Trim().Length -ge 6) { $lits.Add($v.ToString().Trim()) }
            }
            $secret = @(@('ReputationProxy','BearerToken'),@('VirusTotal','ApiKey'),@('MalwareBazaar','AuthKey'),
                        @('Otx','ApiKey'),@('ThreatBook','ApiKey'),@('MetaDefender','ApiKey'),
                        @('HybridAnalysis','ApiKey'),@('ThreatFoxFeed','AuthKey'),@('Ai','ApiKey'))
            foreach ($sp in $secret) {
                $v = $b.($sp[0]).($sp[1])
                # 太短的值不做字面替换,否则会把日志里无关的短串一起打成马赛克
                if ($v -and $v.ToString().Trim().Length -ge 8) { $lits.Add($v.ToString().Trim()) }
            }
        } catch { }
    }
    # 长的先替换,避免短串先命中后把长串切碎导致残留
    $script:RedactLiterals = @($lits | Sort-Object -Property Length -Descending -Unique)
}

function Protect-Text([string]$t) {
    if ([string]::IsNullOrEmpty($t)) { return $t }
    foreach ($lit in $script:RedactLiterals) {
        if ($lit) { $t = $t -replace [regex]::Escape($lit), '<已脱敏>' }
    }
    $t = Hide-KnownNeedles $t
    # 通用形态:JSON 字段、HTTP 头、URL 查询参数
    $t = [regex]::Replace($t, '(?i)("(?:BearerToken|ApiKey|AuthKey|Token|Secret|Password|Cookie)"\s*:\s*")[^"]*(")', '${1}<已脱敏>${2}')
    $t = [regex]::Replace($t, '(?i)(Bearer\s+)[A-Za-z0-9\.\-_=]{8,}', '${1}<已脱敏>')
    $t = [regex]::Replace($t, '(?i)\b(api[_\-]?key|auth[_\-]?key|token|access[_\-]?key)\s*[=:]\s*[A-Za-z0-9\.\-_]{8,}', '${1}=<已脱敏>')
    # 用户名会出现在几乎每条路径里,发到公开场合等于报上自己的名字。
    # 只替换用户名本身,路径结构保留,排障信息不丢。
    if ($env:USERNAME -and $env:USERNAME.Length -ge 3) {
        $t = $t -replace ('(?i)' + [regex]::Escape($env:USERNAME)), '<用户名>'
    }
    return $t
}
# --- redaction:end ---

# 大文件只取尾部:排障看的是「最近发生了什么」。按字节 Seek 而不是
# Get-Content -Tail,后者要把整个 16 MB 读进内存再数行。
function Copy-TailRedacted($src, $dst, [int]$maxBytes) {
    if (-not (Test-Path $src)) { return $false }
    $fi = Get-Item $src
    $note = ''
    $bytes = $null
    try {
        if ($fi.Length -le $maxBytes) {
            $bytes = [IO.File]::ReadAllBytes($src)
        } else {
            $fs = [IO.File]::Open($src, 'Open', 'Read', 'ReadWrite')
            try {
                [void]$fs.Seek(-1 * $maxBytes, 'End')
                $buf = New-Object byte[] $maxBytes
                $read = $fs.Read($buf, 0, $maxBytes)
                $bytes = $buf[0..($read - 1)]
            } finally { $fs.Dispose() }
            $note = ("### 原文件 {0:N0} B,此处只保留最后 {1:N0} B(前面被截掉) ###`r`n" -f $fi.Length, $maxBytes)
        }
    } catch {
        # 服务正在写、被独占锁住等情况:记录原因,不要让整个采集失败
        [IO.File]::WriteAllText($dst, ("### 读取失败:" + $_.Exception.Message + " ###"), (New-Object Text.UTF8Encoding($true)))
        return $true
    }
    $txt = [Text.Encoding]::UTF8.GetString($bytes)
    # 截断处第一行大概率是半行,去掉免得看起来像损坏
    if ($note -ne '') {
        $nl = $txt.IndexOf("`n")
        if ($nl -ge 0 -and $nl -lt $txt.Length - 1) { $txt = $txt.Substring($nl + 1) }
    }
    [IO.File]::WriteAllText($dst, ($note + (Protect-Text $txt)), (New-Object Text.UTF8Encoding($true)))
    return $true
}

function Invoke-CollectLogs {
    $ErrorActionPreference = 'Continue'   # 采集要尽力收完,单项失败不能中断整体

    Initialize-Redaction

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $work  = Join-Path $env:TEMP ("Bulwark-diag-" + $stamp)
    $dataDir = Join-Path $env:ProgramData 'Bulwark'
    New-Item -ItemType Directory -Force -Path $work | Out-Null

    Step '采集诊断信息'
    if (-not $isAdmin) { Warn '当前不是管理员 —— 驱动状态、服务查询等部分信息会缺失(仍会尽力采集)' }
    Info ('工作目录 ' + $work)

    # ---- 1) 体检报告:直接复用 -Check,不另写一套判据 -------------------
    # Ok/Warn/Bad 都是 Write-Host,不进管道;Start-Transcript 能捕获它们,
    # 这样报告内容与用户自己跑 -Check 看到的完全一致,不会两处逻辑打架。
    $rep = Join-Path $work 'report-体检.txt'
    try {
        Start-Transcript -Path $rep -Force | Out-Null
        try { Invoke-Check } catch { Write-Host ('体检过程出错:' + $_.Exception.Message) }
        Stop-Transcript | Out-Null
        # transcript 也要脱敏:里面会打印端点、密钥字段名与包内路径
        [IO.File]::WriteAllText($rep, (Protect-Text ([IO.File]::ReadAllText($rep))), (New-Object Text.UTF8Encoding($true)))
        Ok '体检报告已生成'
    } catch { Warn ('体检报告生成失败:' + $_.Exception.Message) }

    # ---- 2) 环境事实 ---------------------------------------------------
    $envTxt = Join-Path $work 'report-环境.txt'
    $o = New-Object System.Collections.Generic.List[string]
    function E($s) { $o.Add([string]$s) }
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        E ('采集时间   : ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'))
        E ('系统       : ' + $os.Caption + '  ' + $os.Version + '  (' + $os.OSArchitecture + ')')
        E ('内部版本   : ' + $os.BuildNumber)
        E ('语言/区域  : ' + (Get-Culture).Name + ' / ' + (Get-UICulture).Name + '  ACP=' + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage' -Name ACP -EA SilentlyContinue).ACP)
        E ('内存       : ' + [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) + ' GB')
        E ('是否虚拟机 : ' + $cs.Model)
        E ('管理员运行 : ' + $isAdmin)
        E ('PowerShell : ' + $PSVersionTable.PSVersion.ToString())
        E ('包目录     : ' + $pkgDir)
        E ''
        # 同类安全软件是共存类问题的第一现场,必须收
        E '== 已安装的安全软件 (SecurityCenter2) =='
        foreach ($cls in @('AntiVirusProduct','FirewallProduct')) {
            try {
                Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName $cls -EA Stop |
                    ForEach-Object { E ('  [' + $cls + '] ' + $_.displayName + '   state=0x' + ('{0:X}' -f $_.productState)) }
            } catch { E ('  ' + $cls + ' 查询失败:' + $_.Exception.Message) }
        }
        E ''
        E '== 内核筛选器 (fltmc filters) =='
        try { (& $fltmc filters 2>&1) | ForEach-Object { E ('  ' + $_) } } catch { E '  fltmc 执行失败' }
        E ''
        E '== 服务状态 =='
        foreach ($svc in @($ServiceName, $UserService)) {
            E ('  --- ' + $svc)
            try { (& $scExe query $svc 2>&1) | ForEach-Object { E ('    ' + $_) } } catch { E '    sc query 失败' }
            try { (& $scExe qc $svc 2>&1)    | ForEach-Object { E ('    ' + $_) } } catch { }
        }
        E ''
        E '== 启动配置 (bcdedit) =='
        try { (& $bcdedit 2>&1) | Select-String -Pattern 'testsigning|nointegritychecks|hypervisorlaunchtype|identifier|description' |
                ForEach-Object { E ('  ' + $_.Line.Trim()) } } catch { E '  bcdedit 执行失败' }
        E ''
        E '== 相关进程 =='
        foreach ($pn in @('bulwark_service','bulwark_ui')) {
            $ps = Get-Process -Name $pn -EA SilentlyContinue
            if ($ps) { foreach ($p in $ps) { E ('  ' + $pn + '  PID=' + $p.Id + '  启动=' + $p.StartTime + '  内存=' + [math]::Round($p.WorkingSet64/1MB,1) + ' MB') } }
            else { E ('  ' + $pn + ' 未运行') }
        }
        E ''
        E '== 包内文件清单 =='
        foreach ($f in (Get-ChildItem $pkgDir -File | Sort-Object Name)) {
            $h = ''
            try { $h = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.Substring(0,16) } catch { }
            E ('  {0,-28} {1,10} B  {2}  {3}' -f $f.Name, $f.Length, $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $h)
        }
        E ''
        E '== 系统事件日志中与本产品相关的记录(最近 50 条) =='
        try {
            Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 3000 -EA SilentlyContinue |
                Where-Object { $_.Message -match 'Bulwark' -or $_.ProviderName -match 'Bulwark' } |
                Select-Object -First 50 |
                ForEach-Object { E ('  ' + $_.TimeCreated.ToString('MM-dd HH:mm:ss') + ' [' + $_.LevelDisplayName + '] ' + $_.ProviderName + ': ' + ($_.Message -replace "`r?`n", ' ')) }
        } catch { E ('  事件日志读取失败:' + $_.Exception.Message) }
        E ''
        E '== 应用程序错误 / 蓝屏相关(最近 20 条) =='
        try {
            Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error','Application Hang','Windows Error Reporting'; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 200 -EA SilentlyContinue |
                Where-Object { $_.Message -match 'bulwark' } | Select-Object -First 20 |
                ForEach-Object { E ('  ' + $_.TimeCreated.ToString('MM-dd HH:mm:ss') + ' ' + ($_.Message -replace "`r?`n", ' ')) }
        } catch { }
        $dmp = Join-Path $env:SystemRoot 'MEMORY.DMP'
        E ''
        E ('内核转储 MEMORY.DMP : ' + $(if (Test-Path $dmp) { '存在(' + [math]::Round((Get-Item $dmp).Length/1MB,0) + ' MB,未打包,蓝屏排查时再单独索取)' } else { '不存在' }))
        $mini = Join-Path $env:SystemRoot 'Minidump'
        if (Test-Path $mini) {
            E '小型转储 Minidump  :'
            foreach ($f in (Get-ChildItem $mini -File -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 5)) {
                E ('  ' + $f.Name + '  ' + [math]::Round($f.Length/1KB,0) + ' KB  ' + $f.LastWriteTime)
            }
        } else { E '小型转储 Minidump  : 无' }
    } catch { E ('环境采集出错:' + $_.Exception.Message) }
    [IO.File]::WriteAllText($envTxt, (Protect-Text (($o -join "`r`n"))), (New-Object Text.UTF8Encoding($true)))
    Ok '环境信息已采集'

    # ---- 3) 运行期文件 -------------------------------------------------
    # 上限是按「够定位问题」而不是「越多越好」定的:一个能当附件发出去的包
    # 比一个 110 MB 但没人愿意下载的包有用。
    $plan = @(
        @{ N = 'bootstrap-status.txt';    Max = 256KB },   # 起不来时第一个看的
        @{ N = 'crash.log';               Max = 512KB },
        @{ N = 'rep_diag.log';            Max = 512KB },
        @{ N = 'service.log';             Max = 1MB   },   # 主日志,取尾部
        @{ N = 'service.log.1';           Max = 256KB },   # 上一轮轮转
        @{ N = 'rules.json';              Max = 2MB   },   # 「为什么拦了/没拦」要看规则
        @{ N = 'attackchain.json';        Max = 1MB   },
        @{ N = 'attackchain_hits.jsonl';  Max = 512KB },
        @{ N = 'reputation.jsonl';        Max = 512KB },
        @{ N = 'vt_scan_history.json';    Max = 512KB },
        @{ N = 'seen_hashes.txt';         Max = 256KB },
        @{ N = 'baseline.json';           Max = 512KB },
        @{ N = 'client-id.txt';           Max = 4KB   }
    )
    $dataOut = Join-Path $work 'ProgramData-Bulwark'
    New-Item -ItemType Directory -Force -Path $dataOut | Out-Null
    if (-not (Test-Path $dataDir)) {
        [IO.File]::WriteAllText((Join-Path $dataOut '_数据目录不存在.txt'),
            "%ProgramData%\Bulwark 不存在 —— 后台服务从未成功启动过。`r`n这本身就是重要线索:请重点看 report-体检.txt。",
            (New-Object Text.UTF8Encoding($true)))
        Warn '数据目录不存在(服务从未成功启动)'
    } else {
        $got = 0
        foreach ($item in $plan) {
            $src = Join-Path $dataDir $item.N
            if (Copy-TailRedacted $src (Join-Path $dataOut $item.N) $item.Max) { $got++ }
        }
        Info ("已收 $got / " + $plan.Count + ' 个运行期文件')

        # audit / history 是最大的两块,只取最新一个文件的尾部
        foreach ($sub in @('audit','history')) {
            $sd = Join-Path $dataDir $sub
            if (-not (Test-Path $sd)) { continue }
            $od = Join-Path $dataOut $sub
            New-Item -ItemType Directory -Force -Path $od | Out-Null
            $newest = Get-ChildItem $sd -File -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($newest) {
                Copy-TailRedacted $newest.FullName (Join-Path $od $newest.Name) 512KB | Out-Null
                Info ("$sub\ 只取最新的 " + $newest.Name + ' 尾部 512 KB')
            }
            # 其余文件只留清单,让人知道现场还有多少数据可以按需索取
            $inv = New-Object System.Collections.Generic.List[string]
            $inv.Add("$sub\ 目录清单(实际内容未全部打包,如需请单独索取):")
            foreach ($f in (Get-ChildItem $sd -File -EA SilentlyContinue | Sort-Object Name)) {
                $inv.Add(('  {0,-34} {1,12:N0} B  {2}' -f $f.Name, $f.Length, $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))
            }
            [IO.File]::WriteAllText((Join-Path $od '_清单.txt'), ($inv -join "`r`n"), (New-Object Text.UTF8Encoding($true)))
        }

        # 隔离区:只列清单,内容绝不打包(是真实样本)
        $q = Join-Path $dataDir 'quarantine'
        $qinv = New-Object System.Collections.Generic.List[string]
        $qinv.Add('隔离区清单 —— 文件内容【刻意没有打包】。')
        $qinv.Add('这里放的是真实恶意样本:打进压缩包会被其他杀软拦下,也等于在传播样本。')
        $qinv.Add('')
        if (Test-Path $q) {
            $qf = @(Get-ChildItem $q -Recurse -File -EA SilentlyContinue)
            $qinv.Add('文件数:' + $qf.Count)
            foreach ($f in $qf) { $qinv.Add(('  {0,-44} {1,12:N0} B  {2}' -f $f.Name, $f.Length, $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))) }
        } else { $qinv.Add('(隔离区目录不存在)') }
        [IO.File]::WriteAllText((Join-Path $dataOut 'quarantine-仅清单.txt'), (Protect-Text ($qinv -join "`r`n")), (New-Object Text.UTF8Encoding($true)))
    }

    # ---- 4) 脱敏后的配置 -----------------------------------------------
    $cfg = Join-Path $pkgDir 'appsettings.json'
    if (Test-Path $cfg) {
        $raw = [IO.File]::ReadAllText($cfg)
        # 先把所有已知密钥字段整体置空,再走通用脱敏 —— 双保险
        $red = [regex]::Replace($raw, '(?i)("(?:BearerToken|ApiKey|AuthKey)"\s*:\s*")[^"]*(")', '${1}<已脱敏>${2}')
        $red = [regex]::Replace($red, '(?i)("BaseUrl(?:Obfuscated)?"\s*:\s*")[^"]*(")', '${1}<已脱敏>${2}')
        [IO.File]::WriteAllText((Join-Path $work 'appsettings-已脱敏.json'), (Protect-Text $red), (New-Object Text.UTF8Encoding($true)))
        Ok 'appsettings.json 已脱敏后纳入'
    }

    # ---- 5) 必读说明 ---------------------------------------------------
    $readme = @(
        '磐垒主动防御 —— 诊断信息包',
        '',
        '采集时间:' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        '主机名  :' + $env:COMPUTERNAME,
        '',
        '这个包是干什么的',
        '  出问题时把它整个发给作者,就不用来回追问「日志在哪」「什么系统」。',
        '',
        '包里有什么',
        '  report-体检.txt          与自己跑 -Check 看到的完全一致',
        '  report-环境.txt          系统版本、已装的其他安全软件、服务与驱动状态、',
        '                           事件日志里与本产品相关的记录、包内文件清单',
        '  appsettings-已脱敏.json  配置(端点与密钥字段已被替换)',
        '  ProgramData-Bulwark\     运行期日志与状态文件',
        '',
        '已经替你处理掉的东西',
        '  · 信誉代理端点(明文与混淆值)、所有 API 密钥、Bearer 令牌',
        '    —— 实测 service.log 里会出现端点地址,所以这一步是必要的,不是形式',
        '  · Windows 用户名 —— 替换成 <用户名>,路径结构保留',
        '',
        '刻意没有收的东西',
        '  · 隔离区(quarantine)里的文件内容。那是真实恶意样本,打包会被其他',
        '    杀软拦下,也等于在传播样本。只给了文件名和大小清单。',
        '  · audit\ 与 history\ 的全量数据。整个数据目录约上百 MB,当附件发不现实。',
        '    只取了最新一个文件的尾部,其余只留清单 —— 需要的话可以再单独索取。',
        '  · 内核转储 MEMORY.DMP / Minidump。文件太大,蓝屏排查时再单独索取。',
        '',
        '仍然请你自己过一眼',
        '  日志里会包含你机器上的进程命令行和文件路径 —— 这是排障必须的信息,',
        '  但也可能带出你不想公开的内容。发到公开论坛前建议先扫一眼,',
        '  介意的话改成私发给作者。'
    )
    [IO.File]::WriteAllText((Join-Path $work '_必读.txt'), ($readme -join "`r`n"), (New-Object Text.UTF8Encoding($true)))

    # ---- 6) 打包 -------------------------------------------------------
    # 放桌面而不是包目录:包可能在只读介质或 U 盘上,而且桌面最好找。
    $desktop = [Environment]::GetFolderPath('Desktop')
    if (-not $desktop -or -not (Test-Path $desktop)) { $desktop = $env:USERPROFILE }
    $zip = Join-Path $desktop ("Bulwark-诊断-" + $env:COMPUTERNAME + "-" + $stamp + ".zip")
    $zipped = $false
    try {
        # .NET 直接压,不依赖 Compress-Archive(PS 5.1 早期版本对中文名有坑)
        Add-Type -AssemblyName System.IO.Compression.FileSystem -EA Stop
        if (Test-Path $zip) { Remove-Item $zip -Force }
        [IO.Compression.ZipFile]::CreateFromDirectory($work, $zip,
            [IO.Compression.CompressionLevel]::Optimal, $false, [Text.Encoding]::UTF8)
        $zipped = Test-Path $zip
    } catch { Warn ('压缩失败:' + $_.Exception.Message) }

    Write-Host ''
    if ($zipped) {
        $zi = Get-Item $zip
        Write-Host '==== 采集完成 ====' -ForegroundColor Cyan
        Ok ('已生成:' + $zip)
        Ok ('大小:' + [math]::Round($zi.Length / 1KB, 0) + ' KB')
        Info '把这个 zip 发给作者即可。发之前建议先看一眼里面的 _必读.txt。'
        Remove-Item $work -Recurse -Force -EA SilentlyContinue
    } else {
        Bad '压缩没成功,但采集到的文件都还在:'
        Info $work
        Info '可以手动把这个文件夹压缩后发出来。'
    }
    Write-Host ''
}

# =====================================================================
#  卸载 —— 这是正经安全工具,始终保留用户自主卸载的通路,不做成「删不掉」
# =====================================================================
# --- uninstall:begin ---（仓库里的 tools\test-uninstall.ps1 按这两个标记抽取本段做单测）
function Invoke-Uninstall {
    $ErrorActionPreference = 'Continue'   # 卸载要尽力做完每一步,不能中途抛异常留半套
    $needReboot = $false

    Step '停止用户态'
    & $scExe stop $UserService 2>&1 | Out-Null
    Get-Process -Name 'bulwark_ui','bulwark_service' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Ok '已停止(未运行时报错属正常)'

    # 顺序必须是「先卸驱动,再删注册/删文件」:驱动在载时 .sys 被锁死,而且内核自我
    # 保护会硬拦对 \Services\Bulwark* 的注册表写入和对数据目录的删除 —— 顺序反了
    # 后面每一步都会失败,而且失败得很难看懂。
    Step '卸载内核驱动'
    & $fltmc unload $ServiceName 2>&1 | Out-Null
    & $scExe  stop   $ServiceName 2>&1 | Out-Null
    Start-Sleep -Seconds 1
    $stillLoaded = ($null -ne (& $fltmc filters 2>$null | Select-String -SimpleMatch $ServiceName))
    if ($stillLoaded) {
        Warn "$ServiceName 仍在 fltmc filters 中 —— 重启后会彻底卸掉"
        Info '驱动还在的情况下,自我保护会拦住删 .sys 和删数据目录,这两步可能失败。'
        $needReboot = $true
    } else { Ok '驱动已卸载' }

    Step '删除服务注册'
    foreach ($svc in @($ServiceName, $UserService)) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            & $scExe delete $svc 2>&1 | Out-Null
            if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
                Warn "$svc 删除未生效(重启后消失)"; $needReboot = $true
            } else { Ok "$svc 已删除" }
        } else { Ok "$svc 未注册(跳过)" }
    }

    Step '删除 System32\drivers\Bulwark.sys'
    if (Test-Path $dstSys) {
        try { Remove-Item $dstSys -Force; Ok '已删除' }
        catch { Warn '删除失败(驱动可能仍加载中)—— 重启后再运行一次即可'; $needReboot = $true }
    } else { Ok '文件不存在(跳过)' }

    Step '移除测试证书'
    if ($KeepCert) {
        Ok '按 -KeepCert 保留 BulwarkTestCert'
    } else {
        $n = 0
        foreach ($store in @('Root','TrustedPublisher')) {
            Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -like "*$CertSubject*" } |
                ForEach-Object { Remove-Item $_.PSPath -Force -ErrorAction SilentlyContinue; $n++ }
        }
        if ($n -gt 0) { Ok "已移除 $n 份 $CertSubject 证书" } else { Ok '没有找到需要移除的证书' }
    }

    Step '退出测试模式(关闭测试签名)'
    # 这是唯一一项动了「别人也可能在用」的机器全局设置的操作,所以判断要讲清楚。
    $byUs = Get-InstallMark 'TestSigningEnabledByUs'
    if ($KeepTestSigning) {
        Ok '按 -KeepTestSigning 保留测试签名开启状态'
    } elseif ($byUs -eq 0) {
        # 装本产品之前它就是开的 —— 大概率是为别的自签名驱动开的,关掉会连带弄坏
        Warn '测试签名在安装本产品【之前】就已开启,判定不是本产品打开的,保持不动'
        Info '确实要关(会让其他测试签名驱动一起加载不了):'
        Info '  管理员运行  bcdedit /set testsigning off  然后重启'
    } else {
        $out = (& $bcdedit /set testsigning off 2>&1) -join ' '
        if ($LASTEXITCODE -eq 0) {
            Ok '测试签名已关闭 —— 重启后生效,右下角「测试模式」水印随之消失'
            $needReboot = $true
            if ($null -eq $byUs) {
                Info '(没有安装记录,无法判断是否本产品开的;若你还有别的测试签名驱动,'
                Info ' 重启后它们会加载不了,用 bcdedit /set testsigning on 可以再打开。)'
            }
        } else {
            Bad ('bcdedit /set testsigning off 失败:' + $out)
            Info '常见原因:BitLocker 已启用(需先挂起)、或该命令被其他安全软件拦下。'
        }
    }

    Step '清理安装痕迹'
    # 装过「重启后自动继续」就一并清掉,免得卸载后还被拉起来
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' `
                        -Name 'BulwarkSetupResume' -ErrorAction SilentlyContinue
    Ok '已清除「重启后自动继续」'
    if (Test-Path $StateKey) {
        Remove-Item $StateKey -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $StateKey) { Warn "$StateKey 删除失败" } else { Ok '已删除安装标记键' }
    } else { Ok '没有安装标记键(跳过)' }

    # ---- 数据目录 ----------------------------------------------------------
    # 这里放的是用户攒下来的规则、审计日志,以及【真实恶意样本】的隔离区。
    # 删掉不可逆,所以不默认删:要么显式加开关,要么当场问一句。
    Step '数据目录'
    $dataDir = Join-Path $env:ProgramData 'Bulwark'
    if (-not (Test-Path $dataDir)) {
        Ok '数据目录不存在(跳过)'
    } else {
        $files = @(Get-ChildItem $dataDir -Recurse -File -ErrorAction SilentlyContinue)
        $mb = 0
        if ($files.Count -gt 0) { $mb = [math]::Round((($files | Measure-Object -Property Length -Sum).Sum) / 1MB, 1) }
        $qDir = Join-Path $dataDir 'quarantine'
        $qn = 0
        if (Test-Path $qDir) { $qn = @(Get-ChildItem $qDir -Recurse -File -ErrorAction SilentlyContinue).Count }
        Info ("路径:$dataDir")
        Info ("内容:$($files.Count) 个文件,约 $mb MB;隔离区样本 $qn 个")

        $doPurge = $false
        if ($PurgeData) { $doPurge = $true }
        elseif ($KeepData) { $doPurge = $false }
        else {
            Write-Host ''
            Write-Host '  这里面有你的自定义规则、审计日志' -NoNewline -ForegroundColor Yellow
            if ($qn -gt 0) { Write-Host "、以及 $qn 个隔离的真实恶意样本" -NoNewline -ForegroundColor Yellow }
            Write-Host ';删除不可恢复。' -ForegroundColor Yellow
            try {
                $ans = Read-Host '  一并删除数据目录吗?(y/N,默认 N=保留)'
                if ($ans -match '^[Yy]') { $doPurge = $true }
            } catch {
                # 非交互(比如被别的脚本管道调用)时读不到输入 —— 那就按保留处理,
                # 绝不在无人应答的情况下删用户数据。
                Info '(非交互环境,按保留处理;需要删除请加 -PurgeData)'
            }
        }

        if (-not $doPurge) {
            Ok '已保留数据目录(需要删除:加 -PurgeData,或手动删该文件夹)'
        } else {
            Remove-Item $dataDir -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path $dataDir) {
                $left = @(Get-ChildItem $dataDir -Recurse -File -ErrorAction SilentlyContinue).Count
                Warn "数据目录未能完全删除,还剩 $left 个文件"
                if ($stillLoaded) { Info '驱动仍在加载中,自我保护会拦住删除 —— 重启后再删一次即可。' }
                else { Info '可能有文件被占用 —— 重启后手动删除该文件夹即可。' }
            } else { Ok '数据目录已删除' }
        }
    }

    # ---- 复查 --------------------------------------------------------------
    # 光打印「卸载完成」是不够的:上面每一步都可能被自我保护、文件占用或
    # bcdedit 拦下。这里把结果重新读一遍,残留了什么就直说。
    Step '复查(重新读一遍真实状态)'
    $left = @()
    if ($null -ne (& $fltmc filters 2>$null | Select-String -SimpleMatch $ServiceName)) { $left += '内核驱动仍处于加载状态' }
    foreach ($svc in @($ServiceName, $UserService)) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) { $left += "服务 $svc 仍存在" }
    }
    if (Test-Path $dstSys) { $left += 'System32\drivers\Bulwark.sys 仍存在' }
    if (-not $KeepCert) {
        $cn = 0
        foreach ($store in @('Root','TrustedPublisher')) {
            $cn += @(Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue |
                     Where-Object { $_.Subject -like "*$CertSubject*" }).Count
        }
        if ($cn -gt 0) { $left += "$CertSubject 证书仍有 $cn 份" }
    }
    $tsLine = ((& $bcdedit) 2>$null | Select-String -SimpleMatch 'testsigning') -join ' '
    $tsOn = ($tsLine -match 'Yes|是')
    if ($KeepTestSigning -or $byUs -eq 0) {
        Ok ('测试签名:保持不动(当前 ' + $(if ($tsOn) { '开启' } else { '关闭' }) + ')')
    } elseif ($tsOn) {
        $left += '测试签名仍为开启(bcdedit 未生效)'
    } else {
        # 括号是必须的:Ok '...' + $(...) 会被解析成「给 Ok 传三个位置参数」,
        # 非高级函数把多出来的塞进 $args 且不报错,后半句就这么静默消失了。
        Ok ('测试签名:已关闭' + $(if ($needReboot) { '(重启后水印消失)' } else { '' }))
    }
    if (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' `
                         -Name 'BulwarkSetupResume' -ErrorAction SilentlyContinue) { $left += '「重启后自动继续」仍在' }

    Write-Host ''
    if ($left.Count -eq 0) {
        Write-Host '==== 卸载完成:没有残留 ====' -ForegroundColor Green
    } else {
        Write-Host '==== 卸载基本完成,但还有残留 ====' -ForegroundColor Yellow
        foreach ($x in $left) { Bad $x }
        Write-Host ''
        Info '这些几乎都是「文件/服务还被内核占着」造成的:重启一次,再双击 卸载.bat 跑一遍即可清干净。'
    }
    Write-Host ''
    if ($needReboot) { Warn '需要重启一次才能完全生效(退出测试模式、彻底卸掉驱动)' }
    Info '便携包文件夹现在可以直接删除。'
    Write-Host ''
}
# --- uninstall:end ---

# =====================================================================
#  应用在线更新
#
#  服务已经把三个 PE 下到暂存目录并做过四道校验(名字白名单 / 大小 / SHA-256 /
#  签名者指纹)。那为什么这里【还要】把签名重验一遍?
#
#    因为暂存目录在 %LOCALAPPDATA% 下,普通用户可写、不需要管理员。从服务校验
#    完成到本脚本提权取用之间存在一个 TOCTOU 窗口:任何以当前用户身份运行的
#    进程都能在这段时间里把文件换掉。而本脚本接下来要做的事是「把这些文件复制
#    进安装目录,并把其中一个作为内核驱动加载」—— 这是整个产品里权限最高的一次
#    操作。校验必须发生在【使用的那一刻、提权的上下文里】,否则前面四道校验挡不
#    住这个窗口。
#
#  为什么不把暂存目录挪到只有管理员能写的地方?
#    试过这个方向:服务以 SYSTEM 跑,能写 %ProgramData%\Bulwark,但那棵树被内核
#    SelfGuard 守着,连自己的服务进程写都要走白名单,反而更脆。保留用户可写的
#    暂存 + 使用时重验,信任边界更清楚。
# =====================================================================
# --- applyupdate:begin ---（tools\test-update-apply.ps1 按这两个标记抽取本段做单测）
function Compare-BulwarkVersion([string]$a, [string]$b) {
    # 返回 >0 表示 $a 更新。逐段按整数比,避免字符串比较把 "1.1.10" 判成小于 "1.1.9"。
    $pa = @($a -split '\.'); $pb = @($b -split '\.')
    for ($i = 0; $i -lt 4; $i++) {
        $x = 0; $y = 0
        if ($i -lt $pa.Count) { [void][int]::TryParse($pa[$i], [ref]$x) }
        if ($i -lt $pb.Count) { [void][int]::TryParse($pb[$i], [ref]$y) }
        if ($x -ne $y) { return $x - $y }
    }
    return 0
}

function Test-UpdatePayloadTrust($path) {
    # 返回 $null = 可信;否则返回拒绝原因。
    #
    # 要回答两个【互相独立】的问题,缺一不可:
    #   1) 签名是否覆盖当前的文件内容?      -> 看 Status
    #   2) 是谁签的?                        -> 看签名者指纹
    #
    # 本函数最初只做了第 2 条,那是个真实的漏洞,单测抓到的:把 PE 中间一个字节改
    # 掉【不会】破坏嵌入的签名 blob —— 证书还在、指纹还是我们那张,只有摘要不匹配。
    # 实测:
    #   干净文件   Status=UnknownError  SignerPresent=True  Thumb=712BA1C841C8...
    #   篡改一字节 Status=HashMismatch  SignerPresent=True  Thumb=712BA1C841C8...
    # 指纹一模一样。所以「指纹在名单里」完全不能证明文件没被动过。
    if (-not (Test-Path -LiteralPath $path)) { return '文件不存在' }
    $sig = Get-AuthenticodeSignature -LiteralPath $path
    $status = [string]$sig.Status
    if ($status -eq 'NotSigned') { return '没有数字签名' }
    if ($null -eq $sig.SignerCertificate) { return '取不到签名者证书' }

    # 那为什么不直接要求 Status -eq 'Valid'?因为目标机器在【导入这张自签测试证书
    # 之前】,干净文件的状态就是 UnknownError(根不受信任)—— 而那正是一台刚拿到
    # 便携包的机器的状态。要求 Valid 会把所有正常更新拒掉。
    # 所以放行 Valid 与 UnknownError 两种,并在 UnknownError 时补一道链检查:
    # 这个状态是个 catch-all,必须确认「链上唯一的问题就是根不受信任」,否则
    # 证书过期、用途不符等毛病会被它一起放过去。
    $allowed = @('Valid', 'UnknownError')
    if ($allowed -notcontains $status) { return ('签名无效:' + $status + '(文件在下载后被改动过)') }
    if ($status -eq 'UnknownError') {
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        # 目标机器可能没有外网。吊销检查连不上 CRL 会让链构建失败,那不是我们
        # 要在这里判断的问题(信任锚点是钉死的指纹,不是 CA 的吊销状态)。
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        [void]$chain.Build($sig.SignerCertificate)
        $benign = @('NoError', 'UntrustedRoot', 'PartialChain')
        $bad = @($chain.ChainStatus | ForEach-Object { [string]$_.Status } |
                 Where-Object { $benign -notcontains $_ })
        if ($bad.Count -gt 0) { return ('签名链异常:' + ($bad -join ',')) }
    }

    $tp = $sig.SignerCertificate.Thumbprint.ToUpper()
    if ($UpdateSignerThumbprints -notcontains $tp) { return ('签名者指纹不在钉死名单内:' + $tp) }
    return $null
}

function Invoke-ApplyUpdate {
    $ErrorActionPreference = 'Continue'

    $srcDir = $UpdateDir
    if (-not $srcDir) { $srcDir = Join-Path $env:LOCALAPPDATA 'Bulwark\update' }

    Step '检查暂存的更新文件'
    Info ("来源:$srcDir")
    if (-not (Test-Path -LiteralPath $srcDir)) {
        Bad '没有找到已下载的更新。'
        Info '请先在界面里「设置 > 关于与更新 > 检查更新」下载一次。'
        return $false
    }

    # 白名单是固定的三个 PE。脚本与配置【刻意】不在其中:它们无签名且会以管理员
    # 执行,纳入在线更新等于开一条「服务器能在客户端跑任意脚本」的路。
    $payload = @('bulwark_service.exe', 'bulwark_ui.exe', 'Bulwark.sys')

    $staged = @()
    foreach ($n in $payload) {
        $p = Join-Path $srcDir $n
        if (-not (Test-Path -LiteralPath $p)) {
            Bad "缺少 $n —— 更新包不完整,拒绝应用。"
            Info '整份拒绝而不是「装能装的那几个」:混版组合(新服务 + 旧驱动)从未被测过。'
            return $false
        }
        $staged += $p
    }
    Ok ("三个载荷文件齐全")

    Step '校验签名(提权上下文里重验一次)'
    foreach ($p in $staged) {
        $why = Test-UpdatePayloadTrust $p
        if ($why) {
            Bad ((Split-Path $p -Leaf) + ':' + $why)
            Info '更新已被拒绝,安装目录未做任何改动。'
            Info '这通常意味着下载后文件被替换过 —— 请删除暂存目录后重新下载。'
            return $false
        }
    }
    Ok ("$($staged.Count) 个文件均由钉死的证书签名")

    Step '版本比对'
    $curExe = Join-Path $pkgDir 'bulwark_ui.exe'
    if (-not (Test-Path -LiteralPath $curExe)) { Bad "本目录没有 bulwark_ui.exe:$pkgDir"; return $false }
    $curVer = (Get-Item -LiteralPath $curExe).VersionInfo.FileVersion
    $newVer = (Get-Item -LiteralPath (Join-Path $srcDir 'bulwark_ui.exe')).VersionInfo.FileVersion
    Info ("当前 $curVer  ->  待装 $newVer")
    $cmp = Compare-BulwarkVersion $newVer $curVer
    if ($cmp -le 0) {
        # 拒绝同版本和降级。降级是一条真实的攻击路径:把已修掉漏洞的版本换回旧版,
        # 用一个【签名合法】的旧文件就能把防护打回有洞的状态。
        Bad '待装版本不比当前版本新,拒绝应用(不允许降级或重装同版本)。'
        return $false
    }
    Ok '版本递进,可以应用'

    # ---- 停运行时 ----------------------------------------------------------
    # 顺序是【先卸驱动,再杀进程】,而且整段排在「备份」之前。
    #
    # 直觉上应该反过来(先停用户态、再卸内核),卸载流程也是那个顺序。但更新不一样,
    # 因为更新必须【替换正在运行的 exe】,而这要求进程真的死掉:
    #
    #   驱动在载时,我们自己的进程在内核自我保护名单里 —— powershell.exe 拿不到
    #   PROCESS_TERMINATE,Stop-Process 会静默失败。实测(2026-08-12 那次):
    #     02:52:59  停止防护 开始
    #     02:53:00  fltmc unload
    #     02:53:02  [Worker] ... 送 VirusTotal 扫描   <- 服务还在写日志
    #     02:53:07  [Worker] ... bcdedit             <- 依然活着
    #   服务从头到尾没被杀掉,于是它锁着自己的 exe,替换 bulwark_service.exe 必然失败。
    #   而当时这段代码照样打印「均已停止」—— 那句话是假的,比失败本身更误导。
    #
    # 所以:先 fltmc unload 让自我保护消失,再杀进程,并且【必须核实进程真的没了】。
    Step '停止防护'
    # 常驻模式下可能注册成了服务,先请服务控制器停一次(便携模式下报错属正常)。
    & $scExe stop $UserService 2>&1 | Out-Null

    & $fltmc unload $ServiceName 2>&1 | Out-Null
    & $scExe  stop   $ServiceName 2>&1 | Out-Null
    Start-Sleep -Seconds 1
    if ($null -ne (& $fltmc filters 2>$null | Select-String -SimpleMatch $ServiceName)) {
        # 驱动还在载:复制 .sys 一定失败,而部分替换掉的 exe 会和旧驱动组成没测过的
        # 混版。此刻还没动任何文件,停在原状最安全。
        Bad '内核驱动仍处于加载状态,无法替换驱动文件。'
        Info '更新已中止,安装目录保持原样。'
        Info '请重启一次机器,然后再点一次「立即安装」。'
        return $false
    }
    Ok '内核驱动已卸载(自我保护随之解除)'

    # 驱动没了,自我保护也就没了,这时候才杀得掉自己的进程。
    Get-Process -Name 'bulwark_ui','bulwark_service' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    # 核实,而不是「发完命令就当成功」。进程没死却往下走,就是上一版那个失败:
    # 替换报「访问被拒绝」,而日志前一行还写着「均已停止」。
    $alive = @()
    for ($i = 1; $i -le 10; $i++) {
        $alive = @(Get-Process -Name 'bulwark_ui','bulwark_service' -ErrorAction SilentlyContinue)
        if ($alive.Count -eq 0) { break }
        Start-Sleep -Seconds 1
        Get-Process -Name 'bulwark_ui','bulwark_service' -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }
    if ($alive.Count -gt 0) {
        Bad ('以下进程仍在运行,无法替换程序文件:' +
             (($alive | ForEach-Object { $_.ProcessName + '(' + $_.Id + ')' }) -join '、'))
        Info '更新已中止,安装目录保持原样 —— 一个字节都没动。'
        # 驱动是我们刚卸的,必须装回去:否则用户只看到「更新失败」,不知道防护也停了。
        Step '恢复防护'
        if ((Ensure-Driver) -eq $true) { Ok '驱动已重新加载,防护已恢复' }
        else {
            Bad '驱动未能重新加载 —— 防护当前处于停止状态'
            Info '请重启一次机器,然后双击 启动Bulwark.bat。'
        }
        Write-Host ''
        return $false
    }
    Ok '界面与服务已确认退出'

    # ---- 备份 --------------------------------------------------------------
    # 这一步【必须】排在「停止防护」之后。
    #
    # 备份写的是安装目录,而安装目录在内核 SelfGuard 的守护范围内。SelfGuard 的规则是
    # 「仅放行本产品自身进程写入,其余进程写/删/改名一律拒绝」—— 执行本脚本的是
    # powershell.exe,不是本产品进程。所以驱动还在载的时候连备份都会失败:
    #     Copy-Item : 对路径 "...\backup-1.2.3-...\bulwark_service.exe" 的访问被拒绝
    # 这条是实测踩出来的。更麻烦的是当时审计日志把同一个操作记成了「放行」——
    # 内核 SelfGuard 与用户态 RuleEngine 是两条独立的决策路径,生效的是内核那条,
    # 所以「日志里写着放行」并不能证明操作没有被拦。
    #
    # 原先把备份放在最前面的理由是「先备份再动手」。那个理由只针对「替换文件」,
    # 与「停防护」没有先后关系:驱动卸掉之后再备份,依然是在任何文件被替换【之前】
    # 完成的,回滚需要的「原封不动的三个文件」一样拿得到。
    Step '备份当前版本'
    $backupDir = Join-Path $pkgDir ('backup-' + $curVer + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $backupErr = $null
    try {
        New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
        foreach ($n in $payload) {
            $s = Join-Path $pkgDir $n
            if (Test-Path -LiteralPath $s) { Copy-Item -LiteralPath $s -Destination (Join-Path $backupDir $n) -Force }
        }
        $backedUp = @(Get-ChildItem -LiteralPath $backupDir -File).Count
        if ($backedUp -lt 1) { $backupErr = '备份目录是空的' }
    } catch {
        $backupErr = $_.Exception.Message
    }
    if ($backupErr) {
        # 防护此刻已经停了,所以不能就这么 return —— 那会把机器留在没有防护的状态,
        # 而用户只看到一句「备份失败」,完全不知道防护也一起没了。
        Bad ('备份失败,拒绝继续:' + $backupErr)
        Info '没有可回滚的备份就动安装目录,失败时会留下一个跑不起来的包。'
        Step '恢复防护'
        if ((Ensure-Driver) -eq $true) {
            Ok '驱动已重新加载,防护已恢复(安装目录未做任何改动)'
        } else {
            Bad '驱动未能重新加载 —— 防护当前处于停止状态'
            Info '请重启一次机器,然后双击 启动Bulwark.bat。'
        }
        Write-Host ''
        return $false
    }
    Ok ("已备份 $backedUp 个文件到 " + (Split-Path $backupDir -Leaf))
    # ---- 替换 --------------------------------------------------------------
    Step '替换程序文件'
    $copied = @()
    $failed = $null
    foreach ($n in $payload) {
        $s = Join-Path $srcDir $n
        $d = Join-Path $pkgDir $n
        $okCopy = $false
        $lastErr = $null
        # 刚结束的进程句柄有时还没被系统回收,立刻复制会撞「另一个程序正在使用
        # 此文件」。重试三次比直接判失败靠谱,也比一开始就 sleep 5 秒快。
        for ($try = 1; $try -le 3; $try++) {
            try { Copy-Item -LiteralPath $s -Destination $d -Force; $okCopy = $true; break }
            catch { $lastErr = $_.Exception.Message; Start-Sleep -Seconds 2 }
        }
        if (-not $okCopy) { $failed = $n; break }
        $copied += $n
        Ok "$n 已替换"
    }

    if ($failed) {
        Bad "$failed 替换失败 —— 开始回滚"
        # 原因必须打出来。上一版只说「替换失败」,而真实原因是「服务没被杀掉,exe 被锁」——
        # 少了这一行,排查从现象上完全看不出是文件占用还是权限问题。
        if ($lastErr) { Info ('原因:' + $lastErr) }
        Invoke-UpdateRollback $backupDir $copied
        return $false
    }

    # ---- 重新装载驱动 ------------------------------------------------------
    # 复用安装流程本身,而不是另写一段 copy+fltmc load:Ensure-Driver 里那套
    # (证书信任 / Secure Boot 与 HVCI 阻断项 / Instances+Altitude 注册 / 加载后
    # 复查)每一条都是踩出来的,更新路径没有理由少做任何一条。
    Step '重新装载内核驱动'
    $loaded = Ensure-Driver
    if ($loaded -ne $true) {
        # 新驱动装不上就整份回滚。留着「新 exe + 没有驱动」不行:那是降级到
        # 用户态观测,用户以为自己装完了更新,实际上前置拦截已经没了。
        Bad '新版驱动未能加载 —— 开始回滚到更新前的版本'
        Invoke-UpdateRollback $backupDir $copied
        return $false
    }

    # ---- 复查 --------------------------------------------------------------
    # 不能只看「复制没报错」就宣布成功:复制到一半、或复制了但版本号不对(发布
    # 时打错版本)都会让用户装完仍被反复提示更新。这里把结果重新读一遍。
    Step '复查'
    $afterVer = (Get-Item -LiteralPath $curExe).VersionInfo.FileVersion
    if ((Compare-BulwarkVersion $afterVer $curVer) -le 0) {
        Bad "替换后版本仍为 $afterVer —— 更新没有真正生效,回滚"
        Invoke-UpdateRollback $backupDir $copied
        return $false
    }
    Ok "界面/服务版本:$afterVer"
    Ok '内核驱动已加载'

    # 装成功了才清暂存:失败时留着,用户可以直接重试而不必重新下载。
    Remove-Item -LiteralPath $srcDir -Recurse -Force -ErrorAction SilentlyContinue
    Ok '已清理暂存的下载文件'

    Write-Host ''
    Write-Host ("==== 更新完成:$curVer -> $afterVer ====") -ForegroundColor Green
    Info ('更新前的版本备份在:' + (Split-Path $backupDir -Leaf) + '(确认新版没问题后可删除)')
    Write-Host ''
    return $true
}

function Invoke-UpdateRollback($backupDir, $copied) {
    # 回滚的目标不是「恢复文件」,而是「恢复到有防护的可运行状态」。所以除了把
    # 文件换回去,还要把旧驱动重新装载起来 —— 只还文件不重载驱动,等于把机器留在
    # 「没有前置拦截」的状态,而用户完全不知道。
    Step '回滚'
    $restored = 0
    foreach ($n in $copied) {
        $b = Join-Path $backupDir $n
        if (-not (Test-Path -LiteralPath $b)) { continue }
        for ($try = 1; $try -le 3; $try++) {
            try { Copy-Item -LiteralPath $b -Destination (Join-Path $pkgDir $n) -Force; $restored++; break }
            catch { $lastErr = $_.Exception.Message; Start-Sleep -Seconds 2 }
        }
    }
    if ($restored -eq $copied.Count) { Ok "已还原 $restored 个文件" }
    else { Bad ("只还原了 $restored / $($copied.Count) 个文件") }

    $back = Ensure-Driver
    if ($back -eq $true) {
        Ok '旧版驱动已重新加载 —— 防护已恢复'
        Write-Host ''
        Write-Host '==== 更新失败,已回滚到更新前的版本 ====' -ForegroundColor Yellow
        Info '暂存的下载文件保留着,修好原因后可以直接重试。'
    } else {
        # 到这一步说明连回滚都没能把驱动装回去。这是最坏的情况,必须说清楚
        # 下一步怎么做,而不是打一句「回滚失败」让用户自己猜。
        Bad '回滚后驱动仍未加载 —— 防护当前处于停止状态'
        Write-Host ''
        Write-Host '==== 更新失败,且回滚未能完全恢复 ====' -ForegroundColor Red
        Info ('更新前的文件在:' + $backupDir)
        Info '请重启一次机器,然后双击 启动Bulwark.bat。若仍起不来,把上面那个'
        Info 'backup- 目录里的三个文件手动复制回本目录覆盖即可。'
    }
    Write-Host ''
}
# --- applyupdate:end ---

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
        # 记下「是我开的」,卸载时才敢关回去
        [void](Set-InstallMark 'TestSigningEnabledByUs' 1)
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
    # 走到这里说明测试签名本来就是开的。只在【从未记录过】时才记 0:
    # 上一轮我们自己开完要求重启,重启后会再进这个分支,那时若写 0 就把
    # 「是我开的」这个事实抹掉了,卸载也就不会关回去。
    if ($null -eq (Get-InstallMark 'TestSigningEnabledByUs')) {
        [void](Set-InstallMark 'TestSigningEnabledByUs' 0)
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

if ($Uninstall)   { Invoke-Uninstall;   return }
if ($ApplyUpdate) {
    $ok = Invoke-ApplyUpdate
    if ($ok) {
        # 更新装完顺手把防护拉起来,否则用户点完「立即安装」会发现防护是停的。
        # 走的是与正常启动完全相同的 Start-Runtime,不另写一条启动路径。
        Step '启动'
        Start-Runtime
    }
    return
}
if ($CollectLogs) { Invoke-CollectLogs; return }
if ($Check)       { Invoke-Check;       return }

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
