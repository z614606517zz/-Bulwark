# =====================================================================
#  测试签名并加载内核驱动 Bulwark.sys(Minifilter)。需【管理员】运行。
#
#  ⚠ 警告:内核驱动回调里出错会直接蓝屏(BSOD)。首次务必在【带快照的
#    测试虚拟机】里验证;在真机运行前请先做系统还原点。
#
#  本脚本做的事(与 Bulwark.inf / DriverControl.cpp 的注册方式一致):
#    1) 确认测试签名已开启(bcdedit /set testsigning on,需重启一次)
#    2) 生成并信任自签名测试证书(Root + TrustedPublisher)
#    3) 用 signtool 给 .sys 签名
#    4) 把 .sys 复制到 %SystemRoot%\System32\drivers\
#    5) 以【Minifilter】方式注册服务(type=filesys + FltMgr 依赖 +
#       Instances\DefaultInstance + Altitude=385201 + Flags),而非普通
#       kernel 服务 —— 否则不会附加到卷,文件/注册表回调不会触发。
#    6) fltmc load 加载(失败回退 sc start)
#
#  之后让用户态服务以「驱动模式」运行以连接 \BulwarkPort:
#    把 cpp\service\appsettings.json 的 "EventSource" 改为 "Driver",
#    以管理员启动 bulwark_service.exe(或用 -SetServiceMode 让本脚本代改)。
# =====================================================================
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [string]$CertName = "BulwarkTestCert",
    [switch]$SetServiceMode   # 顺便把 cpp\service\appsettings.json 的 EventSource 改为 Driver
)

$ErrorActionPreference = "Stop"

# --- 必须管理员(复制到 System32、注册服务、写 LocalMachine 证书store、加载驱动)---
$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "请以【管理员】身份运行本脚本。"
}

$root = Split-Path -Parent $PSScriptRoot
if (-not $root) { $root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$sys = Join-Path $root "build\driver\$Configuration\Bulwark.sys"
$serviceName = "Bulwark"
$altitude    = "385201"
$instance    = "Bulwark Instance"
$driversDst  = Join-Path $env:SystemRoot "System32\drivers\Bulwark.sys"

if (-not (Test-Path $sys)) {
    throw "未找到驱动: $sys`n请先运行:  powershell -File scripts\build-driver.ps1 -Configuration $Configuration"
}

Write-Host "==== 磐垒 内核驱动 测试签名 + 加载(Minifilter)====" -ForegroundColor Cyan
Write-Host "⚠ 内核回调出错会蓝屏。请确认已在测试机/已建还原点。" -ForegroundColor Red

# 1) 测试签名状态 -------------------------------------------------------------
# bcdedit.exe 仅在 64 位 System32;32 位(SysWOW64)进程会被重定向而找不到 -> 用按位数解析的绝对路径。
$bcdeditExe = if (Test-Path "$env:SystemRoot\Sysnative\bcdedit.exe") { "$env:SystemRoot\Sysnative\bcdedit.exe" } else { "$env:SystemRoot\System32\bcdedit.exe" }
$ts = (& $bcdeditExe | Select-String "testsigning") -join " "
if ($ts -notmatch "Yes") {
    Write-Host "[1/6] 测试签名未开启,正在开启(重启后生效)..." -ForegroundColor Yellow
    & $bcdeditExe /set testsigning on | Out-Host
    Write-Host "    请【重启】后重新运行本脚本。" -ForegroundColor Yellow
    return
}
Write-Host "[1/6] 测试签名已开启。" -ForegroundColor Green

# 2) 测试证书(生成 + 信任)---------------------------------------------------
# 只复用【有私钥 + 未过期 + 带代码签名用途(EKU 1.3.6.1.5.5.7.3.3)】的证书;否则删掉旧的重建,
# 避免复用到不可用的残留证书导致 signtool "No certificates were found that met all the given criteria"。
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$CertName" -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and ((($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId }) -contains '1.3.6.1.5.5.7.3.3')) } | Select-Object -First 1
if (-not $cert) {
    Write-Host "[2/6] 创建并信任测试证书 CN=$CertName ..." -ForegroundColor Cyan
    Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$CertName" } | ForEach-Object { Remove-Item $_.PSPath -Force -ErrorAction SilentlyContinue }
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CertName" `
        -CertStoreLocation Cert:\LocalMachine\My -KeyUsage DigitalSignature `
        -KeySpec Signature -HashAlgorithm SHA256
    foreach ($storeName in @("Root", "TrustedPublisher")) {
        $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
        $st.Open("ReadWrite"); $st.Add($cert); $st.Close()
    }
} else {
    Write-Host "[2/6] 复用已有测试证书 CN=$CertName(有私钥、未过期、含代码签名用途)。" -ForegroundColor Green
}

# 3) signtool 签名 ------------------------------------------------------------
$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "\\x64\\" } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "未找到 signtool.exe(需安装 WDK/SDK)。" }
Write-Host "[3/6] 签名驱动 ($($signtool.FullName)) 指纹 $($cert.Thumbprint)..." -ForegroundColor Cyan
# 用证书【指纹】精确指定(比 /n 主体名更可靠,杜绝 "No certificates met criteria")。
& $signtool.FullName sign /v /fd SHA256 /sm /s My /sha1 $cert.Thumbprint /t http://timestamp.digicert.com $sys
if ($LASTEXITCODE -ne 0) {
    Write-Host "    带时间戳签名失败,改用无时间戳(测试签名可接受)..." -ForegroundColor Yellow
    & $signtool.FullName sign /v /fd SHA256 /sm /s My /sha1 $cert.Thumbprint $sys
    if ($LASTEXITCODE -ne 0) { throw "signtool 签名失败。" }
}

# 4) 停旧 + 复制到 System32\drivers ------------------------------------------
Write-Host "[4/6] 停止旧实例并复制到 $driversDst ..." -ForegroundColor Cyan
& fltmc unload $serviceName  2>$null | Out-Null
& sc.exe stop $serviceName   2>$null | Out-Null
Start-Sleep -Seconds 1
Copy-Item $sys $driversDst -Force

# 5) 以 Minifilter 方式注册(type=filesys + FltMgr + Instances/Altitude)------
Write-Host "[5/6] 注册 Minifilter 服务 $serviceName ..." -ForegroundColor Cyan
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) { & sc.exe delete $serviceName 2>$null | Out-Null; Start-Sleep -Seconds 1 }
& sc.exe create $serviceName type= filesys start= demand `
    binPath= "System32\drivers\Bulwark.sys" depend= FltMgr group= "FSFilter Activity Monitor" | Out-Host

$svcKey = "HKLM\SYSTEM\CurrentControlSet\Services\$serviceName"
& reg.exe add "$svcKey\Instances" /v DefaultInstance /t REG_SZ /d $instance /f | Out-Null
& reg.exe add "$svcKey\Instances\$instance" /v Altitude /t REG_SZ  /d $altitude /f | Out-Null
& reg.exe add "$svcKey\Instances\$instance" /v Flags    /t REG_DWORD /d 0 /f | Out-Null

# 6) 加载(minifilter 用 fltmc load;失败回退 sc start)-----------------------
Write-Host "[6/6] 加载驱动..." -ForegroundColor Cyan
& fltmc load $serviceName | Out-Host
if ($LASTEXITCODE -ne 0) { & sc.exe start $serviceName | Out-Host }

Start-Sleep -Seconds 1
$loaded = (& fltmc filters | Select-String -SimpleMatch $serviceName) -ne $null
if ($loaded) {
    Write-Host "`n✅ 驱动已加载(fltmc filters 可见 $serviceName)。" -ForegroundColor Green
} else {
    Write-Host "`n⚠ 未在 fltmc filters 看到 $serviceName。用 scripts\..\诊断驱动.bat 或 'sc query Bulwark' 排查。" -ForegroundColor Yellow
}

# 可选:把用户态服务切到驱动模式 ----------------------------------------------
if ($SetServiceMode) {
    $appsettings = Join-Path $root "cpp\service\appsettings.json"
    if (Test-Path $appsettings) {
        $json = Get-Content $appsettings -Raw
        $new = [regex]::Replace($json, '("EventSource"\s*:\s*")[^"]*(")', '${1}Driver${2}')
        Set-Content $appsettings $new -NoNewline -Encoding UTF8
        Write-Host "已把 $appsettings 的 EventSource 改为 Driver。" -ForegroundColor Green
    } else {
        Write-Host "未找到 $appsettings,跳过 EventSource 切换。" -ForegroundColor Yellow
    }
}

Write-Host "`n下一步:以管理员启动用户态服务(EventSource=Driver)后,它会连接 \BulwarkPort," -ForegroundColor Cyan
Write-Host "        做协议握手并下发受保护项;此时才是真正的『行为前』内核拦截。" -ForegroundColor Cyan
Write-Host "查看内核日志:DebugView(勾选 Capture Kernel);卸载:fltmc unload Bulwark; sc delete Bulwark" -ForegroundColor DarkGray
