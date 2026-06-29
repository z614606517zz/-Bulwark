# =====================================================================
#  在【测试虚拟机】中以管理员身份运行,用于加载 Bulwark.sys 进行测试。
#  警告:仅在带快照的测试虚拟机里运行!驱动回调出错会导致蓝屏(BSOD)。
# =====================================================================

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$sys = Join-Path $root "build\driver\$Configuration\Bulwark.sys"
$serviceName = "Bulwark"
$certName = "BulwarkTestCert"

if (-not (Test-Path $sys)) {
    throw "未找到驱动: $sys。请先运行 scripts\build-driver.ps1。"
}

# 1) 确认测试签名已开启(未开启则提示开启并重启)
$testsigning = (bcdedit | Select-String "testsigning").ToString()
if ($testsigning -notmatch "Yes") {
    Write-Host "测试签名未开启。正在开启(需重启后生效)..." -ForegroundColor Yellow
    bcdedit /set testsigning on
    Write-Host "请重启虚拟机后重新运行本脚本。" -ForegroundColor Yellow
    return
}

# 2) 生成测试代码签名证书(若不存在)
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$certName" } | Select-Object -First 1
if (-not $cert) {
    Write-Host "创建测试证书 CN=$certName ..." -ForegroundColor Cyan
    $cert = New-SelfSignedCertificate -Type CodeSigningCert `
        -Subject "CN=$certName" -CertStoreLocation Cert:\LocalMachine\My `
        -KeyUsage DigitalSignature -KeySpec Signature -HashAlgorithm SHA256

    # 信任该证书(加入 受信任的根 + 受信任的发布者)
    $store1 = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store1.Open("ReadWrite"); $store1.Add($cert); $store1.Close()
    $store2 = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
    $store2.Open("ReadWrite"); $store2.Add($cert); $store2.Close()
}

# 3) 用 signtool 给驱动签名
$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "x64" } | Select-Object -First 1
if (-not $signtool) { throw "未找到 signtool.exe(需安装 WDK/SDK)。" }

Write-Host "签名驱动..." -ForegroundColor Cyan
# /sm 使用本地计算机证书存储(证书建在 Cert:\LocalMachine\My)。
# 时间戳服务器可能不可达,失败不阻断(测试签名无需时间戳)。
& $signtool.FullName sign /v /fd SHA256 /sm /s My /n "CN=$certName" `
    /t http://timestamp.digicert.com $sys
if ($LASTEXITCODE -ne 0) {
    Write-Host "带时间戳签名失败,重试无时间戳签名(测试签名可接受)..." -ForegroundColor Yellow
    & $signtool.FullName sign /v /fd SHA256 /sm /s My /n "CN=$certName" $sys
}

# 4) 安装并启动驱动服务
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -eq "Running") { sc.exe stop $serviceName | Out-Null; Start-Sleep 2 }
    sc.exe delete $serviceName | Out-Null
    Start-Sleep 1
}

Write-Host "注册内核服务..." -ForegroundColor Cyan
sc.exe create $serviceName type= kernel binPath= "$sys" start= demand | Out-Null

Write-Host "启动驱动..." -ForegroundColor Cyan
sc.exe start $serviceName

Write-Host "完成。用 'sc query Bulwark' 查看状态。" -ForegroundColor Green
Write-Host "查看调试输出:DebugView(勾选 Capture Kernel)。" -ForegroundColor Green
Write-Host "卸载:sc stop Bulwark; sc delete Bulwark" -ForegroundColor Green
