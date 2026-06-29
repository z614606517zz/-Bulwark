# 磐垒主动防御 - 启用内核驱动(测试签名)辅助脚本
# 作用:信任驱动的测试证书 + 开启测试签名模式,使自签名的 Bulwark.sys 能被加载。
# 需以管理员身份运行;完成后需重启电脑生效。

$ErrorActionPreference = 'Stop'
Write-Host "==== 磐垒 驱动启用助手 ====" -ForegroundColor Cyan

$sys = Join-Path $env:SystemRoot 'System32\drivers\Bulwark.sys'
if (-not (Test-Path $sys)) {
    Write-Host "[X] 未找到 $sys —— 请先运行服务端一次(它会安装驱动文件),或确认驱动已部署。" -ForegroundColor Red
    return
}

# 1) 从 .sys 提取签名证书并信任(Root + TrustedPublisher)
Write-Host "[1/4] 提取并信任驱动测试证书..." -ForegroundColor Yellow
$sig = Get-AuthenticodeSignature $sys
$cert = $sig.SignerCertificate
if ($null -eq $cert) {
    Write-Host "[X] 该驱动没有可读取的数字签名,无法继续。" -ForegroundColor Red
    return
}
$cerPath = Join-Path $env:TEMP 'BulwarkTest.cer'
[IO.File]::WriteAllBytes($cerPath, $cert.Export('Cert'))
Import-Certificate -FilePath $cerPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
Import-Certificate -FilePath $cerPath -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
Write-Host ("    已信任证书:" + $cert.Subject)

# 2) 开启测试签名模式
Write-Host "[2/4] 开启测试签名模式 (bcdedit /set testsigning on)..." -ForegroundColor Yellow
& bcdedit /set testsigning on | Out-Host

# 3) 检查 Secure Boot(开启时测试签名不生效)
Write-Host "[3/4] 检查 Secure Boot 状态..." -ForegroundColor Yellow
try {
    $sb = Confirm-SecureBootUEFI
    if ($sb) {
        Write-Host "    [!] 警告:Secure Boot 已开启 —— 测试签名【不会】生效。" -ForegroundColor Red
        Write-Host "        需要进入 BIOS/UEFI 关闭 Secure Boot 后,驱动才能加载。" -ForegroundColor Red
    } else {
        Write-Host "    Secure Boot 已关闭,测试签名可生效。" -ForegroundColor Green
    }
} catch {
    Write-Host "    (传统 BIOS 或无法查询 Secure Boot,通常可正常生效。)"
}

# 4) 提示重启
Write-Host "[4/4] 配置完成。" -ForegroundColor Green
Write-Host ""
Write-Host "请【重启电脑】使测试签名生效。重启后桌面右下角应出现“测试模式”水印," -ForegroundColor Cyan
Write-Host "然后在磐垒设置页打开“内核驱动防护”开关,即可加载驱动。" -ForegroundColor Cyan
Write-Host ""
$ans = Read-Host "现在重启电脑吗?(Y/N)"
if ($ans -eq 'Y' -or $ans -eq 'y') {
    shutdown /r /t 5
    Write-Host "电脑将在 5 秒后重启..."
} else {
    Write-Host "请稍后手动重启以使配置生效。"
}
