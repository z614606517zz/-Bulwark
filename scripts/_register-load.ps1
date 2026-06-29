# 注册 + 加载已签名的 Bulwark minifilter（驱动已在 C:\BulwarkDrv 且签名有效）
$ErrorActionPreference = "Stop"
$serviceName  = "Bulwark"
$altitude     = "385201"
$instanceName = "Bulwark Instance"
$deployed     = "C:\BulwarkDrv\Bulwark.sys"

if (-not (Test-Path $deployed)) { throw "未找到驱动: $deployed" }

# 若已存在，先卸载清理
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    fltmc.exe unload $serviceName 2>$null | Out-Null
    sc.exe stop $serviceName 2>$null | Out-Null
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 1
}

Write-Host "[1/3] 创建 minifilter 服务..." -ForegroundColor Cyan
sc.exe create $serviceName type= filesys binPath= "$deployed" start= demand depend= FltMgr group= "FSFilter Activity Monitor"
if ($LASTEXITCODE -ne 0) { throw "sc create 失败 ($LASTEXITCODE)" }

Write-Host "[2/3] 写入 Instances/Altitude 注册表..." -ForegroundColor Cyan
$svcKey  = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$instKey = "$svcKey\Instances"
New-Item -Path $instKey -Force | Out-Null
New-ItemProperty -Path $instKey -Name "DefaultInstance" -Value $instanceName -PropertyType String -Force | Out-Null
$oneKey = "$instKey\$instanceName"
New-Item -Path $oneKey -Force | Out-Null
New-ItemProperty -Path $oneKey -Name "Altitude" -Value $altitude -PropertyType String -Force | Out-Null
New-ItemProperty -Path $oneKey -Name "Flags" -Value 0 -PropertyType DWord -Force | Out-Null

Write-Host "[3/3] fltmc load $serviceName (此步真正加载内核驱动)..." -ForegroundColor Yellow
fltmc.exe load $serviceName
Write-Host "fltmc load exit code = $LASTEXITCODE"

Write-Host "=== 当前已加载筛选器 ===" -ForegroundColor Cyan
fltmc.exe filters | Select-String -Pattern "Bulwark"
