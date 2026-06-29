# 临时脚本:签名 + 注册 Minifilter 服务(含 Instances/Altitude)+ fltmc load
# Minifilter 必须有实例配置,且用 fltmc 加载,不能裸 sc start。
# demand 启动:重启后不会自动加载,驱动若崩溃不会导致开机死循环。
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$sys  = Join-Path $root "build\driver\Debug\Bulwark.sys"
$thumb = "82159E419E6570129C13A8AB1DAA999D5EC06D16"
$serviceName = "Bulwark"
$altitude = "385201"
$instanceName = "Bulwark Instance"

Write-Host "=== [1/5] 定位 signtool ===" -ForegroundColor Cyan
$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "x64" } | Select-Object -First 1
if (-not $signtool) { throw "未找到 signtool.exe" }

Write-Host "=== [2/5] 签名驱动 ===" -ForegroundColor Cyan
& $signtool.FullName sign /v /sm /fd SHA256 /sha1 $thumb $sys
if ($LASTEXITCODE -ne 0) { throw "签名失败" }
(Get-AuthenticodeSignature $sys).Status

Write-Host "=== [3/5] 部署到纯英文目录并重建服务 ===" -ForegroundColor Cyan
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    fltmc.exe unload $serviceName 2>$null | Out-Null
    if ($existing.Status -eq "Running") { sc.exe stop $serviceName | Out-Null; Start-Sleep 2 }
    sc.exe delete $serviceName | Out-Null
    Start-Sleep 1
}

$drvDir = "C:\BulwarkDrv"
if (-not (Test-Path $drvDir)) { New-Item -ItemType Directory -Path $drvDir | Out-Null }
$deployed = Join-Path $drvDir "Bulwark.sys"
Copy-Item $sys $deployed -Force
Write-Host "驱动已复制到: $deployed"

# 文件系统过滤驱动(minifilter)= type 2,依赖 FltMgr
sc.exe create $serviceName type= filesys binPath= "$deployed" start= demand depend= FltMgr group= "FSFilter Activity Monitor"
if ($LASTEXITCODE -ne 0) { throw "sc create 失败" }

Write-Host "=== [4/5] 写入 Minifilter 实例注册表(Instances/Altitude)===" -ForegroundColor Cyan
$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$instKey = "$svcKey\Instances"
New-Item -Path $instKey -Force | Out-Null
New-ItemProperty -Path $instKey -Name "DefaultInstance" -Value $instanceName -PropertyType String -Force | Out-Null
$oneKey = "$instKey\$instanceName"
New-Item -Path $oneKey -Force | Out-Null
New-ItemProperty -Path $oneKey -Name "Altitude" -Value $altitude -PropertyType String -Force | Out-Null
New-ItemProperty -Path $oneKey -Name "Flags" -Value 0 -PropertyType DWord -Force | Out-Null
Write-Host "实例配置写入完成: Altitude=$altitude"

Write-Host "=== [5/5] fltmc load (这一步真正加载内核驱动, 有bug会蓝屏) ===" -ForegroundColor Yellow
fltmc.exe load $serviceName
$code = $LASTEXITCODE
Write-Host "fltmc load exit code = $code"

Write-Host "=== 状态 ===" -ForegroundColor Cyan
fltmc.exe filters
