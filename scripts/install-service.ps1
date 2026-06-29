# 安装 Bulwark 服务(需以管理员身份运行 PowerShell)
# 用法:右键 "以管理员身份运行 PowerShell",然后执行本脚本。

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$serviceProj = Join-Path $root "Bulwark.Service\Bulwark.Service.csproj"
$publishDir = Join-Path $root "publish\service"
$serviceName = "BulwarkDefense"

Write-Host "[1/3] 发布服务到 $publishDir ..." -ForegroundColor Cyan
dotnet publish $serviceProj -c Release -o $publishDir

$exe = Join-Path $publishDir "Bulwark.Service.exe"
if (-not (Test-Path $exe)) {
    throw "未找到发布产物: $exe"
}

# 若已存在同名服务,先删除
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[2/3] 已存在服务,先停止并删除..." -ForegroundColor Yellow
    if ($existing.Status -ne "Stopped") { Stop-Service $serviceName -Force }
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host "[2/3] 创建服务 $serviceName ..." -ForegroundColor Cyan
# binPath 必须用引号包裹路径
New-Service -Name $serviceName `
            -BinaryPathName "`"$exe`"" `
            -DisplayName "Bulwark 主动防御" `
            -Description "磐垒主动防御(HIPS)决策服务" `
            -StartupType Automatic

Write-Host "[3/3] 启动服务..." -ForegroundColor Cyan
Start-Service $serviceName

Get-Service $serviceName | Format-Table -AutoSize
Write-Host "完成。服务以 LocalSystem 运行(WMI 进程监控需要管理员权限)。" -ForegroundColor Green
Write-Host "现在以管理员身份运行 UI: dotnet run --project Bulwark.UI" -ForegroundColor Green
