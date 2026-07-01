# 安装 Bulwark 服务(需以管理员身份运行 PowerShell)
# 用法:右键 "以管理员身份运行 PowerShell",然后执行本脚本。

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$serviceProj = Join-Path $root "Bulwark.Service\Bulwark.Service.csproj"
$publishDir = Join-Path $root "publish\service"
$serviceName = "BulwarkDefense"

Write-Host "[1/4] 发布服务到 $publishDir ..." -ForegroundColor Cyan
dotnet publish $serviceProj -c Release -o $publishDir

$exe = Join-Path $publishDir "Bulwark.Service.exe"
if (-not (Test-Path $exe)) {
    throw "未找到发布产物: $exe"
}

# 若已存在同名服务,先删除
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[2/4] 已存在服务,先停止并删除..." -ForegroundColor Yellow
    if ($existing.Status -ne "Stopped") { Stop-Service $serviceName -Force }
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host "[3/5] 创建服务 $serviceName ..." -ForegroundColor Cyan
# binPath 必须用引号包裹路径
New-Service -Name $serviceName `
            -BinaryPathName "`"$exe`"" `
            -DisplayName "Bulwark 主动防御" `
            -Description "磐垒主动防御(HIPS)决策服务" `
            -StartupType Automatic

Write-Host "[4/5] 配置崩溃自动恢复(自动重启)..." -ForegroundColor Cyan
# 安全守护进程若因罕见的运行时异常(如 .NET IO 完成端口线程抛出的
# ERROR_ABANDONED_WAIT_0)非正常退出,必须自动重启以尽快恢复防护,
# 避免出现"服务已崩溃、主机在无防护状态下长时间运行"的窗口。
# reset= 86400:失败计数在 24 小时无故障后清零;
# actions= 每次失败依次延迟 5s / 10s / 30s 后重启服务。
# 注意:sc.exe 语法要求 "reset=" 与其值之间必须有空格(作为两个参数传入)。
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

Write-Host "[5/5] 启动服务..." -ForegroundColor Cyan
Start-Service $serviceName

Get-Service $serviceName | Format-Table -AutoSize
Write-Host "完成。服务以 LocalSystem 运行(WMI 进程监控需要管理员权限)。" -ForegroundColor Green
Write-Host "现在以管理员身份运行 UI: dotnet run --project Bulwark.UI" -ForegroundColor Green
