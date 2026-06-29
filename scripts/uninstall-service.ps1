# 卸载 Bulwark 服务(需以管理员身份运行 PowerShell)

$ErrorActionPreference = "Stop"
$serviceName = "BulwarkDefense"

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host "服务 $serviceName 不存在,无需卸载。" -ForegroundColor Yellow
    return
}

if ($existing.Status -ne "Stopped") {
    Write-Host "停止服务..." -ForegroundColor Cyan
    Stop-Service $serviceName -Force
}

Write-Host "删除服务..." -ForegroundColor Cyan
sc.exe delete $serviceName | Out-Null
Write-Host "完成。" -ForegroundColor Green
