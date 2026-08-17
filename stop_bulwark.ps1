# Bulwark 停止脚本
# 需要以管理员权限运行

Write-Host "正在停止 Bulwark..." -ForegroundColor Green

# 1. 停止 UI
Write-Host "`n[1/3] 停止 UI..." -ForegroundColor Yellow
$uiProcess = Get-Process -Name "bulwark_ui" -ErrorAction SilentlyContinue
if ($uiProcess) {
    Stop-Process -Name "bulwark_ui" -Force -ErrorAction SilentlyContinue
    Write-Host "✓ UI 已停止" -ForegroundColor Green
} else {
    Write-Host "○ UI 未运行" -ForegroundColor Gray
}

Start-Sleep -Seconds 1

# 2. 停止服务
Write-Host "`n[2/3] 停止服务..." -ForegroundColor Yellow
Stop-Service -Name "BulwarkService" -Force -ErrorAction SilentlyContinue
if ($?) {
    Write-Host "✓ 服务已停止" -ForegroundColor Green
} else {
    # 尝试停止服务进程
    $serviceProcess = Get-Process -Name "bulwark_service" -ErrorAction SilentlyContinue
    if ($serviceProcess) {
        Stop-Process -Name "bulwark_service" -Force -ErrorAction SilentlyContinue
        Write-Host "✓ 服务进程已停止" -ForegroundColor Green
    } else {
        Write-Host "○ 服务未运行" -ForegroundColor Gray
    }
}

Start-Sleep -Seconds 1

# 3. 停止驱动
Write-Host "`n[3/3] 停止驱动..." -ForegroundColor Yellow
sc.exe stop Bulwark
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ 驱动已停止" -ForegroundColor Green
} else {
    Write-Host "○ 驱动已停止或未运行 (错误码: $LASTEXITCODE)" -ForegroundColor Gray
}

Write-Host "`n完成！" -ForegroundColor Green
Write-Host "如果遇到权限错误，请右键点击此脚本并选择 '以管理员身份运行'" -ForegroundColor Cyan
