# Bulwark 启动脚本
# 需要以管理员权限运行

Write-Host "正在启动 Bulwark..." -ForegroundColor Green

# 1. 启动驱动
Write-Host "`n[1/3] 启动驱动..." -ForegroundColor Yellow
sc.exe start Bulwark
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ 驱动启动成功" -ForegroundColor Green
} else {
    Write-Host "✗ 驱动启动失败 (错误码: $LASTEXITCODE)" -ForegroundColor Red
    # 检查驱动状态
    sc.exe query Bulwark
}

Start-Sleep -Seconds 1

# 2. 启动服务
Write-Host "`n[2/3] 启动服务..." -ForegroundColor Yellow
Start-Service -Name "BulwarkService" -ErrorAction SilentlyContinue
if ($?) {
    Write-Host "✓ 服务启动成功" -ForegroundColor Green
} else {
    Write-Host "✗ 服务启动失败或未安装" -ForegroundColor Red
    # 尝试直接运行服务可执行文件（隐藏窗口）
    Write-Host "尝试直接启动服务进程..." -ForegroundColor Yellow
    $servicePath = Join-Path $PSScriptRoot "cpp\dist\bulwark_service.exe"
    if (Test-Path $servicePath) {
        # 使用 WScript.Shell 完全隐藏窗口
        $wshell = New-Object -ComObject WScript.Shell
        $wshell.Run($servicePath, 0, $false)
        Write-Host "✓ 服务进程已在后台启动（无窗口）" -ForegroundColor Green
    }
}

Start-Sleep -Seconds 2

# 3. 启动 UI
Write-Host "`n[3/3] 启动 UI..." -ForegroundColor Yellow
$uiPath = Join-Path $PSScriptRoot "cpp\dist\bulwark_ui.exe"
if (Test-Path $uiPath) {
    Start-Process -FilePath $uiPath -WorkingDirectory (Split-Path $uiPath)
    Write-Host "✓ UI 已启动" -ForegroundColor Green
} else {
    Write-Host "✗ 找不到 UI 可执行文件: $uiPath" -ForegroundColor Red
}

Write-Host "`n完成！" -ForegroundColor Green
Write-Host "如果遇到权限错误，请右键点击此脚本并选择 '以管理员身份运行'" -ForegroundColor Cyan
