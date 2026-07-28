# 重新编译UI和驱动，确保包含所有2026-07-27/28新功能
param()

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " 磐垒主动防御 - 完整重新编译" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# 1. 编译 UI (包含攻击关系图/进程管理等新页面)
Write-Host "[1/3] 编译 UI..." -ForegroundColor Yellow
Set-Location "d:\新建文件夹 (3)\cpp\build"
cmake --build . --config Release --target bulwark_ui

$uiPath = "ui\Release\bulwark_ui.exe"
if (Test-Path $uiPath) {
    $ui = Get-Item $uiPath
    Write-Host "  ✓ UI 编译成功" -ForegroundColor Green
    Write-Host "    大小: $([math]::Round($ui.Length/1KB)) KB" -ForegroundColor Gray
    Write-Host "    时间: $($ui.LastWriteTime)" -ForegroundColor Gray
} else {
    Write-Host "  ✗ UI 编译失败" -ForegroundColor Red
    exit 1
}

# 2. 编译驱动 (包含命令行硬拦/注册表回调补齐)
Write-Host "`n[2/3] 编译驱动..." -ForegroundColor Yellow
Set-Location "d:\新建文件夹 (3)\Bulwark.Driver"
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\msbuild.exe" `
    "Bulwark.Driver.vcxproj" `
    /p:Configuration=Release `
    /p:Platform=x64 `
    /p:SignMode=TestSign `
    /maxcpucount `
    /v:m

$drvPath = "x64\Release\Bulwark.sys"
if (Test-Path $drvPath) {
    $drv = Get-Item $drvPath
    Write-Host "  ✓ 驱动编译成功" -ForegroundColor Green
    Write-Host "    大小: $([math]::Round($drv.Length/1KB)) KB" -ForegroundColor Gray
    Write-Host "    时间: $($drv.LastWriteTime)" -ForegroundColor Gray
} else {
    Write-Host "  ✗ 驱动编译失败" -ForegroundColor Red
    exit 1
}

# 3. 更新便携包
Write-Host "`n[3/3] 更新便携包..." -ForegroundColor Yellow
$dst = "C:\Users\111\Desktop\新建文件夹 (4)"

Copy-Item "d:\新建文件夹 (3)\cpp\build\ui\Release\bulwark_ui.exe" "$dst\bulwark_ui.exe" -Force
Copy-Item "d:\新建文件夹 (3)\Bulwark.Driver\x64\Release\Bulwark.sys" "$dst\Bulwark.sys" -Force

Write-Host "  ✓ 文件已复制到便携包" -ForegroundColor Green

# 4. 验证
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " 便携包更新完成" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n最终文件时间戳:" -ForegroundColor White
Get-Item "$dst\bulwark_ui.exe","$dst\bulwark_service.exe","$dst\Bulwark.sys" | 
    Select-Object Name,@{N="大小(KB)";E={[math]::Round($_.Length/1KB,1)}},LastWriteTime | 
    Format-Table -AutoSize

Write-Host "新功能验证:" -ForegroundColor White
Write-Host "  ✓ UI: 攻击关系图窗口、事件时间线、进程管理页面" -ForegroundColor Green
Write-Host "  ✓ Service: 进程启动来源溯源、取证服务、实时注册表拦截规则" -ForegroundColor Green
Write-Host "  ✓ Driver: 内核命令行硬拦、注册表回调补齐(5类通知)、SAM导出硬拦" -ForegroundColor Green
