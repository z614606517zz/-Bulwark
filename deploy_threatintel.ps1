# Bulwark 威胁情报源(TASK 7)部署脚本
# 用法:右键以管理员身份运行 PowerShell,执行:
#   powershell -ExecutionPolicy Bypass -File "d:\新建文件夹 (3)\deploy_threatintel.ps1"
# 脚本会:停止 Bulwark.Service 服务 -> 重建解决方案 -> 重启服务。
# 全部日志只写在工作区内(不碰系统目录,避免被自我保护拦截)。

$ErrorActionPreference = 'Continue'
$root = 'd:\新建文件夹 (3)'
$log = Join-Path $root 'deploy_threatintel.log'
$sln = Join-Path $root 'Bulwark.sln'
$buildOut = Join-Path $root 'deploy_threatintel_build.txt'

function Log($m) { "$((Get-Date).ToString('HH:mm:ss')) $m" | Tee-Object -FilePath $log -Append }

"=== DEPLOY START ===" | Out-File $log
Log "停止 Bulwark.Service 服务..."
try {
    Stop-Service -Name 'Bulwark.Service' -Force -ErrorAction Stop
    Log "已发出停止指令"
} catch {
    Log "Stop-Service 失败: $($_.Exception.Message),尝试 sc stop"
    & sc.exe stop Bulwark.Service *>&1 | Out-File $log -Append
}

$stopped = $false
for ($i = 0; $i -lt 60; $i++) {
    $s = Get-Service -Name 'Bulwark.Service' -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq 'Stopped') { $stopped = $true; break }
    Start-Sleep -Milliseconds 500
}
Log "服务已停止 = $stopped"

if (-not $stopped) {
    Log "中止:服务未能停止。请在软件内关闭防护/退出,或检查自我保护设置后重试。"
    Log "=== DEPLOY END (aborted) ==="
    Write-Host "`n部署中止:服务未停止。详见 $log" -ForegroundColor Red
    exit 1
}

Log "重建解决方案..."
& dotnet build $sln -c Debug *>&1 | Out-File $buildOut
$bx = $LASTEXITCODE
Log "构建退出码 = $bx (0=成功)"

Log "重启 Bulwark.Service 服务..."
try {
    Start-Service -Name 'Bulwark.Service' -ErrorAction Stop
    Log "已发出启动指令"
} catch {
    Log "Start-Service 失败: $($_.Exception.Message),尝试 sc start"
    & sc.exe start Bulwark.Service *>&1 | Out-File $log -Append
}
Start-Sleep -Seconds 2
$s2 = Get-Service -Name 'Bulwark.Service' -ErrorAction SilentlyContinue
Log "启动后服务状态 = $($s2.Status)"
Log "=== DEPLOY END ==="

if ($bx -eq 0 -and $s2.Status -eq 'Running') {
    Write-Host "`n✅ 部署成功:威胁情报源已上线,服务已重启运行。" -ForegroundColor Green
    Write-Host "现在可以打开 UI,在设置页『威胁情报』测试微步 / MetaDefender 连接。" -ForegroundColor Green
} else {
    Write-Host "`n⚠ 部署可能未完全成功,详见日志:$log 和 $buildOut" -ForegroundColor Yellow
}
