$ErrorActionPreference = 'Continue'
$log = 'd:\新建文件夹 (3)\deploy_run.log'
"=== DEPLOY START $(Get-Date -Format HH:mm:ss) ===" | Out-File $log

# 1) 停止 Windows 服务(优雅 SCM 停止,自我保护允许的正常停止路径)
try {
    Stop-Service -Name 'Bulwark.Service' -Force -ErrorAction Stop
    "Stop-Service issued" | Out-File $log -Append
} catch {
    "Stop-Service error: $($_.Exception.Message)" | Out-File $log -Append
    sc.exe stop Bulwark.Service | Out-File $log -Append
}

# 等待真正停止(最多 20 秒)
$stopped = $false
for ($i = 0; $i -lt 40; $i++) {
    $s = Get-Service -Name 'Bulwark.Service' -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq 'Stopped') { $stopped = $true; break }
    Start-Sleep -Milliseconds 500
}
"Service stopped = $stopped" | Out-File $log -Append

if (-not $stopped) {
    "ABORT: service did not stop; not building to avoid partial deploy." | Out-File $log -Append
    "=== DEPLOY END (aborted) ===" | Out-File $log -Append
    exit 1
}

# 2) 重建整个解决方案
"Building solution..." | Out-File $log -Append
& dotnet build 'd:\新建文件夹 (3)\Bulwark.sln' -c Debug 2>&1 | Out-File 'd:\新建文件夹 (3)\deploy_build_elev.txt'
$buildExit = $LASTEXITCODE
"Build exit code = $buildExit" | Out-File $log -Append

# 3) 重启服务
try {
    Start-Service -Name 'Bulwark.Service' -ErrorAction Stop
    "Start-Service issued" | Out-File $log -Append
} catch {
    "Start-Service error: $($_.Exception.Message)" | Out-File $log -Append
    sc.exe start Bulwark.Service | Out-File $log -Append
}
Start-Sleep -Seconds 2
$s2 = Get-Service -Name 'Bulwark.Service' -ErrorAction SilentlyContinue
"Service status after start = $($s2.Status)" | Out-File $log -Append

"=== DEPLOY END $(Get-Date -Format HH:mm:ss) ===" | Out-File $log -Append
