# 磐垒 - 停止内核驱动(Bypass 自保护)
# 需管理员权限
$ErrorActionPreference = 'Stop'

# 确保 64 位进程(fltmc 在 32 位下会被 WOW64 重定向)
if (-not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }
}

# 检查管理员权限
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "正在请求管理员权限..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "=============== 停止 Bulwark 内核驱动 ===============" -ForegroundColor Cyan

# 确保 fltmc 路径正确(64-bit)
$env:Path = "$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0;$env:Path"

# 1) 优先卸载用户态服务(断开与驱动的通信端口)
Write-Host "[1/5] 停止用户态服务 BulwarkService ..." -ForegroundColor Yellow
& sc.exe stop BulwarkService 2>&1 | Out-Host

# 2) 通过 fltmc 卸载 minifilter(绕过 SCM,不受注册表硬拦影响)
Write-Host "[2/5] fltmc unload Bulwark ..." -ForegroundColor Yellow
& fltmc.exe unload Bulwark 2>&1 | Out-Host

# 3) 尝试 sc stop(自保护可能拦截,但 unload 后应可成功)
Write-Host "[3/5] sc stop Bulwark ..." -ForegroundColor Yellow
& sc.exe stop Bulwark 2>&1 | Out-Host

# 4) 如有残留实例,尝试 detach
Write-Host "[4/5] 清理 fltmc 实例 ..." -ForegroundColor Yellow
$instances = & fltmc.exe instances -f Bulwark 2>&1
if ($LASTEXITCODE -eq 0) {
    # 尝试 detach 每个实例
    fltmc.exe instances -f Bulwark | Select-String -Pattern '^\s+\d+\s+' | ForEach-Object {
        $parts = $_ -split '\s+'
        if ($parts.Count -ge 3) {
            $vol = $parts[2]
            Write-Host "  detach from $vol ..."
            fltmc.exe detach Bulwark -Volume $vol 2>&1 | Out-Null
        }
    }
    & fltmc.exe unload Bulwark 2>&1 | Out-Host
}

# 5) 最终检查
Write-Host "[5/5] 最终状态检查 ..." -ForegroundColor Yellow
$svc = Get-Service Bulwark -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "[!] 驱动仍在运行。尝试禁用后重启电脑:" -ForegroundColor Red
    Write-Host "    sc config Bulwark start= disabled" -ForegroundColor Gray
    Write-Host "    然后重启电脑。" -ForegroundColor Gray
} elseif ($svc) {
    Write-Host "[OK] 驱动已停止(状态: $($svc.Status))" -ForegroundColor Green
} else {
    Write-Host "[OK] 驱动服务已不存在" -ForegroundColor Green
}

Write-Host "======================================================" -ForegroundColor Cyan
pause
