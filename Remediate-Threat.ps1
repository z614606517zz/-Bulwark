# =====================================================================
#  Bulwark 手动应急清除脚本  (必须"以管理员身份运行")
#  采用隔离(Quarantine)方式：文件移动到隔离目录而非直接删除，可回滚
# =====================================================================
$ErrorActionPreference = 'SilentlyContinue'

# 自动提权
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '需要管理员权限，正在尝试提权...' -ForegroundColor Yellow
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    return
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$quar  = "C:\BulwarkQuarantine\$stamp"
New-Item -ItemType Directory -Path $quar -Force | Out-Null
function Log($m){ Write-Host $m; Add-Content -Path "$quar\remediation.log" -Value $m }
function Quarantine($path){
    if (Test-Path $path) {
        try {
            $dest = Join-Path $quar (Split-Path $path -Leaf)
            if (Test-Path $dest) { $dest = $dest + '_' + (Get-Random) }
            Move-Item -LiteralPath $path -Destination $dest -Force -ErrorAction Stop
            Log("  [隔离] $path  ->  $dest")
        } catch { Log("  [失败] 无法隔离 $path : " + $_.Exception.Message) }
    } else { Log("  [跳过] 不存在: $path") }
}

Log("===== 开始清除  $stamp  隔离区: $quar =====")

# 1) 修复 Winlogon Userinit 劫持
Log('[1] 修复 Winlogon Userinit')
$wlk = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$cur = (Get-ItemProperty $wlk).Userinit
Log("    原值: $cur")
Set-ItemProperty -Path $wlk -Name 'Userinit' -Value 'C:\Windows\System32\userinit.exe,'
Log("    新值: " + (Get-ItemProperty $wlk).Userinit)

# 2) 删除恶意 WMI 事件订阅 (WinUpdate0dd5)
Log('[2] 清除恶意 WMI 永久事件订阅')
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -Filter "Name='WinUpdate0dd5'" | ForEach-Object { Remove-CimInstance $_; Log('    已删除 __EventFilter WinUpdate0dd5') }
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -Filter "Name='WinUpdate0dd5'" | ForEach-Object { Remove-CimInstance $_; Log('    已删除 CommandLineEventConsumer WinUpdate0dd5') }
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Where-Object { $_.Filter -match 'WinUpdate0dd5' -or $_.Consumer -match 'WinUpdate0dd5' } | ForEach-Object { Remove-CimInstance $_; Log('    已删除 关联 Binding') }

# 3) 删除恶意自启动服务
Log('[3] 删除恶意服务')
foreach ($svc in @('8p7SIbO','bBDhjd4')) {
    if (Get-CimInstance Win32_Service -Filter "Name='$svc'") {
        Stop-Service $svc -Force
        sc.exe delete $svc | Out-Null
        Log("    已删除服务: $svc")
    } else { Log("    服务不存在: $svc") }
}

# 4) 结束并隔离守护脚本 (watchdog .bat) + 恶意载荷目录
Log('[4] 隔离恶意文件/目录')
# 先结束可能在跑的 watchdog cmd
Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" | Where-Object { $_.CommandLine -match '\.bat' -and $_.CommandLine -match 'Windows' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force; Log('    结束 watchdog PID=' + $_.ProcessId) }

$targets = @(
  'C:\Windows\BalkNNxjv.bat',
  'C:\Windows\MVDOwDAf.bat',
  'C:\Windows\psgLFQeZH.bat',
  'C:\Windows\xWxoXuq.bat',
  'C:\Windows\ZqCKBdLT.bat',
  'C:\Windows\keylog.xml',
  'C:\Windows\uuid.ini',
  'C:\Windows\uuid_info.dat',
  'C:\Windows\Sub',
  'C:\Users\Administrator\AppData\Local\Programs\skyload',
  'C:\Program Files (x86)\plupt-tm'
)
foreach ($t in $targets) { Quarantine $t }

Log('')
Log('===== 完成。请重启系统后再次扫描确认。 =====')
Log('注意: 以下项需人工确认后再处理(本脚本未动):')
Log('  - C:\Windows\Jdutxudgp\SUPPORT.IMG*  (来源不明的大文件，疑似载荷暂存)')
Log('  - C:\Windows\engcfg.config           (疑似江民AV引擎配置，可能为合法组件)')
Write-Host ''
Write-Host '清除完成。隔离区: ' $quar -ForegroundColor Green
Write-Host '按回车键退出...'
[void](Read-Host)
