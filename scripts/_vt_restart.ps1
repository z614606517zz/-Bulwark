# 干净重启 Bulwark 服务，使其读取 BULWARK_VT_APIKEY 并连接已加载的内核驱动。
# 需以管理员权限运行。
$ErrorActionPreference = 'SilentlyContinue'
$exe = 'D:\新建文件夹 (3)\Bulwark.Service\bin\Debug\net8.0\Bulwark.Service.exe'
$log = 'C:\Windows\Temp\blw_vt_restart.txt'
Remove-Item $log -Force -ErrorAction SilentlyContinue
function L($s){ "$([DateTime]::Now.ToString('HH:mm:ss')) $s" | Out-File $log -Append -Encoding UTF8 }

L "=== begin ==="

# 1) 临时停内核驱动以解除对服务进程的自我保护，确保旧实例可被结束。
L "stopping kernel driver to lift self-protection"
sc.exe stop Bulwark | Out-Null
Start-Sleep -Seconds 2

# 2) 杀掉所有现存服务实例
$procs = Get-Process -Name Bulwark.Service -ErrorAction SilentlyContinue
foreach ($p in $procs) { L ("kill PID " + $p.Id); Stop-Process -Id $p.Id -Force }
Start-Sleep -Seconds 2
$remain = (Get-Process -Name Bulwark.Service -ErrorAction SilentlyContinue | Measure-Object).Count
L ("service instances remaining after kill: " + $remain)

# 3) 重新启动内核驱动
L "starting kernel driver"
sc.exe start Bulwark | Out-Null
Start-Sleep -Seconds 2
$drv = (sc.exe query Bulwark | Select-String 'STATE').ToString()
L ("driver: " + $drv)

# 4) 确认 API Key 环境变量(机器级)可见
$key = [Environment]::GetEnvironmentVariable('BULWARK_VT_APIKEY','Machine')
L ("api key present (machine): " + [bool]$key + ", length=" + ($key.Length))

# 5) 启动单个新服务实例(继承机器级环境变量)
L "starting fresh service instance"
Start-Process -FilePath $exe
Start-Sleep -Seconds 4
$ids = (Get-Process -Name Bulwark.Service -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }) -join ','
L ("service PIDs now: " + $ids)

L "=== done ==="
