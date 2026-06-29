$ErrorActionPreference = 'SilentlyContinue'
$s = Get-Service -Name 'Bulwark.Service'
"service status = $($s.Status)"
$p = Get-CimInstance Win32_Process -Filter "Name='Bulwark.Service.exe'"
if ($p) { "proc pid=$($p.ProcessId) started=$($p.CreationDate)" } else { "proc NONE" }
$dll = 'd:\新建文件夹 (3)\Bulwark.Service\bin\Debug\net8.0\Bulwark.Core.dll'
if (Test-Path $dll) { "Core.dll(service bin) lastWrite = $((Get-Item $dll).LastWriteTime)" }
"deploy_run.log exists = $(Test-Path 'd:\新建文件夹 (3)\deploy_run.log')"
"deploy_build_elev.txt exists = $(Test-Path 'd:\新建文件夹 (3)\deploy_build_elev.txt')"
"now = $(Get-Date -Format 'HH:mm:ss')"
