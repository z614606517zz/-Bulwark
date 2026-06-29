$ErrorActionPreference = 'Stop'
try {
    Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','d:\新建文件夹 (3)\__deploy.ps1' -Wait
    'LAUNCH_OK'
} catch {
    'UAC_DECLINED: ' + $_.Exception.Message
}
