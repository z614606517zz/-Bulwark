$ErrorActionPreference = 'Continue'
$log = 'C:\Windows\Temp\bw_deploy.log'
$sln = 'd:\新建文件夹 (3)\Bulwark.sln'
$buildOut = 'C:\Windows\Temp\bw_build.txt'
"=== DEPLOY START $(Get-Date -Format HH:mm:ss) ===" | Out-File $log

try {
    Stop-Service -Name 'Bulwark.Service' -Force -ErrorAction Stop
    "Stop-Service issued" | Out-File $log -Append
} catch {
    "Stop-Service error: $($_.Exception.Message)" | Out-File $log -Append
    & sc.exe stop Bulwark.Service *>&1 | Out-File $log -Append
}

$stopped = $false
for ($i = 0; $i -lt 40; $i++) {
    $s = Get-Service -Name 'Bulwark.Service' -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq 'Stopped') { $stopped = $true; break }
    Start-Sleep -Milliseconds 500
}
"Service stopped = $stopped" | Out-File $log -Append

if (-not $stopped) {
    "ABORT: service did not stop." | Out-File $log -Append
    "=== DEPLOY END (aborted) ===" | Out-File $log -Append
    exit 1
}

"Building..." | Out-File $log -Append
& dotnet build $sln -c Debug *>&1 | Out-File $buildOut
"Build exit code = $LASTEXITCODE" | Out-File $log -Append

try {
    Start-Service -Name 'Bulwark.Service' -ErrorAction Stop
    "Start-Service issued" | Out-File $log -Append
} catch {
    "Start-Service error: $($_.Exception.Message)" | Out-File $log -Append
    & sc.exe start Bulwark.Service *>&1 | Out-File $log -Append
}
Start-Sleep -Seconds 2
$s2 = Get-Service -Name 'Bulwark.Service' -ErrorAction SilentlyContinue
"Service status after start = $($s2.Status)" | Out-File $log -Append
"=== DEPLOY END $(Get-Date -Format HH:mm:ss) ===" | Out-File $log -Append
