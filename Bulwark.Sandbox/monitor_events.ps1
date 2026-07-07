# 磐垒 · Windows Sandbox 行为采集脚本
# 在沙盒内运行,记录所有进程/文件/注册表/网络行为

param(
    [int]$Duration = 30,
    [string]$LogDir = "C:\transfer\sandbox_logs"
)

$ErrorActionPreference = "SilentlyContinue"
$startTime = Get-Date

# 创建日志目录
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

# 日志文件路径
$processLogFile = Join-Path $LogDir "process_events.json"
$fileLogFile = Join-Path $LogDir "file_events.json"
$regLogFile = Join-Path $LogDir "registry_events.json"
$netLogFile = Join-Path $LogDir "network_events.json"
$summaryFile = Join-Path $LogDir "behavior_summary.json"

# 初始化统计
$stats = @{
    processEvents = 0
    fileEvents = 0
    registryEvents = 0
    networkSnapshots = 0
    newProcesses = @()
    createdFiles = @()
    modifiedFiles = @()
    deletedFiles = @()
    registryChanges = @()
    networkConnections = @()
}

function Write-JsonLog {
    param([string]$LogFile, [hashtable]$Data)
    $Data["_ts"] = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $json = $Data | ConvertTo-Json -Compress
    $json | Out-File $LogFile -Append -Encoding UTF8
}

Write-Host "[监控] 行为采集引擎已启动"
Write-Host "[监控] 监控时长: ${Duration}秒"
Write-Host "[监控] 日志目录: $LogDir"
Write-Host ""

# ============================================
# 1. 进程监控 (WMI 事件订阅)
# ============================================
Write-Host "[监控] 注册进程创建事件..."
$procQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
$procAction = {
    $p = $event.TargetInstance
    $data = @{
        type = "ProcessCreate"
        pid = [int]$p.ProcessId
        name = [string]$p.Name
        path = [string]$p.ExecutablePath
        cmd = [string]$p.CommandLine
        parentPid = [int]$p.ParentProcessId
    }
    $data | ConvertTo-Json -Compress | Out-File $processLogFile -Append -Encoding UTF8
}
Register-WmiEvent -Query $procQuery -Action $procAction -SourceIdentifier "BulwarkProc" | Out-Null

# ============================================
# 2. 文件监控 (FileSystemWatcher)
# ============================================
Write-Host "[监控] 注册文件系统事件..."
$watchPaths = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\AppData\Local\Temp",
    "$env:USERPROFILE\AppData\Roaming",
    "C:\ProgramData"
)

$watchers = @()
foreach ($path in $watchPaths) {
    if (Test-Path $path) {
        $w = New-Object System.IO.FileSystemWatcher
        $w.Path = $path
        $w.IncludeSubdirectories = $true
        $w.NotifyFilter = [System.IO.NotifyFilters]'FileName,DirectoryName,LastWrite,CreationTime'
        $w.EnableRaisingEvents = $true

        $handler = {
            $d = $event.SourceEventArgs
            $info = @{
                type = $d.ChangeType.ToString()
                path = $d.FullPath
                name = $d.Name
            }
            $info | ConvertTo-Json -Compress | Out-File $fileLogFile -Append -Encoding UTF8
        }

        Register-ObjectEvent $w "Created" -Action $handler -SourceIdentifier "FCreate_$($path.GetHashCode())" | Out-Null
        Register-ObjectEvent $w "Changed" -Action $handler -SourceIdentifier "FChange_$($path.GetHashCode())" | Out-Null
        Register-ObjectEvent $w "Deleted" -Action $handler -SourceIdentifier "FDelete_$($path.GetHashCode())" | Out-Null
        Register-ObjectEvent $w "Renamed" -Action $handler -SourceIdentifier "FRename_$($path.GetHashCode())" | Out-Null
        $watchers += $w
    }
}

# ============================================
# 3. 注册表监控 (定期快照)
# ============================================
Write-Host "[监控] 初始化注册表快照..."
$regKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKCU:\Software\Classes\exefile\shell\open\command",
    "HKLM:\SOFTWARE\Classes\exefile\shell\open\command"
)

$regSnapshot = @{}
foreach ($key in $regKeys) {
    if (Test-Path $key) {
        try {
            $vals = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            $regSnapshot[$key] = $vals | ConvertTo-Json -Compress
        } catch {}
    }
}

# 注册表定期检查定时器
$regTimer = New-Object System.Timers.Timer
$regTimer.Interval = 5000  # 每5秒检查一次
$regTimer.AutoReset = $true
$regAction = {
    foreach ($key in $regKeys) {
        if (Test-Path $key) {
            try {
                $current = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | ConvertTo-Json -Compress
                if ($regSnapshot[$key] -ne $current) {
                    @{
                        type = "RegistryChanged"
                        key = $key
                        before = if($regSnapshot[$key]){$regSnapshot[$key]}else{"(empty)"}
                        after = if($current){$current}else{"(empty)"}
                    } | ConvertTo-Json -Compress | Out-File $regLogFile -Append -Encoding UTF8
                    $regSnapshot[$key] = $current
                }
            } catch {}
        }
    }
}
Register-ObjectEvent $regTimer "Elapsed" -Action $regAction -SourceIdentifier "BulwarkReg" | Out-Null
$regTimer.Start()

# ============================================
# 4. 网络监控 (定期快照)
# ============================================
Write-Host "[监控] 启动网络连接监控..."
$netTimer = New-Object System.Timers.Timer
$netTimer.Interval = 3000  # 每3秒
$netTimer.AutoReset = $true
$netAction = {
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)" } |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
            @{N="ProcName";E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}}

    if ($conns) {
        $connList = @($conns | ForEach-Object {
            @{
                local = "$($_.LocalAddress):$($_.LocalPort)"
                remote = "$($_.RemoteAddress):$($_.RemotePort)"
                pid = [int]$_.OwningProcess
                proc = [string]$_.ProcName
            }
        })
        @{
            type = "NetworkSnapshot"
            connections = $connList
        } | ConvertTo-Json -Compress -Depth 5 | Out-File $netLogFile -Append -Encoding UTF8
    }
}
Register-ObjectEvent $netTimer "Elapsed" -Action $netAction -SourceIdentifier "BulwarkNet" | Out-Null
$netTimer.Start()

# ============================================
# 等待监控时长
# ============================================
Write-Host ""
Write-Host "[监控] 采集中... ${Duration}秒"
Write-Host ""

$elapsed = 0
while ($elapsed -lt $Duration) {
    Start-Sleep -Seconds 5
    $elapsed += 5
    $remaining = $Duration - $elapsed
    if ($remaining -gt 0) {
        Write-Host "        剩余 $remaining 秒..."
    }
}

# ============================================
# 停止监控并生成摘要
# ============================================
Write-Host ""
Write-Host "[监控] 正在停止采集..."

# 停止所有事件订阅
Unregister-Event -SourceIdentifier "BulwarkProc" -EA SilentlyContinue
Unregister-Event -SourceIdentifier "BulwarkReg" -EA SilentlyContinue
Unregister-Event -SourceIdentifier "BulwarkNet" -EA SilentlyContinue
Get-EventSubscriber | Where-Object { $_.SourceIdentifier -like "F*" } | Unregister-Event -EA SilentlyContinue
$regTimer.Stop()
$netTimer.Stop()
$watchers | ForEach-Object { $_.Dispose() }

# 统计事件数量
$procCount = (Get-Content $processLogFile -EA SilentlyContinue | Where-Object { $_.Trim() -ne "" } | Measure-Object).Count
$fileCount = (Get-Content $fileLogFile -EA SilentlyContinue | Where-Object { $_.Trim() -ne "" } | Measure-Object).Count
$regCount = (Get-Content $regLogFile -EA SilentlyContinue | Where-Object { $_.Trim() -ne "" } | Measure-Object).Count
$netCount = (Get-Content $netLogFile -EA SilentlyContinue | Where-Object { $_.Trim() -ne "" } | Measure-Object).Count

# 生成摘要
$summary = @{
    startTime = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
    endTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    durationSeconds = $Duration
    statistics = @{
        processEvents = $procCount
        fileEvents = $fileCount
        registryEvents = $regCount
        networkSnapshots = $netCount
    }
    logFiles = @{
        process = "process_events.json"
        file = "file_events.json"
        registry = "registry_events.json"
        network = "network_events.json"
        sysmon = "sysmon.evtx"
        finalProcesses = "final_processes.csv"
        finalNetwork = "final_network.txt"
    }
}
$summary | ConvertTo-Json -Depth 5 | Out-File $summaryFile -Encoding UTF8

# 输出统计
Write-Host ""
Write-Host "========================================"
Write-Host " 行为采集统计"
Write-Host "========================================"
Write-Host " 进程事件:    $procCount 条"
Write-Host " 文件事件:    $fileCount 条"
Write-Host " 注册表变更:  $regCount 条"
Write-Host " 网络快照:    $netCount 条"
Write-Host "========================================"
Write-Host " 日志目录: $LogDir"
Write-Host "========================================"
