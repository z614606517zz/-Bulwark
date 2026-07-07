@echo off
chcp 65001 >nul
echo.
echo  ========================================
echo   磐垒 · Windows Sandbox 行为监控
echo  ========================================
echo.

REM 参数: %1=目标程序路径 %2=监控时长(秒)
set "TARGET=%~1"
set "DURATION=%~2"
if "%DURATION%"=="" set "DURATION=30"

set "LOGDIR=C:\transfer\sandbox_logs"
mkdir "%LOGDIR%" 2>nul

echo  目标程序: %TARGET%
echo  监控时长: %DURATION% 秒
echo  日志目录: %LOGDIR%
echo.

REM ========================================
REM 步骤1: 安装 Sysmon
REM ========================================
echo  [1/5] 安装 Sysmon 行为采集工具...
if exist "C:\transfer\Sysmon.exe" (
    copy "C:\transfer\Sysmon.exe" "C:\Sysmon.exe" >nul 2>&1
) else if not exist "C:\Sysmon.exe" (
    echo  正在下载 Sysmon...
    powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://live.sysinternals.com/Sysmon64.exe' -OutFile 'C:\Sysmon.exe'" >nul 2>&1
)

if exist "C:\Sysmon.exe" (
    C:\Sysmon.exe -accepteula -i >nul 2>&1
    if %errorlevel% equ 0 (
        echo  Sysmon 已安装并运行。
    ) else (
        echo  [!] Sysmon 安装失败,使用内置采集。
    )
) else (
    echo  [!] Sysmon 不可用,使用内置采集。
)

REM ========================================
REM 步骤2: 启动 PowerShell 行为采集
REM ========================================
echo  [2/5] 启动行为采集引擎...
start /b powershell -NoProfile -ExecutionPolicy Bypass -File "C:\transfer\monitor_events.ps1" -Duration %DURATION% -LogDir "%LOGDIR%"

REM ========================================
REM 步骤3: 启动目标程序
REM ========================================
echo  [3/5] 启动目标程序...
echo         %TARGET%
echo.
start "" "%TARGET%"
set "START_TIME=%TIME%"

REM ========================================
REM 步骤4: 等待监控时长
REM ========================================
echo  [4/5] 监控进行中... (%DURATION% 秒)
echo         开始时间: %START_TIME%
echo.

REM 显示倒计时
set /a "remain=%DURATION%"
:countdown
if %remain% leq 0 goto done
echo         剩余 %remain% 秒...
timeout /t 5 /nobreak >nul
set /a "remain=%remain%-5"
goto countdown

:done
echo.
echo  [5/5] 采集完成,收集最终状态...

REM ========================================
REM 步骤5: 收集最终状态
REM ========================================

REM 导出 Sysmon 日志
if exist "C:\Sysmon.exe" (
    wevtutil epl Microsoft-Windows-Sysmon/Operational "%LOGDIR%\sysmon.evtx" /ow:true 2>nul
    if %errorlevel% equ 0 (
        echo  Sysmon 日志已导出。
    )
)

REM 导出当前进程列表
tasklist /FO CSV > "%LOGDIR%\final_processes.csv" 2>nul

REM 导出网络连接
netstat -anob > "%LOGDIR%\final_network.txt" 2>nul

REM 导出注册表启动项
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" "%LOGDIR%\reg_run_hkcu.reg" /y >nul 2>&1
reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" "%LOGDIR%\reg_run_hklm.reg" /y >nul 2>&1
reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "%LOGDIR%\reg_winlogon.reg" /y >nul 2>&1

REM 导出计划任务
schtasks /query /FO CSV > "%LOGDIR%\scheduled_tasks.csv" 2>nul

REM 导出服务列表
sc query type= all state= all > "%LOGDIR%\services.txt" 2>nul

REM 导出 hosts 文件
type "%SystemRoot%\System32\drivers\etc\hosts" > "%LOGDIR%\hosts.txt" 2>nul

REM 生成摘要
echo.
echo  ========================================
echo   监控完成摘要
echo  ========================================
echo   开始时间: %START_TIME%
echo   结束时间: %TIME%
echo   日志目录: %LOGDIR%
echo  ========================================
echo.

REM 列出生成的日志文件
echo  生成的日志文件:
dir /b "%LOGDIR%"
echo.

echo  请关闭此窗口,日志将自动复制到宿主机。
echo  宿主机路径: {{HOST_LOG_DIR}}
echo.
pause >nul
