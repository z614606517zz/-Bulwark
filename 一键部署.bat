@echo off
chcp 65001 >nul
setlocal

rem ============================================================
rem  磐垒主动防御 - 一键编译部署脚本(自动提权)
rem  作用:停服务/驱动 -> 结束旧进程 -> 编译 -> 重启服务+UI
rem ============================================================

rem --- 自动请求管理员权限(部署必须提权:需停驱动/杀提权进程/写被锁 DLL)---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 正在请求管理员权限...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo [1/6] 停止内核驱动 Bulwark ...
sc stop Bulwark >nul 2>&1
timeout /t 2 /nobreak >nul

echo [2/6] 结束旧的服务/UI 进程 ...
taskkill /F /IM Bulwark.Service.exe >nul 2>&1
taskkill /F /IM Bulwark.UI.Scifi.exe >nul 2>&1
timeout /t 2 /nobreak >nul

echo [3/6] 编译整个解决方案(Release)...
dotnet build Bulwark.sln -c Release
if %errorlevel% neq 0 (
    echo.
    echo *** 编译失败,已中止部署。请查看上方错误。***
    pause
    exit /b 1
)

echo [4/6] 启动服务端 ...
start "" "Bulwark.Service\bin\Release\net8.0\Bulwark.Service.exe"
timeout /t 2 /nobreak >nul

echo [5/6] 启动 UI ...
start "" "Bulwark.UI.Scifi\bin\Release\net8.0-windows\Bulwark.UI.Scifi.exe"

echo [6/6] 完成。新功能:事后持续行为防护(自启动持久化监控 + 勒索诱饵)已随服务启动。
echo.
echo 部署完成,可以关闭此窗口。
pause
