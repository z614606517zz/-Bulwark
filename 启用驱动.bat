@echo off
chcp 65001 >nul
rem 磐垒 - 一键启用内核驱动(测试签名)。自动请求管理员权限。
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 正在请求管理员权限...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0启用驱动.ps1"
pause
