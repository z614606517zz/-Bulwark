@echo off
chcp 65001 >nul
rem 磐垒 - 停止内核驱动(自动提权)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 正在请求管理员权限...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
echo =============== 停止 Bulwark 内核驱动 ===============

echo [1/4] 通过 fltmc 卸载 minifilter(绕过 SCM 自保护) ...
fltmc unload Bulwark
if %errorlevel% equ 0 ( echo   [OK] fltmc 卸载成功 ) else ( echo   [!] fltmc 卸载失败(可能无实例附加) )

echo [2/4] 尝试 sc stop(自保护可能拦截) ...
sc stop Bulwark

echo [3/4] 检查驱动状态 ...
sc query Bulwark
sc query Bulwark | findstr /i "STOPPED" >nul && echo   [OK] 驱动已停止 || echo   [!] 驱动仍在运行

echo [4/4] 如果驱动仍无法停止,请重启电脑(该驱动为手动启动,重启后不会自动加载)
echo =============================================
pause
